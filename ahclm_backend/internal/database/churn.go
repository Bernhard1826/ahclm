package database

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"ahclm/internal/models"
)

// analyzeChurnShape decides what a sequence of "the certificate changed"
// observations actually demonstrates.
//
// The change counter that drives the frequent-change finding is computed as
// "the leaf I see now differs from the leaf I saw last time". For a domain
// served by one endpoint that is a replacement in time. For a domain served by
// a pool of servers that hold different certificates concurrently it is not:
// each scan samples whichever server answered, so the counter measures the
// sampling process rather than the deployment's history.
//
// The two cases have opposite signatures and can be separated from the retained
// evidence alone:
//
//   - Replacement in time is monotone. A retired leaf is gone; it cannot come
//     back. Any revisit falsifies the renewal reading.
//   - Concurrent deployment recurs, usually alternating, and the predecessor is
//     frequently still answering on another address in the very same round.
//
// changes must be sorted oldest-first.
func analyzeChurnShape(changes []models.CertObservation, certs map[string]models.Certificate) models.ChurnShape {
	copied := append([]models.CertObservation(nil), changes...)
	return analyzeChurnShapeWithSnapshots(copied, certs, nil)
}

func analyzeChurnShapeWithSnapshots(changes []models.CertObservation, certs map[string]models.Certificate, snapshots []models.MeasurementSnapshot) models.ChurnShape {
	shape := models.ChurnShape{ChangeEvents: len(changes), Interpretation: models.ChurnUndetermined}
	if len(changes) == 0 {
		return shape
	}
	recovered := recoverChangeEndpoints(changes, snapshots)
	if recovered > 0 {
		shape.RecoveredEndpointChanges = recovered
	}

	seen := make(map[string]struct{}, len(changes))
	// The replacement floor has to be computed over every leaf the sequence
	// touched, including the predecessor of the first change, which is never a
	// "new" fingerprint but is still one of the certificates that had to be
	// replaced to produce the observed set.
	universe := make(map[string]struct{}, len(changes)+1)
	spkis := make(map[string]struct{})
	sequence := make([]string, 0, len(changes))
	for index, change := range changes {
		if previous := strings.TrimSpace(change.PreviousFingerprint); previous != "" {
			universe[previous] = struct{}{}
		}
		fingerprint := strings.TrimSpace(change.Fingerprint)
		if fingerprint == "" {
			continue
		}
		universe[fingerprint] = struct{}{}
		sequence = append(sequence, fingerprint)
		if _, repeat := seen[fingerprint]; repeat {
			shape.RevisitEvents++
		}
		seen[fingerprint] = struct{}{}
		if change.SPKIFingerprint != "" {
			spkis[change.SPKIFingerprint] = struct{}{}
		}
		if coexistingLeaves(change) {
			shape.CoexistenceProofs++
		}
		switch endpointRelation(changes, index) {
		case endpointSame:
			shape.SameEndpointChanges++
		case endpointDifferent:
			shape.CrossEndpointChanges++
		default:
			shape.UnknownEndpointChanges++
		}
	}
	for index := 2; index < len(sequence); index++ {
		if sequence[index] == sequence[index-2] {
			shape.AlternationEvents++
		}
	}
	shape.DistinctLeaves = len(seen)
	shape.DistinctSPKIs = len(spkis)
	if len(sequence) > 0 {
		shape.RevisitRatio = round2(float64(shape.RevisitEvents) / float64(len(sequence)))
	}
	// Visiting N distinct leaves requires at least N-1 real replacements. This is
	// a floor, not an estimate: it is the smallest history consistent with the
	// observed set regardless of how the samples were ordered.
	if len(universe) > 0 {
		shape.EffectiveReplacements = len(universe) - 1
	}
	shape.MeanIntervalHours, shape.CadenceRegularity = changeCadence(changes)
	shape.MedianValidityDays = medianValidityDays(changes, certs)
	shape.ObservedSpanDays = round2(changes[len(changes)-1].ObservedAt.Sub(changes[0].ObservedAt).Hours() / 24)
	// Normalize churn by certificate lifetime. Replacing a 90-day certificate
	// every 60 days is the documented ACME cadence, not frequent change.
	if shape.MedianValidityDays > 0 && shape.ObservedSpanDays > 0 {
		periods := shape.ObservedSpanDays / float64(shape.MedianValidityDays)
		if periods > 0 {
			shape.ReplacementsPerValidityPeriod = round2(float64(shape.EffectiveReplacements) / periods)
		}
	}
	fillIssuanceSignals(&shape, changes, certs)
	shape.Interpretation = interpretChurnShape(shape)
	return shape
}

// fillIssuanceSignals records remaining life at replacement and the issuance
// dates of the served leaves. Serving a certificate that was issued weeks
// earlier, with only a few days left, is a pre-issued rolling pipeline. Serving
// a recently issued certificate near a repeatable remaining-life window is
// automated renewal. A different public key is not used here: every new
// issuance produces a new key by default.
func fillIssuanceSignals(shape *models.ChurnShape, changes []models.CertObservation, certs map[string]models.Certificate) {
	if shape == nil || len(changes) == 0 {
		return
	}
	remaining := make([]int, 0, len(changes))
	ages := make([]int, 0, len(changes))
	issuanceDays := make(map[string]struct{})
	issuanceTimes := make([]time.Time, 0, len(changes))
	sameIssuer, issuerPairs := 0, 0
	sameName, namePairs := 0, 0
	monotonePairs, comparablePairs := 0, 0
	var previousNotBefore time.Time
	var previousHasNotBefore bool
	for _, change := range changes {
		if change.DaysUntilExpiry > 0 {
			remaining = append(remaining, change.DaysUntilExpiry)
		}
		cert, ok := certs[strings.TrimSpace(change.Fingerprint)]
		if !ok {
			continue
		}
		if !cert.NotBefore.IsZero() {
			issuanceDays[cert.NotBefore.UTC().Truncate(24*time.Hour).Format("2006-01-02")] = struct{}{}
			issuanceTimes = append(issuanceTimes, cert.NotBefore.UTC())
			if !change.ObservedAt.IsZero() && !change.ObservedAt.Before(cert.NotBefore) {
				ages = append(ages, int(change.ObservedAt.Sub(cert.NotBefore).Hours()/24))
			}
			if previousHasNotBefore {
				comparablePairs++
				if !cert.NotBefore.Before(previousNotBefore) {
					monotonePairs++
				}
			}
			previousNotBefore = cert.NotBefore
			previousHasNotBefore = true
		}
		previous, previousOK := certs[strings.TrimSpace(change.PreviousFingerprint)]
		if previousOK {
			if cert.Issuer != "" || previous.Issuer != "" || cert.IssuerCN != "" || previous.IssuerCN != "" {
				issuerPairs++
				if issuerFamily(cert) == issuerFamily(previous) {
					sameIssuer++
				}
			}
			if cert.CommonName != "" || previous.CommonName != "" {
				namePairs++
				if cert.CommonName == previous.CommonName {
					sameName++
				}
			}
		}
	}
	shape.MedianRemainingDays = medianInt(remaining)
	shape.RemainingSpreadDays = round2(spreadDays(remaining))
	shape.MedianIssuanceAgeDays = medianInt(ages)
	shape.DistinctIssuanceDays = len(issuanceDays)
	shape.IssuanceCadenceDays = issuanceCadenceDays(issuanceTimes)
	if issuerPairs > 0 {
		shape.SameIssuerFraction = round2(float64(sameIssuer) / float64(issuerPairs))
	}
	if namePairs > 0 {
		shape.SameNameFraction = round2(float64(sameName) / float64(namePairs))
	}
	shape.IssuanceMonotone = comparablePairs > 0 && monotonePairs*2 >= comparablePairs
}

func medianInt(values []int) int {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	return sorted[len(sorted)/2]
}

func spreadDays(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := 0.0
	for _, value := range values {
		mean += float64(value)
	}
	mean /= float64(len(values))
	variance := 0.0
	for _, value := range values {
		delta := float64(value) - mean
		variance += delta * delta
	}
	return math.Sqrt(variance / float64(len(values)))
}

func issuanceCadenceDays(times []time.Time) float64 {
	if len(times) < 2 {
		return 0
	}
	sorted := append([]time.Time(nil), times...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left].Before(sorted[right]) })
	unique := make([]time.Time, 0, len(sorted))
	for _, instant := range sorted {
		day := instant.UTC().Truncate(24 * time.Hour)
		if len(unique) == 0 || !unique[len(unique)-1].Equal(day) {
			unique = append(unique, day)
		}
	}
	if len(unique) < 2 {
		return 0
	}
	gaps := make([]float64, 0, len(unique)-1)
	for index := 1; index < len(unique); index++ {
		gaps = append(gaps, unique[index].Sub(unique[index-1]).Hours()/24)
	}
	sort.Float64s(gaps)
	return round2(gaps[len(gaps)/2])
}

func interpretChurnShape(shape models.ChurnShape) string {
	switch {
	case shape.ChangeEvents < 2:
		return models.ChurnUndetermined
	// A round that saw the predecessor and the successor at the same time has
	// proven they are deployed concurrently. No cadence argument can override a
	// direct observation.
	case shape.CoexistenceProofs > 0:
		return models.ChurnSpatialMultiplexing
	case shape.RevisitRatio >= 0.25:
		return models.ChurnSpatialMultiplexing
	case shape.RevisitEvents > 0:
		return models.ChurnMixed
	// Monotone from here on. Only a same-endpoint comparison can turn that into
	// a replacement claim; a monotone sequence sampled from changing addresses
	// is equally consistent with a large pool that we never sampled twice.
	case shape.SameEndpointChanges > shape.CrossEndpointChanges:
		return models.ChurnTemporalReplacement
	case shape.CrossEndpointChanges > 0 && shape.SameEndpointChanges == 0:
		return models.ChurnMixed
	case shape.SameEndpointChanges > 0:
		return models.ChurnTemporalReplacement
	default:
		return models.ChurnUndetermined
	}
}

// coexistingLeaves reports whether this change observation's own endpoint survey
// captured the predecessor and the successor in the same round.
func coexistingLeaves(change models.CertObservation) bool {
	previous := strings.TrimSpace(change.PreviousFingerprint)
	current := strings.TrimSpace(change.Fingerprint)
	if previous == "" || current == "" || previous == current {
		return false
	}
	if change.ChangeClass == models.ChangeClassCoexisting {
		return true
	}
	var probes []models.EndpointProbe
	if strings.TrimSpace(change.EndpointProbes) == "" {
		return false
	}
	if json.Unmarshal([]byte(change.EndpointProbes), &probes) != nil {
		return false
	}
	sawPrevious, sawCurrent := false, false
	for _, probe := range probes {
		if !probe.Success || probe.Fingerprint == "" {
			continue
		}
		if probe.Fingerprint == previous {
			sawPrevious = true
		}
		if probe.Fingerprint == current {
			sawCurrent = true
		}
	}
	return sawPrevious && sawCurrent
}

type endpointComparison int

const (
	endpointUnknown endpointComparison = iota
	endpointSame
	endpointDifferent
)

// endpointRelation compares the address that served the new leaf with the
// address that served the predecessor. When the row does not carry an explicit
// previous address, the preceding change row's address is the endpoint that
// served what is now the predecessor, which makes the comparison recomputable
// for rows written before the field existed.
func endpointRelation(changes []models.CertObservation, index int) endpointComparison {
	current := strings.TrimSpace(changes[index].IPAddress)
	if current == "" {
		return endpointUnknown
	}
	previous := strings.TrimSpace(changes[index].PreviousIPAddress)
	if previous == "" && index > 0 {
		previous = strings.TrimSpace(changes[index-1].IPAddress)
	}
	if previous == "" {
		return endpointUnknown
	}
	if previous == current {
		return endpointSame
	}
	return endpointDifferent
}

// recoverChangeEndpoints fills missing serving addresses from retained round
// snapshots. Historical change rows often omitted the IP; the later round that
// observed the same leaf usually still recorded which address answered.
type leafAppearance struct {
	at time.Time
	ip string
}

func recoverChangeEndpoints(changes []models.CertObservation, snapshots []models.MeasurementSnapshot) int {
	if len(changes) == 0 || len(snapshots) == 0 {
		return 0
	}
	byFingerprint := make(map[string][]leafAppearance)
	for _, snapshot := range snapshots {
		mapping := diagnosisEndpointFingerprintSetFromSnapshot(snapshot)
		if len(mapping) == 0 {
			continue
		}
		for ip, fingerprint := range mapping {
			fingerprint = strings.TrimSpace(fingerprint)
			ip = strings.TrimSpace(ip)
			if fingerprint == "" || ip == "" {
				continue
			}
			byFingerprint[fingerprint] = append(byFingerprint[fingerprint], leafAppearance{at: snapshot.ObservedAt, ip: ip})
		}
	}
	if len(byFingerprint) == 0 {
		return 0
	}
	recovered := 0
	for index := range changes {
		change := &changes[index]
		if strings.TrimSpace(change.IPAddress) == "" {
			if ip := nearestEndpointFor(byFingerprint[strings.TrimSpace(change.Fingerprint)], change.ObservedAt); ip != "" {
				change.IPAddress = ip
				recovered++
			}
		}
		if strings.TrimSpace(change.PreviousIPAddress) == "" {
			if ip := nearestEndpointFor(byFingerprint[strings.TrimSpace(change.PreviousFingerprint)], change.ObservedAt); ip != "" {
				change.PreviousIPAddress = ip
				recovered++
			}
		}
	}
	return recovered
}

const recoveredEndpointWindow = 6 * time.Hour

func nearestEndpointFor(appearances []leafAppearance, at time.Time) string {
	if len(appearances) == 0 || at.IsZero() {
		return ""
	}
	bestIP := ""
	bestDelta := time.Duration(0)
	found := false
	for _, item := range appearances {
		if item.at.IsZero() {
			continue
		}
		delta := item.at.Sub(at)
		if delta < 0 {
			delta = -delta
		}
		if delta > recoveredEndpointWindow {
			continue
		}
		if !found || delta < bestDelta {
			found = true
			bestDelta = delta
			bestIP = item.ip
		}
	}
	if !found {
		return ""
	}
	return bestIP
}

func issuerFamily(cert models.Certificate) string {
	cn := strings.ToLower(strings.TrimSpace(cert.IssuerCN))
	raw := strings.ToLower(strings.TrimSpace(cert.Issuer + " " + cert.IssuerCN))
	switch {
	case strings.Contains(raw, "google trust") || strings.Contains(raw, "pki.goog"):
		return "google_trust_services"
	case shortIssuerSerial(cn, "we", "wr"):
		return "google_trust_services"
	case strings.Contains(raw, "let's encrypt") || strings.Contains(raw, "lets encrypt") || strings.Contains(raw, "isrg"):
		return "lets_encrypt"
	case shortIssuerSerial(cn, "ye", "yr", "r", "e"):
		return "lets_encrypt"
	case strings.Contains(raw, "digicert"):
		return "digicert"
	case strings.Contains(raw, "sectigo") || strings.Contains(raw, "comodo"):
		return "sectigo"
	case strings.Contains(raw, "amazon"):
		return "amazon"
	case strings.Contains(raw, "microsoft"):
		return "microsoft"
	case strings.Contains(raw, "certainly"):
		return "certainly"
	case cn != "":
		return stripIssuerSerial(cn)
	default:
		return strings.TrimSpace(raw)
	}
}

func shortIssuerSerial(cn string, prefixes ...string) bool {
	if cn == "" || len(cn) > 4 {
		return false
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(cn, prefix) && isMostlyDigits(strings.TrimPrefix(cn, prefix)) {
			return true
		}
	}
	return false
}

func stripIssuerSerial(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return value
	}
	last := fields[len(fields)-1]
	if strings.HasPrefix(last, "ocsp") || isMostlyDigits(last) {
		fields = fields[:len(fields)-1]
	}
	if len(fields) == 0 {
		return value
	}
	return strings.Join(fields, " ")
}

func isMostlyDigits(value string) bool {
	digits := 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits > 0 && digits*2 >= len(value)
}

func medianValidityDays(changes []models.CertObservation, certs map[string]models.Certificate) int {
	values := make([]int, 0, len(changes))
	for _, change := range changes {
		cert, ok := certs[change.Fingerprint]
		if !ok {
			continue
		}
		days := cert.ValidityDays
		if days <= 0 && !cert.NotAfter.IsZero() && !cert.NotBefore.IsZero() {
			days = int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
		}
		if days > 0 {
			values = append(values, days)
		}
	}
	if len(values) == 0 {
		return 0
	}
	sort.Ints(values)
	return values[len(values)/2]
}

// churnShapeEvidence renders the discriminating measurements as evidence
// strings so the finding carries the numbers that produced the verdict.
func churnShapeEvidence(shape models.ChurnShape) []string {
	return []string{
		itoaEvidence("change_events", shape.ChangeEvents),
		itoaEvidence("distinct_leaves", shape.DistinctLeaves),
		itoaEvidence("revisit_events", shape.RevisitEvents),
		ftoaEvidence("revisit_ratio", shape.RevisitRatio),
		itoaEvidence("alternation_events", shape.AlternationEvents),
		itoaEvidence("coexistence_proofs", shape.CoexistenceProofs),
		itoaEvidence("same_endpoint_changes", shape.SameEndpointChanges),
		itoaEvidence("cross_endpoint_changes", shape.CrossEndpointChanges),
		itoaEvidence("effective_replacements", shape.EffectiveReplacements),
		ftoaEvidence("replacements_per_validity_period", shape.ReplacementsPerValidityPeriod),
		itoaEvidence("median_remaining_days", shape.MedianRemainingDays),
		itoaEvidence("median_issuance_age_days", shape.MedianIssuanceAgeDays),
		itoaEvidence("distinct_issuance_days", shape.DistinctIssuanceDays),
		ftoaEvidence("issuance_cadence_days", shape.IssuanceCadenceDays),
		"churn_interpretation=" + shape.Interpretation,
	}
}

// analyzeCTCorroboration turns the retained Certificate Transparency documents
// into an independent count of how many certificates were actually issued for
// this name during the observation window.
//
// CT is the only channel in the system that can falsify a replacement count:
// a replacement requires an issuance, and issuances are logged. When the
// observed change count greatly exceeds the number of logged issuances, the
// excess cannot be replacements.
func analyzeCTCorroboration(snapshots []models.MeasurementSnapshot, shape models.ChurnShape, window time.Duration) (coverage float64, entries, issuances int, status, note string) {
	status = models.CTUnavailable
	if len(snapshots) == 0 {
		return 0, 0, 0, status, "No measurement rounds retained CT documents."
	}
	withCT := 0
	keys := make(map[string]struct{})
	var newest time.Time
	for _, snapshot := range snapshots {
		raw := strings.TrimSpace(snapshot.CTJSON)
		if raw == "" || raw == "null" || raw == "[]" {
			continue
		}
		var observations []models.CTObservation
		if json.Unmarshal([]byte(raw), &observations) != nil || len(observations) == 0 {
			continue
		}
		withCT++
		entries += len(observations)
		if snapshot.ObservedAt.After(newest) {
			newest = snapshot.ObservedAt
		}
	}
	coverage = round2(float64(withCT) / float64(len(snapshots)))
	if withCT == 0 {
		return coverage, 0, 0, models.CTUnavailable, "Certificate Transparency was not retrieved for this domain, so the observed replacement count has no independent check."
	}
	// Count only issuances inside the observed window; older log entries describe
	// history this monitoring run did not measure.
	cutoff := newest.Add(-window)
	for _, snapshot := range snapshots {
		raw := strings.TrimSpace(snapshot.CTJSON)
		if raw == "" || raw == "null" || raw == "[]" {
			continue
		}
		var observations []models.CTObservation
		if json.Unmarshal([]byte(raw), &observations) != nil {
			continue
		}
		for _, observation := range observations {
			issuedAt := observation.NotBefore
			if issuedAt == nil {
				issuedAt = observation.EntryTimestamp
			}
			if issuedAt == nil || issuedAt.Before(cutoff) {
				continue
			}
			key := issuanceKey(observation)
			if key == "" {
				continue
			}
			keys[key] = struct{}{}
		}
	}
	issuances = len(keys)
	sources := ctSources(snapshots)
	sourceNote := ""
	if len(sources) > 1 {
		sourceNote = " Independent CT indexes (" + strings.Join(sources, ", ") + ") agree on the issuance count."
	} else if len(sources) == 1 {
		sourceNote = " Issuances were retrieved from " + sources[0] + "."
	}
	switch {
	case issuances == 0:
		return coverage, entries, issuances, models.CTUnavailable, "CT documents were retrieved but contained no dated issuance inside the observed window."
	case shape.ChangeEvents > 0 && issuances*2 < shape.ChangeEvents:
		return coverage, entries, issuances, models.CTContradicted,
			"Certificate Transparency records " + itoa(issuances) + " issuance(s) for this name, far fewer than the " + itoa(shape.ChangeEvents) +
				" changes counted by scanning. The excess cannot be replacements and is consistent with sampling concurrently deployed certificates." + sourceNote
	default:
		return coverage, entries, issuances, models.CTCorroborated,
			"Certificate Transparency records " + itoa(issuances) + " issuance(s), consistent with " + itoa(shape.EffectiveReplacements) + " measured replacement(s)." + sourceNote
	}
}

func ctSources(snapshots []models.MeasurementSnapshot) []string {
	seen := make(map[string]struct{})
	for _, snapshot := range snapshots {
		raw := strings.TrimSpace(snapshot.CTJSON)
		if raw == "" || raw == "null" || raw == "[]" {
			continue
		}
		var observations []models.CTObservation
		if json.Unmarshal([]byte(raw), &observations) != nil {
			continue
		}
		for _, observation := range observations {
			for _, source := range strings.Split(observation.Source, "+") {
				source = strings.TrimSpace(source)
				if source == "" {
					continue
				}
				seen[source] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for source := range seen {
		out = append(out, source)
	}
	sort.Strings(out)
	return out
}

func round2(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return math.Round(value*100) / 100
}

func itoa(value int) string { return strconv.Itoa(value) }

func itoaEvidence(key string, value int) string { return key + "=" + strconv.Itoa(value) }

func ftoaEvidence(key string, value float64) string {
	return key + "=" + strconv.FormatFloat(value, 'f', 2, 64)
}
