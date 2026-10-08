package database

import (
	"encoding/json"
	"fmt"

	"sort"
	"strings"
	"time"

	"ahclm/internal/models"
)

// Minimum rounds are definitional, not tuned: "held across rounds" needs the
// same observation in at least two retained rounds. How long an open rollout
// has lasted is not compared with a fixed number of hours but with the
// measured reference distribution of completed rollouts (rollout_reference.go).
const (
	minStableMultiProviderRounds = 2
	minStableAddressRounds       = 2
)

// defectiveFindingCodes are the validation results that make an endpoint's
// certificate unfit for the queried name. Their presence makes the divergence a
// real defect no matter how the endpoints are distributed across providers.
var defectiveFindingCodes = map[string]struct{}{
	"hostname_mismatch":             {},
	"expired_endpoint":              {},
	"not_yet_valid":                 {},
	"local_chain_validation_failed": {},
}

// analyzeEndpointDivergence explains why sampled endpoints of one domain served
// different certificates.
//
// Mixed certificates are the normal, permanent steady state of a multi-CDN or
// RSA+ECDSA deployment, so their mere presence proves nothing. What separates a
// deliberate arrangement from a real inconsistency is the *structure* of the
// split:
//
//   - A deliberate multi-provider split partitions cleanly. Each provider's
//     address space serves one certificate consistently, and the assignment
//     persists across rounds. The diversity is between providers, never inside
//     one.
//   - A deliberate dual-certificate split serves the same names from the same
//     issuer under different key algorithms, so clients negotiate whichever they
//     support.
//   - A real inconsistency shows up as disagreement *inside* one operator's own
//     address space, as a predecessor certificate that failed to propagate, or
//     as an endpoint whose certificate is simply not valid for the name.
//
// Address-level comparison cannot see this, which is why the previous stability
// test failed on every CDN: rotating edge addresses changed the map keys every
// round, so a permanently stable arrangement never looked stable. This compares
// by network partition instead.
func analyzeEndpointDivergence(probes []models.EndpointProbe, snapshots []models.MeasurementSnapshot, previousFingerprint string, replacedAt, now time.Time) models.EndpointDivergence {
	divergence := models.EndpointDivergence{EndpointsProbed: len(probes), Verdict: models.DivergenceUndetermined}

	answered := make([]models.EndpointProbe, 0, len(probes))
	for _, probe := range probes {
		if probe.Success && probe.IPAddress != "" && probe.Fingerprint != "" {
			answered = append(answered, probe)
		}
	}
	divergence.EndpointsAnswered = len(answered)
	if len(answered) < 2 {
		return divergence
	}

	leaves := make(map[string]struct{})
	issuers := make(map[string]struct{})
	keyAlgos := make(map[string]struct{})
	sanSets := make(map[string]struct{})
	defectiveFingerprints := make(map[string]struct{})
	byGroup := make(map[string]map[string]struct{})
	for _, probe := range answered {
		leaves[probe.Fingerprint] = struct{}{}
		if probe.IssuerCN != "" {
			issuers[probe.IssuerCN] = struct{}{}
		}
		if probe.KeyAlgorithm != "" {
			keyAlgos[probe.KeyAlgorithm] = struct{}{}
		}
		if probe.SANsHash != "" {
			sanSets[probe.SANsHash] = struct{}{}
		}
		group := providerGroup(probe.IPAddress)
		if byGroup[group] == nil {
			byGroup[group] = make(map[string]struct{})
		}
		byGroup[group][probe.Fingerprint] = struct{}{}
		if isDefectiveProbe(probe, now) {
			divergence.DefectiveEndpoints = append(divergence.DefectiveEndpoints, probe.IPAddress)
			defectiveFingerprints[strings.ToLower(strings.TrimSpace(probe.Fingerprint))] = struct{}{}
		}
	}
	divergence.DistinctLeaves = len(leaves)
	divergence.DistinctIssuers = len(issuers)
	divergence.DistinctKeyAlgos = len(keyAlgos)
	divergence.DistinctSANSets = len(sanSets)
	divergence.NetworkGroups = len(byGroup)
	for _, fingerprints := range byGroup {
		if len(fingerprints) > 1 {
			divergence.IntraGroupConflicts++
		}
	}
	divergence.CleanPartition = divergence.IntraGroupConflicts == 0
	divergence.FunctionallyEquivalent = len(divergence.DefectiveEndpoints) == 0
	sort.Strings(divergence.DefectiveEndpoints)

	// An RSA+ECDSA pair is the same certificate content signed under two key
	// algorithms: one issuer, one name set, more than one algorithm.
	divergence.DualCertificateSplit = divergence.DistinctLeaves >= 2 &&
		divergence.DistinctIssuers == 1 &&
		divergence.DistinctSANSets == 1 &&
		divergence.DistinctKeyAlgos >= 2

	if previousFingerprint != "" {
		servesPredecessor := false
		servesOther := false
		for _, probe := range answered {
			if probe.Fingerprint == previousFingerprint {
				servesPredecessor = true
				divergence.PredecessorEndpoints = append(divergence.PredecessorEndpoints, probe.IPAddress)
			} else {
				servesOther = true
			}
		}
		if !servesPredecessor || !servesOther {
			divergence.PredecessorEndpoints = nil
		}
		// A leaf is a predecessor only if some address was observed serving
		// it and later serving one of the other current leaves. The previous
		// main-handshake leaf is otherwise just the leaf of a different server.
		if len(divergence.PredecessorEndpoints) > 0 && !observedSuccession(snapshots, answered, previousFingerprint) {
			divergence.PredecessorEndpoints = nil
			divergence.MissingEvidence = append(divergence.MissingEvidence, "no address was observed serving the previous leaf and later one of the other current leaves, so it is not shown to be a predecessor")
		}
		sort.Strings(divergence.PredecessorEndpoints)
		if len(divergence.PredecessorEndpoints) > 0 && !replacedAt.IsZero() && now.After(replacedAt) {
			divergence.ResidueHours = round2(now.Sub(replacedAt).Hours())
		}
	}

	divergence.AddressReturns = addressReturns(snapshots, answered)
	divergence.AddressPools, divergence.PooledEndpoints = addressPools(snapshots, probes)
	divergence.PredecessorIssuedAt, divergence.SuccessorIssuedAt = issuanceBounds(answered, previousFingerprint)
	for _, probe := range probes {
		if probe.Unobservable {
			divergence.UnobservableEndpoints = append(divergence.UnobservableEndpoints, probe.IPAddress)
		}
	}
	sort.Strings(divergence.UnobservableEndpoints)
	divergence.IndependentLineages = divergence.AddressReturns == 0 && divergence.AddressPools == 0 && independentLineages(snapshots, answered)
	divergence.StableRounds = stableGroupRounds(snapshots, groupSignature(answered))
	divergence.StableAddressRounds, divergence.StableAddressSpanHours = stableAddressRounds(snapshots, answered)
	measurePredecessorEvidence(&divergence, probes, snapshots, previousFingerprint, now)
	measureGlobalProbeEvidence(&divergence, snapshots, previousFingerprint, defectiveFingerprints)
	divergence.CDN = analyzeCDNEvidence(answered, snapshots)
	if divergence.CDN != nil && divergence.CDN.Note != "" && models.CDNMethodFor(divergence.CDN.Completeness) != "vendor" {
		divergence.MissingEvidence = uniqueEvidenceStrings(append(divergence.MissingEvidence, divergence.CDN.Note))
	}
	divergence.Verdict = classifyDivergence(divergence)
	return divergence
}

func classifyDivergence(divergence models.EndpointDivergence) string {
	stuck := divergence.StrongEvidence
	cdn := divergence.CDN
	vendorComplete := cdn != nil && models.CDNMethodFor(cdn.Completeness) == "vendor"
	switch {
	case divergence.EndpointsAnswered < 2 || divergence.DistinctLeaves < 2:
		return models.DivergenceUndetermined
	// Named vendors are used only when every answering endpoint maps to a
	// published CDN prefix. CNAME/HTTPS without that mapping stays a hostname
	// hint and does not decide multi-CDN. The assignment must also persist
	// across independent rounds; one clean round is not enough to distinguish a
	// deliberate split from a rollout that has not settled.
	case vendorComplete && cdn.DistinctVendors >= 2 && cdn.CleanVendorSplit && divergence.StableRounds >= minStableMultiProviderRounds && divergence.IndependentLineages && divergence.AddressReturns == 0 && divergence.AddressPools == 0:
		return models.DivergenceIntentionalMultiCDN
	case vendorComplete && (cdn.DistinctVendors == 1 || cdn.VendorConflicts > 0):
		return classifySameVendorDivergence(divergence, stuck)
	// Each provider network serving one certificate is the fallback shape of a
	// multi-CDN deployment when vendors cannot be named. Require the same
	// provider-to-certificate assignment in independent rounds: a one-round
	// clean partition is insufficient endpoint coverage, not a benign verdict.
	case stableMultiProviderPartition(divergence):
		return models.DivergenceIntentionalMultiCDN
	// A certificate that is expired, not yet valid, name-mismatched or fails
	// chain validation is a defect on its own terms inside one fleet, so it
	// outranks dual-certificate and intra-network readings.
	case len(divergence.DefectiveEndpoints) > 0:
		return models.DivergenceDefectiveEndpoint
	case divergence.DualCertificateSplit:
		return models.DivergenceDualCertificate
	case perEndpointIssuance(divergence):
		return models.DivergencePerEndpoint
	// Disagreement inside one provider's own address space cannot be a
	// between-provider arrangement.
	case divergence.IntraGroupConflicts > 0 && stuck:
		return models.DivergenceStuckRollout
	case divergence.IntraGroupConflicts > 0 && divergence.StableRounds >= 2:
		return models.DivergenceIntraFleet
	case divergence.IntraGroupConflicts > 0:
		return models.DivergencePropagating
	case stuck:
		return models.DivergenceStuckRollout
	case len(divergence.PredecessorEndpoints) > 0, divergence.AddressReturns > 0, divergence.AddressPools > 0:
		return models.DivergencePropagating
	default:
		return models.DivergenceUndetermined
	}
}

// perEndpointIssuance: each address keeps its own leaf across rounds, every
// leaf is valid for the name, and no address was ever seen moving from one of
// these leaves to another, so none is a predecessor. Clients see a split view,
// not a rollout or an invalid certificate.
func perEndpointIssuance(divergence models.EndpointDivergence) bool {
	return divergence.IndependentLineages &&
		len(divergence.DefectiveEndpoints) == 0 &&
		divergence.StableAddressRounds >= minStableAddressRounds
}

// addressLineages returns, per address, the sequence of distinct leaves it
// served in retained rounds (oldest first), ending with the current survey.
func addressLineages(snapshots []models.MeasurementSnapshot, answered []models.EndpointProbe) map[string][]string {
	ordered := append([]models.MeasurementSnapshot(nil), snapshots...)
	sort.SliceStable(ordered, func(left, right int) bool { return ordered[left].ObservedAt.Before(ordered[right].ObservedAt) })
	lineages := make(map[string][]string)
	add := func(address, leaf string) {
		if address == "" || leaf == "" {
			return
		}
		sequence := lineages[address]
		if len(sequence) == 0 || sequence[len(sequence)-1] != leaf {
			lineages[address] = append(sequence, leaf)
		}
	}
	for _, snapshot := range ordered {
		for address, leaf := range snapshotEndpointMap(snapshot) {
			add(address, leaf)
		}
	}
	for _, probe := range answered {
		add(probe.IPAddress, probe.Fingerprint)
	}
	return lineages
}

// observedSuccession reports whether some address served previous and later
// served one of the other currently answering leaves.
func observedSuccession(snapshots []models.MeasurementSnapshot, answered []models.EndpointProbe, previous string) bool {
	successors := make(map[string]struct{})
	for _, probe := range answered {
		if probe.Fingerprint != previous {
			successors[probe.Fingerprint] = struct{}{}
		}
	}
	for _, sequence := range addressLineages(snapshots, answered) {
		seenPrevious := false
		for _, leaf := range sequence {
			if leaf == previous {
				seenPrevious = true
				continue
			}
			if _, successor := successors[leaf]; successor && seenPrevious {
				return true
			}
		}
	}
	return false
}

// addressReturns counts addresses that went back to a leaf they had already
// served (A, then B, then A again). Renewal never returns to a retired leaf, so
// such an address fronts several servers holding different certificates.
func addressReturns(snapshots []models.MeasurementSnapshot, answered []models.EndpointProbe) int {
	returns := 0
	for _, sequence := range addressLineages(snapshots, answered) {
		seen := make(map[string]struct{}, len(sequence))
		for _, leaf := range sequence {
			if _, again := seen[leaf]; again {
				returns++
				break
			}
			seen[leaf] = struct{}{}
		}
	}
	return returns
}

// addressPools counts addresses that presented more than one leaf within one
// round (repeated handshakes), in the current survey or any retained round.
func addressPools(snapshots []models.MeasurementSnapshot, current []models.EndpointProbe) (int, []string) {
	pooled := make(map[string]string)
	record := func(probes []models.EndpointProbe) {
		for _, probe := range probes {
			if probe.Success && len(probe.OtherFingerprints) > 0 {
				if _, seen := pooled[probe.IPAddress]; seen {
					continue
				}
				leaves := []string{shortProofFP(probe.Fingerprint)}
				for _, other := range probe.OtherFingerprints {
					leaves = append(leaves, shortProofFP(other))
				}
				pooled[probe.IPAddress] = fmt.Sprintf("%s presented %s within %d handshakes of one round", probe.IPAddress, strings.Join(leaves, " and "), probe.Handshakes)
			}
		}
	}
	record(current)
	for _, snapshot := range snapshots {
		raw := strings.TrimSpace(snapshot.EndpointProbesJSON)
		if raw == "" || raw == "null" {
			continue
		}
		var probes []models.EndpointProbe
		if json.Unmarshal([]byte(raw), &probes) == nil {
			record(probes)
		}
	}
	lines := make([]string, 0, len(pooled))
	for _, line := range pooled {
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return len(pooled), lines
}

// issuanceBounds reads when the predecessor and the earliest other current
// leaf were issued, from their embedded SCTs (NotBefore when absent).
func issuanceBounds(answered []models.EndpointProbe, previous string) (*time.Time, *time.Time) {
	issued := func(probe models.EndpointProbe) *time.Time {
		if probe.EarliestSCT != nil {
			return probe.EarliestSCT
		}
		return probe.NotBefore
	}
	var predecessor, successor *time.Time
	for _, probe := range answered {
		at := issued(probe)
		if at == nil {
			continue
		}
		if previous != "" && probe.Fingerprint == previous {
			predecessor = at
			continue
		}
		if successor == nil || at.Before(*successor) {
			successor = at
		}
	}
	if previous == "" {
		return nil, nil
	}
	return predecessor, successor
}

// independentLineages reports whether no address was ever observed moving
// between two of the currently answering leaves. Each leaf then belongs to its
// own address lineage and none is another's predecessor.
func independentLineages(snapshots []models.MeasurementSnapshot, answered []models.EndpointProbe) bool {
	current := make(map[string]struct{})
	for _, probe := range answered {
		current[probe.Fingerprint] = struct{}{}
	}
	if len(current) < 2 {
		return false
	}
	for _, sequence := range addressLineages(snapshots, answered) {
		for index := 1; index < len(sequence); index++ {
			_, from := current[sequence[index-1]]
			_, to := current[sequence[index]]
			if from && to {
				return false
			}
		}
	}
	return true
}

// stableAddressRounds counts retained rounds in which every current answering
// address that was probed served the same leaf as now, and the hours between
// the first and last such round. Unlike stableGroupRounds it sees which
// address holds which certificate.
func stableAddressRounds(snapshots []models.MeasurementSnapshot, answered []models.EndpointProbe) (int, float64) {
	if len(answered) < 2 {
		return 0, 0
	}
	matched := 0
	var first, last time.Time
	for _, snapshot := range snapshots {
		assignment := snapshotEndpointMap(snapshot)
		if len(assignment) < 2 {
			continue
		}
		same := true
		for _, probe := range answered {
			if leaf, ok := assignment[probe.IPAddress]; !ok || leaf != probe.Fingerprint {
				same = false
				break
			}
		}
		if !same {
			continue
		}
		matched++
		if first.IsZero() || snapshot.ObservedAt.Before(first) {
			first = snapshot.ObservedAt
		}
		if snapshot.ObservedAt.After(last) {
			last = snapshot.ObservedAt
		}
	}
	if matched == 0 {
		return 0, 0
	}
	return matched, roundEvidence(last.Sub(first).Hours())
}

func stableMultiProviderPartition(divergence models.EndpointDivergence) bool {
	// An address that went back to a leaf it had already served fronts several
	// servers, and an address seen moving from one current leaf to another is
	// a replacement: either is direct per-address evidence that outranks the
	// /16 and /32 approximation.
	return divergence.AddressReturns == 0 && divergence.AddressPools == 0 && divergence.IndependentLineages && divergence.CleanPartition &&
		divergence.NetworkGroups >= 2 &&
		divergence.StableRounds >= minStableMultiProviderRounds
}

func classifySameVendorDivergence(divergence models.EndpointDivergence, stuck bool) string {
	// One named CDN across one or more prefixes is not a multi-CDN split.
	if len(divergence.DefectiveEndpoints) > 0 {
		return models.DivergenceDefectiveEndpoint
	}
	if divergence.DualCertificateSplit {
		return models.DivergenceDualCertificate
	}
	if perEndpointIssuance(divergence) {
		return models.DivergencePerEndpoint
	}
	conflict := divergence.IntraGroupConflicts > 0 || (divergence.CDN != nil && divergence.CDN.VendorConflicts > 0)
	if conflict && stuck {
		return models.DivergenceStuckRollout
	}
	if conflict && divergence.StableRounds >= 2 {
		return models.DivergenceIntraFleet
	}
	if conflict {
		return models.DivergencePropagating
	}
	if stuck {
		return models.DivergenceStuckRollout
	}
	if len(divergence.PredecessorEndpoints) > 0 || divergence.AddressReturns > 0 || divergence.AddressPools > 0 {
		return models.DivergencePropagating
	}
	if divergence.StableRounds >= 2 {
		return models.DivergenceIntraFleet
	}
	return models.DivergencePropagating
}

func analyzeCDNEvidence(probes []models.EndpointProbe, snapshots []models.MeasurementSnapshot) *models.CDNEvidence {
	evidence := &models.CDNEvidence{
		Completeness:    models.CDNCompletenessNone,
		Method:          "network",
		EndpointVendors: map[string]string{},
	}
	topology := latestTopologySnapshot(snapshots)
	directory := latestDirectory(snapshots)
	directoryByIP := directoryEndpointMap(directory)
	evidence.CNAMEVendors = models.CDNVendorsFromNames(topology.CNAMEChain)
	evidence.HTTPSVendors = models.CDNVendorsFromNames(topology.HTTPSTargets)
	evidence.HTTPVendors = models.CDNVendorFromHTTPFingerprint(latestHTTPFingerprint(snapshots))
	nsVendors := models.CDNVendorsFromNames(topology.NSHosts)
	if directory != nil && directory.Domain != nil {
		nsVendors = uniqueEvidenceStrings(append(nsVendors, models.CDNVendorsFromNames(directory.Domain.Nameservers)...))
	}
	evidence.HostnameVendors = uniqueEvidenceStrings(append(append(append(append([]string{}, evidence.CNAMEVendors...), evidence.HTTPSVendors...), evidence.HTTPVendors...), nsVendors...))

	vendorLeaves := make(map[string]map[string]struct{})
	unidentified := make([]string, 0)
	identified := 0
	prefixIdentified := 0
	directoryIdentified := 0
	answered := 0
	sourceSet := make(map[string]struct{})
	for _, probe := range probes {
		if !probe.Success || probe.IPAddress == "" {
			continue
		}
		answered++
		vendor, source := models.CDNVendorFromAddressSource(probe.IPAddress)
		if vendor == models.CDNVendorNone {
			if record, ok := directoryByIP[probe.IPAddress]; ok {
				if record.SourceAgreement == models.DirectoryAgreementConflict {
					unidentified = append(unidentified, probe.IPAddress)
					continue
				}
				vendor = models.CDNVendorFromDirectory(record.ASN, record.ASNName, record.NetName, record.OrgName, record.Handle)
				if vendor != models.CDNVendorNone {
					if record.SourceAgreement == models.DirectoryAgreementAgreed {
						source = "numbering_authority_agreed"
					} else if strings.Contains(record.Source, "ripestat") {
						source = "ripestat"
					} else {
						source = "numbering_authority"
					}
				}
			}
		} else if source != "official_prefix_conflict" {
			prefixIdentified++
		} else {
			vendor = models.CDNVendorNone
		}
		if vendor == models.CDNVendorNone {
			unidentified = append(unidentified, probe.IPAddress)
			continue
		}
		if source == "numbering_authority" || source == "ripestat" || source == "numbering_authority_agreed" {
			directoryIdentified++
		}
		if source != "" {
			sourceSet[source] = struct{}{}
		}
		identified++
		evidence.EndpointVendors[probe.IPAddress] = vendor
		if vendorLeaves[vendor] == nil {
			vendorLeaves[vendor] = make(map[string]struct{})
		}
		if probe.Fingerprint != "" {
			vendorLeaves[vendor][probe.Fingerprint] = struct{}{}
		}
	}
	evidence.IdentifiedCount = identified
	evidence.Unidentified = unidentified
	evidence.DistinctVendors = len(vendorLeaves)
	for _, fingerprints := range vendorLeaves {
		if len(fingerprints) > 1 {
			evidence.VendorConflicts++
		}
	}
	evidence.CleanVendorSplit = evidence.VendorConflicts == 0 && evidence.DistinctVendors > 0
	hostnameHint := len(evidence.HostnameVendors) > 0
	prefixComplete := answered > 0 && prefixIdentified == answered
	directoryComplete := answered > 0 && identified == answered
	sources := sortedSourceSet(sourceSet)
	switch {
	case prefixComplete && hostnameHint:
		evidence.Completeness = models.CDNCompletenessBoth
		evidence.Sources = append(sources, "dns_control_plane")
		evidence.Note = "Every answering endpoint maps to an official CDN prefix list and the hostname has a matching control-plane record."
	case prefixComplete:
		evidence.Completeness = models.CDNCompletenessPrefix
		evidence.Sources = sources
		evidence.Note = "Every answering endpoint maps to an official CDN prefix list. The hostname has no CNAME, HTTPS/SVCB or nameserver vendor record, so the vendor reading uses address space."
	case directoryComplete && hostnameHint:
		evidence.Completeness = models.CDNCompletenessBoth
		evidence.Sources = append(sources, "dns_control_plane")
		evidence.Note = "Every answering endpoint maps to a numbering-authority or RIPEstat CDN identity. The hostname also has a CDN nameserver, CNAME or HTTPS record."
	case directoryComplete && directoryIdentified > 0:
		evidence.Completeness = models.CDNCompletenessDirectory
		evidence.Sources = sources
		evidence.Note = "Every answering endpoint maps to a named CDN from official prefix lists, RIPEstat routing, or numbering-authority ASN/org records."
	case identified > 0:
		evidence.Completeness = models.CDNCompletenessPartial
		evidence.Sources = sources
		evidence.Note = "Not every answering endpoint maps to an official CDN prefix list or numbering-authority identity, so the multi-CDN verdict stays on the IPv4 /16 and IPv6 /32 partition."
	case hostnameHint:
		evidence.Completeness = models.CDNCompletenessHostname
		evidence.Sources = []string{"dns_control_plane"}
		evidence.Note = "The hostname has a CDN control-plane or nameserver record, but endpoint addresses are not attributed to a published prefix or ASN, so the multi-CDN verdict stays on the network partition."
	default:
		evidence.Completeness = models.CDNCompletenessNone
		evidence.Note = "No CNAME, HTTPS/SVCB, nameserver, published CDN prefix or numbering-authority record identified a vendor; the multi-CDN verdict uses the IPv4 /16 and IPv6 /32 partition."
	}
	evidence.Method = models.CDNMethodFor(evidence.Completeness)
	if evidence.EndpointVendors != nil && len(evidence.EndpointVendors) == 0 {
		evidence.EndpointVendors = nil
	}
	return evidence
}

func latestTopologySnapshot(snapshots []models.MeasurementSnapshot) models.TopologySnapshot {
	for _, snapshot := range snapshots {
		if strings.TrimSpace(snapshot.TopologyJSON) == "" || snapshot.TopologyJSON == "null" {
			continue
		}
		var topology models.TopologySnapshot
		if json.Unmarshal([]byte(snapshot.TopologyJSON), &topology) == nil {
			return topology
		}
	}
	return models.TopologySnapshot{}
}

func latestHTTPFingerprint(snapshots []models.MeasurementSnapshot) *models.HTTPFingerprint {
	for _, snapshot := range snapshots {
		if strings.TrimSpace(snapshot.HTTPJSON) == "" || snapshot.HTTPJSON == "null" {
			continue
		}
		var fingerprint models.HTTPFingerprint
		if json.Unmarshal([]byte(snapshot.HTTPJSON), &fingerprint) == nil {
			return &fingerprint
		}
	}
	return nil
}

type retainedGlobalEndpoint struct {
	region      string
	address     string
	fingerprint string
	authorized  bool
}

type retainedGlobalRound struct {
	observedAt time.Time
	endpoints  []retainedGlobalEndpoint
}

// measureGlobalProbeEvidence folds remote HTTPS observations into the endpoint
// diagnosis without pretending that they are direct-IP probes. Each observation
// is a real TLS connection made through that region's own resolver. It can
// corroborate that a predecessor or a locally validated bad leaf is reachable
// from another region; it cannot reveal why the CDN selected that edge.
func measureGlobalProbeEvidence(divergence *models.EndpointDivergence, snapshots []models.MeasurementSnapshot, previousFingerprint string, defectiveFingerprints map[string]struct{}) {
	if divergence == nil || len(snapshots) == 0 {
		return
	}
	ordered := append([]models.MeasurementSnapshot(nil), snapshots...)
	sort.SliceStable(ordered, func(left, right int) bool {
		return ordered[left].ObservedAt.After(ordered[right].ObservedAt)
	})
	rounds := make([]retainedGlobalRound, 0)
	for _, snapshot := range ordered {
		raw := strings.TrimSpace(snapshot.GlobalProbesJSON)
		if raw == "" || raw == "null" {
			continue
		}
		var evidence models.GlobalProbeEvidence
		if json.Unmarshal([]byte(raw), &evidence) != nil {
			continue
		}
		round := retainedGlobalRound{observedAt: snapshot.ObservedAt}
		for _, probe := range evidence.HTTPS {
			fingerprint := strings.ToLower(strings.TrimSpace(probe.Fingerprint))
			address := strings.TrimSpace(probe.ResolvedAddress)
			if !probe.TLSObserved || fingerprint == "" || address == "" {
				continue
			}
			region := globalProbeRegion(probe.Location)
			if region == "" {
				continue
			}
			round.endpoints = append(round.endpoints, retainedGlobalEndpoint{
				region: region, address: address, fingerprint: fingerprint, authorized: probe.TLSAuthorized,
			})
		}
		if len(round.endpoints) > 0 {
			rounds = append(rounds, round)
		}
	}
	if len(rounds) == 0 {
		return
	}

	divergence.GlobalProbeRounds = len(rounds)
	latest := rounds[0]
	regions := make(map[string]struct{}, len(latest.endpoints))
	defectiveRegions := make(map[string]struct{})
	for _, endpoint := range latest.endpoints {
		regions[endpoint.region] = struct{}{}
		if !endpoint.authorized {
			if _, locallyDefective := defectiveFingerprints[endpoint.fingerprint]; locallyDefective {
				defectiveRegions[endpoint.region] = struct{}{}
			}
		}
	}
	divergence.GlobalHTTPSRegions = sortedEvidenceSet(regions)
	divergence.GlobalDefectiveRegions = sortedEvidenceSet(defectiveRegions)

	previousFingerprint = strings.ToLower(strings.TrimSpace(previousFingerprint))
	if previousFingerprint == "" || len(divergence.PredecessorEndpoints) == 0 {
		return
	}
	predecessorRegions := make(map[string]struct{})
	predecessorEndpoints := make(map[string]struct{})
	continuing := make(map[string]struct{})
	for _, endpoint := range latest.endpoints {
		if endpoint.fingerprint != previousFingerprint {
			continue
		}
		predecessorRegions[endpoint.region] = struct{}{}
		predecessorEndpoints[fmt.Sprintf("%s=%s", endpoint.region, endpoint.address)] = struct{}{}
		continuing[globalEndpointKey(endpoint)] = struct{}{}
	}
	divergence.GlobalPredecessorRegions = sortedEvidenceSet(predecessorRegions)
	divergence.GlobalPredecessorEndpoints = sortedEvidenceSet(predecessorEndpoints)
	if len(continuing) == 0 {
		return
	}

	divergence.GlobalConsecutivePredecessorRounds = 1
	oldest := latest.observedAt
	for _, round := range rounds[1:] {
		kept := make(map[string]struct{})
		for _, endpoint := range round.endpoints {
			if endpoint.fingerprint != previousFingerprint {
				continue
			}
			key := globalEndpointKey(endpoint)
			if _, present := continuing[key]; present {
				kept[key] = struct{}{}
			}
		}
		if len(kept) == 0 {
			break
		}
		continuing = kept
		divergence.GlobalConsecutivePredecessorRounds++
		if !round.observedAt.IsZero() && round.observedAt.Before(oldest) {
			oldest = round.observedAt
		}
	}
	if !latest.observedAt.IsZero() && !oldest.IsZero() && latest.observedAt.After(oldest) {
		divergence.GlobalPredecessorSpanHours = roundEvidence(latest.observedAt.Sub(oldest).Hours())
	}
}

func globalProbeRegion(location models.GlobalProbeLocation) string {
	if continent := strings.ToUpper(strings.TrimSpace(location.Continent)); continent != "" {
		return continent
	}
	if country := strings.ToUpper(strings.TrimSpace(location.Country)); country != "" {
		return country
	}
	return strings.ToUpper(strings.TrimSpace(location.Region))
}

func globalEndpointKey(endpoint retainedGlobalEndpoint) string {
	return endpoint.region + "\x00" + endpoint.address
}

// measurePredecessorEvidence applies the hard gates for the third-layer
// rollout diagnosis. Snapshot rows are newest-first in production, but the
// helper sorts a copy so fixtures and imported evidence remain deterministic.
func measurePredecessorEvidence(divergence *models.EndpointDivergence, probes []models.EndpointProbe, snapshots []models.MeasurementSnapshot, previousFingerprint string, now time.Time) {
	if divergence == nil || previousFingerprint == "" || len(divergence.PredecessorEndpoints) == 0 {
		return
	}
	ordered := append([]models.MeasurementSnapshot(nil), snapshots...)
	sort.SliceStable(ordered, func(left, right int) bool {
		return ordered[left].ObservedAt.After(ordered[right].ObservedAt)
	})
	continuityRounds := ordered
	// The scheduler writes a measurement snapshot and the lifecycle observation
	// for the same scan. The endpoint survey is the current round already, so
	// do not count that snapshot a second time as independent persistence.
	duplicateCurrentRound := len(probes) > 0 && len(ordered) > 0 && !now.IsZero() && !ordered[0].ObservedAt.IsZero() && ordered[0].ObservedAt.Equal(now)
	if duplicateCurrentRound {
		continuityRounds = ordered[1:]
	}

	active, activeKnown := snapshotActiveIPs(ordered)
	current := make(map[string]string)
	currentAnswered := 0
	for _, probe := range probes {
		if probe.IPAddress == "" {
			continue
		}
		if probe.Success && probe.Fingerprint != "" {
			current[probe.IPAddress] = probe.Fingerprint
			currentAnswered++
		}
	}
	if len(current) == 0 && len(ordered) > 0 {
		current = snapshotEndpointMap(ordered[0])
		for address, fingerprint := range current {
			if address != "" && fingerprint != "" {
				currentAnswered++
			}
		}
	}

	activePredecessors := make(map[string]struct{})
	retiredPredecessors := make(map[string]struct{})
	if activeKnown {
		for address, fingerprint := range current {
			if fingerprint != previousFingerprint {
				continue
			}
			if _, ok := active[address]; ok {
				activePredecessors[address] = struct{}{}
			} else {
				retiredPredecessors[address] = struct{}{}
			}
		}
	}
	divergence.ActivePredecessorEndpoints = sortedEvidenceSet(activePredecessors)
	divergence.RetiredPredecessorEndpoints = sortedEvidenceSet(retiredPredecessors)

	if activeKnown && len(active) > 0 {
		covered := 0
		for address := range active {
			if _, ok := current[address]; ok {
				covered++
			}
		}
		divergence.ActiveEndpointCoverage = roundEvidence(float64(covered) / float64(len(active)))
	} else if len(probes) > 0 {
		divergence.ActiveEndpointCoverage = roundEvidence(float64(currentAnswered) / float64(len(probes)))
	}

	// Continuity starts with the currently active predecessor endpoints and can
	// only continue while the exact same address is present in each historical
	// round's DNS consensus and still serves the predecessor leaf.
	continuing := make(map[string]struct{}, len(activePredecessors))
	for address := range activePredecessors {
		continuing[address] = struct{}{}
	}
	if !activeKnown || len(continuing) == 0 {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "current DNS consensus does not contain a predecessor endpoint")
	} else {
		divergence.ConsecutivePredecessorRounds = 1
		oldest := now
		resolverRounds := 0
		if duplicateCurrentRound && resolverRoundEvidence(ordered, 0) {
			resolverRounds++
		}
		for _, snapshot := range continuityRounds {
			addresses := snapshotEndpointMap(snapshot)
			roundActive, known := snapshotActiveIPsFor(snapshot)
			if !known {
				break
			}
			// Residue only accrues after the replacement: a round in which no
			// endpoint served anything but the predecessor predates it.
			// A round with one answering endpoint cannot show whether the
			// successor was present, so it neither counts nor ends continuity.
			if len(addresses) < 2 {
				continue
			}
			if !servesOtherLeaf(addresses, previousFingerprint) {
				break
			}
			kept := make(map[string]struct{})
			for address := range continuing {
				if addresses[address] == previousFingerprint {
					if _, ok := roundActive[address]; ok {
						kept[address] = struct{}{}
					}
				}
			}
			if len(kept) == 0 {
				break
			}
			continuing = kept
			divergence.ConsecutivePredecessorRounds++
			if !snapshot.ObservedAt.IsZero() && snapshot.ObservedAt.Before(oldest) {
				oldest = snapshot.ObservedAt
			}
			if resolverRoundEvidence([]models.MeasurementSnapshot{snapshot}, 0) {
				resolverRounds++
			}
		}
		divergence.ResolverConsistentRounds = resolverRounds
		if !oldest.IsZero() && !now.Before(oldest) {
			divergence.PredecessorSpanHours = roundEvidence(now.Sub(oldest).Hours())
		}
	}

	// Resolver evidence can still be useful even when continuity stops at the
	// first historical row. Count only rounds with an independent quorum.
	if divergence.ResolverConsistentRounds == 0 {
		for _, snapshot := range ordered {
			if snapshot.ResolverQuorum >= 2 && snapshot.ResolverAgreement >= 0.5 {
				divergence.ResolverConsistentRounds++
			}
		}
	}

	// A clean partition is only benign after it has persisted across independent
	// rounds. Without that horizon, do not suppress a possible partial rollout.
	benignPartition := stableMultiProviderPartition(*divergence) && divergence.IntraGroupConflicts == 0
	// The proven overlap (predecessor and another leaf both seen live) is
	// placed in the reference distribution of completed rollouts. "Stuck" is
	// the operator's alert share applied to that measured position.
	position := positionOfOverlap(divergence.PredecessorSpanHours)
	if position.known {
		divergence.ReferenceCompleted = position.completed
		divergence.ReferenceFinishedWithin = position.finishedWithin
		divergence.ReferenceShare = roundEvidence(position.share)
		divergence.AlertShare = position.alertShare
	}
	divergence.StrongEvidence = activeKnown && len(divergence.ActivePredecessorEndpoints) > 0 &&
		divergence.ConsecutivePredecessorRounds >= 2 && position.beyondAlert &&
		!benignPartition && !divergence.DualCertificateSplit

	if !activeKnown {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "active DNS consensus was not retained for the current round")
	}
	if len(divergence.ActivePredecessorEndpoints) == 0 && len(divergence.RetiredPredecessorEndpoints) > 0 {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "predecessor was observed only on a retired or non-consensus endpoint")
	}
	if len(divergence.ActivePredecessorEndpoints) > 0 && divergence.ConsecutivePredecessorRounds < 2 {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "the predecessor and another leaf were seen live together in only one round, so no overlap duration is proven yet")
	}
	switch {
	case len(divergence.ActivePredecessorEndpoints) == 0:
	case !position.known:
		divergence.MissingEvidence = append(divergence.MissingEvidence, "the reference distribution of completed rollouts is not computed yet, so the overlap cannot be placed")
	case position.alertShare <= 0:
		divergence.MissingEvidence = append(divergence.MissingEvidence, "no operator alert share is configured, so an open rollout is reported by its measured position only")
	case !position.beyondAlert:
		divergence.MissingEvidence = append(divergence.MissingEvidence, fmt.Sprintf("the proven overlap of %.1f hours is longer than %d of %d completed rollouts certainly took (%.1f%%), not beyond the configured %.0f%%", divergence.PredecessorSpanHours, position.finishedWithin, position.completed, position.share*100, position.alertShare*100))
	}
	if benignPartition {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "clean multi-provider partition remains a competing explanation")
	}
	divergence.MissingEvidence = uniqueEvidenceStrings(divergence.MissingEvidence)
	divergence.ReversalConditions = []string{
		"the same active endpoint serves the successor in a later round",
		"the predecessor leaves the active DNS consensus or only remains reachable as a retired address",
		"a clean stable multi-provider partition or valid dual-certificate pair is established",
	}
}

func servesOtherLeaf(assignment map[string]string, fingerprint string) bool {
	for _, leaf := range assignment {
		if leaf != "" && leaf != fingerprint {
			return true
		}
	}
	return false
}

func snapshotEndpointMap(snapshot models.MeasurementSnapshot) map[string]string {
	assignment := make(map[string]string)
	raw := strings.TrimSpace(snapshot.EndpointFingerprintsJSON)
	if raw == "" || raw == "null" || json.Unmarshal([]byte(raw), &assignment) != nil {
		return map[string]string{}
	}
	return assignment
}

func snapshotActiveIPs(snapshots []models.MeasurementSnapshot) (map[string]struct{}, bool) {
	if len(snapshots) == 0 {
		return nil, false
	}
	return snapshotActiveIPsFor(snapshots[0])
}

func snapshotActiveIPsFor(snapshot models.MeasurementSnapshot) (map[string]struct{}, bool) {
	var topology models.TopologySnapshot
	if strings.TrimSpace(snapshot.TopologyJSON) == "" || json.Unmarshal([]byte(snapshot.TopologyJSON), &topology) != nil {
		return nil, false
	}
	ips := topology.ConsensusIPs
	if len(ips) == 0 {
		ips = topology.PublicIPs
	}
	if len(ips) == 0 {
		return nil, false
	}
	active := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip != "" {
			active[ip] = struct{}{}
		}
	}
	return active, len(active) > 0
}

func resolverRoundEvidence(snapshots []models.MeasurementSnapshot, index int) bool {
	return index >= 0 && index < len(snapshots) && snapshots[index].ResolverQuorum >= 2 && snapshots[index].ResolverAgreement >= 0.5
}

func sortedEvidenceSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func roundEvidence(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}

func sortedSourceSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueEvidenceStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// DivergenceIsBenign reports whether the verdict describes an expected property
// of the deployment rather than a defect.
func divergenceIsBenign(verdict string) bool {
	switch verdict {
	case models.DivergenceIntentionalMultiCDN, models.DivergenceDualCertificate, models.DivergencePerEndpoint:
		return true
	default:
		return false
	}
}

func isDefectiveProbe(probe models.EndpointProbe, now time.Time) bool {
	for _, finding := range probe.Findings {
		if _, bad := defectiveFindingCodes[finding.Code]; bad {
			return true
		}
	}
	// Legacy probe rows predate per-endpoint validation findings; the retained
	// NotAfter still shows an endpoint serving an expired certificate.
	if probe.NotAfter != nil && now.After(*probe.NotAfter) {
		return true
	}
	return false
}

// providerGroup delegates to the shared allocation grouping so the detector and
// the analysis layer partition addresses identically.
func providerGroup(address string) string { return models.ProviderGroup(address) }

// groupSignature reduces an endpoint survey to "which provider served which
// certificates", discarding the individual addresses that a CDN rotates.
func groupSignature(probes []models.EndpointProbe) string {
	assignment := make(map[string]string, len(probes))
	for _, probe := range probes {
		if probe.Success && probe.Fingerprint != "" {
			assignment[probe.IPAddress] = probe.Fingerprint
		}
	}
	return models.ProviderAssignmentSignature(assignment)
}

// stableGroupRounds counts how many retained rounds carried the same
// provider-to-certificate assignment as the current one.
func stableGroupRounds(snapshots []models.MeasurementSnapshot, signature string) int {
	if signature == "" {
		return 0
	}
	matched := 0
	for _, snapshot := range snapshots {
		raw := strings.TrimSpace(snapshot.EndpointFingerprintsJSON)
		if raw == "" || raw == "null" {
			continue
		}
		assignment := make(map[string]string)
		if json.Unmarshal([]byte(raw), &assignment) != nil || len(assignment) < 2 {
			continue
		}
		if models.ProviderAssignmentSignature(assignment) == signature {
			matched++
		}
	}
	return matched
}

// probesFromSnapshot reconstructs a minimal endpoint survey from a measurement
// snapshot. Only the address and the certificate it served are recoverable, so
// the tests that need issuer, key algorithm or name coverage stay unresolved
// instead of being answered from missing data.
func probesFromSnapshot(snapshot models.MeasurementSnapshot) []models.EndpointProbe {
	raw := strings.TrimSpace(snapshot.EndpointFingerprintsJSON)
	if raw == "" || raw == "null" {
		return nil
	}
	assignment := make(map[string]string)
	if json.Unmarshal([]byte(raw), &assignment) != nil {
		return nil
	}
	probes := make([]models.EndpointProbe, 0, len(assignment))
	for address, fingerprint := range assignment {
		if address == "" || fingerprint == "" {
			continue
		}
		probes = append(probes, models.EndpointProbe{IPAddress: address, Success: true, Fingerprint: fingerprint})
	}
	sort.Slice(probes, func(left, right int) bool { return probes[left].IPAddress < probes[right].IPAddress })
	return probes
}

// divergenceEvidence renders the structural measurements that produced the
// verdict so a reader can check it without re-running the analysis.
func divergenceEvidence(divergence models.EndpointDivergence) []string {
	evidence := []string{
		itoaEvidence("endpoints_answered", divergence.EndpointsAnswered),
		itoaEvidence("distinct_leaves", divergence.DistinctLeaves),
		itoaEvidence("network_groups", divergence.NetworkGroups),
		itoaEvidence("intra_group_conflicts", divergence.IntraGroupConflicts),
		"clean_provider_partition=" + boolText(divergence.CleanPartition),
		"dual_certificate_split=" + boolText(divergence.DualCertificateSplit),
		"functionally_equivalent=" + boolText(divergence.FunctionallyEquivalent),
		itoaEvidence("stable_rounds", divergence.StableRounds),
		itoaEvidence("stable_address_rounds", divergence.StableAddressRounds),
		ftoaEvidence("stable_address_span_hours", divergence.StableAddressSpanHours),
		"independent_lineages=" + boolText(divergence.IndependentLineages),
		itoaEvidence("address_returns", divergence.AddressReturns),
		itoaEvidence("address_pools", divergence.AddressPools),
		itoaEvidence("unobservable_endpoints", len(divergence.UnobservableEndpoints)),
		itoaEvidence("distinct_issuers", divergence.DistinctIssuers),
		itoaEvidence("distinct_key_algorithms", divergence.DistinctKeyAlgos),
		"divergence_verdict=" + divergence.Verdict,
	}
	if divergence.CDN != nil {
		evidence = append(evidence,
			"cdn_completeness="+divergence.CDN.Completeness,
			"cdn_method="+divergence.CDN.Method,
			itoaEvidence("cdn_distinct_vendors", divergence.CDN.DistinctVendors),
			itoaEvidence("cdn_vendor_conflicts", divergence.CDN.VendorConflicts),
		)
	}
	if len(divergence.DefectiveEndpoints) > 0 {
		evidence = append(evidence, "defective_endpoints="+strings.Join(divergence.DefectiveEndpoints, ","))
	}
	if len(divergence.PredecessorEndpoints) > 0 {
		evidence = append(evidence,
			"predecessor_endpoints="+strings.Join(divergence.PredecessorEndpoints, ","),
			ftoaEvidence("predecessor_residue_hours", divergence.ResidueHours))
	}
	evidence = append(evidence,
		itoaEvidence("consecutive_predecessor_rounds", divergence.ConsecutivePredecessorRounds),
		ftoaEvidence("predecessor_span_hours", divergence.PredecessorSpanHours),
		itoaEvidence("resolver_consistent_rounds", divergence.ResolverConsistentRounds),
		ftoaEvidence("active_endpoint_coverage", divergence.ActiveEndpointCoverage),
		itoaEvidence("global_probe_rounds", divergence.GlobalProbeRounds),
		itoaEvidence("global_https_regions", len(divergence.GlobalHTTPSRegions)),
		itoaEvidence("global_predecessor_regions", len(divergence.GlobalPredecessorRegions)),
		itoaEvidence("global_consecutive_predecessor_rounds", divergence.GlobalConsecutivePredecessorRounds),
		ftoaEvidence("global_predecessor_span_hours", divergence.GlobalPredecessorSpanHours),
		itoaEvidence("global_defective_regions", len(divergence.GlobalDefectiveRegions)),
		"strong_evidence="+boolText(divergence.StrongEvidence))
	if len(divergence.ActivePredecessorEndpoints) > 0 {
		evidence = append(evidence, "active_predecessor_endpoints="+strings.Join(divergence.ActivePredecessorEndpoints, ","))
	}
	if len(divergence.RetiredPredecessorEndpoints) > 0 {
		evidence = append(evidence, "retired_predecessor_endpoints="+strings.Join(divergence.RetiredPredecessorEndpoints, ","))
	}
	if len(divergence.GlobalPredecessorEndpoints) > 0 {
		evidence = append(evidence, "global_predecessor_endpoints="+strings.Join(divergence.GlobalPredecessorEndpoints, ","))
	}
	return evidence
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
