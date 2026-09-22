package database

import (
	"encoding/json"

	"sort"
	"strings"
	"time"

	"ahclm/internal/models"
)

// propagationWindow is how long a certificate replacement is allowed to take to
// reach every sampled edge before the remaining predecessor is treated as stuck
// rather than in flight.
const propagationWindow = 24 * time.Hour

// A predecessor is only a strong rollout-failure signal when the same DNS
// active endpoint keeps serving it across independent rounds. A single old IP
// can be a retired edge, a stale direct probe, or a normal multi-CDN member.
const (
	minStrongPredecessorRounds = 3
	minStrongPredecessorSpan   = 24 * time.Hour
	minStrongResolverRounds    = 2
	minStrongActiveCoverage    = 0.5
	// A clean provider split is only an intentional multi-CDN explanation
	// after it persists across independent measurement rounds. A single round
	// can just be a rollout or a transient endpoint assignment.
	minStableMultiProviderRounds = 2
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
		sort.Strings(divergence.PredecessorEndpoints)
		if len(divergence.PredecessorEndpoints) > 0 && !replacedAt.IsZero() && now.After(replacedAt) {
			divergence.ResidueHours = round2(now.Sub(replacedAt).Hours())
		}
	}

	divergence.StableRounds = stableGroupRounds(snapshots, groupSignature(answered))
	measurePredecessorEvidence(&divergence, probes, snapshots, previousFingerprint, now)
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
	case vendorComplete && cdn.DistinctVendors >= 2 && cdn.CleanVendorSplit && divergence.StableRounds >= minStableMultiProviderRounds:
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
	case len(divergence.PredecessorEndpoints) > 0:
		return models.DivergencePropagating
	default:
		return models.DivergenceUndetermined
	}
}

func stableMultiProviderPartition(divergence models.EndpointDivergence) bool {
	return divergence.CleanPartition &&
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
	if len(divergence.PredecessorEndpoints) > 0 {
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
	divergence.StrongEvidence = activeKnown && len(divergence.ActivePredecessorEndpoints) > 0 &&
		divergence.ConsecutivePredecessorRounds >= minStrongPredecessorRounds &&
		divergence.PredecessorSpanHours >= minStrongPredecessorSpan.Hours() &&
		divergence.ResolverConsistentRounds >= minStrongResolverRounds &&
		divergence.ActiveEndpointCoverage >= minStrongActiveCoverage &&
		!benignPartition && !divergence.DualCertificateSplit

	if !activeKnown {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "active DNS consensus was not retained for the current round")
	}
	if len(divergence.ActivePredecessorEndpoints) == 0 && len(divergence.RetiredPredecessorEndpoints) > 0 {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "predecessor was observed only on a retired or non-consensus endpoint")
	}
	if divergence.ConsecutivePredecessorRounds < minStrongPredecessorRounds {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "same active endpoint did not retain the predecessor for three consecutive rounds")
	}
	if divergence.PredecessorSpanHours < minStrongPredecessorSpan.Hours() {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "predecessor continuity spans less than 24 hours")
	}
	if divergence.ResolverConsistentRounds < minStrongResolverRounds {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "fewer than two resolver-quorum rounds corroborate the active endpoint")
	}
	if divergence.ActiveEndpointCoverage < minStrongActiveCoverage {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "active endpoint coverage is below 50 percent")
	}
	if benignPartition {
		divergence.MissingEvidence = append(divergence.MissingEvidence, "clean multi-provider partition remains a competing explanation")
	}
	divergence.MissingEvidence = uniqueEvidenceStrings(divergence.MissingEvidence)
	divergence.ReversalConditions = []string{
		"the same active endpoint serves the successor in a later corroborated round",
		"the predecessor leaves the active DNS consensus or only remains reachable as a retired address",
		"a clean stable multi-provider partition or valid dual-certificate pair is established",
	}
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
	case models.DivergenceIntentionalMultiCDN, models.DivergenceDualCertificate:
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
		"strong_evidence="+boolText(divergence.StrongEvidence))
	if len(divergence.ActivePredecessorEndpoints) > 0 {
		evidence = append(evidence, "active_predecessor_endpoints="+strings.Join(divergence.ActivePredecessorEndpoints, ","))
	}
	if len(divergence.RetiredPredecessorEndpoints) > 0 {
		evidence = append(evidence, "retired_predecessor_endpoints="+strings.Join(divergence.RetiredPredecessorEndpoints, ","))
	}
	return evidence
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
