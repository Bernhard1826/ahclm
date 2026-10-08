package database

import (
	"strings"

	"ahclm/internal/models"
)

// Confidence in a causal reading must be a function of how well the retained
// evidence *discriminates* between the competing explanations, not of how many
// samples were taken. Repeating a measurement that cannot tell two hypotheses
// apart produces more data and no more certainty, so sample volume alone must
// never raise confidence.
//
// These helpers compute a ceiling from the independent channels that were
// actually available, and every hypothesis confidence is clamped to it.

var confidenceRank = map[string]int{"low": 0, "medium": 1, "high": 2}

func capConfidence(actual, ceiling string) string {
	actualRank, ok := confidenceRank[actual]
	if !ok {
		return ceiling
	}
	ceilingRank, ok := confidenceRank[ceiling]
	if !ok {
		return actual
	}
	if actualRank <= ceilingRank {
		return actual
	}
	return ceiling
}

// confidenceCeiling counts the independent things that had to agree before a
// causal reading could be believed:
//
//   - an external record of issuance (Certificate Transparency logs, a
//     handshake SCT, or a Merkle inclusion proof that the served leaf was logged),
//   - an endpoint survey wide enough to see more than one server,
//   - a numbering-authority identity (RDAP/ASN) for the answering addresses,
//   - CAA that authorizes or forbids the served issuer,
//   - DNSSEC-authenticated control-plane records,
//   - a discriminating test that returned a definite verdict rather than
//     "undetermined",
//   - a direct simultaneous observation rather than an inference over time.
//
// Fewer than two of those cannot support more than low confidence no matter how
// strongly a weighted score came out.
func confidenceCeiling(corroboration *models.EvidenceCorroboration, discriminated, directProof bool) string {
	if corroboration == nil {
		return "low"
	}
	independent := 0
	if corroboration.CTStatus == models.CTCorroborated || corroboration.SCTVerified || corroboration.SCTInclusionProofs > 0 {
		independent++
	}
	if corroboration.EndpointCoverage >= 0.5 {
		independent++
	}
	if corroboration.DirectoryStatus == models.DirectoryIdentified {
		independent++
	}
	if corroboration.CAAStatus == models.CAAAuthorized || corroboration.CAAStatus == models.CAAUnauthorized {
		independent++
	}
	if corroboration.DNSSECValidated {
		independent++
	}
	// A matching result from an external multi-region probe is independent of
	// this collector's local resolver and network. Mere remote reachability is
	// not enough: it must corroborate the same predecessor or locally validated
	// defective leaf.
	if corroboration.GlobalProbeRegions >= 2 && (corroboration.GlobalPredecessorRegions > 0 || corroboration.GlobalDefectiveRegions > 0) {
		independent++
	}
	if discriminated {
		independent++
	}
	if directProof {
		independent++
	}
	switch {
	case independent >= 3:
		return "high"
	case independent == 2:
		return "medium"
	default:
		return "low"
	}
}

// endpointCoverage is the share of probed addresses that actually answered,
// averaged over the retained rounds. A survey that never reaches a second
// endpoint cannot distinguish a deployment property from a sampling artifact,
// which is why it gates confidence rather than merely being reported.
func endpointCoverage(snapshots []models.MeasurementSnapshot) float64 {
	probed, answered := 0, 0
	for _, snapshot := range snapshots {
		probed += snapshot.EndpointCount
		answered += snapshot.SuccessfulEndpointCount
	}
	if probed == 0 {
		return 0
	}
	return round2(float64(answered) / float64(probed))
}

func latestResolverAgreement(snapshots []models.MeasurementSnapshot) float64 {
	if len(snapshots) == 0 {
		return 0
	}
	return snapshots[0].ResolverAgreement
}

// evidenceProvenance separates rows written by the current detection rules from
// rows written by a superseded generation. Detection rules have been tightened
// since the earliest rows were recorded, so a finding whose support is mostly
// legacy rows carries the older, weaker guarantees and must say so instead of
// silently inheriting the current rules' credibility.
func evidenceProvenance(rows []models.CertObservation) *models.EvidenceProvenance {
	provenance := &models.EvidenceProvenance{TotalEvents: len(rows)}
	for _, row := range rows {
		if strings.TrimSpace(row.DetectorVersion) == models.DetectorCurrent {
			provenance.CurrentEvents++
		} else {
			provenance.LegacyEvents++
		}
	}
	if provenance.TotalEvents > 0 {
		provenance.CurrentShare = round2(float64(provenance.CurrentEvents) / float64(provenance.TotalEvents))
	}
	provenance.LegacyDominated = provenance.TotalEvents > 0 && provenance.CurrentShare < 0.5
	return provenance
}
