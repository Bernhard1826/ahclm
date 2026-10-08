package database

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"ahclm/internal/models"
)

const maxChangeExhibits = 12

// attachInvestigation writes the operator-facing case file onto a diagnosis.
// For certificate diversity, frequent change and stale-after-topology-change
// the case file is a numbered proof: proven steps are direct measurements,
// inferred steps are reversible operational readings. The anomaly index keeps
// a compact evidence case (facts, no round dump); the on-demand evidence
// endpoint rebuilds the full round record.
func attachInvestigation(item models.Anomaly, context diagnosisContext, diagnosis *models.CauseDiagnosis) {
	if diagnosis == nil {
		return
	}
	diagnosis.Investigation = buildInvestigation(item, context, *diagnosis)
	if diagnosis.EvidenceCase == nil {
		diagnosis.EvidenceCase = buildCompactEvidenceCase(item, context, *diagnosis)
	} else if len(diagnosis.Investigation.Facts) > 0 {
		diagnosis.EvidenceCase.SupportingEvidence = uniqueEvidenceStrings(diagnosis.Investigation.Facts)
	}
}

func buildInvestigation(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis) *models.Investigation {
	investigation := &models.Investigation{
		FindingClass:     findingClassOf(diagnosis),
		Cause:            diagnosis.Summary,
		CauseLabel:       causeLabelOf(diagnosis),
		CauseCode:        diagnosis.PrimaryCode,
		CauseStatus:      diagnosis.CauseStatus,
		Confidence:       diagnosis.Confidence,
		MissingEvidence:  append([]string(nil), diagnosis.MeasurementPlan...),
		Facts:            investigationFacts(item, context, diagnosis),
		WhyThisCause:     whyThisCause(diagnosis),
		RuledOut:         ruledOutReadings(diagnosis),
		InternalEvidence: diagnosis.InternalEvidence,
	}
	if diagnosis.EvidenceCase != nil {
		investigation.MissingEvidence = uniqueEvidenceStrings(append(investigation.MissingEvidence, diagnosis.EvidenceCase.MissingEvidence...))
		investigation.Reversal = append([]string(nil), diagnosis.EvidenceCase.ReversalConditions...)
	} else if diagnosis.Divergence != nil {
		investigation.MissingEvidence = uniqueEvidenceStrings(append(investigation.MissingEvidence, diagnosis.Divergence.MissingEvidence...))
		investigation.Reversal = append([]string(nil), diagnosis.Divergence.ReversalConditions...)
	}
	if item.Type != "frequent_change" && item.Type != "early_renewal" && item.Type != "same_key" {
		if isTLSValidationType(item.Type) {
			investigation.ProviderGroups = tlsProviderExhibits(item, context)
		} else if !isCertificateConditionType(item.Type) {
			investigation.ProviderGroups = providerExhibits(item, context, diagnosis)
		}
	}
	if usesChangeSequence(item.Type) {
		investigation.ChangeSequence = changeExhibits(context)
		investigation.RelatedNames = relatedNameProbes(context)
	}
	if diagnosis.Divergence != nil && usesEndpointDiversity(item.Type) {
		investigation.CDN = diagnosis.Divergence.CDN
	}
	investigation.Certificates = certificateExhibits(context, investigation)
	investigation.Problem, investigation.WhyProblem = investigationProblem(item, context, diagnosis, investigation)
	if diagnosis.BenignExplanation != "" {
		investigation.Cause = diagnosis.BenignExplanation
	}
	if len(investigation.Reversal) == 0 && diagnosis.EvidenceCase != nil {
		investigation.Reversal = append([]string(nil), diagnosis.EvidenceCase.ReversalConditions...)
	}
	attachProof(investigation, item, context, diagnosis)
	investigation.Impact = buildFindingImpact(item, context, diagnosis, investigation)
	return investigation
}

func usesChangeSequence(code string) bool {
	switch code {
	case "frequent_change", "early_renewal", "same_key", models.ObsStaleAfterChange:
		return true
	default:
		return false
	}
}

func usesEndpointDiversity(code string) bool {
	switch code {
	case models.ObsDeploymentFailure, models.ObsStaleAfterChange:
		return true
	default:
		return isTLSValidationType(code)
	}
}

func investigationNeedsTLSLeaves(investigation *models.Investigation) bool {
	if investigation == nil {
		return false
	}
	if usesEndpointDiversity(investigation.CauseCode) {
		return true
	}
	switch investigation.CauseCode {
	case tlsCauseExpiredLeaf, tlsCauseNameMismatch, tlsCauseNonHTTPSIdentity, tlsCauseNotYetValid, tlsCauseLocalChain, tlsCauseProbeIncomplete:
		return true
	default:
		return len(investigation.ProviderGroups) > 0
	}
}

func attachProof(investigation *models.Investigation, item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis) {
	if investigation == nil {
		return
	}
	investigation.Proof, investigation.Inference = investigationProof(item, context, diagnosis, investigation)
	if item.Type == models.ObsDeploymentFailure || item.Type == models.ObsStaleAfterChange {
		investigation.Inference = dropOverlappingEvidence(investigation.Inference, investigation.Proof)
	}
	switch {
	case len(investigation.Proof) > 0 && len(investigation.Inference) == 0:
		investigation.ProofKind = "proven"
	case len(investigation.Proof) > 0 && len(investigation.Inference) > 0:
		investigation.ProofKind = "mixed"
	case len(investigation.Inference) > 0:
		investigation.ProofKind = "inferred"
	case diagnosis.CauseStatus == "established":
		investigation.ProofKind = "proven"
	case diagnosis.CauseStatus == "inferred":
		investigation.ProofKind = "inferred"
	default:
		investigation.ProofKind = "unestablished"
	}
}

func dropOverlappingEvidence(inferred, proven []models.InvestigationProofStep) []models.InvestigationProofStep {
	if len(inferred) == 0 || len(proven) == 0 {
		return inferred
	}
	seen := make(map[string]struct{})
	for _, step := range proven {
		for _, line := range step.Evidence {
			seen[line] = struct{}{}
		}
	}
	out := make([]models.InvestigationProofStep, 0, len(inferred))
	for _, step := range inferred {
		kept := make([]string, 0, len(step.Evidence))
		for _, line := range step.Evidence {
			if _, ok := seen[line]; ok {
				continue
			}
			kept = append(kept, line)
		}
		if len(kept) == 0 && strings.TrimSpace(step.Basis) != "" {
			if _, ok := seen[step.Basis]; !ok {
				kept = []string{step.Basis}
			}
		}
		if len(kept) == 0 {
			continue
		}
		step.Evidence = kept
		out = append(out, step)
	}
	return out
}

func investigationProof(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis, investigation *models.Investigation) (proven, inferred []models.InvestigationProofStep) {
	switch item.Type {
	case models.ObsDeploymentFailure:
		return diversityProof(diagnosis, investigation)
	case models.ObsStaleAfterChange:
		return staleProof(diagnosis, investigation)
	case "frequent_change":
		return frequentChangeProof(diagnosis, investigation)
	case "same_key":
		return sameKeyProof(diagnosis, investigation)
	case "early_renewal":
		return earlyRenewalProof(diagnosis, investigation)
	default:
		if isTLSValidationType(item.Type) {
			return tlsValidationProof(item, context, diagnosis, investigation)
		}
		if isCertificateConditionType(item.Type) {
			return certificateConditionProof(item, context, diagnosis, investigation)
		}
		return nil, nil
	}
}

func provenStep(label, claim string, evidence []string, basis string) models.InvestigationProofStep {
	return models.InvestigationProofStep{Kind: "proven", Label: label, Claim: claim, Evidence: measuredEvidence(evidence), Basis: basis}
}

func inferredStep(label, claim string, evidence []string, basis string) models.InvestigationProofStep {
	return models.InvestigationProofStep{Kind: "inferred", Label: label, Claim: claim, Evidence: measuredEvidence(evidence), Basis: basis}
}

func appendInferred(dst []models.InvestigationProofStep, label, claim string, evidence []string, basis string) []models.InvestigationProofStep {
	step := inferredStep(label, claim, evidence, basis)
	if len(step.Evidence) == 0 {
		return dst
	}
	return append(dst, step)
}

func measuredEvidence(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range uniqueEvidenceStrings(values) {
		if isNarrativeEvidence(value) {
			continue
		}
		out = append(out, value)
	}
	return out
}

func isNarrativeEvidence(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return true
	}
	for _, marker := range []string{
		"this is a problem",
		"this is not counted",
		"this is a suspected",
		"cannot reappear",
		"cannot explain",
		"falsif",
		"not observed on the control plane",
		"that operational sequence",
		"strong-evidence",
		"propagation window",
		"no endpoint divergence",
		"no churn shape",
		"missing comparison",
		"later round",
		"best-supported",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func diversityProof(diagnosis models.CauseDiagnosis, investigation *models.Investigation) (proven, inferred []models.InvestigationProofStep) {
	d := diagnosis.Divergence
	if d == nil {
		inferred = appendInferred(inferred,
			"Coverage",
			"Live certificate diversity cannot be read from this sample.",
			[]string{"Answering endpoints retained: 0. Distinct leaves retained: 0."},
			"An endpoint survey with at least two successful TLS answers is required.",
		)
		return proven, inferred
	}
	mixEvidence := answeringEndpointEvidence(investigation, 8)
	mixEvidence = append(mixEvidence, fmt.Sprintf("Round count of answering endpoints: %d. Distinct leaf fingerprints: %d.", d.EndpointsAnswered, d.DistinctLeaves))
	mixClaim := "The current measurement round served more than one leaf certificate."
	if d.DistinctLeaves < 2 {
		mixClaim = "The current measurement round served one leaf certificate."
	}
	proven = append(proven, provenStep(
		"Observed mix",
		mixClaim,
		mixEvidence,
		"Direct TLS probes in one round, keyed by endpoint address and leaf fingerprint.",
	))
	if d.IntraGroupConflicts > 0 {
		proven = append(proven, provenStep(
			"Same-network disagreement",
			"The mix is inside one provider network, so a between-provider split cannot explain it.",
			append(conflictingNetworkEvidence(investigation, d), fmt.Sprintf("Conflicting networks: %d of %d. Intra-network conflicts: %d.", d.IntraGroupConflicts, d.NetworkGroups, d.IntraGroupConflicts)),
			"IPv4 /16 and IPv6 /32 partition of answering addresses; named CDN prefixes when every endpoint maps to a published vendor.",
		))
	} else if d.NetworkGroups >= 2 {
		proven = append(proven, provenStep(
			"Between-provider split",
			"Each provider network served one certificate consistently.",
			append(providerLeafEvidence(investigation), fmt.Sprintf("Provider networks: %d. Intra-network conflicts: %d.", d.NetworkGroups, d.IntraGroupConflicts)),
			"The same partition used for multi-CDN: one leaf per network allocation.",
		))
	}
	if d.StableRounds >= 2 {
		proven = append(proven, provenStep(
			"Persistence",
			"The same network-to-certificate assignment held in earlier rounds.",
			[]string{
				fmt.Sprintf("Rounds in which each network served the same set of leaves: %d. This compares networks, not which address held which leaf.", d.StableRounds),
				fmt.Sprintf("Rounds in which every answering address served the same leaf as now: %d, spanning %.1f hours.", d.StableAddressRounds, d.StableAddressSpanHours),
				fmt.Sprintf("Resolver-consistent rounds retained: %d.", d.ResolverConsistentRounds),
			},
			"Compared by network allocation so CDN edge-address rotation does not reset the assignment.",
		))
	}
	if len(d.PooledEndpoints) > 0 {
		proven = append(proven, provenStep(
			"Several servers behind one address",
			"At least one address presented more than one leaf within a single round, so it fronts servers holding different certificates.",
			d.PooledEndpoints,
			"Repeated TLS handshakes to the same address in one round.",
		))
	}
	if len(d.DefectiveEndpoints) > 0 {
		proven = append(proven, provenStep(
			"Invalid leaf",
			"At least one sampled endpoint served a certificate that is not currently valid for this name.",
			defectiveEndpointEvidence(investigation, d.DefectiveEndpoints),
			"Hostname mismatch, NotBefore/NotAfter, or local chain validation on the captured chain.",
		))
	}
	if len(d.GlobalDefectiveRegions) > 0 {
		proven = append(proven, provenStep(
			"Cross-region validation failure",
			"Remote HTTPS probes also rejected the same leaf that local direct probes validated as defective.",
			[]string{
				"Latest retained multi-region HTTPS round covered: " + strings.Join(d.GlobalHTTPSRegions, ", ") + ".",
				"Regions matching a locally defective leaf fingerprint: " + strings.Join(d.GlobalDefectiveRegions, ", ") + ".",
			},
			"Remote probes follow their region's resolver path; the leaf fingerprint is matched to the local defective-leaf measurement.",
		))
	}
	if d.IndependentLineages && d.StableAddressRounds > 0 {
		proven = append(proven, provenStep(
			"Separate lineages",
			"No address was ever observed moving from one of the current leaves to another, so none of them is a predecessor.",
			append(answeringEndpointEvidence(investigation, 8), fmt.Sprintf("Rounds in which every answering address served the same leaf as now: %d, spanning %.1f hours.", d.StableAddressRounds, d.StableAddressSpanHours)),
			"Per-address sequence of served leaves across retained rounds.",
		))
	}
	switch diagnosis.PrimaryCode {
	case models.DivergenceIntraFleet:
		proven = append(proven, provenStep(
			"Conclusion",
			"This is intra-fleet inconsistency, not a deliberate multi-CDN split.",
			conflictingNetworkEvidence(investigation, d),
			"Multi-CDN requires one leaf per provider. Disagreement inside one allocation falsifies that.",
		))
	case models.DivergenceDefectiveEndpoint:
		proven = append(proven, provenStep(
			"Conclusion",
			"A sampled endpoint is serving a certificate that is not valid for this name.",
			defectiveEndpointEvidence(investigation, d.DefectiveEndpoints),
			"Validity is evaluated on the captured chain for the queried name.",
		))
	case models.DivergenceStuckRollout:
		if d.StrongEvidence {
			stuckEvidence := predecessorMeasurement(investigation, d)
			proven = append(proven, provenStep(
				"Stuck predecessor",
				"Active DNS still serves the replaced certificate, and the proven overlap is longer than the configured share of completed rollouts took.",
				stuckEvidence,
				"The predecessor fingerprint remains on a DNS-active address with resolver-quorum continuity.",
			))
			proven = append(proven, provenStep(
				"Conclusion",
				"The replacement did not reach every active endpoint.",
				stuckEvidence,
				"Stuck is the operator alert share applied to the measured position of the proven overlap among completed rollouts.",
			))
		} else {
			inferred = appendInferred(inferred,
				"Stuck rollout",
				fmt.Sprintf("The predecessor is still answering after %.1f hours, which is consistent with a stuck rollout.", d.ResidueHours),
				predecessorContinuityEvidence(d),
				"Strong-evidence gates require DNS-active continuity across independent rounds.",
			)
		}
	case models.DivergencePropagating:
		inferred = appendInferred(inferred,
			"Not yet settled",
			fmt.Sprintf("Predecessor and successor are both still reachable after %.1f hours.", d.ResidueHours),
			predecessorContinuityEvidence(d),
			"A stuck reading requires the proven overlap on an active DNS address to exceed the configured share of completed rollouts.",
		)
	case models.DivergenceUndetermined:
		inferred = appendInferred(inferred,
			"Structure not established",
			fmt.Sprintf("The retained sample is %d answering endpoint(s) across %d provider network(s) and %d stable round(s), which cannot separate a deliberate split from inconsistency.", d.EndpointsAnswered, d.NetworkGroups, d.StableRounds),
			append(answeringEndpointEvidence(investigation, 8), fmt.Sprintf("Answering endpoints: %d. Distinct leaves: %d. Provider networks: %d. Stable rounds: %d.", d.EndpointsAnswered, d.DistinctLeaves, d.NetworkGroups, d.StableRounds)),
			"A multi-CDN reading needs a clean between-provider partition that holds across rounds.",
		)
	case models.DivergenceIntentionalMultiCDN, models.DivergenceDualCertificate, models.DivergencePerEndpoint:
		proven = append(proven, provenStep("Conclusion", diagnosis.BenignExplanation, providerLeafEvidence(investigation), "Each provider or algorithm pair is internally consistent."))
	}
	return proven, inferred
}

func staleProof(diagnosis models.CauseDiagnosis, investigation *models.Investigation) (proven, inferred []models.InvestigationProofStep) {
	d := diagnosis.Divergence
	if d == nil {
		inferred = appendInferred(inferred,
			"Coverage",
			"A leftover predecessor cannot be read: no post-change endpoint-to-certificate map was retained.",
			[]string{"Endpoint-to-certificate map retained: 0 answering endpoints."},
			"A stale reading needs the post-change endpoint-to-certificate map.",
		)
		return proven, inferred
	}
	mixEvidence := answeringEndpointEvidence(investigation, 8)
	mixEvidence = append(mixEvidence, fmt.Sprintf("Answering endpoints: %d. Distinct leaves: %d.", d.EndpointsAnswered, d.DistinctLeaves))
	if d.DistinctLeaves >= 2 {
		proven = append(proven, provenStep(
			"Post-change mix",
			"After the DNS/IP-set change, sampled endpoints still serve more than one certificate.",
			mixEvidence,
			"Current-round TLS probes compared by leaf fingerprint.",
		))
	} else {
		proven = append(proven, provenStep(
			"Current leaf",
			"The current sampled endpoints serve one certificate.",
			mixEvidence,
			"Address-pool rotation without a leftover predecessor is not a stale certificate.",
		))
	}
	if len(d.ActivePredecessorEndpoints) > 0 {
		proven = append(proven, provenStep(
			"Active predecessor",
			"Active DNS still serves the predecessor certificate.",
			predecessorEndpointEvidence(investigation, d),
			"Those addresses are in the current resolver consensus and still present the replaced leaf.",
		))
	} else if len(d.RetiredPredecessorEndpoints) > 0 {
		proven = append(proven, provenStep(
			"Retired predecessor only",
			"The predecessor was observed only on addresses that are no longer in DNS consensus.",
			retiredPredecessorEvidence(investigation, d.RetiredPredecessorEndpoints),
			"A live stale edge requires the predecessor on an active DNS address.",
		))
	}
	if len(d.GlobalPredecessorRegions) > 0 {
		evidence := []string{
			"Latest retained multi-region HTTPS round covered: " + strings.Join(d.GlobalHTTPSRegions, ", ") + ".",
			"Regions that reached the predecessor leaf: " + strings.Join(d.GlobalPredecessorRegions, ", ") + ".",
			"Remote predecessor paths: " + strings.Join(d.GlobalPredecessorEndpoints, ", ") + ".",
		}
		if d.GlobalConsecutivePredecessorRounds >= 2 {
			evidence = append(evidence, fmt.Sprintf("The same regional resolver path retained the predecessor for %d global-probe rounds spanning %.1f hours.", d.GlobalConsecutivePredecessorRounds, d.GlobalPredecessorSpanHours))
		}
		proven = append(proven, provenStep(
			"Cross-region predecessor",
			"Remote HTTPS probes also reached the predecessor through their own regional resolver paths.",
			evidence,
			"Each remote probe reports the address it resolved and the leaf fingerprint it received; this corroborates reachability, not the CDN's internal configuration.",
		))
	}
	switch diagnosis.PrimaryCode {
	case models.DivergenceStuckRollout:
		if d.StrongEvidence {
			proven = append(proven, provenStep(
				"Conclusion",
				"A topology change left an active DNS endpoint on the replaced certificate for longer than the configured share of completed rollouts took.",
				predecessorMeasurement(investigation, d),
				"Stuck-rollout gates all passed: DNS-active predecessor, independent rounds, resolver quorum.",
			))
		} else {
			inferred = appendInferred(inferred,
				"Cutover lag",
				fmt.Sprintf("The predecessor is still visible after %.1f hours, with %d consecutive DNS-active predecessor round(s).", d.ResidueHours, d.ConsecutivePredecessorRounds),
				predecessorContinuityEvidence(d),
				"Continuity across independent DNS-active rounds is still incomplete.",
			)
		}
	case models.DivergencePropagating:
		inferred = appendInferred(inferred,
			"In-flight cutover",
			fmt.Sprintf("After the topology change, %d leaf(s) remain reachable and residue is %.1f hours.", d.DistinctLeaves, d.ResidueHours),
			predecessorContinuityEvidence(d),
			"A stuck reading waits for the proven overlap to exceed the configured share of completed rollouts.",
		)
	case "dns_cutover_before_tls_deployment":
		inferred = appendInferred(inferred,
			"DNS moved first",
			"Current DNS answers serve the successor while retired addresses still serve the predecessor, so the address set and the certificate assignment moved together.",
			append(retiredPredecessorEvidence(investigation, d.RetiredPredecessorEndpoints), predecessorContinuityEvidence(d)...),
			"Inferred from the coincidence of DNS and TLS assignment changes.",
		)
	case models.DivergenceIntraFleet, models.DivergenceDefectiveEndpoint:
		proven = append(proven, provenStep(
			"Conclusion",
			"Post-change endpoints do not agree on a currently valid certificate for the name.",
			append(conflictingNetworkEvidence(investigation, d), defectiveEndpointEvidence(investigation, d.DefectiveEndpoints)...),
			"Validity and assignment are taken from the post-change survey.",
		))
	default:
		if d.DistinctLeaves < 2 && len(d.ActivePredecessorEndpoints) == 0 {
			proven = append(proven, provenStep(
				"Conclusion",
				"This is address-pool rotation, not a stale certificate after topology change.",
				append(answeringEndpointEvidence(investigation, 8), fmt.Sprintf("Distinct leaves: %d. Active predecessors: %d. Retired predecessors: %d.", d.DistinctLeaves, len(d.ActivePredecessorEndpoints), len(d.RetiredPredecessorEndpoints))),
				"A DNS answer-set difference without a leftover predecessor is pool rotation.",
			))
		} else {
			inferred = appendInferred(inferred,
				"Not established",
				fmt.Sprintf("The post-change sample has %d distinct leaf(s), %d active predecessor(s) and %d retired predecessor(s).", d.DistinctLeaves, len(d.ActivePredecessorEndpoints), len(d.RetiredPredecessorEndpoints)),
				predecessorContinuityEvidence(d),
				"A stale proof needs the predecessor fingerprint on a DNS-consensus address.",
			)
		}
	}
	return proven, inferred
}

func frequentChangeProof(diagnosis models.CauseDiagnosis, investigation *models.Investigation) (proven, inferred []models.InvestigationProofStep) {
	s := diagnosis.ChurnShape
	if s == nil {
		inferred = appendInferred(inferred,
			"Coverage",
			"Replacement in time cannot be read: no retained change sequence was attached.",
			[]string{"Retained change rows with a churn shape: 0."},
			"Replacement in time needs consecutive scans from the same address.",
		)
		return proven, inferred
	}
	proven = append(proven, provenStep(
		"Counted differences",
		"Monitoring recorded repeated leaf-fingerprint differences.",
		[]string{
			fmt.Sprintf("Counted fingerprint differences: %d.", s.ChangeEvents),
			fmt.Sprintf("Distinct leaves: %d.", s.DistinctLeaves),
			fmt.Sprintf("Replacement floor after removing revisits: %d.", s.EffectiveReplacements),
		},
		"Each change row is a fingerprint difference between consecutive successful scans.",
	))
	endpointEvidence := []string{
		fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges),
		fmt.Sprintf("Different-address comparisons: %d.", s.CrossEndpointChanges),
		fmt.Sprintf("Change rows with no serving address: %d.", s.UnknownEndpointChanges),
	}
	endpointEvidence = append(endpointEvidence, changeRelationEvidence(investigation, "same_endpoint", 6)...)
	if s.SameEndpointChanges > 0 {
		proven = append(proven, provenStep(
			"Endpoint comparison",
			"Replacement in time is proven on the same address.",
			endpointEvidence,
			"A replacement is only proven when the address that served the new leaf is the address that served the previous one.",
		))
	} else {
		proven = append(proven, provenStep(
			"Endpoint comparison",
			"The counted differences were not shown to be replacements on the same address.",
			endpointEvidence,
			"Without a same-address comparison, sampling another server cannot be separated from replacement in time.",
		))
	}
	if s.RevisitEvents > 0 {
		proven = append(proven, provenStep(
			"Revisits",
			"A previously seen leaf came back, so the counter is sampling concurrently deployed certificates, not finishing a lifetime.",
			[]string{fmt.Sprintf("Revisit events in the retained sequence: %d.", s.RevisitEvents)},
			"The change sequence is not monotone.",
		))
	}
	if s.CoexistenceProofs > 0 {
		proven = append(proven, provenStep(
			"Same-round coexistence",
			"Predecessor and successor were observed in the same round, which falsifies replacement in time.",
			append([]string{fmt.Sprintf("Rounds that captured both leaves at once: %d.", s.CoexistenceProofs)}, changeRelationEvidence(investigation, "coexisting", 4)...),
			"Direct observation in one endpoint survey.",
		))
	}
	if s.SameEndpointChanges > 0 && s.MedianRemainingDays > 0 {
		proven = append(proven, provenStep(
			"Remaining life at replacement",
			"When the same address swapped leaves, the outgoing certificate still had unused lifetime.",
			[]string{
				fmt.Sprintf("Median remaining life at replacement: %d day(s).", s.MedianRemainingDays),
				fmt.Sprintf("Median issuance age when served: %d day(s).", s.MedianIssuanceAgeDays),
				fmt.Sprintf("Median certificate lifetime: %d day(s).", s.MedianValidityDays),
			},
			"NotAfter minus observation time, and NotBefore versus observation time, on the retained certificates.",
		))
	}
	lifeEvidence := append([]string{
		fmt.Sprintf("Same-endpoint replacements: %d.", s.SameEndpointChanges),
		fmt.Sprintf("Median remaining life: %d day(s).", s.MedianRemainingDays),
		fmt.Sprintf("Median issuance age: %d day(s).", s.MedianIssuanceAgeDays),
		fmt.Sprintf("Median lifetime: %d day(s).", s.MedianValidityDays),
	}, changeRelationEvidence(investigation, "same_endpoint", 6)...)
	if transitions := transitionIdentityEvidence(investigation, "same_endpoint", 6); len(transitions) > 0 {
		proven = append(proven, provenStep(
			"Certificate-content deltas",
			"The retained same-address replacements include the following observable certificate-content changes.",
			transitions,
			"Issuer, common name, key algorithm, public key and SAN sets compared from the predecessor and successor leaves.",
		))
		lifeEvidence = append(lifeEvidence, transitions...)
	}
	if related := relatedNameMeasurementEvidence(investigation, 8); len(related) > 0 {
		proven = append(proven, provenStep(
			"Active checks of changed SAN names",
			"The monitor actively resolved and contacted the following names that entered or left the certificate SAN set.",
			related,
			"Multi-resolver DNS, SNI TLS and bounded direct endpoint probes collected after the SAN transitions.",
		))
	}
	if transient := transientRelatedNameEvidence(investigation, 8); len(transient) > 0 {
		inferred = appendInferred(inferred,
			"Transient-name pattern",
			"Names that changed the root certificate are now absent from public DNS after appearing and disappearing in certificate transitions; this supports a temporary-name workflow, but does not identify the private system that created it.",
			transient,
			"A current DNS absence cannot reconstruct the deleted record or prove a Git/CI source.",
		)
	}
	switch diagnosis.PrimaryCode {
	case "concurrent_multi_certificate_pool":
		proven = append(proven, provenStep("Conclusion", diagnosis.BenignExplanation, []string{fmt.Sprintf("%d revisit(s); replacement floor %d.", s.RevisitEvents, s.EffectiveReplacements)}, "Revisits or same-round coexistence falsify frequent replacement."))
	case "short_lived_certificate_automation":
		proven = append(proven, provenStep("Conclusion", diagnosis.BenignExplanation, []string{fmt.Sprintf("Median lifetime %d day(s); replacements per lifetime period %.2f.", s.MedianValidityDays, s.ReplacementsPerValidityPeriod)}, "Replacement cadence matches the certificates' own short validity."))
	case "preissued_rolling_pipeline":
		if diagnosis.CauseStatus == "established" {
			proven = append(proven, provenStep(
				"Conclusion",
				"A pre-issued inventory is being rolled forward: each day a different already-old leaf appears near expiry.",
				lifeEvidence,
				"Same-address replacement plus remaining-life and issuance-age on those leaves.",
			))
		} else {
			inferred = appendInferred(inferred,
				"Pre-issued pipeline",
				fmt.Sprintf("Served leaves are already %d day(s) old with %d day(s) left, which matches a rolling inventory rather than one certificate finishing its life.", s.MedianIssuanceAgeDays, s.MedianRemainingDays),
				[]string{
					fmt.Sprintf("Counted fingerprint differences: %d.", s.ChangeEvents),
					fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges),
					fmt.Sprintf("Change rows with no serving address: %d.", s.UnknownEndpointChanges),
					fmt.Sprintf("Median remaining life: %d day(s).", s.MedianRemainingDays),
					fmt.Sprintf("Median issuance age: %d day(s).", s.MedianIssuanceAgeDays),
					fmt.Sprintf("Median lifetime: %d day(s).", s.MedianValidityDays),
				},
				"A later round that records the serving address can confirm or overturn it.",
			)
		}
	case "automated_renewal_policy":
		if diagnosis.CauseStatus == "established" {
			proven = append(proven, provenStep(
				"Conclusion",
				"A still-fresh certificate is being re-issued at replacement time instead of being used for most of its lifetime.",
				lifeEvidence,
				"Same-address replacement plus remaining-life and issuance-age on those leaves.",
			))
		} else {
			inferred = appendInferred(inferred,
				"Replacement-time automation",
				fmt.Sprintf("Replacement-time leaves still have %d of %d day(s) left and issuance age %d, which matches extra issuance of a still-fresh certificate.", s.MedianRemainingDays, s.MedianValidityDays, s.MedianIssuanceAgeDays),
				[]string{
					fmt.Sprintf("Counted fingerprint differences: %d.", s.ChangeEvents),
					fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges),
					fmt.Sprintf("Change rows with no serving address: %d.", s.UnknownEndpointChanges),
					fmt.Sprintf("Median remaining life: %d day(s).", s.MedianRemainingDays),
					fmt.Sprintf("Median issuance age: %d day(s).", s.MedianIssuanceAgeDays),
					fmt.Sprintf("Median lifetime: %d day(s).", s.MedianValidityDays),
				},
				"A later same-endpoint comparison can confirm or overturn it.",
			)
		}
	case "incident_driven_reissue":
		triggerEvidence := primaryHypothesisEvidence(diagnosis, "incident_driven_reissue")
		if diagnosis.CauseStatus == "established" {
			proven = append(proven, provenStep(
				"Revocation or emergency trigger",
				"A retained revocation or CA emergency-renewal signal is associated with this replacement sequence.",
				triggerEvidence,
				"Only retained revocation status or ARI emergency observations can name this trigger.",
			))
			inferred = appendInferred(inferred,
				"Private cause not exposed",
				"The trigger signal does not establish why the certificate was revoked or which internal controller performed every later replacement.",
				triggerEvidence,
				"Revocation records and ARI expose a status signal, not the operator's incident report or deployment logs.",
			)
		}
	case "ca_or_policy_migration", "edge_or_deployment_rollout":
		if diagnosis.CauseStatus == "established" {
			proven = append(proven, provenStep("Conclusion", diagnosis.PrimaryLabel+" follows from same-endpoint replacements plus the issuer or name fields on those leaves.", []string{fmt.Sprintf("Same-endpoint replacements: %d.", s.SameEndpointChanges), fmt.Sprintf("Issuer unchanged in %.0f%% of those replacements.", s.SameIssuerFraction*100), fmt.Sprintf("Name unchanged in %.0f%% of those replacements.", s.SameNameFraction*100)}, "Identity fields are read from the retained certificates."))
		} else {
			inferred = appendInferred(inferred, diagnosis.PrimaryLabel, fmt.Sprintf("Issuer unchanged in %.0f%% and name unchanged in %.0f%% of the counted replacements, with %d same-address comparison(s).", s.SameIssuerFraction*100, s.SameNameFraction*100, s.SameEndpointChanges), []string{
				fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges),
				fmt.Sprintf("Change rows with no serving address: %d.", s.UnknownEndpointChanges),
				fmt.Sprintf("Issuer unchanged: %.0f%%.", s.SameIssuerFraction*100),
				fmt.Sprintf("Name unchanged: %.0f%%.", s.SameNameFraction*100),
			}, "Cause status is inferred.")
		}
	case "replacement_mechanism_unestablished":
		proven = append(proven, provenStep("Replacement in time", "Successive samples from the same endpoint served different certificates.", []string{fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges)}, "Same address, different fingerprint."))
		inferred = appendInferred(inferred, "Process unnamed", fmt.Sprintf("Remaining life %d day(s), issuance age %d day(s) and issuer unchanged in %.0f%% do not match a named process.", s.MedianRemainingDays, s.MedianIssuanceAgeDays, s.SameIssuerFraction*100), []string{
			fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges),
			fmt.Sprintf("Median remaining life: %d day(s).", s.MedianRemainingDays),
			fmt.Sprintf("Median issuance age: %d day(s).", s.MedianIssuanceAgeDays),
			fmt.Sprintf("Issuer unchanged: %.0f%%.", s.SameIssuerFraction*100),
		}, "No tight remaining-life window, staggered inventory, or fresh-at-replacement signature.")
	case "endpoint_attribution_unavailable", "insufficient_longitudinal_evidence":
		inferred = appendInferred(inferred, "Not established", fmt.Sprintf("%d counted difference(s) have no serving address, so they cannot be attributed to one endpoint.", s.UnknownEndpointChanges), []string{
			fmt.Sprintf("Counted fingerprint differences: %d.", s.ChangeEvents),
			fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges),
			fmt.Sprintf("Change rows with no serving address: %d.", s.UnknownEndpointChanges),
		}, "Frequent change is not proven without a same-address replacement.")
	default:
		if s.SameEndpointChanges > 0 {
			proven = append(proven, provenStep("Replacement in time", "Successive samples from the same endpoint served different certificates.", []string{fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges)}, "Same address, different fingerprint."))
		} else {
			inferred = appendInferred(inferred, "Not established", fmt.Sprintf("Same-address comparisons are %d of %d counted differences, so replacement versus sampling cannot be separated.", s.SameEndpointChanges, s.ChangeEvents), []string{
				fmt.Sprintf("Counted fingerprint differences: %d.", s.ChangeEvents),
				fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges),
				fmt.Sprintf("Change rows with no serving address: %d.", s.UnknownEndpointChanges),
			}, "Replacement in time requires the serving address on consecutive scans.")
		}
	}
	return proven, inferred
}

func primaryHypothesisEvidence(diagnosis models.CauseDiagnosis, code string) []string {
	for _, hypothesis := range diagnosis.Hypotheses {
		if hypothesis.Code == code {
			return measuredEvidence(hypothesis.Evidence)
		}
	}
	return nil
}

func sameKeyProof(diagnosis models.CauseDiagnosis, investigation *models.Investigation) (proven, inferred []models.InvestigationProofStep) {
	pairEvidence := sameKeyPairEvidence(investigation, diagnosis)
	s := diagnosis.ChurnShape
	if len(pairEvidence) == 0 && (s == nil || s.ChangeEvents == 0) {
		inferred = appendInferred(inferred,
			"Coverage",
			"Same-key replacement cannot be read: no retained pair has both leaf fingerprints and both SPKI fingerprints.",
			[]string{"Retained same-key pairs: 0."},
			"A same-key reading needs previous and current leaf fingerprints plus previous and current SPKI fingerprints.",
		)
		return proven, inferred
	}
	leafEvidence := append([]string{}, pairEvidence...)
	if s != nil {
		leafEvidence = append(leafEvidence, fmt.Sprintf("Same-key pairs: %d. Distinct leaves: %d.", s.ChangeEvents, s.DistinctLeaves))
	}
	proven = append(proven, provenStep(
		"Leaf changed",
		"A later scan served a different leaf certificate than the previous scan.",
		leafEvidence,
		"Leaf fingerprints compared between consecutive successful scans.",
	))
	spkiEvidence := append([]string{}, pairEvidence...)
	if s != nil {
		spkiEvidence = append(spkiEvidence, fmt.Sprintf("Distinct SPKI fingerprint(s) across those pairs: %d.", s.DistinctSPKIs))
	}
	proven = append(proven, provenStep(
		"SPKI unchanged",
		"Those two leaves share one SPKI fingerprint, so the public key did not rotate.",
		spkiEvidence,
		"SPKI fingerprints taken from the retained certificates or the replacement row.",
	))
	addressEvidence := append([]string{}, pairEvidence...)
	if s != nil {
		addressEvidence = append(addressEvidence,
			fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges),
			fmt.Sprintf("Different-address comparisons: %d.", s.CrossEndpointChanges),
			fmt.Sprintf("Pairs with no serving address: %d.", s.UnknownEndpointChanges),
			fmt.Sprintf("Same-address pairs without issuance dates: %d.", s.UndatedEndpointChanges),
		)
	}
	if s != nil && s.SameEndpointChanges > 0 {
		proven = append(proven, provenStep(
			"Same address",
			"The new leaf was served from the same address as the previous leaf.",
			addressEvidence,
			"Replacement in time is only proven when consecutive scans share the serving address.",
		))
	} else if s != nil && s.CrossEndpointChanges > 0 {
		proven = append(proven, provenStep(
			"Different addresses",
			"The new leaf was served from a different address than the previous leaf.",
			addressEvidence,
			"Consecutive scans recorded both serving addresses, and they differ.",
		))
	} else {
		proven = append(proven, provenStep(
			"Serving address",
			"The serving address was not retained on those pairs, so replacement in time is not proven.",
			addressEvidence,
			"Without the previous and current address, concurrent deployment cannot be separated from replacement.",
		))
	}
	lifeEvidence := append([]string{}, pairEvidence...)
	if s != nil {
		lifeEvidence = append(lifeEvidence,
			fmt.Sprintf("Median successor remaining life: %d day(s).", s.MedianRemainingDays),
			fmt.Sprintf("Median successor issuance age: %d day(s).", s.MedianIssuanceAgeDays),
		)
	}
	switch diagnosis.PrimaryCode {
	case "concurrent_same_key":
		inferred = appendInferred(inferred,
			"Concurrent leaves",
			fmt.Sprintf("Predecessor and successor that share one SPKI were observed in the same round (%d coexistence proof(s)).", valueOr(s, func(shape *models.ChurnShape) int { return shape.CoexistenceProofs })),
			append(pairEvidence, coexistenceCount(s)...),
			"Same-round observation of two leaves is concurrent deployment, not a replacement that kept the key.",
		)
	case "same_key_reissue":
		if diagnosis.CauseStatus == "established" {
			proven = append(proven, provenStep(
				"Conclusion",
				"The successor leaf was served with the predecessor public key.",
				pairEvidence,
				"Different leaf fingerprints, identical SPKI fingerprints, same serving address.",
			))
			if s != nil && (s.MedianRemainingDays > 0 || s.MedianIssuanceAgeDays >= 0) && len(lifeEvidence) > 0 {
				inferred = appendInferred(inferred,
					"Key reused on a new leaf",
					fmt.Sprintf("The successor still had %d day(s) remaining and issuance age %d day(s) when it was served, so a new leaf was issued or deployed without rotating the public key.", s.MedianRemainingDays, s.MedianIssuanceAgeDays),
					lifeEvidence,
					"Remaining life is NotAfter minus observation time; issuance age is observation time minus NotBefore.",
				)
			}
		} else {
			inferred = appendInferred(inferred,
				"Shared SPKI without a serving address",
				fmt.Sprintf("Leaf fingerprints differ while SPKI fingerprints match on %d pair(s); serving address missing on %d.", valueOr(s, func(shape *models.ChurnShape) int { return shape.ChangeEvents }), valueOr(s, func(shape *models.ChurnShape) int { return shape.UnknownEndpointChanges })),
				addressEvidence,
				"The shared SPKI is measured. Replacement in time waits for the serving address on consecutive scans.",
			)
		}
	}
	return proven, inferred
}

func coexistenceCount(shape *models.ChurnShape) []string {
	if shape == nil {
		return nil
	}
	return []string{fmt.Sprintf("Same-round coexistence proofs: %d.", shape.CoexistenceProofs)}
}

func valueOr(shape *models.ChurnShape, read func(*models.ChurnShape) int) int {
	if shape == nil {
		return 0
	}
	return read(shape)
}

func sameKeyPairEvidence(investigation *models.Investigation, diagnosis models.CauseDiagnosis) []string {
	out := make([]string, 0, 8)
	certs := map[string]models.CertificateExhibit{}
	if investigation != nil {
		for _, cert := range investigation.Certificates {
			certs[cert.Fingerprint] = cert
		}
		for _, change := range investigation.ChangeSequence {
			previous := certs[change.PreviousFingerprint]
			current := certs[change.Fingerprint]
			previousSPKI := firstNonEmpty(change.PreviousSPKIFingerprint, previous.SPKIFingerprint)
			currentSPKI := firstNonEmpty(change.SPKIFingerprint, current.SPKIFingerprint)
			if previousSPKI == "" || currentSPKI == "" || previousSPKI != currentSPKI {
				continue
			}
			line := fmt.Sprintf("%s leaf %s → %s; SPKI %s",
				change.ObservedAt.UTC().Format(time.RFC3339),
				shortProofFP(change.PreviousFingerprint),
				shortProofFP(change.Fingerprint),
				shortProofFP(currentSPKI),
			)
			switch {
			case change.Relation == "same_endpoint" && change.IPAddress != "":
				line += "; same address " + change.IPAddress
			case change.PreviousIP != "" && change.IPAddress != "":
				line += "; addresses " + change.PreviousIP + " → " + change.IPAddress
			case change.IPAddress != "":
				line += "; serving address " + change.IPAddress
			default:
				line += "; serving address not retained"
			}
			if change.DaysUntilExpiry > 0 {
				line += fmt.Sprintf("; successor remaining life %d day(s)", change.DaysUntilExpiry)
			}
			out = append(out, line)
		}
	}
	if len(out) == 0 && len(diagnosis.Hypotheses) > 0 {
		out = append(out, diagnosis.Hypotheses[0].Evidence...)
	}
	return measuredEvidence(out)
}

func earlyRenewalProof(diagnosis models.CauseDiagnosis, investigation *models.Investigation) (proven, inferred []models.InvestigationProofStep) {
	pairEvidence := earlyRenewalPairEvidence(investigation, diagnosis)
	s := diagnosis.ChurnShape
	if len(pairEvidence) == 0 && (s == nil || s.SameEndpointChanges == 0 && s.CrossEndpointChanges == 0 && s.UnknownEndpointChanges == 0) {
		inferred = appendInferred(inferred,
			"Coverage",
			"Early renewal cannot be read: no retained replacement has a predecessor NotAfter at observation time.",
			[]string{"Retained predecessor NotAfter comparisons: 0."},
			"Early renewal needs the predecessor NotAfter, the observation time, and the serving address.",
		)
		return proven, inferred
	}
	lifeEvidence := append([]string{}, pairEvidence...)
	if s != nil {
		lifeEvidence = append(lifeEvidence, fmt.Sprintf("Predecessor remaining life at replacement: %d day(s).", s.MedianRemainingDays))
		if s.MedianValidityDays > 0 {
			lifeEvidence = append(lifeEvidence, fmt.Sprintf("Predecessor lifetime: %d day(s).", s.MedianValidityDays))
		}
	}
	addressEvidence := append([]string{}, pairEvidence...)
	if s != nil {
		addressEvidence = append(addressEvidence,
			fmt.Sprintf("Same-address comparisons: %d.", s.SameEndpointChanges),
			fmt.Sprintf("Different-address comparisons: %d.", s.CrossEndpointChanges),
			fmt.Sprintf("Pairs with no serving address: %d.", s.UnknownEndpointChanges),
			fmt.Sprintf("Same-address pairs without issuance dates: %d.", s.UndatedEndpointChanges),
		)
	}
	transitionEvidence := transitionIdentityEvidence(investigation, "same_endpoint", 6)
	relatedNameEvidence := relatedNameMeasurementEvidence(investigation, 8)
	transientNameEvidence := transientRelatedNameEvidence(investigation, 8)
	switch diagnosis.PrimaryCode {
	case "early_renewal_replacement":
		proven = append(proven, provenStep(
			"Predecessor remaining life",
			fmt.Sprintf("The predecessor still had more than 30 days remaining when it was replaced (%d day(s)).", valueOr(s, func(shape *models.ChurnShape) int { return shape.MedianRemainingDays })),
			lifeEvidence,
			"Predecessor remaining life is predecessor NotAfter minus the observation time of the replacement.",
		))
		proven = append(proven, provenStep(
			"Same address",
			"The new leaf was served from the same address as the previous leaf.",
			addressEvidence,
			"Replacement in time is only proven when consecutive scans share the serving address.",
		))
		proven = append(proven, provenStep(
			"Conclusion",
			"This is an early replacement: a still-valid predecessor was retired more than 30 days before its NotAfter on the same address.",
			pairEvidence,
			"Predecessor remaining life > 30 days and same serving address.",
		))
		if len(transitionEvidence) > 0 {
			proven = append(proven, provenStep(
				"What changed in the replacement",
				"The predecessor and successor differ in the retained certificate fields below; this identifies the externally observable change, not the private actor that requested it.",
				transitionEvidence,
				"Issuer, common name, key algorithm, public key and SAN sets compared from the two retained leaves.",
			))
		}
		if len(relatedNameEvidence) > 0 {
			proven = append(proven, provenStep(
				"Active checks of changed SAN names",
				"The monitor actively resolved and contacted names that entered or left the replacement certificate SAN set.",
				relatedNameEvidence,
				"Multi-resolver DNS, SNI TLS and bounded direct endpoint probes collected after the SAN transitions.",
			))
		}
		if len(transientNameEvidence) > 0 {
			inferred = appendInferred(inferred,
				"Transient-name pattern",
				"A changed SAN name is now absent from public DNS after entering and leaving the certificate; this supports a temporary-name workflow but cannot identify the private system that created it.",
				transientNameEvidence,
				"Current DNS absence cannot reconstruct the deleted record or prove a Git/CI source.",
			)
		}
		if s != nil && s.MedianIssuanceAgeDays >= 0 {
			inferred = appendInferred(inferred,
				"New leaf at replacement time",
				fmt.Sprintf("The successor's issuance age at observation was %d day(s), so a new leaf was served while the predecessor still had %d day(s) remaining.", s.MedianIssuanceAgeDays, s.MedianRemainingDays),
				append(pairEvidence, fmt.Sprintf("Successor issuance age: %d day(s).", s.MedianIssuanceAgeDays)),
				"Issuance age is observation time minus successor NotBefore.",
			)
		}
	case "concurrent_multi_certificate_pool":
		proven = append(proven, provenStep(
			"Different addresses",
			"The two leaves were observed on different addresses or in the same round.",
			addressEvidence,
			"Concurrent deployment is not a replacement in time.",
		))
		proven = append(proven, provenStep(
			"Conclusion",
			"This is not early renewal: the predecessor remaining life is from a concurrent leaf, not a same-address replacement.",
			lifeEvidence,
			"Early renewal requires a same-address replacement.",
		))
	case "short_lived_certificate_automation":
		proven = append(proven, provenStep(
			"Short predecessor lifetime",
			fmt.Sprintf("The predecessor lifetime is %d day(s), which is not a long-lived certificate being retired early.", valueOr(s, func(shape *models.ChurnShape) int { return shape.MedianValidityDays })),
			lifeEvidence,
			"Predecessor lifetime is NotAfter minus NotBefore.",
		))
	default:
		if s != nil && s.UnknownEndpointChanges > 0 {
			inferred = appendInferred(inferred,
				"Address not retained",
				fmt.Sprintf("%d leaf change(s) have a predecessor with more than 30 days remaining, but the serving address was not retained.", s.UnknownEndpointChanges),
				addressEvidence,
				"Without the serving address, concurrent deployment cannot be separated from replacement.",
			)
		} else {
			inferred = appendInferred(inferred,
				"Not established",
				"No retained same-address replacement has a predecessor remaining life greater than 30 days.",
				append(lifeEvidence, addressEvidence...),
				"Early renewal is predecessor NotAfter minus observation time, on the same serving address.",
			)
		}
	}
	return proven, inferred
}

func earlyRenewalPairEvidence(investigation *models.Investigation, diagnosis models.CauseDiagnosis) []string {
	if len(diagnosis.Hypotheses) > 0 && len(diagnosis.Hypotheses[0].Evidence) > 0 {
		return measuredEvidence(diagnosis.Hypotheses[0].Evidence)
	}
	out := make([]string, 0, 8)
	if investigation == nil {
		return nil
	}
	certs := map[string]models.CertificateExhibit{}
	for _, cert := range investigation.Certificates {
		certs[cert.Fingerprint] = cert
	}
	for _, change := range investigation.ChangeSequence {
		previous := certs[change.PreviousFingerprint]
		if previous.NotAfter == nil || change.ObservedAt.IsZero() || !jsonableTime(*previous.NotAfter) || !jsonableTime(change.ObservedAt) {
			continue
		}
		remaining := models.DaysUntil(*previous.NotAfter, change.ObservedAt)
		if remaining <= earlyRenewalLeadDays {
			continue
		}
		line := fmt.Sprintf("%s leaf %s → %s; predecessor remaining life %d day(s) (not_after=%s)",
			change.ObservedAt.UTC().Format(time.RFC3339),
			shortProofFP(change.PreviousFingerprint),
			shortProofFP(change.Fingerprint),
			remaining,
			previous.NotAfter.UTC().Format(time.RFC3339),
		)
		switch {
		case change.Relation == "same_endpoint" && change.IPAddress != "":
			line += "; same address " + change.IPAddress
		case change.PreviousIP != "" && change.IPAddress != "":
			line += "; addresses " + change.PreviousIP + " → " + change.IPAddress
		case change.IPAddress != "":
			line += "; serving address " + change.IPAddress
		default:
			line += "; serving address not retained"
		}
		out = append(out, line)
	}
	return measuredEvidence(out)
}

func shortProofFP(fingerprint string) string {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return "(not captured)"
	}
	if len(fingerprint) <= 16 {
		return fingerprint
	}
	return fingerprint[:12] + "…"
}

func predecessorEndpointEvidence(investigation *models.Investigation, divergence *models.EndpointDivergence) []string {
	if divergence == nil {
		return nil
	}
	out := make([]string, 0, len(divergence.ActivePredecessorEndpoints))
	if investigation != nil {
		wanted := map[string]struct{}{}
		for _, address := range divergence.ActivePredecessorEndpoints {
			wanted[address] = struct{}{}
		}
		for _, group := range investigation.ProviderGroups {
			for _, endpoint := range group.Endpoints {
				if _, ok := wanted[endpoint.IPAddress]; !ok {
					continue
				}
				dns := "not in DNS"
				if endpoint.ActiveDNS {
					dns = "active DNS"
				}
				line := fmt.Sprintf("%s (%s, %s) served predecessor leaf %s", endpoint.IPAddress, dns, group.Group, shortProofFP(endpoint.Fingerprint))
				if endpoint.IssuerCN != "" {
					line += ", issuer " + endpoint.IssuerCN
				}
				out = append(out, line)
			}
		}
	}
	if len(out) == 0 && len(divergence.ActivePredecessorEndpoints) > 0 {
		out = append(out, "Active-DNS predecessor address(es): "+strings.Join(divergence.ActivePredecessorEndpoints, ", ")+".")
	}
	return out
}

func predecessorContinuityEvidence(divergence *models.EndpointDivergence) []string {
	if divergence == nil {
		return nil
	}
	out := make([]string, 0, 5)
	if len(divergence.RetiredPredecessorEndpoints) > 0 {
		out = append(out, "Retired / non-consensus predecessor address(es): "+strings.Join(divergence.RetiredPredecessorEndpoints, ", ")+".")
	}
	out = append(out, fmt.Sprintf("Consecutive DNS-active predecessor rounds: %d.", divergence.ConsecutivePredecessorRounds))
	out = append(out, fmt.Sprintf("Proven overlap (predecessor and another leaf both seen live): %.1f hours.", divergence.PredecessorSpanHours))
	if divergence.PredecessorIssuedAt != nil && divergence.SuccessorIssuedAt != nil {
		out = append(out, fmt.Sprintf("Issued (earliest embedded SCT, else NotBefore): predecessor %s, successor %s.", divergence.PredecessorIssuedAt.UTC().Format(time.RFC3339), divergence.SuccessorIssuedAt.UTC().Format(time.RFC3339)))
	}
	out = append(out, fmt.Sprintf("Resolver-consistent rounds: %d.", divergence.ResolverConsistentRounds))
	if line := referencePositionLine(divergence); line != "" {
		out = append(out, line)
	}
	return out
}

// referencePositionLine places the proven overlap in the measured reference
// distribution and names the operator standard it is compared with.
func referencePositionLine(divergence *models.EndpointDivergence) string {
	if divergence == nil || divergence.ReferenceCompleted == 0 {
		return ""
	}
	line := fmt.Sprintf("Of %d completed rollouts measured by this monitor, %d (%.1f%%) certainly finished within %.1f hours.",
		divergence.ReferenceCompleted, divergence.ReferenceFinishedWithin, divergence.ReferenceShare*100, divergence.PredecessorSpanHours)
	if divergence.AlertShare > 0 {
		line += fmt.Sprintf(" Operator alert share: %.0f%% (a configured standard, not a measurement).", divergence.AlertShare*100)
	}
	return line
}

func predecessorMeasurement(investigation *models.Investigation, divergence *models.EndpointDivergence) []string {
	return append(predecessorEndpointEvidence(investigation, divergence), predecessorContinuityEvidence(divergence)...)
}

func retiredPredecessorEvidence(investigation *models.Investigation, addresses []string) []string {
	if len(addresses) == 0 {
		return nil
	}
	wanted := map[string]struct{}{}
	for _, address := range addresses {
		wanted[address] = struct{}{}
	}
	out := make([]string, 0, len(addresses))
	if investigation != nil {
		for _, group := range investigation.ProviderGroups {
			for _, endpoint := range group.Endpoints {
				if _, ok := wanted[endpoint.IPAddress]; !ok {
					continue
				}
				dns := "not in DNS"
				if endpoint.ActiveDNS {
					dns = "active DNS"
				}
				out = append(out, fmt.Sprintf("%s (%s, %s) served leaf %s", endpoint.IPAddress, dns, group.Group, shortProofFP(endpoint.Fingerprint)))
			}
		}
	}
	if len(out) == 0 {
		out = append(out, "Retired / non-consensus predecessor address(es): "+strings.Join(addresses, ", ")+".")
	}
	return out
}

func answeringEndpointEvidence(investigation *models.Investigation, limit int) []string {
	if investigation == nil || limit <= 0 {
		return nil
	}
	out := make([]string, 0, limit)
	extra := 0
	for _, group := range investigation.ProviderGroups {
		for _, endpoint := range group.Endpoints {
			if !endpoint.Success || endpoint.Fingerprint == "" {
				continue
			}
			if len(out) >= limit {
				extra++
				continue
			}
			dns := "not in DNS"
			if endpoint.ActiveDNS {
				dns = "active DNS"
			}
			line := fmt.Sprintf("%s (%s, %s) served leaf %s", endpoint.IPAddress, dns, group.Group, shortProofFP(endpoint.Fingerprint))
			if endpoint.IssuerCN != "" {
				line += ", issuer " + endpoint.IssuerCN
			}
			out = append(out, line)
		}
	}
	if extra > 0 {
		out = append(out, fmt.Sprintf("and %d further answering endpoint(s) in the same round.", extra))
	}
	return out
}

func conflictingNetworkEvidence(investigation *models.Investigation, divergence *models.EndpointDivergence) []string {
	if investigation == nil {
		if divergence != nil {
			return []string{fmt.Sprintf("%d provider network(s) served more than one leaf.", divergence.IntraGroupConflicts)}
		}
		return nil
	}
	out := make([]string, 0)
	for _, group := range investigation.ProviderGroups {
		if !group.Conflict {
			continue
		}
		parts := make([]string, 0, len(group.Endpoints))
		for _, endpoint := range group.Endpoints {
			if endpoint.Fingerprint == "" {
				continue
			}
			parts = append(parts, endpoint.IPAddress+" → "+shortProofFP(endpoint.Fingerprint))
		}
		label := group.Group
		if group.Vendor != "" {
			label += " · " + group.Vendor
		}
		out = append(out, fmt.Sprintf("%s served %d leaf(s): %s.", label, group.LeafCount, strings.Join(parts, "; ")))
	}
	if len(out) == 0 && divergence != nil && divergence.IntraGroupConflicts > 0 {
		out = append(out, fmt.Sprintf("%d provider network(s) served more than one leaf.", divergence.IntraGroupConflicts))
	}
	return out
}

func providerLeafEvidence(investigation *models.Investigation) []string {
	if investigation == nil {
		return nil
	}
	out := make([]string, 0, len(investigation.ProviderGroups))
	for _, group := range investigation.ProviderGroups {
		label := group.Group
		if group.Vendor != "" {
			label += " · " + group.Vendor
		}
		leaves := make([]string, 0)
		seen := map[string]struct{}{}
		for _, endpoint := range group.Endpoints {
			if endpoint.Fingerprint == "" {
				continue
			}
			if _, ok := seen[endpoint.Fingerprint]; ok {
				continue
			}
			seen[endpoint.Fingerprint] = struct{}{}
			leaves = append(leaves, shortProofFP(endpoint.Fingerprint))
		}
		out = append(out, fmt.Sprintf("%s served %d leaf(s): %s.", label, group.LeafCount, strings.Join(leaves, ", ")))
	}
	return out
}

func defectiveEndpointEvidence(investigation *models.Investigation, addresses []string) []string {
	if len(addresses) == 0 {
		return nil
	}
	wanted := map[string]struct{}{}
	for _, address := range addresses {
		wanted[address] = struct{}{}
	}
	out := make([]string, 0, len(addresses))
	if investigation != nil {
		for _, group := range investigation.ProviderGroups {
			for _, endpoint := range group.Endpoints {
				if _, ok := wanted[endpoint.IPAddress]; !ok {
					continue
				}
				line := endpoint.IPAddress + " served leaf " + shortProofFP(endpoint.Fingerprint)
				if endpoint.IssuerCN != "" {
					line += ", issuer " + endpoint.IssuerCN
				}
				out = append(out, line)
			}
		}
	}
	if len(out) == 0 {
		out = append(out, "Defective endpoint(s): "+strings.Join(addresses, ", ")+".")
	}
	return out
}

func changeRelationEvidence(investigation *models.Investigation, relation string, limit int) []string {
	if investigation == nil || limit <= 0 {
		return nil
	}
	out := make([]string, 0, limit)
	extra := 0
	for _, change := range investigation.ChangeSequence {
		match := change.Relation == relation
		if relation == "coexisting" {
			match = change.Coexisting || change.ChangeClass == "coexisting_leaf"
		}
		if !match {
			continue
		}
		if len(out) >= limit {
			extra++
			continue
		}
		when := ""
		if !change.ObservedAt.IsZero() {
			when = change.ObservedAt.UTC().Format("2006-01-02")
		}
		ip := change.IPAddress
		if ip == "" {
			ip = change.PreviousIP
		}
		if ip == "" {
			ip = "address not retained"
		}
		line := fmt.Sprintf("%s %s: %s → %s", when, ip, shortProofFP(change.PreviousFingerprint), shortProofFP(change.Fingerprint))
		if change.DaysUntilExpiry > 0 {
			line += fmt.Sprintf(" (%d day(s) left on the new leaf)", change.DaysUntilExpiry)
		}
		out = append(out, strings.TrimSpace(line))
	}
	if extra > 0 {
		out = append(out, fmt.Sprintf("and %d further matching replacement(s).", extra))
	}
	return out
}

// transitionIdentityEvidence renders only per-pair certificate deltas.  It is
// kept separate from the churn score so users can see why a particular
// replacement is notable without mistaking the delta for proof of who changed
// a private deployment configuration.
func transitionIdentityEvidence(investigation *models.Investigation, relation string, limit int) []string {
	if investigation == nil || limit <= 0 {
		return nil
	}
	out := make([]string, 0, limit)
	extra := 0
	for _, change := range investigation.ChangeSequence {
		if change.Relation != relation {
			continue
		}
		parts := make([]string, 0, 5)
		if len(change.SANsAdded) > 0 {
			parts = append(parts, "SAN added: "+strings.Join(change.SANsAdded, ", "))
		}
		if len(change.SANsRemoved) > 0 {
			parts = append(parts, "SAN removed: "+strings.Join(change.SANsRemoved, ", "))
		}
		if change.IssuerChanged {
			parts = append(parts, "issuer: "+change.PreviousIssuerCN+" → "+change.IssuerCN)
		}
		if change.CommonNameChanged {
			parts = append(parts, "CN: "+change.PreviousCommonName+" → "+change.CommonName)
		}
		if change.KeyAlgorithmChanged {
			parts = append(parts, "key algorithm: "+change.PreviousKeyAlgorithm+" → "+change.KeyAlgorithm)
		}
		if change.PublicKeyChanged {
			parts = append(parts, "public key changed")
		} else if change.PreviousSPKIFingerprint != "" && change.SPKIFingerprint != "" {
			parts = append(parts, "public key retained")
		}
		if len(parts) == 0 {
			continue
		}
		if len(out) >= limit {
			extra++
			continue
		}
		when := "time not retained"
		if !change.ObservedAt.IsZero() {
			when = change.ObservedAt.UTC().Format(time.RFC3339)
		}
		ip := change.IPAddress
		if ip == "" {
			ip = change.PreviousIP
		}
		if ip == "" {
			ip = "address not retained"
		}
		out = append(out, when+" "+ip+": "+strings.Join(parts, "; ")+".")
	}
	if extra > 0 {
		out = append(out, fmt.Sprintf("and %d further same-address replacement(s) with retained certificate deltas.", extra))
	}
	return out
}

func relatedNameMeasurementEvidence(investigation *models.Investigation, limit int) []string {
	if investigation == nil || limit <= 0 {
		return nil
	}
	out := make([]string, 0, limit)
	extra := 0
	for _, probe := range investigation.RelatedNames {
		if len(out) >= limit {
			extra++
			continue
		}
		line := probe.Name + ": DNS=" + probe.DNSStatus
		if probe.ResolverQuorum > 0 {
			line += fmt.Sprintf(" resolver_quorum=%d", probe.ResolverQuorum)
		}
		if len(probe.ResolvedIPs) > 0 {
			line += " ips=" + strings.Join(probe.ResolvedIPs, ",")
		}
		if len(probe.CNAMEChain) > 0 {
			line += " cname=" + strings.Join(probe.CNAMEChain, ",")
		}
		if probe.TLSAnswered {
			line += fmt.Sprintf(" tls_answered=true covers_own_name=%t covers_root_name=%t", probe.CoversOwnName, probe.CoversRootName)
			if probe.SharesRootIP || probe.SharesRootCNAME || probe.SharesRootLeaf {
				shared := make([]string, 0, 3)
				if probe.SharesRootIP {
					shared = append(shared, "IP")
				}
				if probe.SharesRootCNAME {
					shared = append(shared, "CNAME")
				}
				if probe.SharesRootLeaf {
					shared = append(shared, "leaf")
				}
				line += " shares_root=" + strings.Join(shared, "+")
			}
		}
		if probe.HTTP != nil {
			line += fmt.Sprintf(" http_status=%d", probe.HTTP.StatusCode)
			if probe.HTTP.Redirect != "" {
				line += " redirect=" + probe.HTTP.Redirect
			}
		}
		if probe.Error != "" {
			line += " error=" + probe.Error
		}
		out = append(out, line)
	}
	if extra > 0 {
		out = append(out, fmt.Sprintf("and %d further actively measured SAN name(s).", extra))
	}
	return out
}

func transientRelatedNameEvidence(investigation *models.Investigation, limit int) []string {
	if investigation == nil || limit <= 0 {
		return nil
	}
	out := make([]string, 0, limit)
	for _, probe := range investigation.RelatedNames {
		if !probe.BranchLikeLabel || probe.DNSStatus != "no_public_address" || probe.RemovedCount == 0 {
			continue
		}
		line := fmt.Sprintf("%s: branch-like label=%t; SAN additions=%d removals=%d; current DNS has no usable public address.", probe.Name, probe.BranchLikeLabel, probe.AddedCount, probe.RemovedCount)
		out = append(out, line)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func findingClassOf(diagnosis models.CauseDiagnosis) string {
	if diagnosis.BenignExplanation != "" {
		return models.FindingExpected
	}
	if diagnosis.CauseStatus == "unestablished" || diagnosis.CauseStatus == "inferred" {
		return models.FindingInsufficient
	}
	switch diagnosis.PrimaryCode {
	case models.DivergenceUndetermined, "insufficient_longitudinal_evidence", "endpoint_attribution_unavailable", "replacement_mechanism_unestablished", "same_key_unestablished", "early_renewal_unestablished":
		return models.FindingInsufficient
	default:
		return models.FindingIncident
	}
}

func causeLabelOf(diagnosis models.CauseDiagnosis) string {
	label := strings.TrimSpace(diagnosis.PrimaryLabel)
	switch diagnosis.CauseStatus {
	case "inferred":
		if label == "" {
			return "Inferred from issuance shape"
		}
		return "Inferred: " + label
	case "unestablished":
		if label == "" {
			return "Process not established"
		}
		return label
	default:
		return label
	}
}

// isSummaryIssueRegisterFinding applies the suppression rules that do not need
// longitudinal joins, while retaining lifecycle candidates for the detail
// view to classify once evidence is loaded.
func isSummaryIssueRegisterFinding(item *models.Anomaly) bool {
	if item == nil {
		return false
	}
	if suppressExpectedInfrastructureChurn(*item) {
		return false
	}
	if item.FindingClass == models.FindingExpected {
		return false
	}
	if item.FindingClass == models.FindingInsufficient && item.Diagnosis == nil {
		return true
	}
	if item.Diagnosis != nil {
		return isIssueRegisterFinding(*item)
	}
	switch item.Type {
	case models.ObsDeploymentFailure, models.ObsStaleAfterChange, "frequent_change", "same_key", "early_renewal":
		item.FindingClass = models.FindingInsufficient
		if item.Reason == "" {
			item.Reason = "Candidate finding retained pending longitudinal diagnosis."
		}
		if item.EvidenceStatus == "" {
			item.EvidenceStatus = models.EvidenceStatusPending
		}
		if item.EvidencePendingReason == "" {
			item.EvidencePendingReason = "The summary index omits longitudinal joins; open the finding for evidence-backed classification."
		}
		return true
	default:
		return isIssueRegisterFinding(*item)
	}
}

// isIssueRegisterFinding reports whether a decorated finding belongs on the
// Anomalies issue register. Only confirmed incidents and suspected problems
// remain. Expected properties and measurement artifacts (CDN IP rotation,
// historical mixed fingerprints that have since settled, change counters
// without a same-endpoint replacement, mixed leaves after DNS change without
// a leftover predecessor on current DNS) are omitted.
func isIssueRegisterFinding(item models.Anomaly) bool {
	// These names route to shared service infrastructure rather than identifying
	// one HTTPS site. Certificate churn on them is expected and must not reach
	// the issue register, regardless of how an earlier probe classified it.
	if suppressExpectedInfrastructureChurn(item) {
		return false
	}
	if item.FindingClass == models.FindingExpected {
		return false
	}
	if item.Diagnosis != nil && item.Diagnosis.BenignExplanation != "" {
		return false
	}
	if item.Diagnosis != nil && item.Diagnosis.Investigation != nil && item.Diagnosis.Investigation.FindingClass == models.FindingExpected {
		return false
	}
	// Summary rows carry a persisted evidence-gate classification but omit the
	// expensive diagnosis object. Preserve those rows for the compact issue
	// register; the domain detail endpoint can later refine their status.
	if item.Diagnosis == nil && (item.FindingClass == models.FindingIncident || item.FindingClass == models.FindingInsufficient) {
		return true
	}
	switch item.Type {
	case models.ObsDeploymentFailure:
		return currentCertificateDiversityProblem(item)
	case models.ObsStaleAfterChange:
		return currentStaleCertificateProblem(item)
	case "frequent_change":
		return currentFrequentChangeProblem(item)
	case "same_key":
		return currentSameKeyProblem(item)
	case "early_renewal":
		return currentEarlyRenewalProblem(item)
	case "unreachable", "measurement_failed", "endpoint_probe_inconclusive", "expiring_soon":
		// These are measurement states or expiry warnings, not evidence that
		// the monitored site has a certificate deployment defect.
		return false
	default:
		return true
	}
}

func currentCertificateDiversityProblem(item models.Anomaly) bool {
	if divergenceIsBenign(diagnosisCode(item)) {
		return false
	}
	divergence := diagnosisDivergence(item)
	if divergence != nil && divergence.FunctionallyEquivalent && (divergence.AddressPools > 0 || divergence.AddressReturns > 0) {
		return false
	}
	return divergence != nil && divergence.DistinctLeaves >= 2
}

func currentStaleCertificateProblem(item models.Anomaly) bool {
	if divergenceIsBenign(diagnosisCode(item)) {
		return false
	}
	divergence := diagnosisDivergence(item)
	if divergence == nil {
		return false
	}
	// A same-name certificate served by several address pools is ordinary CDN
	// rotation. It is not stale residue unless one endpoint is still serving a
	// certificate that is actually defective for the queried name.
	if divergence.FunctionallyEquivalent && (divergence.AddressPools > 0 || divergence.AddressReturns > 0) {
		return false
	}
	// The type name is leftover predecessor on current DNS after a topology
	// change. Do not place a one-round candidate on the issue register: it may
	// be ordinary propagation. Mixed leaves, retired-edge residue, intra-fleet
	// disagreement and a defective certificate without that leftover are
	// different findings.
	return divergence.StrongEvidence
}

func currentEarlyRenewalProblem(item models.Anomaly) bool {
	if divergenceIsBenign(diagnosisCode(item)) {
		return false
	}
	switch diagnosisCode(item) {
	case "concurrent_multi_certificate_pool", "short_lived_certificate_automation", "early_renewal_unestablished":
		return false
	}
	if item.Diagnosis != nil && item.Diagnosis.BenignExplanation != "" {
		return false
	}
	shape := diagnosisChurn(item)
	if shape == nil {
		return false
	}
	return diagnosisCode(item) == "early_renewal_replacement" && shape.SameEndpointChanges > 0 && shape.MedianRemainingDays > earlyRenewalLeadDays
}

func currentSameKeyProblem(item models.Anomaly) bool {
	switch diagnosisCode(item) {
	case "same_key_unestablished", "concurrent_same_key":
		// Without a same-address replacement there is no replacement to call
		// same-key: the shared key is on concurrently served leaves.
		return false
	}
	shape := diagnosisChurn(item)
	if shape == nil {
		return false
	}
	return shape.SameEndpointChanges > 0 && shape.DistinctSPKIs >= 1
}

func currentFrequentChangeProblem(item models.Anomaly) bool {
	switch diagnosisCode(item) {
	case "concurrent_multi_certificate_pool", "short_lived_certificate_automation",
		"preissued_rolling_pipeline", "automated_renewal_policy",
		"ca_or_policy_migration", "edge_or_deployment_rollout",
		"replacement_mechanism_unestablished", "insufficient_longitudinal_evidence",
		"endpoint_attribution_unavailable":
		// These describe a valid rollout, a certificate inventory policy, a
		// migration, or evidence that is not specific enough to call a fault.
		// They belong in diagnosis detail, not the issue register.
		return false
	}
	shape := diagnosisChurn(item)
	// Frequency needs at least two proven successor certificates: one renewal,
	// however many addresses it reached, is a single event with no interval.
	return shape != nil && shape.ProvenSuccessors >= 2
}

func diagnosisChurn(item models.Anomaly) *models.ChurnShape {
	if item.Diagnosis == nil {
		return nil
	}
	return item.Diagnosis.ChurnShape
}

func diagnosisCode(item models.Anomaly) string {
	if item.Diagnosis == nil {
		return ""
	}
	return item.Diagnosis.PrimaryCode
}

func diagnosisDivergence(item models.Anomaly) *models.EndpointDivergence {
	if item.Diagnosis == nil {
		return nil
	}
	return item.Diagnosis.Divergence
}

func investigationProblem(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis, investigation *models.Investigation) (problem, why string) {
	switch item.Type {
	case models.ObsDeploymentFailure:
		leaves, endpoints, groups, conflicts := 0, 0, 0, 0
		if diagnosis.Divergence != nil {
			leaves = diagnosis.Divergence.DistinctLeaves
			endpoints = diagnosis.Divergence.EndpointsAnswered
			groups = diagnosis.Divergence.NetworkGroups
			conflicts = diagnosis.Divergence.IntraGroupConflicts
		}
		if leaves == 0 && investigation != nil {
			for _, group := range investigation.ProviderGroups {
				endpoints += len(group.Endpoints)
				leaves += group.LeafCount
				if group.Conflict {
					conflicts++
				}
			}
			groups = len(investigation.ProviderGroups)
		}
		problem = fmt.Sprintf("%d sampled endpoint(s) served %d distinct certificate(s) across %d provider network(s).", maxInt(endpoints, 0), maxInt(leaves, 0), maxInt(groups, 0))
		switch diagnosis.PrimaryCode {
		case models.DivergenceIntentionalMultiCDN:
			if diagnosis.Divergence != nil && diagnosis.Divergence.CDN != nil && models.CDNMethodFor(diagnosis.Divergence.CDN.Completeness) == "vendor" && diagnosis.Divergence.CDN.DistinctVendors >= 2 {
				why = "This is not counted as a problem: each named CDN served one certificate consistently, which is the expected shape of a multi-CDN deployment."
			} else {
				why = "This is not counted as a problem: each provider network served one certificate consistently, which is the expected shape of a multi-CDN deployment. Endpoint vendors were not complete, so the reading uses the IPv4 /16 and IPv6 /32 partition."
			}
		case models.DivergenceDualCertificate:
			why = "This is not counted as a problem: the leaves differ only by public-key algorithm while covering the same names from the same issuer."
		case models.DivergenceIntraFleet:
			if diagnosis.Divergence != nil && diagnosis.Divergence.CDN != nil && models.CDNMethodFor(diagnosis.Divergence.CDN.Completeness) == "vendor" && diagnosis.Divergence.CDN.DistinctVendors <= 1 {
				why = "This is a problem because addresses attributed to the same named CDN served more than one certificate. Multi-CDN does not explain disagreement inside one operator."
			} else {
				why = fmt.Sprintf("This is a problem because %d provider network(s) served more than one certificate. Multi-CDN does not explain disagreement inside one operator's own address space.", conflicts)
			}
		case models.DivergenceStuckRollout:
			why = "This is a problem because an active DNS endpoint is still serving the replaced certificate for longer than the configured share of completed rollouts took."
		case models.DivergencePropagating:
			if conflicts > 0 {
				why = fmt.Sprintf("This is a problem because %d provider network(s) served more than one certificate in the same round. Multi-CDN does not explain disagreement inside one operator; the assignment has not settled yet.", conflicts)
			} else {
				why = "This is a problem only if the mixed assignment persists. The current evidence shows a replacement that has not yet settled."
			}
		case models.DivergenceDefectiveEndpoint:
			why = "This is a problem because at least one endpoint served a certificate that is not currently valid for the queried name."
		default:
			if leaves < 2 {
				why = "This is not counted as a problem: the current sampled endpoints serve one certificate. An earlier mixed-fingerprint row is historical, not a live diversity incident."
			} else {
				why = "Mixed certificates were measured, but the retained sample is too small to tell a deliberate multi-provider split from an inconsistent deployment."
			}
		}
		return problem, why
	case models.ObsStaleAfterChange:
		leaves, endpoints := 0, 0
		if diagnosis.Divergence != nil {
			leaves = diagnosis.Divergence.DistinctLeaves
			endpoints = diagnosis.Divergence.EndpointsAnswered
		}
		problem = fmt.Sprintf("%d sampled endpoint(s) currently serve %d distinct certificate(s) after a DNS/IP-set change.", maxInt(endpoints, 0), maxInt(leaves, 0))
		switch diagnosis.PrimaryCode {
		case models.DivergenceStuckRollout:
			why = "This is a problem because an active DNS endpoint is still serving the predecessor certificate after the topology change, for longer than the configured share of completed rollouts took."
		case models.DivergencePropagating:
			why = "This is a suspected problem: the predecessor and successor are both still reachable after the topology change, and the assignment has not settled."
		case models.DivergenceIntraFleet, models.DivergenceDefectiveEndpoint:
			why = "This is a problem because the post-change endpoints do not agree on a currently valid certificate for the name."
		case "dns_cutover_before_tls_deployment":
			why = "This is a problem because a retired edge is still serving the previous certificate while a new edge already serves the successor."
		case models.DivergenceIntentionalMultiCDN, models.DivergenceDualCertificate:
			why = "This is not counted as a stale certificate: the DNS/IP-set change left a deliberate multi-certificate arrangement in place."
		default:
			why = "This is not counted as a stale certificate: the current sampled endpoints serve one still-valid leaf. Address-pool rotation is not a topology cutover that left a predecessor behind."
		}
		return problem, why
	case "early_renewal":
		pairs, remaining, validity, same := item.OccurrenceCount, 0, 0, 0
		if diagnosis.ChurnShape != nil {
			pairs = diagnosis.ChurnShape.EffectiveReplacements
			if pairs == 0 {
				pairs = diagnosis.ChurnShape.SameEndpointChanges
			}
			remaining = diagnosis.ChurnShape.MedianRemainingDays
			validity = diagnosis.ChurnShape.MedianValidityDays
			same = diagnosis.ChurnShape.SameEndpointChanges
		}
		problem = fmt.Sprintf("%d same-address replacement(s) retired a predecessor that still had %d day(s) remaining.", maxInt(pairs, same), remaining)
		switch diagnosis.PrimaryCode {
		case "concurrent_multi_certificate_pool":
			why = "This is not counted as early renewal: the predecessor and successor were observed on different addresses or in the same round, so the difference is concurrent deployment."
		case "short_lived_certificate_automation":
			why = fmt.Sprintf("This is not counted as early renewal: the predecessor lifetime is %d day(s), so replacement at this cadence is the designed short-lived schedule.", validity)
		case "early_renewal_unestablished":
			why = "A leaf fingerprint difference was retained, but predecessor remaining life on a same-address replacement was not measured, so early renewal is not proven."
		default:
			why = fmt.Sprintf("The predecessor NotAfter minus the observation time is %d day(s), which is more than 30, and consecutive scans shared the serving address (%d same-address pair(s)).", remaining, same)
		}
		return problem, why
	case "same_key":
		pairs, leaves, spkis := 0, 0, 0
		same, unknown := 0, 0
		remaining := 0
		if diagnosis.ChurnShape != nil {
			pairs = diagnosis.ChurnShape.ChangeEvents
			leaves = diagnosis.ChurnShape.DistinctLeaves
			spkis = diagnosis.ChurnShape.DistinctSPKIs
			same = diagnosis.ChurnShape.SameEndpointChanges
			unknown = diagnosis.ChurnShape.UnknownEndpointChanges
			remaining = diagnosis.ChurnShape.MedianRemainingDays
		}
		if pairs == 0 {
			pairs = item.OccurrenceCount
		}
		problem = fmt.Sprintf("%d leaf change(s) kept the same public key across %d distinct leaf certificate(s).", maxInt(pairs, 1), maxInt(leaves, 0))
		switch diagnosis.PrimaryCode {
		case "concurrent_same_key":
			why = "Predecessor and successor were observed in the same round while sharing one SPKI fingerprint, so the shared key is concurrent deployment, not a replacement that kept the key."
		case "same_key_unestablished":
			why = "No retained pair has both leaf fingerprints and both SPKI fingerprints, so same-key replacement cannot be read."
		default:
			if same > 0 {
				why = fmt.Sprintf("The address that served the new leaf is the address that served the previous leaf, and both leaves share one SPKI fingerprint (%d same-address pair(s), %d distinct SPKI(s)).", same, maxInt(spkis, 1))
				if remaining > 0 {
					why += fmt.Sprintf(" At replacement the successor still had %d day(s) remaining.", remaining)
				}
			} else {
				why = fmt.Sprintf("Leaf fingerprints differ while SPKI fingerprints match. Serving address was not retained on %d of %d pair(s), so replacement in time is not proven.", unknown, maxInt(pairs, 1))
			}
		}
		return problem, why
	case "frequent_change":
		changes, leaves, revisits, replacements := item.OccurrenceCount, 0, 0, 0
		same, cross := 0, 0
		if diagnosis.ChurnShape != nil {
			changes = diagnosis.ChurnShape.ChangeEvents
			leaves = diagnosis.ChurnShape.DistinctLeaves
			revisits = diagnosis.ChurnShape.RevisitEvents
			replacements = diagnosis.ChurnShape.EffectiveReplacements
			same = diagnosis.ChurnShape.SameEndpointChanges
			cross = diagnosis.ChurnShape.CrossEndpointChanges
		}
		validity := 0
		if diagnosis.ChurnShape != nil {
			validity = diagnosis.ChurnShape.MedianValidityDays
		}
		if validity > 0 {
			problem = fmt.Sprintf("The served leaf changed %d time(s) across %d distinct %d-day certificate(s). A single lifetime at that length would not produce this many replacements.", changes, leaves, validity)
		} else {
			problem = fmt.Sprintf("The served leaf changed %d time(s) across %d distinct certificate(s).", changes, leaves)
		}
		switch diagnosis.PrimaryCode {
		case "concurrent_multi_certificate_pool":
			why = fmt.Sprintf("This is not counted as frequent change: %d of those differences returned to a certificate seen earlier, so at most %d real replacement(s) occurred. The counter is sampling concurrently deployed certificates.", revisits, replacements)
		case "short_lived_certificate_automation":
			why = "This is not counted as an incident: replacement at this cadence matches the certificates' own short validity period."
		case "endpoint_attribution_unavailable":
			why = "The differences are real, but no serving address was retained, so replacement in time cannot be separated from different servers answering."
		case "preissued_rolling_pipeline":
			remaining := 0
			if diagnosis.ChurnShape != nil {
				remaining = diagnosis.ChurnShape.MedianRemainingDays
			}
			if diagnosis.CauseStatus == "inferred" {
				why = fmt.Sprintf("The differences are real. Serving addresses were not retained on those change rows, so replacement in time is not established. The served leaves were already old and only %d day(s) remained, which is many certificates per lifetime, not one renewal per certificate.", remaining)
			} else {
				why = fmt.Sprintf("This is a problem because one %d-day certificate is not being used for most of its life. The same address swapped in the next already-issued leaf when only %d day(s) remained (%d same-endpoint comparison(s)), so the change counter moves every day even though each leaf was valid for about %d days.", validity, remaining, same, validity)
			}
		case "automated_renewal_policy":
			if diagnosis.CauseStatus == "inferred" {
				why = "The differences are real. Serving addresses were not retained on those change rows, so replacement in time is not established. The served leaves were issued at replacement time with almost a full lifetime left, which is many issuances per lifetime, not one renewal per certificate."
			} else {
				why = fmt.Sprintf("This is a problem because a certificate that still has almost its full lifetime left is being replaced by another newly issued leaf on the same address (%d same-endpoint comparison(s)). That is extra issuance and deployment, not finishing the current lifetime.", same)
			}
		case "replacement_mechanism_unestablished":
			why = fmt.Sprintf("This is a problem because successive samples from the same endpoint served different certificates (%d same-endpoint comparison(s)). Issuance dates, remaining life and issuer fields do not identify the operational process.", same)
		case "ca_or_policy_migration", "edge_or_deployment_rollout", "incident_driven_reissue":
			why = fmt.Sprintf("This is a problem because the sequence is replacements in time (%d same-endpoint comparison(s), %d cross-endpoint), not a multi-certificate pool being sampled in turn. Each replacement still consumes a new issuance instead of using the current leaf for most of its lifetime.", same, cross)
		default:
			if diagnosis.ChurnShape != nil && diagnosis.ChurnShape.Interpretation == models.ChurnTemporalReplacement {
				why = "This is a problem because successive samples from the same endpoint served different certificates, which is replacement in time."
			} else {
				why = "The change counter moved, but the retained evidence does not yet establish whether the differences are replacements or sampling."
			}
		}
		return problem, why
	default:
		if isTLSValidationType(item.Type) {
			rows := tlsFindingsForCode(parseTLSFindings(context.state), item.Type)
			checkedAt := tlsCheckedAt(context.state, item)
			return tlsValidationProblem(item, diagnosis, rows, checkedAt), tlsValidationWhy(item, context, rows, checkedAt)
		}
		if isCertificateConditionType(item.Type) {
			checkedAt := certificateConditionCheckedAt(item, context.state)
			return certificateConditionProblem(item, context, checkedAt), certificateConditionWhy(item, context, checkedAt)
		}
		if item.Description != "" {
			return item.Description, diagnosis.Summary
		}
		return "A measured certificate condition was retained.", diagnosis.Summary
	}
}

func investigationFacts(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis) []string {
	facts := make([]string, 0, 12)
	if isTLSValidationType(item.Type) {
		facts = append(facts, tlsValidationFacts(item, context, diagnosis)...)
	}
	if isCertificateConditionType(item.Type) {
		facts = append(facts, certificateConditionFacts(item, context)...)
	}
	if diagnosis.Divergence != nil && usesEndpointDiversity(item.Type) {
		d := diagnosis.Divergence
		facts = append(facts,
			fmt.Sprintf("%d endpoint(s) answered with %d distinct certificate(s).", d.EndpointsAnswered, d.DistinctLeaves),
			fmt.Sprintf("Addresses fall into %d provider network(s); %d of those networks served more than one certificate.", d.NetworkGroups, d.IntraGroupConflicts),
		)
		if d.StableRounds > 0 {
			facts = append(facts, fmt.Sprintf("The same provider-to-certificate assignment held in %d earlier round(s), compared by network allocation rather than by rotating edge address.", d.StableRounds))
		}
		if d.StableAddressRounds > 0 {
			facts = append(facts, fmt.Sprintf("Every answering address served the same leaf as now in %d retained round(s) spanning %.1f hours.", d.StableAddressRounds, d.StableAddressSpanHours))
		}
		for _, line := range d.PooledEndpoints {
			facts = append(facts, "Several servers behind one address: "+line+".")
		}
		if len(d.UnobservableEndpoints) > 0 {
			facts = append(facts, fmt.Sprintf("%d resolved address(es) cannot be reached from this vantage (no IPv6 route), so what they serve is unknown: %s.", len(d.UnobservableEndpoints), strings.Join(d.UnobservableEndpoints, ", ")))
		}
		if d.DualCertificateSplit {
			facts = append(facts, fmt.Sprintf("Leaves share one issuer and one name set under %d public-key algorithms.", d.DistinctKeyAlgos))
		}
		if len(d.DefectiveEndpoints) > 0 {
			facts = append(facts, fmt.Sprintf("%d endpoint(s) served a certificate that is not currently valid for the name: %s.", len(d.DefectiveEndpoints), strings.Join(d.DefectiveEndpoints, ", ")))
		}
		if d.CDN != nil {
			facts = append(facts, cdnFact(d.CDN))
		}
		if d.CleanPartition && d.NetworkGroups >= 2 && (d.CDN == nil || models.CDNMethodFor(d.CDN.Completeness) != "vendor" || d.CDN.DistinctVendors >= 2) {
			facts = append(facts, "Each provider network served one certificate consistently, so the diversity is between providers, not inside one of them.")
		} else if d.CDN != nil && models.CDNMethodFor(d.CDN.Completeness) == "vendor" && d.CDN.DistinctVendors <= 1 && d.DistinctLeaves >= 2 {
			facts = append(facts, "This is not a multi-CDN split: every answering endpoint maps to the same named CDN.")
		} else if d.IntraGroupConflicts > 0 {
			facts = append(facts, "This is not a multi-CDN split: more than one certificate was served inside a single provider network.")
		}
		if !(d.CleanPartition && d.NetworkGroups >= 2) {
			if len(d.ActivePredecessorEndpoints) > 0 {
				facts = append(facts, fmt.Sprintf("Active DNS still serves the predecessor on %s for %d consecutive round(s) spanning %.1f hours.", strings.Join(d.ActivePredecessorEndpoints, ", "), d.ConsecutivePredecessorRounds, d.PredecessorSpanHours))
			} else if len(d.RetiredPredecessorEndpoints) > 0 {
				facts = append(facts, fmt.Sprintf("The predecessor was observed only on retired / non-consensus address(es): %s.", strings.Join(d.RetiredPredecessorEndpoints, ", ")))
			}
			if line := referencePositionLine(d); line != "" && len(d.ActivePredecessorEndpoints) > 0 {
				facts = append(facts, line)
			}
		}
	}
	if diagnosis.ChurnShape != nil && item.Type == "early_renewal" {
		s := diagnosis.ChurnShape
		facts = append(facts,
			fmt.Sprintf("Same-address replacements with predecessor remaining life > 30 days: %d.", s.SameEndpointChanges),
			fmt.Sprintf("Predecessor remaining life at replacement: %d day(s). Predecessor lifetime: %d day(s).", s.MedianRemainingDays, s.MedianValidityDays),
			fmt.Sprintf("Endpoint comparison: %d same address with a later-issued successor, %d same address without issuance dates, %d pool or different address, %d unrecorded.", s.SameEndpointChanges, s.UndatedEndpointChanges, s.CrossEndpointChanges, s.UnknownEndpointChanges),
		)
		if s.MedianIssuanceAgeDays >= 0 && s.SameEndpointChanges > 0 {
			facts = append(facts, fmt.Sprintf("Successor issuance age at observation: %d day(s).", s.MedianIssuanceAgeDays))
		}
	} else if diagnosis.ChurnShape != nil && item.Type == "same_key" {
		s := diagnosis.ChurnShape
		facts = append(facts,
			fmt.Sprintf("Same-key pairs: %d. Distinct leaves: %d. Distinct SPKI(s): %d.", s.ChangeEvents, s.DistinctLeaves, s.DistinctSPKIs),
			fmt.Sprintf("Endpoint comparison: %d same address with a later-issued successor, %d same address without issuance dates, %d pool or different address, %d unrecorded.", s.SameEndpointChanges, s.UndatedEndpointChanges, s.CrossEndpointChanges, s.UnknownEndpointChanges),
		)
		if s.MedianRemainingDays > 0 {
			facts = append(facts, fmt.Sprintf("At those replacements the successor had %d day(s) remaining.", s.MedianRemainingDays))
		}
		if s.MedianIssuanceAgeDays > 0 || (s.MedianIssuanceAgeDays == 0 && s.SameEndpointChanges > 0) {
			facts = append(facts, fmt.Sprintf("Successor issuance age at observation: %d day(s).", s.MedianIssuanceAgeDays))
		}
		if s.CoexistenceProofs > 0 {
			facts = append(facts, fmt.Sprintf("Same-round coexistence of predecessor and successor: %d.", s.CoexistenceProofs))
		}
	} else if diagnosis.ChurnShape != nil && item.Type == "frequent_change" {
		s := diagnosis.ChurnShape
		facts = append(facts,
			fmt.Sprintf("Change counter: %d difference(s), %d distinct leaf certificate(s), replacement floor %d.", s.ChangeEvents, s.DistinctLeaves, s.EffectiveReplacements),
			fmt.Sprintf("%d change(s) returned to a certificate already seen; a replaced certificate cannot come back.", s.RevisitEvents),
			fmt.Sprintf("Endpoint comparison: %d same address with a later-issued successor, %d same address without issuance dates, %d pool or different address, %d unrecorded.", s.SameEndpointChanges, s.UndatedEndpointChanges, s.CrossEndpointChanges, s.UnknownEndpointChanges),
		)
		if s.MedianRemainingDays > 0 {
			facts = append(facts, fmt.Sprintf("At replacement, the served certificate had %d day(s) left (spread %.1f day(s)).", s.MedianRemainingDays, s.RemainingSpreadDays))
		}
		if s.MedianIssuanceAgeDays > 0 {
			facts = append(facts, fmt.Sprintf("Those certificates had already been issued for %d day(s) when they were served.", s.MedianIssuanceAgeDays))
		}
		if s.DistinctIssuanceDays > 0 {
			if s.IssuanceCadenceDays > 0 {
				facts = append(facts, fmt.Sprintf("Issuance dates cover %d distinct day(s), median %s apart.", s.DistinctIssuanceDays, formatDays(s.IssuanceCadenceDays)))
			} else {
				facts = append(facts, fmt.Sprintf("Issuance dates cover %d distinct day(s).", s.DistinctIssuanceDays))
			}
		}
		if s.SameIssuerFraction > 0 || s.SameNameFraction > 0 {
			facts = append(facts, fmt.Sprintf("Issuer stayed the same in %.0f%% of replacements; the certificate name stayed the same in %.0f%%.", s.SameIssuerFraction*100, s.SameNameFraction*100))
		}
		if s.MedianValidityDays > 0 {
			facts = append(facts, fmt.Sprintf("Median certificate lifetime is %d day(s); replacements per lifetime period: %.2f.", s.MedianValidityDays, s.ReplacementsPerValidityPeriod))
		}
	}
	if diagnosis.Corroboration != nil {
		if diagnosis.Corroboration.CTNote != "" {
			facts = append(facts, diagnosis.Corroboration.CTNote)
		}
		if diagnosis.Corroboration.SCTNote != "" {
			facts = append(facts, diagnosis.Corroboration.SCTNote)
		}
		if diagnosis.Corroboration.DirectoryNote != "" {
			facts = append(facts, diagnosis.Corroboration.DirectoryNote)
		}
		if diagnosis.Corroboration.CAANote != "" {
			facts = append(facts, diagnosis.Corroboration.CAANote)
		}
		if diagnosis.Corroboration.DNSSECNote != "" {
			facts = append(facts, diagnosis.Corroboration.DNSSECNote)
		}
		if diagnosis.Corroboration.TimingNote != "" {
			facts = append(facts, diagnosis.Corroboration.TimingNote)
		}
	}
	// The same endpoint survey also contains a no-SNI control. Include it in
	// every case, not only certificate-diversity findings: it can explain a
	// hostname mismatch, a stale/default edge, or an apparent leaf change
	// before any operational cause is attributed.
	facts = append(facts, endpointSelectionFacts(context)...)
	if item.OccurrenceCount > 0 && len(facts) == 0 {
		facts = append(facts, fmt.Sprintf("Observed %d time(s) across %d monitoring round(s).", item.OccurrenceCount, item.MonitoringCount))
	}
	return facts
}

func endpointSelectionFacts(context diagnosisContext) []string {
	probes := currentEndpointSurvey(context)
	if len(probes) == 0 {
		return nil
	}
	facts := make([]string, 0, len(probes))
	for _, probe := range probes {
		analysis := probe.SelectionAnalysis
		if analysis == nil || strings.TrimSpace(analysis.Interpretation) == "" {
			continue
		}
		line := fmt.Sprintf("Endpoint %s: requested SNI %q; no-SNI comparison classified as %s.", probe.IPAddress, firstNonEmpty(probe.RequestedSNI, "<empty>"), analysis.Interpretation)
		if analysis.SelectedFingerprint != "" {
			line += fmt.Sprintf(" SNI leaf %s.", shortEvidenceFingerprint(analysis.SelectedFingerprint))
			if analysis.DefaultFingerprint != "" {
				line += fmt.Sprintf(" Default leaf %s.", shortEvidenceFingerprint(analysis.DefaultFingerprint))
			}
		}
		facts = append(facts, line)
	}
	return facts
}

func shortEvidenceFingerprint(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 16 {
		return value
	}
	return value[:16]
}

func ruledOutReason(hypothesis models.CauseHypothesis) string {
	reason := strings.TrimSpace(strings.Join(hypothesis.Contradictions, " "))
	if reason != "" {
		return reason
	}
	return "Lower support from the retained measurements than the primary reading."
}

func whyThisCause(diagnosis models.CauseDiagnosis) []string {
	steps := make([]string, 0, 6)
	if explanation := operationalCauseExplanation(diagnosis); explanation != "" {
		steps = append(steps, explanation)
	} else if len(diagnosis.Hypotheses) > 0 && diagnosis.Hypotheses[0].Rationale != "" {
		steps = append(steps, diagnosis.Hypotheses[0].Rationale)
	} else if diagnosis.Summary != "" {
		steps = append(steps, diagnosis.Summary)
	}
	if diagnosis.CauseStatus == "inferred" && diagnosis.PrimaryCode != "same_key_reissue" && diagnosis.PrimaryCode != "concurrent_same_key" && diagnosis.PrimaryCode != "same_key_unestablished" && diagnosis.PrimaryCode != "early_renewal_replacement" && diagnosis.PrimaryCode != "early_renewal_unestablished" {
		steps = append(steps, "This is an inference from issuance dates and remaining life. Same-endpoint replacement has not been established, so a later round that records the serving address can confirm or overturn it.")
	}
	steps = append(steps, measuredCauseFacts(diagnosis)...)
	return uniqueEvidenceStrings(steps)
}

func operationalCauseExplanation(diagnosis models.CauseDiagnosis) string {
	shape := diagnosis.ChurnShape
	remaining, age, validity := 0, 0, 0
	if shape != nil {
		remaining = shape.MedianRemainingDays
		age = shape.MedianIssuanceAgeDays
		validity = shape.MedianValidityDays
	}
	switch diagnosis.PrimaryCode {
	case tlsCauseExpiredLeaf, tlsCauseNameMismatch, tlsCauseNonHTTPSIdentity, tlsCauseNotYetValid, tlsCauseLocalChain, tlsCauseProbeIncomplete,
		certCauseExpiredServed, certCauseExpiredObserved, certCauseExpiringSoon, certCauseRevoked, certCauseResidual, certCauseUnreachable, certCauseARIEmergency:
		return diagnosis.Summary
	case "preissued_rolling_pipeline":
		return fmt.Sprintf("Normal renewal uses one %d-day certificate for most of its life and would produce one replacement every two months, not a daily change. Here the served leaf is already %d day(s) old and only %d day(s) remain, so a pre-issued inventory is being pushed forward: certificates are minted ahead of time, held, then served only near expiry so the private key is on the edge for those last days rather than the full lifetime. That is why 'replace near expiry' still looks like frequent change — each day is a different already-old leaf, not one certificate finishing its own lifetime.", maxInt(validity, 90), age, remaining)
	case "automated_renewal_policy":
		return fmt.Sprintf("Normal renewal for a %d-day leaf is once per lifetime (typical ACME/CDN schedules retry about 30 days before expiry). Here a new leaf is minted at replacement time with %d day(s) remaining and issuance age %d, so the automation is re-issuing a still-fresh certificate instead of using the current one. On Cloudflare-fronted names this is the edge certificate being retriggered; TLS cannot see whether that was a dashboard change, DCV retry, or an internal CA failover.", maxInt(validity, 90), remaining, age)
	case "ca_or_policy_migration":
		return "The replacements are still fresh short-lived issuances, but the CA family or the certificate name changed with them. WE1/WR2 are Google Trust Services; YE1/YE2 are Let's Encrypt. On a CDN-fronted name that is the CDN selecting or failing over between those CAs (and keeping a backup from the other CA), not the site operator switching vendors week to week. A name change such as www.loc.gov to loc.gov is a coverage change."
	case "short_lived_certificate_automation":
		return fmt.Sprintf("These certificates themselves last about %d day(s). Replacing them on that cadence is the designed lifetime, not an extra operational process on top of a 90-day leaf.", maxInt(validity, 0))
	case "same_key_reissue":
		if remaining > 0 {
			return fmt.Sprintf("The successor leaf still had %d day(s) remaining and issuance age %d day(s) when it was served with the predecessor SPKI.", remaining, age)
		}
		return "The successor leaf was served with the predecessor SPKI fingerprint."
	case "concurrent_same_key":
		return "Predecessor and successor that share one SPKI were observed in the same round."
	case "early_renewal_replacement":
		return fmt.Sprintf("The predecessor still had %d day(s) remaining of a %d-day lifetime when the same address served a new leaf.", remaining, validity)
	default:
		return ""
	}
}

func measuredCauseFacts(diagnosis models.CauseDiagnosis) []string {
	if diagnosis.ChurnShape == nil {
		return nil
	}
	shape := diagnosis.ChurnShape
	facts := make([]string, 0, 4)
	switch diagnosis.PrimaryCode {
	case "preissued_rolling_pipeline":
		if shape.MedianIssuanceAgeDays > 0 && shape.MedianRemainingDays > 0 {
			facts = append(facts, fmt.Sprintf("Served certificates were already %d day(s) old and had %d day(s) left (spread %.1f).", shape.MedianIssuanceAgeDays, shape.MedianRemainingDays, shape.RemainingSpreadDays))
		}
		if shape.DistinctIssuanceDays > 0 {
			if shape.IssuanceCadenceDays > 0 {
				facts = append(facts, fmt.Sprintf("Issuance dates cover %d distinct day(s), median %s apart.", shape.DistinctIssuanceDays, formatDays(shape.IssuanceCadenceDays)))
			} else {
				facts = append(facts, fmt.Sprintf("Issuance dates cover %d distinct day(s).", shape.DistinctIssuanceDays))
			}
		}
		if shape.SameIssuerFraction > 0 {
			facts = append(facts, fmt.Sprintf("Issuer stayed the same in %.0f%% of replacements.", shape.SameIssuerFraction*100))
		}
	case "automated_renewal_policy":
		if shape.MedianIssuanceAgeDays > 0 || shape.MedianRemainingDays > 0 {
			facts = append(facts, fmt.Sprintf("Served certificates were issued %d day(s) before they appeared, with %d day(s) remaining.", shape.MedianIssuanceAgeDays, shape.MedianRemainingDays))
		}
		if shape.MeanIntervalHours > 0 {
			facts = append(facts, fmt.Sprintf("Mean replacement interval is %.1f hours.", shape.MeanIntervalHours))
		}
	case "ca_or_policy_migration":
		facts = append(facts, fmt.Sprintf("Issuer stayed the same in %.0f%% of replacements; the certificate name stayed the same in %.0f%%.", shape.SameIssuerFraction*100, shape.SameNameFraction*100))
	case "short_lived_certificate_automation":
		facts = append(facts, fmt.Sprintf("Median certificate lifetime is %d day(s).", shape.MedianValidityDays))
	case "replacement_mechanism_unestablished":
		facts = append(facts, fmt.Sprintf("%d same-endpoint comparison(s) served a different leaf, but issuance dates and remaining life do not name the process.", shape.SameEndpointChanges))
	case "endpoint_attribution_unavailable":
		facts = append(facts, fmt.Sprintf("%d comparison(s) have no retained serving address, so replacement in time cannot be separated from different servers answering.", shape.UnknownEndpointChanges))
	}
	return facts
}

func ruledOutReadings(diagnosis models.CauseDiagnosis) []models.InvestigationRuledOut {
	if len(diagnosis.Hypotheses) < 2 {
		return nil
	}
	out := make([]models.InvestigationRuledOut, 0, 3)
	for _, hypothesis := range diagnosis.Hypotheses[1:] {
		if len(out) >= 3 {
			break
		}
		if hypothesis.Score < 0.08 {
			continue
		}
		if hypothesis.Code == "replacement_mechanism_unestablished" && diagnosis.PrimaryCode != "replacement_mechanism_unestablished" {
			continue
		}
		if hypothesis.Code == "endpoint_attribution_unavailable" && diagnosis.PrimaryCode != "endpoint_attribution_unavailable" {
			continue
		}
		reason := ruledOutReason(hypothesis)
		out = append(out, models.InvestigationRuledOut{Label: hypothesis.Label, Reason: reason})
	}
	return out
}

func selectionDefaultFingerprint(probe models.EndpointProbe) string {
	if probe.SelectionAnalysis == nil {
		return ""
	}
	return probe.SelectionAnalysis.DefaultFingerprint
}

func selectionInterpretation(probe models.EndpointProbe) string {
	if probe.SelectionAnalysis == nil {
		return ""
	}
	return probe.SelectionAnalysis.Interpretation
}

func providerExhibits(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis) []models.ProviderExhibit {
	probes := currentEndpointSurvey(context)
	if len(probes) == 0 && len(context.snapshots) > 0 {
		probes = probesFromSnapshot(context.snapshots[0])
	}
	if len(probes) == 0 {
		return nil
	}
	active := map[string]struct{}{}
	activeKnown := false
	if len(context.snapshots) > 0 {
		active, activeKnown = snapshotActiveIPsFor(context.snapshots[0])
	}
	groups := make(map[string][]models.EndpointExhibit)
	order := make([]string, 0)
	for _, probe := range probes {
		if probe.IPAddress == "" {
			continue
		}
		group := models.ProviderGroup(probe.IPAddress)
		if _, seen := groups[group]; !seen {
			order = append(order, group)
		}
		groups[group] = append(groups[group], models.EndpointExhibit{
			IPAddress:               probe.IPAddress,
			ActiveDNS:               activeKnown && hasEvidenceAddress(active, probe.IPAddress),
			Success:                 probe.Success,
			RequestedSNI:            probe.RequestedSNI,
			Fingerprint:             probe.Fingerprint,
			DefaultFingerprint:      selectionDefaultFingerprint(probe),
			SPKIFingerprint:         probe.SPKIFingerprint,
			IssuerCN:                probe.IssuerCN,
			KeyAlgorithm:            probe.KeyAlgorithm,
			SelectionInterpretation: selectionInterpretation(probe),
			Error:                   probe.Error,
		})
	}
	exhibits := make([]models.ProviderExhibit, 0, len(order))
	for _, group := range order {
		endpoints := groups[group]
		sort.Slice(endpoints, func(left, right int) bool { return endpoints[left].IPAddress < endpoints[right].IPAddress })
		leaves := make(map[string]struct{})
		for _, endpoint := range endpoints {
			if endpoint.Fingerprint != "" {
				leaves[endpoint.Fingerprint] = struct{}{}
			}
		}
		vendor := ""
		if diagnosis.Divergence != nil && diagnosis.Divergence.CDN != nil {
			for _, endpoint := range endpoints {
				name := diagnosis.Divergence.CDN.EndpointVendors[endpoint.IPAddress]
				if name == "" {
					continue
				}
				if vendor == "" {
					vendor = name
				} else if vendor != name {
					vendor = ""
					break
				}
			}
		}
		exhibits = append(exhibits, models.ProviderExhibit{
			Group:     group,
			Vendor:    vendor,
			Conflict:  len(leaves) > 1,
			LeafCount: len(leaves),
			Endpoints: endpoints,
		})
	}
	sort.Slice(exhibits, func(left, right int) bool {
		if exhibits[left].Conflict != exhibits[right].Conflict {
			return exhibits[left].Conflict
		}
		return exhibits[left].Group < exhibits[right].Group
	})
	if item.Type != models.ObsDeploymentFailure && item.Type != models.ObsStaleAfterChange && diagnosis.Divergence == nil {
		if len(exhibits) < 2 && !hasConflictingProvider(exhibits) {
			return nil
		}
	}
	return exhibits
}

func hasConflictingProvider(exhibits []models.ProviderExhibit) bool {
	for _, exhibit := range exhibits {
		if exhibit.Conflict {
			return true
		}
	}
	return false
}

func changeExhibits(context diagnosisContext) []models.ChangeExhibit {
	changes := make([]models.CertObservation, 0)
	for _, observation := range context.observations {
		if observation.ObservationType == models.ObsChange {
			changes = append(changes, observation)
		}
	}
	recoverChangeEndpoints(changes, context.snapshots)
	sort.SliceStable(changes, func(left, right int) bool {
		return changes[left].ObservedAt.Before(changes[right].ObservedAt)
	})
	if len(changes) == 0 {
		return nil
	}
	start := 0
	if len(changes) > maxChangeExhibits {
		start = len(changes) - maxChangeExhibits
	}
	exhibits := make([]models.ChangeExhibit, 0, len(changes)-start)
	for index := start; index < len(changes); index++ {
		change := changes[index]
		relation := "unknown"
		switch endpointRelation(changes, index) {
		case endpointSame:
			relation = "same_endpoint"
		case endpointDifferent:
			relation = "different_endpoint"
		}
		exhibit := models.ChangeExhibit{
			ObservedAt:              change.ObservedAt,
			PreviousFingerprint:     change.PreviousFingerprint,
			Fingerprint:             change.Fingerprint,
			PreviousIP:              change.PreviousIPAddress,
			IPAddress:               change.IPAddress,
			Relation:                relation,
			Coexisting:              coexistingLeaves(change),
			ChangeClass:             change.ChangeClass,
			DaysUntilExpiry:         change.DaysUntilExpiry,
			PreviousSPKIFingerprint: change.PreviousSPKIFingerprint,
			SPKIFingerprint:         change.SPKIFingerprint,
		}
		fillChangeIdentity(&exhibit, context.certificates)
		exhibits = append(exhibits, exhibit)
	}
	return exhibits
}

// relatedNameProbes selects the latest public probe for each SAN-transition
// name. It reports a current public measurement, not a reconstructed history
// of names that have already disappeared.
func relatedNameProbes(context diagnosisContext) []models.RelatedNameProbe {
	latest := make(map[string]models.RelatedNameProbe)
	for _, snapshot := range context.snapshots {
		raw := strings.TrimSpace(snapshot.RelatedNamesJSON)
		if raw == "" || raw == "null" || raw == "[]" {
			continue
		}
		var probes []models.RelatedNameProbe
		if json.Unmarshal([]byte(raw), &probes) != nil {
			continue
		}
		for _, probe := range probes {
			probe.Name = models.GetDomain(probe.Name)
			if probe.Name == "" {
				continue
			}
			previous, seen := latest[probe.Name]
			if !seen || probe.ProbedAt.After(previous.ProbedAt) {
				latest[probe.Name] = probe
			}
		}
	}
	out := make([]models.RelatedNameProbe, 0, len(latest))
	for _, probe := range latest {
		out = append(out, probe)
	}
	sort.Slice(out, func(left, right int) bool {
		if out[left].BranchLikeLabel != out[right].BranchLikeLabel {
			return out[left].BranchLikeLabel
		}
		if !out[left].ProbedAt.Equal(out[right].ProbedAt) {
			return out[left].ProbedAt.After(out[right].ProbedAt)
		}
		return out[left].Name < out[right].Name
	})
	return out
}

// fillChangeIdentity exposes only differences that can be read from the two
// retained certificates.  It intentionally does not guess what deployment
// tool, operator, or CA-side event caused the difference.
func fillChangeIdentity(exhibit *models.ChangeExhibit, certificates map[string]models.Certificate) {
	if exhibit == nil || len(certificates) == 0 {
		return
	}
	previous, previousOK := certificates[strings.TrimSpace(exhibit.PreviousFingerprint)]
	current, currentOK := certificates[strings.TrimSpace(exhibit.Fingerprint)]
	if !previousOK || !currentOK {
		return
	}

	if exhibit.PreviousSPKIFingerprint == "" {
		exhibit.PreviousSPKIFingerprint = previous.SPKIFingerprint
	}
	if exhibit.SPKIFingerprint == "" {
		exhibit.SPKIFingerprint = current.SPKIFingerprint
	}
	exhibit.PreviousIssuerCN = previous.IssuerCN
	exhibit.IssuerCN = current.IssuerCN
	exhibit.PreviousCommonName = previous.CommonName
	exhibit.CommonName = current.CommonName
	exhibit.PreviousKeyAlgorithm = previous.KeyAlgorithm
	exhibit.KeyAlgorithm = current.KeyAlgorithm

	if previous.IssuerCN != "" && current.IssuerCN != "" {
		exhibit.IssuerChanged = normalizeIdentityField(previous.IssuerCN) != normalizeIdentityField(current.IssuerCN)
	}
	if previous.CommonName != "" && current.CommonName != "" {
		exhibit.CommonNameChanged = normalizeIdentityField(previous.CommonName) != normalizeIdentityField(current.CommonName)
	}
	if previous.KeyAlgorithm != "" && current.KeyAlgorithm != "" {
		exhibit.KeyAlgorithmChanged = normalizeIdentityField(previous.KeyAlgorithm) != normalizeIdentityField(current.KeyAlgorithm)
	}
	if exhibit.PreviousSPKIFingerprint != "" && exhibit.SPKIFingerprint != "" {
		exhibit.PublicKeyChanged = exhibit.PreviousSPKIFingerprint != exhibit.SPKIFingerprint
	}

	previousSANs := normalizedCertificateNames(models.ParseSANs(previous.SANs))
	currentSANs := normalizedCertificateNames(models.ParseSANs(current.SANs))
	if len(previousSANs) > 0 && len(currentSANs) > 0 {
		exhibit.SANsAdded = certificateNameDifference(currentSANs, previousSANs)
		exhibit.SANsRemoved = certificateNameDifference(previousSANs, currentSANs)
	}
}

func normalizeIdentityField(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizedCertificateNames(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func certificateNameDifference(left, right []string) []string {
	existing := make(map[string]struct{}, len(right))
	for _, value := range right {
		existing[value] = struct{}{}
	}
	out := make([]string, 0)
	for _, value := range left {
		if _, ok := existing[value]; !ok {
			out = append(out, value)
		}
	}
	return out
}

func certificateExhibits(context diagnosisContext, investigation *models.Investigation) []models.CertificateExhibit {
	needed := make(map[string]struct{})
	if investigation != nil {
		for _, group := range investigation.ProviderGroups {
			for _, endpoint := range group.Endpoints {
				if endpoint.Fingerprint != "" {
					needed[endpoint.Fingerprint] = struct{}{}
				}
				if endpoint.DefaultFingerprint != "" {
					needed[endpoint.DefaultFingerprint] = struct{}{}
				}
			}
		}
		for _, change := range investigation.ChangeSequence {
			if change.Fingerprint != "" {
				needed[change.Fingerprint] = struct{}{}
			}
			if change.PreviousFingerprint != "" {
				needed[change.PreviousFingerprint] = struct{}{}
			}
		}
	}
	if context.state != nil {
		if investigationNeedsTLSLeaves(investigation) {
			for _, finding := range parseTLSFindings(context.state) {
				if finding.Fingerprint != "" {
					needed[finding.Fingerprint] = struct{}{}
				}
			}
		}
		if fp := context.state.CurrentFingerprint; fp != "" {
			needed[fp] = struct{}{}
		}
		if fp := context.state.ResidualFingerprint; fp != "" {
			needed[fp] = struct{}{}
		}
	}
	if len(needed) == 0 {
		return nil
	}
	probeByFingerprint := certificateProbeIndex(context)
	exhibits := make([]models.CertificateExhibit, 0, len(needed))
	for fingerprint := range needed {
		exhibit := models.CertificateExhibit{Fingerprint: fingerprint}
		if cert, ok := context.certificates[fingerprint]; ok {
			fillCertificateExhibitFromInventory(&exhibit, cert)
		}
		if probe, ok := probeByFingerprint[fingerprint]; ok {
			fillCertificateExhibitFromProbe(&exhibit, probe)
		}
		fillCertificateExhibitFromTLSFinding(&exhibit, context, fingerprint)
		exhibits = append(exhibits, exhibit)
	}
	sort.Slice(exhibits, func(left, right int) bool {
		leftTime, rightTime := time.Time{}, time.Time{}
		if exhibits[left].NotBefore != nil {
			leftTime = *exhibits[left].NotBefore
		}
		if exhibits[right].NotBefore != nil {
			rightTime = *exhibits[right].NotBefore
		}
		if !leftTime.Equal(rightTime) {
			return leftTime.Before(rightTime)
		}
		return exhibits[left].Fingerprint < exhibits[right].Fingerprint
	})
	return exhibits
}

func certificateProbeIndex(context diagnosisContext) map[string]models.EndpointProbe {
	index := make(map[string]models.EndpointProbe)
	probes := currentEndpointSurvey(context)
	for _, probe := range probes {
		if probe.Fingerprint != "" {
			if _, seen := index[probe.Fingerprint]; !seen {
				index[probe.Fingerprint] = probe
			}
		}
		for _, selection := range probe.SelectionProbes {
			if selection.Fingerprint == "" {
				continue
			}
			if _, seen := index[selection.Fingerprint]; seen {
				continue
			}
			// Keep the no-SNI leaf available to the certificate exhibit without
			// treating it as a second primary endpoint assignment.
			index[selection.Fingerprint] = models.EndpointProbe{
				IPAddress:           probe.IPAddress,
				RequestedSNI:        selection.RequestedSNI,
				Success:             selection.Success,
				Fingerprint:         selection.Fingerprint,
				SPKIFingerprint:     selection.SPKIFingerprint,
				IssuerCN:            selection.IssuerCN,
				CommonName:          selection.CommonName,
				KeyAlgorithm:        selection.KeyAlgorithm,
				KeySize:             selection.KeySize,
				SerialNumber:        selection.SerialNumber,
				SANs:                append([]string(nil), selection.SANs...),
				SANsHash:            selection.SANsHash,
				NotBefore:           selection.NotBefore,
				NotAfter:            selection.NotAfter,
				ChainFingerprints:   append([]string(nil), selection.ChainFingerprints...),
				CoversRequestedName: selection.CoversRequestedName,
				Findings:            append([]models.TLSFinding(nil), selection.Findings...),
			}
		}
	}
	return index
}

func fillCertificateExhibitFromInventory(exhibit *models.CertificateExhibit, cert models.Certificate) {
	exhibit.Issuer = cert.Issuer
	exhibit.IssuerCN = cert.IssuerCN
	exhibit.Subject = cert.Subject
	exhibit.CommonName = cert.CommonName
	exhibit.KeyAlgorithm = cert.KeyAlgorithm
	exhibit.KeySize = cert.KeySize
	exhibit.PublicKeyType = cert.PublicKeyType
	exhibit.SignatureAlgorithm = cert.SignatureAlgo
	exhibit.SPKIFingerprint = cert.SPKIFingerprint
	exhibit.SerialNumber = cert.SerialNumber
	exhibit.IsCA = cert.IsCA
	exhibit.SelfSigned = cert.SelfSigned
	if sans := models.ParseSANs(cert.SANs); len(sans) > 0 {
		exhibit.SANs = sans
	}
	exhibit.ValidityDays = cert.ValidityDays
	if jsonableTime(cert.NotBefore) && !cert.NotBefore.IsZero() {
		notBefore := cert.NotBefore
		exhibit.NotBefore = &notBefore
	}
	if jsonableTime(cert.NotAfter) && !cert.NotAfter.IsZero() {
		notAfter := cert.NotAfter
		exhibit.NotAfter = &notAfter
	}
	if chain := parseChainEntries(cert.Chain); len(chain) > 0 {
		exhibit.Chain = chain
	}
	if pemText := pemFromStoredDER(cert.RawCert); pemText != "" {
		exhibit.PEM = pemText
	}
}

func parseChainEntries(raw string) []models.ChainEntry {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" || raw == "[]" {
		return nil
	}
	var entries []models.ChainEntry
	if json.Unmarshal([]byte(raw), &entries) != nil || len(entries) == 0 {
		return nil
	}
	return entries
}

func pemFromStoredDER(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "BEGIN CERTIFICATE") {
		return raw
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(der) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func fillCertificateExhibitFromTLSFinding(exhibit *models.CertificateExhibit, context diagnosisContext, fingerprint string) {
	if exhibit == nil || fingerprint == "" || context.state == nil {
		return
	}
	for _, finding := range parseTLSFindings(context.state) {
		if finding.Fingerprint != fingerprint {
			continue
		}
		if exhibit.NotAfter == nil {
			if notAfter, ok := tlsLeafNotAfter(finding, context); ok && jsonableTime(notAfter) {
				value := notAfter
				exhibit.NotAfter = &value
			}
		}
		if exhibit.NotBefore == nil {
			if notBefore, ok := tlsLeafNotBefore(finding, context); ok && jsonableTime(notBefore) {
				value := notBefore
				exhibit.NotBefore = &value
			}
		}
	}
}

func fillCertificateExhibitFromProbe(exhibit *models.CertificateExhibit, probe models.EndpointProbe) {
	if exhibit.IssuerCN == "" {
		exhibit.IssuerCN = probe.IssuerCN
	}
	if exhibit.CommonName == "" {
		exhibit.CommonName = probe.CommonName
	}
	if exhibit.KeyAlgorithm == "" {
		exhibit.KeyAlgorithm = probe.KeyAlgorithm
	}
	if exhibit.SPKIFingerprint == "" {
		exhibit.SPKIFingerprint = probe.SPKIFingerprint
	}
	if exhibit.SerialNumber == "" {
		exhibit.SerialNumber = probe.SerialNumber
	}
	if len(exhibit.SANs) == 0 && len(probe.SANs) > 0 {
		exhibit.SANs = append([]string(nil), probe.SANs...)
	}
	if exhibit.NotBefore == nil && probe.NotBefore != nil && jsonableTime(*probe.NotBefore) && !probe.NotBefore.IsZero() {
		notBefore := *probe.NotBefore
		exhibit.NotBefore = &notBefore
	}
	if exhibit.NotAfter == nil && probe.NotAfter != nil && jsonableTime(*probe.NotAfter) && !probe.NotAfter.IsZero() {
		notAfter := *probe.NotAfter
		exhibit.NotAfter = &notAfter
	}
	if exhibit.ValidityDays == 0 && exhibit.NotBefore != nil && exhibit.NotAfter != nil && exhibit.NotAfter.After(*exhibit.NotBefore) {
		exhibit.ValidityDays = int(exhibit.NotAfter.Sub(*exhibit.NotBefore).Hours() / 24)
	}
}

func cdnFact(cdn *models.CDNEvidence) string {
	if cdn == nil {
		return ""
	}
	switch cdn.Completeness {
	case models.CDNCompletenessBoth, models.CDNCompletenessPrefix, models.CDNCompletenessDirectory:
		source := "published prefixes"
		if cdn.Completeness == models.CDNCompletenessDirectory {
			source = "numbering-authority ASN/org records"
		} else if cdn.Completeness == models.CDNCompletenessBoth {
			source = "published prefixes, DNS control-plane records or numbering-authority identity"
		}
		if cdn.DistinctVendors <= 1 {
			return fmt.Sprintf("CDN identification is complete from %s (%s): every answering endpoint maps to one named CDN, so this is not a multi-CDN split.", source, strings.Join(namedVendors(cdn), ", "))
		}
		return fmt.Sprintf("CDN identification is complete from %s: %d named CDN(s) (%s).", source, cdn.DistinctVendors, strings.Join(namedVendors(cdn), ", "))
	case models.CDNCompletenessPartial:
		return fmt.Sprintf("CDN identification is partial: %d endpoint(s) mapped to a published prefix and %d did not, so the multi-CDN verdict stays on the IPv4 /16 and IPv6 /32 partition.", cdn.IdentifiedCount, len(cdn.Unidentified))
	case models.CDNCompletenessHostname:
		return fmt.Sprintf("The hostname has a CDN control-plane record (%s), but endpoint addresses are not attributed to a published prefix, so the multi-CDN verdict stays on the network partition.", strings.Join(cdn.HostnameVendors, ", "))
	default:
		return "No CNAME, HTTPS/SVCB or published CDN prefix identified a vendor; the multi-CDN verdict uses the IPv4 /16 and IPv6 /32 partition."
	}
}

func namedVendors(cdn *models.CDNEvidence) []string {
	if cdn == nil {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, vendor := range cdn.EndpointVendors {
		if vendor == "" {
			continue
		}
		if _, ok := seen[vendor]; ok {
			continue
		}
		seen[vendor] = struct{}{}
		out = append(out, vendor)
	}
	sort.Strings(out)
	return out
}

func formatDays(value float64) string {
	if value == 1 {
		return "1 day"
	}
	if value == float64(int(value)) {
		return fmt.Sprintf("%d days", int(value))
	}
	return fmt.Sprintf("%.1f days", value)
}

func maxInt(value, floor int) int {
	if value < floor {
		return floor
	}
	return value
}
