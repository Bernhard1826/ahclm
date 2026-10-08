package database

import (
	"fmt"
	"strings"

	"ahclm/internal/models"
)

// buildFindingImpact writes what the retained measurements imply for clients
// and operators. It does not invent user harm, compromise, or a global outage.
func buildFindingImpact(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis, investigation *models.Investigation) *models.FindingImpact {
	impact := &models.FindingImpact{
		SeverityCeiling: models.ImpactNone,
		NotEstablished:  defaultImpactNotEstablished(),
	}
	if investigation != nil && investigation.FindingClass == models.FindingExpected && diagnosis.PrimaryCode == models.DivergencePerEndpoint && diagnosis.Divergence != nil {
		// Expected, but the split is a measured fact: clients reach different
		// valid leaves. Only leaf or key pinning and single-fingerprint checks
		// see it.
		impact.SeverityCeiling = models.ImpactSplitView
		impact.Summary = "No incident is opened: every sampled leaf is valid for the name. Clients that land on different endpoints receive different leaves, which only matters to leaf or key pinning and to checks that expect one fingerprint per name."
		impact.Effects = []models.ImpactEffect{splitViewEffect(diagnosis.Divergence)}
		return impact
	}
	if investigation != nil && investigation.FindingClass == models.FindingExpected {
		impact.Summary = "No client-facing incident is opened. The retained assignment is an expected deployment property."
		impact.Effects = []models.ImpactEffect{{
			Kind:     "proven",
			Code:     "no_incident",
			Label:    "No incident impact",
			Claim:    impact.Summary,
			Audience: "operators",
			Evidence: compactImpactEvidence(investigation.WhyProblem, diagnosis.BenignExplanation),
		}}
		return impact
	}

	switch {
	case isTLSValidationType(item.Type):
		fillTLSImpact(impact, item, context, diagnosis)
	case isCertificateConditionType(item.Type):
		fillCertificateConditionImpact(impact, item, context, diagnosis)
	case item.Type == models.ObsDeploymentFailure:
		fillDiversityImpact(impact, diagnosis, investigation)
	case item.Type == models.ObsStaleAfterChange:
		fillStaleImpact(impact, diagnosis, investigation)
	case item.Type == "same_key":
		fillSameKeyImpact(impact, diagnosis)
	case item.Type == "frequent_change" || item.Type == "early_renewal":
		fillChurnImpact(impact, item, diagnosis)
	default:
		impact.Summary = "The retained measurements describe a certificate condition; they do not establish a client-visible outage."
		impact.SeverityCeiling = models.ImpactMeasurementOnly
	}
	if impact.Summary == "" {
		impact.Summary = "Impact is limited to what the retained handshakes and DNS answers show."
	}
	if len(impact.Effects) == 0 && investigation != nil && investigation.FindingClass == models.FindingInsufficient {
		impact.SeverityCeiling = models.ImpactMeasurementOnly
		impact.Summary = "The retained sample is too small to name a client-facing consequence."
		impact.Effects = []models.ImpactEffect{{
			Kind:     "inferred",
			Code:     "insufficient_impact",
			Label:    "Consequence not established",
			Claim:    impact.Summary,
			Audience: "operators",
		}}
	}
	return impact
}

func defaultImpactNotEstablished() []string {
	return []string{
		"User account compromise, phishing success, or stolen session cookies.",
		"Private-key theft. Same-key replacement only shows the public key did not change.",
		"A worldwide outage. This collector has one TLS vantage.",
		"How many users were affected. Handshake counts here are samples, not traffic.",
	}
}

func fillTLSImpact(impact *models.FindingImpact, item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis) {
	rows := tlsFindingsForCode(parseTLSFindings(context.state), item.Type)
	ips := uniqueFindingIPs(rows)
	ipText := sampledIPText(ips)
	switch item.Type {
	case "expired_endpoint":
		impact.SeverityCeiling = models.ImpactClientRejection
		impact.Summary = "A relying party that checks NotAfter will refuse the handshake at the sampled endpoint" + ipSuffix(ipText) + "."
		impact.Effects = withOptionalEffect(
			rejectionEffect("expired_leaf_rejected", "Clients that enforce NotAfter reject the handshake", impact.Summary, compactImpactEvidence(diagnosis.Summary, strings.Join(ips, ", "))),
			splitIfPartial(ips, diagnosis),
		)
	case "hostname_mismatch":
		if reason := nonHTTPSIdentityReason(item.Domain); reason != "" {
			impact.SeverityCeiling = models.ImpactMeasurementOnly
			impact.Summary = "The queried name is not an HTTPS identity name, so a hostname mismatch here is not a web-client rejection."
			impact.Effects = []models.ImpactEffect{{
				Kind: "proven", Code: "non_https_identity", Label: "Not an HTTPS client identity",
				Claim: impact.Summary, Audience: "operators", Evidence: compactImpactEvidence(reason),
			}}
			return
		}
		impact.SeverityCeiling = models.ImpactClientRejection
		impact.Summary = "A relying party that checks the name will refuse the handshake at the sampled endpoint" + ipSuffix(ipText) + "."
		impact.Effects = withOptionalEffect(
			rejectionEffect("name_mismatch_rejected", "Clients that enforce the name refuse the handshake", impact.Summary, compactImpactEvidence(diagnosis.Summary, ipText)),
			splitIfPartial(ips, diagnosis),
		)
	case "not_yet_valid":
		impact.SeverityCeiling = models.ImpactClientRejection
		impact.Summary = "A relying party that checks NotBefore will refuse the handshake at the sampled endpoint" + ipSuffix(ipText) + "."
		impact.Effects = []models.ImpactEffect{
			rejectionEffect("not_yet_valid_rejected", "Clients that enforce NotBefore reject the handshake", impact.Summary, compactImpactEvidence(diagnosis.Summary, ipText)),
		}
	case "local_chain_validation_failed":
		impact.SeverityCeiling = models.ImpactMeasurementOnly
		impact.Summary = "This collector's x509.Verify rejected the chain. That is this machine's roots and path construction, not a global browser result."
		impact.Effects = []models.ImpactEffect{{
			Kind: "proven", Code: "local_verify_failed", Label: "Collector chain verification failed",
			Claim: impact.Summary, Audience: "operators", Evidence: compactImpactEvidence(diagnosis.Summary, ipText),
		}}
		impact.NotEstablished = append(impact.NotEstablished, "That every browser or OS trust store would also reject this chain.")
	case "endpoint_probe_inconclusive":
		impact.SeverityCeiling = models.ImpactMeasurementOnly
		impact.Summary = "Extra addresses did not return a certificate, so client-visible status there is unknown."
		impact.Effects = []models.ImpactEffect{{
			Kind: "proven", Code: "unknown_endpoint", Label: "Unprobed or failed extra endpoints",
			Claim: impact.Summary, Audience: "operators", Evidence: compactImpactEvidence(diagnosis.Summary),
		}}
	}
}

func fillCertificateConditionImpact(impact *models.FindingImpact, item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis) {
	cert, hasCert := currentCertificate(context)
	ip := servedFrom(context.state)
	switch item.Type {
	case "expired_served":
		impact.SeverityCeiling = models.ImpactClientRejection
		days := 0
		if hasCert && !cert.NotAfter.IsZero() {
			days = daysPastNotAfter(cert.NotAfter, certificateConditionCheckedAt(item, context.state))
		}
		impact.Summary = "A relying party that checks NotAfter will refuse the currently recorded leaf."
		if days > 0 {
			impact.Summary = fmt.Sprintf("A relying party that checks NotAfter will refuse the currently recorded leaf (%d day(s) past NotAfter).", days)
		}
		impact.Effects = []models.ImpactEffect{
			rejectionEffect("expired_leaf_served", "Clients that enforce NotAfter reject this name", impact.Summary, compactImpactEvidence(diagnosis.Summary, ip)),
		}
	case "expired_observed":
		impact.SeverityCeiling = models.ImpactMeasurementOnly
		impact.Summary = "An expired leaf was recorded while the row was dormant. That historical observation does not establish that clients currently fail."
		impact.Effects = []models.ImpactEffect{{
			Kind: "proven", Code: "historical_expiry", Label: "Historical expired observation",
			Claim: impact.Summary, Audience: "operators", Evidence: compactImpactEvidence(diagnosis.Summary),
		}}
	case "expiring_soon":
		impact.SeverityCeiling = models.ImpactPendingExpiry
		days := 0
		if hasCert && !cert.NotAfter.IsZero() {
			days = models.DaysUntil(cert.NotAfter, certificateConditionCheckedAt(item, context.state))
			if days < 0 {
				days = 0
			}
		}
		impact.Summary = fmt.Sprintf("If this leaf is not replaced, clients that enforce NotAfter will start refusing it in %d day(s).", days)
		impact.Effects = []models.ImpactEffect{{
			Kind: "inferred", Code: "pending_notafter", Label: "Pending client rejection if not replaced",
			Claim: impact.Summary, Audience: "clients", Evidence: compactImpactEvidence(diagnosis.Summary),
		}}
		impact.NotEstablished = append(impact.NotEstablished, "That the operator will fail to replace the leaf before NotAfter.")
	case "revoked":
		impact.SeverityCeiling = models.ImpactClientRejection
		impact.Summary = "A relying party that checks OCSP or CRL for this leaf will treat it as revoked."
		impact.Effects = []models.ImpactEffect{
			rejectionEffect("revoked_leaf", "Clients that check revocation refuse this leaf", impact.Summary, compactImpactEvidence(diagnosis.Summary)),
		}
		impact.NotEstablished = append(impact.NotEstablished, "That every client actually performs a live revocation check.")
	case models.ObsResidual:
		impact.SeverityCeiling = models.ImpactClientRejection
		duration := residualDuration(item, context)
		claim := "A revoked leaf remained reachable after the CA revocation timestamp, so clients that still reach that endpoint can be offered a revoked certificate."
		if duration > 0 {
			claim = fmt.Sprintf("A revoked leaf remained reachable for at least %.1f hour(s) after the CA revocation timestamp.", duration.Hours())
		}
		impact.Summary = claim
		impact.Effects = []models.ImpactEffect{
			rejectionEffect("revoked_leaf_still_served", "Revoked leaf still offered after CA timestamp", claim, compactImpactEvidence(diagnosis.Summary)),
		}
	case "unreachable", "measurement_failed":
		impact.SeverityCeiling = models.ImpactMeasurementOnly
		impact.Summary = "This collector did not obtain a certificate. That is this vantage's reachability, not a proven global outage."
		impact.Effects = []models.ImpactEffect{{
			Kind: "proven", Code: "collector_unreachable", Label: "Collector handshake failed",
			Claim: impact.Summary, Audience: "operators", Evidence: compactImpactEvidence(diagnosis.Summary),
		}}
	case "ari_emergency":
		impact.SeverityCeiling = models.ImpactPendingExpiry
		impact.Summary = "The CA pulled the ARI renewal window to the present. That is a CA-side signal to replace the leaf, not a measured client outage."
		impact.Effects = []models.ImpactEffect{{
			Kind: "proven", Code: "ari_window_now", Label: "CA asked for immediate renewal",
			Claim: impact.Summary, Audience: "operators", Evidence: compactImpactEvidence(diagnosis.Summary),
		}}
		impact.Effects = append(impact.Effects, models.ImpactEffect{
			Kind: "inferred", Code: "mass_revocation_signal", Label: "May precede mass revocation",
			Claim:    "RFC 9773 uses an ARI window pulled to now as an emergency-renewal signal, often before a mass revocation. This collector did not observe the revocation itself.",
			Audience: "operators",
			Evidence: compactImpactEvidence(diagnosis.Summary),
		})
	}
}

func fillDiversityImpact(impact *models.FindingImpact, diagnosis models.CauseDiagnosis, investigation *models.Investigation) {
	d := diagnosis.Divergence
	if d == nil {
		impact.SeverityCeiling = models.ImpactMeasurementOnly
		impact.Summary = "Mixed certificates were recorded, but the retained sample does not name a client-facing consequence."
		return
	}
	switch diagnosis.PrimaryCode {
	case models.DivergenceDefectiveEndpoint:
		impact.SeverityCeiling = models.ImpactClientRejection
		n := len(d.DefectiveEndpoints)
		impact.Summary = fmt.Sprintf("%d sampled endpoint(s) served a leaf that is not currently valid for the queried name. Clients that land there and enforce name, time or chain checks will refuse.", n)
		impact.Effects = []models.ImpactEffect{
			rejectionEffect("defective_endpoint", "Invalid leaf at a sampled endpoint", impact.Summary, compactImpactEvidence(strings.Join(d.DefectiveEndpoints, ", "))),
			splitViewEffect(d),
		}
	case models.DivergenceStuckRollout, models.DivergenceIntraFleet:
		impact.SeverityCeiling = models.ImpactSplitView
		impact.Summary = "Clients that land on different sampled endpoints of this name can be offered different currently valid leaves. That is a split view, not a proven outage."
		impact.Effects = []models.ImpactEffect{splitViewEffect(d)}
		if d.IntraGroupConflicts > 0 {
			impact.Effects = append(impact.Effects, models.ImpactEffect{
				Kind: "proven", Code: "intra_operator_split", Label: "Split inside one operator network",
				Claim:    fmt.Sprintf("%d provider network(s) served more than one leaf, so the split is not explained by two named CDNs.", d.IntraGroupConflicts),
				Audience: "operators",
			})
		}
	case models.DivergencePropagating:
		impact.SeverityCeiling = models.ImpactSplitView
		impact.Summary = "During the current replacement, clients can still be offered either the predecessor or the successor, depending on which sampled endpoint they reach."
		impact.Effects = []models.ImpactEffect{
			{Kind: "proven", Code: "transient_split", Label: "Transient split view during replacement", Claim: impact.Summary, Audience: "clients"},
		}
	default:
		if d.DistinctLeaves >= 2 {
			impact.SeverityCeiling = models.ImpactSplitView
			impact.Summary = "Sampled endpoints served more than one leaf. A client-visible split is possible; the retained sample does not prove every client sees it."
			impact.Effects = []models.ImpactEffect{splitViewEffect(d)}
		} else if investigation != nil {
			impact.SeverityCeiling = models.ImpactMeasurementOnly
			impact.Summary = "The current sampled endpoints do not establish a live client-facing split."
		}
	}
}

func fillStaleImpact(impact *models.FindingImpact, diagnosis models.CauseDiagnosis, _ *models.Investigation) {
	d := diagnosis.Divergence
	switch diagnosis.PrimaryCode {
	case models.DivergenceStuckRollout:
		impact.SeverityCeiling = models.ImpactSplitView
		hours := 0.0
		if d != nil {
			hours = d.ResidueHours
			if hours == 0 {
				hours = d.PredecessorSpanHours
			}
		}
		impact.Summary = "After the DNS/IP-set change, an address still in the current resolver answers still serves the predecessor leaf."
		if hours > 0 {
			impact.Summary = fmt.Sprintf("After the DNS/IP-set change, an address still in the current resolver answers has served the predecessor leaf for at least %.1f hour(s).", hours)
		}
		impact.Effects = []models.ImpactEffect{
			{Kind: "proven", Code: "stale_active_endpoint", Label: "Current DNS still offers the predecessor", Claim: impact.Summary, Audience: "clients"},
		}
		if d != nil && len(d.ActivePredecessorEndpoints) > 0 {
			impact.Effects[0].Evidence = compactImpactEvidence(strings.Join(d.ActivePredecessorEndpoints, ", "))
		}
	case models.DivergencePropagating:
		impact.SeverityCeiling = models.ImpactSplitView
		impact.Summary = "Predecessor and successor are both still reachable after the topology change. Clients can still land on the old leaf until the assignment settles."
		impact.Effects = []models.ImpactEffect{
			{Kind: "proven", Code: "cutover_in_flight", Label: "Cutover not settled", Claim: impact.Summary, Audience: "clients"},
		}
	case "dns_cutover_before_tls_deployment":
		impact.SeverityCeiling = models.ImpactSplitView
		impact.Summary = "A retired edge still serves the previous leaf while a new edge already serves the successor. Clients following current DNS get the new leaf; clients that still reach the old address get the old one."
		impact.Effects = []models.ImpactEffect{
			{Kind: "proven", Code: "retired_edge_residue", Label: "Old address still serves the old leaf", Claim: impact.Summary, Audience: "clients"},
		}
	default:
		impact.SeverityCeiling = models.ImpactMeasurementOnly
		impact.Summary = "The current sampled endpoints do not establish that clients still receive a leftover predecessor on live DNS."
	}
}

func fillSameKeyImpact(impact *models.FindingImpact, diagnosis models.CauseDiagnosis) {
	shape := diagnosis.ChurnShape
	same := 0
	if shape != nil {
		same = shape.SameEndpointChanges
	}
	switch diagnosis.PrimaryCode {
	case "same_key_unestablished", "concurrent_same_key":
		impact.SeverityCeiling = models.ImpactMeasurementOnly
		impact.Summary = "A shared public key was recorded, but replacement in time on one address is not established, so key-continuity impact is not proven."
		return
	}
	impact.SeverityCeiling = models.ImpactKeyContinuity
	impact.Summary = "The new leaf still uses the previous public key. Anyone who already has that public key can impersonate the new leaf the same way they could impersonate the old one."
	if same > 0 {
		impact.Summary = fmt.Sprintf("On the same address, the new leaf still uses the previous public key (%d same-address pair(s)). Anyone who already has that public key can impersonate the new leaf the same way they could impersonate the old one.", same)
	}
	impact.Effects = []models.ImpactEffect{{
		Kind: "proven", Code: "spki_unchanged", Label: "Public key did not change",
		Claim:    fmt.Sprintf("Leaf fingerprints differ while SPKI fingerprints match (%d same-address pair(s)).", same),
		Audience: "relying_parties",
	}, {
		Kind: "inferred", Code: "compromise_window_continues", Label: "A prior key-compromise would still apply",
		Claim:    impact.Summary,
		Audience: "operators",
		Evidence: compactImpactEvidence("SPKI fingerprints match across the replacement"),
	}}
	impact.NotEstablished = append(impact.NotEstablished, "That the private key was stolen. Same-key replacement only shows the public key did not rotate.")
}

func fillChurnImpact(impact *models.FindingImpact, item models.Anomaly, diagnosis models.CauseDiagnosis) {
	shape := diagnosis.ChurnShape
	same, remaining, validity, replacements := 0, 0, 0, 0
	if shape != nil {
		same = shape.SameEndpointChanges
		remaining = shape.MedianRemainingDays
		validity = shape.MedianValidityDays
		replacements = shape.EffectiveReplacements
		if replacements == 0 {
			replacements = shape.ChangeEvents
		}
	}
	switch diagnosis.PrimaryCode {
	case "concurrent_multi_certificate_pool", "short_lived_certificate_automation":
		impact.SeverityCeiling = models.ImpactNone
		impact.Summary = "The change counter is sampling a designed multi-certificate or short-lived schedule. No extra client-facing failure is established."
		return
	case "endpoint_attribution_unavailable", "early_renewal_unestablished", "replacement_mechanism_unestablished":
		impact.SeverityCeiling = models.ImpactMeasurementOnly
		impact.Summary = "Leaves differed across samples, but replacement in time is not established, so extra-issuance impact is not proven."
		return
	}
	impact.SeverityCeiling = models.ImpactExtraIssuance
	if item.Type == "early_renewal" && remaining > 0 {
		impact.Summary = fmt.Sprintf("A still-valid leaf was replaced %d day(s) before NotAfter. Clients keep working if they get the successor; the cost is extra issuance and a shorter effective lifetime.", remaining)
	} else if remaining > 0 && validity > 0 {
		impact.Summary = fmt.Sprintf("The same address swapped in another leaf when about %d of %d validity day(s) remained. Clients keep working; operators spend extra issuances instead of using one leaf for most of its life.", remaining, validity)
	} else {
		impact.Summary = fmt.Sprintf("%d replacement(s) were measured on a retained address. Clients that follow the new leaf keep working; extra issuance is the established operator cost.", maxInt(replacements, same))
	}
	impact.Effects = []models.ImpactEffect{{
		Kind: "proven", Code: "extra_issuance", Label: "Extra issuance instead of finishing the current lifetime",
		Claim:    impact.Summary,
		Audience: "operators",
		Evidence: compactImpactEvidence(fmt.Sprintf("%d same-address replacement(s)", same)),
	}}
	if remaining > 30 {
		impact.Effects = append(impact.Effects, models.ImpactEffect{
			Kind: "inferred", Code: "shortened_effective_lifetime", Label: "Effective lifetime much shorter than NotAfter",
			Claim:    fmt.Sprintf("The predecessor still had %d day(s) remaining, so relying parties that cache by NotAfter overestimate how long that leaf will be served.", remaining),
			Audience: "relying_parties",
		})
	}
}

func withOptionalEffect(base models.ImpactEffect, extra models.ImpactEffect) []models.ImpactEffect {
	out := []models.ImpactEffect{base}
	if extra.Code != "" || extra.Claim != "" {
		out = append(out, extra)
	}
	return out
}

func rejectionEffect(code, label, claim string, evidence []string) models.ImpactEffect {
	return models.ImpactEffect{
		Kind: "proven", Code: code, Label: label, Claim: claim, Audience: "clients", Evidence: evidence,
	}
}

func splitViewEffect(d *models.EndpointDivergence) models.ImpactEffect {
	if d == nil {
		return models.ImpactEffect{Kind: "inferred", Code: "possible_split", Label: "Possible split view", Claim: "Different sampled endpoints served different leaves.", Audience: "clients"}
	}
	return models.ImpactEffect{
		Kind:     "proven",
		Code:     "split_view",
		Label:    "Different endpoints offer different leaves",
		Claim:    fmt.Sprintf("%d answering endpoint(s) served %d distinct leaf certificate(s).", d.EndpointsAnswered, d.DistinctLeaves),
		Audience: "clients",
	}
}

func splitIfPartial(ips []string, diagnosis models.CauseDiagnosis) models.ImpactEffect {
	if diagnosis.Divergence != nil && diagnosis.Divergence.EndpointsAnswered > len(ips) && len(ips) > 0 {
		return models.ImpactEffect{
			Kind: "proven", Code: "partial_rejection", Label: "Only some sampled endpoints reject",
			Claim:    "Other sampled endpoints of this name did not carry this TLS finding, so clients may succeed or fail depending on which address they reach.",
			Audience: "clients",
		}
	}
	return models.ImpactEffect{}
}

func sampledIPText(ips []string) string {
	switch len(ips) {
	case 0:
		return ""
	case 1:
		return ips[0]
	default:
		if len(ips) > 4 {
			return strings.Join(ips[:4], ", ") + fmt.Sprintf(" +%d", len(ips)-4)
		}
		return strings.Join(ips, ", ")
	}
}

func ipSuffix(ipText string) string {
	if ipText == "" {
		return ""
	}
	return " (" + ipText + ")"
}

func compactImpactEvidence(parts ...string) []string {
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		text := strings.TrimSpace(part)
		if text == "" {
			continue
		}
		if _, ok := seen[text]; ok {
			continue
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	return out
}
