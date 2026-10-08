package database

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"ahclm/internal/models"
)

const (
	tlsCauseExpiredLeaf      = "expired_leaf_at_sampled_endpoint"
	tlsCauseNameMismatch     = "name_mismatch_at_sampled_endpoint"
	tlsCauseNonHTTPSIdentity = "non_https_identity_name"
	tlsCauseNotYetValid      = "not_yet_valid_leaf_at_sampled_endpoint"
	tlsCauseLocalChain       = "local_chain_invalid_at_sampled_endpoint"
	tlsCauseProbeIncomplete  = "endpoint_probe_incomplete"
)

func isTLSValidationType(code string) bool {
	switch code {
	case "expired_endpoint", "hostname_mismatch", "not_yet_valid", "local_chain_validation_failed", "endpoint_probe_inconclusive":
		return true
	default:
		return false
	}
}

func parseTLSFindings(dc *models.DomainCertificate) []models.TLSFinding {
	if dc == nil || strings.TrimSpace(dc.TLSFindings) == "" || dc.TLSFindings == "null" || dc.TLSFindings == "[]" {
		return nil
	}
	var findings []models.TLSFinding
	if json.Unmarshal([]byte(dc.TLSFindings), &findings) != nil {
		return nil
	}
	return findings
}

func tlsFindingsForCode(findings []models.TLSFinding, code string) []models.TLSFinding {
	out := make([]models.TLSFinding, 0)
	for _, finding := range findings {
		if finding.Code == code {
			out = append(out, finding)
		}
	}
	return out
}

func tlsCheckedAt(dc *models.DomainCertificate, item models.Anomaly) time.Time {
	if dc != nil && dc.TLSCheckedAt != nil && !dc.TLSCheckedAt.IsZero() {
		return dc.TLSCheckedAt.UTC()
	}
	if !item.DetectedAt.IsZero() {
		return item.DetectedAt.UTC()
	}
	return time.Now().UTC()
}

func seedTLSValidationAnomaly(dc models.DomainCertificate, code string, rows []models.TLSFinding) models.Anomaly {
	checkedAt := tlsCheckedAt(&dc, models.Anomaly{})
	fingerprint := dc.CurrentFingerprint
	for _, row := range rows {
		if row.Fingerprint != "" {
			fingerprint = row.Fingerprint
			break
		}
	}
	item := models.Anomaly{
		Domain:          dc.Domain,
		Type:            code,
		Severity:        "warning",
		Fingerprint:     fingerprint,
		DetectedAt:      checkedAt,
		OccurrenceCount: 1,
	}
	diagnosis := inferTLSValidationDiagnosis(item, diagnosisContext{state: &dc})
	item.Description = tlsValidationProblem(item, diagnosis, rows, checkedAt)
	reason, evidence := tlsValidationConfirmed(item, diagnosis, rows, checkedAt)
	state := models.EvidenceStatusComplete
	if code == "endpoint_probe_inconclusive" {
		state = models.EvidenceStatusPending
	}
	return withAnomalyCause(item, anomalyCause{confirmedReason: reason, confirmedEvidence: evidence, evidenceStatus: state})
}

// seedTLSValidationObservation builds the index record without running the
// cause classifier. The Anomalies endpoint only needs the sampled condition
// and the direct TLS evidence; the full diagnosis remains on the domain API.
func seedTLSValidationObservation(dc models.DomainCertificate, code string, rows []models.TLSFinding) models.Anomaly {
	checkedAt := tlsCheckedAt(&dc, models.Anomaly{})
	fingerprint := dc.CurrentFingerprint
	for _, row := range rows {
		if row.Fingerprint != "" {
			fingerprint = row.Fingerprint
			break
		}
	}
	item := models.Anomaly{
		Domain:          dc.Domain,
		Type:            code,
		Severity:        "warning",
		Fingerprint:     fingerprint,
		DetectedAt:      checkedAt,
		OccurrenceCount: 1,
	}
	item.Description = tlsValidationProblem(item, models.CauseDiagnosis{}, rows, checkedAt)
	item.Evidence = tlsFindingEvidence(item, diagnosisContext{}, rows, checkedAt)
	item.ConfirmedEvidence = append([]string(nil), item.Evidence...)
	if code == "endpoint_probe_inconclusive" {
		item.EvidencePendingReason = "The sampled endpoint did not return a certificate for the additional probe."
	}
	return item
}

func inferTLSValidationDiagnosis(item models.Anomaly, context diagnosisContext) models.CauseDiagnosis {
	findings := parseTLSFindings(context.state)
	rows := tlsFindingsForCode(findings, item.Type)
	checkedAt := tlsCheckedAt(context.state, item)
	evidence := tlsFindingEvidence(item, context, rows, checkedAt)
	related := relatedTLSEvidence(item, findings, rows)
	evidence = uniqueEvidenceStrings(append(evidence, related...))

	diagnosis := models.CauseDiagnosis{
		Confidence:           "high",
		EvidenceCompleteness: 1,
		MeasuredRounds:       len(context.snapshots),
		CauseStatus:          "established",
		Hypotheses:           nil,
	}
	if context.state != nil {
		diagnosis.EvidenceCompleteness = completenessScore(len(context.snapshots), len(context.observations), true)
	}

	switch item.Type {
	case "expired_endpoint":
		diagnosis.PrimaryCode = tlsCauseExpiredLeaf
		diagnosis.PrimaryLabel = "Expired leaf at sampled endpoint"
		diagnosis.Summary = tlsExpiredConclusion(rows, checkedAt)
		diagnosis.MeasurementPlan = []string{"A later handshake at the same address serving a leaf whose NotAfter is still in the future would remove this reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       tlsCauseExpiredLeaf,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "The captured leaf NotAfter is before the TLS check time on a completed handshake.",
			Evidence:   evidence,
			Contradictions: []string{
				"A later handshake at the same address with NotAfter still in the future would remove this reading.",
			},
		}}
	case "hostname_mismatch":
		if reason := nonHTTPSIdentityReason(item.Domain); reason != "" {
			diagnosis.PrimaryCode = tlsCauseNonHTTPSIdentity
			diagnosis.PrimaryLabel = "Non-HTTPS identity name"
			diagnosis.Summary = reason
			diagnosis.BenignExplanation = reason
			diagnosis.CauseStatus = "established"
			diagnosis.MeasurementPlan = []string{"This name is not a site HTTPS identity. A later handshake cannot make the alias match the leaf, and that is not a site certificate defect."}
			diagnosis.Hypotheses = []models.CauseHypothesis{{
				Code:       tlsCauseNonHTTPSIdentity,
				Label:      diagnosis.PrimaryLabel,
				Score:      1,
				Confidence: "high",
				Rationale:  reason,
				Evidence:   evidence,
			}}
			break
		}
		diagnosis.PrimaryCode = tlsCauseNameMismatch
		diagnosis.PrimaryLabel = "Name mismatch at sampled endpoint"
		diagnosis.Summary = tlsMismatchConclusion(item.Domain, rows)
		diagnosis.MeasurementPlan = []string{"A later handshake at the same address whose leaf verifies for this name would remove this reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       tlsCauseNameMismatch,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "VerifyHostname on the captured leaf failed for the queried name.",
			Evidence:   evidence,
		}}
	case "not_yet_valid":
		diagnosis.PrimaryCode = tlsCauseNotYetValid
		diagnosis.PrimaryLabel = "Leaf not yet valid at sampled endpoint"
		diagnosis.Summary = tlsNotYetValidConclusion(rows, checkedAt)
		diagnosis.MeasurementPlan = []string{"A later handshake after NotBefore, or a leaf whose NotBefore is already in the past, would remove this reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       tlsCauseNotYetValid,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "The captured leaf NotBefore is after the TLS check time.",
			Evidence:   evidence,
		}}
	case "local_chain_validation_failed":
		diagnosis.PrimaryCode = tlsCauseLocalChain
		diagnosis.PrimaryLabel = "Local chain validation failed at sampled endpoint"
		diagnosis.Summary = tlsLocalChainConclusion(rows)
		diagnosis.MeasurementPlan = []string{"This is the collector's verifier and local roots, not a global browser result. A chain that verifies here, or an independent public verifier that accepts the same chain, would change this reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       tlsCauseLocalChain,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "x509.Verify against the collector's roots failed on the captured chain after leaf time-validity checks were excluded.",
			Evidence:   evidence,
		}}
	case "endpoint_probe_inconclusive":
		diagnosis.PrimaryCode = tlsCauseProbeIncomplete
		diagnosis.PrimaryLabel = "Additional endpoint check incomplete"
		diagnosis.Summary = tlsInconclusiveConclusion(rows)
		diagnosis.CauseStatus = "unestablished"
		diagnosis.Confidence = "low"
		diagnosis.MeasurementPlan = []string{"A later probe that completes a TLS handshake at the unanswered address would replace this incomplete check with a certificate reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       tlsCauseProbeIncomplete,
			Label:      diagnosis.PrimaryLabel,
			Score:      0.4,
			Confidence: "low",
			Rationale:  "The extra endpoint probe did not obtain a certificate, so certificate status at that address is unknown.",
			Evidence:   evidence,
		}}
	default:
		return inferBasicDiagnosis(item, context)
	}

	if len(rows) == 0 {
		diagnosis.CauseStatus = "unestablished"
		diagnosis.Confidence = "low"
		diagnosis.Summary = "No retained TLS finding of this code was attached to the domain row."
		diagnosis.MeasurementPlan = []string{"Retain the sampled-endpoint TLS finding with IP, fingerprint and the named check detail."}
	}
	return diagnosis
}

func tlsValidationProblem(item models.Anomaly, diagnosis models.CauseDiagnosis, rows []models.TLSFinding, checkedAt time.Time) string {
	switch item.Type {
	case "expired_endpoint":
		return tlsExpiredProblem(rows, checkedAt)
	case "hostname_mismatch":
		return tlsMismatchProblem(item.Domain, rows)
	case "not_yet_valid":
		return tlsNotYetValidProblem(rows, checkedAt)
	case "local_chain_validation_failed":
		return tlsLocalChainProblem(rows)
	case "endpoint_probe_inconclusive":
		return tlsInconclusiveProblem(rows)
	default:
		if item.Description != "" {
			return item.Description
		}
		return diagnosis.Summary
	}
}

func tlsValidationWhy(item models.Anomaly, context diagnosisContext, rows []models.TLSFinding, checkedAt time.Time) string {
	switch item.Type {
	case "expired_endpoint":
		return tlsExpiredWhy(item, context, rows, checkedAt)
	case "hostname_mismatch":
		if len(rows) == 0 {
			return "No retained hostname-mismatch finding was attached to this domain row."
		}
		if reason := nonHTTPSIdentityReason(item.Domain); reason != "" {
			return reason
		}
		return "VerifyHostname on the captured leaf failed for the queried name."
	case "not_yet_valid":
		if len(rows) == 0 {
			return "No retained not-yet-valid finding was attached to this domain row."
		}
		return "The captured leaf NotBefore is after the TLS check time, so the leaf is not yet a valid server certificate."
	case "local_chain_validation_failed":
		if len(rows) == 0 {
			return "No retained chain-validation finding was attached to this domain row."
		}
		return "The collector's x509.Verify rejected the captured chain. That is this machine's roots and path construction, not a global browser result."
	case "endpoint_probe_inconclusive":
		if len(rows) == 0 {
			return "No retained incomplete-probe finding was attached to this domain row."
		}
		return "Those extra addresses did not return a certificate, so expiry, name binding and chain status there are unknown."
	default:
		return ""
	}
}

func tlsValidationConfirmed(item models.Anomaly, diagnosis models.CauseDiagnosis, rows []models.TLSFinding, checkedAt time.Time) (string, []string) {
	evidence := tlsFindingEvidence(item, diagnosisContext{}, rows, checkedAt)
	if diagnosis.Summary != "" {
		return diagnosis.Summary, evidence
	}
	return tlsValidationProblem(item, diagnosis, rows, checkedAt), evidence
}

func tlsExpiredProblem(rows []models.TLSFinding, checkedAt time.Time) string {
	ips := uniqueFindingIPs(rows)
	switch len(ips) {
	case 0:
		return "A sampled endpoint served a leaf whose NotAfter had already passed."
	case 1:
		if notAfter, ok := tlsRowNotAfter(rows[0]); ok && !checkedAt.IsZero() {
			return fmt.Sprintf("Sampled endpoint %s served a leaf whose NotAfter %s had already passed at %s.", ips[0], notAfter.UTC().Format(time.RFC3339), checkedAt.UTC().Format(time.RFC3339))
		}
		return fmt.Sprintf("Sampled endpoint %s served a leaf whose NotAfter had already passed.", ips[0])
	default:
		return fmt.Sprintf("%d sampled endpoint(s) served a leaf whose NotAfter had already passed.", len(ips))
	}
}

func tlsExpiredWhy(item models.Anomaly, context diagnosisContext, rows []models.TLSFinding, checkedAt time.Time) string {
	if len(rows) == 0 {
		return "No retained expired-endpoint finding was attached to this domain row."
	}
	parts := []string{"A completed TLS handshake presented a leaf with NotAfter before the check time."}
	if mismatch := tlsFindingsForCode(parseTLSFindings(context.state), "hostname_mismatch"); len(mismatch) > 0 {
		if same := overlappingFindingLeaves(rows, mismatch); len(same) > 0 {
			parts = append(parts, "The same leaf also failed hostname verification for "+item.Domain+".")
		}
	}
	if current, ok := currentCertificate(context); ok && !leafIsCurrent(rows, current.Fingerprint) && current.NotAfter.After(checkedAt) {
		parts = append(parts, "The currently recorded leaf for this name is still inside its validity window; the expired leaf was observed on a sampled endpoint.")
	}
	return strings.Join(parts, " ")
}

func tlsExpiredConclusion(rows []models.TLSFinding, checkedAt time.Time) string {
	if len(rows) == 0 {
		return "No retained expired-endpoint finding was attached to this domain row."
	}
	if len(uniqueFindingIPs(rows)) == 1 {
		if notAfter, ok := tlsRowNotAfter(rows[0]); ok && !checkedAt.IsZero() {
			days := -models.DaysUntil(notAfter, checkedAt)
			if days < 1 {
				days = 1
			}
			return fmt.Sprintf("A sampled endpoint presented a leaf whose NotAfter had passed by %d day(s) at the TLS check time.", days)
		}
	}
	return fmt.Sprintf("%d sampled endpoint(s) presented a leaf whose NotAfter had already passed at the TLS check time.", len(uniqueFindingIPs(rows)))
}

func tlsMismatchProblem(domain string, rows []models.TLSFinding) string {
	ips := uniqueFindingIPs(rows)
	if len(ips) == 1 {
		return fmt.Sprintf("Sampled endpoint %s served a leaf that is not valid for %s.", ips[0], domain)
	}
	if len(ips) == 0 {
		return fmt.Sprintf("A sampled endpoint served a leaf that is not valid for %s.", domain)
	}
	return fmt.Sprintf("%d sampled endpoint(s) served a leaf that is not valid for %s.", len(ips), domain)
}

func tlsMismatchConclusion(domain string, rows []models.TLSFinding) string {
	if len(rows) == 0 {
		return "No retained hostname-mismatch finding was attached to this domain row."
	}
	return fmt.Sprintf("VerifyHostname failed for %s on %d captured leaf(s).", domain, len(uniqueFindingFingerprints(rows)))
}

func tlsNotYetValidProblem(rows []models.TLSFinding, checkedAt time.Time) string {
	ips := uniqueFindingIPs(rows)
	if len(ips) == 1 {
		if notBefore, ok := tlsRowNotBefore(rows[0]); ok && !checkedAt.IsZero() {
			return fmt.Sprintf("Sampled endpoint %s served a leaf whose NotBefore %s is still in the future at %s.", ips[0], notBefore.UTC().Format(time.RFC3339), checkedAt.UTC().Format(time.RFC3339))
		}
		return fmt.Sprintf("Sampled endpoint %s served a leaf that is not yet valid.", ips[0])
	}
	if len(ips) == 0 {
		return "A sampled endpoint served a leaf that is not yet valid."
	}
	return fmt.Sprintf("%d sampled endpoint(s) served a leaf that is not yet valid.", len(ips))
}

func tlsNotYetValidConclusion(rows []models.TLSFinding, checkedAt time.Time) string {
	if len(rows) == 0 {
		return "No retained not-yet-valid finding was attached to this domain row."
	}
	if notBefore, ok := tlsRowNotBefore(rows[0]); ok && !checkedAt.IsZero() {
		return fmt.Sprintf("A sampled endpoint presented a leaf whose NotBefore %s is after the TLS check time %s.", notBefore.UTC().Format(time.RFC3339), checkedAt.UTC().Format(time.RFC3339))
	}
	return "A sampled endpoint presented a leaf that is not yet valid at the TLS check time."
}

func tlsLocalChainProblem(rows []models.TLSFinding) string {
	ips := uniqueFindingIPs(rows)
	if len(ips) == 1 {
		return fmt.Sprintf("The collector's verifier rejected the chain captured at %s.", ips[0])
	}
	if len(ips) == 0 {
		return "The collector's verifier rejected a captured chain at a sampled endpoint."
	}
	return fmt.Sprintf("The collector's verifier rejected the chain captured at %d sampled endpoint(s).", len(ips))
}

func tlsLocalChainConclusion(rows []models.TLSFinding) string {
	if len(rows) == 0 {
		return "No retained chain-validation finding was attached to this domain row."
	}
	if rows[0].Detail != "" {
		return "The collector's x509.Verify failed: " + rows[0].Detail
	}
	return "The collector's x509.Verify failed on the captured chain."
}

func tlsInconclusiveProblem(rows []models.TLSFinding) string {
	ips := uniqueFindingIPs(rows)
	capOnly := 0
	for _, row := range rows {
		if strings.Contains(strings.ToLower(row.Detail), "sampling cap") {
			capOnly++
		}
	}
	if capOnly == len(rows) && len(rows) > 0 {
		return "Endpoint sampling reached its cap; untested addresses remain unknown."
	}
	if len(ips) == 1 {
		return fmt.Sprintf("Additional endpoint %s did not return a certificate.", ips[0])
	}
	if len(ips) == 0 {
		return "An additional endpoint check did not return a certificate."
	}
	return fmt.Sprintf("%d additional endpoint(s) did not return a certificate.", len(ips))
}

func tlsInconclusiveConclusion(rows []models.TLSFinding) string {
	if len(rows) == 0 {
		return "No retained incomplete-probe finding was attached to this domain row."
	}
	return tlsInconclusiveProblem(rows)
}

func tlsFindingEvidence(item models.Anomaly, context diagnosisContext, rows []models.TLSFinding, checkedAt time.Time) []string {
	out := make([]string, 0, len(rows)+4)
	if !checkedAt.IsZero() {
		out = append(out, "checked_at="+checkedAt.UTC().Format(time.RFC3339))
	}
	if item.Domain != "" {
		out = append(out, "queried_name="+item.Domain)
	}
	for _, row := range rows {
		out = append(out, tlsRowEvidence(row, context, checkedAt)...)
	}
	return uniqueEvidenceStrings(out)
}

func tlsRowEvidence(row models.TLSFinding, context diagnosisContext, checkedAt time.Time) []string {
	parts := make([]string, 0, 6)
	if row.IPAddress != "" {
		parts = append(parts, "ip="+row.IPAddress)
	}
	if row.Fingerprint != "" {
		parts = append(parts, "fingerprint="+row.Fingerprint)
	}
	if notAfter, ok := tlsLeafNotAfter(row, context); ok {
		parts = append(parts, "not_after="+notAfter.UTC().Format(time.RFC3339))
		if !checkedAt.IsZero() && checkedAt.After(notAfter) {
			days := -models.DaysUntil(notAfter, checkedAt)
			if days < 1 {
				days = 1
			}
			parts = append(parts, fmt.Sprintf("days_past_not_after=%d", days))
		}
	}
	if notBefore, ok := tlsLeafNotBefore(row, context); ok {
		parts = append(parts, "not_before="+notBefore.UTC().Format(time.RFC3339))
	}
	if row.Detail != "" {
		parts = append(parts, "detail="+row.Detail)
	}
	return parts
}

func tlsRowLine(row models.TLSFinding, context diagnosisContext, checkedAt time.Time) string {
	ip := row.IPAddress
	if ip == "" {
		ip = "(address not retained)"
	}
	leaf := shortProofFP(row.Fingerprint)
	switch row.Code {
	case "expired_endpoint":
		if notAfter, ok := tlsLeafNotAfter(row, context); ok {
			line := fmt.Sprintf("%s served leaf %s with not_after=%s", ip, leaf, notAfter.UTC().Format(time.RFC3339))
			if !checkedAt.IsZero() {
				days := -models.DaysUntil(notAfter, checkedAt)
				if days < 1 {
					days = 1
				}
				line += fmt.Sprintf(" at checked_at=%s (%d day(s) past)", checkedAt.UTC().Format(time.RFC3339), days)
			}
			return line
		}
	case "not_yet_valid":
		if notBefore, ok := tlsLeafNotBefore(row, context); ok {
			line := fmt.Sprintf("%s served leaf %s with not_before=%s", ip, leaf, notBefore.UTC().Format(time.RFC3339))
			if !checkedAt.IsZero() {
				line += " at checked_at=" + checkedAt.UTC().Format(time.RFC3339)
			}
			return line
		}
	case "hostname_mismatch", "local_chain_validation_failed":
		line := fmt.Sprintf("%s served leaf %s", ip, leaf)
		if row.Detail != "" {
			line += ": " + row.Detail
		}
		return line
	case "endpoint_probe_inconclusive":
		line := ip + " returned no certificate"
		if row.Detail != "" {
			line += ": " + row.Detail
		}
		return line
	}
	line := ip + " finding " + row.Code
	if row.Fingerprint != "" {
		line += " leaf " + leaf
	}
	if row.Detail != "" {
		line += ": " + row.Detail
	}
	return line
}

func relatedTLSEvidence(item models.Anomaly, findings, rows []models.TLSFinding) []string {
	if item.Type != "expired_endpoint" && item.Type != "not_yet_valid" && item.Type != "hostname_mismatch" {
		return nil
	}
	out := make([]string, 0)
	for _, other := range findings {
		if other.Code == item.Type {
			continue
		}
		if other.Code != "hostname_mismatch" && other.Code != "expired_endpoint" && other.Code != "not_yet_valid" && other.Code != "local_chain_validation_failed" {
			continue
		}
		if !sameFindingLeaf(other, rows) {
			continue
		}
		out = append(out, other.Code+"@"+other.IPAddress+" "+other.Detail)
	}
	return out
}

func tlsValidationFacts(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis) []string {
	rows := tlsFindingsForCode(parseTLSFindings(context.state), item.Type)
	checkedAt := tlsCheckedAt(context.state, item)
	facts := make([]string, 0, 8)
	for _, row := range rows {
		facts = append(facts, tlsRowLine(row, context, checkedAt))
	}
	if current, ok := currentCertificate(context); ok {
		facts = append(facts, "current_fingerprint="+current.Fingerprint)
		if !current.NotAfter.IsZero() {
			facts = append(facts, "current_not_after="+current.NotAfter.UTC().Format(time.RFC3339))
		}
		if item.Type == "expired_endpoint" && !leafIsCurrent(rows, current.Fingerprint) {
			facts = append(facts, "expired_leaf_differs_from_current=true")
		}
	}
	if diagnosis.Summary != "" && len(facts) == 0 {
		facts = append(facts, diagnosis.Summary)
	}
	return uniqueEvidenceStrings(facts)
}

func tlsProviderExhibits(item models.Anomaly, context diagnosisContext) []models.ProviderExhibit {
	rows := tlsFindingsForCode(parseTLSFindings(context.state), item.Type)
	if len(rows) == 0 {
		return providerExhibits(item, context, models.CauseDiagnosis{})
	}
	probes := currentEndpointSurvey(context)
	probeByIP := make(map[string]models.EndpointProbe, len(probes))
	for _, probe := range probes {
		if probe.IPAddress != "" {
			probeByIP[probe.IPAddress] = probe
		}
	}
	active := map[string]struct{}{}
	activeKnown := false
	if len(context.snapshots) > 0 {
		active, activeKnown = snapshotActiveIPsFor(context.snapshots[0])
	}
	groups := make(map[string][]models.EndpointExhibit)
	order := make([]string, 0)
	seenIP := make(map[string]struct{})
	for _, row := range rows {
		ip := row.IPAddress
		if ip == "" {
			continue
		}
		if _, dup := seenIP[ip]; dup {
			continue
		}
		seenIP[ip] = struct{}{}
		group := models.ProviderGroup(ip)
		if _, seen := groups[group]; !seen {
			order = append(order, group)
		}
		endpoint := models.EndpointExhibit{
			IPAddress:   ip,
			ActiveDNS:   activeKnown && hasEvidenceAddress(active, ip),
			Success:     row.Fingerprint != "" && row.Code != "endpoint_probe_inconclusive",
			Fingerprint: row.Fingerprint,
			Error:       row.Detail,
		}
		if probe, ok := probeByIP[ip]; ok {
			endpoint.Success = probe.Success
			endpoint.RequestedSNI = probe.RequestedSNI
			if probe.Fingerprint != "" {
				endpoint.Fingerprint = probe.Fingerprint
			}
			if probe.SelectionAnalysis != nil {
				endpoint.DefaultFingerprint = probe.SelectionAnalysis.DefaultFingerprint
				endpoint.SelectionInterpretation = probe.SelectionAnalysis.Interpretation
			}
			endpoint.SPKIFingerprint = probe.SPKIFingerprint
			endpoint.IssuerCN = probe.IssuerCN
			endpoint.KeyAlgorithm = probe.KeyAlgorithm
			if probe.Error != "" {
				endpoint.Error = probe.Error
			}
		}
		groups[group] = append(groups[group], endpoint)
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
		exhibits = append(exhibits, models.ProviderExhibit{
			Group:     group,
			LeafCount: len(leaves),
			Conflict:  len(leaves) > 1,
			Endpoints: endpoints,
		})
	}
	sort.Slice(exhibits, func(left, right int) bool { return exhibits[left].Group < exhibits[right].Group })
	return exhibits
}

func currentCertificate(context diagnosisContext) (models.Certificate, bool) {
	if context.state == nil {
		return models.Certificate{}, false
	}
	if context.state.CurrentCertificate != nil {
		return *context.state.CurrentCertificate, true
	}
	if fp := context.state.CurrentFingerprint; fp != "" {
		if cert, ok := context.certificates[fp]; ok {
			return cert, true
		}
		return models.Certificate{Fingerprint: fp}, true
	}
	return models.Certificate{}, false
}

func leafIsCurrent(rows []models.TLSFinding, currentFingerprint string) bool {
	if currentFingerprint == "" {
		return false
	}
	matched := false
	for _, row := range rows {
		if row.Fingerprint == "" {
			continue
		}
		matched = true
		if row.Fingerprint != currentFingerprint {
			return false
		}
	}
	return matched
}

func uniqueFindingIPs(rows []models.TLSFinding) []string {
	seen := make(map[string]struct{}, len(rows))
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.IPAddress == "" {
			continue
		}
		if _, ok := seen[row.IPAddress]; ok {
			continue
		}
		seen[row.IPAddress] = struct{}{}
		out = append(out, row.IPAddress)
	}
	sort.Strings(out)
	return out
}

func uniqueFindingFingerprints(rows []models.TLSFinding) []string {
	seen := make(map[string]struct{}, len(rows))
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.Fingerprint == "" {
			continue
		}
		if _, ok := seen[row.Fingerprint]; ok {
			continue
		}
		seen[row.Fingerprint] = struct{}{}
		out = append(out, row.Fingerprint)
	}
	return out
}

func sameFindingLeaf(candidate models.TLSFinding, rows []models.TLSFinding) bool {
	for _, row := range rows {
		if candidate.IPAddress != "" && candidate.IPAddress == row.IPAddress {
			return true
		}
		if candidate.Fingerprint != "" && candidate.Fingerprint == row.Fingerprint {
			return true
		}
	}
	return false
}

func overlappingFindingLeaves(left, right []models.TLSFinding) []models.TLSFinding {
	out := make([]models.TLSFinding, 0)
	for _, row := range right {
		if sameFindingLeaf(row, left) {
			out = append(out, row)
		}
	}
	return out
}

func tlsLeafNotAfter(row models.TLSFinding, context diagnosisContext) (time.Time, bool) {
	if t, ok := tlsRowNotAfter(row); ok {
		return t, true
	}
	if cert, ok := tlsLeafCertificate(row, context); ok && !cert.NotAfter.IsZero() {
		return cert.NotAfter, true
	}
	return time.Time{}, false
}

func tlsLeafNotBefore(row models.TLSFinding, context diagnosisContext) (time.Time, bool) {
	if t, ok := tlsRowNotBefore(row); ok {
		return t, true
	}
	if cert, ok := tlsLeafCertificate(row, context); ok && !cert.NotBefore.IsZero() {
		return cert.NotBefore, true
	}
	return time.Time{}, false
}

func tlsLeafCertificate(row models.TLSFinding, context diagnosisContext) (models.Certificate, bool) {
	if row.Fingerprint == "" || context.certificates == nil {
		return models.Certificate{}, false
	}
	cert, ok := context.certificates[row.Fingerprint]
	return cert, ok
}

func tlsRowNotAfter(row models.TLSFinding) (time.Time, bool) {
	return findingTimeField(row.Detail, "NotAfter")
}

func tlsRowNotBefore(row models.TLSFinding) (time.Time, bool) {
	return findingTimeField(row.Detail, "NotBefore")
}

func findingTimeField(detail, key string) (time.Time, bool) {
	if detail == "" || key == "" {
		return time.Time{}, false
	}
	needles := []string{"certificate " + key + "=", key + "="}
	rest := ""
	for _, needle := range needles {
		if idx := strings.Index(detail, needle); idx >= 0 {
			rest = strings.TrimSpace(detail[idx+len(needle):])
			break
		}
	}
	if rest == "" {
		return time.Time{}, false
	}
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		rest = rest[:i]
	}
	parsed, err := time.Parse(time.RFC3339, rest)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func tlsValidationProof(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis, investigation *models.Investigation) (proven, inferred []models.InvestigationProofStep) {
	rows := tlsFindingsForCode(parseTLSFindings(context.state), item.Type)
	checkedAt := tlsCheckedAt(context.state, item)
	if len(rows) == 0 {
		inferred = appendInferred(inferred,
			"Coverage",
			"This TLS check cannot be reconstructed: no retained finding of this code was attached to the domain row.",
			[]string{"tls_findings_for_code=0", "type=" + item.Type},
			"The finding is stored on the domain row as a named TLS check with IP, fingerprint and detail.",
		)
		return proven, inferred
	}

	leafEvidence := make([]string, 0, len(rows)+2)
	if !checkedAt.IsZero() {
		leafEvidence = append(leafEvidence, "checked_at="+checkedAt.UTC().Format(time.RFC3339))
	}
	for _, row := range rows {
		leafEvidence = append(leafEvidence, tlsRowLine(row, context, checkedAt))
		leafEvidence = append(leafEvidence, tlsRowEvidence(row, context, checkedAt)...)
	}
	leafEvidence = uniqueEvidenceStrings(leafEvidence)

	switch item.Type {
	case "expired_endpoint":
		proven = append(proven, provenStep(
			"Captured leaf",
			"A completed TLS handshake at a sampled endpoint presented a leaf whose NotAfter is before the check time.",
			leafEvidence,
			"Leaf NotAfter compared with the TLS check time on the captured chain.",
		))
		findings := parseTLSFindings(context.state)
		if mismatch := overlappingFindingLeaves(rows, tlsFindingsForCode(findings, "hostname_mismatch")); len(mismatch) > 0 {
			mismatchEvidence := make([]string, 0, len(mismatch))
			for _, row := range mismatch {
				mismatchEvidence = append(mismatchEvidence, tlsRowLine(row, context, checkedAt))
			}
			proven = append(proven, provenStep(
				"Name binding",
				"The expired leaf is not valid for "+item.Domain+".",
				mismatchEvidence,
				"VerifyHostname on the same captured leaf.",
			))
		}
		if current, ok := currentCertificate(context); ok {
			currentEvidence := []string{"current_fingerprint=" + current.Fingerprint}
			if !current.NotAfter.IsZero() {
				currentEvidence = append(currentEvidence, "current_not_after="+current.NotAfter.UTC().Format(time.RFC3339))
			}
			if !checkedAt.IsZero() {
				currentEvidence = append(currentEvidence, "checked_at="+checkedAt.UTC().Format(time.RFC3339))
			}
			if leafIsCurrent(rows, current.Fingerprint) {
				proven = append(proven, provenStep(
					"Conclusion",
					"The currently recorded certificate for this name is expired at the sampled endpoint.",
					append(leafEvidence, currentEvidence...),
					"The expired leaf fingerprint is the domain's current fingerprint.",
				))
			} else if current.NotAfter.After(checkedAt) {
				proven = append(proven, provenStep(
					"Current leaf",
					"The currently recorded certificate for this name is still inside its validity window.",
					currentEvidence,
					"Domain current fingerprint and NotAfter compared with the TLS check time.",
				))
				proven = append(proven, provenStep(
					"Conclusion",
					"A sampled endpoint served a leaf whose NotAfter had already passed.",
					leafEvidence,
					"Leaf NotAfter compared with the TLS check time on the captured chain.",
				))
				inferred = appendInferred(inferred,
					"Shared-host leftover",
					"The expired leaf is a different certificate from the currently recorded leaf, so this is leftover or shared-host material on that sampled address, not expiry of the name's current certificate.",
					append(append([]string{}, leafEvidence...), currentEvidence...),
					"Inferred from fingerprint disagreement plus, when present, hostname mismatch on the expired leaf.",
				)
			} else {
				proven = append(proven, provenStep(
					"Conclusion",
					"A sampled endpoint served an expired leaf, and the currently recorded certificate for this name is also past NotAfter.",
					append(leafEvidence, currentEvidence...),
					"Expired sampled leaf compared with the domain's current NotAfter.",
				))
			}
		} else {
			proven = append(proven, provenStep(
				"Conclusion",
				"A sampled endpoint served a leaf whose NotAfter had already passed.",
				leafEvidence,
				"No separate current-certificate row was retained to compare against.",
			))
		}
	case "hostname_mismatch":
		proven = append(proven, provenStep(
			"Captured leaf",
			"A sampled endpoint served a leaf that failed hostname verification for "+item.Domain+".",
			leafEvidence,
			"VerifyHostname on the captured leaf.",
		))
		if selectionEvidence := tlsNameSelectionEvidence(item.Domain, rows, context); len(selectionEvidence) > 0 {
			proven = append(proven, provenStep(
				"SNI selection control",
				"The endpoint did not select a certificate valid for the queried name after the client supplied the requested SNI.",
				selectionEvidence,
				"Same-address TLS handshakes compared the requested-name SNI with an empty-SNI control.",
			))
		}
		if reason := nonHTTPSIdentityReason(item.Domain); reason != "" {
			proven = append(proven, provenStep(
				"Queried name",
				reason,
				[]string{"queried_name=" + item.Domain},
				"The monitored name is a DNS/CDN/service alias, not a site HTTPS identity.",
			))
			proven = append(proven, provenStep(
				"Conclusion",
				"The name mismatch is expected for this alias and is not a site certificate defect.",
				append([]string{"queried_name=" + item.Domain}, leafEvidence...),
				"Hostname verification is evaluated against a name that is not issued as a TLS identity.",
			))
			break
		}
		proven = append(proven, provenStep(
			"Conclusion",
			"The captured certificate is not issued for this name at that sampled endpoint.",
			leafEvidence,
			"Name binding is evaluated on the captured chain for the queried name.",
		))
	case "not_yet_valid":
		proven = append(proven, provenStep(
			"Captured leaf",
			"A sampled endpoint served a leaf whose NotBefore is after the TLS check time.",
			leafEvidence,
			"Leaf NotBefore compared with the TLS check time on the captured chain.",
		))
		proven = append(proven, provenStep(
			"Conclusion",
			"The captured certificate is not yet valid at that sampled endpoint.",
			leafEvidence,
			"A leaf is not a valid server certificate before NotBefore.",
		))
	case "local_chain_validation_failed":
		proven = append(proven, provenStep(
			"Captured chain",
			"The collector's verifier rejected the captured chain at a sampled endpoint.",
			leafEvidence,
			"x509.Verify against this machine's roots, after leaf NotBefore/NotAfter were excluded from this code.",
		))
		inferred = appendInferred(inferred,
			"Local trust only",
			"This does not establish that browsers reject the same chain. It is this collector's roots and path construction.",
			leafEvidence,
			"The finding is produced by the local verifier, not by an independent public trust report.",
		)
	case "endpoint_probe_inconclusive":
		proven = append(proven, provenStep(
			"Incomplete probe",
			"An additional sampled address did not return a certificate.",
			leafEvidence,
			"Direct TLS probe or sampling-cap record on the extra endpoint.",
		))
		inferred = appendInferred(inferred,
			"Status unknown",
			"Certificate expiry, name binding and chain status at that address remain unknown until a handshake completes.",
			leafEvidence,
			"No leaf was captured, so the named TLS checks cannot run.",
		)
	}
	return proven, inferred
}

// tlsNameSelectionEvidence narrows a hostname mismatch to the observable TLS
// selection behaviour at the same address.  It deliberately stops there:
// DNS intent, virtual-host configuration, and edge propagation remain private
// control-plane facts unless supplied by the operator.
func tlsNameSelectionEvidence(domain string, rows []models.TLSFinding, context diagnosisContext) []string {
	probes := currentEndpointSurvey(context)
	if len(probes) == 0 {
		return nil
	}
	matched := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		matched[strings.TrimSpace(row.IPAddress)+"|"+strings.TrimSpace(row.Fingerprint)] = struct{}{}
	}
	out := make([]string, 0, len(probes))
	for _, probe := range probes {
		if probe.SelectionAnalysis == nil || !probe.Success || probe.CoversRequestedName {
			continue
		}
		key := strings.TrimSpace(probe.IPAddress) + "|" + strings.TrimSpace(probe.Fingerprint)
		if _, ok := matched[key]; !ok {
			// Older TLS findings may not retain the fingerprint.  Preserve an IP
			// match only when it is the one mismatching endpoint in this survey.
			byIP := strings.TrimSpace(probe.IPAddress) + "|"
			if _, fallback := matched[byIP]; !fallback {
				continue
			}
		}
		analysis := probe.SelectionAnalysis
		line := fmt.Sprintf("address=%s requested_sni=%s selected_fingerprint=%s selected_covers_requested_name=%t",
			probe.IPAddress, domain, probe.Fingerprint, analysis.SelectedCoversRequestedName)
		if analysis.DefaultFingerprint != "" {
			line += fmt.Sprintf(" no_sni_fingerprint=%s no_sni_covers_requested_name=%t", analysis.DefaultFingerprint, analysis.DefaultCoversRequestedName)
		}
		line += " selection=" + analysis.Interpretation
		out = append(out, line)
	}
	return uniqueEvidenceStrings(out)
}

func collectTLSFindingFingerprints(states []models.DomainCertificate) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, state := range states {
		if fp := state.CurrentFingerprint; fp != "" {
			if _, ok := seen[fp]; !ok {
				seen[fp] = struct{}{}
				out = append(out, fp)
			}
		}
		for _, finding := range parseTLSFindings(&state) {
			if finding.Fingerprint == "" {
				continue
			}
			if _, ok := seen[finding.Fingerprint]; ok {
				continue
			}
			seen[finding.Fingerprint] = struct{}{}
			out = append(out, finding.Fingerprint)
		}
	}
	return out
}
