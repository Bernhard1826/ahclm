package cost

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"ahclm/internal/models"
)

const comparisonBasis = "Active findings gate this comparison. Configured unit prices are assumptions, not measured money. Exposure assumes the current condition persists; only additional measurement cost uses historical probability. Past costs are excluded from this forward comparison."

var issueOrder = []string{
	"certificate_validation",
	"revoked",
	"expired_served",
	"residual",
	"deployment_failure",
	"stale_after_change",
	"unreachable",
	"ari_emergency",
	"expiring_soon",
	"early_renewal",
	"same_key",
	"frequent_change",
}

// Calculate builds a transparent, incremental comparison for one domain. It
// only becomes applicable when the current AHCLM state or a current-fingerprint
// observation contains a measured problem. Historical events for certificates
// that are no longer deployed are intentionally ignored.
func Calculate(evidence models.CostEvidence, cfg models.CostConfig, now time.Time) models.CostBreakdown {
	result := models.CostBreakdown{
		Scope:          "Current certificate with an AHCLM-confirmed active-measurement finding",
		Basis:          comparisonBasis,
		Currency:       cfg.Currency,
		EvidenceStatus: models.EvidenceStatusUnknown,
		Confidence:     "unknown",
		Decision:       "not_applicable",
	}
	if now.IsZero() {
		now = time.Now()
	}
	if evidence.Domain == nil {
		result.Unknowns = []string{"domain state is unavailable"}
		return result
	}
	if evidence.Domain.EvidenceStatus != "" {
		result.EvidenceStatus = evidence.Domain.EvidenceStatus
	}
	if evidence.Certificate == nil {
		result.Unknowns = []string{"current certificate was not captured by active measurement"}
		return result
	}

	dc := evidence.Domain
	cert := evidence.Certificate
	issues, issueEvidence, issueTypes := measuredIssues(evidence, now)
	result.IssueTypes = issueTypes
	if len(result.IssueTypes) == 0 {
		result.Basis = "No current AHCLM active-measurement problem was found; cost comparison is intentionally not applied"
		return result
	}
	result.Applicable = true

	confirmed := false
	for _, kind := range result.IssueTypes {
		if kind != "stale_after_change" && kind != "unreachable" && kind != "deployment_failure" && kind != "certificate_validation" {
			confirmed = true
			break
		}
	}
	if confirmed {
		result.Confidence = "confirmed"
	} else {
		result.Confidence = "inferred"
	}

	if !dc.NextScanAt.IsZero() {
		next := dc.NextScanAt
		result.NextMeasurementAt = &next
		result.WaitHorizonHours = math.Max(0, next.Sub(now).Hours())
	} else {
		result.Unknowns = append(result.Unknowns, "next active measurement is not scheduled")
	}

	missing := make(map[string]bool)
	addItem := func(items *[]models.CostLineItem, code, label, field string, amount float64, basis string, evidence []string) {
		*items = append(*items, models.CostLineItem{Code: code, Label: label, Amount: amount, Basis: basis, Evidence: evidence, Method: "configured_scenario"})
		if amount <= 0 && !missing[field] {
			result.Unknowns = append(result.Unknowns, fmt.Sprintf("cost.%s is zero or not configured", field))
			missing[field] = true
		}
	}

	if result.NextMeasurementAt != nil {
		addItem(&result.WaitItems, "active_measurement", "One next active measurement", "active_measurement_cost", cfg.ActiveMeasurementCost,
			"one scheduled AHCLM scan before the comparison horizon", []string{"next_scan_at is used as the horizon end"})
	}

	rates := map[string]struct {
		code  string
		field string
		label string
		rate  float64
	}{
		"revoked":            {"revoked_service_exposure", "revoked_service_per_hour", "Revoked-service exposure", cfg.RevokedServicePerHour},
		"expired_served":     {"expired_service_exposure", "expired_service_per_hour", "Expired-service exposure", cfg.ExpiredServicePerHour},
		"residual":           {"residual_exposure", "residual_exposure_per_hour", "Residual-certificate exposure", cfg.ResidualExposurePerHour},
		"deployment_failure": {"partial_deployment_exposure", "partial_deployment_per_hour", "Partial-deployment exposure", cfg.PartialDeploymentPerHour},
		"stale_after_change": {"stale_certificate_exposure", "stale_certificate_per_hour", "Stale-certificate exposure", cfg.StaleCertificatePerHour},
		"unreachable":        {"unreachable_service_exposure", "unreachable_service_per_hour", "Unreachable-service exposure", cfg.UnreachableServicePerHour},
	}
	for _, kind := range result.IssueTypes {
		if kind == "residual" && issues["revoked"] || kind == "stale_after_change" && issues["deployment_failure"] {
			continue // Overlapping exposure is charged once.
		}
		if rate, ok := rates[kind]; ok && result.WaitHorizonHours > 0 {
			addItem(&result.WaitItems, rate.code, rate.label, rate.field, rate.rate*result.WaitHorizonHours,
				fmt.Sprintf("%s per hour × %.2f-hour wait horizon", rate.field, result.WaitHorizonHours), issueEvidence[kind])
		}
	}
	// A currently valid certificate can become expired before the next scan.
	// Charge that post-expiry interval separately instead of treating the whole
	// wait horizon as either valid service or already-expired service.
	if result.NextMeasurementAt != nil && !cert.NotAfter.Before(now) && cert.NotAfter.Before(*result.NextMeasurementAt) {
		expiredHours := result.NextMeasurementAt.Sub(cert.NotAfter).Hours()
		if expiredHours > 0 {
			addItem(&result.WaitItems, "expired_service_after_expiry", "Expired-service exposure after certificate expiry", "expired_service_per_hour", cfg.ExpiredServicePerHour*expiredHours,
				fmt.Sprintf("expired_service_per_hour per hour × %.2f hours from NotAfter to the next measurement", expiredHours), []string{
					"not_after=" + cert.NotAfter.UTC().Format(time.RFC3339),
					"next_measurement_at=" + result.NextMeasurementAt.UTC().Format(time.RFC3339),
				})
		}
	}
	if cert.NotAfter.After(now) && result.NextMeasurementAt != nil && cert.NotAfter.Before(*result.NextMeasurementAt) {
		addItem(&result.WaitItems, "expiry_incident", "Expiry incident before next measurement", "expiry_incident_cost", cfg.ExpiryIncidentCost,
			"conditional incident cost if this certificate remains deployed past NotAfter; prior incidents are excluded", issueEvidence["expired_served"])
	}

	addItem(&result.RotateItems, "issuance", "Issue replacement certificate", "issuance_cost", cfg.IssuanceCost,
		"one certificate issuance operation", []string{cert.Fingerprint})
	addItem(&result.RotateItems, "ct_submission", "Submit replacement to CT monitors", "ct_per_certificate_cost", cfg.CTPerCertificateCost,
		"one CT-observable certificate issuance", []string{"certificate transparency cost is charged per replacement certificate"})
	addItem(&result.RotateItems, "deployment", "Deploy replacement certificate", "deployment_cost", cfg.DeploymentCost,
		"one deployment/rollout operation", []string{dc.Domain})
	addItem(&result.RotateItems, "verification", "Verify deployment with active measurement", "verification_cost", cfg.VerificationCost,
		"one post-deployment active verification", []string{"AHCLM active measurement remains the source of truth"})
	if issues["deployment_failure"] {
		result.Unknowns = append(result.Unknowns, "Deployment retry and rollback costs are unquantified: observed certificate inconsistency does not identify deployment attempts or rollback actions")
	}
	if result.Confidence != "confirmed" {
		addItem(&result.RotateItems, "manual_review", "Manual review of inferred cause", "manual_review_cost", cfg.ManualReviewCost,
			"included when the measured symptom does not establish its operational cause", nil)
	}

	// One optional additional probe, not a geometric retry loop. Completed
	// monitoring rounds are trials; internal retries are not independent trials.
	n, failed := 0, 0
	for _, job := range validJobs(evidence.ScanJobs, now) {
		n++
		if !job.Success {
			failed++
		}
	}
	if n > 0 {
		p := float64(failed+1) / float64(n+2)
		item := models.CostLineItem{Code: "additional_probe", Label: "Expected additional active measurement", Amount: p * cfg.ActiveMeasurementCost, Method: "probability_estimate", Probability: &p, SampleCount: n, Basis: "Beta(1,1) smoothed failed-round probability times one additional probe cost; assumes one extra probe after failure", Evidence: []string{fmt.Sprintf("%d failed / %d completed domain monitoring rounds in the last 30 days; maximum 500 rounds", failed, n)}}
		if result.NextMeasurementAt != nil {
			result.WaitItems = append(result.WaitItems, item)
		}
		result.RotateItems = append(result.RotateItems, item)
		result.Unknowns = append(result.Unknowns, "Historical probe failure estimates may change after replacement; they do not estimate deployment failure or business outage")
	} else {
		result.Unknowns = append(result.Unknowns, "Additional probe cost is unquantified: no completed recent monitoring rounds")
	}
	result.Unknowns = append(result.Unknowns, "Future exposure totals assume persistence until the next measurement; a measured symptom does not establish future duration or business loss")
	for _, item := range result.WaitItems {
		result.WaitCost += item.Amount
	}
	for _, item := range result.RotateItems {
		result.RotateCost += item.Amount
	}
	result.WaitCost = round(result.WaitCost)
	result.RotateCost = round(result.RotateCost)
	result.HardConstraint = issues["revoked"] || issues["expired_served"] || issues["ari_emergency"]
	applyIntervals(&result, evidence, cfg, now)
	if result.NextMeasurementAt == nil && !result.HardConstraint {
		result.Decision = "remeasure"
		return result
	}
	// A stale or unreachable symptom is measured, but its operational cause is
	// not established by the public probe. Show both scenario totals while
	// requiring a fresh measurement/manual review before recommending a change.
	if result.Confidence != "confirmed" && !result.HardConstraint {
		result.Decision = "remeasure"
		return result
	}
	switch {
	case result.HardConstraint || result.Comparison == "replace_lower":
		result.Decision = "issue"
	case result.Comparison == "wait_lower":
		result.Decision = "wait"
	default:
		result.Decision = "remeasure"
	}
	return result
}

// HasMeasuredProblem is the inexpensive gate used by API callers before they
// build a cost breakdown. It shares the exact same evidence classification as
// Calculate, so a clean certificate never receives a cost calculation result.
func HasMeasuredProblem(evidence models.CostEvidence, now time.Time) bool {
	_, _, issueTypes := measuredIssues(evidence, now)
	return len(issueTypes) > 0
}

func measuredIssues(evidence models.CostEvidence, now time.Time) (map[string]bool, map[string][]string, []string) {
	issues := make(map[string]bool)
	issueEvidence := make(map[string][]string)
	if now.IsZero() {
		now = time.Now()
	}
	if evidence.Domain == nil || evidence.Certificate == nil {
		return issues, issueEvidence, nil
	}

	dc := evidence.Domain
	cert := evidence.Certificate
	addIssue := func(kind string, evidenceText string) {
		issues[kind] = true
		if evidenceText != "" {
			issueEvidence[kind] = append(issueEvidence[kind], evidenceText)
		}
	}
	var findings []models.TLSFinding
	if dc.Status == models.StatusActive && json.Unmarshal([]byte(dc.TLSFindings), &findings) == nil && len(findings) > 0 {
		addIssue("certificate_validation", "latest active TLS validation contains findings; review endpoint-specific evidence")
	}

	if dc.RevocationStatus == models.RevocationRevoked {
		addIssue("revoked", "current deployment revocation_status=revoked")
	}
	if dc.Status == models.StatusActive && dc.ConsecutiveFailures == 0 && dc.LastScannedAt.After(cert.NotAfter) && cert.NotAfter.Before(now) {
		addIssue("expired_served", fmt.Sprintf("current certificate NotAfter=%s", cert.NotAfter.UTC().Format(time.RFC3339)))
	} else if dc.Status == models.StatusActive && !cert.NotAfter.Before(now) && cert.NotAfter.Sub(now) <= 7*24*time.Hour {
		addIssue("expiring_soon", fmt.Sprintf("current certificate expires at %s", cert.NotAfter.UTC().Format(time.RFC3339)))
	}
	if dc.Status == models.StatusUnreachable {
		addIssue("unreachable", fmt.Sprintf("current domain status=unreachable after %d consecutive failures", dc.ConsecutiveFailures))
	}
	if dc.ResidualFingerprint != "" {
		text := "open residual fingerprint is tracked by AHCLM"
		if dc.ResidualObservationCount > 0 {
			text = fmt.Sprintf("open residual fingerprint with %d follow-up observations", dc.ResidualObservationCount)
		}
		addIssue("residual", text)
	}
	if dc.ARIEmergency {
		addIssue("ari_emergency", "active ARI measurement marked the renewal window as emergency")
	}
	if dc.ChangeCount >= 3 {
		addIssue("frequent_change", fmt.Sprintf("active measurement recorded %d certificate changes", dc.ChangeCount))
	}

	for _, observation := range evidence.Observations {
		if observation.ObservedAt.After(now) {
			continue
		}
		if dc.CurrentFingerprint == "" || observation.Fingerprint != dc.CurrentFingerprint {
			continue
		}
		observed := observation.ObservedAt.UTC().Format(time.RFC3339)
		switch observation.ObservationType {
		case models.ObsDeploymentFailure:
			addIssue("deployment_failure", fmt.Sprintf("deployment_failure observed at %s", observed))
		case models.ObsStaleAfterChange:
			addIssue("stale_after_change", fmt.Sprintf("stale_after_change observed at %s", observed))
		case models.ObsUnreachable:
			if dc.Status == models.StatusUnreachable {
				addIssue("unreachable", fmt.Sprintf("unreachable observed at %s", observed))
			}
		case models.ObsResidual:
			if dc.ResidualFingerprint != "" {
				addIssue("residual", fmt.Sprintf("residual observed at %s", observed))
			}
		case models.ObsARIEmergency:
			addIssue("ari_emergency", fmt.Sprintf("ari_emergency observed at %s", observed))
		case models.ObsSameKey:
			addIssue("same_key", fmt.Sprintf("same_key replacement observed at %s", observed))
		case models.ObsChange:
			if observation.DaysUntilExpiry > 30 {
				addIssue("early_renewal", fmt.Sprintf("early renewal observed at %s with %d days to expiry", observed, observation.DaysUntilExpiry))
			}
		}
	}

	issueTypes := make([]string, 0, len(issues))
	for _, kind := range issueOrder {
		if issues[kind] {
			issueTypes = append(issueTypes, kind)
		}
	}
	return issues, issueEvidence, issueTypes
}

func round(value float64) float64 {
	return math.Round(value*10000) / 10000
}
