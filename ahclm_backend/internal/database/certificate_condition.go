package database

import (
	"fmt"
	"strings"
	"time"

	"ahclm/internal/models"
)

const (
	certCauseExpiredServed   = "expired_leaf_still_served"
	certCauseExpiredObserved = "expired_leaf_historically_observed"
	certCauseExpiringSoon    = "current_leaf_inside_expiry_window"
	certCauseRevoked         = "current_leaf_revoked"
	certCauseResidual        = "revoked_leaf_still_observable"
	certCauseUnreachable     = "tls_measurement_failed"
	certCauseARIEmergency    = "ari_window_pulled_to_present"
)

func isCertificateConditionType(code string) bool {
	switch strings.TrimSpace(code) {
	case "expired_served", "expired_observed", "expiring_soon", "revoked",
		models.ObsResidual, "unreachable", "measurement_failed", "ari_emergency":
		return true
	default:
		return false
	}
}

func seedCertificateConditionAnomaly(item *models.Anomaly, dc *models.DomainCertificate) {
	if item == nil || dc == nil {
		return
	}
	item.Domain = dc.Domain
	if item.Fingerprint == "" {
		item.Fingerprint = dc.CurrentFingerprint
	}
	if item.Type == models.ObsResidual && dc.ResidualFingerprint != "" {
		item.Fingerprint = dc.ResidualFingerprint
	}
	now := time.Now().UTC()
	switch item.Type {
	case "expired_served", "expiring_soon", "expired_observed":
		item.DetectedAt = firstTimePtr(dc.LastScannedAt, now)
		item.OccurrenceCount = maxInt(item.OccurrenceCount, 1)
	case "revoked":
		item.DetectedAt = firstTime(dc.RevokedAt, firstTimePtr(dc.LastScannedAt, now))
		item.OccurrenceCount = maxInt(item.OccurrenceCount, 1)
	case "unreachable", "measurement_failed":
		item.DetectedAt = firstTimePtr(dc.LastScannedAt, now)
		item.OccurrenceCount = dc.ConsecutiveFailures
	case "ari_emergency":
		item.DetectedAt = firstTime(dc.ARICheckedAt, firstTimePtr(dc.LastScannedAt, now))
		item.OccurrenceCount = maxInt(item.OccurrenceCount, 1)
	case models.ObsResidual:
		item.DetectedAt = firstTime(dc.ResidualLastSeenAt, firstTimePtr(dc.LastScannedAt, now))
		if dc.ResidualObservationCount > 0 {
			item.OccurrenceCount = dc.ResidualObservationCount
		}
		item.OccurrenceCount = maxInt(item.OccurrenceCount, 1)
	}
}

func inferCertificateConditionDiagnosis(item models.Anomaly, context diagnosisContext) models.CauseDiagnosis {
	checkedAt := certificateConditionCheckedAt(item, context.state)
	evidence := certificateConditionEvidence(item, context, checkedAt)
	diagnosis := models.CauseDiagnosis{
		Confidence:           "high",
		EvidenceCompleteness: completenessScore(len(context.snapshots), len(context.observations), context.state != nil),
		MeasuredRounds:       len(context.snapshots),
		CauseStatus:          "established",
		Hypotheses:           nil,
	}
	switch item.Type {
	case "expired_served":
		diagnosis.PrimaryCode = certCauseExpiredServed
		diagnosis.PrimaryLabel = "Expired leaf still served"
		diagnosis.Summary = certificateConditionConclusion(item, context, checkedAt)
		diagnosis.MeasurementPlan = []string{"A later successful handshake whose leaf NotAfter is still in the future would remove this reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       certCauseExpiredServed,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "The currently recorded leaf NotAfter is before the last successful scan time.",
			Evidence:   evidence,
		}}
	case "expired_observed":
		diagnosis.PrimaryCode = certCauseExpiredObserved
		diagnosis.PrimaryLabel = "Expired leaf historically observed"
		diagnosis.Summary = certificateConditionConclusion(item, context, checkedAt)
		diagnosis.MeasurementPlan = []string{"A later successful handshake would replace this historical dormant-row observation with a current certificate reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       certCauseExpiredObserved,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "A previous collector recorded an expired certificate while the row was marked dormant.",
			Evidence:   evidence,
		}}
	case "expiring_soon":
		diagnosis.PrimaryCode = certCauseExpiringSoon
		diagnosis.PrimaryLabel = "Current leaf inside expiry window"
		diagnosis.Summary = certificateConditionConclusion(item, context, checkedAt)
		diagnosis.MeasurementPlan = []string{"A replacement whose NotAfter is outside the seven-day window, or the current leaf passing NotAfter, would change this reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       certCauseExpiringSoon,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "The currently recorded leaf NotAfter falls inside the seven-day expiry window.",
			Evidence:   evidence,
		}}
	case "revoked":
		diagnosis.PrimaryCode = certCauseRevoked
		diagnosis.PrimaryLabel = "Current leaf revoked"
		diagnosis.Summary = certificateConditionConclusion(item, context, checkedAt)
		diagnosis.MeasurementPlan = []string{"A later revocation check reporting good, or a replacement leaf that is not revoked, would remove this reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       certCauseRevoked,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "The retained revocation check reported the currently recorded certificate as revoked.",
			Evidence:   evidence,
		}}
	case models.ObsResidual:
		diagnosis.PrimaryCode = certCauseResidual
		diagnosis.PrimaryLabel = "Revoked leaf still observable"
		diagnosis.Summary = certificateConditionConclusion(item, context, checkedAt)
		diagnosis.MeasurementPlan = []string{"A later probe that no longer presents the revoked leaf would remove this residual-service reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       certCauseResidual,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "The revoked leaf was observed again after the CA revocation timestamp.",
			Evidence:   evidence,
		}}
	case "unreachable", "measurement_failed":
		diagnosis.PrimaryCode = certCauseUnreachable
		diagnosis.PrimaryLabel = "TLS measurement failed"
		diagnosis.Summary = certificateConditionConclusion(item, context, checkedAt)
		diagnosis.MeasurementPlan = []string{"A later successful TLS handshake that returns a certificate would replace this failed attempt with a certificate reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       certCauseUnreachable,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "The latest monitoring attempt failed to obtain a TLS certificate.",
			Evidence:   evidence,
		}}
	case "ari_emergency":
		diagnosis.PrimaryCode = certCauseARIEmergency
		diagnosis.PrimaryLabel = "ARI window pulled to the present"
		diagnosis.Summary = certificateConditionConclusion(item, context, checkedAt)
		diagnosis.MeasurementPlan = []string{"A later ARI response whose renewal window is no longer immediate would remove this reading."}
		diagnosis.Hypotheses = []models.CauseHypothesis{{
			Code:       certCauseARIEmergency,
			Label:      diagnosis.PrimaryLabel,
			Score:      1,
			Confidence: "high",
			Rationale:  "The CA ARI response moved the renewal window to the present.",
			Evidence:   evidence,
		}}
	default:
		return inferBasicDiagnosis(item, context)
	}
	if context.state == nil {
		diagnosis.CauseStatus = "unestablished"
		diagnosis.Confidence = "low"
		diagnosis.Summary = "No domain certificate row was retained for this finding."
		diagnosis.MeasurementPlan = []string{"Retain the current leaf, last scan time and the named certificate-condition fields on the domain row."}
	}
	return diagnosis
}

func certificateConditionProblem(item models.Anomaly, context diagnosisContext, checkedAt time.Time) string {
	dc := context.state
	cert, hasCert := currentCertificate(context)
	switch item.Type {
	case "expired_served":
		if !hasCert || cert.NotAfter.IsZero() {
			return "The currently recorded leaf for this name is past NotAfter."
		}
		days := daysPastNotAfter(cert.NotAfter, checkedAt)
		ip := servedFrom(dc)
		if ip != "" {
			return fmt.Sprintf("The currently recorded leaf for %s, last obtained from %s, has NotAfter %s, which had already passed at last scan %s by %d day(s).",
				item.Domain, ip, cert.NotAfter.UTC().Format(time.RFC3339), formatCheckedAt(checkedAt), days)
		}
		return fmt.Sprintf("The currently recorded leaf for %s has NotAfter %s, which had already passed at last scan %s by %d day(s).",
			item.Domain, cert.NotAfter.UTC().Format(time.RFC3339), formatCheckedAt(checkedAt), days)
	case "expired_observed":
		when := formatCheckedAt(checkedAt)
		if hasCert && !cert.NotAfter.IsZero() {
			return fmt.Sprintf("A previous collector recorded an expired leaf for %s (NotAfter %s) while the row was marked dormant at %s.",
				item.Domain, cert.NotAfter.UTC().Format(time.RFC3339), when)
		}
		return fmt.Sprintf("A previous collector recorded an expired certificate for %s while the row was marked dormant.", item.Domain)
	case "expiring_soon":
		if !hasCert || cert.NotAfter.IsZero() {
			return "The currently recorded leaf is inside the seven-day expiry window."
		}
		days := models.DaysUntil(cert.NotAfter, checkedAt)
		if days < 0 {
			days = 0
		}
		return fmt.Sprintf("The currently recorded leaf for %s expires on %s, which is %d day(s) from last scan %s.",
			item.Domain, cert.NotAfter.UTC().Format(time.RFC3339), days, formatCheckedAt(checkedAt))
	case "revoked":
		via := "unknown"
		if dc != nil && dc.RevocationCheckedVia != "" {
			via = dc.RevocationCheckedVia
		}
		if dc != nil && dc.Status == models.StatusUnreachable {
			return fmt.Sprintf("The last successful revocation check reported the currently recorded leaf for %s as revoked via %s; current endpoint revalidation is pending.", item.Domain, via)
		}
		return fmt.Sprintf("The currently recorded leaf for %s was reported as revoked by the retained revocation check via %s.", item.Domain, via)
	case models.ObsResidual:
		duration := residualDuration(item, context)
		fp := residualFingerprint(item, context)
		if duration > 0 && fp != "" {
			return fmt.Sprintf("Revoked leaf %s for %s remained observable %.1f hour(s) after the CA revocation timestamp.", shortProofFP(fp), item.Domain, duration.Hours())
		}
		if duration > 0 {
			return fmt.Sprintf("A revoked leaf for %s remained observable %.1f hour(s) after the CA revocation timestamp.", item.Domain, duration.Hours())
		}
		return fmt.Sprintf("A revoked leaf for %s remained observable after the CA revocation timestamp.", item.Domain)
	case "unreachable":
		failure := failureClassOf(dc)
		n := 0
		if dc != nil {
			n = dc.ConsecutiveFailures
		}
		return fmt.Sprintf("Repeated monitoring of %s did not obtain a TLS certificate (%d consecutive failure(s), classified as %s).", item.Domain, n, failure)
	case "measurement_failed":
		failure := failureClassOf(dc)
		n := 0
		if dc != nil {
			n = dc.ConsecutiveFailures
		}
		return fmt.Sprintf("The latest monitoring attempt for %s failed to obtain a TLS certificate (classified as %s, %d consecutive failure(s)); repeat confirmation is pending.", item.Domain, failure, n)
	case "ari_emergency":
		if dc != nil && dc.Status == models.StatusUnreachable {
			return fmt.Sprintf("The last successful CA ARI response for %s moved the renewal window to the present; current endpoint revalidation is pending.", item.Domain)
		}
		if start, end, ok := ariWindowOf(dc); ok {
			return fmt.Sprintf("The CA ARI response for %s moved the renewal window to the present (window %s .. %s).", item.Domain, start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
		}
		return fmt.Sprintf("The CA ARI response for %s moved the renewal window to the present.", item.Domain)
	default:
		if item.Description != "" {
			return item.Description
		}
		return "A measured certificate condition was retained."
	}
}

func certificateConditionWhy(item models.Anomaly, context diagnosisContext, checkedAt time.Time) string {
	dc := context.state
	cert, hasCert := currentCertificate(context)
	switch item.Type {
	case "expired_served":
		if !hasCert || cert.NotAfter.IsZero() {
			return "The currently recorded leaf is past NotAfter on the last successful scan."
		}
		parts := []string{fmt.Sprintf("A successful TLS handshake returned a leaf whose NotAfter %s is before last scan %s.", cert.NotAfter.UTC().Format(time.RFC3339), formatCheckedAt(checkedAt))}
		if dc != nil && dc.Status == models.StatusUnreachable {
			parts = append(parts, "Subsequent endpoint measurements are unreachable, so the finding remains critical pending revalidation.")
		}
		return strings.Join(parts, " ")
	case "expired_observed":
		return "A previous collector recorded an expired certificate while the row was marked dormant. That historical observation does not establish that the domain is currently offline."
	case "expiring_soon":
		if !hasCert || cert.NotAfter.IsZero() {
			return "The currently recorded leaf is inside the seven-day expiry window."
		}
		days := models.DaysUntil(cert.NotAfter, checkedAt)
		if days < 0 {
			days = 0
		}
		return fmt.Sprintf("The currently deployed certificate NotAfter is %s, which is %d day(s) from the last scan, inside the seven-day expiry window.", cert.NotAfter.UTC().Format(time.RFC3339), days)
	case "revoked":
		via := "unknown"
		if dc != nil && dc.RevocationCheckedVia != "" {
			via = dc.RevocationCheckedVia
		}
		parts := []string{fmt.Sprintf("The retained revocation check reported the currently recorded certificate as revoked via %s.", via)}
		if dc != nil && dc.Status == models.StatusUnreachable {
			parts = append(parts, "Subsequent endpoint measurements are unreachable, so the finding remains critical pending revalidation.")
		}
		return strings.Join(parts, " ")
	case models.ObsResidual:
		duration := residualDuration(item, context)
		if duration > 0 {
			return fmt.Sprintf("The revoked leaf was observed again %.1f hour(s) after the CA revocation timestamp. That duration is a direct lower bound for residual service at the observed endpoint.", duration.Hours())
		}
		return "The revoked leaf was observed again after the CA revocation timestamp."
	case "unreachable", "measurement_failed":
		failure := failureClassOf(dc)
		n := 0
		if dc != nil {
			n = dc.ConsecutiveFailures
		}
		if item.Type == "measurement_failed" {
			return fmt.Sprintf("The latest monitoring attempt failed to obtain a TLS certificate and was classified as %s (%d consecutive failure(s)). Repeat confirmation is pending.", failure, n)
		}
		return fmt.Sprintf("Repeated monitoring failed to obtain a TLS certificate and was classified as %s (%d consecutive failure(s)).", failure, n)
	case "ari_emergency":
		parts := []string{"The CA's ARI response moved the renewal window to the present."}
		if dc != nil && dc.Status == models.StatusUnreachable {
			parts = append(parts, "Subsequent endpoint measurements are unreachable, so the finding remains critical pending revalidation.")
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

func certificateConditionConclusion(item models.Anomaly, context diagnosisContext, checkedAt time.Time) string {
	dc := context.state
	cert, hasCert := currentCertificate(context)
	switch item.Type {
	case "expired_served":
		if hasCert && !cert.NotAfter.IsZero() {
			days := daysPastNotAfter(cert.NotAfter, checkedAt)
			return fmt.Sprintf("A successful TLS handshake returned a certificate whose NotAfter time had passed by %d day(s).", days)
		}
		return "A successful TLS handshake returned a certificate whose NotAfter had already passed."
	case "expired_observed":
		return "A previous collector recorded an expired certificate while the row was marked dormant."
	case "expiring_soon":
		if hasCert && !cert.NotAfter.IsZero() {
			days := models.DaysUntil(cert.NotAfter, checkedAt)
			if days < 0 {
				days = 0
			}
			return fmt.Sprintf("The currently deployed certificate is inside the seven-day expiry window (%d day(s) remaining).", days)
		}
		return "The currently deployed certificate is inside the seven-day expiry window."
	case "revoked":
		if dc != nil && dc.Status == models.StatusUnreachable {
			return "The last successful TLS measurement reported the certificate as revoked; subsequent endpoint measurements are unreachable, so the finding remains critical pending revalidation."
		}
		return "The current certificate was reported as revoked by the retained revocation check."
	case models.ObsResidual:
		duration := residualDuration(item, context)
		if duration > 0 {
			return fmt.Sprintf("The revoked leaf was observed again %.1f hour(s) after the CA revocation timestamp. This is a direct lower bound for residual service at the observed endpoint.", duration.Hours())
		}
		return "The revoked leaf was observed again after the CA revocation timestamp."
	case "unreachable", "measurement_failed":
		failure := failureClassOf(dc)
		return fmt.Sprintf("The latest monitoring attempt failed to obtain a TLS certificate and was classified as %s.", failure)
	case "ari_emergency":
		if dc != nil && dc.Status == models.StatusUnreachable {
			return "The last successful CA ARI response moved the renewal window to the present; subsequent endpoint measurements are unreachable, so the finding remains critical pending revalidation."
		}
		return "The CA's ARI response moved the renewal window to the present."
	default:
		return item.Reason
	}
}

func certificateConditionFacts(item models.Anomaly, context diagnosisContext) []string {
	return uniqueEvidenceStrings(certificateConditionEvidence(item, context, certificateConditionCheckedAt(item, context.state)))
}

func certificateConditionEvidence(item models.Anomaly, context diagnosisContext, checkedAt time.Time) []string {
	dc := context.state
	out := make([]string, 0, 12)
	if !checkedAt.IsZero() {
		out = append(out, "checked_at="+checkedAt.UTC().Format(time.RFC3339))
	}
	if dc != nil {
		if dc.CurrentFingerprint != "" {
			out = append(out, "current_fingerprint="+dc.CurrentFingerprint)
		}
		if dc.Status != "" {
			out = append(out, "status="+dc.Status)
		}
		if !dc.LastScannedAt.IsZero() {
			out = append(out, "last_scanned_at="+dc.LastScannedAt.UTC().Format(time.RFC3339))
		}
		if ip := servedFrom(dc); ip != "" {
			out = append(out, "last_endpoint_ip="+ip)
		}
	}
	if cert, ok := currentCertificate(context); ok {
		if !cert.NotAfter.IsZero() {
			out = append(out, "not_after="+cert.NotAfter.UTC().Format(time.RFC3339))
			if item.Type == "expired_served" || item.Type == "expired_observed" {
				out = append(out, fmt.Sprintf("days_past_not_after=%d", daysPastNotAfter(cert.NotAfter, checkedAt)))
			}
			if item.Type == "expiring_soon" {
				out = append(out, fmt.Sprintf("days_until_expiry=%d", models.DaysUntil(cert.NotAfter, checkedAt)))
			}
		}
		if !cert.NotBefore.IsZero() {
			out = append(out, "not_before="+cert.NotBefore.UTC().Format(time.RFC3339))
		}
		if cert.Fingerprint != "" {
			out = append(out, "leaf="+shortProofFP(cert.Fingerprint))
		}
	}
	switch item.Type {
	case "revoked":
		if dc != nil {
			out = append(out, "revocation_status="+firstNonEmpty(dc.RevocationStatus, "unknown"))
			out = append(out, "checked_via="+firstNonEmpty(dc.RevocationCheckedVia, "unknown"))
			if dc.RevokedAt != nil && !dc.RevokedAt.IsZero() {
				out = append(out, "revoked_at="+dc.RevokedAt.UTC().Format(time.RFC3339))
			}
			if dc.RevocationCheckedAt != nil && !dc.RevocationCheckedAt.IsZero() {
				out = append(out, "revocation_checked_at="+dc.RevocationCheckedAt.UTC().Format(time.RFC3339))
			}
			if dc.RevocationReason != "" {
				out = append(out, "revocation_reason="+dc.RevocationReason)
			}
			if dc.Status == models.StatusUnreachable {
				out = append(out, "last_known_status=unreachable", "revalidation=pending")
			}
		}
	case models.ObsResidual:
		fp := residualFingerprint(item, context)
		if fp != "" {
			out = append(out, "residual_fingerprint="+fp)
		}
		if observation, ok := latestObservationOf(context, models.ObsResidual); ok {
			out = append(out, "observed_at="+observation.ObservedAt.UTC().Format(time.RFC3339))
			if observation.ResidualDurationSeconds > 0 {
				out = append(out, fmt.Sprintf("residual_duration_seconds=%d", observation.ResidualDurationSeconds))
			}
			if observation.RevokedAt != nil && !observation.RevokedAt.IsZero() {
				out = append(out, "revoked_at="+observation.RevokedAt.UTC().Format(time.RFC3339))
			}
			if observation.IPAddress != "" {
				out = append(out, "ip="+observation.IPAddress)
			}
			out = append(out, "observation_type="+observation.ObservationType)
		} else if dc != nil {
			if dc.ResidualRevokedAt != nil && !dc.ResidualRevokedAt.IsZero() {
				out = append(out, "revoked_at="+dc.ResidualRevokedAt.UTC().Format(time.RFC3339))
			}
			if dc.ResidualLastSeenAt != nil && !dc.ResidualLastSeenAt.IsZero() {
				out = append(out, "residual_last_seen_at="+dc.ResidualLastSeenAt.UTC().Format(time.RFC3339))
			}
			if dc.ResidualObservationCount > 0 {
				out = append(out, fmt.Sprintf("residual_observation_count=%d", dc.ResidualObservationCount))
			}
		}
		if duration := residualDuration(item, context); duration > 0 {
			out = append(out, fmt.Sprintf("residual_hours=%.1f", duration.Hours()))
		}
	case "unreachable", "measurement_failed":
		out = append(out, "failure_class="+failureClassOf(dc))
		if dc != nil {
			out = append(out, fmt.Sprintf("consecutive_failures=%d", dc.ConsecutiveFailures))
			if dc.LastError != "" {
				out = append(out, "latest_error="+dc.LastError)
			}
		}
	case "ari_emergency":
		out = append(out, "ari_emergency=true")
		if dc != nil {
			if dc.ARICheckedAt != nil && !dc.ARICheckedAt.IsZero() {
				out = append(out, "ari_checked_at="+dc.ARICheckedAt.UTC().Format(time.RFC3339))
			}
			if start, end, ok := ariWindowOf(dc); ok {
				out = append(out, "ari_window_start="+start.UTC().Format(time.RFC3339), "ari_window_end="+end.UTC().Format(time.RFC3339))
			}
			if dc.ARIExplanationURL != "" {
				out = append(out, "ari_explanation_url="+dc.ARIExplanationURL)
			}
			if dc.Status == models.StatusUnreachable {
				out = append(out, "last_known_status=unreachable", "revalidation=pending")
			}
		}
	case "expired_served", "expired_observed":
		if dc != nil && dc.Status == models.StatusUnreachable {
			out = append(out, "last_known_status=unreachable", "revalidation=pending")
		}
		if dc != nil && dc.Status == models.StatusDormant {
			out = append(out, "legacy_status=dormant")
		}
	}
	return uniqueEvidenceStrings(out)
}

func certificateConditionProof(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis, investigation *models.Investigation) (proven, inferred []models.InvestigationProofStep) {
	checkedAt := certificateConditionCheckedAt(item, context.state)
	evidence := certificateConditionEvidence(item, context, checkedAt)
	if context.state == nil {
		inferred = appendInferred(inferred,
			"Coverage",
			"This certificate-condition finding cannot be reconstructed: no domain certificate row was retained.",
			[]string{"type=" + item.Type},
			"The finding is stored from the current leaf, last scan and named condition fields on the domain row.",
		)
		return proven, inferred
	}
	switch item.Type {
	case "expired_served":
		proven = append(proven, provenStep(
			"Captured leaf",
			"A successful TLS handshake returned the currently recorded leaf whose NotAfter is before the last scan time.",
			evidence,
			"Leaf NotAfter compared with last_scanned_at on the domain row.",
		))
		if context.state.Status == models.StatusUnreachable {
			proven = append(proven, provenStep(
				"Revalidation pending",
				"Subsequent endpoint measurements are unreachable, so the expired leaf has not been revalidated.",
				evidence,
				"Domain status after the last successful scan.",
			))
		}
		proven = append(proven, provenStep(
			"Conclusion",
			certificateConditionConclusion(item, context, checkedAt),
			evidence,
			"The currently recorded leaf NotAfter is before the last successful scan.",
		))
		inferred = appendInferred(inferred,
			"Deployment lag",
			"The endpoint likely has an outdated deployment or missed renewal; certificate expiry alone does not prove that the domain is retired.",
			evidence,
			"Inferred from continued service of a leaf past NotAfter. Public TLS cannot observe operator intent or retirement.",
		)
	case "expired_observed":
		proven = append(proven, provenStep(
			"Historical observation",
			"A previous collector recorded an expired certificate while the row was marked dormant.",
			evidence,
			"Dormant-row status plus the retained leaf NotAfter.",
		))
		proven = append(proven, provenStep(
			"Conclusion",
			"An expired leaf was observed historically for this name.",
			evidence,
			"The dormant-row observation is a measurement, not a current handshake.",
		))
		inferred = appendInferred(inferred,
			"Current state unknown",
			"The domain may have changed state since that observation; expiry on a dormant row cannot establish that it is offline.",
			evidence,
			"Dormant is a legacy collector mark. No current handshake is attached to this finding.",
		)
	case "expiring_soon":
		proven = append(proven, provenStep(
			"Current leaf",
			"The currently recorded leaf NotAfter falls inside the seven-day expiry window.",
			evidence,
			"Leaf NotAfter compared with the last scan time.",
		))
		proven = append(proven, provenStep(
			"Conclusion",
			certificateConditionConclusion(item, context, checkedAt),
			evidence,
			"Seven-day remaining-life window on the currently deployed certificate.",
		))
		inferred = appendInferred(inferred,
			"Renewal attention",
			"Renewal or deployment attention may be required before expiry. Remaining life does not prove that renewal has failed.",
			evidence,
			"Inferred from remaining life inside the warning window, not from a failed handshake.",
		)
	case "revoked":
		proven = append(proven, provenStep(
			"Revocation check",
			"The retained revocation check reported the currently recorded certificate as revoked.",
			evidence,
			"OCSP, CRL or stapled-OCSP status stored on the domain row.",
		))
		if context.state.Status == models.StatusUnreachable {
			proven = append(proven, provenStep(
				"Revalidation pending",
				"Subsequent endpoint measurements are unreachable, so the revoked leaf has not been revalidated.",
				evidence,
				"Domain status after the last successful scan.",
			))
		}
		proven = append(proven, provenStep(
			"Conclusion",
			certificateConditionConclusion(item, context, checkedAt),
			evidence,
			"revocation_status=revoked on the currently recorded leaf.",
		))
		if context.state.RevocationReason != "" {
			inferred = appendInferred(inferred,
				"CA reason",
				fmt.Sprintf("The CA-reported revocation reason is %q; this is a CA classification and does not prove the operator's intent.", context.state.RevocationReason),
				evidence,
				"The reason string is copied from the CA response. Public measurements cannot read operator intent.",
			)
		} else {
			inferred = appendInferred(inferred,
				"Operator intent unknown",
				"A revoked status does not establish why the certificate was revoked or whether the operator intended it.",
				evidence,
				"Revocation is a CA/status-protocol result, not an operator statement.",
			)
		}
	case models.ObsResidual:
		proven = append(proven, provenStep(
			"Revoked leaf still served",
			"The revoked leaf was observed again after the CA revocation timestamp.",
			evidence,
			"Direct TLS observation of the revoked fingerprint after revoked_at.",
		))
		proven = append(proven, provenStep(
			"Conclusion",
			certificateConditionConclusion(item, context, checkedAt),
			evidence,
			"Observation time minus CA revocation time is a lower bound for residual service at this vantage.",
		))
		inferred = appendInferred(inferred,
			"Configuration lag",
			"The endpoint likely retained an obsolete certificate configuration after CA revocation; this observation does not establish how many other edges or clients accepted it.",
			evidence,
			"Inferred from residual service at the observed endpoint only.",
		)
	case "unreachable", "measurement_failed":
		claim := "The latest monitoring attempt failed to obtain a TLS certificate."
		if item.Type == "unreachable" {
			claim = "Repeated monitoring did not obtain a TLS certificate."
		}
		proven = append(proven, provenStep(
			"Failed handshake",
			claim,
			evidence,
			"Last failure class, last error and consecutive-failure count on the domain row.",
		))
		proven = append(proven, provenStep(
			"Conclusion",
			certificateConditionConclusion(item, context, checkedAt),
			evidence,
			"A failed TLS attempt has no certificate evidence to enrich; the failure itself is the measurement.",
		))
		inferred = appendInferred(inferred,
			"Vantage-specific failure",
			"This is a vantage-specific observation and does not prove that the domain has been taken offline.",
			evidence,
			"Unreachability at this collector does not establish global retirement or DNS withdrawal.",
		)
	case "ari_emergency":
		proven = append(proven, provenStep(
			"ARI window",
			"The CA ARI response moved the renewal window to the present.",
			evidence,
			"ari_emergency=true and the stored ARI window on the domain row.",
		))
		if context.state.Status == models.StatusUnreachable {
			proven = append(proven, provenStep(
				"Revalidation pending",
				"Subsequent endpoint measurements are unreachable, so the ARI emergency has not been revalidated.",
				evidence,
				"Domain status after the last successful ARI check.",
			))
		}
		proven = append(proven, provenStep(
			"Conclusion",
			certificateConditionConclusion(item, context, checkedAt),
			evidence,
			"ARI suggestedWindowStart at or before now is stored as ari_emergency.",
		))
		inferred = appendInferred(inferred,
			"Urgent renewal or CA incident",
			"This may indicate urgent renewal pressure or a broader CA incident; it does not establish the operator's intent.",
			evidence,
			"ARI is a CA-side signal. Public TLS cannot read why the CA pulled the window forward.",
		)
	}
	return proven, inferred
}

func certificateConditionCheckedAt(item models.Anomaly, dc *models.DomainCertificate) time.Time {
	if !item.DetectedAt.IsZero() {
		return item.DetectedAt.UTC()
	}
	if dc != nil {
		switch item.Type {
		case "revoked":
			if dc.RevocationCheckedAt != nil && !dc.RevocationCheckedAt.IsZero() {
				return dc.RevocationCheckedAt.UTC()
			}
			if dc.RevokedAt != nil && !dc.RevokedAt.IsZero() {
				return dc.RevokedAt.UTC()
			}
		case "ari_emergency":
			if dc.ARICheckedAt != nil && !dc.ARICheckedAt.IsZero() {
				return dc.ARICheckedAt.UTC()
			}
		case models.ObsResidual:
			if dc.ResidualLastSeenAt != nil && !dc.ResidualLastSeenAt.IsZero() {
				return dc.ResidualLastSeenAt.UTC()
			}
		}
		if !dc.LastScannedAt.IsZero() {
			return dc.LastScannedAt.UTC()
		}
	}
	return time.Now().UTC()
}

func servedFrom(dc *models.DomainCertificate) string {
	if dc == nil {
		return ""
	}
	return strings.TrimSpace(dc.LastEndpointIP)
}

func failureClassOf(dc *models.DomainCertificate) string {
	if dc == nil || strings.TrimSpace(dc.LastFailureClass) == "" {
		return "unknown"
	}
	return dc.LastFailureClass
}

func daysPastNotAfter(notAfter, checkedAt time.Time) int {
	if notAfter.IsZero() || checkedAt.IsZero() {
		return 0
	}
	days := -models.DaysUntil(notAfter, checkedAt)
	if days < 1 {
		return 1
	}
	return days
}

func formatCheckedAt(checkedAt time.Time) string {
	if checkedAt.IsZero() {
		return "unknown"
	}
	return checkedAt.UTC().Format(time.RFC3339)
}

func latestObservationOf(context diagnosisContext, kind string) (models.CertObservation, bool) {
	for _, observation := range context.observations {
		if observation.ObservationType == kind {
			return observation, true
		}
	}
	return models.CertObservation{}, false
}

func residualFingerprint(item models.Anomaly, context diagnosisContext) string {
	if context.state != nil && context.state.ResidualFingerprint != "" {
		return context.state.ResidualFingerprint
	}
	if observation, ok := latestObservationOf(context, models.ObsResidual); ok && observation.Fingerprint != "" {
		return observation.Fingerprint
	}
	return item.Fingerprint
}

func residualDuration(item models.Anomaly, context diagnosisContext) time.Duration {
	if observation, ok := latestObservationOf(context, models.ObsResidual); ok && observation.ResidualDurationSeconds > 0 {
		return time.Duration(observation.ResidualDurationSeconds) * time.Second
	}
	if context.state != nil && context.state.ResidualRevokedAt != nil && context.state.ResidualLastSeenAt != nil {
		start := context.state.ResidualRevokedAt.UTC()
		end := context.state.ResidualLastSeenAt.UTC()
		if end.After(start) {
			return end.Sub(start)
		}
	}
	return 0
}

func ariWindowOf(dc *models.DomainCertificate) (start, end time.Time, ok bool) {
	if dc == nil || dc.ARIWindowStart == nil || dc.ARIWindowEnd == nil {
		return time.Time{}, time.Time{}, false
	}
	if dc.ARIWindowStart.IsZero() || dc.ARIWindowEnd.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	return *dc.ARIWindowStart, *dc.ARIWindowEnd, true
}
