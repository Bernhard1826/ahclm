package database

import (
	"strings"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestExpiredServedProofCitesNotAfterAndLastScan(t *testing.T) {
	checkedAt := time.Date(2026, 9, 19, 2, 18, 41, 0, time.UTC)
	notAfter := time.Date(2026, 3, 22, 15, 17, 26, 0, time.UTC)
	fp := "e47ab2ca23c2bc24b3ada7ea4252cf08222077a13a2568ded835651561aca8c8"
	item := models.Anomaly{Domain: "00yuyin.com", Type: "expired_served", DetectedAt: checkedAt, Fingerprint: fp}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:             "00yuyin.com",
			CurrentFingerprint: fp,
			Status:             models.StatusActive,
			LastScannedAt:      checkedAt,
			LastEndpointIP:     "47.108.214.201",
			CurrentCertificate: &models.Certificate{Fingerprint: fp, NotAfter: notAfter},
		},
		certificates: map[string]models.Certificate{
			fp: {Fingerprint: fp, NotAfter: notAfter},
		},
	}
	diagnosis := inferCertificateConditionDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if diagnosis.PrimaryCode != certCauseExpiredServed {
		t.Fatalf("primary = %q, want %s", diagnosis.PrimaryCode, certCauseExpiredServed)
	}
	if diagnosis.CauseStatus != "established" {
		t.Fatalf("cause status = %q, want established", diagnosis.CauseStatus)
	}
	if findingClassOf(diagnosis) != models.FindingIncident {
		t.Fatalf("finding class = %q, want incident", findingClassOf(diagnosis))
	}
	if containsFold(investigation.Problem, "changed 0 time") || containsFold(investigation.Problem, "distinct certificate") {
		t.Fatalf("frequent-change template leaked into expired_served problem: %q", investigation.Problem)
	}
	if containsFold(investigation.Cause, "insufficient") {
		t.Fatalf("generic diagnosis leaked into expired_served cause: %#v", investigation)
	}
	if !hasProofLabel(investigation.Proof, "Captured leaf") || !hasProofLabel(investigation.Proof, "Conclusion") {
		t.Fatalf("expired_served omitted a measurement step: %#v", investigation.Proof)
	}
	if investigation.CauseStatus != "established" {
		t.Fatalf("expired_served cause status = %q, want established", investigation.CauseStatus)
	}
	if investigation.ProofKind != "mixed" {
		t.Fatalf("expired_served proof kind = %q, want mixed (measured condition plus an operational reading)", investigation.ProofKind)
	}
	assertClaimThenEvidence(t, investigation.Proof)
	assertClaimThenEvidence(t, investigation.Inference)
	if !proofEvidenceContains(investigation.Proof, "2026-03-22T15:17:26Z") || !proofEvidenceContains(investigation.Proof, "47.108.214.201") {
		t.Fatalf("expired_served proof did not cite NotAfter and last endpoint: %#v", investigation.Proof)
	}
	if !containsFold(investigation.Problem, "47.108.214.201") || !containsFold(investigation.Problem, "2026-03-22") {
		t.Fatalf("problem did not name the expired current leaf: %q", investigation.Problem)
	}
	if !containsFold(investigation.WhyProblem, "NotAfter") {
		t.Fatalf("why-problem did not cite NotAfter: %q", investigation.WhyProblem)
	}
}

func TestRevokedProofCitesRevocationCheck(t *testing.T) {
	checkedAt := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	revokedAt := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	fp := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	item := models.Anomaly{Domain: "revoked.example", Type: "revoked", DetectedAt: checkedAt, Fingerprint: fp}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:               "revoked.example",
			CurrentFingerprint:   fp,
			Status:               models.StatusActive,
			RevocationStatus:     models.RevocationRevoked,
			RevocationCheckedVia: models.CheckedViaOCSP,
			RevokedAt:            &revokedAt,
			RevocationCheckedAt:  &checkedAt,
			RevocationReason:     "keyCompromise",
			LastScannedAt:        checkedAt,
			CurrentCertificate:   &models.Certificate{Fingerprint: fp, NotAfter: checkedAt.Add(30 * 24 * time.Hour)},
		},
	}
	diagnosis := inferCertificateConditionDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if diagnosis.PrimaryCode != certCauseRevoked {
		t.Fatalf("primary = %q", diagnosis.PrimaryCode)
	}
	if containsFold(investigation.Problem, "changed 0 time") {
		t.Fatalf("frequent-change template leaked into revoked problem: %q", investigation.Problem)
	}
	if !containsFold(investigation.Problem, "revoked") || !containsFold(investigation.Problem, "ocsp") {
		t.Fatalf("revoked problem omitted the check: %q", investigation.Problem)
	}
	assertClaimThenEvidence(t, investigation.Proof)
	assertClaimThenEvidence(t, investigation.Inference)
	if !proofEvidenceContains(investigation.Proof, "revocation_status=revoked") || !proofEvidenceContains(investigation.Proof, "checked_via=ocsp") {
		t.Fatalf("revoked proof omitted the check evidence: %#v", investigation.Proof)
	}
	if !containsFold(investigation.Inference[0].Claim, "keyCompromise") {
		t.Fatalf("CA reason was not kept as inference: %#v", investigation.Inference)
	}
}

func TestUnreachableProofDoesNotUseChurnLanguage(t *testing.T) {
	checkedAt := time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC)
	item := models.Anomaly{Domain: "down.example", Type: "unreachable", DetectedAt: checkedAt, OccurrenceCount: 8}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:              "down.example",
			Status:              models.StatusUnreachable,
			ConsecutiveFailures: 8,
			LastFailureClass:    "dial_timeout",
			LastError:           "i/o timeout",
			LastScannedAt:       checkedAt,
		},
	}
	diagnosis := inferCertificateConditionDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if diagnosis.PrimaryCode != certCauseUnreachable {
		t.Fatalf("primary = %q", diagnosis.PrimaryCode)
	}
	if containsFold(investigation.Problem, "changed") || containsFold(investigation.Problem, "distinct certificate") {
		t.Fatalf("churn language leaked into unreachable problem: %q", investigation.Problem)
	}
	if !containsFold(investigation.Problem, "dial_timeout") {
		t.Fatalf("unreachable problem omitted failure class: %q", investigation.Problem)
	}
	assertClaimThenEvidence(t, investigation.Proof)
	if !proofEvidenceContains(investigation.Proof, "consecutive_failures=8") || !proofEvidenceContains(investigation.Proof, "i/o timeout") {
		t.Fatalf("unreachable proof omitted failure evidence: %#v", investigation.Proof)
	}
	if !containsFold(investigation.Inference[0].Claim, "does not prove") {
		t.Fatalf("unreachable inference should not claim retirement: %#v", investigation.Inference)
	}
}

func TestResidualProofCitesDurationAfterRevocation(t *testing.T) {
	revokedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	seenAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	fp := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	item := models.Anomaly{Domain: "residual.example", Type: models.ObsResidual, DetectedAt: seenAt, Fingerprint: fp}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:              "residual.example",
			ResidualFingerprint: fp,
			ResidualRevokedAt:   &revokedAt,
			ResidualLastSeenAt:  &seenAt,
		},
		observations: []models.CertObservation{{
			Domain:                  "residual.example",
			ObservationType:         models.ObsResidual,
			Fingerprint:             fp,
			ObservedAt:              seenAt,
			RevokedAt:               &revokedAt,
			ResidualDurationSeconds: int64(seenAt.Sub(revokedAt).Seconds()),
			IPAddress:               "192.0.2.9",
		}},
	}
	diagnosis := inferCertificateConditionDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if diagnosis.PrimaryCode != certCauseResidual {
		t.Fatalf("primary = %q", diagnosis.PrimaryCode)
	}
	if containsFold(investigation.Problem, "changed 0 time") {
		t.Fatalf("frequent-change template leaked into residual problem: %q", investigation.Problem)
	}
	if !containsFold(investigation.Problem, "hour") {
		t.Fatalf("residual problem omitted duration: %q", investigation.Problem)
	}
	assertClaimThenEvidence(t, investigation.Proof)
	if !proofEvidenceContains(investigation.Proof, "192.0.2.9") || !proofEvidenceContains(investigation.Proof, "residual_duration_seconds") {
		t.Fatalf("residual proof omitted observation evidence: %#v", investigation.Proof)
	}
}

func TestExpiringSoonAndARIEmergencyKeepOwnCopy(t *testing.T) {
	now := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	notAfter := now.Add(3 * 24 * time.Hour)
	fp := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	expiring := models.Anomaly{Domain: "soon.example", Type: "expiring_soon", DetectedAt: now, Fingerprint: fp}
	expiringCtx := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:             "soon.example",
			CurrentFingerprint: fp,
			Status:             models.StatusActive,
			LastScannedAt:      now,
			CurrentCertificate: &models.Certificate{Fingerprint: fp, NotAfter: notAfter},
		},
	}
	expiringInv := buildInvestigation(expiring, expiringCtx, inferCertificateConditionDiagnosis(expiring, expiringCtx))
	if containsFold(expiringInv.Problem, "changed") {
		t.Fatalf("expiring_soon used churn language: %q", expiringInv.Problem)
	}
	if !containsFold(expiringInv.Problem, "2026-09-22") {
		t.Fatalf("expiring_soon problem omitted NotAfter: %q", expiringInv.Problem)
	}

	start := now.Add(-time.Hour)
	end := now.Add(time.Hour)
	checked := now
	ari := models.Anomaly{Domain: "ari.example", Type: "ari_emergency", DetectedAt: checked, Fingerprint: fp}
	ariCtx := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:             "ari.example",
			CurrentFingerprint: fp,
			Status:             models.StatusActive,
			ARIEmergency:       true,
			ARIWindowStart:     &start,
			ARIWindowEnd:       &end,
			ARICheckedAt:       &checked,
		},
	}
	ariInv := buildInvestigation(ari, ariCtx, inferCertificateConditionDiagnosis(ari, ariCtx))
	if containsFold(ariInv.Problem, "changed 0 time") {
		t.Fatalf("ari_emergency used churn language: %q", ariInv.Problem)
	}
	if !containsFold(ariInv.Problem, "ARI") && !containsFold(ariInv.Problem, "renewal window") {
		t.Fatalf("ari_emergency problem omitted the ARI window: %q", ariInv.Problem)
	}
	assertClaimThenEvidence(t, ariInv.Proof)
}

func TestDiagnosisTypeForDoesNotRemapCertificateConditions(t *testing.T) {
	rows := []models.CertObservation{{ObservationType: models.ObsChange}}
	if got := diagnosisTypeFor("expired_served", rows); got != "expired_served" {
		t.Fatalf("expired_served remapped to %q", got)
	}
	if got := diagnosisTypeFor("revoked", nil); got != "revoked" {
		t.Fatalf("revoked remapped to %q", got)
	}
}

func TestCertificateConditionInvestigationOmitsChurnExhibits(t *testing.T) {
	now := time.Date(2026, 9, 19, 3, 14, 37, 0, time.UTC)
	fp := "80a74e4c04e7d64ebc250bc158a57575c2d6d4cbddb1bace76d169e7aec8298a"
	item := models.Anomaly{Domain: "presage.io", Type: "expired_served", DetectedAt: now, Fingerprint: fp}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:             "presage.io",
			CurrentFingerprint: fp,
			Status:             models.StatusActive,
			LastScannedAt:      now,
			LastEndpointIP:     "217.70.184.55",
			CurrentCertificate: &models.Certificate{Fingerprint: fp, NotAfter: time.Date(2025, 10, 3, 23, 59, 59, 0, time.UTC)},
		},
		observations: []models.CertObservation{{
			Domain:          "presage.io",
			ObservationType: models.ObsChange,
			Fingerprint:     "other",
			ObservedAt:      now.Add(-time.Hour),
		}},
	}
	investigation := buildInvestigation(item, context, inferCertificateConditionDiagnosis(item, context))
	if len(investigation.ChangeSequence) != 0 {
		t.Fatalf("expired_served should not carry a change sequence: %#v", investigation.ChangeSequence)
	}
	if len(investigation.ProviderGroups) != 0 {
		t.Fatalf("expired_served should not carry provider groups: %#v", investigation.ProviderGroups)
	}
	for _, fact := range investigation.Facts {
		if containsFold(fact, "change counter") || containsFold(fact, "provider network") {
			t.Fatalf("expired_served fact leaked churn/diversity language: %q", fact)
		}
	}
}

func TestInferDiagnosisRoutesCertificateConditions(t *testing.T) {
	now := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	item := models.Anomaly{Domain: "route.example", Type: "expired_served", DetectedAt: now}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:             "route.example",
			CurrentFingerprint: "dd",
			Status:             models.StatusActive,
			LastScannedAt:      now,
			CurrentCertificate: &models.Certificate{Fingerprint: "dd", NotAfter: now.Add(-48 * time.Hour)},
		},
	}
	diagnosis := inferDiagnosis(item, context)
	if diagnosis.PrimaryCode != certCauseExpiredServed {
		t.Fatalf("inferDiagnosis routed expired_served to %q", diagnosis.PrimaryCode)
	}
	if strings.Contains(strings.ToLower(diagnosis.Summary), "insufficient") {
		t.Fatalf("expired_served fell through to basic diagnosis: %#v", diagnosis)
	}
}
