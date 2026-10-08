package database

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestExpiredEndpointProofCitesNotAfterAndAddress(t *testing.T) {
	checkedAt := time.Date(2026, 9, 19, 2, 18, 41, 0, time.UTC)
	notAfter := time.Date(2026, 3, 22, 15, 17, 26, 0, time.UTC)
	fp := "e47ab2ca23c2bc24b3ada7ea4252cf08222077a13a2568ded835651561aca8c8"
	findings, _ := json.Marshal([]models.TLSFinding{{
		Code:        "expired_endpoint",
		Detail:      "certificate NotAfter=2026-03-22T15:17:26Z",
		IPAddress:   "47.108.214.201",
		Fingerprint: fp,
	}})
	item := models.Anomaly{Domain: "00yuyin.com", Type: "expired_endpoint", DetectedAt: checkedAt, Fingerprint: fp}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:             "00yuyin.com",
			CurrentFingerprint: fp,
			TLSFindings:        string(findings),
			TLSCheckedAt:       &checkedAt,
			CurrentCertificate: &models.Certificate{Fingerprint: fp, NotAfter: notAfter},
		},
		certificates: map[string]models.Certificate{
			fp: {Fingerprint: fp, NotAfter: notAfter},
		},
	}
	diagnosis := inferTLSValidationDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if diagnosis.PrimaryCode != tlsCauseExpiredLeaf {
		t.Fatalf("primary = %q, want %s", diagnosis.PrimaryCode, tlsCauseExpiredLeaf)
	}
	if diagnosis.CauseStatus != "established" {
		t.Fatalf("cause status = %q, want established", diagnosis.CauseStatus)
	}
	if findingClassOf(diagnosis) != models.FindingIncident {
		t.Fatalf("finding class = %q, want incident", findingClassOf(diagnosis))
	}
	if containsFold(investigation.Problem, "named check") || containsFold(investigation.Cause, "local trust") || containsFold(investigation.Cause, "insufficient") {
		t.Fatalf("generic TLS template leaked into expired-endpoint prose: %#v", investigation)
	}
	if !hasProofLabel(investigation.Proof, "Captured leaf") || !hasProofLabel(investigation.Proof, "Conclusion") {
		t.Fatalf("expired-endpoint omitted a measurement step: %#v", investigation.Proof)
	}
	assertClaimThenEvidence(t, investigation.Proof)
	if !proofEvidenceContains(investigation.Proof, "47.108.214.201") || !proofEvidenceContains(investigation.Proof, "2026-03-22T15:17:26Z") {
		t.Fatalf("expired-endpoint proof did not cite IP and NotAfter: %#v", investigation.Proof)
	}
	if !containsFold(investigation.Problem, "47.108.214.201") || !containsFold(investigation.Problem, "2026-03-22") {
		t.Fatalf("problem did not name the expired endpoint: %q", investigation.Problem)
	}
	item.FindingClass = findingClassOf(diagnosis)
	item.Diagnosis = &diagnosis
	if !isIssueRegisterFinding(item) {
		t.Fatal("measured expired leaf must stay on the issue register")
	}
}

func TestExpiredEndpointLeftoverIsInferredFromFingerprintDisagreement(t *testing.T) {
	checkedAt := time.Date(2026, 9, 19, 0, 34, 23, 0, time.UTC)
	currentFP := "626e3d138070db57ec6b0fb1f9d60a8960bdd1031cc06dd7fdf02acfb8029ebd"
	expiredFP := "e74a9781db7b5d09b48da7e784cd78f25aa0e39900a4f49878b199ac4fbe7d8e"
	findings, _ := json.Marshal([]models.TLSFinding{
		{
			Code:        "hostname_mismatch",
			Detail:      "x509: certificate is valid for *.kernfusion.at, kernfusion.at, n200.org, www.n200.org, not 0.openwrt.pool.ntp.org",
			IPAddress:   "162.244.81.139",
			Fingerprint: expiredFP,
		},
		{
			Code:        "expired_endpoint",
			Detail:      "certificate NotAfter=2026-09-17T18:27:56Z",
			IPAddress:   "162.244.81.139",
			Fingerprint: expiredFP,
		},
	})
	item := models.Anomaly{Domain: "0.openwrt.pool.ntp.org", Type: "expired_endpoint", DetectedAt: checkedAt}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:             "0.openwrt.pool.ntp.org",
			CurrentFingerprint: currentFP,
			TLSFindings:        string(findings),
			TLSCheckedAt:       &checkedAt,
			CurrentCertificate: &models.Certificate{
				Fingerprint: currentFP,
				NotAfter:    time.Date(2026, 9, 24, 12, 25, 49, 0, time.UTC),
			},
		},
		certificates: map[string]models.Certificate{
			currentFP: {Fingerprint: currentFP, NotAfter: time.Date(2026, 9, 24, 12, 25, 49, 0, time.UTC)},
			expiredFP: {Fingerprint: expiredFP, NotAfter: time.Date(2026, 9, 17, 18, 27, 56, 0, time.UTC)},
		},
	}
	diagnosis := inferTLSValidationDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if diagnosis.PrimaryCode != tlsCauseExpiredLeaf {
		t.Fatalf("primary = %q, want expired leaf", diagnosis.PrimaryCode)
	}
	if investigation.ProofKind != "mixed" {
		t.Fatalf("leftover expired leaf proof kind = %q, want mixed: %#v", investigation.ProofKind, investigation)
	}
	assertClaimThenEvidence(t, investigation.Proof)
	assertClaimThenEvidence(t, investigation.Inference)
	if !hasProofLabel(investigation.Proof, "Name binding") {
		t.Fatalf("leftover expired leaf omitted the hostname-mismatch measurement: %#v", investigation.Proof)
	}
	if !proofEvidenceContains(investigation.Proof, "162.244.81.139") || !proofEvidenceContains(investigation.Proof, "2026-09-17T18:27:56Z") {
		t.Fatalf("leftover expired leaf did not cite the expired endpoint: %#v", investigation.Proof)
	}
	if len(investigation.Inference) == 0 || !containsFold(investigation.Inference[0].Claim, "different certificate") {
		t.Fatalf("leftover reading was not inferred from fingerprint disagreement: %#v", investigation.Inference)
	}
	if !proofEvidenceContains(investigation.Inference, currentFP[:12]) && !proofEvidenceContains(investigation.Inference, "current_fingerprint="+currentFP) {
		t.Fatalf("leftover inference did not cite the still-valid current leaf: %#v", investigation.Inference)
	}
	if containsFold(investigation.Cause, "insufficient longitudinal") || containsFold(investigation.WhyProblem, "local trust failures") {
		t.Fatalf("leftover expired leaf reused the generic TLS template: %#v", investigation)
	}
}

func TestHostnameMismatchProofCitesVerifyHostnameDetail(t *testing.T) {
	checkedAt := time.Date(2026, 9, 19, 2, 19, 31, 0, time.UTC)
	fp := "c20bf20961097fd25862aeedbc3258c16305240606d67256b4b90fd1251c821d"
	findings, _ := json.Marshal([]models.TLSFinding{{
		Code:        "hostname_mismatch",
		Detail:      "x509: certificate is valid for *.yun300.cn, yun300.cn, not 027oa.cn",
		IPAddress:   "16.163.201.39",
		Fingerprint: fp,
	}})
	item := models.Anomaly{Domain: "027oa.cn", Type: "hostname_mismatch", DetectedAt: checkedAt}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:       "027oa.cn",
			TLSFindings:  string(findings),
			TLSCheckedAt: &checkedAt,
		},
	}
	diagnosis := inferTLSValidationDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if diagnosis.PrimaryCode != tlsCauseNameMismatch {
		t.Fatalf("primary = %q, want name mismatch", diagnosis.PrimaryCode)
	}
	assertClaimThenEvidence(t, investigation.Proof)
	if !proofEvidenceContains(investigation.Proof, "16.163.201.39") || !proofEvidenceContains(investigation.Proof, "*.yun300.cn") {
		t.Fatalf("name-mismatch proof did not cite address and VerifyHostname detail: %#v", investigation.Proof)
	}
	if containsFold(investigation.Cause, "expired") && !containsFold(investigation.Problem, "not valid for 027oa.cn") {
		t.Fatalf("name mismatch was explained as expiry: %#v", investigation)
	}
	item.FindingClass = findingClassOf(diagnosis)
	item.Diagnosis = &diagnosis
	if !isIssueRegisterFinding(item) {
		t.Fatal("a site name whose leaf is issued for a different name must stay on the issue register")
	}
}

func TestHostnameMismatchProofShowsSNIBindingEvidence(t *testing.T) {
	checkedAt := time.Date(2026, 9, 20, 2, 19, 31, 0, time.UTC)
	fp := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	findings, _ := json.Marshal([]models.TLSFinding{{
		Code:        "hostname_mismatch",
		Detail:      "x509: certificate is valid for *.platform.example, not requested.example",
		IPAddress:   "192.0.2.10",
		Fingerprint: fp,
	}})
	probes, _ := json.Marshal([]models.EndpointProbe{{
		IPAddress: "192.0.2.10", RequestedSNI: "requested.example", Success: true, Fingerprint: fp, CoversRequestedName: false,
		SelectionAnalysis: &models.EndpointSelectionAnalysis{
			RequestedSNI: "requested.example", SelectedFingerprint: fp, DefaultFingerprint: fp,
			SelectedCoversRequestedName: false, DefaultCoversRequestedName: false,
			Interpretation: "same_default_certificate_name_mismatch",
		},
	}})
	item := models.Anomaly{Domain: "requested.example", Type: "hostname_mismatch", DetectedAt: checkedAt}
	context := diagnosisContext{
		state:        &models.DomainCertificate{Domain: "requested.example", TLSFindings: string(findings), TLSCheckedAt: &checkedAt},
		observations: []models.CertObservation{{ObservationType: "hostname_mismatch", ObservedAt: checkedAt, EndpointProbes: string(probes)}},
	}
	diagnosis := inferTLSValidationDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if !hasProofLabel(investigation.Proof, "SNI selection control") {
		t.Fatalf("missing SNI selection proof: %#v", investigation.Proof)
	}
	if !proofEvidenceContains(investigation.Proof, "selected_covers_requested_name=false") || !proofEvidenceContains(investigation.Proof, "same_default_certificate_name_mismatch") {
		t.Fatalf("SNI selection evidence missing: %#v", investigation.Proof)
	}
}

func TestNonHTTPSIdentityNameMismatchIsWithdrawn(t *testing.T) {
	checkedAt := time.Date(2026, 9, 19, 2, 19, 31, 0, time.UTC)
	cases := []struct {
		domain string
		detail string
		want   string
	}{
		{
			domain: "0.pool.ntp.org",
			detail: "x509: certificate is valid for galleonsupport.com, not 0.pool.ntp.org",
			want:   "NTP pool alias",
		},
		{
			domain: "0-courier.push.apple.com",
			detail: "x509: certificate is valid for courier.push.apple.com, not 0-courier.push.apple.com",
			want:   "Apple Push",
		},
		{
			domain: "1036149.sched.ssp-dk.tdnsstic1.cn",
			detail: "x509: certificate is valid for *.cdn.myqcloud.com, not 1036149.sched.ssp-dk.tdnsstic1.cn",
			want:   "CDN or DNS delivery alias",
		},
	}
	for _, test := range cases {
		t.Run(test.domain, func(t *testing.T) {
			findings, _ := json.Marshal([]models.TLSFinding{{
				Code:        "hostname_mismatch",
				Detail:      test.detail,
				IPAddress:   "192.0.2.1",
				Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			}})
			item := models.Anomaly{Domain: test.domain, Type: "hostname_mismatch", DetectedAt: checkedAt}
			context := diagnosisContext{
				state: &models.DomainCertificate{Domain: test.domain, TLSFindings: string(findings), TLSCheckedAt: &checkedAt},
			}
			diagnosis := inferTLSValidationDiagnosis(item, context)
			if diagnosis.PrimaryCode != tlsCauseNonHTTPSIdentity {
				t.Fatalf("primary = %q, want %s", diagnosis.PrimaryCode, tlsCauseNonHTTPSIdentity)
			}
			if diagnosis.BenignExplanation == "" || !containsFold(diagnosis.BenignExplanation, test.want) {
				t.Fatalf("benign explanation = %q, want %q", diagnosis.BenignExplanation, test.want)
			}
			if findingClassOf(diagnosis) != models.FindingExpected {
				t.Fatalf("finding class = %q, want expected", findingClassOf(diagnosis))
			}
			item.FindingClass = findingClassOf(diagnosis)
			item.Diagnosis = &diagnosis
			applyDiagnosisToFinding(&item, &diagnosis)
			if isIssueRegisterFinding(item) {
				t.Fatalf("%s must not appear on the issue register: %#v", test.domain, item)
			}
		})
	}
}

func TestIncompleteProbeStaysUnestablished(t *testing.T) {
	checkedAt := time.Date(2026, 9, 19, 2, 19, 31, 0, time.UTC)
	findings, _ := json.Marshal([]models.TLSFinding{{
		Code:      "endpoint_probe_inconclusive",
		Detail:    "Additional endpoint probe did not obtain a certificate: TLS handshake failed: EOF",
		IPAddress: "129.250.35.251",
	}})
	item := models.Anomaly{Domain: "pool.example", Type: "endpoint_probe_inconclusive", DetectedAt: checkedAt}
	context := diagnosisContext{
		state: &models.DomainCertificate{Domain: "pool.example", TLSFindings: string(findings), TLSCheckedAt: &checkedAt},
	}
	diagnosis := inferTLSValidationDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if diagnosis.PrimaryCode != tlsCauseProbeIncomplete || diagnosis.CauseStatus != "unestablished" {
		t.Fatalf("incomplete probe = %#v, want unestablished", diagnosis)
	}
	if findingClassOf(diagnosis) != models.FindingInsufficient {
		t.Fatalf("incomplete probe class = %q, want insufficient", findingClassOf(diagnosis))
	}
	assertClaimThenEvidence(t, investigation.Proof)
	assertClaimThenEvidence(t, investigation.Inference)
	if !proofEvidenceContains(investigation.Proof, "129.250.35.251") || !proofEvidenceContains(investigation.Proof, "EOF") {
		t.Fatalf("incomplete probe did not cite the failed address: %#v", investigation.Proof)
	}
}

func TestSeedTLSValidationAnomalyKeepsNotAfterEvidence(t *testing.T) {
	checkedAt := time.Date(2026, 9, 19, 2, 18, 41, 0, time.UTC)
	fp := "e47ab2ca23c2bc24b3ada7ea4252cf08222077a13a2568ded835651561aca8c8"
	rows := []models.TLSFinding{{
		Code:        "expired_endpoint",
		Detail:      "certificate NotAfter=2026-03-22T15:17:26Z",
		IPAddress:   "47.108.214.201",
		Fingerprint: fp,
	}}
	encoded, _ := json.Marshal(rows)
	dc := models.DomainCertificate{
		Domain:             "00yuyin.com",
		CurrentFingerprint: fp,
		TLSFindings:        string(encoded),
		TLSCheckedAt:       &checkedAt,
		CurrentCertificate: &models.Certificate{Fingerprint: fp, NotAfter: time.Date(2026, 3, 22, 15, 17, 26, 0, time.UTC)},
	}
	item := seedTLSValidationAnomaly(dc, "expired_endpoint", rows)
	if item.Type != "expired_endpoint" {
		t.Fatalf("type = %q", item.Type)
	}
	if containsFold(item.Reason, "named check") || containsFold(item.Description, "Active TLS validation") {
		t.Fatalf("seed kept the generic TLS template: %#v", item)
	}
	joined := strings.Join(item.ConfirmedEvidence, " ")
	if !strings.Contains(joined, "47.108.214.201") || !strings.Contains(joined, "2026-03-22T15:17:26Z") {
		t.Fatalf("seed evidence omitted IP/NotAfter: %#v", item.ConfirmedEvidence)
	}
}
