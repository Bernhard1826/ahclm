package database

import (
	"ahclm/internal/models"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var auditBase = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

func auditFP(s string) string        { return strings.Repeat(s, 64) }
func auditJSON(v interface{}) string { b, _ := json.Marshal(v); return string(b) }

func TestCodeAuditReversedCausalSequence(t *testing.T) {
	ip := "23.185.0.2"
	es := []models.InternalEvidenceEvent{
		{Domain: "yale.edu", EventType: InternalEventHostnameBinding, SourceSystem: "synthetic", SourceRecordID: "1", CorrelationID: "unrelated-1", IPAddress: ip, Status: "applied", OccurredAt: auditBase.Add(48 * time.Hour)},
		{Domain: "yale.edu", EventType: InternalEventEdgePublish, SourceSystem: "synthetic", SourceRecordID: "2", CorrelationID: "unrelated-2", IPAddress: ip, Status: "succeeded", OccurredAt: auditBase.Add(24 * time.Hour)},
		{Domain: "yale.edu", EventType: InternalEventEdgeServeCheck, SourceSystem: "synthetic", SourceRecordID: "3", CorrelationID: "unrelated-3", IPAddress: ip, Status: "mismatch", OccurredAt: auditBase},
	}
	got := SummarizeInternalEvidenceForContext(es, "hostname_mismatch", nil, []models.CertObservation{{IPAddress: ip, ObservedAt: auditBase}}, nil)
	if got.Status == "complete" {
		t.Errorf("reverse time + unrelated IDs accepted: status=%s cause=%s confidence=%s", got.Status, got.RootCauseCode, got.Confidence)
	}
}

func TestCodeAuditUnrelatedEventSatisfiesCausalCount(t *testing.T) {
	es := []models.InternalEvidenceEvent{
		{Domain: "example.com", EventType: InternalEventHostnameBinding, SourceSystem: "synthetic", SourceRecordID: "wrong-endpoint", IPAddress: "8.8.8.8", Status: "missing", OccurredAt: auditBase},
		{Domain: "example.com", EventType: InternalEventKeyGenerated, SourceSystem: "synthetic", SourceRecordID: "unrelated-key", IPAddress: "1.1.1.1", Status: "succeeded", OccurredAt: auditBase},
	}
	got := SummarizeInternalEvidenceForContext(es, "hostname_mismatch", nil, []models.CertObservation{{IPAddress: "1.1.1.1", ObservedAt: auditBase}}, nil)
	if got.Status == "complete" {
		t.Errorf("unmatched binding supplied cause; unrelated key event supplied match count: %+v", got)
	}
}

func TestCodeAuditFailedDeploymentIsNotExactDeployment(t *testing.T) {
	fp := auditFP("a")
	got := BuildPublicKeyDeploymentCycle("example.com", []models.Certificate{{Fingerprint: fp, NotBefore: auditBase, FirstSeenAt: auditBase.Add(time.Hour)}}, nil, nil, []models.InternalEvidenceEvent{{Domain: "example.com", SourceSystem: "synthetic", SourceRecordID: "failed", EventType: InternalEventDeployment, Fingerprint: fp, Status: "failed", OccurredAt: auditBase.Add(time.Minute)}})
	if got.Metrics.FirstDeployedAt != nil {
		t.Errorf("failed deployment became exact successful deployment time: %v", got.Metrics.FirstDeployedAt)
	}
}

func TestCodeAuditExactIssuanceIntervalUsesActualIssuance(t *testing.T) {
	fp := auditFP("a")
	got := BuildPublicKeyDeploymentCycle("example.com", []models.Certificate{{Fingerprint: fp, NotBefore: auditBase, FirstSeenAt: auditBase.Add(time.Hour)}}, nil, nil, []models.InternalEvidenceEvent{{Domain: "example.com", SourceSystem: "synthetic", SourceRecordID: "issued", EventType: InternalEventCertificateIssued, Fingerprint: fp, Status: "succeeded", OccurredAt: auditBase.Add(30 * time.Minute)}})
	if got.Metrics.IssuanceToFirstPublicSeconds == nil || *got.Metrics.IssuanceToFirstPublicSeconds != 1800 {
		t.Errorf("exact issuance at +30min, first public +60min: got %v seconds (value=%v), want 1800", got.Metrics.IssuanceToFirstPublicSeconds, *got.Metrics.IssuanceToFirstPublicSeconds)
	}
}

func TestCodeAuditLastSeenMustIncludeUnchangedRounds(t *testing.T) {
	a, b := auditFP("a"), auditFP("b")
	cs := []models.Certificate{{Fingerprint: a, NotBefore: auditBase.Add(-time.Hour), FirstSeenAt: auditBase}, {Fingerprint: b, NotBefore: auditBase, FirstSeenAt: auditBase.Add(30 * time.Minute)}}
	var ss []models.MeasurementSnapshot
	for i, fp := range []string{a, a, b} {
		ss = append(ss, models.MeasurementSnapshot{ObservedAt: auditBase.Add(time.Duration((i+1)*10) * time.Minute), EndpointProbesJSON: auditJSON([]models.EndpointProbe{{IPAddress: "1.1.1.1", Success: true, Fingerprint: fp}}), SuccessfulEndpointCount: 1, FingerprintCount: 1})
	}
	obs := []models.CertObservation{{ObservationType: models.ObsChange, ObservedAt: auditBase.Add(30 * time.Minute), Fingerprint: b, PreviousFingerprint: a, IPAddress: "1.1.1.1"}}
	got := BuildPublicKeyDeploymentCycle("example.com", cs, obs, ss, nil)
	if got.Metrics.SuccessorToPreviousRetirementSec == nil || *got.Metrics.SuccessorToPreviousRetirementSec != 600 {
		t.Errorf("A seen at +10,+20min; B at +30min: got %v seconds (value=%v), want 600", got.Metrics.SuccessorToPreviousRetirementSec, *got.Metrics.SuccessorToPreviousRetirementSec)
	}
}

func TestCodeAuditCurrentLeafMustFollowObservation(t *testing.T) {
	a, b := auditFP("a"), auditFP("b")
	cs := []models.Certificate{{Fingerprint: a, NotBefore: auditBase.Add(-time.Hour), FirstSeenAt: auditBase}, {Fingerprint: b, NotBefore: auditBase, FirstSeenAt: auditBase.Add(time.Minute)}}
	obs := []models.CertObservation{{ObservationType: models.ObsChange, ObservedAt: auditBase.Add(time.Minute), PreviousFingerprint: a, Fingerprint: b, IPAddress: "1.1.1.1"}, {ObservationType: models.ObsChange, ObservedAt: auditBase.Add(2 * time.Minute), PreviousFingerprint: b, Fingerprint: a, IPAddress: "1.1.1.1"}}
	got := BuildPublicKeyDeploymentCycle("example.com", cs, obs, nil, nil)
	if got.CurrentFingerprint != a {
		t.Errorf("latest observed rollback leaf=A; reported current=%s", got.CurrentFingerprint)
	}
}

func TestCodeAuditInfrastructureMustNotHideExpiry(t *testing.T) {
	for _, d := range []string{"google.cn", "example.cloudfront.net"} {
		x := models.Anomaly{Domain: d, Type: "expired_endpoint", FindingClass: models.FindingIncident}
		if !isSummaryIssueRegisterFinding(&x) {
			t.Errorf("confirmed expired_endpoint silently removed for %s", d)
		}
	}
}

func TestCodeAuditPartialCTCannotDisproveObservedReplacements(t *testing.T) {
	at := auditBase.Add(-time.Hour)
	ss := []models.MeasurementSnapshot{{ObservedAt: auditBase, CTJSON: auditJSON([]models.CTObservation{{Source: "crt.sh", SerialNumber: "01", NotBefore: &at}})}}
	for i := 0; i < 9; i++ {
		ss = append(ss, models.MeasurementSnapshot{ObservedAt: auditBase, ErrorsJSON: `["CT fetch failed"]`})
	}
	coverage, _, count, status, note := analyzeCTCorroboration(ss, models.ChurnShape{ChangeEvents: 6, EffectiveReplacements: 6}, 24*time.Hour)
	if status == models.CTContradicted {
		t.Errorf("partial CT coverage=%v entries=%d conclusively contradicts six observed replacements: %s", coverage, count, note)
	}
}

func TestCodeAuditAmbiguousHistoricalAddressCannotBecomeProof(t *testing.T) {
	a, b := auditFP("a"), auditFP("b")
	ss := []models.MeasurementSnapshot{{ObservedAt: auditBase, EndpointFingerprintsJSON: auditJSON(map[string]string{"1.1.1.1": a, "8.8.8.8": a})}}
	ips := map[string]int{}
	for i := 0; i < 200; i++ {
		obs := []models.CertObservation{{ObservedAt: auditBase, IPAddress: "1.1.1.1", Fingerprint: b, PreviousFingerprint: a}}
		recoverChangeEndpoints(obs, ss)
		ips[obs[0].PreviousIPAddress]++
	}
	if len(ips) != 1 || ips[""] != 200 {
		t.Errorf("ambiguous predecessors must remain unknown: %v", ips)
	}
}

func TestCodeAuditValidCausalSequenceStillCompletes(t *testing.T) {
	es := []models.InternalEvidenceEvent{
		{Domain: "example.com", EventType: InternalEventHostnameBinding, SourceSystem: "operator", CorrelationID: "release-1", IPAddress: "1.1.1.1", Status: "applied", OccurredAt: auditBase},
		{Domain: "example.com", EventType: InternalEventEdgePublish, SourceSystem: "operator", CorrelationID: "release-1", IPAddress: "1.1.1.1", Status: "succeeded", OccurredAt: auditBase.Add(time.Minute)},
		{Domain: "example.com", EventType: InternalEventEdgeServeCheck, SourceSystem: "operator", CorrelationID: "release-1", IPAddress: "1.1.1.1", Status: "mismatch", OccurredAt: auditBase.Add(2 * time.Minute)},
	}
	obs := []models.CertObservation{{Domain: "example.com", IPAddress: "1.1.1.1", ObservedAt: auditBase.Add(3 * time.Minute)}}
	got := SummarizeInternalEvidenceForContext(es, "hostname_mismatch", nil, obs, nil)
	if got.Status != "complete" || got.RootCauseCode != "edge_runtime_or_cache_stale" {
		t.Fatalf("valid causal trace rejected: %+v", got)
	}
	es[0].IPAddress = "8.8.8.8"
	got = SummarizeInternalEvidenceForContext(es, "hostname_mismatch", nil, obs, nil)
	if got.Status == "complete" {
		t.Fatal("shared correlation ID overrode a contradictory endpoint")
	}
}

func TestCodeAuditUnverifiedHistoricalSCTCannotRaiseConfidence(t *testing.T) {
	snap := models.MeasurementSnapshot{SCTJSON: auditJSON([]models.SCTObservation{{LogID: "aa", Inclusion: models.SCTInclusionProven}})}
	_, _, _, _, _, included, _ := analyzeSCTCorroboration([]models.MeasurementSnapshot{snap})
	if included != 0 {
		t.Fatal("legacy unverified tree head treated as proof")
	}
	c := &models.EvidenceCorroboration{SCTPresented: true, EndpointCoverage: 0.8}
	if confidenceCeiling(c, false, false) != "low" {
		t.Fatal("unverified SCT raised confidence")
	}
}

func TestCodeAuditSupersededBindingFailureDoesNotSupplyCurrentCause(t *testing.T) {
	es := []models.InternalEvidenceEvent{
		{ID: 1, EventType: InternalEventHostnameBinding, SourceSystem: "controller", IPAddress: "1.1.1.1", CorrelationID: "run", Status: "failed", OccurredAt: auditBase},
		{ID: 2, EventType: InternalEventHostnameBinding, SourceSystem: "controller", IPAddress: "1.1.1.1", CorrelationID: "run", Status: "applied", OccurredAt: auditBase.Add(time.Minute)},
		{ID: 3, EventType: InternalEventEdgePublish, SourceSystem: "edge", IPAddress: "1.1.1.1", CorrelationID: "run", Status: "succeeded", OccurredAt: auditBase.Add(2 * time.Minute)},
		{ID: 4, EventType: InternalEventEdgeServeCheck, SourceSystem: "edge", IPAddress: "1.1.1.1", CorrelationID: "run", Status: "mismatch", OccurredAt: auditBase.Add(3 * time.Minute)},
	}
	got := SummarizeInternalEvidenceForContext(es, "hostname_mismatch", nil, []models.CertObservation{{IPAddress: "1.1.1.1", ObservedAt: auditBase.Add(4 * time.Minute)}}, nil)
	if got.RootCauseCode != "edge_runtime_or_cache_stale" {
		t.Fatalf("superseded failure supplied cause: %+v", got)
	}
	for _, line := range got.Evidence {
		if strings.Contains(line, "event#1 ") {
			t.Fatal("superseded event attributed as support")
		}
	}
}

func TestCodeAuditAmbiguousAddressCannotFallBackToPreviousRow(t *testing.T) {
	at := auditBase
	obs := []models.CertObservation{
		{ObservedAt: at.Add(-time.Minute), IPAddress: "1.1.1.1", Fingerprint: auditFP("a")},
		{ObservedAt: at, IPAddress: "1.1.1.1", Fingerprint: auditFP("b"), PreviousFingerprint: auditFP("a")},
	}
	snapshots := []models.MeasurementSnapshot{{ObservedAt: at, EndpointFingerprintsJSON: auditJSON(map[string]string{"1.1.1.1": auditFP("a"), "8.8.8.8": auditFP("a")})}}
	recoverChangeEndpoints(obs, snapshots)
	if endpointRelation(obs, 1) != endpointUnknown {
		t.Fatal("ambiguity overwritten by previous-row fallback")
	}
}
