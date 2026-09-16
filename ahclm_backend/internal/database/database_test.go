package database

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestAnomalyCauseIsMutuallyExclusive(t *testing.T) {
	confirmed := withAnomalyCause(models.Anomaly{}, anomalyCause{
		confirmedReason:   "direct observation",
		confirmedEvidence: []string{"fact=true"},
		inferredReason:    "interpretation",
		inferredEvidence:  []string{"inference=possible"},
	})
	if confirmed.CauseClassification != "confirmed" || confirmed.InferredReason != "" || len(confirmed.InferredEvidence) != 0 {
		t.Fatalf("confirmed cause was not exclusive: %#v", confirmed)
	}
	inferred := withAnomalyCause(models.Anomaly{}, anomalyCause{
		inferredReason:   "interpretation",
		inferredEvidence: []string{"inference=possible"},
	})
	if inferred.CauseClassification != "inferred" || inferred.ConfirmedReason != "" || len(inferred.ConfirmedEvidence) != 0 {
		t.Fatalf("inferred cause was not exclusive: %#v", inferred)
	}
}

func TestInferChurnDiagnosisFindsCadencedAutomatedRenewal(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changes := make([]models.CertObservation, 0, 4)
	certs := make(map[string]models.Certificate)
	for i := 0; i < 4; i++ {
		oldFP := "old-" + string(rune('a'+i))
		newFP := "new-" + string(rune('a'+i))
		changes = append(changes, models.CertObservation{ObservationType: models.ObsChange, ObservedAt: t0.Add(time.Duration(i*30*24) * time.Hour), Fingerprint: newFP, PreviousFingerprint: oldFP, PreviousSPKIFingerprint: "spki-stable", SPKIFingerprint: "spki-stable", DaysUntilExpiry: 20})
		certs[oldFP] = models.Certificate{Fingerprint: oldFP, Issuer: "CA", IssuerCN: "CA", NotBefore: t0, NotAfter: t0.Add(90 * 24 * time.Hour)}
		certs[newFP] = models.Certificate{Fingerprint: newFP, Issuer: "CA", IssuerCN: "CA", NotBefore: t0, NotAfter: t0.Add(90 * 24 * time.Hour)}
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: changes, certificates: certs})
	if diagnosis.PrimaryCode != "automated_renewal_policy" {
		t.Fatalf("primary diagnosis = %q, want automated renewal: %#v", diagnosis.PrimaryCode, diagnosis)
	}
	if len(diagnosis.Hypotheses) < 3 || diagnosis.Hypotheses[0].Score < 0.6 {
		t.Fatalf("automated renewal support too weak: %#v", diagnosis.Hypotheses)
	}
}

func TestInferChurnDiagnosisFindsKeyRotation(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changes := []models.CertObservation{
		{ObservationType: models.ObsChange, ObservedAt: t0, Fingerprint: "b", PreviousFingerprint: "a", PreviousSPKIFingerprint: "spki-a", SPKIFingerprint: "spki-b", DaysUntilExpiry: 180},
		{ObservationType: models.ObsChange, ObservedAt: t0.Add(3 * 24 * time.Hour), Fingerprint: "c", PreviousFingerprint: "b", PreviousSPKIFingerprint: "spki-b", SPKIFingerprint: "spki-c", DaysUntilExpiry: 160},
		{ObservationType: models.ObsChange, ObservedAt: t0.Add(17 * 24 * time.Hour), Fingerprint: "d", PreviousFingerprint: "c", PreviousSPKIFingerprint: "spki-c", SPKIFingerprint: "spki-d", DaysUntilExpiry: 140},
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: changes})
	if diagnosis.PrimaryCode != "key_security_rotation" {
		t.Fatalf("primary diagnosis = %q, want key rotation: %#v", diagnosis.PrimaryCode, diagnosis)
	}
}

func TestInferChurnDiagnosisRequiresLongitudinalEvidence(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, observations := range []([]models.CertObservation){
		nil,
		{{ObservationType: models.ObsChange, ObservedAt: t0, Fingerprint: "new", PreviousFingerprint: "old"}},
	} {
		diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: observations})
		if diagnosis.PrimaryCode != "insufficient_longitudinal_evidence" || diagnosis.Confidence != "low" {
			t.Fatalf("diagnosis = %#v, want a low-confidence evidence gate", diagnosis)
		}
	}
}

func TestEvidenceSignalsDetectPolicyAndEdgeChanges(t *testing.T) {
	snapshots := []models.MeasurementSnapshot{
		{CAAJSON: `[{"flag":0,"tag":"issue","value":"old-ca"}]`, HTTPJSON: `{"status_code":200,"server":"edge-a"}`},
		{CAAJSON: `[{"flag":0,"tag":"issue","value":"new-ca"}]`, HTTPJSON: `{"status_code":200,"server":"edge-b"}`},
	}
	caaCoverage, caaChanges := caaSignals(snapshots)
	httpCoverage, httpChanges := httpSignals(snapshots)
	if caaCoverage != 1 || caaChanges != 1 || httpCoverage != 1 || httpChanges != 1 {
		t.Fatalf("signals = caa %.2f/%.2f http %.2f/%.2f, want complete changing signals", caaCoverage, caaChanges, httpCoverage, httpChanges)
	}
}

func TestInferTopologyDiagnosisSuppressesCDNFalsePositive(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	endpointMap := mapJSON(map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"})
	snapshots := []models.MeasurementSnapshot{
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
	}
	diagnosis := inferTopologyDiagnosis(models.Anomaly{Type: models.ObsDeploymentFailure}, diagnosisContext{snapshots: snapshots})
	if diagnosis.PrimaryCode != "intentional_cdn_diversity" {
		t.Fatalf("primary diagnosis = %q, want intentional CDN diversity: %#v", diagnosis.PrimaryCode, diagnosis)
	}
}

func TestNormalizedFinishTimeClampsClockReversal(t *testing.T) {
	started := time.Date(2026, time.August, 3, 20, 0, 1, 0, time.UTC)
	finished := started.Add(-time.Millisecond)
	if got := normalizedFinishTime(&started, finished); !got.Equal(started) {
		t.Fatalf("finish time = %v, want %v", got, started)
	}
}

func TestNormalizedFinishTimePreservesValidFinish(t *testing.T) {
	started := time.Date(2026, time.August, 3, 20, 0, 1, 0, time.UTC)
	finished := started.Add(time.Second)
	if got := normalizedFinishTime(&started, finished); !got.Equal(finished) {
		t.Fatalf("finish time = %v, want %v", got, finished)
	}
}

func TestNormalizeTrancoRanksRejectsNonPositiveAndCanonicalizesHosts(t *testing.T) {
	ranked := normalizeTrancoRanks(map[string]int{
		"WWW.Example.com":  7,
		"example.com/path": 3,
		"zero.example":     0,
		"negative.example": -1,
		"outside.example":  models.TrancoTopLimit + 1,
	})
	if len(ranked) != 1 || ranked["example.com"] != 3 {
		t.Fatalf("normalized ranks = %#v, want only canonical example.com at rank 3", ranked)
	}
}

func TestTrancoPopulationBoundaryIsFixed(t *testing.T) {
	if models.TrancoTopLimit != 10000 {
		t.Fatalf("Tranco population limit = %d, want 10000", models.TrancoTopLimit)
	}
	for _, rank := range []int{0, -1, models.TrancoTopLimit + 1} {
		if rank >= 1 && rank <= models.TrancoTopLimit {
			t.Fatalf("rank %d unexpectedly falls inside the monitored range", rank)
		}
	}
}

func TestRegisterTrancoDomainsRejectsIncompleteRankSetBeforeDatabaseWrite(t *testing.T) {
	ranked := make(map[string]int, models.TrancoTopLimit)
	for rank := 1; rank <= models.TrancoTopLimit; rank++ {
		// Keep the row count at 10,000 while duplicating rank 9,999; rank
		// 10,000 is therefore missing and must fail the exact-list check.
		assignedRank := rank
		if rank == models.TrancoTopLimit {
			assignedRank = models.TrancoTopLimit - 1
		}
		ranked[fmt.Sprintf("rank-%05d.example", rank)] = assignedRank
	}
	if _, err := (&Database{}).RegisterTrancoDomains(ranked); err == nil {
		t.Fatal("incomplete Tranco rank set was accepted")
	}
}
