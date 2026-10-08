package analysis

import (
	"encoding/json"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestMechanismRanksWrongNameSelectionAbovePoolResidue(t *testing.T) {
	probes := []models.EndpointProbe{{
		IPAddress: "23.185.0.2", RequestedSNI: "yale.edu", Success: true, Fingerprint: "pantheon",
		CoversRequestedName: false,
		SelectionAnalysis: &models.EndpointSelectionAnalysis{
			SelectedFingerprint: "pantheon", CertificateChanged: false, SelectedCoversRequestedName: false,
		},
	}, {
		IPAddress: "23.185.0.4", RequestedSNI: "yale.edu", Success: true, Fingerprint: "yale",
		CoversRequestedName: true,
		SelectionAnalysis: &models.EndpointSelectionAnalysis{
			SelectedFingerprint: "yale", DefaultFingerprint: "default", CertificateChanged: true, SelectedCoversRequestedName: true,
		},
	}}
	report := InferMechanisms("yale.edu", nil, nil, probes)
	if report.Status != "supported" || report.MostSupported != MechanismWrongName {
		t.Fatalf("report = %+v, want M1 supported", report)
	}
	if score(report, MechanismCertificatePool) != 0 || score(report, MechanismPoolResidue) != 0 {
		t.Fatalf("unrelated mechanisms received points: %+v", report.Scores)
	}
	if len(report.Matrix) != 10 || len(report.Columns) != 7 {
		t.Fatalf("matrix = %d rows, %d columns", len(report.Matrix), len(report.Columns))
	}
	if len(report.Missing) == 0 {
		t.Fatal("name mismatch omitted the control-plane gap")
	}
}

func TestMechanismConfirmsSameKeyAndRejectsItWhenKeysDiffer(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	same := InferMechanisms("1688.com", nil, []models.CertObservation{{
		ObservedAt: base, ObservationType: models.ObsChange, IPAddress: "192.0.2.1",
		PreviousFingerprint: "old", Fingerprint: "new", PreviousSPKIFingerprint: "key", SPKIFingerprint: "key",
	}}, nil)
	if same.MostSupported != MechanismSameKey {
		t.Fatalf("same-key report = %+v", same)
	}
	different := InferMechanisms("example.com", nil, []models.CertObservation{{
		ObservedAt: base, ObservationType: models.ObsChange, IPAddress: "192.0.2.1",
		PreviousFingerprint: "old", Fingerprint: "new", PreviousSPKIFingerprint: "key-a", SPKIFingerprint: "key-b",
	}}, nil)
	if score(different, MechanismSameKey) >= 0 {
		t.Fatalf("different SPKI did not contradict same-key reissue: %+v", different.Scores)
	}
}

func TestMechanismPrefersPreissuedStockWhenAgeAndForwardSequenceAgree(t *testing.T) {
	start := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	certs := []models.Certificate{
		storedLeaf("b", "key-b", start.Add(-20*24*time.Hour), 90, []string{"example.com"}),
		storedLeaf("c", "key-c", start.Add(-18*24*time.Hour), 90, []string{"example.com"}),
		storedLeaf("d", "key-d", start.Add(-16*24*time.Hour), 90, []string{"example.com"}),
	}
	observations := []models.CertObservation{
		change("192.0.2.1", "a", "b", "key-a", "key-b", start),
		change("192.0.2.1", "b", "c", "key-b", "key-c", start.Add(time.Hour)),
		change("192.0.2.1", "c", "d", "key-c", "key-d", start.Add(2*time.Hour)),
	}
	report := InferMechanisms("example.com", certs, observations, nil)
	if report.Status != "supported" || report.MostSupported != MechanismPreissued {
		t.Fatalf("report = %+v, scores %+v", report.Status, report.Scores)
	}
}

func TestMechanismKeepsPoolAndRollbackTogetherWhenAnOlderLeafReturns(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	certs := []models.Certificate{
		storedLeaf("a", "key-a", start, 90, []string{"example.com"}),
		storedLeaf("b", "key-b", start.Add(5*24*time.Hour), 90, []string{"example.com"}),
	}
	observations := []models.CertObservation{
		change("192.0.2.1", "a", "b", "", "", start.Add(10*24*time.Hour)),
		change("192.0.2.1", "b", "a", "", "", start.Add(11*24*time.Hour)),
	}
	report := InferMechanisms("example.com", certs, observations, nil)
	if report.Status != "ambiguous" {
		t.Fatalf("status = %s, want both pool and rollback kept visible", report.Status)
	}
	if score(report, MechanismRolloutRace) < 2 || score(report, MechanismCertificatePool) < 2 {
		t.Fatalf("scores = %+v", report.Scores)
	}
}

func TestMechanismRecordsSANCounterexample(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	certs := []models.Certificate{
		storedLeaf("a", "key-a", start, 90, []string{"example.com"}),
		storedLeaf("b", "key-b", start.Add(time.Hour), 90, []string{"example.com", "preview.example.com"}),
		storedLeaf("c", "key-c", start.Add(2*time.Hour), 90, []string{"example.com", "preview.example.com"}),
	}
	observations := []models.CertObservation{
		change("192.0.2.1", "a", "b", "key-a", "key-b", start.Add(2*time.Hour)),
		change("192.0.2.1", "b", "c", "key-b", "key-c", start.Add(3*time.Hour)),
	}
	report := InferMechanisms("example.com", certs, observations, nil)
	if len(report.Counterexamples) != 1 {
		t.Fatalf("counterexamples = %+v", report.Counterexamples)
	}
}

func TestMechanismStaysInsufficientWithoutFeatures(t *testing.T) {
	report := InferMechanisms("example.com", nil, nil, nil)
	if report.Status != "insufficient" || report.MostSupported != "" {
		t.Fatalf("report = %+v", report)
	}
}

func score(report MechanismReport, id string) int {
	for _, item := range report.Scores {
		if item.ID == id {
			return item.Score
		}
	}
	return 0
}

func storedLeaf(fingerprint, spki string, notBefore time.Time, days int, sans []string) models.Certificate {
	encoded, _ := json.Marshal(sans)
	return models.Certificate{
		Fingerprint: fingerprint, SPKIFingerprint: spki, NotBefore: notBefore,
		NotAfter: notBefore.Add(time.Duration(days) * 24 * time.Hour), ValidityDays: days, SANs: string(encoded),
	}
}

func change(ip, previous, current, previousSPKI, spki string, at time.Time) models.CertObservation {
	return models.CertObservation{
		ObservedAt: at, ObservationType: models.ObsChange, IPAddress: ip,
		PreviousFingerprint: previous, Fingerprint: current,
		PreviousSPKIFingerprint: previousSPKI, SPKIFingerprint: spki,
	}
}
