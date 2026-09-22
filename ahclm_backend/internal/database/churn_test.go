package database

import (
	"encoding/json"
	"testing"
	"time"

	"ahclm/internal/models"
)

func changeRow(at time.Time, previous, current, previousSPKI, spki, ip string) models.CertObservation {
	return models.CertObservation{
		ObservationType:         models.ObsChange,
		ObservedAt:              at,
		Fingerprint:             current,
		PreviousFingerprint:     previous,
		SPKIFingerprint:         spki,
		PreviousSPKIFingerprint: previousSPKI,
		IPAddress:               ip,
		DaysUntilExpiry:         40,
	}
}

// Two servers holding different certificates, sampled in turn, produce a long
// run of "changes" that never leaves a two-element set. A replaced certificate
// cannot come back, so the revisits falsify the renewal reading outright.
func TestChurnShapeDetectsAlternatingCertificatePool(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changes := make([]models.CertObservation, 0, 46)
	for index := 0; index < 46; index++ {
		previous, current := "leaf-a", "leaf-b"
		previousSPKI, spki := "spki-a", "spki-b"
		address := "192.0.2.2"
		if index%2 == 1 {
			previous, current = "leaf-b", "leaf-a"
			previousSPKI, spki = "spki-b", "spki-a"
			address = "192.0.2.1"
		}
		changes = append(changes, changeRow(t0.Add(time.Duration(index*6)*time.Hour), previous, current, previousSPKI, spki, address))
	}
	shape := analyzeChurnShape(changes, nil)
	if shape.Interpretation != models.ChurnSpatialMultiplexing {
		t.Fatalf("interpretation = %q, want spatial multiplexing: %#v", shape.Interpretation, shape)
	}
	if shape.DistinctLeaves != 2 {
		t.Fatalf("distinct leaves = %d, want 2", shape.DistinctLeaves)
	}
	if shape.EffectiveReplacements != 1 {
		t.Fatalf("effective replacements = %d, want 1 for a two-certificate pool", shape.EffectiveReplacements)
	}
	if shape.RevisitEvents != 44 || shape.AlternationEvents != 44 {
		t.Fatalf("revisit/alternation counts = %d/%d, want 44/44: %#v", shape.RevisitEvents, shape.AlternationEvents, shape)
	}
}

// The failure this analysis exists to prevent: alternating between two servers
// guarantees a same-key fraction of zero, which the old scoring turned into a
// high-confidence "public-key security rotation" verdict.
func TestInferChurnDiagnosisRejectsKeyRotationSamplingArtifact(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changes := make([]models.CertObservation, 0, 20)
	for index := 0; index < 20; index++ {
		previous, current := "leaf-a", "leaf-b"
		previousSPKI, spki := "spki-a", "spki-b"
		address := "192.0.2.2"
		if index%2 == 1 {
			previous, current = "leaf-b", "leaf-a"
			previousSPKI, spki = "spki-b", "spki-a"
			address = "192.0.2.1"
		}
		changes = append(changes, changeRow(t0.Add(time.Duration(index*6)*time.Hour), previous, current, previousSPKI, spki, address))
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: changes})
	if diagnosis.PrimaryCode == "key_security_rotation" {
		t.Fatalf("a sampling artifact was reported as key rotation: %#v", diagnosis)
	}
	if diagnosis.PrimaryCode != "concurrent_multi_certificate_pool" {
		t.Fatalf("primary diagnosis = %q, want a concurrently deployed pool", diagnosis.PrimaryCode)
	}
	if diagnosis.BenignExplanation == "" {
		t.Fatal("a pool that is not changing frequently must carry the explanation that withdraws the problem claim")
	}
	if diagnosis.ChurnShape == nil || diagnosis.ChurnShape.EffectiveReplacements != 1 {
		t.Fatalf("diagnosis did not report the replacement floor: %#v", diagnosis.ChurnShape)
	}
	for _, hypothesis := range diagnosis.Hypotheses {
		if hypothesis.Code == "key_security_rotation" {
			t.Fatalf("public-key change must not be scored as a cause: %#v", hypothesis)
		}
	}
}

// A round that sees the predecessor and the successor at once settles the
// question directly, without needing a long sequence to accumulate revisits.
func TestChurnShapeUsesConcurrentObservationAsProof(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	probes, _ := json.Marshal([]models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "leaf-a"},
		{IPAddress: "198.51.100.1", Success: true, Fingerprint: "leaf-b"},
	})
	changes := []models.CertObservation{
		changeRow(t0, "leaf-x", "leaf-a", "spki-x", "spki-a", "192.0.2.1"),
		func() models.CertObservation {
			row := changeRow(t0.Add(6*time.Hour), "leaf-a", "leaf-b", "spki-a", "spki-b", "198.51.100.1")
			row.EndpointProbes = string(probes)
			return row
		}(),
	}
	shape := analyzeChurnShape(changes, nil)
	if shape.CoexistenceProofs != 1 {
		t.Fatalf("coexistence proofs = %d, want 1: %#v", shape.CoexistenceProofs, shape)
	}
	if shape.Interpretation != models.ChurnSpatialMultiplexing {
		t.Fatalf("interpretation = %q, want spatial multiplexing on direct evidence", shape.Interpretation)
	}
}

// A monotone sequence measured from one endpoint is a genuine replacement
// history and must not be reclassified as a sampling artifact.
func TestChurnShapeKeepsMonotoneSameEndpointAsReplacement(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changes := []models.CertObservation{
		changeRow(t0, "leaf-0", "leaf-1", "spki-0", "spki-1", "192.0.2.1"),
		changeRow(t0.Add(30*24*time.Hour), "leaf-1", "leaf-2", "spki-1", "spki-2", "192.0.2.1"),
		changeRow(t0.Add(60*24*time.Hour), "leaf-2", "leaf-3", "spki-2", "spki-3", "192.0.2.1"),
	}
	shape := analyzeChurnShape(changes, nil)
	if shape.Interpretation != models.ChurnTemporalReplacement {
		t.Fatalf("interpretation = %q, want temporal replacement: %#v", shape.Interpretation, shape)
	}
	if shape.RevisitEvents != 0 || shape.SameEndpointChanges == 0 {
		t.Fatalf("monotone same-endpoint sequence was misread: %#v", shape)
	}
	if shape.EffectiveReplacements != 3 {
		t.Fatalf("effective replacements = %d, want 3", shape.EffectiveReplacements)
	}
}

// Short-lived certificates are replaced often by design. Normalizing by the
// certificate's own validity period is what separates that from real churn.
func TestInferChurnDiagnosisRecognizesShortLivedAutomation(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changes := make([]models.CertObservation, 0, 12)
	certs := make(map[string]models.Certificate)
	for index := 0; index < 12; index++ {
		previous := "leaf-" + string(rune('a'+index))
		current := "leaf-" + string(rune('b'+index))
		changes = append(changes, changeRow(t0.Add(time.Duration(index*48)*time.Hour), previous, current, "spki-shared", "spki-shared", "192.0.2.1"))
		certs[current] = models.Certificate{Fingerprint: current, Issuer: "CA", IssuerCN: "CA", ValidityDays: 6, NotBefore: t0, NotAfter: t0.Add(6 * 24 * time.Hour)}
		certs[previous] = certs[current]
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: changes, certificates: certs})
	if diagnosis.PrimaryCode != "short_lived_certificate_automation" {
		t.Fatalf("primary diagnosis = %q, want short-lived certificate automation: %#v", diagnosis.PrimaryCode, diagnosis)
	}
	if diagnosis.BenignExplanation == "" {
		t.Fatal("designed short-lived replacement must withdraw the problem claim")
	}
	if diagnosis.ChurnShape == nil || diagnosis.ChurnShape.MedianValidityDays != 6 {
		t.Fatalf("validity normalization was not applied: %#v", diagnosis.ChurnShape)
	}
}

// Certificate Transparency is the only independent record of issuance. When it
// logs far fewer issuances than the scan counted changes, the excess cannot be
// replacements.
func TestCTCorroborationContradictsInflatedChangeCount(t *testing.T) {
	observed := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	issued := observed.Add(-10 * 24 * time.Hour)
	entries, _ := json.Marshal([]models.CTObservation{
		{SHA256: "aaa", SerialNumber: "01", NotBefore: &issued},
		{SHA256: "bbb", SerialNumber: "02", NotBefore: &issued},
	})
	snapshots := []models.MeasurementSnapshot{{ObservedAt: observed, CTJSON: string(entries)}}
	shape := models.ChurnShape{ChangeEvents: 99, EffectiveReplacements: 1}
	_, _, issuances, status, note := analyzeCTCorroboration(snapshots, shape, 30*24*time.Hour)
	if issuances != 2 {
		t.Fatalf("issuances = %d, want 2 distinct serials", issuances)
	}
	if status != models.CTContradicted {
		t.Fatalf("status = %q, want the count to be contradicted", status)
	}
	if note == "" {
		t.Fatal("a contradiction must say what it contradicts")
	}
}

// Confidence must come from independent channels agreeing, never from taking
// more samples with the same blind spot.
func TestConfidenceCeilingRequiresIndependentChannels(t *testing.T) {
	bare := &models.EvidenceCorroboration{CTStatus: models.CTUnavailable}
	if got := confidenceCeiling(bare, false, false); got != "low" {
		t.Fatalf("ceiling = %q, want low with no independent channel", got)
	}
	if got := confidenceCeiling(bare, true, false); got != "low" {
		t.Fatalf("ceiling = %q, want low with only one channel", got)
	}
	withCoverage := &models.EvidenceCorroboration{CTStatus: models.CTUnavailable, EndpointCoverage: 0.8}
	if got := confidenceCeiling(withCoverage, true, false); got != "medium" {
		t.Fatalf("ceiling = %q, want medium without an external issuance record", got)
	}
	full := &models.EvidenceCorroboration{CTStatus: models.CTCorroborated, EndpointCoverage: 0.8}
	if got := confidenceCeiling(full, true, true); got != "high" {
		t.Fatalf("ceiling = %q, want high when every channel is present", got)
	}
	sctOnly := &models.EvidenceCorroboration{CTStatus: models.CTUnavailable, SCTPresented: true, EndpointCoverage: 0.8}
	if got := confidenceCeiling(sctOnly, false, false); got != "medium" {
		t.Fatalf("ceiling = %q, want handshake SCTs to count as the issuance channel", got)
	}
	directory := &models.EvidenceCorroboration{CTStatus: models.CTUnavailable, DirectoryStatus: models.DirectoryIdentified, EndpointCoverage: 0.8}
	if got := confidenceCeiling(directory, true, false); got != "high" {
		t.Fatalf("ceiling = %q, want numbering-authority identity to raise the ceiling", got)
	}
	caa := &models.EvidenceCorroboration{CTStatus: models.CTUnavailable, CAAStatus: models.CAAAuthorized, EndpointCoverage: 0.8}
	if got := confidenceCeiling(caa, false, false); got != "medium" {
		t.Fatalf("ceiling = %q, want CAA authorization to count as an independent channel", got)
	}
	if got := capConfidence("high", "medium"); got != "medium" {
		t.Fatalf("cap = %q, want the ceiling to bind", got)
	}
}

// Rows written by a superseded rule generation must not inherit the current
// rules' credibility.
func TestEvidenceProvenanceMarksLegacyDominatedFindings(t *testing.T) {
	rows := []models.CertObservation{
		{DetectorVersion: models.DetectorLegacy},
		{DetectorVersion: models.DetectorLegacy},
		{DetectorVersion: models.DetectorCurrent},
	}
	provenance := evidenceProvenance(rows)
	if !provenance.LegacyDominated || provenance.CurrentEvents != 1 || provenance.LegacyEvents != 2 {
		t.Fatalf("provenance = %#v, want a legacy-dominated finding", provenance)
	}
}

// Historical rows can be reclassified from what they already retained.
func TestReplayChangeClassRecoversConcurrencyFromStoredProbes(t *testing.T) {
	probes, _ := json.Marshal([]models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old"},
		{IPAddress: "198.51.100.1", Success: true, Fingerprint: "new"},
	})
	row := models.CertObservation{PreviousFingerprint: "old", Fingerprint: "new", EndpointProbes: string(probes), IPAddress: "198.51.100.1"}
	if got := replayChangeClass(row, "192.0.2.1"); got != models.ChangeClassCoexisting {
		t.Fatalf("class = %q, want coexisting leaves", got)
	}
	plain := models.CertObservation{PreviousFingerprint: "old", Fingerprint: "new", IPAddress: "192.0.2.1"}
	if got := replayChangeClass(plain, "192.0.2.1"); got != models.ChangeClassReplacement {
		t.Fatalf("class = %q, want a same-endpoint replacement", got)
	}
	if got := replayChangeClass(plain, "198.51.100.1"); got != models.ChangeClassEndpointSampling {
		t.Fatalf("class = %q, want endpoint sampling", got)
	}
}
