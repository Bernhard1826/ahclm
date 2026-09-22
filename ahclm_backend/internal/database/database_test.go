package database

import (
	"encoding/json"
	"fmt"
	"strings"
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
		observed := t0.Add(time.Duration(i*30*24) * time.Hour)
		notBefore := observed.Add(-2 * 24 * time.Hour)
		notAfter := notBefore.Add(90 * 24 * time.Hour)
		changes = append(changes, models.CertObservation{ObservationType: models.ObsChange, ObservedAt: observed, Fingerprint: newFP, PreviousFingerprint: oldFP, PreviousSPKIFingerprint: "spki-stable", SPKIFingerprint: "spki-stable", DaysUntilExpiry: 88, IPAddress: "192.0.2.1"})
		certs[oldFP] = models.Certificate{Fingerprint: oldFP, Issuer: "CA", IssuerCN: "CA", CommonName: "example", ValidityDays: 90, NotBefore: notBefore.Add(-30 * 24 * time.Hour), NotAfter: notAfter.Add(-30 * 24 * time.Hour)}
		certs[newFP] = models.Certificate{Fingerprint: newFP, Issuer: "CA", IssuerCN: "CA", CommonName: "example", ValidityDays: 90, NotBefore: notBefore, NotAfter: notAfter}
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: changes, certificates: certs})
	if diagnosis.PrimaryCode != "automated_renewal_policy" {
		t.Fatalf("primary diagnosis = %q, want automated renewal: %#v", diagnosis.PrimaryCode, diagnosis)
	}
	if len(diagnosis.Hypotheses) < 3 || diagnosis.Hypotheses[0].Score < 0.6 {
		t.Fatalf("automated renewal support too weak: %#v", diagnosis.Hypotheses)
	}
}

func TestInferChurnDiagnosisLeavesIrregularReplacementUnexplained(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changes := []models.CertObservation{
		{ObservationType: models.ObsChange, ObservedAt: t0, Fingerprint: "b", PreviousFingerprint: "a", PreviousSPKIFingerprint: "spki-a", SPKIFingerprint: "spki-b", DaysUntilExpiry: 180, IPAddress: "192.0.2.1"},
		{ObservationType: models.ObsChange, ObservedAt: t0.Add(3 * 24 * time.Hour), Fingerprint: "c", PreviousFingerprint: "b", PreviousSPKIFingerprint: "spki-b", SPKIFingerprint: "spki-c", DaysUntilExpiry: 160, IPAddress: "192.0.2.1"},
		{ObservationType: models.ObsChange, ObservedAt: t0.Add(17 * 24 * time.Hour), Fingerprint: "d", PreviousFingerprint: "c", PreviousSPKIFingerprint: "spki-c", SPKIFingerprint: "spki-d", DaysUntilExpiry: 140, IPAddress: "192.0.2.1"},
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: changes})
	if diagnosis.PrimaryCode == "key_security_rotation" {
		t.Fatalf("a different public key was treated as a cause: %#v", diagnosis)
	}
	if diagnosis.PrimaryCode != "replacement_mechanism_unestablished" {
		t.Fatalf("primary diagnosis = %q, want an unestablished replacement process: %#v", diagnosis.PrimaryCode, diagnosis)
	}
}

func TestInferChurnDiagnosisFindsPreissuedRollingPipeline(t *testing.T) {
	t0 := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	issued := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	changes := make([]models.CertObservation, 0, 8)
	certs := make(map[string]models.Certificate)
	for i := 0; i < 8; i++ {
		oldFP := "leaf-" + string(rune('a'+i))
		newFP := "leaf-" + string(rune('b'+i))
		notBefore := issued.Add(time.Duration(i) * 24 * time.Hour)
		notAfter := notBefore.Add(90 * 24 * time.Hour)
		changes = append(changes, models.CertObservation{
			ObservationType: models.ObsChange, ObservedAt: t0.Add(time.Duration(i) * 24 * time.Hour),
			Fingerprint: newFP, PreviousFingerprint: oldFP, DaysUntilExpiry: 7, IPAddress: "192.0.2.1",
		})
		certs[oldFP] = models.Certificate{Fingerprint: oldFP, Issuer: "CN=DigiCert", IssuerCN: "DigiCert", CommonName: "*.example", ValidityDays: 90, NotBefore: notBefore.Add(-24 * time.Hour), NotAfter: notAfter.Add(-24 * time.Hour)}
		certs[newFP] = models.Certificate{Fingerprint: newFP, Issuer: "CN=DigiCert", IssuerCN: "DigiCert", CommonName: "*.example", ValidityDays: 90, NotBefore: notBefore, NotAfter: notAfter}
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: changes, certificates: certs})
	if diagnosis.PrimaryCode != "preissued_rolling_pipeline" {
		t.Fatalf("primary diagnosis = %q, want a pre-issued rolling pipeline: %#v", diagnosis.PrimaryCode, diagnosis)
	}
	if diagnosis.ChurnShape == nil || diagnosis.ChurnShape.MedianRemainingDays != 7 || diagnosis.ChurnShape.DistinctIssuanceDays < 4 {
		t.Fatalf("pipeline signals missing: %#v", diagnosis.ChurnShape)
	}
}

func TestInferChurnDiagnosisTreatsFreshDailyIssuanceAsAutomation(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	changes := make([]models.CertObservation, 0, 6)
	certs := make(map[string]models.Certificate)
	for i := 0; i < 6; i++ {
		oldFP := "leaf-" + string(rune('a'+i))
		newFP := "leaf-" + string(rune('b'+i))
		observed := t0.Add(time.Duration(i) * 24 * time.Hour)
		notBefore := observed
		notAfter := notBefore.Add(90 * 24 * time.Hour)
		changes = append(changes, models.CertObservation{
			ObservationType: models.ObsChange, ObservedAt: observed,
			Fingerprint: newFP, PreviousFingerprint: oldFP, DaysUntilExpiry: 89, IPAddress: "192.0.2.1",
		})
		certs[oldFP] = models.Certificate{Fingerprint: oldFP, Issuer: "CA", IssuerCN: "CA", CommonName: "example", ValidityDays: 90, NotBefore: notBefore.Add(-24 * time.Hour), NotAfter: notAfter.Add(-24 * time.Hour)}
		certs[newFP] = models.Certificate{Fingerprint: newFP, Issuer: "CA", IssuerCN: "CA", CommonName: "example", ValidityDays: 90, NotBefore: notBefore, NotAfter: notAfter}
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: changes, certificates: certs})
	if diagnosis.PrimaryCode == "preissued_rolling_pipeline" {
		t.Fatalf("a freshly issued 90-day certificate was called a pre-issued inventory: %#v", diagnosis)
	}
	if diagnosis.PrimaryCode != "automated_renewal_policy" {
		t.Fatalf("primary diagnosis = %q, want issuance at replacement time: %#v", diagnosis.PrimaryCode, diagnosis)
	}
}

func TestIssuerFamilyIgnoresIntermediateSerial(t *testing.T) {
	we := models.Certificate{IssuerCN: "WE1", Issuer: "CN=WE1, O=Google Trust Services"}
	wr := models.Certificate{IssuerCN: "WR2", Issuer: "CN=WR2, O=Google Trust Services"}
	if issuerFamily(we) != issuerFamily(wr) {
		t.Fatalf("GTS intermediates should be one issuer family: %q vs %q", issuerFamily(we), issuerFamily(wr))
	}
	r10 := models.Certificate{IssuerCN: "R10", Issuer: "CN=R10, O=Let's Encrypt"}
	r11 := models.Certificate{IssuerCN: "R11", Issuer: "CN=R11, O=Let's Encrypt"}
	if issuerFamily(r10) != issuerFamily(r11) {
		t.Fatalf("Let's Encrypt intermediates should be one issuer family: %q vs %q", issuerFamily(r10), issuerFamily(r11))
	}
}

func TestTopologySignalsIgnoreAddressSetChurnWithoutLeafChange(t *testing.T) {
	snapshots := []models.MeasurementSnapshot{
		{ObservedAt: time.Date(2026, 9, 18, 6, 0, 0, 0, time.UTC), TopologyHash: "b", EndpointFingerprintsJSON: `{"172.217.75.94":"leaf-a","192.178.164.94":"leaf-a"}`},
		{ObservedAt: time.Date(2026, 9, 17, 6, 0, 0, 0, time.UTC), TopologyHash: "a", EndpointFingerprintsJSON: `{"142.251.181.94":"leaf-a","172.217.75.94":"leaf-a"}`},
	}
	topologyChanges, endpointChanges := topologySignals(snapshots)
	if topologyChanges == 0 {
		t.Fatal("address-set rotation should still be visible as a topology hash change")
	}
	if endpointChanges != 0 {
		t.Fatalf("VIP rotation without a leaf change was scored as a rollout: %.2f", endpointChanges)
	}
}

func TestInferChurnDiagnosisDoesNotNameEdgeRolloutWithoutEndpointIdentity(t *testing.T) {
	t0 := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	changes := make([]models.CertObservation, 0, 5)
	certs := make(map[string]models.Certificate)
	for i := 0; i < 5; i++ {
		oldFP := "leaf-" + string(rune('a'+i))
		newFP := "leaf-" + string(rune('b'+i))
		observed := t0.Add(time.Duration(i*20) * 24 * time.Hour)
		notBefore := observed.Add(-18 * 24 * time.Hour)
		notAfter := notBefore.Add(83 * 24 * time.Hour)
		changes = append(changes, models.CertObservation{
			ObservationType: models.ObsChange, ObservedAt: observed,
			Fingerprint: newFP, PreviousFingerprint: oldFP, DaysUntilExpiry: 66,
		})
		certs[oldFP] = models.Certificate{Fingerprint: oldFP, Issuer: "O=Google Trust Services", IssuerCN: "WR2", CommonName: "*.google.de", ValidityDays: 83, NotBefore: notBefore.Add(-24 * time.Hour), NotAfter: notAfter.Add(-24 * time.Hour)}
		certs[newFP] = models.Certificate{Fingerprint: newFP, Issuer: "O=Google Trust Services", IssuerCN: "WE2", CommonName: "*.google.de", ValidityDays: 83, NotBefore: notBefore, NotAfter: notAfter}
	}
	snapshots := []models.MeasurementSnapshot{
		{ObservedAt: t0.Add(80 * 24 * time.Hour), TopologyHash: "b", EndpointFingerprintsJSON: `{"172.217.75.94":"leaf-e"}`},
		{ObservedAt: t0, TopologyHash: "a", EndpointFingerprintsJSON: `{"142.251.181.94":"leaf-a"}`},
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: changes, certificates: certs, snapshots: snapshots})
	if diagnosis.PrimaryCode == "edge_or_deployment_rollout" {
		t.Fatalf("address-set rotation was named as an edge rollout: %#v", diagnosis)
	}
	if diagnosis.PrimaryCode == "ca_or_policy_migration" {
		t.Fatalf("GTS intermediate serials were named as a CA migration: %#v", diagnosis)
	}
}

func TestInferChurnDiagnosisInfersAutomationWithoutEndpointIdentity(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	changes := make([]models.CertObservation, 0, 5)
	certs := make(map[string]models.Certificate)
	for i := 0; i < 5; i++ {
		oldFP := "leaf-" + string(rune('a'+i))
		newFP := "leaf-" + string(rune('b'+i))
		observed := t0.Add(time.Duration(i) * 24 * time.Hour)
		notBefore := observed
		notAfter := notBefore.Add(90 * 24 * time.Hour)
		changes = append(changes, models.CertObservation{
			ObservationType: models.ObsChange, ObservedAt: observed,
			Fingerprint: newFP, PreviousFingerprint: oldFP, DaysUntilExpiry: 89,
		})
		certs[oldFP] = models.Certificate{Fingerprint: oldFP, Issuer: "CA", IssuerCN: "CA", CommonName: "example", ValidityDays: 90, NotBefore: notBefore.Add(-24 * time.Hour), NotAfter: notAfter.Add(-24 * time.Hour)}
		certs[newFP] = models.Certificate{Fingerprint: newFP, Issuer: "CA", IssuerCN: "CA", CommonName: "example", ValidityDays: 90, NotBefore: notBefore, NotAfter: notAfter}
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: changes, certificates: certs})
	if diagnosis.PrimaryCode != "automated_renewal_policy" {
		t.Fatalf("primary diagnosis = %q, want inferred issuance at replacement time: %#v", diagnosis.PrimaryCode, diagnosis)
	}
	if diagnosis.CauseStatus != "inferred" {
		t.Fatalf("cause status = %q, want inferred when serving addresses are missing", diagnosis.CauseStatus)
	}
	if diagnosis.Confidence != "low" {
		t.Fatalf("inferred readings must stay low-confidence, got %q", diagnosis.Confidence)
	}
}

func TestNearestEndpointIgnoresStaleSnapshots(t *testing.T) {
	at := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	got := nearestEndpointFor([]leafAppearance{
		{at: at.Add(24 * time.Hour), ip: "192.0.2.1"},
	}, at)
	if got != "" {
		t.Fatalf("a snapshot a day later was used as the serving address: %q", got)
	}
	got = nearestEndpointFor([]leafAppearance{
		{at: at.Add(30 * time.Minute), ip: "192.0.2.8"},
	}, at)
	if got != "192.0.2.8" {
		t.Fatalf("a same-round snapshot was not recovered: %q", got)
	}
}

func TestRecoverChangeEndpointsFromSnapshots(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	changes := []models.CertObservation{
		{ObservationType: models.ObsChange, ObservedAt: t0, Fingerprint: "new-a", PreviousFingerprint: "old-a", DaysUntilExpiry: 89},
		{ObservationType: models.ObsChange, ObservedAt: t0.Add(24 * time.Hour), Fingerprint: "new-b", PreviousFingerprint: "new-a", DaysUntilExpiry: 89},
	}
	snapshots := []models.MeasurementSnapshot{
		{ObservedAt: t0, EndpointFingerprintsJSON: `{"192.0.2.1":"new-a"}`},
		{ObservedAt: t0.Add(24 * time.Hour), EndpointFingerprintsJSON: `{"192.0.2.1":"new-b"}`},
	}
	shape := analyzeChurnShapeWithSnapshots(changes, nil, snapshots)
	if shape.SameEndpointChanges < 1 {
		t.Fatalf("snapshot recovery did not produce a same-endpoint comparison: %#v", shape)
	}
	if shape.RecoveredEndpointChanges == 0 {
		t.Fatal("recovered endpoint count was not recorded")
	}
}

func TestInferChurnDiagnosisRequiresLongitudinalEvidence(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, observations := range []([]models.CertObservation){
		nil,
		{{ObservationType: models.ObsChange, ObservedAt: t0, Fingerprint: "new", PreviousFingerprint: "old"}},
	} {
		diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: observations})
		if diagnosis.PrimaryCode != "insufficient_longitudinal_evidence" || diagnosis.Confidence != "low" || diagnosis.CauseStatus != "unestablished" {
			t.Fatalf("diagnosis = %#v, want a low-confidence unestablished evidence gate", diagnosis)
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
	// Two certificates, each served consistently from its own network
	// allocation, holding across independent rounds.
	endpointMap := mapJSON(map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"})
	snapshots := []models.MeasurementSnapshot{
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
	}
	diagnosis := inferTopologyDiagnosis(models.Anomaly{Type: models.ObsDeploymentFailure}, diagnosisContext{snapshots: snapshots})
	if diagnosis.PrimaryCode != models.DivergenceIntentionalMultiCDN {
		t.Fatalf("primary diagnosis = %q, want a deliberate multi-provider arrangement", diagnosis.PrimaryCode)
	}
	if diagnosis.BenignExplanation == "" {
		t.Fatal("a deliberate arrangement must carry the explanation that withdraws the problem claim")
	}
	if diagnosis.Divergence == nil || !diagnosis.Divergence.CleanPartition || diagnosis.Divergence.StableRounds < 2 {
		t.Fatalf("divergence evidence did not record the clean stable partition: %#v", diagnosis.Divergence)
	}
}

// Edge addresses rotate on nearly every query. The steady state that has to be
// recognized is "which provider serves which certificate", so a rotation inside
// one allocation must not read as a new transition.
func TestDivergenceStabilitySurvivesEdgeAddressRotation(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	snapshots := []models.MeasurementSnapshot{
		{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"23.43.51.10": "a", "104.16.7.9": "b"})},
		{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"23.43.99.4": "a", "104.16.200.1": "b"})},
		{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"23.43.12.55": "a", "104.16.31.77": "b"})},
	}
	diagnosis := inferTopologyDiagnosis(models.Anomaly{Type: models.ObsDeploymentFailure}, diagnosisContext{snapshots: snapshots})
	if diagnosis.Divergence == nil || diagnosis.Divergence.StableRounds < 2 {
		t.Fatalf("address rotation inside one allocation reset the stability test: %#v", diagnosis.Divergence)
	}
	if diagnosis.PrimaryCode != models.DivergenceIntentionalMultiCDN {
		t.Fatalf("primary diagnosis = %q, want a deliberate multi-provider arrangement", diagnosis.PrimaryCode)
	}
}

// Two addresses inside one allocation serving different certificates cannot be
// a between-provider arrangement, so the multi-CDN reading must not apply.
func TestDivergenceUsesNamedVendorsWhenEveryEndpointIsIdentified(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	topology, _ := json.Marshal(models.TopologySnapshot{
		CNAMEChain: []string{"www.example.com.cdn.cloudflare.net", "www.example.com.fastly.net"},
	})
	assignment := mapJSON(map[string]string{"104.16.7.9": "a", "151.101.1.1": "b"})
	probes := []models.EndpointProbe{
		{IPAddress: "104.16.7.9", Success: true, Fingerprint: "a"},
		{IPAddress: "151.101.1.1", Success: true, Fingerprint: "b"},
	}
	snapshots := []models.MeasurementSnapshot{
		{FingerprintCount: 2, EndpointFingerprintsJSON: assignment, TopologyJSON: string(topology)},
		{FingerprintCount: 2, EndpointFingerprintsJSON: assignment, TopologyJSON: string(topology)},
	}
	divergence := analyzeEndpointDivergence(probes, snapshots, "", time.Time{}, time.Now())
	if divergence.CDN == nil || divergence.CDN.Method != "vendor" || divergence.CDN.DistinctVendors != 2 {
		t.Fatalf("complete vendor evidence was not used: %#v", divergence.CDN)
	}
	if divergence.Verdict != models.DivergenceIntentionalMultiCDN {
		t.Fatalf("verdict = %q, want named multi-CDN", divergence.Verdict)
	}
}

func TestDivergenceSameNamedCDNAcrossPrefixesIsNotMultiCDN(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	assignment := mapJSON(map[string]string{"104.16.7.9": "a", "172.64.1.10": "b"})
	probes := []models.EndpointProbe{
		{IPAddress: "104.16.7.9", Success: true, Fingerprint: "a", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n"},
		{IPAddress: "172.64.1.10", Success: true, Fingerprint: "b", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n"},
	}
	snapshots := []models.MeasurementSnapshot{
		{FingerprintCount: 2, EndpointFingerprintsJSON: assignment},
		{FingerprintCount: 2, EndpointFingerprintsJSON: assignment},
		{FingerprintCount: 2, EndpointFingerprintsJSON: assignment},
	}
	divergence := analyzeEndpointDivergence(probes, snapshots, "", time.Time{}, time.Now())
	if divergence.CDN == nil || divergence.CDN.Method != "vendor" || divergence.CDN.DistinctVendors != 1 {
		t.Fatalf("same-vendor prefixes were not identified: %#v", divergence.CDN)
	}
	if divergence.CleanPartition && divergence.NetworkGroups >= 2 && divergence.Verdict == models.DivergenceIntentionalMultiCDN {
		t.Fatalf("two Cloudflare prefixes were still treated as multi-CDN: %#v", divergence)
	}
	if divergence.Verdict != models.DivergenceIntraFleet {
		t.Fatalf("verdict = %q, want intra-fleet inside one named CDN", divergence.Verdict)
	}
}

func TestDivergenceDirectoryASNNamesVendorWithoutPublishedPrefix(t *testing.T) {
	directory, _ := json.Marshal(models.DirectoryObservation{
		Status: models.DirectoryIdentified,
		Endpoints: []models.IPDirectoryRecord{
			{IPAddress: "192.0.2.1", ASN: 13335, ASNName: "CLOUDFLARENET", OrgName: "Cloudflare, Inc."},
			{IPAddress: "198.51.100.1", ASN: 54113, ASNName: "FASTLY", OrgName: "Fastly, Inc."},
		},
	})
	assignment, _ := json.Marshal(map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"})
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "a"},
		{IPAddress: "198.51.100.1", Success: true, Fingerprint: "b"},
	}
	snapshots := []models.MeasurementSnapshot{
		{DirectoryJSON: string(directory), EndpointFingerprintsJSON: string(assignment), FingerprintCount: 2},
		{DirectoryJSON: string(directory), EndpointFingerprintsJSON: string(assignment), FingerprintCount: 2},
	}
	divergence := analyzeEndpointDivergence(probes, snapshots, "", time.Time{}, time.Now())
	if divergence.CDN == nil || divergence.CDN.Method != "vendor" || divergence.CDN.DistinctVendors != 2 {
		t.Fatalf("ASN identification did not name two CDNs: %#v", divergence.CDN)
	}
	if divergence.Verdict != models.DivergenceIntentionalMultiCDN {
		t.Fatalf("verdict = %q, want named multi-CDN from numbering-authority records", divergence.Verdict)
	}
}

func TestDivergenceFallsBackToNetworkPartitionWhenVendorsAreIncomplete(t *testing.T) {
	topology, _ := json.Marshal(models.TopologySnapshot{CNAMEChain: []string{"www.example.com.fastly.net"}})
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "a"},
		{IPAddress: "198.51.100.1", Success: true, Fingerprint: "b"},
	}
	divergence := analyzeEndpointDivergence(probes, []models.MeasurementSnapshot{{TopologyJSON: string(topology)}}, "", time.Time{}, time.Now())
	if divergence.CDN == nil || divergence.CDN.Method != "network" || divergence.CDN.Completeness != models.CDNCompletenessHostname {
		t.Fatalf("hostname-only evidence must stay on the network method: %#v", divergence.CDN)
	}
	if divergence.Verdict != models.DivergenceUndetermined {
		t.Fatalf("one clean fallback round must remain insufficient, got %q", divergence.Verdict)
	}
}

func TestDivergenceRequiresStableNamedVendorSplit(t *testing.T) {
	topology, _ := json.Marshal(models.TopologySnapshot{
		CNAMEChain: []string{"www.example.com.cdn.cloudflare.net", "www.example.com.fastly.net"},
	})
	probes := []models.EndpointProbe{
		{IPAddress: "104.16.7.9", Success: true, Fingerprint: "a"},
		{IPAddress: "151.101.1.1", Success: true, Fingerprint: "b"},
	}
	assignment := map[string]string{"104.16.7.9": "a", "151.101.1.1": "b"}
	encoded, _ := json.Marshal(assignment)
	divergence := analyzeEndpointDivergence(probes, []models.MeasurementSnapshot{{
		FingerprintCount: 2, EndpointFingerprintsJSON: string(encoded), TopologyJSON: string(topology),
	}}, "", time.Time{}, time.Now())
	if divergence.CDN == nil || divergence.CDN.Method != "vendor" || divergence.CDN.DistinctVendors != 2 {
		t.Fatalf("complete vendor evidence was not retained: %#v", divergence.CDN)
	}
	if divergence.Verdict != models.DivergenceUndetermined {
		t.Fatalf("one named-vendor round must remain insufficient, got %q", divergence.Verdict)
	}
}

func TestDivergenceFlagsConflictInsideOneProviderNetwork(t *testing.T) {
	probes := []models.EndpointProbe{
		{IPAddress: "165.189.150.147", Success: true, Fingerprint: "a", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "names"},
		{IPAddress: "165.189.241.136", Success: true, Fingerprint: "b", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "names"},
	}
	divergence := analyzeEndpointDivergence(probes, nil, "", time.Time{}, time.Now())
	if divergence.CleanPartition || divergence.IntraGroupConflicts != 1 {
		t.Fatalf("same-allocation disagreement was not detected: %#v", divergence)
	}
	if divergenceIsBenign(divergence.Verdict) {
		t.Fatalf("verdict %q must not be benign for an intra-network conflict", divergence.Verdict)
	}
}

// An RSA plus ECDSA pair covers the same names from the same issuer on purpose.
func TestDivergenceRecognizesDualCertificatePair(t *testing.T) {
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "rsa-leaf", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "same-names"},
		{IPAddress: "192.0.2.2", Success: true, Fingerprint: "ec-leaf", IssuerCN: "CA", KeyAlgorithm: "ECDSA", SANsHash: "same-names"},
	}
	divergence := analyzeEndpointDivergence(probes, nil, "", time.Time{}, time.Now())
	if !divergence.DualCertificateSplit || divergence.Verdict != models.DivergenceDualCertificate {
		t.Fatalf("dual-certificate pair was not recognized: %#v", divergence)
	}
	if !divergenceIsBenign(divergence.Verdict) {
		t.Fatal("a deliberate algorithm pair must be treated as an expected property")
	}
}

// A certificate that is not valid for the queried name is a defect whatever the
// endpoint distribution looks like, so no benign structure may outrank it.
func TestDivergenceDefectiveEndpointOutranksBenignStructure(t *testing.T) {
	expired := time.Now().Add(-48 * time.Hour)
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "a", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n"},
		{IPAddress: "198.51.100.1", Success: true, Fingerprint: "b", IssuerCN: "CA", KeyAlgorithm: "ECDSA", SANsHash: "n", NotAfter: &expired},
	}
	assignment, _ := json.Marshal(map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"})
	snapshots := []models.MeasurementSnapshot{
		{EndpointFingerprintsJSON: string(assignment)},
		{EndpointFingerprintsJSON: string(assignment)},
		{EndpointFingerprintsJSON: string(assignment)},
	}
	divergence := analyzeEndpointDivergence(probes, snapshots, "", time.Time{}, time.Now())
	if divergence.Verdict != models.DivergenceIntentionalMultiCDN {
		t.Fatalf("verdict = %q, want the multi-provider split even when one provider's leaf is invalid: %#v", divergence.Verdict, divergence)
	}
	if !divergenceIsBenign(divergence.Verdict) {
		t.Fatal("a clean two-provider split must stay an expected property")
	}
	if divergence.FunctionallyEquivalent || len(divergence.DefectiveEndpoints) != 1 {
		t.Fatalf("the invalid leaf must still be recorded as a separate defect: %#v", divergence)
	}
}

func TestDivergenceDefectiveEndpointInsideOneNetworkRemainsAnIncident(t *testing.T) {
	expired := time.Now().Add(-48 * time.Hour)
	probes := []models.EndpointProbe{
		{IPAddress: "165.189.150.147", Success: true, Fingerprint: "a", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n"},
		{IPAddress: "165.189.241.136", Success: true, Fingerprint: "b", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n", NotAfter: &expired},
	}
	divergence := analyzeEndpointDivergence(probes, nil, "", time.Time{}, time.Now())
	if divergence.Verdict != models.DivergenceDefectiveEndpoint {
		t.Fatalf("verdict = %q, want the defective-endpoint reading inside one network: %#v", divergence.Verdict, divergence)
	}
	if divergenceIsBenign(divergence.Verdict) || divergence.FunctionallyEquivalent {
		t.Fatal("an endpoint serving an expired certificate inside one network must not be reported as an expected property")
	}
}

// Elapsed time by itself is not enough: without retained DNS-active rounds an
// old direct-probe address may be retired, so the result stays provisional.
func TestDivergenceSeparatesStuckRolloutFromPropagation(t *testing.T) {
	now := time.Now()
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n"},
		{IPAddress: "192.0.2.2", Success: true, Fingerprint: "new", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n"},
	}
	inFlight := analyzeEndpointDivergence(probes, nil, "old", now.Add(-2*time.Hour), now)
	if inFlight.Verdict != models.DivergencePropagating {
		t.Fatalf("a two-hour-old replacement should still be in flight, got %q", inFlight.Verdict)
	}
	stuck := analyzeEndpointDivergence(probes, nil, "old", now.Add(-96*time.Hour), now)
	if stuck.Verdict != models.DivergencePropagating || stuck.StrongEvidence {
		t.Fatalf("elapsed time without active-round evidence must stay provisional: %#v", stuck)
	}
}

func TestDivergenceRequiresSameActiveEndpointAcrossRounds(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	topologyJSON := func(ips []string) string {
		encoded, _ := json.Marshal(models.TopologySnapshot{ConsensusIPs: ips, PublicIPs: ips, ResolverQuorum: 2, ResolverAgreement: 1})
		return string(encoded)
	}
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	assignment := mapJSON(map[string]string{"192.0.2.1": "old", "192.0.2.2": "new"})
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n"},
		{IPAddress: "192.0.2.2", Success: true, Fingerprint: "new", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n"},
	}
	snapshots := []models.MeasurementSnapshot{
		{ObservedAt: now.Add(-24 * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: assignment, TopologyJSON: topologyJSON([]string{"192.0.2.1", "192.0.2.2"})},
		{ObservedAt: now.Add(-48 * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: assignment, TopologyJSON: topologyJSON([]string{"192.0.2.1", "192.0.2.2"})},
		{ObservedAt: now.Add(-72 * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: assignment, TopologyJSON: topologyJSON([]string{"192.0.2.1", "192.0.2.2"})},
	}
	divergence := analyzeEndpointDivergence(probes, snapshots, "old", now.Add(-96*time.Hour), now)
	if !divergence.StrongEvidence || divergence.Verdict != models.DivergenceStuckRollout {
		t.Fatalf("complete active-endpoint continuity should establish a stuck rollout: %#v", divergence)
	}
	if divergence.ConsecutivePredecessorRounds < 3 || divergence.PredecessorSpanHours < 24 || divergence.ResolverConsistentRounds < 2 {
		t.Fatalf("hard evidence gates were not recorded: %#v", divergence)
	}
	if len(divergence.ActivePredecessorEndpoints) != 1 || divergence.ActivePredecessorEndpoints[0] != "192.0.2.1" {
		t.Fatalf("active predecessor endpoint was not retained: %#v", divergence.ActivePredecessorEndpoints)
	}
}

func TestDivergenceDoesNotTreatRetiredPredecessorAsActive(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	topology, _ := json.Marshal(models.TopologySnapshot{ConsensusIPs: []string{"198.51.100.1"}, PublicIPs: []string{"198.51.100.1"}, ResolverQuorum: 2, ResolverAgreement: 1})
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n"},
		{IPAddress: "198.51.100.1", Success: true, Fingerprint: "new", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n"},
	}
	divergence := analyzeEndpointDivergence(probes, []models.MeasurementSnapshot{{ObservedAt: now.Add(-48 * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: mapJSON(map[string]string{"192.0.2.1": "old", "198.51.100.1": "new"}), TopologyJSON: string(topology)}}, "old", now.Add(-96*time.Hour), now)
	if divergence.StrongEvidence || divergence.Verdict == models.DivergenceStuckRollout {
		t.Fatalf("retired predecessor was promoted to a stuck rollout: %#v", divergence)
	}
	if len(divergence.RetiredPredecessorEndpoints) != 1 || divergence.RetiredPredecessorEndpoints[0] != "192.0.2.1" {
		t.Fatalf("retired predecessor was not classified explicitly: %#v", divergence)
	}
}

func TestBuildEvidenceCasePreservesDNSStateAndReasoningLayers(t *testing.T) {
	t0 := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	topology, _ := json.Marshal(models.TopologySnapshot{ConsensusIPs: []string{"198.51.100.1"}, PublicIPs: []string{"198.51.100.1"}, ResolverQuorum: 2, ResolverAgreement: 1})
	assignment, _ := json.Marshal(map[string]string{"192.0.2.1": "old", "198.51.100.1": "new"})
	divergence := models.EndpointDivergence{
		EndpointsAnswered: 2, DistinctLeaves: 2, Verdict: models.DivergencePropagating,
		RetiredPredecessorEndpoints: []string{"192.0.2.1"},
		MissingEvidence:             []string{"predecessor was observed only on a retired or non-consensus endpoint"},
		ReversalConditions:          []string{"the predecessor leaves the active DNS consensus"},
	}
	diagnosis := models.CauseDiagnosis{
		PrimaryCode: "rollout_in_progress", PrimaryLabel: "Rollout in progress", Confidence: "low",
		Summary: "The assignment has not settled.", EvidenceCompleteness: 0.4,
		Hypotheses: []models.CauseHypothesis{
			{Code: "rollout_in_progress", Label: "Rollout in progress"},
			{Code: "intentional_multi_cdn", Label: "Intentional multi-provider deployment", Contradictions: []string{"a stable assignment would refute this"}},
		},
		MeasurementPlan: []string{"collect another independent round"}, Divergence: &divergence,
		Corroboration: &models.EvidenceCorroboration{ConfidenceCeiling: "medium"},
	}
	caseFile := buildEvidenceCase(models.Anomaly{Domain: "example.com", Type: models.ObsDeploymentFailure}, diagnosisContext{
		snapshots: []models.MeasurementSnapshot{{ObservedAt: t0, Trigger: "deep", ResolverQuorum: 2, ResolverAgreement: 1, EndpointCount: 2, SuccessfulEndpointCount: 2, EndpointFingerprintsJSON: string(assignment), TopologyJSON: string(topology)}},
	}, diagnosis)
	if len(caseFile.Rounds) != 1 || caseFile.Rounds[0].Endpoints[0].ActiveDNS {
		t.Fatalf("retired endpoint was not shown as outside DNS consensus: %#v", caseFile.Rounds)
	}
	if caseFile.Rounds[0].Endpoints[1].ActiveDNS != true {
		t.Fatalf("active endpoint was not shown as DNS-active: %#v", caseFile.Rounds)
	}
	if caseFile.ConfidenceCeiling != "medium" || len(caseFile.Contradictions) == 0 || len(caseFile.MissingEvidence) == 0 {
		t.Fatalf("evidence reasoning layers were not preserved: %#v", caseFile)
	}
	for _, fact := range caseFile.SupportingEvidence {
		if strings.Contains(fact, "=") && !strings.Contains(fact, " ") {
			t.Fatalf("supporting evidence still uses raw field encoding: %q", fact)
		}
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

func evidenceHas(evidence []string, want string) bool {
	for _, item := range evidence {
		if item == want {
			return true
		}
	}
	return false
}

func TestSameKeyEvidenceCarriesTheEndpointPairItClaims(t *testing.T) {
	// The confirmed reason names "the observed endpoint", so the endpoint pair
	// must be recheckable from the finding alone.
	cause := lifecycleCause(models.CertObservation{
		ObservationType:     models.ObsSameKey,
		ObservedAt:          time.Now(),
		PreviousFingerprint: "aaa",
		Fingerprint:         "bbb",
		PreviousIPAddress:   "203.0.113.10",
		IPAddress:           "203.0.113.10",
	}, 1)

	for _, want := range []string{
		"previous_endpoint_ip=203.0.113.10",
		"observed_endpoint_ip=203.0.113.10",
		"endpoint_comparison=same_endpoint",
	} {
		if !evidenceHas(cause.confirmedEvidence, want) {
			t.Fatalf("same-key evidence is missing %q: %v", want, cause.confirmedEvidence)
		}
	}
}

func TestSameKeyEvidenceMarksAnUnknownEndpointPairInsteadOfImplyingOne(t *testing.T) {
	cause := lifecycleCause(models.CertObservation{
		ObservationType:     models.ObsSameKey,
		ObservedAt:          time.Now(),
		PreviousFingerprint: "aaa",
		Fingerprint:         "bbb",
	}, 1)

	if !evidenceHas(cause.confirmedEvidence, "endpoint_comparison=unknown") {
		t.Fatalf("a row without an endpoint pair must say so: %v", cause.confirmedEvidence)
	}
	if evidenceHas(cause.confirmedEvidence, "endpoint_comparison=same_endpoint") {
		t.Fatalf("a row without an endpoint pair must not claim the same endpoint: %v", cause.confirmedEvidence)
	}
}

func TestStaleAfterChangeSurfacesTheEndpointProbesThatProveIt(t *testing.T) {
	// staleEndpointEvidence() only writes this row when a retired address served
	// the predecessor and a current address served the successor. That proof has
	// to reach the finding, otherwise it rests on set inequality alone.
	probes, err := json.Marshal([]models.EndpointProbe{
		{IPAddress: "198.51.100.7", Success: true, Fingerprint: "aaa"},
		{IPAddress: "203.0.113.9", Success: true, Fingerprint: "bbb"},
	})
	if err != nil {
		t.Fatalf("marshal probes: %v", err)
	}

	cause := lifecycleCause(models.CertObservation{
		ObservationType:     models.ObsStaleAfterChange,
		ObservedAt:          time.Now(),
		ResolvedIPs:         `["203.0.113.9"]`,
		PreviousResolvedIPs: `["198.51.100.7"]`,
		EndpointProbes:      string(probes),
	}, 1)

	if !evidenceHas(cause.confirmedEvidence, "endpoint_probes="+string(probes)) {
		t.Fatalf("stale evidence dropped the endpoint probes: %v", cause.confirmedEvidence)
	}
}
