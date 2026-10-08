package database

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestImpactExpectedMultiCDNHasNoIncident(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	endpointMap := mapJSON(map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"})
	snapshots := []models.MeasurementSnapshot{
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
	}
	item := models.Anomaly{Domain: "cdn.example", Type: models.ObsDeploymentFailure}
	context := diagnosisContext{snapshots: snapshots}
	diagnosis := inferTopologyDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if investigation.Impact == nil {
		t.Fatal("expected impact analysis")
	}
	if investigation.Impact.SeverityCeiling != models.ImpactNone {
		t.Fatalf("ceiling = %q, want none for expected multi-CDN", investigation.Impact.SeverityCeiling)
	}
	if !containsFold(investigation.Impact.Summary, "no client-facing incident") {
		t.Fatalf("summary still treated multi-CDN as an incident: %q", investigation.Impact.Summary)
	}
}

func TestImpactIntraFleetIsSplitViewNotOutage(t *testing.T) {
	probes := []models.EndpointProbe{
		{IPAddress: "165.189.150.147", Success: true, Fingerprint: "a", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "names"},
		{IPAddress: "165.189.241.136", Success: true, Fingerprint: "b", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "names"},
	}
	encoded, _ := json.Marshal(probes)
	// Earlier rounds saw the same two leaves on other addresses of the same
	// /16: the network serves two leaves, but no address kept its own, so
	// this is not an independent certificate per endpoint.
	assignment, _ := json.Marshal(map[string]string{"165.189.150.148": "a", "165.189.241.137": "b"})
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	item := models.Anomaly{Domain: "split.example", Type: models.ObsDeploymentFailure}
	context := diagnosisContext{
		observations: []models.CertObservation{{
			ObservationType: models.ObsDeploymentFailure, ObservedAt: now, EndpointProbes: string(encoded),
		}},
		snapshots: []models.MeasurementSnapshot{
			{ObservedAt: now.Add(-24 * time.Hour), FingerprintCount: 2, EndpointFingerprintsJSON: string(assignment)},
			{ObservedAt: now.Add(-48 * time.Hour), FingerprintCount: 2, EndpointFingerprintsJSON: string(assignment)},
		},
	}
	diagnosis := inferTopologyDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if investigation.Impact == nil {
		t.Fatal("expected impact analysis")
	}
	if investigation.Impact.SeverityCeiling != models.ImpactSplitView {
		t.Fatalf("ceiling = %q, want split_view", investigation.Impact.SeverityCeiling)
	}
	if containsFold(investigation.Impact.Summary, "outage") && !containsFold(investigation.Impact.Summary, "not a proven outage") {
		t.Fatalf("split view was written as an outage: %q", investigation.Impact.Summary)
	}
	if !impactHasCode(investigation.Impact, "split_view") && !impactHasCode(investigation.Impact, "intra_operator_split") {
		t.Fatalf("missing split-view effect: %#v", investigation.Impact.Effects)
	}
	if !impactForbids(investigation.Impact, "worldwide outage") {
		t.Fatalf("must refuse a worldwide outage claim: %#v", investigation.Impact.NotEstablished)
	}
}

func TestImpactExpiredServedIsClientRejection(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	notAfter := now.Add(-48 * time.Hour)
	item := models.Anomaly{Domain: "expired.example", Type: "expired_served", DetectedAt: now}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:             "expired.example",
			CurrentFingerprint: "leaf-old",
			LastEndpointIP:     "192.0.2.9",
			LastScannedAt:      now,
			Status:             models.StatusActive,
		},
		certificates: map[string]models.Certificate{
			"leaf-old": {Fingerprint: "leaf-old", NotAfter: notAfter, NotBefore: now.Add(-90 * 24 * time.Hour)},
		},
	}
	diagnosis := inferCertificateConditionDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if investigation.Impact == nil {
		t.Fatal("expected impact analysis")
	}
	if investigation.Impact.SeverityCeiling != models.ImpactClientRejection {
		t.Fatalf("ceiling = %q, want client_rejection", investigation.Impact.SeverityCeiling)
	}
	if !containsFold(investigation.Impact.Summary, "refuse") && !containsFold(investigation.Impact.Summary, "NotAfter") {
		t.Fatalf("expired served did not name client rejection: %q", investigation.Impact.Summary)
	}
	if !impactHasCode(investigation.Impact, "expired_leaf_served") {
		t.Fatalf("missing rejection effect: %#v", investigation.Impact.Effects)
	}
}

func TestImpactSameKeyDoesNotClaimTheft(t *testing.T) {
	t0 := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	item := models.Anomaly{Domain: "key.example", Type: "same_key", OccurrenceCount: 1}
	context := diagnosisContext{
		observations: []models.CertObservation{{
			ObservationType: models.ObsSameKey, ObservedAt: t0,
			Fingerprint: "leaf-new", PreviousFingerprint: "leaf-old",
			SPKIFingerprint: "spki-same", PreviousSPKIFingerprint: "spki-same",
			IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1",
			ChangeClass: models.ChangeClassReplacement,
		}},
		certificates: map[string]models.Certificate{
			"leaf-old": {Fingerprint: "leaf-old", SPKIFingerprint: "spki-same", NotBefore: t0.Add(-20 * 24 * time.Hour), NotAfter: t0.Add(70 * 24 * time.Hour)},
			"leaf-new": {Fingerprint: "leaf-new", SPKIFingerprint: "spki-same", NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(89 * 24 * time.Hour)},
		},
	}
	diagnosis := inferSameKeyDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if investigation.Impact == nil {
		t.Fatal("expected impact analysis")
	}
	if investigation.FindingClass == models.FindingInsufficient {
		t.Fatalf("same-address same-key should be established enough for impact: %#v", investigation)
	}
	if investigation.Impact.SeverityCeiling != models.ImpactKeyContinuity {
		t.Fatalf("ceiling = %q, want key_continuity (diagnosis=%q)", investigation.Impact.SeverityCeiling, diagnosis.PrimaryCode)
	}
	if !impactHasCode(investigation.Impact, "spki_unchanged") {
		t.Fatalf("missing proven SPKI effect: %#v", investigation.Impact.Effects)
	}
	if containsFold(investigation.Impact.Summary, "stolen") || containsFold(investigation.Impact.Summary, "was compromised") {
		t.Fatalf("same-key impact claimed theft: %q", investigation.Impact.Summary)
	}
	if !impactForbids(investigation.Impact, "private-key theft") && !impactForbids(investigation.Impact, "stolen") {
		t.Fatalf("must state private-key theft is not established: %#v", investigation.Impact.NotEstablished)
	}
}

func TestImpactUnreachableIsThisVantageOnly(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	item := models.Anomaly{Domain: "down.example", Type: "unreachable", OccurrenceCount: 4, DetectedAt: now}
	context := diagnosisContext{
		state: &models.DomainCertificate{
			Domain:              "down.example",
			Status:              models.StatusUnreachable,
			ConsecutiveFailures: 4,
			LastFailureClass:    "tls_timeout",
			LastScannedAt:       now,
		},
	}
	diagnosis := inferCertificateConditionDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if investigation.Impact == nil {
		t.Fatal("expected impact analysis")
	}
	if investigation.Impact.SeverityCeiling != models.ImpactMeasurementOnly {
		t.Fatalf("ceiling = %q, want measurement_only", investigation.Impact.SeverityCeiling)
	}
	if containsFold(investigation.Impact.Summary, "global outage") && !containsFold(investigation.Impact.Summary, "not a proven global") {
		t.Fatalf("unreachable was written as a global outage: %q", investigation.Impact.Summary)
	}
	if !impactForbids(investigation.Impact, "worldwide outage") {
		t.Fatalf("must refuse worldwide outage: %#v", investigation.Impact.NotEstablished)
	}
}

func impactHasCode(impact *models.FindingImpact, code string) bool {
	if impact == nil {
		return false
	}
	for _, effect := range impact.Effects {
		if effect.Code == code {
			return true
		}
	}
	return false
}

func impactForbids(impact *models.FindingImpact, needle string) bool {
	if impact == nil {
		return false
	}
	for _, line := range impact.NotEstablished {
		if containsFold(line, needle) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(impact.Summary), strings.ToLower(needle))
}
