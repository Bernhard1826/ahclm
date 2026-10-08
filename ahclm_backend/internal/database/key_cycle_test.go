package database

import (
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestPublicKeyCycleTreatsNotBeforeAsLowerBound(t *testing.T) {
	issued := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	seen := issued.Add(48 * time.Hour)
	certs := []models.Certificate{{
		Fingerprint:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SPKIFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		NotBefore:       issued, FirstSeenAt: seen,
	}}
	cycle := BuildPublicKeyDeploymentCycle("example.com", certs, nil, nil, nil)
	if cycle.Status != "external_only" {
		t.Fatalf("status = %s, want external_only without control-plane events", cycle.Status)
	}
	if cycle.Metrics.IssuanceToFirstPublicSeconds == nil || *cycle.Metrics.IssuanceToFirstPublicSeconds != 48*3600 {
		t.Fatalf("issuance-to-first-public = %v, want 48h", cycle.Metrics.IssuanceToFirstPublicSeconds)
	}
	var lowerBound bool
	for _, event := range cycle.Events {
		if event.Kind == "not_before_lower_bound" && event.LowerBound {
			lowerBound = true
		}
		if event.Kind == "deployed" {
			t.Fatal("a public observation must not be labeled as an exact deployment")
		}
	}
	if !lowerBound {
		t.Fatal("NotBefore was not recorded as a lower bound")
	}
}

func TestPublicKeyCycleUsesImportedDeploymentTime(t *testing.T) {
	issued := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	deployed := issued.Add(6 * time.Hour)
	fingerprint := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	certs := []models.Certificate{{Fingerprint: fingerprint, SPKIFingerprint: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", NotBefore: issued, FirstSeenAt: deployed.Add(time.Hour)}}
	events := []models.InternalEvidenceEvent{
		{ID: 1, Domain: "example.com", OccurredAt: issued.Add(time.Minute), EventType: InternalEventCertificateIssued, SourceSystem: "acme", Fingerprint: fingerprint, Status: "succeeded"},
		{ID: 2, Domain: "example.com", OccurredAt: deployed, EventType: InternalEventDeployment, SourceSystem: "edge", Fingerprint: fingerprint, Status: "succeeded", CorrelationID: "rel-9"},
		{ID: 3, Domain: "example.com", OccurredAt: issued, EventType: InternalEventRenewalPolicy, SourceSystem: "controller", Status: "evaluated", CorrelationID: "rel-9"},
	}
	cycle := BuildPublicKeyDeploymentCycle("example.com", certs, nil, nil, events)
	if cycle.Status != "complete" {
		t.Fatalf("status = %s, want complete once policy, issuance and deployment correlate", cycle.Status)
	}
	if cycle.Metrics.FirstIssuedExactAt == nil || !cycle.Metrics.FirstIssuedExactAt.Equal(issued.Add(time.Minute)) {
		t.Fatalf("first exact issuance = %v, want imported issuance event", cycle.Metrics.FirstIssuedExactAt)
	}
	if cycle.Metrics.FirstDeployedAt == nil || !cycle.Metrics.FirstDeployedAt.Equal(deployed) {
		t.Fatalf("first deployment = %v, want imported deployment event", cycle.Metrics.FirstDeployedAt)
	}
	if cycle.Metrics.DeploymentToFirstPublicSeconds == nil || *cycle.Metrics.DeploymentToFirstPublicSeconds != 3600 {
		t.Fatalf("deployment-to-first-public = %v, want 1h", cycle.Metrics.DeploymentToFirstPublicSeconds)
	}
	found := false
	for _, event := range cycle.Events {
		if event.Kind == "deployed" && event.EvidenceID == 2 && !event.LowerBound {
			found = true
		}
	}
	if !found {
		t.Fatal("imported deployment event was not kept as an exact timeline point")
	}
}

func TestPublicKeyCycleCountsSameKeyReplacement(t *testing.T) {
	spki := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	observations := []models.CertObservation{{
		ObservationType: models.ObsChange, ObservedAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		PreviousFingerprint:     "1111111111111111111111111111111111111111111111111111111111111111",
		Fingerprint:             "2222222222222222222222222222222222222222222222222222222222222222",
		PreviousSPKIFingerprint: spki, SPKIFingerprint: spki,
	}}
	cycle := BuildPublicKeyDeploymentCycle("example.com", nil, observations, nil, nil)
	if cycle.SameKeyReplacements != 1 {
		t.Fatalf("same-key replacements = %d, want 1", cycle.SameKeyReplacements)
	}
}
