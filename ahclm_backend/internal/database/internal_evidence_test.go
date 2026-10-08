package database

import (
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestSummarizeInternalEvidenceForContextRequiresPublicCorrelation(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	events := []models.InternalEvidenceEvent{
		{EventType: InternalEventRenewalPolicy, OccurredAt: base, SourceSystem: "controller", Status: "evaluated", CorrelationID: "run-1"},
		{EventType: InternalEventCertificateIssued, OccurredAt: base.Add(time.Minute), SourceSystem: "acme", Status: "succeeded", CorrelationID: "run-1", Fingerprint: fingerprint},
		{EventType: InternalEventDeployment, OccurredAt: base.Add(2 * time.Minute), SourceSystem: "edge", Status: "succeeded", CorrelationID: "run-1", Fingerprint: fingerprint},
	}
	withoutMatch := SummarizeInternalEvidenceForContext(events, "frequent_change", nil, nil, nil)
	if withoutMatch.Status != "partial" || withoutMatch.CorrelatedEvents != 0 {
		t.Fatalf("summary without public match = %+v, want partial and zero correlated events", withoutMatch)
	}
	withMatch := SummarizeInternalEvidenceForContext(events, "frequent_change", []models.Certificate{{Fingerprint: fingerprint}}, nil, nil)
	if withMatch.Status != "complete" || withMatch.CorrelatedEvents != 3 {
		t.Fatalf("summary with fingerprint match = %+v, want complete sequence", withMatch)
	}
}

func TestValidateInternalEvidenceRequiresCorrelationKey(t *testing.T) {
	event := &models.InternalEvidenceEvent{
		Domain: "example.com", OccurredAt: time.Now().UTC(), EventType: InternalEventDeployment, SourceSystem: "edge",
	}
	if err := validateInternalEvidence(event); err == nil {
		t.Fatal("event without a source or observation correlation key was accepted")
	}
}
