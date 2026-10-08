package database

import (
	"encoding/json"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestRelatedNameCandidatesUseOnlyChangedSubdomainSANs(t *testing.T) {
	observed := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	observations := []models.CertObservation{
		{ObservedAt: observed, PreviousFingerprint: "old", Fingerprint: "new"},
		{ObservedAt: observed.Add(time.Hour), PreviousFingerprint: "new", Fingerprint: "later"},
	}
	certificates := map[string]models.Certificate{
		"old":   {Fingerprint: "old", SANs: `["example.com","*.example.com","stable.example.com"]`},
		"new":   {Fingerprint: "new", SANs: `["example.com","stable.example.com","feat-42-preview.example.com"]`},
		"later": {Fingerprint: "later", SANs: `["example.com","stable.example.com"]`},
	}

	candidates := relatedNameCandidates("example.com", observations, certificates, 0)
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v, want exactly the changed concrete subdomain", candidates)
	}
	got := candidates[0]
	if got.Name != "feat-42-preview.example.com" || got.AddedCount != 1 || got.RemovedCount != 1 || !got.BranchLikeLabel {
		t.Fatalf("candidate = %#v, want added+removed branch-like preview name", got)
	}
	if !got.FirstObservedAt.Equal(observed) || !got.LastObservedAt.Equal(observed.Add(time.Hour)) {
		t.Fatalf("observation window = %s..%s", got.FirstObservedAt, got.LastObservedAt)
	}
}

func TestTransientRelatedNameEvidenceNeedsPublicAbsenceAndRemoval(t *testing.T) {
	investigation := &models.Investigation{RelatedNames: []models.RelatedNameProbe{
		{Name: "feat-preview.example.com", BranchLikeLabel: true, RemovedCount: 1, DNSStatus: "no_public_address"},
		{Name: "preview-still-live.example.com", BranchLikeLabel: true, RemovedCount: 1, DNSStatus: "active"},
		{Name: "ordinary.example.com", RemovedCount: 1, DNSStatus: "no_public_address"},
	}}
	evidence := transientRelatedNameEvidence(investigation, 8)
	if len(evidence) != 1 || evidence[0] == "" {
		t.Fatalf("transient evidence = %#v, want only removed branch-like name with no public address", evidence)
	}
	if want := "feat-preview.example.com"; !containsFold(evidence[0], want) {
		t.Fatalf("evidence = %q, want %q", evidence[0], want)
	}
}

func TestRelatedNameProbePrioritiesPutUnmeasuredAndInconclusiveNamesFirst(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	probes, err := json.Marshal([]models.RelatedNameProbe{
		{Name: "resolved.example.com", ProbedAt: now, DNSStatus: "no_public_address"},
		{Name: "retry.example.com", ProbedAt: now, DNSStatus: "inconclusive"},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidates := []models.RelatedNameCandidate{{Name: "resolved.example.com"}, {Name: "retry.example.com"}, {Name: "new.example.com"}}
	markRelatedNameProbePriorities(candidates, []models.MeasurementSnapshot{{RelatedNamesJSON: string(probes)}})
	if candidates[0].NeedsPriorityProbe || !candidates[1].NeedsPriorityProbe || !candidates[2].NeedsPriorityProbe {
		t.Fatalf("priority flags = %#v", candidates)
	}
}
