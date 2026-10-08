package models

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizePropagationLocations(t *testing.T) {
	got := NormalizePropagationLocations([]string{"eu", " NA ", "EU", "", "as"})
	want := []string{"AS", "EU", "NA"}
	if len(got) != len(want) {
		t.Fatalf("locations = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("locations = %#v, want %#v", got, want)
		}
	}
}

func TestOriginViaCDNRequiresUncachedPathAndSourceTimestamp(t *testing.T) {
	updatedAt := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	req := CDNPropagationStartRequest{
		Domain:            "www.example.com",
		CertificateLayer:  CDNPropagationLayerOriginViaCDN,
		ProbePath:         "/healthz?check=origin",
		TargetFingerprint: strings.Repeat("ab", 32),
		SourceUpdatedAt:   &updatedAt,
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("valid CDN origin request was rejected: %v", err)
	}
	req.TargetFingerprint = ""
	if err := req.Validate(); err == nil {
		t.Fatal("missing origin certificate fingerprint accepted")
	}
	req.TargetFingerprint = strings.Repeat("ab", 32)
	req.SourceUpdatedAt = nil
	if err := req.Validate(); err == nil {
		t.Fatal("missing source certificate update time should be rejected")
	}
	req.SourceUpdatedAt = &updatedAt
	req.ProbePath = "https://example.com/healthz"
	if err := req.Validate(); err == nil {
		t.Fatal("absolute URL should not be accepted as a request path")
	}
}

func TestPropagationRequestRequiresSHA256Fingerprints(t *testing.T) {
	req := CDNPropagationStartRequest{Domain: "example.com", TargetFingerprint: "a"}
	if err := req.Validate(); err == nil {
		t.Fatal("short target fingerprint should be rejected")
	}
	req.TargetFingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := req.Validate(); err != nil {
		t.Fatalf("valid target fingerprint was rejected: %v", err)
	}
}

func TestPropagationRequestRejectsSameFingerprints(t *testing.T) {
	fingerprint := strings.Repeat("ab", 32)
	req := CDNPropagationStartRequest{Domain: "example.com", PreviousFingerprint: fingerprint, TargetFingerprint: strings.ToUpper(fingerprint)}
	if err := req.Validate(); err == nil {
		t.Fatal("identical previous and target fingerprints should be rejected")
	}
}

func TestPropagationWatcherDoesNotRequireTargetFingerprint(t *testing.T) {
	req := CDNPropagationStartRequest{
		Domain:           "example.com",
		CertificateLayer: CDNPropagationLayerEdge,
		WatchChanges:     true,
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("valid edge watcher was rejected: %v", err)
	}
	req.CertificateLayer = CDNPropagationLayerOrigin
	if err := req.Validate(); err == nil {
		t.Fatal("origin watcher without an IP and SNI/Host should be rejected")
	}
	req.ProbeTarget = "192.0.2.10"
	req.ProbeHost = "origin.example.com"
	if err := req.Validate(); err == nil {
		t.Fatal("origin watcher with a documentation IP should be rejected")
	}
	req.ProbeTarget = "1.1.1.1"
	if err := req.Validate(); err != nil {
		t.Fatalf("valid direct-origin watcher was rejected: %v", err)
	}
}

func TestPropagationLocationKeyUsesContinentBucket(t *testing.T) {
	first := PropagationLocationKey(GlobalProbeLocation{Continent: "na", City: "New York"})
	second := PropagationLocationKey(GlobalProbeLocation{Continent: "NA", City: "Chicago"})
	if first != "NA" || second != first {
		t.Fatalf("location keys = %q and %q, want stable NA bucket", first, second)
	}
}
