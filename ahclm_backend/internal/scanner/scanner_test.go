package scanner

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestEnrichWithoutRevocationOrARIEndpointIsNotApplicable(t *testing.T) {
	s := &Scanner{config: &models.ScannerConfig{CheckRevocation: true, CheckCRL: true}}
	result := &models.ScanResult{
		Success:  true,
		RawChain: []*x509.Certificate{{IsCA: false}},
	}

	s.enrichResult(context.Background(), result)

	if result.EvidenceStatus != models.EvidenceStatusNotApplicable {
		t.Fatalf("evidence status = %q, want %q", result.EvidenceStatus, models.EvidenceStatusNotApplicable)
	}
	if result.EvidencePendingReason == "" {
		t.Fatal("expected a reason for not-applicable evidence")
	}
}

func instantRetryAfter(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- time.Now()
	return ch
}

func TestScanWithRetryReturnsLastFailedResult(t *testing.T) {
	attempts := 0
	result, err := scanWithRetry(
		context.Background(),
		"example.com",
		2,
		func(_ context.Context, domain string) (*models.ScanResult, error) {
			attempts++
			return &models.ScanResult{
				Domain:  domain,
				Success: false,
				Error:   fmt.Sprintf("attempt %d failed", attempts),
			}, nil
		},
		instantRetryAfter,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	if result == nil || result.Success || result.Error != "attempt 3 failed" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestScanWithRetryStopsOnSuccess(t *testing.T) {
	attempts := 0
	result, err := scanWithRetry(
		context.Background(),
		"example.com",
		2,
		func(_ context.Context, domain string) (*models.ScanResult, error) {
			attempts++
			return &models.ScanResult{
				Domain:  domain,
				Success: attempts == 2,
				Error:   "temporary failure",
			}, nil
		},
		instantRetryAfter,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if result == nil || !result.Success {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestScanWithRetryDoesNotRepeatDeterministicEndpointFailure(t *testing.T) {
	attempts := 0
	result, err := scanWithRetry(
		context.Background(),
		"cdn.example.com",
		2,
		func(_ context.Context, domain string) (*models.ScanResult, error) {
			attempts++
			return &models.ScanResult{
				Domain:       domain,
				Success:      false,
				FailureClass: models.ScanFailureNoEndpoint,
				Error:        "TLS attempt failed: EOF",
			}, nil
		},
		instantRetryAfter,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	if result == nil || result.FailureClass != models.ScanFailureNoEndpoint {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestFailureClassForErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "dns", err: errors.New("dial tcp: lookup missing.example.com: no such host"), want: models.ScanFailureDNS},
		{name: "endpoint", err: errors.New("TLS handshake failed: EOF"), want: models.ScanFailureNoEndpoint},
		{name: "tls", err: errors.New("TLS handshake failed: remote error: tls: internal error"), want: models.ScanFailureTLS},
		{name: "network", err: errors.New("dial tcp: i/o timeout"), want: models.ScanFailureNetwork},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FailureClassForError(tc.err); got != tc.want {
				t.Fatalf("class = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestScanWithRetryReturnsAttemptErrorWhenNoResult(t *testing.T) {
	want := errors.New("scanner unavailable")
	result, err := scanWithRetry(
		context.Background(),
		"example.com",
		1,
		func(context.Context, string) (*models.ScanResult, error) {
			return nil, want
		},
		instantRetryAfter,
	)
	if result != nil {
		t.Fatalf("result = %+v, want nil", result)
	}
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}
