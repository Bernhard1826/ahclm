package scanner

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestFreshGlobalProbeContext(t *testing.T) {
	if requestsFreshGlobalProbes(context.Background()) {
		t.Fatal("ordinary scans must not request fresh Globalping probes")
	}
	if !requestsFreshGlobalProbes(withFreshGlobalProbes(context.Background())) {
		t.Fatal("explicit remeasurement must bypass cached Globalping probes")
	}
}

func TestFreshGlobalProbesUseOneHTTPSMeasurementAndBypassCache(t *testing.T) {
	var createCount int
	var createType string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			createCount++
			var request struct {
				Type string `json:"type"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode create request: %v", err)
			}
			createType = request.Type
			w.Header().Set("Location", server.URL+"/v1/measurements/fresh")
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"id":"fresh"}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":"fresh","status":"finished","results":[{"probe":{"continent":"EU","region":"Europe","country":"DE","city":"Berlin","asn":64500,"network":"test"},"result":{"status":"finished","statusCode":200,"resolvedAddress":"192.0.2.10","tls":{"authorized":true,"fingerprint256":"AA:BB","subject":{"CN":"example.com","alt":"DNS:example.com"}}}}]}`)
	}))
	defer server.Close()

	s := &Scanner{
		config:     &models.ScannerConfig{GlobalProbeEndpoint: server.URL, GlobalProbeLocations: []string{"EU"}},
		client:     server.Client(),
		globalPing: newServiceGate("Globalping", 0, 30*time.Minute, 10),
	}
	s.globalPing.store("global-probes:example.com", models.GlobalProbeEvidence{Provider: "cached"}, time.Now())

	evidence, err := s.fetchGlobalProbes(withFreshGlobalProbes(context.Background()), "example.com")
	if err != nil {
		t.Fatalf("fetch fresh global probes: %v", err)
	}
	if createCount != 1 || createType != "http" {
		t.Fatalf("created %d measurements with type %q, want one HTTPS measurement", createCount, createType)
	}
	if evidence == nil || evidence.HTTPSMeasurementID != "fresh" || evidence.DNSMeasurementID != "" {
		t.Fatalf("unexpected fresh probe measurement IDs: %+v", evidence)
	}
	if len(evidence.HTTPS) != 1 || evidence.HTTPS[0].ResolvedAddress != "192.0.2.10" || evidence.HTTPS[0].Fingerprint != "aabb" {
		t.Fatalf("unexpected fresh HTTPS evidence: %+v", evidence.HTTPS)
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

func TestRelatedNameDNSStatusAndTopologyOverlap(t *testing.T) {
	missing := &models.TopologySnapshot{Resolvers: []models.DNSResolverObservation{
		{Error: "resolver returned no usable public records"},
		{Error: "resolver returned CNAME but no usable public address"},
	}}
	if got := relatedNameDNSStatus(missing); got != "no_public_address" {
		t.Fatalf("DNS status = %q, want no_public_address", got)
	}
	partial := &models.TopologySnapshot{Resolvers: []models.DNSResolverObservation{
		{Error: "resolver returned no usable public records"},
		{Error: "temporary DNS timeout"},
	}}
	if got := relatedNameDNSStatus(partial); got != "inconclusive" {
		t.Fatalf("DNS status = %q, want inconclusive", got)
	}
	if !overlappingStrings([]string{"198.51.100.10", "target.example"}, []string{"TARGET.EXAMPLE"}) {
		t.Fatal("expected case-insensitive shared topology item")
	}
	if overlappingStrings([]string{"198.51.100.10"}, []string{"198.51.100.11"}) {
		t.Fatal("different topology items reported as shared")
	}
}

func TestRelatedNameCandidateRotationAdvancesByWholeBatch(t *testing.T) {
	candidates := []models.RelatedNameCandidate{
		{Name: "one.example.com"}, {Name: "two.example.com"}, {Name: "three.example.com"},
		{Name: "four.example.com"}, {Name: "five.example.com"},
	}
	batch := func(rotation int) []string {
		selected := selectRelatedNameCandidates("example.com", candidates, 2, rotation)
		out := make([]string, 0, len(selected))
		for _, candidate := range selected {
			out = append(out, candidate.Name)
		}
		return out
	}
	if got, want := strings.Join(batch(0), ","), "one.example.com,two.example.com"; got != want {
		t.Fatalf("rotation 0 = %q, want %q", got, want)
	}
	if got, want := strings.Join(batch(1), ","), "three.example.com,four.example.com"; got != want {
		t.Fatalf("rotation 1 = %q, want %q", got, want)
	}
	if got, want := strings.Join(batch(2), ","), "five.example.com,one.example.com"; got != want {
		t.Fatalf("rotation 2 = %q, want %q", got, want)
	}
}
