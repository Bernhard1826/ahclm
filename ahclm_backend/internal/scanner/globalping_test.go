package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestGlobalTraceAnswersKeepsFinalAuthoritativeAnswer(t *testing.T) {
	raw := `;; Received 100 bytes from 198.41.0.4#53(a.root-servers.net) in 1 ms

example.com.	172800	IN	NS	ns.example.net.
;; Received 100 bytes from 192.0.2.53#53(ns.example.net) in 2 ms

example.com.	300	IN	A	203.0.113.10
example.com.	300	IN	A	203.0.113.11
;; Received 100 bytes from 203.0.113.53#53(ns1.example.com) in 3 ms
`
	answers := globalTraceAnswers(raw, "example.com")
	if len(answers) != 2 || answers[0].Type != "A" || answers[0].Value != "203.0.113.10" || answers[1].Value != "203.0.113.11" {
		t.Fatalf("unexpected trace answers: %#v", answers)
	}
}

func TestParseGlobalPingSANs(t *testing.T) {
	got := parseGlobalPingSANs("DNS:b.example, DNS:a.example, DNS:a.example")
	if len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("unexpected SANs: %#v", got)
	}
}

func TestMeasureGlobalHTTPSUsesRequestedRegionsAndParsesLeaf(t *testing.T) {
	var requested []map[string]interface{}
	var authorization []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = append(authorization, r.Header.Get("Authorization"))
		if r.Method == http.MethodPost {
			var body struct {
				Type      string                   `json:"type"`
				Target    string                   `json:"target"`
				Locations []map[string]interface{} `json:"locations"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode measurement request: %v", err)
			}
			if body.Type != "http" || body.Target != "example.com" {
				t.Errorf("request = type %q target %q", body.Type, body.Target)
			}
			requested = body.Locations
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"id":"measure-1"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"measure-1","status":"finished","results":[{"probe":{"continent":"NA","country":"US","city":"New York"},"result":{"status":"finished","resolvedAddress":"203.0.113.10","tls":{"authorized":true,"fingerprint256":"AA:BB","subject":{"CN":"example.com","alt":"DNS:example.com"}}}}]}`))
	}))
	defer server.Close()

	scan := &Scanner{
		config:     &models.ScannerConfig{GlobalProbeEndpoint: server.URL, GlobalProbeTimeout: time.Second, GlobalProbeToken: "test-token", UserAgent: "test"},
		client:     server.Client(),
		globalPing: newServiceGate("test", 0, 0, 8),
	}
	evidence, err := scan.MeasureGlobalHTTPS(context.Background(), "HTTPS://Example.com/path", []string{"na", "eu"})
	if err != nil {
		t.Fatalf("measure global HTTPS: %v", err)
	}
	if len(requested) != 2 || requested[0]["continent"] != "EU" || requested[1]["continent"] != "NA" {
		t.Fatalf("requested locations = %#v", requested)
	}
	if len(authorization) != 2 || authorization[0] != "Bearer test-token" || authorization[1] != "Bearer test-token" {
		t.Fatalf("authorization headers = %#v", authorization)
	}
	if evidence.HTTPSMeasurementID != "measure-1" || len(evidence.HTTPS) != 1 {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
	probe := evidence.HTTPS[0]
	if !probe.TLSObserved || !probe.TLSAuthorized || probe.Fingerprint != "aabb" || probe.ResolvedAddress != "203.0.113.10" || probe.Location.Continent != "NA" {
		t.Fatalf("unexpected parsed probe: %#v", probe)
	}
}

func TestMeasureGlobalHTTPSWithTargetSetsOriginHostForIPTarget(t *testing.T) {
	var gotTarget, gotHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct {
				Target  string `json:"target"`
				Options struct {
					Request struct {
						Host string `json:"host"`
					} `json:"request"`
				} `json:"measurementOptions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode measurement request: %v", err)
			}
			gotTarget, gotHost = body.Target, body.Options.Request.Host
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"id":"origin-measurement"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"origin-measurement","status":"finished","results":[{"probe":{"continent":"EU"},"result":{"status":"finished","resolvedAddress":"1.1.1.1","tls":{"authorized":true,"fingerprint256":"AA:BB","subject":{"CN":"origin.example.com","alt":"DNS:origin.example.com"}}}}]}`))
	}))
	defer server.Close()

	scan := &Scanner{
		config:     &models.ScannerConfig{GlobalProbeEndpoint: server.URL, GlobalProbeTimeout: time.Second, UserAgent: "test"},
		client:     server.Client(),
		globalPing: newServiceGate("test", 0, 0, 8),
	}
	evidence, err := scan.MeasureGlobalHTTPSWithTarget(context.Background(), "1.1.1.1", "origin.example.com", []string{"eu"})
	if err != nil {
		t.Fatalf("measure origin target: %v", err)
	}
	if gotTarget != "1.1.1.1" || gotHost != "origin.example.com" {
		t.Fatalf("target/host = %q/%q, want 1.1.1.1/origin.example.com", gotTarget, gotHost)
	}
	if evidence.HTTPSMeasurementID != "origin-measurement" || len(evidence.HTTPS) != 1 || evidence.HTTPS[0].Fingerprint != "aabb" {
		t.Fatalf("unexpected origin evidence: %#v", evidence)
	}
}

func TestMeasureGlobalHTTPSPathUsesCacheBustingGETThroughCDNHost(t *testing.T) {
	var gotTarget, gotHost, gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct {
				Target  string `json:"target"`
				Options struct {
					Request struct {
						Method string `json:"method"`
						Path   string `json:"path"`
						Host   string `json:"host"`
					} `json:"request"`
				} `json:"measurementOptions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode measurement request: %v", err)
			}
			gotTarget, gotHost = body.Target, body.Options.Request.Host
			gotMethod, gotPath = body.Options.Request.Method, body.Options.Request.Path
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"id":"cdn-origin-check"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cdn-origin-check","status":"finished","results":[{"probe":{"continent":"EU"},"result":{"status":"finished","statusCode":200,"tls":{"authorized":true,"fingerprint256":"AA:BB","subject":{"CN":"www.example.com","alt":"DNS:www.example.com"}}}}]}`))
	}))
	defer server.Close()

	scan := &Scanner{
		config:     &models.ScannerConfig{GlobalProbeEndpoint: server.URL, GlobalProbeTimeout: time.Second, UserAgent: "test"},
		client:     server.Client(),
		globalPing: newServiceGate("test", 0, 0, 8),
	}
	evidence, err := scan.MeasureGlobalHTTPSPath(context.Background(), "www.example.com", "www.example.com", "/healthz?probe=origin", []string{"eu"})
	if err != nil {
		t.Fatalf("measure CDN origin path: %v", err)
	}
	if gotTarget != "www.example.com" || gotHost != "www.example.com" || gotMethod != "GET" {
		t.Fatalf("target/host/method = %q/%q/%q", gotTarget, gotHost, gotMethod)
	}
	if !strings.HasPrefix(gotPath, "/healthz?") || !strings.Contains(gotPath, "probe=origin") || !strings.Contains(gotPath, "_ahclm_probe=") {
		t.Fatalf("probe path = %q, want configured and cache-busting query parameters", gotPath)
	}
	if len(evidence.HTTPS) != 1 || evidence.HTTPS[0].HTTPStatus != http.StatusOK || !evidence.HTTPS[0].TLSAuthorized {
		t.Fatalf("unexpected CDN origin response evidence: %#v", evidence)
	}
}

func TestMeasureGlobalHTTPSWithTargetRejectsNonPublicIP(t *testing.T) {
	scan := &Scanner{config: &models.ScannerConfig{}, globalPing: newServiceGate("test", 0, 0, 8)}
	if _, err := scan.MeasureGlobalHTTPSWithTarget(context.Background(), "192.168.1.10", "origin.example.com", []string{"eu"}); err == nil {
		t.Fatal("private origin IP should be rejected")
	}
}

func TestRefreshGlobalPingCreateLimitIncludesCredits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/limits" {
			t.Fatalf("path = %q, want /v1/limits", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"rateLimit":{"measurements":{"create":{"remaining":2,"reset":600}}},"credits":{"remaining":1}}`))
	}))
	defer server.Close()

	gate := newServiceGate("test", 0, 0, 8)
	gate.setCooldown(time.Now().Add(time.Hour))
	scan := &Scanner{
		config:     &models.ScannerConfig{GlobalProbeEndpoint: server.URL, GlobalProbeTimeout: time.Second},
		client:     server.Client(),
		globalPing: gate,
	}
	if err := scan.refreshGlobalPingCreateLimit(context.Background(), 3); err != nil {
		t.Fatalf("refresh Globalping create limit: %v", err)
	}
	if _, err := gate.reserve(time.Now()); err != nil {
		t.Fatalf("two free tests plus one credit should allow three tests: %v", err)
	}
}

func TestFetchGlobalProbesDefersWhenRoutineBudgetIsInsufficient(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		http.Error(w, "unexpected Globalping request", http.StatusInternalServerError)
	}))
	defer server.Close()

	scan := &Scanner{
		config: &models.ScannerConfig{
			GlobalProbeEndpoint:  server.URL,
			GlobalProbeLocations: []string{"NA", "EU", "AS"},
		},
		client:                server.Client(),
		globalPing:            newServiceGate("test", 0, 0, 8),
		globalProbeScanBudget: newGlobalProbeScanBudget(5),
	}
	_, err := scan.fetchGlobalProbes(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "needs 6") {
		t.Fatalf("error = %v, want budget deferral for six tests", err)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("Globalping requests = %d, want no provider request", got)
	}
}

func TestMeasureGlobalHTTPSRetriesRateLimitedStatusPoll(t *testing.T) {
	var polls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"id":"measure-retry"}`))
			return
		}

		if atomic.AddInt32(&polls, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"poll rate limit"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"measure-retry","status":"finished","results":[]}`))
	}))
	defer server.Close()

	scan := &Scanner{
		config:     &models.ScannerConfig{GlobalProbeEndpoint: server.URL, GlobalProbeTimeout: 3 * time.Second, GlobalProbeToken: "test-token", UserAgent: "test"},
		client:     server.Client(),
		globalPing: newServiceGate("test", 0, 0, 8),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	evidence, err := scan.MeasureGlobalHTTPS(ctx, "example.com", []string{"na"})
	if err != nil {
		t.Fatalf("measure global HTTPS after status-poll rate limit: %v", err)
	}
	if evidence.HTTPSMeasurementID != "measure-retry" {
		t.Fatalf("measurement id = %q, want measure-retry", evidence.HTTPSMeasurementID)
	}
	if got := atomic.LoadInt32(&polls); got != 2 {
		t.Fatalf("status polls = %d, want one retry after the 429", got)
	}
}
