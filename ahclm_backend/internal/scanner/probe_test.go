package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"ahclm/internal/models"
)

func testLeaf(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func probeScanner(handshakes int) *Scanner {
	rl := make(chan struct{}, 4)
	for i := 0; i < 4; i++ {
		rl <- struct{}{}
	}
	return &Scanner{config: &models.ScannerConfig{Timeout: time.Second, MaxEndpointSamples: 2, EndpointHandshakes: handshakes, EndpointProbeConcurrency: 2}, rateLimit: rl}
}

// dingtalk.com: one address fronting servers with different leaves. Repeated
// handshakes within one round record the second leaf on the same probe.
func TestRepeatedHandshakesProveAddressPool(t *testing.T) {
	leaves := []*x509.Certificate{testLeaf(t, 1), testLeaf(t, 2)}
	var calls int64
	s := probeScanner(3)
	s.probeHandshake = func(_ context.Context, _, _ string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
		n := atomic.AddInt64(&calls, 1)
		return []*x509.Certificate{leaves[n%2]}, nil, &models.ConnectionInfo{}, nil
	}
	probes := s.ProbeEndpointsRotated(context.Background(), "example.com", []string{"8.8.8.8"}, 0)
	if len(probes) != 1 || !probes[0].Success || probes[0].Handshakes != 3 || len(probes[0].OtherFingerprints) != 1 {
		t.Fatalf("pool not recorded: %#v", probes)
	}
}

func TestEndpointProbeRecordsNoSNISelection(t *testing.T) {
	withSNI := testLeaf(t, 10)
	withoutSNI := testLeaf(t, 11)
	s := probeScanner(1)
	s.probeHandshakeWithSNI = func(_ context.Context, _, _ string, serverName string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
		if serverName == "" {
			return []*x509.Certificate{withoutSNI}, nil, &models.ConnectionInfo{NegotiatedProtocol: "http/1.1"}, nil
		}
		return []*x509.Certificate{withSNI}, nil, &models.ConnectionInfo{NegotiatedProtocol: "h2"}, nil
	}

	probes := s.ProbeEndpointsRotated(context.Background(), "example.com", []string{"8.8.8.8"}, 0)
	if len(probes) != 1 {
		t.Fatalf("probes = %#v, want one", probes)
	}
	probe := probes[0]
	if probe.RequestedSNI != "example.com" {
		t.Fatalf("requested SNI = %q, want example.com", probe.RequestedSNI)
	}
	if probe.Fingerprint != models.Fingerprint(withSNI) {
		t.Fatalf("primary fingerprint = %q, want SNI-selected leaf", probe.Fingerprint)
	}
	if len(probe.SelectionProbes) != 1 {
		t.Fatalf("selection probes = %#v, want one no-SNI comparison", probe.SelectionProbes)
	}
	selection := probe.SelectionProbes[0]
	if selection.Variant != "no_sni" || selection.RequestedSNI != "" || !selection.Success {
		t.Fatalf("selection metadata = %#v", selection)
	}
	if selection.Fingerprint != models.Fingerprint(withoutSNI) {
		t.Fatalf("no-SNI fingerprint = %q, want default leaf", selection.Fingerprint)
	}
	if selection.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("no-SNI ALPN = %q, want http/1.1", selection.NegotiatedProtocol)
	}
	if probe.SelectionAnalysis == nil || probe.SelectionAnalysis.Interpretation != "sni_selects_alternate_name_matching_certificate" {
		t.Fatalf("selection analysis = %#v, want alternate name-matching SNI selection", probe.SelectionAnalysis)
	}
	if !probe.SelectionAnalysis.CertificateChanged || !probe.SelectionAnalysis.SelectedCoversRequestedName || !probe.SelectionAnalysis.DefaultCoversRequestedName {
		t.Fatalf("selection analysis flags = %#v", probe.SelectionAnalysis)
	}
}

// Past the sampling cap, successive rounds sample different addresses.
func TestSamplingWindowRotatesPastCap(t *testing.T) {
	s := probeScanner(1)
	leaf := testLeaf(t, 3)
	s.probeHandshake = func(_ context.Context, _, _ string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
		return []*x509.Certificate{leaf}, nil, &models.ConnectionInfo{}, nil
	}
	ips := []string{"8.8.8.1", "8.8.8.2", "8.8.8.3"}
	seen := map[string]bool{}
	for round := 0; round < 3; round++ {
		for _, probe := range s.ProbeEndpointsRotated(context.Background(), "example.com", ips, round) {
			seen[probe.IPAddress] = true
		}
	}
	if len(seen) != 3 {
		t.Fatalf("rotation never sampled every address: %v", seen)
	}
}

// Without an IPv6 route the address is unobservable, not a failed endpoint,
// and nothing is dialled.
func TestNoIPv6RouteMarksAddressUnobservable(t *testing.T) {
	s := probeScanner(1)
	s.ipv6Route = false
	s.probeHandshake = func(_ context.Context, _, _ string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
		t.Fatal("dialled an address this vantage cannot reach")
		return nil, nil, nil, nil
	}
	probes := s.ProbeEndpointsRotated(context.Background(), "example.com", []string{"2606:4700::1"}, 0)
	if len(probes) != 1 || !probes[0].Unobservable || probes[0].Success {
		t.Fatalf("probe = %#v", probes)
	}
}

// After HTTP 429 the gate stops sending until Retry-After has passed and
// reuses cached answers.
func TestServiceGateHonorsRetryAfter(t *testing.T) {
	gate := newServiceGate("crt.sh", 0, time.Hour, 10)
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	gate.observe(&http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"120"}}}, now)
	if _, err := gate.reserve(now.Add(time.Minute)); err == nil {
		t.Fatal("sent during the cooldown")
	}
	if _, err := gate.reserve(now.Add(3 * time.Minute)); err != nil {
		t.Fatalf("still blocked after Retry-After: %v", err)
	}
	gate.store("q", []models.CTObservation{{SHA256: "a"}}, now)
	if value, ok := gate.cached("q", now.Add(30*time.Minute)); !ok || len(value.([]models.CTObservation)) != 1 {
		t.Fatal("cached answer not reused")
	}
}

func TestServiceGateHonorsRateLimitResetHeaders(t *testing.T) {
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{name: "absolute X-RateLimit-Reset", header: "X-RateLimit-Reset", value: strconv.FormatInt(now.Add(120*time.Second).Unix(), 10)},
		{name: "delta RateLimit-Reset", header: "RateLimit-Reset", value: "120"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gate := newServiceGate("globalping", 0, 0, 1)
			gate.observe(&http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{tt.header: []string{tt.value}}}, now)
			if _, err := gate.reserve(now.Add(time.Minute)); err == nil {
				t.Fatalf("sent during the header-defined cooldown")
			}
			if _, err := gate.reserve(now.Add(3 * time.Minute)); err != nil {
				t.Fatalf("still blocked after header-defined cooldown: %v", err)
			}
		})
	}
}
