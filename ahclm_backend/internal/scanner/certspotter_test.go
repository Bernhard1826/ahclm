package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestCertSpotterParsesIssuanceByFingerprint(t *testing.T) {
	payload := []map[string]any{{
		"id":          "1",
		"cert_sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		"dns_names":   []string{"example.com"},
		"not_before":  "2026-01-01T00:00:00Z",
		"not_after":   "2026-04-01T00:00:00Z",
		"issuer":      map[string]any{"name": "C=US, O=Let's Encrypt, CN=R3"},
	}}
	body, _ := json.Marshal(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cert_sha256") == "" {
			t.Fatalf("query = %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer server.Close()
	s := &Scanner{config: &models.ScannerConfig{
		Timeout:             time.Second,
		CTTimeout:           time.Second,
		CertSpotterEndpoint: server.URL,
	}}
	entries, err := s.fetchCertSpotter(context.Background(), &models.ScanResult{
		Cert: &models.Certificate{Fingerprint: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", SerialNumber: "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Source != "certspotter" {
		t.Fatalf("entries = %#v", entries)
	}
}
