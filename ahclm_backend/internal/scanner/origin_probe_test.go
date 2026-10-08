package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestOriginProbesUseDistinctRegionalNoncesAndRetainCertificateHeaders(t *testing.T) {
	var mu sync.Mutex
	nonces := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var request struct {
				Locations []struct {
					Continent string `json:"continent"`
				} `json:"locations"`
				Options struct {
					Request struct {
						Path string `json:"path"`
					} `json:"request"`
				} `json:"measurementOptions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if len(request.Locations) != 1 {
				t.Error("origin probes must not share a nonce between regions")
				w.WriteHeader(400)
				return
			}
			region := request.Locations[0].Continent
			u, _ := url.ParseRequestURI(request.Options.Request.Path)
			mu.Lock()
			nonces[region] = u.Query().Get("_ahclm_probe")
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": region})
			return
		}
		region := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		mu.Lock()
		nonce := nonces[region]
		mu.Unlock()
		result := map[string]any{"status": "finished", "statusCode": 200, "headers": map[string]string{"x-ahclm-origin-fingerprint": strings.Repeat("ab", 32), "x-ahclm-probe": nonce, "x-ahclm-origin-tls-resumed": "false", "set-cookie": "must not persist"}, "tls": map[string]any{"authorized": true, "fingerprint256": "AA:BB"}}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": region, "status": "finished", "results": []any{map[string]any{"probe": map[string]string{"continent": region}, "result": result}}})
	}))
	defer server.Close()
	scan := &Scanner{config: &models.ScannerConfig{GlobalProbeEndpoint: server.URL}, client: server.Client(), globalPing: newServiceGate("test", 0, 0, 8)}
	evidence, err := scan.MeasureGlobalHTTPSPath(context.Background(), "www.example.com", "www.example.com", "/.well-known/ahclm-origin", []string{"AS", "EU"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.HTTPS) != 2 || len(evidence.HTTPSMeasurementIDs) != 2 {
		t.Fatalf("missing regional evidence: %+v", evidence)
	}
	if evidence.HTTPS[0].RequestNonce == evidence.HTTPS[1].RequestNonce {
		t.Fatal("regions shared a cache key")
	}
	for _, probe := range evidence.HTTPS {
		if len(probe.RequestNonce) != 32 || probe.RequestNonce != probe.OriginProbeNonce || probe.OriginFingerprint != strings.Repeat("ab", 32) || probe.OriginTLSResumed != "false" || probe.ObservedAt == nil || time.Since(*probe.ObservedAt) > time.Minute {
			t.Fatalf("incomplete origin evidence: %+v", probe)
		}
	}
	encoded, _ := json.Marshal(evidence)
	if strings.Contains(string(encoded), "must not persist") {
		t.Fatal("unrelated response header persisted")
	}
}

func TestOriginHeaderParsingRejectsDuplicateProof(t *testing.T) {
	result := globalPingProbeResult{RawHeaders: "HTTP/1.1 200 OK\r\nX-AHCLM-Probe: nonce\r\n"}
	if globalResponseHeader(result, "X-AHCLM-Probe") != "nonce" {
		t.Fatal("raw response header not parsed")
	}
	result.RawHeaders += "X-AHCLM-Probe: other\r\n"
	if globalResponseHeader(result, "X-AHCLM-Probe") != "" {
		t.Fatal("ambiguous proof accepted")
	}
	result = globalPingProbeResult{Headers: map[string]json.RawMessage{"x-ahclm-probe": json.RawMessage(`["one","two"]`)}}
	if globalResponseHeader(result, "X-AHCLM-Probe") != "" {
		t.Fatal("multiple structured values accepted")
	}
}
