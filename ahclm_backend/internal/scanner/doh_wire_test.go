package scanner

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ahclm/internal/models"

	"golang.org/x/net/dns/dnsmessage"
)

// Quad9's /dns-query rejects the JSON name/type form with 400; the scanner must
// retry in RFC 8484 wire format instead of recording a failed resolver.
func TestDoHFallsBackToWireFormat(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("dns")
		if raw == "" {
			http.Error(w, "DoH unable to decode BASE64-URL", http.StatusBadRequest)
			return
		}
		packed, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			t.Fatal(err)
		}
		var query dnsmessage.Message
		if err := query.Unpack(packed); err != nil {
			t.Fatal(err)
		}
		reply := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true},
			Questions: query.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}},
			}},
		}
		body, _ := reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport)
	saved := transport.TLSClientConfig
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig
	defer func() { transport.TLSClientConfig = saved }()
	s := &Scanner{config: &models.ScannerConfig{Timeout: 5 * time.Second}}
	payload, err := s.queryDoHPayload(context.Background(), server.URL+"/dns-query", "example.com", "A")
	if err != nil {
		t.Fatalf("wire fallback failed: %v", err)
	}
	if len(payload.Answer) != 1 || payload.Answer[0].Data != "192.0.2.7" || payload.Answer[0].Type != 1 {
		t.Fatalf("answer = %#v", payload.Answer)
	}
}
