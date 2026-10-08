package scanner

import (
	"ahclm/internal/models"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCodeAuditSecondLeafMustBeValidated(t *testing.T) {
	good := testLeaf(t, 1001)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1002), Subject: pkix.Name{CommonName: "wrong.example"}, DNSNames: []string{"wrong.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s := probeScanner(2)
	calls := 0
	s.probeHandshakeWithSNI = func(_ context.Context, _, _, name string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
		if name != "" {
			calls++
			if calls == 2 {
				return []*x509.Certificate{bad}, nil, &models.ConnectionInfo{}, nil
			}
		}
		return []*x509.Certificate{good}, nil, &models.ConnectionInfo{}, nil
	}
	ps := s.ProbeEndpointsRotated(context.Background(), "example.com", []string{"8.8.8.8"}, 0)
	if len(ps) != 1 {
		t.Fatal(ps)
	}
	p := ps[0]
	for _, f := range p.Findings {
		if f.Code == "hostname_mismatch" && f.Fingerprint == models.Fingerprint(bad) {
			return
		}
	}
	t.Errorf("second SNI leaf mismatch discarded; handshakes=%d covers_name=%v other_fingerprints=%v findings=%+v", p.Handshakes, p.CoversRequestedName, p.OtherFingerprints, p.Findings)
}

func TestCodeAuditSCTWithoutSignatureMustBeRejected(t *testing.T) {
	raw := make([]byte, 43)
	for i := 1; i <= 32; i++ {
		raw[i] = 1
	}
	binary.BigEndian.PutUint64(raw[33:41], uint64(time.Now().UnixMilli()))
	if got, ok := parseSCT(raw); ok {
		t.Errorf("43-byte SCT with no signature structure accepted: log=%s", got.LogID)
	}
}

func TestCodeAuditUnsignedTreeHeadCannotProveInclusion(t *testing.T) {
	leaf := testLeaf(t, 1003)
	obs := models.SCTObservation{TimestampMS: uint64(time.Now().UnixMilli())}
	hs := merkleLeafHashes([]*x509.Certificate{leaf}, obs)
	if len(hs) == 0 {
		t.Fatal("missing test hash")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ct/v1/get-sth" {
			json.NewEncoder(w).Encode(map[string]interface{}{"tree_size": 1, "sha256_root_hash": hs[0]})
			return
		}
		if r.URL.Path == "/ct/v1/get-proof-by-hash" {
			json.NewEncoder(w).Encode(map[string]interface{}{"leaf_index": 0, "audit_path": []string{}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	if _, err := base64.StdEncoding.DecodeString(hs[0]); err != nil {
		t.Fatal(err)
	}
	obs.LogURL = server.URL
	s := &Scanner{config: &models.ScannerConfig{Timeout: time.Second}, client: server.Client()}
	ok, _, _, err := s.proveSCTInclusion(context.Background(), []*x509.Certificate{leaf}, obs)
	if err == nil && ok {
		t.Error("invented unsigned STH and empty proof accepted as verified inclusion")
	}
}
