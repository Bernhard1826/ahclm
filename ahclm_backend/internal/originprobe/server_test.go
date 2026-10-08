package originprobe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCertificate(t *testing.T, serial int64) (string, string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, parsed
}

// This experiment uses real, verified TLS on both hops and a real reverse proxy.
// It is a local mechanism test, not a measurement of a commercial CDN.
func TestRotationThroughProxyRetainsOldConnectionUntilNewHandshake(t *testing.T) {
	oldCert, oldKey, oldLeaf := testCertificate(t, 1)
	newCert, newKey, newLeaf := testCertificate(t, 2)
	origin := New()
	first, err := origin.Rotate(oldCert, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := origin.Server(listener.Addr().String())
	defer server.Close()
	go func() { _ = server.ServeTLS(listener, "", "") }()
	pool := x509.NewCertPool()
	pool.AddCert(oldLeaf)
	pool.AddCert(newLeaf)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ClientSessionCache: tls.NewLRUClientSessionCache(4)}, MaxIdleConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	target, _ := url.Parse("https://" + listener.Addr().String())
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	edge := httptest.NewTLSServer(proxy)
	defer edge.Close()
	client := edge.Client()
	request := func(nonce string) (string, string) {
		t.Helper()
		res, err := client.Get(edge.URL + Path + "?_ahclm_probe=" + nonce)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		if res.StatusCode != 200 || res.Header.Get("X-AHCLM-Probe") != nonce || res.Header.Get("X-AHCLM-Origin-TLS-Resumed") != "false" {
			t.Fatalf("invalid evidence: %d %+v", res.StatusCode, res.Header)
		}
		digest := sha256.Sum256(res.TLS.PeerCertificates[0].Raw)
		return res.Header.Get("X-AHCLM-Origin-Fingerprint"), hex.EncodeToString(digest[:])
	}
	before, edgeBefore := request("00000000000000000000000000000001")
	if before != first.Fingerprint {
		t.Fatal("wrong initial connection certificate")
	}
	rotation, err := origin.Rotate(newCert, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.PreviousFingerprint != first.Fingerprint || rotation.SourceUpdatedAt.IsZero() {
		t.Fatal("incomplete rotation event")
	}
	reused, edgeReused := request("00000000000000000000000000000002")
	if reused != first.Fingerprint {
		t.Fatalf("old keepalive connection incorrectly labeled new: %s", reused)
	}
	transport.CloseIdleConnections()
	fresh, edgeFresh := request("00000000000000000000000000000003")
	if fresh != rotation.Fingerprint {
		t.Fatal("new TLS handshake did not use rotated certificate")
	}
	if edgeBefore != edgeReused || edgeBefore != edgeFresh {
		t.Fatal("origin rotation unexpectedly altered the proxy certificate")
	}
	// Session tickets must not hide the certificate of a subsequent connection.
	transport.CloseIdleConnections()
	if next, _ := request("00000000000000000000000000000004"); next != rotation.Fingerprint {
		t.Fatal("new connection lost certificate identity")
	}
	if _, err := origin.Rotate(newCert, oldKey); err == nil {
		t.Fatal("mismatched key accepted")
	}
	transport.CloseIdleConnections()
	if next, _ := request("00000000000000000000000000000005"); next != rotation.Fingerprint {
		t.Fatal("invalid reload changed active certificate")
	}
	evidence := map[string]any{"scope": "local TLS reverse proxy; not a commercial CDN", "source_updated_at": rotation.SourceUpdatedAt, "old_origin_fingerprint": first.Fingerprint, "new_origin_fingerprint": rotation.Fingerprint, "reused_connection_fingerprint": reused, "fresh_connection_fingerprint": fresh, "edge_certificate_unchanged": true, "http_success_on_old_connection": true, "fresh_nonce_verified": true}
	encoded, _ := json.Marshal(evidence)
	t.Logf("LOCAL_ROTATION_EVIDENCE %s", encoded)
}
