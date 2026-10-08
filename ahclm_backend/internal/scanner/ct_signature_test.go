package scanner

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ahclm/internal/models"
)

// This fixture serializes the RFC wire structure independently of production
// helpers. In particular, LogEntryType is uint16, not one byte.
func TestAuthenticatedCTInclusionAndTampering(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id := sha256.Sum256(keyDER)
	logID := hex.EncodeToString(id[:])
	leaf := testLeaf(t, 90210)
	ts := uint64(time.Now().Add(-time.Minute).UnixMilli())
	var entry bytes.Buffer
	entry.Write([]byte{0, 0}) // version, certificate_timestamp
	binary.Write(&entry, binary.BigEndian, ts)
	binary.Write(&entry, binary.BigEndian, uint16(0)) // x509_entry
	n := len(leaf.Raw)
	entry.Write([]byte{byte(n >> 16), byte(n >> 8), byte(n)})
	entry.Write(leaf.Raw)
	entry.Write([]byte{0, 0}) // empty extensions
	sign := func(body []byte) []byte {
		digest := sha256.Sum256(body)
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte{4, 3, byte(len(sig) >> 8), byte(len(sig))}, sig...)
	}
	obs := models.SCTObservation{LogID: logID, TimestampMS: ts, Signature: sign(entry.Bytes())}
	root := sha256.Sum256(append([]byte{0}, entry.Bytes()...))
	var sth bytes.Buffer
	sth.Write([]byte{0, 1}) // version, tree_hash
	binary.Write(&sth, binary.BigEndian, ts+1)
	binary.Write(&sth, binary.BigEndian, uint64(1))
	sth.Write(root[:])
	validSig := sign(sth.Bytes())
	for _, scenario := range []string{"valid", "unsigned_sth", "tampered_sth", "tampered_sct", "wrong_leaf"} {
		t.Run(scenario, func(t *testing.T) {
			signature := append([]byte(nil), validSig...)
			if scenario == "unsigned_sth" {
				signature = nil
			}
			if scenario == "tampered_sth" {
				signature[len(signature)-1] ^= 1
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/ct/v1/get-sth":
					json.NewEncoder(w).Encode(map[string]interface{}{"tree_size": 1, "timestamp": ts + 1, "sha256_root_hash": base64.StdEncoding.EncodeToString(root[:]), "tree_head_signature": base64.StdEncoding.EncodeToString(signature)})
				case "/ct/v1/get-proof-by-hash":
					if r.URL.Query().Get("hash") != base64.StdEncoding.EncodeToString(root[:]) {
						http.NotFound(w, r)
						return
					}
					json.NewEncoder(w).Encode(map[string]interface{}{"leaf_index": 0, "audit_path": []string{}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			old := models.CurrentEvidenceDatasets()
			models.ReplaceEvidenceDatasets(models.DatasetSnapshot{Logs: map[string]models.DatasetLog{logID: {LogID: logID, Key: base64.StdEncoding.EncodeToString(keyDER), URL: server.URL}}})
			defer models.ReplaceEvidenceDatasets(old)
			input := obs
			input.Signature = append([]byte(nil), obs.Signature...)
			if scenario == "tampered_sct" {
				input.Signature[len(input.Signature)-1] ^= 1
			}
			chain := []*x509.Certificate{leaf}
			if scenario == "wrong_leaf" {
				chain = []*x509.Certificate{testLeaf(t, 90211)}
			}
			s := &Scanner{config: &models.ScannerConfig{Timeout: time.Second, CheckSCTInclusion: true}, evidenceClient: server.Client()}
			got, _, _, err := s.proveSCTInclusion(context.Background(), chain, input)
			if scenario == "valid" {
				if err != nil || !got {
					t.Fatalf("valid signed proof rejected: %v", err)
				}
			} else if got {
				t.Fatal("unauthenticated proof accepted")
			}
		})
	}
}
