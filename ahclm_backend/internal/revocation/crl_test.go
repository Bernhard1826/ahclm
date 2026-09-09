package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"ahclm/internal/models"
)

type fakeCRLCacheStore struct {
	entry   *models.CRLCacheEntry
	lookups int
	saves   int
}

func (s *fakeCRLCacheStore) GetCRLCache(_ string, _ time.Time) (*models.CRLCacheEntry, error) {
	s.lookups++
	return s.entry, nil
}

func (s *fakeCRLCacheStore) SaveCRLCache(entry *models.CRLCacheEntry) error {
	s.saves++
	s.entry = entry
	return nil
}

func TestGetCRLUsesPersistentCache(t *testing.T) {
	now := time.Now().UTC()
	issuer, key := testIssuer(t, now)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   big.NewInt(99),
			RevocationTime: now.Add(-time.Minute),
		}},
	}, issuer, key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}

	store := &fakeCRLCacheStore{entry: &models.CRLCacheEntry{
		URL:       "https://cache.example.test/crl",
		RawDER:    crlDER,
		FetchedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}}
	checker := NewChecker(time.Second, true, time.Hour, store)
	got := checker.getCRL(context.Background(), store.entry.URL, issuer)
	if got == nil {
		t.Fatal("expected CRL from persistent cache")
	}
	if store.lookups != 1 {
		t.Fatalf("persistent cache lookups = %d, want 1", store.lookups)
	}
	if store.saves != 0 {
		t.Fatalf("unexpected cache save on cache hit: %d", store.saves)
	}
	if len(got.RevokedCertificateEntries) != 1 || got.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(99)) != 0 {
		t.Fatalf("unexpected CRL entries: %+v", got.RevokedCertificateEntries)
	}
}

func testIssuer(t *testing.T, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AHCLM test issuer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create issuer certificate: %v", err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse issuer certificate: %v", err)
	}
	return issuer, key
}
