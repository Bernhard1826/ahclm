package ari

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"ahclm/internal/models"
)

type fakeCacheStore struct {
	entry     *models.ARICacheEntry
	lookups   int
	saves     int
	lookupKey string
}

func (s *fakeCacheStore) GetARICache(identifier string, _ time.Time) (*models.ARICacheEntry, error) {
	s.lookups++
	s.lookupKey = identifier
	return s.entry, nil
}

func (s *fakeCacheStore) SaveARICache(entry *models.ARICacheEntry) error {
	s.saves++
	s.entry = entry
	return nil
}

func TestCertID(t *testing.T) {
	// Serial 200 (0xC8) has its high bit set, so the DER INTEGER content is
	// {0x00, 0xC8} — this is exactly what an ARI CertID must encode, and what
	// distinguishes the correct DER encoding from a raw big.Int.Bytes().
	leaf := &x509.Certificate{
		AuthorityKeyId: []byte{0xAB, 0xCD},
		SerialNumber:   big.NewInt(200),
	}
	id, ok := CertID(leaf)
	if !ok {
		t.Fatal("expected ok=true for cert with AKI")
	}
	parts := strings.SplitN(id, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("expected two dot-separated parts, got %q", id)
	}
	aki, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || !bytes.Equal(aki, []byte{0xAB, 0xCD}) {
		t.Fatalf("AKI part decoded to %x (err=%v), want abcd", aki, err)
	}
	serial, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !bytes.Equal(serial, []byte{0x00, 0xC8}) {
		t.Fatalf("serial part decoded to %x (err=%v), want 00c8", serial, err)
	}
}

func TestCertIDLowSerial(t *testing.T) {
	// Serial 65 (0x41) has no high bit → DER content is just {0x41}, no pad.
	leaf := &x509.Certificate{AuthorityKeyId: []byte{0x01}, SerialNumber: big.NewInt(65)}
	id, ok := CertID(leaf)
	if !ok {
		t.Fatal("expected ok")
	}
	serial, _ := base64.RawURLEncoding.DecodeString(strings.SplitN(id, ".", 2)[1])
	if !bytes.Equal(serial, []byte{0x41}) {
		t.Fatalf("serial decoded to %x, want 41", serial)
	}
}

func TestCertIDNoAKI(t *testing.T) {
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1)}
	if _, ok := CertID(leaf); ok {
		t.Fatal("expected ok=false when AuthorityKeyId is missing")
	}
}

func TestResolveCA(t *testing.T) {
	providers, err := compileProviders([]models.ARIProviderConfig{
		{Name: "Let's Encrypt", DirectoryURL: "https://le.test/directory", IssuerCommonNamePatterns: []string{`^[RE][0-9]{1,2}$`}, IssuerOrganizationContains: []string{"Let's Encrypt"}},
		{Name: "Google Trust Services", DirectoryURL: "https://gts.test/directory", IssuerCommonNamePatterns: []string{`^W[RE][0-9]{1,2}$`}, IssuerOrganizationContains: []string{"Google Trust Services"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		cn, org  string
		wantName string
	}{
		{"R13", "", "Let's Encrypt"},
		{"E7", "", "Let's Encrypt"},
		{"", "Let's Encrypt", "Let's Encrypt"},
		{"WE1", "", "Google Trust Services"},
		{"WR2", "", "Google Trust Services"},
		{"", "Google Trust Services LLC", "Google Trust Services"},
		{"DigiCert Global G3 TLS ECC SHA384 2020 CA1", "DigiCert Inc", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		leaf := &x509.Certificate{Issuer: pkix.Name{CommonName: tc.cn}}
		if tc.org != "" {
			leaf.Issuer.Organization = []string{tc.org}
		}
		_, name := resolveCA(leaf, providers...)
		if name != tc.wantName {
			t.Errorf("resolveCA(cn=%q,org=%q) = %q, want %q", tc.cn, tc.org, name, tc.wantName)
		}
	}
}

func TestFetchUsesPersistentCache(t *testing.T) {
	now := time.Now().UTC()
	windowStart := now.Add(24 * time.Hour)
	windowEnd := windowStart.Add(24 * time.Hour)
	store := &fakeCacheStore{
		entry: &models.ARICacheEntry{
			ARIIdentifier:  "placeholder",
			Source:         "Let's Encrypt",
			Status:         models.ARIStatusOK,
			WindowStart:    &windowStart,
			WindowEnd:      &windowEnd,
			RetryAfterSecs: 3600,
			ExpiresAt:      now.Add(time.Hour),
		},
	}
	leaf := &x509.Certificate{
		AuthorityKeyId: []byte{0x01},
		SerialNumber:   big.NewInt(42),
		Issuer:         pkix.Name{CommonName: "R13"},
	}
	id, ok := CertID(leaf)
	if !ok {
		t.Fatal("expected ARI certificate identifier")
	}
	store.entry.ARIIdentifier = id

	checker, err := NewChecker(time.Second, 24*time.Hour, time.Hour, []models.ARIProviderConfig{{Name: "Let's Encrypt", DirectoryURL: "https://le.test/directory", IssuerCommonNamePatterns: []string{`^R[0-9]+$`}}}, store)
	if err != nil {
		t.Fatal(err)
	}
	info := checker.Fetch(context.Background(), leaf)
	if info.Status != models.ARIStatusOK {
		t.Fatalf("status = %q, want %q", info.Status, models.ARIStatusOK)
	}
	if store.lookups != 1 || store.lookupKey != id {
		t.Fatalf("cache lookup = %d for %q, want one lookup for %q", store.lookups, store.lookupKey, id)
	}
	if store.saves != 0 {
		t.Fatalf("unexpected persistent cache save on cache hit: %d", store.saves)
	}
	if info.NextPollAt == nil || !info.NextPollAt.Equal(store.entry.ExpiresAt) {
		t.Fatalf("next poll = %v, want cache expiry %v", info.NextPollAt, store.entry.ExpiresAt)
	}
}

func TestARIWindowFraction(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.AddDate(0, 0, 90) // 90-day cert
	// Window starting at day 60 should be at fraction 2/3.
	ws := nb.AddDate(0, 0, 60)
	f := models.ARIWindowFraction(nb, na, ws)
	if f < 0.66 || f > 0.68 {
		t.Fatalf("fraction = %.3f, want ~0.667", f)
	}
}

func TestARIIsEmergency(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.AddDate(0, 0, 90)

	// Normal: at day 62, window already at day 60 (fraction .667) — NOT emergency.
	now := nb.AddDate(0, 0, 62)
	if models.ARIIsEmergency(now, nb, na, nb.AddDate(0, 0, 60)) {
		t.Error("normal last-third window should not be flagged emergency")
	}
	// Emergency: at day 20, CA pulls window back to day 18 (fraction .2) — urgent.
	now = nb.AddDate(0, 0, 20)
	if !models.ARIIsEmergency(now, nb, na, nb.AddDate(0, 0, 18)) {
		t.Error("window pulled to ~day 18 while at day 20 should be emergency")
	}
	// Future window is never an emergency.
	now = nb.AddDate(0, 0, 20)
	if models.ARIIsEmergency(now, nb, na, nb.AddDate(0, 0, 60)) {
		t.Error("future window should not be emergency")
	}
}
