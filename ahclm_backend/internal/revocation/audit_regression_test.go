package revocation

import (
	"ahclm/internal/models"
	"crypto/rand"
	"crypto/x509"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"testing"
	"time"
)

func TestCodeAuditExpiredOCSPMustNotBeCurrentGood(t *testing.T) {
	now := time.Now().UTC()
	issuer, key := testIssuer(t, now)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42)}
	der, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{Status: ocsp.Good, SerialNumber: leaf.SerialNumber, ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: now.Add(-24 * time.Hour)}, key)
	if err != nil {
		t.Fatal(err)
	}
	got := parseOCSP(der, leaf, issuer, models.CheckedViaStapledOCSP)
	if got != nil && got.Status == models.RevocationGood {
		t.Errorf("signed OCSP expired 24h ago accepted as current good: %+v", got)
	}
}

func TestCodeAuditFutureCRLMustNotBeCurrent(t *testing.T) {
	now := time.Now().UTC()
	issuer, key := testIssuer(t, now)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(42), ThisUpdate: now.Add(24 * time.Hour), NextUpdate: now.Add(48 * time.Hour)}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	if got := parseVerifiedCRL(der, issuer, now); got != nil {
		t.Errorf("signed CRL ThisUpdate 24h in future accepted: %v", got.ThisUpdate)
	}
}
