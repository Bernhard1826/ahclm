// Package revocation determines the revocation status of an X.509 certificate
// using (in order of preference) a stapled OCSP response, an active OCSP query,
// and optionally a CRL lookup.
package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"ahclm/internal/models"

	"golang.org/x/crypto/ocsp"
)

// Status is the outcome of a revocation check.
type Status struct {
	Status     string     // good, revoked, unknown, not_checked
	CheckedVia string     // stapled_ocsp, ocsp, crl, none
	RevokedAt  *time.Time // set when revoked
	Reason     string     // human-readable revocation reason
}

// CRLCacheStore is implemented by the persistence layer. Cached payloads are
// always parsed and signature-verified again before they are trusted.
type CRLCacheStore interface {
	GetCRLCache(url string, now time.Time) (*models.CRLCacheEntry, error)
	SaveCRLCache(entry *models.CRLCacheEntry) error
}

// Checker performs revocation checks with a bounded HTTP client and an
// in-memory CRL cache (CRLs are large and heavily shared between certificates).
type Checker struct {
	client   *http.Client
	checkCRL bool
	store    CRLCacheStore

	crlMu    sync.Mutex
	crlCache map[string]*cachedCRL
	crlTTL   time.Duration
}

type cachedCRL struct {
	list      *x509.RevocationList
	expiresAt time.Time
}

// NewChecker builds a Checker. If checkCRL is true, a CRL lookup is attempted
// when OCSP is unavailable (as is now the case for Let's Encrypt and other
// CRL-only CAs).
func NewChecker(timeout time.Duration, checkCRL bool, crlTTL time.Duration, store CRLCacheStore) *Checker {
	return &Checker{
		client:   &http.Client{Timeout: timeout},
		checkCRL: checkCRL,
		store:    store,
		crlCache: make(map[string]*cachedCRL),
		crlTTL:   crlTTL,
	}
}

// Check evaluates the leaf certificate (chain[0]) against its issuer. `stapled`
// is the OCSP response captured during the TLS handshake (may be nil).
func (c *Checker) Check(ctx context.Context, chain []*x509.Certificate, stapled []byte) *Status {
	if len(chain) == 0 {
		return &Status{Status: models.RevocationNotChecked, CheckedVia: models.CheckedViaNone}
	}
	leaf := chain[0]
	if leaf.IsCA {
		// Root/intermediate served alone — nothing meaningful to check.
		return &Status{Status: models.RevocationNotChecked, CheckedVia: models.CheckedViaNone}
	}

	issuer := c.findIssuer(ctx, chain)
	if issuer == nil {
		return &Status{Status: models.RevocationUnknown, CheckedVia: models.CheckedViaNone}
	}

	// 1. Stapled OCSP (free — captured during handshake).
	if len(stapled) > 0 {
		if st := parseOCSP(stapled, leaf, issuer, models.CheckedViaStapledOCSP); st != nil {
			return st
		}
	}

	// 2. Active OCSP query.
	if len(leaf.OCSPServer) > 0 {
		if st := c.queryOCSP(ctx, leaf, issuer); st != nil {
			return st
		}
	}

	// 3. CRL fallback (optional).
	if c.checkCRL && len(leaf.CRLDistributionPoints) > 0 {
		if st := c.checkCRL_(ctx, leaf, issuer); st != nil {
			return st
		}
	}

	return &Status{Status: models.RevocationUnknown, CheckedVia: models.CheckedViaNone}
}

// findIssuer returns the issuing certificate, preferring the presented chain
// and falling back to an AIA (IssuingCertificateURL) fetch.
func (c *Checker) findIssuer(ctx context.Context, chain []*x509.Certificate) *x509.Certificate {
	if len(chain) >= 2 {
		return chain[1]
	}
	leaf := chain[0]
	for _, url := range leaf.IssuingCertificateURL {
		if cert := c.fetchCertificate(ctx, url); cert != nil {
			return cert
		}
	}
	return nil
}

func (c *Checker) fetchCertificate(ctx context.Context, url string) *x509.Certificate {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	if cert, err := x509.ParseCertificate(body); err == nil {
		return cert
	}
	if block, _ := pem.Decode(body); block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return cert
		}
	}
	return nil
}

func (c *Checker) queryOCSP(ctx context.Context, leaf, issuer *x509.Certificate) *Status {
	reqDER, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, leaf.OCSPServer[0], bytes.NewReader(reqDER))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || len(body) == 0 {
		return nil
	}
	return parseOCSP(body, leaf, issuer, models.CheckedViaOCSP)
}

func parseOCSP(der []byte, leaf, issuer *x509.Certificate, via string) *Status {
	resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err != nil {
		return nil
	}
	now := time.Now()
	// A valid signature authenticates the response, not its freshness.
	const skew = 5 * time.Minute
	if resp.ThisUpdate.IsZero() || resp.ThisUpdate.After(now.Add(skew)) || resp.ProducedAt.After(now.Add(skew)) {
		return nil
	}
	if !resp.NextUpdate.IsZero() {
		if !resp.NextUpdate.After(now) || resp.NextUpdate.Before(resp.ThisUpdate) {
			return nil
		}
	} else if now.Sub(resp.ThisUpdate) > 24*time.Hour {
		return nil
	}
	switch resp.Status {
	case ocsp.Good:
		return &Status{Status: models.RevocationGood, CheckedVia: via}
	case ocsp.Revoked:
		t := resp.RevokedAt
		return &Status{
			Status:     models.RevocationRevoked,
			CheckedVia: via,
			RevokedAt:  &t,
			Reason:     revocationReason(resp.RevocationReason),
		}
	default:
		return &Status{Status: models.RevocationUnknown, CheckedVia: via}
	}
}

// revocationReason maps an OCSP/CRL reason code to a readable string.
func revocationReason(code int) string {
	reasons := map[int]string{
		0: "unspecified", 1: "keyCompromise", 2: "cACompromise",
		3: "affiliationChanged", 4: "superseded", 5: "cessationOfOperation",
		6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn",
		10: "aACompromise",
	}
	if r, ok := reasons[code]; ok {
		return r
	}
	return fmt.Sprintf("reason_%d", code)
}
