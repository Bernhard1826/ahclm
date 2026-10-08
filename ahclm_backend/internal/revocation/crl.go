package revocation

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"time"

	"ahclm/internal/models"
)

// checkCRL_ checks whether the leaf's serial number appears in its CRL. CRLs
// are cached by distribution-point URL because a single CA CRL (shard) covers
// many certificates — essential for scanning at Tranco scale.
func (c *Checker) checkCRL_(ctx context.Context, leaf, issuer *x509.Certificate) *Status {
	for _, url := range leaf.CRLDistributionPoints {
		crl := c.getCRL(ctx, url, issuer)
		if crl == nil {
			continue
		}
		for i := range crl.RevokedCertificateEntries {
			entry := &crl.RevokedCertificateEntries[i]
			if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				t := entry.RevocationTime
				return &Status{
					Status:     models.RevocationRevoked,
					CheckedVia: models.CheckedViaCRL,
					RevokedAt:  &t,
					Reason:     revocationReason(entry.ReasonCode),
				}
			}
		}
		// Parsed and verified a CRL; serial absent ⇒ good.
		return &Status{Status: models.RevocationGood, CheckedVia: models.CheckedViaCRL}
	}
	return nil
}

// getCRL returns a parsed, issuer-verified CRL for url, using the cache when
// fresh and fetching otherwise.
func (c *Checker) getCRL(ctx context.Context, url string, issuer *x509.Certificate) *x509.RevocationList {
	now := time.Now()

	c.crlMu.Lock()
	if cached, ok := c.crlCache[url]; ok && now.Before(cached.expiresAt) {
		list := cached.list
		c.crlMu.Unlock()
		if list.CheckSignatureFrom(issuer) == nil {
			return list
		}
		c.crlMu.Lock()
		delete(c.crlCache, url)
		c.crlMu.Unlock()
	} else {
		c.crlMu.Unlock()
	}

	// The database cache avoids a large CRL download after a process restart.
	// A persisted payload is never trusted without parsing and verifying it
	// against the issuer certificate observed in this scan.
	if c.store != nil {
		if cached, err := c.store.GetCRLCache(url, now); err == nil && cached != nil {
			if crl := parseVerifiedCRL(cached.RawDER, issuer, now); crl != nil {
				c.cacheCRL(url, crl, cached.ExpiresAt)
				return crl
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil || len(body) == 0 {
		return nil
	}
	crl := parseVerifiedCRL(body, issuer, now)
	if crl == nil {
		return nil
	}

	expiresAt := crlCacheExpiry(crl, now, c.crlTTL)
	c.cacheCRL(url, crl, expiresAt)
	if c.store != nil {
		_ = c.store.SaveCRLCache(&models.CRLCacheEntry{
			URL:        url,
			RawDER:     body,
			ThisUpdate: timePtr(crl.ThisUpdate),
			NextUpdate: timePtr(crl.NextUpdate),
			FetchedAt:  now,
			ExpiresAt:  expiresAt,
		})
	}
	return crl
}

func (c *Checker) cacheCRL(url string, crl *x509.RevocationList, expiresAt time.Time) {
	c.crlMu.Lock()
	c.crlCache[url] = &cachedCRL{list: crl, expiresAt: expiresAt}
	c.crlMu.Unlock()
}

func parseVerifiedCRL(raw []byte, issuer *x509.Certificate, now time.Time) *x509.RevocationList {
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return nil
	}
	if crl.ThisUpdate.IsZero() || crl.ThisUpdate.After(now.Add(5*time.Minute)) ||
		crl.NextUpdate.IsZero() || !crl.NextUpdate.After(now) || crl.NextUpdate.Before(crl.ThisUpdate) {
		return nil
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil
	}
	return crl
}

func crlCacheExpiry(crl *x509.RevocationList, now time.Time, ttl time.Duration) time.Time {
	expiresAt := now.Add(ttl)
	if !crl.NextUpdate.IsZero() && crl.NextUpdate.Before(expiresAt) {
		return crl.NextUpdate
	}
	return expiresAt
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	out := t
	return &out
}
