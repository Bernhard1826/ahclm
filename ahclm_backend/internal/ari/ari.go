// Package ari queries a certificate's issuing CA for ACME Renewal Information
// (RFC 9773): the CA-recommended renewal window (suggestedWindow). Normally the
// window sits in the final third of the certificate lifetime; in an emergency
// (mass revocation) the CA pulls it forward to "now" to force immediate renewal.
package ari

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"ahclm/internal/models"
)

type provider struct {
	name       string
	directory  string
	cnPatterns []*regexp.Regexp
	orgNeedles []string
}

func compileProviders(configs []models.ARIProviderConfig) ([]provider, error) {
	providers := make([]provider, 0, len(configs))
	for _, cfg := range configs {
		p := provider{name: cfg.Name, directory: cfg.DirectoryURL, orgNeedles: cfg.IssuerOrganizationContains}
		for _, pattern := range cfg.IssuerCommonNamePatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("ARI provider %q has invalid issuer pattern %q: %w", cfg.Name, pattern, err)
			}
			p.cnPatterns = append(p.cnPatterns, re)
		}
		providers = append(providers, p)
	}
	return providers, nil
}

// CacheStore is implemented by the persistence layer. The ARI package keeps
// this dependency as an interface so it can still operate without a database.
type CacheStore interface {
	GetARICache(identifier string, now time.Time) (*models.ARICacheEntry, error)
	SaveARICache(entry *models.ARICacheEntry) error
}

// resolveCA returns the ACME directory URL and CA display name for the leaf's
// issuer, or ("","") when the issuer is not a known ARI-capable CA. The table is
// intentionally small and easy to extend as more CAs deploy ARI.
func resolveCA(leaf *x509.Certificate, providers ...provider) (directoryURL, name string) {
	cn := leaf.Issuer.CommonName
	org := ""
	if len(leaf.Issuer.Organization) > 0 {
		org = leaf.Issuer.Organization[0]
	}
	for _, provider := range providers {
		for _, pattern := range provider.cnPatterns {
			if pattern.MatchString(cn) {
				return provider.directory, provider.name
			}
		}
		for _, needle := range provider.orgNeedles {
			if strings.Contains(strings.ToLower(org), strings.ToLower(needle)) {
				return provider.directory, provider.name
			}
		}
	}
	return "", ""
}

// CertID builds the RFC 9773 ARI certificate identifier:
//
//	base64url(AKI keyIdentifier) "." base64url(DER serial number content)
//
// It returns ok=false when the certificate lacks an Authority Key Identifier.
func CertID(leaf *x509.Certificate) (string, bool) {
	if len(leaf.AuthorityKeyId) == 0 {
		return "", false
	}
	// The serial number is the content octets of its DER INTEGER encoding, which
	// prepends a 0x00 when the high bit is set — asn1.Marshal produces exactly
	// that, and is more correct than big.Int.Bytes() for such serials. X.509
	// serials are <= 20 octets, so the DER length is always in short form (one
	// byte) and der[2:] strips tag(1)+length(1).
	serialDER, err := asn1.Marshal(leaf.SerialNumber)
	if err != nil || len(serialDER) < 2 {
		return "", false
	}
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)
	serial := base64.RawURLEncoding.EncodeToString(serialDER[2:])
	return aki + "." + serial, true
}

// Checker fetches ARI with a bounded HTTP client. It caches (a) each CA's
// renewalInfo base URL discovered from its ACME directory and (b) the last
// result per CertID, honouring the server's Retry-After so that frequent
// re-scans of a domain near expiry do not re-query ARI every time.
type Checker struct {
	client          *http.Client
	store           CacheStore
	providers       []provider
	cacheDefaultTTL time.Duration
	cacheMinimumTTL time.Duration

	mu       sync.Mutex
	dirCache map[string]string        // directoryURL -> renewalInfo base
	results  map[string]*cachedResult // certID -> last result
}

type cachedResult struct {
	info      *models.ARIInfo
	expiresAt time.Time
}

// NewChecker builds a Checker with the given per-request timeout.
func NewChecker(timeout, cacheDefaultTTL, cacheMinimumTTL time.Duration, configs []models.ARIProviderConfig, store CacheStore) (*Checker, error) {
	providers, err := compileProviders(configs)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 || cacheDefaultTTL <= 0 || cacheMinimumTTL <= 0 || cacheMinimumTTL > cacheDefaultTTL {
		return nil, fmt.Errorf("invalid ARI timeout/cache configuration")
	}
	return &Checker{
		client:          &http.Client{Timeout: timeout},
		store:           store,
		providers:       providers,
		cacheDefaultTTL: cacheDefaultTTL,
		cacheMinimumTTL: cacheMinimumTTL,
		dirCache:        make(map[string]string),
		results:         make(map[string]*cachedResult),
	}, nil
}

// Fetch returns the ARI information for the leaf certificate. It never returns
// nil; failure modes are conveyed via the ARIInfo.Status field.
func (c *Checker) Fetch(ctx context.Context, leaf *x509.Certificate) *models.ARIInfo {
	dirURL, caName := resolveCA(leaf, c.providers...)
	if dirURL == "" {
		return &models.ARIInfo{Status: models.ARIStatusUnsupported}
	}
	certID, ok := CertID(leaf)
	if !ok {
		return &models.ARIInfo{Status: models.ARIStatusUnavailable, Source: caName}
	}

	now := time.Now()

	// Serve from the in-memory cache while Retry-After has not elapsed.
	c.mu.Lock()
	if r, ok := c.results[certID]; ok && now.Before(r.expiresAt) {
		info := *r.info
		c.mu.Unlock()
		return &info
	}
	c.mu.Unlock()

	// The persistent cache survives restarts. It is only used while fresh; a
	// transient database error must not prevent a live CA query.
	if c.store != nil {
		if cached, err := c.store.GetARICache(certID, now); err == nil && cached != nil {
			info := ariInfoFromCache(cached)
			c.cacheLocal(certID, info, cached.ExpiresAt)
			return info
		}
	}

	base, err := c.renewalBase(ctx, dirURL)
	if err != nil {
		return &models.ARIInfo{Status: models.ARIStatusError, Source: caName}
	}

	info := c.fetchWindow(ctx, base, certID)
	info.Source = caName

	// Cache successful and definitive-unavailable responses. Network/parse
	// errors are deliberately not cached so the next scheduled scan can retry.
	if info.Status == models.ARIStatusOK || info.Status == models.ARIStatusUnavailable {
		expiresAt := now.Add(c.cacheTTL(info.RetryAfterSecs))
		nextPoll := expiresAt
		info.NextPollAt = &nextPoll
		c.cacheLocal(certID, info, expiresAt)
		if c.store != nil {
			_ = c.store.SaveARICache(&models.ARICacheEntry{
				ARIIdentifier:  certID,
				Source:         info.Source,
				Status:         info.Status,
				WindowStart:    info.WindowStart,
				WindowEnd:      info.WindowEnd,
				ExplanationURL: info.ExplanationURL,
				RetryAfterSecs: info.RetryAfterSecs,
				FetchedAt:      now,
				ExpiresAt:      expiresAt,
			})
		}
	}
	return info
}

func (c *Checker) cacheLocal(certID string, info *models.ARIInfo, expiresAt time.Time) {
	clone := *info
	c.mu.Lock()
	c.results[certID] = &cachedResult{info: &clone, expiresAt: expiresAt}
	c.mu.Unlock()
}

func (c *Checker) cacheTTL(retryAfterSecs int) time.Duration {
	ttl := time.Duration(retryAfterSecs) * time.Second
	if ttl <= 0 {
		return c.cacheDefaultTTL
	}
	if ttl < c.cacheMinimumTTL {
		return c.cacheMinimumTTL
	}
	return ttl
}

func ariInfoFromCache(entry *models.ARICacheEntry) *models.ARIInfo {
	info := &models.ARIInfo{
		Status:         entry.Status,
		Source:         entry.Source,
		WindowStart:    entry.WindowStart,
		WindowEnd:      entry.WindowEnd,
		ExplanationURL: entry.ExplanationURL,
		RetryAfterSecs: entry.RetryAfterSecs,
	}
	nextPoll := entry.ExpiresAt
	info.NextPollAt = &nextPoll
	return info
}

// renewalBase discovers (and caches) the renewalInfo endpoint from the CA's
// ACME directory resource, rather than hard-coding a draft/RFC path.
func (c *Checker) renewalBase(ctx context.Context, dirURL string) (string, error) {
	c.mu.Lock()
	if base, ok := c.dirCache[dirURL]; ok {
		c.mu.Unlock()
		return base, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dirURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&dir); err != nil {
		return "", err
	}
	if dir.RenewalInfo == "" {
		return "", fmt.Errorf("ACME directory has no renewalInfo endpoint")
	}
	c.mu.Lock()
	c.dirCache[dirURL] = dir.RenewalInfo
	c.mu.Unlock()
	return dir.RenewalInfo, nil
}

// fetchWindow performs the ARI GET and parses the suggestedWindow.
func (c *Checker) fetchWindow(ctx context.Context, base, certID string) *models.ARIInfo {
	url := strings.TrimRight(base, "/") + "/" + certID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return &models.ARIInfo{Status: models.ARIStatusError}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return &models.ARIInfo{Status: models.ARIStatusError}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 404 = the CA has no ARI for this certificate (e.g. too old / unknown).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &models.ARIInfo{Status: models.ARIStatusUnavailable}
	}

	var payload struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err := json.Unmarshal(body, &payload); err != nil {
		return &models.ARIInfo{Status: models.ARIStatusError}
	}

	info := &models.ARIInfo{
		Status:         models.ARIStatusOK,
		ExplanationURL: payload.ExplanationURL,
		RetryAfterSecs: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
	if !payload.SuggestedWindow.Start.IsZero() {
		s := payload.SuggestedWindow.Start
		info.WindowStart = &s
	}
	if !payload.SuggestedWindow.End.IsZero() {
		e := payload.SuggestedWindow.End
		info.WindowEnd = &e
	}
	return info
}

// parseRetryAfter accepts either a delta-seconds integer or an HTTP-date.
func parseRetryAfter(h string) int {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if n, err := strconv.Atoi(h); err == nil {
		return n
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return int(d.Seconds())
		}
	}
	return 0
}
