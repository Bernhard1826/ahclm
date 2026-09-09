package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ahclm/internal/ari"
	"ahclm/internal/models"
	"ahclm/internal/revocation"
)

// Scanner performs TLS handshakes to capture the deployed certificate chain and
// (optionally) its revocation status. It behaves like a lightweight zgrab.
type Scanner struct {
	config    *models.ScannerConfig
	client    *http.Client
	checker   *revocation.Checker
	ari       *ari.Checker
	rateLimit chan struct{}
	wg        sync.WaitGroup
}

// PersistentCacheStore combines the optional ARI and CRL persistence
// interfaces. Passing nil keeps the scanner fully functional with memory-only
// caches, which is useful for tests and standalone use.
type PersistentCacheStore interface {
	ari.CacheStore
	revocation.CRLCacheStore
}

// NewScanner creates a new certificate scanner.
func NewScanner(cfg *models.ScannerConfig, cacheStore PersistentCacheStore) (*Scanner, error) {
	rl := make(chan struct{}, cfg.RateLimit)
	for i := 0; i < cfg.RateLimit; i++ {
		rl <- struct{}{}
	}

	// A scanner records whatever is presented, so certificate verification is
	// disabled (we must still capture expired / self-signed / revoked certs).
	transport := &http.Transport{
		MaxIdleConnsPerHost:   cfg.Workers,
		IdleConnTimeout:       cfg.HTTPIdleConnTimeout,
		TLSHandshakeTimeout:   cfg.Timeout,
		ExpectContinueTimeout: cfg.HTTPExpectContinueTimeout,
		DialContext:           (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // scanner captures untrusted certs by design
			MinVersion:         tls.VersionTLS10,
		},
	}

	ariChecker, err := ari.NewChecker(cfg.ARITimeout, cfg.ARICacheDefaultTTL, cfg.ARICacheMinimumTTL, cfg.ARIProviders, cacheStore)
	if err != nil {
		return nil, err
	}
	return &Scanner{
		config:    cfg,
		client:    &http.Client{Transport: transport, Timeout: cfg.Timeout},
		checker:   revocation.NewChecker(cfg.RevocationTimeout, cfg.CheckCRL, cfg.CRLCacheTTL, cacheStore),
		ari:       ariChecker,
		rateLimit: rl,
	}, nil
}

// Scan performs a complete scan. It is retained for callers that explicitly
// request a deep/manual scan; the adaptive scheduler uses ScanBaseline followed
// by Enrich so routine TLS monitoring does not fan out to external services.
func (s *Scanner) Scan(ctx context.Context, domain string) (*models.ScanResult, error) {
	return s.scan(ctx, domain, true)
}

// ScanBaseline captures only the endpoint's TLS state and certificate chain.
func (s *Scanner) ScanBaseline(ctx context.Context, domain string) (*models.ScanResult, error) {
	return s.scan(ctx, domain, false)
}

func (s *Scanner) scan(ctx context.Context, domain string, enrich bool) (*models.ScanResult, error) {
	start := time.Now()
	domain = models.GetDomain(domain)

	result := &models.ScanResult{
		Domain:               domain,
		ScannedAt:            start,
		RevocationStatus:     models.RevocationNotChecked,
		RevocationCheckedVia: models.CheckedViaNone,
		EvidenceStatus:       models.EvidenceStatusUnknown,
	}
	// Keep the resolver snapshot beside the TLS observation. It is cheap enough
	// for the baseline and is the only defensible public signal for a later
	// topology-change comparison.
	result.ResolvedIPs = s.resolveIPs(ctx, domain)
	result.ResolvedIPsKnown = len(result.ResolvedIPs) > 0

	select {
	case <-s.rateLimit:
		defer func() { s.rateLimit <- struct{}{} }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Certificate monitoring only needs the TLS handshake. Doing it first avoids
	// treating a server that closes an HTTP request (common for CDN/DNS names)
	// as a failed certificate endpoint. The HTTP path remains a compatibility
	// fallback for unusual servers that only complete the handshake through the
	// standard client transport.
	chain, stapled, connInfo, tlsErr := s.handshakeTLS(ctx, domain, result.ResolvedIPs)
	if tlsErr != nil {
		var httpsErr error
		chain, stapled, connInfo, httpsErr = s.handshakeHTTPS(ctx, domain, result.ResolvedIPs)
		if httpsErr != nil {
			result.Success = false
			result.FailureClass = FailureClassForErrors(tlsErr, httpsErr)
			result.Error = fmt.Sprintf("TLS attempt failed: %v; HTTPS fallback failed: %v", tlsErr, httpsErr)
			result.EvidenceStatus = models.EvidenceStatusNotApplicable
			result.EvidencePendingReason = "No certificate was obtained for evidence enrichment."
			result.ScanDuration = time.Since(start)
			return result, nil
		}
	}
	if len(chain) == 0 {
		result.Success = false
		result.FailureClass = models.ScanFailureNoEndpoint
		result.Error = "no certificate presented"
		result.EvidenceStatus = models.EvidenceStatusNotApplicable
		result.EvidencePendingReason = "No certificate was presented by the endpoint."
		result.ScanDuration = time.Since(start)
		return result, nil
	}

	result.Success = true
	result.ConnectionInfo = connInfo
	if connInfo != nil {
		connInfo.ResolvedIPs = append([]string(nil), result.ResolvedIPs...)
		// Keep the resolver snapshot pure. The dialled address can be a local
		// transparent-egress endpoint and is already retained separately in
		// ConnectionInfo.IPAddress; it must not become DNS topology evidence.
		if !result.ResolvedIPsKnown {
			connInfo.ResolvedIPs = nil
		}
	}
	result.RawChain = chain
	result.StapledOCSP = append([]byte(nil), stapled...)
	result.Cert = models.FromX509Cert(chain[0], start)
	result.Cert.Chain = models.BuildChainJSON(chain)
	for _, c := range chain {
		result.Chain = append(result.Chain, models.FromX509Cert(c, start))
	}

	if enrich {
		s.enrichResult(ctx, result)
	} else {
		result.EvidenceStatus = models.EvidenceStatusBaseline
	}

	result.ScanDuration = time.Since(start)
	return result, nil
}

// resolveIPs captures the current A/AAAA set without making DNS failure hide a
// successful TLS observation. The empty result means the resolver did not
// provide a usable snapshot, not that the domain has no DNS records.
func (s *Scanner) resolveIPs(ctx context.Context, domain string) []string {
	lookupCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	addresses := make([]net.IP, 0)
	for _, recordType := range []string{"A", "AAAA"} {
		values, err := s.resolveIPsViaDoH(lookupCtx, domain, recordType)
		if err != nil {
			continue
		}
		addresses = append(addresses, values...)
	}
	if len(addresses) == 0 {
		// The TLS handshake may still succeed through the host resolver, but a
		// failed public DNS snapshot must remain unknown rather than becoming
		// topology evidence from a synthetic WSL/enterprise answer.
		return nil
	}
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		ip := address.String()
		if !models.IsPublicIP(ip) {
			continue
		}
		result = addUniqueIP(result, ip)
	}
	sort.Strings(result)
	return result
}

// resolveIPsViaDoH uses public recursive resolvers so WSL/enterprise
// synthetic DNS answers cannot be persisted as public topology evidence.
func (s *Scanner) resolveIPsViaDoH(ctx context.Context, domain, recordType string) ([]net.IP, error) {
	clients := []string{
		"https://cloudflare-dns.com/dns-query?name=" + url.QueryEscape(domain) + "&type=" + recordType,
		"https://dns.google/resolve?name=" + url.QueryEscape(domain) + "&type=" + recordType,
	}
	client := &http.Client{Timeout: s.config.Timeout}
	for _, endpoint := range clients {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var payload struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		err = json.NewDecoder(resp.Body).Decode(&payload)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		values := make([]net.IP, 0, len(payload.Answer))
		for _, answer := range payload.Answer {
			ip := net.ParseIP(strings.TrimSpace(answer.Data))
			if ip == nil {
				continue
			}
			if (recordType == "A" && answer.Type != 1) || (recordType == "AAAA" && answer.Type != 28) {
				continue
			}
			values = append(values, ip)
		}
		if len(values) > 0 {
			return values, nil
		}
	}
	return nil, fmt.Errorf("public DNS resolution failed for %s", domain)
}

func addUniqueIP(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

// ProbeEndpoints performs a bounded, direct-IP TLS sweep. It is intentionally
// separate from ScanBaseline: the scheduler invokes it only after a candidate
// certificate/topology event, keeping routine Top-1000 monitoring lightweight.
func (s *Scanner) ProbeEndpoints(ctx context.Context, domain string, ips []string) []models.EndpointProbe {
	const maxEndpoints = 16
	unique := make([]string, 0, len(ips))
	for _, value := range ips {
		ip := strings.TrimSpace(value)
		if !models.IsPublicIP(ip) {
			continue
		}
		unique = addUniqueIP(unique, ip)
	}
	sort.Strings(unique)
	if len(unique) > maxEndpoints {
		unique = unique[:maxEndpoints]
	}
	probes := make([]models.EndpointProbe, 0, len(unique))
	for _, ip := range unique {
		probe := models.EndpointProbe{IPAddress: ip}
		probeCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
		chain, _, _, err := s.handshakeTLSAt(probeCtx, domain, ip)
		cancel()
		if err != nil {
			probe.Error = err.Error()
			probes = append(probes, probe)
			continue
		}
		if len(chain) == 0 {
			probe.Error = "no peer certificate found"
			probes = append(probes, probe)
			continue
		}
		probe.Success = true
		probe.Fingerprint = models.Fingerprint(chain[0])
		probe.SPKIFingerprint = models.SPKIFingerprint(chain[0])
		probes = append(probes, probe)
	}
	return probes
}

// Enrich performs the configured deep evidence checks against the certificate
// chain already captured in result. It never opens a second TLS connection.
func (s *Scanner) Enrich(ctx context.Context, result *models.ScanResult) {
	if result == nil {
		return
	}
	select {
	case <-s.rateLimit:
		defer func() { s.rateLimit <- struct{}{} }()
	case <-ctx.Done():
		result.EvidenceStatus = models.EvidenceStatusPending
		result.EvidencePendingReason = "Evidence enrichment was canceled before completion."
		if !result.ScannedAt.IsZero() {
			result.ScanDuration = time.Since(result.ScannedAt)
		}
		return
	}
	s.enrichResult(ctx, result)
	if !result.ScannedAt.IsZero() {
		result.ScanDuration = time.Since(result.ScannedAt)
	}
}

func (s *Scanner) enrichResult(ctx context.Context, result *models.ScanResult) {
	if !result.Success || len(result.RawChain) == 0 {
		result.EvidenceStatus = models.EvidenceStatusNotApplicable
		result.EvidencePendingReason = "No successful TLS certificate is available for evidence enrichment."
		return
	}
	leaf := result.RawChain[0]
	attempted := false
	var pending []string

	if s.config.CheckRevocation && !leaf.IsCA {
		hasRevocationSource := len(result.StapledOCSP) > 0 || len(leaf.OCSPServer) > 0 || (s.config.CheckCRL && len(leaf.CRLDistributionPoints) > 0)
		if hasRevocationSource {
			attempted = true
			revCtx, cancel := context.WithTimeout(ctx, s.config.RevocationTimeout)
			st := s.checker.Check(revCtx, result.RawChain, result.StapledOCSP)
			cancel()
			result.RevocationStatus = st.Status
			result.RevocationCheckedVia = st.CheckedVia
			checkedAt := time.Now().UTC()
			result.RevocationCheckedAt = &checkedAt
			result.RevokedAt = st.RevokedAt
			result.RevocationReason = st.Reason
			if st.Status == models.RevocationUnknown && st.CheckedVia == models.CheckedViaNone && (len(leaf.OCSPServer) > 0 || (s.config.CheckCRL && len(leaf.CRLDistributionPoints) > 0)) {
				pending = append(pending, "OCSP/CRL endpoints did not return verifiable revocation evidence")
			}
		}
	}

	// ARI (CA-recommended renewal window) is queried only for an enrichment pass.
	if s.config.CheckARI && !leaf.IsCA {
		attempted = true
		ariCtx, cancel := context.WithTimeout(ctx, s.config.ARITimeout)
		result.ARI = s.ari.Fetch(ariCtx, leaf)
		cancel()
		if result.ARI != nil && result.ARI.Status == models.ARIStatusError {
			pending = append(pending, "ARI endpoint returned a transient error")
		}
	}

	switch {
	case len(pending) > 0:
		result.EvidenceStatus = models.EvidenceStatusPending
		result.EvidencePendingReason = strings.Join(pending, "; ")
	case attempted:
		result.EvidenceStatus = models.EvidenceStatusComplete
		result.EvidencePendingReason = ""
	default:
		result.EvidenceStatus = models.EvidenceStatusNotApplicable
		result.EvidencePendingReason = "No configured deep evidence source applies to this certificate."
	}
}

// handshakeHTTPS performs an HTTPS GET and extracts the TLS state. It is kept
// as a fallback because a few non-standard endpoints behave differently when
// reached through net/http than through a bare TLS connection.
func (s *Scanner) handshakeHTTPS(ctx context.Context, domain string, addresses []string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
	if len(addresses) == 0 {
		return nil, nil, nil, fmt.Errorf("public DNS resolution failed for %s", domain)
	}
	address := addresses[0]
	url := fmt.Sprintf("https://%s/", net.JoinHostPort(domain, strconv.Itoa(s.config.TLSPort)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "*/*")

	transport := s.client.Transport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: s.config.Timeout}
	transport.DialContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(dialCtx, network, net.JoinHostPort(address, strconv.Itoa(s.config.TLSPort)))
	}
	client := &http.Client{Transport: transport, Timeout: s.config.Timeout}
	defer transport.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("HTTPS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, nil, nil, fmt.Errorf("no TLS certificate found")
	}

	connInfo := &models.ConnectionInfo{
		Protocol:    "HTTPS",
		TLSVersion:  models.GetTLSVersionName(resp.TLS.Version),
		CipherSuite: models.GetCipherSuiteName(resp.TLS.CipherSuite),
		IPAddress:   address,
	}
	return resp.TLS.PeerCertificates, resp.TLS.OCSPResponse, connInfo, nil
}

// handshakeTLS performs a direct TLS handshake on the configured TLS port.
func (s *Scanner) handshakeTLS(ctx context.Context, domain string, addresses []string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
	if len(addresses) == 0 {
		return nil, nil, nil, fmt.Errorf("public DNS resolution failed for %s", domain)
	}
	var lastErr error
	for _, address := range addresses {
		chain, stapled, info, err := s.handshakeTLSAt(ctx, domain, address)
		if err == nil {
			return chain, stapled, info, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no public TLS endpoint resolved for %s", domain)
	}
	return nil, nil, nil, lastErr
}

// handshakeTLSAt performs a TLS handshake with SNI set to domain while dialing
// address directly. It is used only with a public DNS address so the TLS
// endpoint and persisted topology evidence refer to the same network path.
func (s *Scanner) handshakeTLSAt(ctx context.Context, domain, address string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, //nolint:gosec // scanner captures untrusted certs by design
		MinVersion:         tls.VersionTLS10,
	}

	start := time.Now()
	dialer := &net.Dialer{Timeout: s.config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(s.config.TLSPort)))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("TCP dial failed: %w", err)
	}
	defer conn.Close()

	remoteIP := ""
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = addr.IP.String()
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil, nil, fmt.Errorf("no peer certificates found")
	}

	connInfo := &models.ConnectionInfo{
		Protocol:       "TLS",
		TLSVersion:     models.GetTLSVersionName(state.Version),
		CipherSuite:    models.GetCipherSuiteName(state.CipherSuite),
		ConnectionTime: time.Since(start).Milliseconds(),
		IPAddress:      remoteIP,
	}
	return state.PeerCertificates, state.OCSPResponse, connInfo, nil
}

type scanAttemptFunc func(context.Context, string) (*models.ScanResult, error)
type retryAfterFunc func(time.Duration) <-chan time.Time

// ScanWithRetry scans a domain with exponential backoff retries. Target scan
// failures still return a ScanResult so callers can persist the failed scan.
func (s *Scanner) ScanWithRetry(ctx context.Context, domain string) (*models.ScanResult, error) {
	return scanWithRetryConfig(ctx, domain, s.config.Retries, s.Scan, time.After, s.config.RetryBackoffUnit)
}

// ScanBaselineWithRetry retries only the lightweight TLS baseline operation.
func (s *Scanner) ScanBaselineWithRetry(ctx context.Context, domain string) (*models.ScanResult, error) {
	return scanWithRetryConfig(ctx, domain, s.config.Retries, s.ScanBaseline, time.After, s.config.RetryBackoffUnit)
}

func scanWithRetry(ctx context.Context, domain string, retries int, scan scanAttemptFunc, after retryAfterFunc) (*models.ScanResult, error) {
	return scanWithRetryConfig(ctx, domain, retries, scan, after, time.Second)
}

func scanWithRetryConfig(ctx context.Context, domain string, retries int, scan scanAttemptFunc, after retryAfterFunc, backoffUnit time.Duration) (*models.ScanResult, error) {
	if retries < 0 {
		retries = 0
	}

	var lastResult *models.ScanResult
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			select {
			case <-after(time.Duration(1<<uint(attempt)) * backoffUnit):
			case <-ctx.Done():
				if lastResult != nil {
					return lastResult, nil
				}
				return nil, ctx.Err()
			}
		}
		result, err := scan(ctx, domain)
		if err != nil {
			lastErr = err
			continue
		}
		if result == nil {
			lastErr = fmt.Errorf("scanner returned nil result")
			continue
		}
		if result.Success {
			return result, nil
		}
		lastResult = result
		lastErr = fmt.Errorf("%s", result.Error)
		// A deterministic DNS/TLS/endpoint result will not improve by repeating
		// it three times immediately. Scan() always classifies its target
		// failures; an empty class preserves retry behaviour for custom callers
		// and older tests that return synthetic results.
		if result.FailureClass != "" && !retryableFailureClass(result.FailureClass) {
			return result, nil
		}
	}
	if lastResult != nil {
		return lastResult, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("scan produced no result")
}

func retryableFailureClass(class string) bool {
	return class == models.ScanFailureNetwork
}

// FailureClassForError classifies errors returned before Scan can build a
// ScanResult, such as a canceled context or an unexpected scanner failure.
func FailureClassForError(errs ...error) string {
	return classifyFailure(errs...)
}

// FailureClassForErrors is also used when both the direct TLS and HTTP
// fallback attempts fail.
func FailureClassForErrors(errs ...error) string {
	return classifyFailure(errs...)
}

func classifyFailure(errs ...error) string {
	return models.ClassifyScanFailure(errs...)
}

// Close waits for in-flight work and releases resources.
func (s *Scanner) Close() error {
	s.wg.Wait()
	return nil
}

// ValidateDomain checks whether a domain is scannable.
func ValidateDomain(domain string) error {
	domain = strings.TrimSpace(models.GetDomain(domain))
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if strings.ContainsAny(domain, " \t\r\n") {
		return fmt.Errorf("domain contains invalid characters")
	}
	if models.IsPrivateIP(domain) {
		return fmt.Errorf("private IP addresses are not allowed")
	}
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("domain must contain a dot")
	}
	return nil
}
