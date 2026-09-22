package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	datasets  *datasetFetcher
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
	// Optional evidence controls have safe operational defaults. Explicitly
	// configured values are preserved; this keeps older config files useful while
	// enabling the deeper measurement path for new deployments.
	if len(cfg.DNSResolvers) == 0 {
		cfg.DNSResolvers = []string{
			"https://cloudflare-dns.com/dns-query",
			"https://dns.google/resolve",
			"https://dns.quad9.net/dns-query",
		}
	}
	if cfg.MaxEndpointSamples <= 0 {
		cfg.MaxEndpointSamples = 16
	}
	if cfg.EndpointProbeConcurrency <= 0 {
		cfg.EndpointProbeConcurrency = 4
	}
	if cfg.CTTimeout <= 0 {
		cfg.CTTimeout = 5 * time.Second
	}
	if strings.TrimSpace(cfg.CTEndpoint) == "" {
		cfg.CTEndpoint = "https://crt.sh/"
	}
	if cfg.RDAPTimeout <= 0 {
		cfg.RDAPTimeout = 8 * time.Second
	}
	if strings.TrimSpace(cfg.RDAPEndpoint) == "" {
		cfg.RDAPEndpoint = "https://rdap.org"
	}
	if strings.TrimSpace(cfg.RIPEstatEndpoint) == "" {
		cfg.RIPEstatEndpoint = defaultRIPEstatPrefixURL
	}
	if strings.TrimSpace(cfg.CloudflareIPv4URL) == "" {
		cfg.CloudflareIPv4URL = defaultCloudflareIPv4URL
	}
	if strings.TrimSpace(cfg.CloudflareIPv6URL) == "" {
		cfg.CloudflareIPv6URL = defaultCloudflareIPv6URL
	}
	if strings.TrimSpace(cfg.FastlyPublicIPURL) == "" {
		cfg.FastlyPublicIPURL = defaultFastlyPublicIPURL
	}
	if strings.TrimSpace(cfg.CloudfrontIPURL) == "" {
		cfg.CloudfrontIPURL = defaultCloudfrontIPURL
	}
	if strings.TrimSpace(cfg.ChromeLogListURL) == "" {
		cfg.ChromeLogListURL = defaultChromeLogListURL
	}
	if strings.TrimSpace(cfg.AppleLogListURL) == "" {
		cfg.AppleLogListURL = defaultAppleLogListURL
	}
	if strings.TrimSpace(cfg.AWSIPRangesURL) == "" {
		cfg.AWSIPRangesURL = defaultAWSIPRangesURL
	}
	if strings.TrimSpace(cfg.BunnyEdgeListURL) == "" {
		cfg.BunnyEdgeListURL = defaultBunnyEdgeListURL
	}
	if strings.TrimSpace(cfg.CertSpotterEndpoint) == "" {
		cfg.CertSpotterEndpoint = defaultCertSpotterURL
	}
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
	scan := &Scanner{
		config:    cfg,
		client:    &http.Client{Transport: transport, Timeout: cfg.Timeout},
		checker:   revocation.NewChecker(cfg.RevocationTimeout, cfg.CheckCRL, cfg.CRLCacheTTL, cacheStore),
		ari:       ariChecker,
		rateLimit: rl,
	}
	if cfg.CheckOfficialPrefixes || cfg.CheckChromeLogList || cfg.CheckAppleLogList || cfg.CheckRIPEstat {
		scan.datasets = newDatasetFetcher(cfg)
		scan.datasets.Start(context.Background())
	}
	return scan, nil
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
	// Keep independent public-recursive resolver snapshots beside the TLS
	// observation. A union alone cannot tell CDN steering from a real topology
	// transition, so the resolver quorum and CNAME chain are retained as well.
	result.Topology = s.resolveTopology(ctx, domain)
	if result.Topology != nil {
		result.ResolvedIPs = append([]string(nil), result.Topology.PublicIPs...)
	}
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
		connInfo.SCTs = mergeSCTObservations(append(append([]models.SCTObservation(nil), connInfo.SCTs...), parseEmbeddedSCTs(chain[0])...))
		connInfo.ResolvedIPs = append([]string(nil), result.ResolvedIPs...)
		// Keep the resolver snapshot pure. The dialled address can be a local
		// transparent-egress endpoint and is already retained separately in
		// ConnectionInfo.IPAddress; it must not become DNS topology evidence.
		if !result.ResolvedIPsKnown {
			connInfo.ResolvedIPs = nil
		}
	}
	result.RawChain = chain
	ip := ""
	if connInfo != nil {
		ip = connInfo.IPAddress
	}
	result.TLSFindings = validateChain(domain, ip, chain, time.Now())
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

// resolveIPs is retained for callers that only need the public-IP union. New
// code should use resolveTopology so resolver identity and agreement are not
// discarded.
func (s *Scanner) resolveIPs(ctx context.Context, domain string) []string {
	topology := s.resolveTopology(ctx, domain)
	if topology == nil {
		return nil
	}
	return append([]string(nil), topology.PublicIPs...)
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type dohPayload struct {
	Status    int         `json:"Status"`
	AD        bool        `json:"AD"`
	Answer    []dohAnswer `json:"Answer"`
	Authority []dohAnswer `json:"Authority"`
}

// queryDoH uses a single configured public recursive resolver and returns the
// raw RRset. It deliberately accepts both Google's /resolve endpoint and the
// RFC 8484 JSON endpoint used by Cloudflare/Quad9.
func (s *Scanner) queryDoH(ctx context.Context, resolver, domain, recordType string) ([]dohAnswer, error) {
	payload, err := s.queryDoHPayload(ctx, resolver, domain, recordType)
	if err != nil {
		return nil, err
	}
	return append(payload.Answer, payload.Authority...), nil
}

func (s *Scanner) queryDoHPayload(ctx context.Context, resolver, domain, recordType string) (dohPayload, error) {
	endpoint, err := url.Parse(strings.TrimSpace(resolver))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return dohPayload{}, fmt.Errorf("invalid DoH resolver %q", resolver)
	}
	query := endpoint.Query()
	query.Set("name", domain)
	query.Set("type", recordType)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return dohPayload{}, err
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{Timeout: s.config.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return dohPayload{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return dohPayload{}, fmt.Errorf("DoH resolver returned HTTP %d", resp.StatusCode)
	}
	var payload dohPayload
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return dohPayload{}, err
	}
	if payload.Status != 0 && payload.Status != 3 { // NOERROR or NXDOMAIN
		return dohPayload{}, fmt.Errorf("DNS status %d", payload.Status)
	}
	return payload, nil
}

// resolveTopology captures A/AAAA/CNAME answers from independent public
// resolvers. PublicIPs is the union (for bounded probing), while ConsensusIPs
// is the majority view used for transition decisions.
func (s *Scanner) resolveTopology(ctx context.Context, domain string) *models.TopologySnapshot {
	resolvers := append([]string(nil), s.config.DNSResolvers...)
	if len(resolvers) == 0 {
		resolvers = []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/resolve", "https://dns.quad9.net/dns-query"}
	}
	type resolverResult struct {
		index int
		obs   models.DNSResolverObservation
	}
	results := make(chan resolverResult, len(resolvers))
	var wg sync.WaitGroup
	for i, resolver := range resolvers {
		wg.Add(1)
		go func(index int, resolver string) {
			defer wg.Done()
			obs := models.DNSResolverObservation{Resolver: resolver}
			resolverCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
			defer cancel()
			dnssecHits := 0
			dnssecChecks := 0
			for _, typ := range []string{"A", "AAAA", "CNAME", "HTTPS", "NS"} {
				payload, err := s.queryDoHPayload(resolverCtx, resolver, domain, typ)
				if err != nil {
					obs.Error = err.Error()
					continue
				}
				dnssecChecks++
				if payload.AD {
					dnssecHits++
				}
				answers := append(payload.Answer, payload.Authority...)
				for _, answer := range answers {
					if answer.TTL > 0 && (obs.TTL == 0 || answer.TTL < obs.TTL) {
						obs.TTL = answer.TTL
					}
					switch answer.Type {
					case 1:
						if ip := net.ParseIP(strings.TrimSpace(answer.Data)); ip != nil && models.IsPublicIP(ip.String()) {
							obs.A = addUniqueIP(obs.A, ip.String())
						}
					case 28:
						if ip := net.ParseIP(strings.TrimSpace(answer.Data)); ip != nil && models.IsPublicIP(ip.String()) {
							obs.AAAA = addUniqueIP(obs.AAAA, ip.String())
						}
					case 5:
						name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(answer.Data)), ".")
						if name != "" {
							obs.CNAME = addUniqueIP(obs.CNAME, name)
						}
					case 2:
						name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(answer.Data)), ".")
						if name != "" {
							obs.NS = addUniqueIP(obs.NS, name)
						}
					case 65:
						for _, target := range models.ParseHTTPSTargets(answer.Data) {
							if target != "" {
								obs.HTTPS = addUniqueIP(obs.HTTPS, target)
							}
						}
					}
				}
			}
			if len(obs.NS) == 0 {
				if parent := parentDomain(domain); parent != "" && parent != domain {
					if answers, err := s.queryDoH(resolverCtx, resolver, parent, "NS"); err == nil {
						for _, answer := range answers {
							if answer.Type != 2 {
								continue
							}
							name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(answer.Data)), ".")
							if name != "" {
								obs.NS = addUniqueIP(obs.NS, name)
							}
						}
					}
				}
			}
			sort.Strings(obs.A)
			sort.Strings(obs.AAAA)
			sort.Strings(obs.CNAME)
			sort.Strings(obs.HTTPS)
			sort.Strings(obs.NS)
			obs.DNSSEC = dnssecChecks > 0 && dnssecHits == dnssecChecks
			// A CNAME-only response is useful control-plane evidence, but it is
			// not an address answer and must not increase the address resolver
			// quorum used for topology transitions.
			obs.Success = len(obs.A) > 0 || len(obs.AAAA) > 0
			if !obs.Success && obs.Error == "" {
				if len(obs.CNAME) > 0 {
					obs.Error = "resolver returned CNAME but no usable public address"
				} else {
					obs.Error = "resolver returned no usable public records"
				}
			}
			results <- resolverResult{index: index, obs: obs}
		}(i, resolver)
	}
	wg.Wait()
	close(results)
	ordered := make([]models.DNSResolverObservation, len(resolvers))
	for item := range results {
		ordered[item.index] = item.obs
	}
	snapshot := &models.TopologySnapshot{Resolvers: ordered}
	addressResolvers := make(map[string]int)
	successful := 0
	dnssecValidated := 0
	for _, obs := range ordered {
		if obs.DNSSEC {
			dnssecValidated++
		}
		// Keep CNAME evidence even when the resolver did not return an address.
		// This lets the diagnosis explain a control-plane change without turning
		// a CNAME-only view into a false address quorum.
		for _, cname := range obs.CNAME {
			if !containsString(snapshot.CNAMEChain, cname) {
				snapshot.CNAMEChain = append(snapshot.CNAMEChain, cname)
			}
		}
		for _, target := range obs.HTTPS {
			if !containsString(snapshot.HTTPSTargets, target) {
				snapshot.HTTPSTargets = append(snapshot.HTTPSTargets, target)
			}
		}
		for _, ns := range obs.NS {
			if !containsString(snapshot.NSHosts, ns) {
				snapshot.NSHosts = append(snapshot.NSHosts, ns)
			}
		}
		if !obs.Success {
			continue
		}
		successful++
		seen := make(map[string]struct{})
		for _, ip := range append(append([]string{}, obs.A...), obs.AAAA...) {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			seen[ip] = struct{}{}
			if !containsString(snapshot.PublicIPs, ip) {
				snapshot.PublicIPs = append(snapshot.PublicIPs, ip)
			}
		}
		for ip := range seen {
			addressResolvers[ip]++
		}
	}
	if successful > 0 {
		quorum := successful/2 + 1
		for ip, count := range addressResolvers {
			if count >= quorum {
				snapshot.ConsensusIPs = append(snapshot.ConsensusIPs, ip)
			}
		}
		snapshot.ResolverQuorum = successful
		// Agreement is the fraction of successful resolvers sharing the most
		// common address. It is intentionally conservative for CDN steering.
		maxCount := 0
		for _, count := range addressResolvers {
			if count > maxCount {
				maxCount = count
			}
		}
		if successful > 0 {
			snapshot.ResolverAgreement = float64(maxCount) / float64(successful)
		}
	}
	sort.Strings(snapshot.PublicIPs)
	sort.Strings(snapshot.ConsensusIPs)
	sort.Strings(snapshot.CNAMEChain)
	sort.Strings(snapshot.HTTPSTargets)
	sort.Strings(snapshot.NSHosts)
	snapshot.DNSSECValidated = dnssecValidated
	canonical, _ := json.Marshal(struct {
		IPs       []string `json:"ips"`
		Consensus []string `json:"consensus"`
		CNAME     []string `json:"cname"`
		HTTPS     []string `json:"https"`
		NS        []string `json:"ns"`
	}{snapshot.PublicIPs, snapshot.ConsensusIPs, snapshot.CNAMEChain, snapshot.HTTPSTargets, snapshot.NSHosts})
	digest := sha256.Sum256(canonical)
	snapshot.TopologyHash = hex.EncodeToString(digest[:])
	return snapshot
}

func containsString(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}

// resolveIPsViaDoH remains as a small compatibility helper for tests and
// callers that expect a single resolver-style query.
func (s *Scanner) resolveIPsViaDoH(ctx context.Context, domain, recordType string) ([]net.IP, error) {
	resolvers := s.config.DNSResolvers
	if len(resolvers) == 0 {
		resolvers = []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/resolve", "https://dns.quad9.net/dns-query"}
	}
	answers, err := s.queryDoH(ctx, resolvers[0], domain, recordType)
	if err != nil {
		return nil, err
	}
	values := make([]net.IP, 0, len(answers))
	for _, answer := range answers {
		ip := net.ParseIP(strings.TrimSpace(answer.Data))
		if ip == nil || (recordType == "A" && answer.Type != 1) || (recordType == "AAAA" && answer.Type != 28) {
			continue
		}
		values = append(values, ip)
	}
	return values, nil
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
// certificate/topology event, keeping routine Top-N monitoring lightweight.
func (s *Scanner) ProbeEndpoints(ctx context.Context, domain string, ips []string) []models.EndpointProbe {
	maxEndpoints := s.config.MaxEndpointSamples
	if maxEndpoints <= 0 {
		maxEndpoints = 16
	}
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
	probes := make([]models.EndpointProbe, len(unique))
	var wg sync.WaitGroup
	concurrency := s.config.EndpointProbeConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	slots := make(chan struct{}, concurrency)
	for index, ip := range unique {
		wg.Add(1)
		go func(index int, ip string) {
			defer wg.Done()
			probe := models.EndpointProbe{IPAddress: ip}
			defer func() { probes[index] = probe }()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				probe.Error = ctx.Err().Error()
				return
			}
			select {
			case <-s.rateLimit:
				defer func() { s.rateLimit <- struct{}{} }()
			case <-ctx.Done():
				probe.Error = ctx.Err().Error()
				return
			}
			probeCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
			chain, _, info, err := s.handshakeTLSAt(probeCtx, domain, ip)
			cancel()
			if err != nil {
				probe.Error = err.Error()
				return
			}
			if len(chain) == 0 {
				probe.Error = "no peer certificate found"
				return
			}
			probe.Success = true
			probe.Fingerprint = models.Fingerprint(chain[0])
			probe.SPKIFingerprint = models.SPKIFingerprint(chain[0])
			probe.IssuerCN = chain[0].Issuer.CommonName
			probe.CommonName = chain[0].Subject.CommonName
			probe.SerialNumber = chain[0].SerialNumber.Text(16)
			probe.SANs = append([]string(nil), chain[0].DNSNames...)
			// The key algorithm and the covered name set are what separate a
			// deliberate RSA plus ECDSA pair from endpoints that disagree: the
			// pair serves the same names from the same issuer on purpose.
			probe.KeyAlgorithm = chain[0].PublicKeyAlgorithm.String()
			probe.KeySize = models.PublicKeySize(chain[0])
			probe.SANsHash = models.SANSetHash(chain[0].DNSNames)
			nb := chain[0].NotBefore.UTC()
			probe.NotBefore = &nb
			na := chain[0].NotAfter.UTC()
			probe.NotAfter = &na
			if info != nil {
				probe.TLSVersion = info.TLSVersion
				probe.CipherSuite = info.CipherSuite
			}
			probe.Findings = validateChain(domain, ip, chain, time.Now())
		}(index, ip)
	}
	wg.Wait()
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
	deep := &models.DeepEvidence{CollectedAt: time.Now().UTC(), Topology: result.Topology, EndpointProbes: result.EndpointProbes, Status: models.EvidenceStatusPending}
	deep.SCTs = collectResultSCTs(result)
	if s.config.CheckSCTInclusion && len(deep.SCTs) > 0 {
		attempted = true
		deep.SCTs = s.verifySCTInclusions(ctx, result.RawChain, deep.SCTs)
	}
	if s.config.CheckCAA {
		attempted = true
		if records, err := s.fetchCAA(ctx, result.Domain); err != nil {
			deep.Errors = append(deep.Errors, "CAA: "+err.Error())
			pending = append(pending, "CAA lookup failed")
		} else {
			deep.CAA = records
		}
	}
	if s.config.CheckCT {
		attempted = true
		if entries, err := s.fetchCT(ctx, result); err != nil {
			deep.Errors = append(deep.Errors, "CT: "+err.Error())
			pending = append(pending, "certificate-transparency lookup failed")
		} else {
			deep.CT = entries
		}
	}
	if s.config.CheckCertSpotter {
		attempted = true
		if entries, err := s.fetchCertSpotter(ctx, result); err != nil {
			deep.Errors = append(deep.Errors, "CertSpotter: "+err.Error())
			pending = append(pending, "independent CT index lookup failed")
		} else {
			deep.CT = mergeCTObservations(append(deep.CT, entries...))
		}
	}
	if s.config.CheckHTTPFingerprint {
		attempted = true
		if fp, err := s.fetchHTTPFingerprint(ctx, result.Domain, result.ConnectionInfo); err != nil {
			deep.Errors = append(deep.Errors, "HTTP: "+err.Error())
			pending = append(pending, "HTTP/CDN fingerprint lookup failed")
		} else {
			deep.HTTP = fp
		}
	}
	if s.config.CheckRDAP || s.config.CheckASN || s.config.CheckRIPEstat {
		attempted = true
		addresses := directoryAddresses(result)
		if directory, err := s.fetchDirectory(ctx, result.Domain, addresses); err != nil {
			deep.Errors = append(deep.Errors, "directory: "+err.Error())
			if directory != nil {
				deep.Directory = directory
			}
			pending = append(pending, "RDAP/ASN lookup failed")
		} else {
			deep.Directory = directory
		}
	}

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
	if result.EvidenceStatus == models.EvidenceStatusComplete {
		deep.Status = models.EvidenceStatusComplete
	} else if result.EvidenceStatus == models.EvidenceStatusNotApplicable {
		deep.Status = models.EvidenceStatusNotApplicable
	}
	result.DeepEvidence = deep
}

func (s *Scanner) fetchCAA(ctx context.Context, domain string) ([]models.CAARecord, error) {
	resolvers := s.config.DNSResolvers
	if len(resolvers) == 0 {
		resolvers = []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"}
	}
	var firstErr error
	for _, resolver := range resolvers {
		answers, err := s.queryDoH(ctx, resolver, domain, "CAA")
		if err != nil {
			firstErr = err
			continue
		}
		records := make([]models.CAARecord, 0, len(answers))
		for _, answer := range answers {
			if answer.Type != 257 {
				continue
			}
			parts := strings.Fields(answer.Data)
			if len(parts) < 3 {
				continue
			}
			flag, _ := strconv.Atoi(parts[0])
			tag := strings.Trim(parts[1], `"`)
			value := strings.Trim(strings.Join(parts[2:], " "), `"`)
			records = append(records, models.CAARecord{Flag: uint8(flag), Tag: tag, Value: value})
		}
		return records, nil
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no configured resolver returned CAA")
	}
	return nil, firstErr
}

func (s *Scanner) fetchCT(ctx context.Context, result *models.ScanResult) ([]models.CTObservation, error) {
	if result == nil {
		return nil, fmt.Errorf("CT lookup has no scan result")
	}
	queries := make([]string, 0, 3)
	if result.Cert != nil && result.Cert.Fingerprint != "" {
		queries = append(queries, result.Cert.Fingerprint)
	}
	if result.Cert != nil && result.Cert.SerialNumber != "" {
		queries = append(queries, result.Cert.SerialNumber)
	}
	if result.Domain != "" {
		queries = append(queries, result.Domain)
	}
	var firstErr error
	merged := make([]models.CTObservation, 0)
	for _, query := range queries {
		entries, err := s.fetchCTQuery(ctx, query)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		merged = append(merged, entries...)
		if result.Cert != nil && ctContainsLeaf(entries, result.Cert.Fingerprint, result.Cert.SerialNumber) {
			return mergeCTObservations(merged), nil
		}
		if len(merged) >= 40 {
			break
		}
	}
	if len(merged) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return mergeCTObservations(merged), nil
}

func (s *Scanner) fetchCTQuery(ctx context.Context, query string) ([]models.CTObservation, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(s.config.CTEndpoint), "/")
	if endpoint == "" {
		return nil, fmt.Errorf("CT endpoint is empty")
	}
	requestCtx, cancel := context.WithTimeout(ctx, s.config.CTTimeout)
	defer cancel()
	queryURL := endpoint + "/?q=" + url.QueryEscape(query) + "&output=json"
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: s.config.CTTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CT endpoint returned HTTP %d", resp.StatusCode)
	}
	var raw []struct {
		ID             int64  `json:"id"`
		IssuerName     string `json:"issuer_name"`
		SerialNumber   string `json:"serial_number"`
		SHA256         string `json:"sha256"`
		NotBefore      string `json:"not_before"`
		NotAfter       string `json:"not_after"`
		EntryTimestamp string `json:"entry_timestamp"`
		NameValue      string `json:"name_value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&raw); err != nil {
		return nil, err
	}
	entries := make([]models.CTObservation, 0, len(raw))
	for _, item := range raw {
		entry := models.CTObservation{
			ID:           item.ID,
			IssuerName:   item.IssuerName,
			SerialNumber: normalizeSerial(item.SerialNumber),
			SHA256:       strings.ToLower(strings.TrimSpace(item.SHA256)),
			Names:        strings.Fields(strings.ReplaceAll(item.NameValue, "\n", " ")),
			Source:       "crt.sh",
		}
		for rawValue, target := range map[string]**time.Time{item.NotBefore: &entry.NotBefore, item.NotAfter: &entry.NotAfter, item.EntryTimestamp: &entry.EntryTimestamp} {
			if strings.TrimSpace(rawValue) == "" {
				continue
			}
			if parsed, parseErr := time.Parse(time.RFC3339, rawValue); parseErr == nil {
				value := parsed.UTC()
				*target = &value
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func mergeCTObservations(values []models.CTObservation) []models.CTObservation {
	seen := make(map[string]int, len(values))
	out := make([]models.CTObservation, 0, len(values))
	for _, value := range values {
		key := value.SHA256
		if key == "" {
			key = normalizeSerial(value.SerialNumber) + "|" + value.IssuerName
		}
		if key == "|" || key == "" {
			key = fmt.Sprintf("%d", value.ID)
		}
		if index, ok := seen[key]; ok {
			if out[index].Source != "" && value.Source != "" && !strings.Contains(out[index].Source, value.Source) {
				out[index].Source = out[index].Source + "+" + value.Source
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, value)
	}
	return out
}

func ctContainsLeaf(entries []models.CTObservation, fingerprint, serial string) bool {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	serial = normalizeSerial(serial)
	for _, entry := range entries {
		if fingerprint != "" && strings.ToLower(strings.TrimSpace(entry.SHA256)) == fingerprint {
			return true
		}
		if serial != "" && normalizeSerial(entry.SerialNumber) == serial {
			return true
		}
	}
	return false
}

func normalizeSerial(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, ":", "")
	value = strings.TrimPrefix(value, "0x")
	return strings.TrimLeft(value, "0")
}

func (s *Scanner) fetchHTTPFingerprint(ctx context.Context, domain string, info *models.ConnectionInfo) (*models.HTTPFingerprint, error) {
	requestCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	address := ""
	if info != nil {
		address = info.IPAddress
	}
	if address == "" {
		// Resolve once. The previous implementation performed two full
		// multi-resolver snapshots here, multiplying latency and external DNS
		// traffic during every deep round.
		resolved := s.resolveIPs(requestCtx, domain)
		if len(resolved) > 0 {
			address = resolved[0]
		}
	}
	if address == "" {
		return nil, fmt.Errorf("no public address available")
	}
	transport := s.client.Transport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: s.config.Timeout}
	transport.DialContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(dialCtx, network, net.JoinHostPort(address, strconv.Itoa(s.config.TLSPort)))
	}
	client := &http.Client{Transport: transport, Timeout: s.config.Timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	fp := &models.HTTPFingerprint{IPAddress: address, StatusCode: resp.StatusCode, Server: resp.Header.Get("Server"), Via: resp.Header.Get("Via"), Cache: resp.Header.Get("Age")}
	fp.Redirect = resp.Header.Get("Location")
	for _, name := range []string{"cf-ray", "x-cache", "x-served-by", "x-amz-cf-id", "x-akamai-transformed", "x-fastly-request-id", "x-cdn"} {
		if value := resp.Header.Get(name); value != "" {
			fp.ProviderSignals = append(fp.ProviderSignals, name+"="+value)
		}
	}
	return fp, nil
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
	client := &http.Client{Transport: transport, Timeout: s.config.Timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
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
		SCTs:        handshakeSCTs(resp.TLS),
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
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
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
		Protocol:           "TLS",
		TLSVersion:         models.GetTLSVersionName(state.Version),
		CipherSuite:        models.GetCipherSuiteName(state.CipherSuite),
		NegotiatedProtocol: state.NegotiatedProtocol,
		ALPN:               state.NegotiatedProtocol,
		ConnectionTime:     time.Since(start).Milliseconds(),
		IPAddress:          remoteIP,
		SCTs:               handshakeSCTs(&state),
	}
	return state.PeerCertificates, state.OCSPResponse, connInfo, nil
}

func handshakeSCTs(state *tls.ConnectionState) []models.SCTObservation {
	if state == nil {
		return nil
	}
	return parseHandshakeSCTs(state.SignedCertificateTimestamps)
}

func collectResultSCTs(result *models.ScanResult) []models.SCTObservation {
	if result == nil {
		return nil
	}
	out := make([]models.SCTObservation, 0, 4)
	if result.ConnectionInfo != nil {
		out = append(out, result.ConnectionInfo.SCTs...)
	}
	if len(result.RawChain) > 0 {
		out = append(out, parseEmbeddedSCTs(result.RawChain[0])...)
	}
	return mergeSCTObservations(out)
}

func directoryAddresses(result *models.ScanResult) []string {
	if result == nil {
		return nil
	}
	out := append([]string(nil), result.ResolvedIPs...)
	if result.ConnectionInfo != nil && result.ConnectionInfo.IPAddress != "" {
		out = addUniqueIP(out, result.ConnectionInfo.IPAddress)
	}
	for _, probe := range result.EndpointProbes {
		if probe.IPAddress != "" {
			out = addUniqueIP(out, probe.IPAddress)
		}
	}
	return out
}

func parentDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	labels := strings.Split(domain, ".")
	if len(labels) < 3 {
		return ""
	}
	return strings.Join(labels[1:], ".")
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
	if s.datasets != nil {
		s.datasets.Stop()
	}
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
