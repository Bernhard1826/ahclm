package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	config         *models.ScannerConfig
	client         *http.Client
	evidenceClient *http.Client
	checker        *revocation.Checker
	ari            *ari.Checker
	datasets       *datasetFetcher
	rateLimit      chan struct{}
	wg             sync.WaitGroup
	// External CT services are paced and back off after HTTP 429; results
	// for the same query are reused instead of asked for again.
	crtsh                 *serviceGate
	certSpotter           *serviceGate
	globalPing            *serviceGate
	globalProbeScanBudget *globalProbeScanBudget
	// ipv6Route is false when this vantage has no route to IPv6 addresses;
	// such addresses are recorded as unobservable instead of being dialled.
	ipv6Route bool
	// probeHandshake replaces the endpoint handshake in legacy tests. The
	// SNI-aware hook below is used by selection-matrix tests and production
	// probes when the requested SNI must be varied.
	probeHandshake        func(ctx context.Context, domain, address string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error)
	probeHandshakeWithSNI func(ctx context.Context, domain, address, serverName string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error)
}

type freshGlobalProbeContextKey struct{}

func withFreshGlobalProbes(ctx context.Context) context.Context {
	return context.WithValue(ctx, freshGlobalProbeContextKey{}, true)
}

func requestsFreshGlobalProbes(ctx context.Context) bool {
	fresh, _ := ctx.Value(freshGlobalProbeContextKey{}).(bool)
	return fresh
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
	if cfg.EndpointHandshakes <= 0 {
		cfg.EndpointHandshakes = 3
	}
	if cfg.EndpointProbeConcurrency <= 0 {
		cfg.EndpointProbeConcurrency = 4
	}
	if cfg.RelatedNameProbeLimit <= 0 {
		cfg.RelatedNameProbeLimit = 8
	}
	if cfg.RelatedNameProbeTimeout <= 0 {
		cfg.RelatedNameProbeTimeout = 90 * time.Second
	}
	if strings.TrimSpace(cfg.GlobalProbeEndpoint) == "" {
		cfg.GlobalProbeEndpoint = "https://api.globalping.io"
	}
	if cfg.GlobalProbeTimeout <= 0 {
		cfg.GlobalProbeTimeout = 45 * time.Second
	}
	if cfg.GlobalProbeScanTestsPerHour <= 0 {
		cfg.GlobalProbeScanTestsPerHour = 100
	}
	if len(cfg.GlobalProbeLocations) == 0 {
		cfg.GlobalProbeLocations = []string{"NA", "EU", "AS"}
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
		config:         cfg,
		client:         &http.Client{Transport: transport, Timeout: cfg.Timeout},
		evidenceClient: &http.Client{Timeout: cfg.Timeout},
		checker:        revocation.NewChecker(cfg.RevocationTimeout, cfg.CheckCRL, cfg.CRLCacheTTL, cacheStore),
		ari:            ariChecker,
		rateLimit:      rl,
		// crt.sh and the unauthenticated CertSpotter API throttle aggressively:
		// one request every few seconds, reused for a day per query.
		crtsh:                 newServiceGate("crt.sh", 3*time.Second, 24*time.Hour, 20000),
		certSpotter:           newServiceGate("CertSpotter", 2*time.Second, 24*time.Hour, 20000),
		globalPing:            newServiceGate("Globalping", time.Second, 30*time.Minute, 2000),
		globalProbeScanBudget: newGlobalProbeScanBudget(cfg.GlobalProbeScanTestsPerHour),
		ipv6Route:             hasIPv6Route(),
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

// ScanFresh performs a complete scan while bypassing cached Globalping probe
// results. It uses one cross-region HTTPS measurement so repeated manual
// remeasurement does not spend a second API measurement on a DNS trace.
func (s *Scanner) ScanFresh(ctx context.Context, domain string) (*models.ScanResult, error) {
	return s.scan(withFreshGlobalProbes(ctx), domain, true)
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
		for i := range connInfo.SCTs {
			connInfo.SCTs[i].SignatureVerified = verifySCTSignature(chain, connInfo.SCTs[i])
		}
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

// wireOnlyResolvers remembers resolvers that rejected the JSON query form, so
// later queries go straight to RFC 8484 instead of paying two round trips.
var wireOnlyResolvers sync.Map

func (s *Scanner) queryDoHPayload(ctx context.Context, resolver, domain, recordType string) (dohPayload, error) {
	if _, wireOnly := wireOnlyResolvers.Load(resolver); wireOnly {
		return s.queryDoHWire(ctx, resolver, domain, recordType)
	}
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
		// Quad9's /dns-query only speaks RFC 8484 wire format and answers the
		// JSON name/type query with 400; switch that resolver to wire format.
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnsupportedMediaType {
			wireOnlyResolvers.Store(resolver, true)
			payload, wireErr := s.queryDoHWire(ctx, resolver, domain, recordType)
			if wireErr != nil {
				return dohPayload{}, fmt.Errorf("DoH resolver returned HTTP %d for JSON; wire format: %w", resp.StatusCode, wireErr)
			}
			return payload, nil
		}
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
				// NS records from the authority section of an A/AAAA response are
				// referral/delegation material, not necessarily the zone's own
				// authoritative servers. Only the NS answer section is used for
				// direct authoritative probing; otherwise a recursive referral can
				// pollute the nameserver set and make the comparison meaningless.
				answers := payload.Answer
				if typ != "NS" {
					answers = append(answers, payload.Authority...)
				}
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
					if payload, err := s.queryDoHPayload(resolverCtx, resolver, parent, "NS"); err == nil {
						for _, answer := range payload.Answer {
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
	s.enrichAuthoritativeTopology(ctx, domain, snapshot)
	snapshot.DNSSECValidated = dnssecValidated
	canonical, _ := json.Marshal(struct {
		IPs        []string `json:"ips"`
		Consensus  []string `json:"consensus"`
		CNAME      []string `json:"cname"`
		HTTPS      []string `json:"https"`
		NS         []string `json:"ns"`
		Authority  []string `json:"authority"`
		AuthorityC []string `json:"authority_cname"`
	}{snapshot.PublicIPs, snapshot.ConsensusIPs, snapshot.CNAMEChain, snapshot.HTTPSTargets, snapshot.NSHosts, snapshot.AuthoritativeIPs, snapshot.AuthoritativeCNAME})
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
	return s.ProbeEndpointsRotated(ctx, domain, ips, 0)
}

// ProbeRelatedNames actively checks the SAN names that recently entered or
// left a root-domain certificate. It measures the public DNS/TLS/HTTP state
// now; it never claims to recover a deleted record or a private deployment
// event. The bounded rotated window prevents a large changing SAN set from
// becoming an unbounded scan fan-out.
func (s *Scanner) ProbeRelatedNames(ctx context.Context, root string, candidates []models.RelatedNameCandidate, rotation int, rootTopology *models.TopologySnapshot, rootCert *models.Certificate, rootHTTP *models.HTTPFingerprint) []models.RelatedNameProbe {
	root = models.GetDomain(root)
	if root == "" || len(candidates) == 0 || s.config.RelatedNameProbeLimit <= 0 {
		return nil
	}
	selected := selectRelatedNameCandidates(root, candidates, s.config.RelatedNameProbeLimit, rotation)
	if len(selected) == 0 {
		return nil
	}

	probes := make([]models.RelatedNameProbe, len(selected))
	concurrency := s.config.EndpointProbeConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > len(selected) {
		concurrency = len(selected)
	}
	slots := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for index, candidate := range selected {
		wg.Add(1)
		go func(index int, candidate models.RelatedNameCandidate) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				probes[index] = relatedNameCanceledProbe(candidate)
				return
			}
			probes[index] = s.probeRelatedName(ctx, root, candidate, rotation, rootTopology, rootCert, rootHTTP)
		}(index, candidate)
	}
	wg.Wait()
	return probes
}

// selectRelatedNameCandidates takes one non-overlapping batch per rotation.
// For example, with limit=8, rotations 0, 1 and 2 select 0..7, 8..15 and
// 16..23. This lets repeated deep rounds cover a long history rather than
// moving a one-name sliding window across it.
func selectRelatedNameCandidates(root string, candidates []models.RelatedNameCandidate, limit, rotation int) []models.RelatedNameCandidate {
	root = models.GetDomain(root)
	if root == "" || limit <= 0 {
		return nil
	}
	unique := make([]models.RelatedNameCandidate, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate.Name = models.GetDomain(candidate.Name)
		if candidate.Name == "" || candidate.Name == root {
			continue
		}
		if _, ok := seen[candidate.Name]; ok {
			continue
		}
		seen[candidate.Name] = struct{}{}
		unique = append(unique, candidate)
	}
	if len(unique) == 0 {
		return nil
	}
	if limit > len(unique) {
		limit = len(unique)
	}
	start := 0
	if rotation > 0 {
		start = (rotation * limit) % len(unique)
	}
	selected := make([]models.RelatedNameCandidate, 0, limit)
	for index := 0; index < limit; index++ {
		selected = append(selected, unique[(start+index)%len(unique)])
	}
	return selected
}

func relatedNameCanceledProbe(candidate models.RelatedNameCandidate) models.RelatedNameProbe {
	return models.RelatedNameProbe{
		Name: candidate.Name, FirstObservedAt: candidate.FirstObservedAt, LastObservedAt: candidate.LastObservedAt,
		AddedCount: candidate.AddedCount, RemovedCount: candidate.RemovedCount, BranchLikeLabel: candidate.BranchLikeLabel,
		ProbedAt: time.Now().UTC(), DNSStatus: "inconclusive", Error: context.Canceled.Error(),
	}
}

func (s *Scanner) probeRelatedName(ctx context.Context, root string, candidate models.RelatedNameCandidate, rotation int, rootTopology *models.TopologySnapshot, rootCert *models.Certificate, rootHTTP *models.HTTPFingerprint) models.RelatedNameProbe {
	probe := models.RelatedNameProbe{
		Name: candidate.Name, FirstObservedAt: candidate.FirstObservedAt, LastObservedAt: candidate.LastObservedAt,
		AddedCount: candidate.AddedCount, RemovedCount: candidate.RemovedCount, BranchLikeLabel: candidate.BranchLikeLabel,
		ProbedAt: time.Now().UTC(), DNSStatus: "inconclusive",
	}
	nameCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	topology := s.resolveTopology(nameCtx, candidate.Name)
	cancel()
	if topology == nil {
		probe.Error = "DNS topology was not collected"
		return probe
	}
	probe.ResolverQuorum = topology.ResolverQuorum
	probe.ResolvedIPs = append([]string(nil), topology.PublicIPs...)
	probe.CNAMEChain = append([]string(nil), topology.CNAMEChain...)
	probe.SharesRootIP = overlappingStrings(probe.ResolvedIPs, topologyIPs(rootTopology))
	probe.SharesRootCNAME = overlappingStrings(probe.CNAMEChain, topologyCNAMEs(rootTopology))
	if len(probe.ResolvedIPs) == 0 {
		probe.DNSStatus = relatedNameDNSStatus(topology)
		return probe
	}
	probe.DNSStatus = "active"

	addresses := relatedNameAddresses(probe.ResolvedIPs, 4)
	handshakeCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	chain, _, info, err := s.endpointHandshake(handshakeCtx, candidate.Name, addresses[0], candidate.Name)
	cancel()
	if err != nil || len(chain) == 0 {
		if err != nil {
			probe.Error = "TLS: " + err.Error()
		} else {
			probe.Error = "TLS: no peer certificate found"
		}
		return probe
	}
	leaf := chain[0]
	probe.TLSAnswered = true
	probe.Fingerprint = models.Fingerprint(leaf)
	probe.IssuerCN = leaf.Issuer.CommonName
	probe.CommonName = leaf.Subject.CommonName
	probe.SANs = append([]string(nil), leaf.DNSNames...)
	probe.CoversOwnName = leaf.VerifyHostname(candidate.Name) == nil
	probe.CoversRootName = leaf.VerifyHostname(root) == nil
	if rootCert != nil && rootCert.Fingerprint != "" {
		probe.SharesRootLeaf = probe.Fingerprint == rootCert.Fingerprint
	}
	if s.config.CheckHTTPFingerprint {
		httpCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
		fingerprint, httpErr := s.fetchHTTPFingerprint(httpCtx, candidate.Name, info)
		cancel()
		if httpErr != nil {
			probe.Error = appendRelatedProbeError(probe.Error, "HTTP: "+httpErr.Error())
		} else {
			probe.HTTP = fingerprint
			_ = rootHTTP // Retain both fingerprints for an operator-side comparison; no header equality is a provider identity proof.
		}
	}
	probe.EndpointProbes = s.ProbeEndpointsRotated(ctx, candidate.Name, addresses, rotation)
	return probe
}

func appendRelatedProbeError(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "; " + next
}

func relatedNameAddresses(values []string, limit int) []string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	if limit > 0 && len(values) > limit {
		values = values[:limit]
	}
	return values
}

func relatedNameDNSStatus(topology *models.TopologySnapshot) string {
	if topology == nil || len(topology.Resolvers) == 0 {
		return "inconclusive"
	}
	for _, resolver := range topology.Resolvers {
		if strings.Contains(resolver.Error, "no usable public") || strings.Contains(resolver.Error, "CNAME but no usable") {
			continue
		}
		return "inconclusive"
	}
	return "no_public_address"
}

func topologyIPs(topology *models.TopologySnapshot) []string {
	if topology == nil {
		return nil
	}
	return topology.PublicIPs
}

func topologyCNAMEs(topology *models.TopologySnapshot) []string {
	if topology == nil {
		return nil
	}
	return topology.CNAMEChain
}

func overlappingStrings(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(left))
	for _, value := range left {
		seen[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}
	for _, value := range right {
		if _, ok := seen[strings.ToLower(strings.TrimSpace(value))]; ok {
			return true
		}
	}
	return false
}

// ProbeEndpointsRotated is ProbeEndpoints with a rotation offset: when more
// addresses resolve than the sampling cap allows, successive rounds start the
// sampled window at a different address so that, over rounds, every resolved
// address is observed instead of always the same sorted prefix.
func (s *Scanner) ProbeEndpointsRotated(ctx context.Context, domain string, ips []string, rotation int) []models.EndpointProbe {
	maxEndpoints := s.config.MaxEndpointSamples
	if maxEndpoints <= 0 {
		maxEndpoints = 16
	}
	handshakes := s.config.EndpointHandshakes
	if handshakes <= 0 {
		handshakes = 1
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
		offset := 0
		if rotation > 0 {
			offset = rotation % len(unique)
		}
		window := make([]string, 0, maxEndpoints)
		for index := 0; index < maxEndpoints; index++ {
			window = append(window, unique[(offset+index)%len(unique)])
		}
		sort.Strings(window)
		unique = window
	}
	probes := make([]models.EndpointProbe, len(unique))
	var wg sync.WaitGroup
	concurrency := s.config.EndpointProbeConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	slots := make(chan struct{}, concurrency)
	for index, ip := range unique {
		if !s.ipv6Route && strings.Contains(ip, ":") {
			// This vantage has no IPv6 route: dialling would only produce the
			// local kernel's "network is unreachable". Record the address as
			// unobservable so it is never read as a server-side failure.
			probes[index] = models.EndpointProbe{IPAddress: ip, Unobservable: true, Error: "vantage has no IPv6 route; address not observable from this monitor"}
			continue
		}
		wg.Add(1)
		go func(index int, ip string) {
			defer wg.Done()
			probe := models.EndpointProbe{IPAddress: ip, RequestedSNI: domain}
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
			// Several handshakes to the same address in one round: a second
			// distinct leaf proves the address fronts servers holding
			// different certificates, which one handshake per round can only
			// suggest across rounds.
			for attempt := 0; attempt < handshakes; attempt++ {
				probeCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
				chain, _, info, err := s.endpointHandshake(probeCtx, domain, ip, domain)
				cancel()
				if err != nil || len(chain) == 0 {
					if !probe.Success {
						if err != nil {
							probe.Error = err.Error()
						} else {
							probe.Error = "no peer certificate found"
						}
						break
					}
					continue
				}
				probe.Handshakes++
				fingerprint := models.Fingerprint(chain[0])
				if probe.Success {
					if fingerprint != probe.Fingerprint && !containsString(probe.OtherFingerprints, fingerprint) {
						probe.OtherFingerprints = append(probe.OtherFingerprints, fingerprint)
						other := models.EndpointProbe{IPAddress: ip, RequestedSNI: domain, Handshakes: 1}
						fillProbe(&other, domain, ip, chain, info)
						probe.OtherLeaves = append(probe.OtherLeaves, other)
						probe.Findings = append(probe.Findings, other.Findings...)
					}
					continue
				}
				fillProbe(&probe, domain, ip, chain, info)
			}

			// A no-SNI handshake is a controlled comparison, not another
			// endpoint fingerprint. It reveals whether the normal domain SNI
			// selects a different certificate from the endpoint default.
			selection := models.EndpointSelectionProbe{Variant: "no_sni"}
			probeCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
			chain, _, info, err := s.endpointHandshake(probeCtx, domain, ip, "")
			cancel()
			if err != nil || len(chain) == 0 {
				if err != nil {
					selection.Error = err.Error()
				} else {
					selection.Error = "no peer certificate found"
				}
			} else {
				fillSelectionProbe(&selection, domain, ip, chain, info)
			}
			probe.SelectionProbes = append(probe.SelectionProbes, selection)
			probe.SelectionAnalysis = compareEndpointSelection(&probe, domain, selection)
		}(index, ip)
	}
	wg.Wait()
	return probes
}

// endpointHandshake keeps the old test hook working while allowing the
// selection matrix to vary the TLS ServerName. An empty serverName means that
// the ClientHello omits SNI.
func (s *Scanner) endpointHandshake(ctx context.Context, domain, address, serverName string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
	if s.probeHandshakeWithSNI != nil {
		return s.probeHandshakeWithSNI(ctx, domain, address, serverName)
	}
	if s.probeHandshake != nil {
		return s.probeHandshake(ctx, domain, address)
	}
	return s.handshakeTLSAtWithSNI(ctx, domain, address, serverName)
}

// fillProbe records the first answered handshake's leaf on the probe.
func fillProbe(probe *models.EndpointProbe, domain, ip string, chain []*x509.Certificate, info *models.ConnectionInfo) {
	leaf := chain[0]
	probe.Success = true
	probe.RawCert = base64.StdEncoding.EncodeToString(leaf.Raw)
	probe.Error = ""
	probe.Fingerprint = models.Fingerprint(leaf)
	probe.SPKIFingerprint = models.SPKIFingerprint(leaf)
	probe.IssuerCN = leaf.Issuer.CommonName
	probe.CommonName = leaf.Subject.CommonName
	probe.SerialNumber = leaf.SerialNumber.Text(16)
	probe.SANs = append([]string(nil), leaf.DNSNames...)
	probe.CoversRequestedName = leaf.VerifyHostname(domain) == nil
	for _, cert := range chain {
		probe.ChainFingerprints = append(probe.ChainFingerprints, models.Fingerprint(cert))
	}
	// The key algorithm and the covered name set are what separate a
	// deliberate RSA plus ECDSA pair from endpoints that disagree: the pair
	// serves the same names from the same issuer on purpose.
	probe.KeyAlgorithm = leaf.PublicKeyAlgorithm.String()
	probe.KeySize = models.PublicKeySize(leaf)
	probe.SANsHash = models.SANSetHash(leaf.DNSNames)
	nb := leaf.NotBefore.UTC()
	probe.NotBefore = &nb
	na := leaf.NotAfter.UTC()
	probe.NotAfter = &na
	for _, sct := range parseEmbeddedSCTs(leaf) {
		if sct.Timestamp != nil && (probe.EarliestSCT == nil || sct.Timestamp.Before(*probe.EarliestSCT)) {
			at := sct.Timestamp.UTC()
			probe.EarliestSCT = &at
		}
	}
	if info != nil {
		probe.TLSVersion = info.TLSVersion
		probe.CipherSuite = info.CipherSuite
	}
	probe.Findings = validateChain(domain, ip, chain, time.Now())
}

func fillSelectionProbe(probe *models.EndpointSelectionProbe, domain, ip string, chain []*x509.Certificate, info *models.ConnectionInfo) {
	leaf := chain[0]
	probe.Success = true
	probe.Error = ""
	probe.Fingerprint = models.Fingerprint(leaf)
	probe.SPKIFingerprint = models.SPKIFingerprint(leaf)
	probe.IssuerCN = leaf.Issuer.CommonName
	probe.CommonName = leaf.Subject.CommonName
	probe.KeyAlgorithm = leaf.PublicKeyAlgorithm.String()
	probe.KeySize = models.PublicKeySize(leaf)
	probe.SerialNumber = leaf.SerialNumber.Text(16)
	probe.SANs = append([]string(nil), leaf.DNSNames...)
	probe.SANsHash = models.SANSetHash(leaf.DNSNames)
	probe.CoversRequestedName = leaf.VerifyHostname(domain) == nil
	for _, cert := range chain {
		probe.ChainFingerprints = append(probe.ChainFingerprints, models.Fingerprint(cert))
	}
	nb := leaf.NotBefore.UTC()
	probe.NotBefore = &nb
	na := leaf.NotAfter.UTC()
	probe.NotAfter = &na
	for _, sct := range parseEmbeddedSCTs(leaf) {
		if sct.Timestamp != nil && (probe.EarliestSCT == nil || sct.Timestamp.Before(*probe.EarliestSCT)) {
			at := sct.Timestamp.UTC()
			probe.EarliestSCT = &at
		}
	}
	if info != nil {
		probe.TLSVersion = info.TLSVersion
		probe.CipherSuite = info.CipherSuite
		probe.NegotiatedProtocol = info.NegotiatedProtocol
	}
	probe.Findings = validateChain(domain, ip, chain, time.Now())
}

// compareEndpointSelection turns the two handshakes made against one IP into
// an auditable, bounded statement. It deliberately distinguishes the
// certificate-selection fact from the unobservable reason in a hosting or CA
// control plane.
func compareEndpointSelection(primary *models.EndpointProbe, domain string, control models.EndpointSelectionProbe) *models.EndpointSelectionAnalysis {
	analysis := &models.EndpointSelectionAnalysis{RequestedSNI: domain}
	if primary == nil || !primary.Success {
		analysis.Interpretation = "primary_sni_probe_failed"
		analysis.Error = "the domain-SNI handshake did not return a certificate"
		return analysis
	}
	if !control.Success {
		analysis.SelectedFingerprint = primary.Fingerprint
		analysis.SelectedCoversRequestedName = primary.CoversRequestedName
		analysis.Interpretation = "no_sni_control_failed"
		analysis.Error = control.Error
		analysis.Evidence = []string{
			"requested_sni=" + domain,
			"selected_fingerprint=" + primary.Fingerprint,
			"selected_covers_requested_name=" + strconv.FormatBool(primary.CoversRequestedName),
		}
		return analysis
	}

	analysis.SelectedFingerprint = primary.Fingerprint
	analysis.DefaultFingerprint = control.Fingerprint
	analysis.CertificateChanged = primary.Fingerprint != control.Fingerprint
	analysis.SelectedCoversRequestedName = primary.CoversRequestedName
	analysis.DefaultCoversRequestedName = control.CoversRequestedName
	analysis.SANSetChanged = primary.SANsHash != control.SANsHash
	analysis.ChainChanged = !sameStrings(primary.ChainFingerprints, control.ChainFingerprints)
	analysis.Evidence = []string{
		"requested_sni=" + domain,
		"selected_fingerprint=" + primary.Fingerprint,
		"default_fingerprint=" + control.Fingerprint,
		"certificate_changed=" + strconv.FormatBool(analysis.CertificateChanged),
		"selected_covers_requested_name=" + strconv.FormatBool(analysis.SelectedCoversRequestedName),
		"default_covers_requested_name=" + strconv.FormatBool(analysis.DefaultCoversRequestedName),
	}
	if analysis.SANSetChanged {
		analysis.Evidence = append(analysis.Evidence, "san_set_changed=true")
	}
	if analysis.ChainChanged {
		analysis.Evidence = append(analysis.Evidence, "chain_changed=true")
	}

	switch {
	case !analysis.CertificateChanged && analysis.SelectedCoversRequestedName:
		analysis.Interpretation = "same_name_matching_certificate_with_or_without_sni"
	case !analysis.CertificateChanged:
		analysis.Interpretation = "same_default_certificate_name_mismatch"
	case analysis.SelectedCoversRequestedName && !analysis.DefaultCoversRequestedName:
		analysis.Interpretation = "sni_selects_name_matching_certificate"
	case analysis.SelectedCoversRequestedName && analysis.DefaultCoversRequestedName:
		analysis.Interpretation = "sni_selects_alternate_name_matching_certificate"
	default:
		analysis.Interpretation = "sni_selects_certificate_not_matching_name"
	}
	return analysis
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// hasIPv6Route reports whether the host has any route to global IPv6 space.
// A UDP "connect" sends nothing; it only asks the kernel for a route.
// certificateLookupTTL keeps CT answers for one certificate (by fingerprint or
// serial) for a week: the logged entries of an issued certificate do not change.
const certificateLookupTTL = 7 * 24 * time.Hour

func hasIPv6Route() bool {
	conn, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
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
	// Cross-region DNS/TLS evidence has its own bounded timeout and is needed by
	// stale/deployment diagnosis. Run it before slower CT and directory lookups
	// so an otherwise successful manual scan does not consume its entire budget
	// before reaching the independent network measurement.
	if s.config.CheckGlobalProbes {
		attempted = true
		probeCtx, cancel := context.WithTimeout(ctx, s.config.GlobalProbeTimeout)
		global, err := s.fetchGlobalProbes(probeCtx, result.Domain)
		cancel()
		if global != nil {
			deep.GlobalProbes = global
		}
		if err != nil {
			deep.Errors = append(deep.Errors, "global probes: "+err.Error())
			pending = append(pending, "multi-continent DNS/TLS measurement failed")
		}
	}
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
	gate := s.crtsh
	if gate != nil {
		if value, ok := gate.cached(query, time.Now()); ok {
			return value.([]models.CTObservation), nil
		}
		wait, gateErr := gate.reserve(time.Now())
		if gateErr != nil {
			return nil, gateErr
		}
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
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
	if gate != nil {
		gate.observe(resp, time.Now())
	}
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
	if gate != nil {
		ttl := time.Duration(0)
		if !strings.Contains(query, ".") {
			ttl = certificateLookupTTL // fingerprint or serial, not a domain
		}
		gate.storeFor(query, entries, time.Now(), ttl)
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

// ProbeHTTP runs one application-layer route check for a deep-diagnosis
// experiment. When address is empty the scanner resolves the domain itself.
// The regular survey keeps using fetchHTTPFingerprint.
func (s *Scanner) ProbeHTTP(ctx context.Context, domain, address string) (*models.HTTPFingerprint, error) {
	info := &models.ConnectionInfo{IPAddress: address}
	return s.fetchHTTPFingerprint(ctx, domain, info)
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
	// Make the application-layer authority explicit. TLS SNI and HTTP Host are
	// separate routing inputs even when they normally contain the same name.
	req.Host = domain
	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("HTTPS response did not expose TLS certificate state")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	fp := &models.HTTPFingerprint{
		IPAddress:          address,
		RequestedSNI:       domain,
		HostHeader:         req.Host,
		StatusCode:         resp.StatusCode,
		Server:             resp.Header.Get("Server"),
		Via:                resp.Header.Get("Via"),
		Cache:              resp.Header.Get("Age"),
		TLSFingerprint:     models.Fingerprint(resp.TLS.PeerCertificates[0]),
		TLSVersion:         models.GetTLSVersionName(resp.TLS.Version),
		NegotiatedProtocol: resp.TLS.NegotiatedProtocol,
	}
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
	req.Host = domain
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
		Protocol:           "HTTPS",
		RequestedSNI:       domain,
		HTTPHost:           domain,
		TLSVersion:         models.GetTLSVersionName(resp.TLS.Version),
		CipherSuite:        models.GetCipherSuiteName(resp.TLS.CipherSuite),
		NegotiatedProtocol: resp.TLS.NegotiatedProtocol,
		ALPN:               resp.TLS.NegotiatedProtocol,
		IPAddress:          address,
		SCTs:               handshakeSCTs(resp.TLS),
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
	return s.handshakeTLSAtWithSNI(ctx, domain, address, domain)
}

// handshakeTLSAtWithSNI performs a direct TLS handshake while allowing the
// caller to choose the ClientHello SNI. An empty serverName deliberately omits
// the SNI extension so the endpoint's default certificate can be compared with
// the certificate selected for the monitored hostname.
func (s *Scanner) handshakeTLSAtWithSNI(ctx context.Context, domain, address, serverName string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	tlsConfig := &tls.Config{
		ServerName:         serverName,
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
		RequestedSNI:       serverName,
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

// ScanFreshWithRetry retries an explicit deep scan without reusing a prior
// Globalping result for the domain.
func (s *Scanner) ScanFreshWithRetry(ctx context.Context, domain string) (*models.ScanResult, error) {
	return scanWithRetryConfig(ctx, domain, s.config.Retries, s.ScanFresh, time.After, s.config.RetryBackoffUnit)
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
