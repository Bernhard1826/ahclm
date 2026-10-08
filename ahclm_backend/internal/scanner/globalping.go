package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ahclm/internal/models"
)

// Globalping is used only for a bounded deep/manual measurement. The provider
// runs DNS traces and HTTPS requests from separately located probes, giving us
// external evidence that cannot be fabricated by this monitor's local DNS or
// egress network. It is deliberately not called for baseline scans.
const defaultGlobalPingEndpoint = "https://api.globalping.io"

var (
	globalPingAuthorityLine = regexp.MustCompile(`(?m)^;; Received \d+ bytes from ([^#\s]+)#53\(([^)]+)\)`) // final trace hop
	globalPingRRLine        = regexp.MustCompile(`(?m)^\S+\s+\d+\s+IN\s+(A|AAAA|CNAME)\s+(\S+)`)
)

const globalPingMeasurementPollInterval = 750 * time.Millisecond

type globalPingRetryError struct {
	wait time.Duration
	msg  string
}

func (e *globalPingRetryError) Error() string { return e.msg }

type globalPingMeasurement struct {
	ID      string                     `json:"id"`
	Status  string                     `json:"status"`
	Results []globalPingMeasurementRow `json:"results"`
}

type globalPingMeasurementRow struct {
	Probe  globalPingProbe       `json:"probe"`
	Result globalPingProbeResult `json:"result"`
}

type globalPingProbe struct {
	Continent string   `json:"continent"`
	Region    string   `json:"region"`
	Country   string   `json:"country"`
	City      string   `json:"city"`
	ASN       int      `json:"asn"`
	Network   string   `json:"network"`
	Resolvers []string `json:"resolvers"`
}

type globalPingProbeResult struct {
	Status          string                     `json:"status"`
	StatusCode      int                        `json:"statusCode"`
	Resolver        string                     `json:"resolver"`
	ResolvedAddress string                     `json:"resolvedAddress"`
	RawOutput       string                     `json:"rawOutput"`
	Headers         map[string]json.RawMessage `json:"headers"`
	RawHeaders      string                     `json:"rawHeaders"`
	Answers         []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"answers"`
	TLS *struct {
		Authorized     bool   `json:"authorized"`
		Error          string `json:"error"`
		Fingerprint256 string `json:"fingerprint256"`
		Subject        struct {
			CN  string `json:"CN"`
			Alt string `json:"alt"`
		} `json:"subject"`
	} `json:"tls"`
	Error json.RawMessage `json:"error"`
}

func (s *Scanner) fetchGlobalProbes(ctx context.Context, domain string) (*models.GlobalProbeEvidence, error) {
	if s == nil || s.globalPing == nil {
		return nil, fmt.Errorf("global probe client is unavailable")
	}
	domain = models.GetDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("invalid global probe domain")
	}
	cacheKey := "global-probes:" + domain
	if !requestsFreshGlobalProbes(ctx) {
		if cached, ok := s.globalPing.cached(cacheKey, time.Now()); ok {
			if evidence, ok := cached.(models.GlobalProbeEvidence); ok {
				copy := evidence
				return &copy, nil
			}
		}
	}
	requiredTests := len(models.NormalizePropagationLocations(s.config.GlobalProbeLocations))
	if !requestsFreshGlobalProbes(ctx) {
		// A normal deep scan creates one DNS and one HTTPS measurement, each
		// consuming one test per configured region.
		requiredTests *= 2
	}
	if s.globalProbeScanBudget != nil {
		allowed, remaining := s.globalProbeScanBudget.reserve(time.Now(), requiredTests)
		if !allowed {
			return nil, fmt.Errorf("routine Globalping scan budget exhausted for the rolling hour (%d tests remain; this scan needs %d); deferred before sending a measurement", remaining, requiredTests)
		}
	}
	wait, err := s.reserveGlobalPing(ctx, requiredTests)
	if err != nil {
		return nil, err
	}
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	evidence := models.GlobalProbeEvidence{Provider: "Globalping", CollectedAt: time.Now().UTC()}
	if !requestsFreshGlobalProbes(ctx) {
		dns, err := s.runGlobalPingMeasurement(ctx, domain, "dns", s.config.GlobalProbeLocations, "", "", "")
		if err != nil {
			return nil, err
		}
		evidence.DNSMeasurementID = dns.ID
		evidence.DNS = globalDNSProbes(dns, domain)
	}

	https, err := s.runGlobalPingMeasurement(ctx, domain, "http", s.config.GlobalProbeLocations, domain, "HEAD", "/")
	if err != nil {
		evidence.Error = "HTTPS: " + err.Error()
		return &evidence, err
	}
	evidence.HTTPSMeasurementID = https.ID
	evidence.HTTPS = globalHTTPSProbes(https)
	if len(evidence.DNS) == 0 && len(evidence.HTTPS) == 0 {
		return nil, fmt.Errorf("global probes completed without results")
	}
	s.globalPing.store(cacheKey, evidence, time.Now())
	return &evidence, nil
}

// MeasureGlobalHTTPS performs one uncached cross-continent HTTPS measurement.
// It is the primitive used by the propagation worker; unlike a normal deep
// scan it does not repeat CT, CAA, revocation or local endpoint enrichment.
func (s *Scanner) MeasureGlobalHTTPS(ctx context.Context, domain string, configuredLocations []string) (*models.GlobalProbeEvidence, error) {
	domain = models.GetDomain(domain)
	return s.MeasureGlobalHTTPSWithTarget(ctx, domain, domain, configuredLocations)
}

// MeasureGlobalHTTPSWithTarget performs an uncached cross-continent HTTPS
// measurement against target while optionally overriding the HTTP Host header
// and TLS SNI with host. This allows an origin IP to be measured directly
// without resolving the public CDN hostname at each Globalping probe.
func (s *Scanner) MeasureGlobalHTTPSWithTarget(ctx context.Context, target, host string, configuredLocations []string) (*models.GlobalProbeEvidence, error) {
	return s.measureGlobalHTTPSRequest(ctx, target, host, "HEAD", "/", configuredLocations)
}

// MeasureGlobalHTTPSPath sends a cache-busting GET through the public CDN
// hostname. The configured endpoint must be excluded from CDN caching and
// should return its expected status only after reaching the origin.
func (s *Scanner) MeasureGlobalHTTPSPath(ctx context.Context, target, host, path string, configuredLocations []string) (*models.GlobalProbeEvidence, error) {
	path = strings.TrimSpace(path)
	if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n# ") || strings.HasPrefix(path, "//") {
		return nil, fmt.Errorf("invalid global probe path")
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid global probe path")
	}
	locations := models.NormalizePropagationLocations(configuredLocations)
	if len(locations) == 0 {
		return nil, fmt.Errorf("at least one origin probe location is required")
	}
	// A distinct nonce per region prevents one region's response from proving
	// another region's origin request if a CDN accidentally caches this path.
	results := make([]*models.GlobalProbeEvidence, len(locations))
	var wg sync.WaitGroup
	for i, location := range locations {
		wg.Add(1)
		go func(i int, location string) {
			defer wg.Done()
			nonceBytes := make([]byte, 16)
			_, randomErr := rand.Read(nonceBytes)
			nonce := hex.EncodeToString(nonceBytes)
			requestURI := *u
			query := requestURI.Query()
			query.Set("_ahclm_probe", nonce)
			requestURI.RawQuery = query.Encode()
			var part *models.GlobalProbeEvidence
			err := randomErr
			if err == nil {
				part, err = s.measureGlobalHTTPSRequest(ctx, target, host, "GET", requestURI.RequestURI(), []string{location})
			}
			if part == nil {
				part = &models.GlobalProbeEvidence{}
			}
			observedAt := time.Now().UTC()
			if err != nil {
				part.Error = err.Error()
				part.HTTPS = []models.GlobalHTTPSProbe{{Location: models.GlobalProbeLocation{Continent: location}, Status: "error", Error: err.Error()}}
			}
			for j := range part.HTTPS {
				part.HTTPS[j].MeasurementID = part.HTTPSMeasurementID
				part.HTTPS[j].RequestNonce = nonce
				part.HTTPS[j].ObservedAt = &observedAt
			}
			results[i] = part
		}(i, location)
	}
	wg.Wait()
	evidence := &models.GlobalProbeEvidence{Provider: "Globalping", CollectedAt: time.Now().UTC()}
	var problems []string
	for _, part := range results {
		evidence.HTTPS = append(evidence.HTTPS, part.HTTPS...)
		if part.HTTPSMeasurementID != "" {
			evidence.HTTPSMeasurementIDs = append(evidence.HTTPSMeasurementIDs, part.HTTPSMeasurementID)
		}
		if part.Error != "" {
			problems = append(problems, part.Error)
		}
	}
	if len(evidence.HTTPSMeasurementIDs) > 0 {
		evidence.HTTPSMeasurementID = evidence.HTTPSMeasurementIDs[0]
	}
	evidence.Error = strings.Join(problems, "; ")
	return evidence, nil
}

func (s *Scanner) measureGlobalHTTPSRequest(ctx context.Context, target, host, method, path string, configuredLocations []string) (*models.GlobalProbeEvidence, error) {
	if s == nil || s.globalPing == nil {
		return nil, fmt.Errorf("global probe client is unavailable")
	}
	target = strings.TrimSpace(target)
	if ip := net.ParseIP(target); ip != nil {
		target = ip.String()
		if !models.IsPublicIP(target) {
			return nil, fmt.Errorf("global probe IP target must be public")
		}
	} else {
		target = strings.TrimSuffix(strings.ToLower(target), ".")
		if err := ValidateDomain(target); err != nil {
			return nil, fmt.Errorf("invalid global probe target: %w", err)
		}
	}
	if target == "" || strings.ContainsAny(target, " \t\r\n/\\") {
		return nil, fmt.Errorf("invalid global probe target")
	}
	host = strings.TrimSpace(host)
	if host != "" {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if strings.ContainsAny(host, " \t\r\n/:\\") || net.ParseIP(host) != nil {
			return nil, fmt.Errorf("invalid global probe host")
		}
		if err := ValidateDomain(host); err != nil {
			return nil, fmt.Errorf("invalid global probe host: %w", err)
		}
	}
	locations := models.NormalizePropagationLocations(configuredLocations)
	if len(locations) == 0 {
		locations = models.NormalizePropagationLocations(s.config.GlobalProbeLocations)
	}
	if len(locations) == 0 {
		return nil, fmt.Errorf("no global probe locations configured")
	}
	wait, err := s.reserveGlobalPing(ctx, len(locations))
	if err != nil {
		return nil, err
	}
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	measurement, err := s.runGlobalPingMeasurement(ctx, target, "http", locations, host, method, path)
	if err != nil {
		return nil, err
	}
	return &models.GlobalProbeEvidence{
		Provider:           "Globalping",
		CollectedAt:        time.Now().UTC(),
		HTTPSMeasurementID: measurement.ID,
		HTTPS:              globalHTTPSProbes(measurement),
	}, nil
}

func (s *Scanner) reserveGlobalPing(ctx context.Context, requiredTests int) (time.Duration, error) {
	now := time.Now()
	if requiredTests <= 0 {
		requiredTests = 1
	}
	if s.globalPing.needsCooldownRefresh(now) {
		// The in-memory fallback may outlive the provider's hourly window. Ask
		// Globalping for the authoritative reset before skipping more work.
		_ = s.refreshGlobalPingCreateLimit(ctx, requiredTests)
	}
	return s.globalPing.reserve(time.Now())
}

func (s *Scanner) refreshGlobalPingCreateLimit(ctx context.Context, requiredTests int) error {
	endpoint := strings.TrimRight(strings.TrimSpace(s.config.GlobalProbeEndpoint), "/")
	if endpoint == "" {
		endpoint = defaultGlobalPingEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/limits", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", globalPingUserAgent(s.config.UserAgent))
	setGlobalPingAuthorization(req, s.config.GlobalProbeToken)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Globalping limits returned HTTP %d", resp.StatusCode)
	}
	var limits struct {
		RateLimit struct {
			Measurements struct {
				Create struct {
					Remaining int64 `json:"remaining"`
					Reset     int64 `json:"reset"`
				} `json:"create"`
			} `json:"measurements"`
		} `json:"rateLimit"`
		Credits struct {
			Remaining int64 `json:"remaining"`
		} `json:"credits"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&limits); err != nil {
		return err
	}
	create := limits.RateLimit.Measurements.Create
	if requiredTests <= 0 {
		requiredTests = 1
	}
	// The hourly free-test allowance and the account's credit balance are
	// independent sources of tests. A measurement can draw from both (for
	// example, two free tests plus one credit for three locations).
	if create.Remaining+limits.Credits.Remaining >= int64(requiredTests) {
		s.globalPing.clearCooldown()
		return nil
	}
	if create.Reset > 0 {
		s.globalPing.setCooldown(time.Now().Add(time.Duration(create.Reset) * time.Second))
	}
	return nil
}

func (s *Scanner) runGlobalPingMeasurement(ctx context.Context, target, measurementType string, configuredLocations []string, requestHost, requestMethod, requestPath string) (*globalPingMeasurement, error) {
	locations := make([]map[string]any, 0, len(configuredLocations))
	for _, location := range configuredLocations {
		continent := strings.ToUpper(strings.TrimSpace(location))
		if continent != "" {
			locations = append(locations, map[string]any{"continent": continent, "limit": 1})
		}
	}
	if len(locations) == 0 {
		return nil, fmt.Errorf("no global probe locations configured")
	}
	request := map[string]any{
		"type":      measurementType,
		"target":    target,
		"locations": locations,
		"timeout":   15,
	}
	if measurementType == "dns" {
		request["measurementOptions"] = map[string]any{
			"query":    map[string]any{"type": "A"},
			"protocol": "TCP",
			"trace":    true,
		}
	} else {
		if requestMethod == "" {
			requestMethod = "HEAD"
		}
		if requestPath == "" {
			requestPath = "/"
		}
		httpRequest := map[string]any{"method": requestMethod, "path": requestPath}
		if requestHost = strings.TrimSpace(requestHost); requestHost != "" {
			httpRequest["host"] = requestHost
		}
		request["measurementOptions"] = map[string]any{
			"protocol": "HTTPS",
			"request":  httpRequest,
		}
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(strings.TrimSpace(s.config.GlobalProbeEndpoint), "/")
	if endpoint == "" {
		endpoint = defaultGlobalPingEndpoint
	}
	createURL := endpoint + "/v1/measurements"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, createURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", globalPingUserAgent(s.config.UserAgent))
	setGlobalPingAuthorization(req, s.config.GlobalProbeToken)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	s.globalPing.observe(resp, time.Now())
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode != http.StatusAccepted {
		if resp.StatusCode == http.StatusTooManyRequests {
			// A create 429 may be an account credit exhaustion without a useful
			// Retry-After header. Refresh the provider's authoritative reset so
			// every active experiment does not retry pointlessly on each tick.
			_ = s.refreshGlobalPingCreateLimit(ctx, len(models.NormalizePropagationLocations(configuredLocations)))
		}
		return nil, fmt.Errorf("Globalping create %s measurement returned HTTP %d: %s", measurementType, resp.StatusCode, compactGlobalPingError(responseBody))
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(responseBody, &created); err != nil || created.ID == "" {
		return nil, fmt.Errorf("Globalping did not return a measurement id")
	}
	measurementURL := strings.TrimSpace(resp.Header.Get("Location"))
	if measurementURL == "" {
		measurementURL = createURL + "/" + created.ID
	}
	for {
		measurement, err := s.getGlobalPingMeasurement(ctx, measurementURL)
		if err != nil {
			var retryErr *globalPingRetryError
			if errors.As(err, &retryErr) {
				select {
				case <-time.After(retryErr.wait):
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return nil, err
		}
		if measurement.Status != "in-progress" {
			if measurement.Status != "finished" {
				return nil, fmt.Errorf("Globalping %s measurement ended with %q", measurementType, measurement.Status)
			}
			return measurement, nil
		}
		select {
		case <-time.After(globalPingMeasurementPollInterval):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *Scanner) getGlobalPingMeasurement(ctx context.Context, measurementURL string) (*globalPingMeasurement, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, measurementURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", globalPingUserAgent(s.config.UserAgent))
	setGlobalPingAuthorization(req, s.config.GlobalProbeToken)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := rateLimitWait(resp.Header, time.Now())
			if wait <= 0 {
				wait = time.Second
			}
			return nil, &globalPingRetryError{wait: wait, msg: "Globalping measurement status request was rate-limited"}
		}
		return nil, fmt.Errorf("Globalping measurement status returned HTTP %d: %s", resp.StatusCode, compactGlobalPingError(body))
	}
	var measurement globalPingMeasurement
	if err := json.Unmarshal(body, &measurement); err != nil {
		return nil, err
	}
	return &measurement, nil
}

func globalDNSProbes(measurement *globalPingMeasurement, domain string) []models.GlobalDNSProbe {
	if measurement == nil {
		return nil
	}
	probes := make([]models.GlobalDNSProbe, 0, len(measurement.Results))
	for _, row := range measurement.Results {
		probe := models.GlobalDNSProbe{
			Location: globalProbeLocation(row.Probe),
			Status:   row.Result.Status,
			Resolver: row.Result.Resolver,
			Error:    globalPingResultError(row.Result.Error),
		}
		if probe.Resolver == "" && len(row.Probe.Resolvers) > 0 {
			probe.Resolver = strings.Join(row.Probe.Resolvers, ",")
		}
		if match := lastGlobalPingAuthority(row.Result.RawOutput); match != nil {
			probe.AuthoritativeAddress = match[1]
			probe.AuthoritativeNameserver = match[2]
		}
		for _, answer := range row.Result.Answers {
			if value := strings.TrimSpace(answer.Value); value != "" {
				probe.Answers = append(probe.Answers, models.GlobalDNSAnswer{Type: strings.ToUpper(answer.Type), Value: value})
			}
		}
		if len(probe.Answers) == 0 {
			probe.Answers = globalTraceAnswers(row.Result.RawOutput, domain)
		}
		probes = append(probes, probe)
	}
	sort.Slice(probes, func(i, j int) bool {
		return globalLocationKey(probes[i].Location) < globalLocationKey(probes[j].Location)
	})
	return probes
}

func globalTraceAnswers(raw, domain string) []models.GlobalDNSAnswer {
	received := globalPingAuthorityLine.FindAllStringIndex(raw, -1)
	if len(received) < 2 {
		return nil
	}
	// In a +trace output, the final answer appears after the penultimate
	// "Received" line and before the final one (which names the authoritative
	// server that supplied it). This excludes glue from the earlier delegation
	// hops while retaining a CNAME target's A/AAAA records.
	finalBlock := raw[received[len(received)-2][1]:received[len(received)-1][0]]
	answers := make([]models.GlobalDNSAnswer, 0)
	for _, match := range globalPingRRLine.FindAllStringSubmatch(finalBlock, -1) {
		if len(match) != 3 {
			continue
		}
		value := strings.TrimSuffix(strings.TrimSpace(match[2]), ".")
		if value == "" {
			continue
		}
		answers = append(answers, models.GlobalDNSAnswer{Type: match[1], Value: value})
	}
	if len(answers) == 0 {
		return nil
	}
	// A malformed trace can echo unrelated records. Keep only an answer that
	// contains an A/AAAA or CNAME and do not add the terminal NS delegation.
	// domain is intentionally accepted here so callers retain the target in the
	// parsing contract even for a CNAME chain whose final owner differs.
	_ = domain
	return answers
}

func globalHTTPSProbes(measurement *globalPingMeasurement) []models.GlobalHTTPSProbe {
	if measurement == nil {
		return nil
	}
	probes := make([]models.GlobalHTTPSProbe, 0, len(measurement.Results))
	for _, row := range measurement.Results {
		probe := models.GlobalHTTPSProbe{
			Location:        globalProbeLocation(row.Probe),
			Status:          row.Result.Status,
			ResolvedAddress: row.Result.ResolvedAddress,
			HTTPStatus:      row.Result.StatusCode,
			Error:           globalPingResultError(row.Result.Error),
		}
		probe.OriginFingerprint = globalResponseHeader(row.Result, "X-AHCLM-Origin-Fingerprint")
		probe.OriginProbeNonce = globalResponseHeader(row.Result, "X-AHCLM-Probe")
		probe.OriginTLSResumed = globalResponseHeader(row.Result, "X-AHCLM-Origin-TLS-Resumed")
		if row.Result.TLS != nil {
			probe.TLSObserved = true
			probe.TLSAuthorized = row.Result.TLS.Authorized
			probe.TLSError = row.Result.TLS.Error
			probe.CommonName = row.Result.TLS.Subject.CN
			probe.SANs = parseGlobalPingSANs(row.Result.TLS.Subject.Alt)
			probe.Fingerprint = strings.ReplaceAll(strings.ToLower(row.Result.TLS.Fingerprint256), ":", "")
		}
		probes = append(probes, probe)
	}
	sort.Slice(probes, func(i, j int) bool {
		return globalLocationKey(probes[i].Location) < globalLocationKey(probes[j].Location)
	})
	return probes
}

func globalProbeLocation(probe globalPingProbe) models.GlobalProbeLocation {
	return models.GlobalProbeLocation{Continent: probe.Continent, Region: probe.Region, Country: probe.Country, City: probe.City, ASN: probe.ASN, Network: probe.Network}
}

func globalLocationKey(location models.GlobalProbeLocation) string {
	return strings.Join([]string{location.Continent, location.Country, location.City, location.Network}, "\x00")
}

func lastGlobalPingAuthority(raw string) []string {
	matches := globalPingAuthorityLine.FindAllStringSubmatch(raw, -1)
	if len(matches) == 0 {
		return nil
	}
	return matches[len(matches)-1]
}

func globalPingResultError(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var asString string
	if json.Unmarshal(raw, &asString) == nil {
		return strings.TrimSpace(asString)
	}
	return compactGlobalPingError(raw)
}

func compactGlobalPingError(body []byte) string {
	value := strings.TrimSpace(string(body))
	if len(value) > 320 {
		return value[:320] + "…"
	}
	return value
}

func parseGlobalPingSANs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	values := make([]string, 0)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		item = strings.TrimPrefix(item, "DNS:")
		if item != "" && !containsString(values, item) {
			values = append(values, item)
		}
	}
	sort.Strings(values)
	return values
}

func globalPingUserAgent(configured string) string {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return "AHCLM-CertMonitor/2.0"
	}
	return configured
}

func setGlobalPingAuthorization(req *http.Request, token string) {
	if token = strings.TrimSpace(token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// globalResponseHeader handles both Globalping structured headers and raw headers.
// Ambiguous duplicate values are rejected rather than treated as origin proof.
func globalResponseHeader(result globalPingProbeResult, name string) string {
	var values []string
	for key, raw := range result.Headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil {
			values = append(values, value)
			continue
		}
		var list []string
		if json.Unmarshal(raw, &list) == nil {
			values = append(values, list...)
		}
	}
	if len(values) == 0 && result.RawHeaders != "" {
		raw := strings.ReplaceAll(result.RawHeaders, "\r\n", "\n")
		if strings.HasPrefix(raw, "HTTP/") {
			_, raw, _ = strings.Cut(raw, "\n")
		}
		headers, err := textproto.NewReader(bufio.NewReader(strings.NewReader(raw + "\n\n"))).ReadMIMEHeader()
		if err == nil {
			values = headers.Values(name)
		}
	}
	if len(values) != 1 || len(values[0]) > 128 {
		return ""
	}
	return strings.TrimSpace(values[0])
}
