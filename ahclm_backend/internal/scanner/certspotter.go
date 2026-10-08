package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ahclm/internal/models"
)

func (s *Scanner) fetchCertSpotter(ctx context.Context, result *models.ScanResult) ([]models.CTObservation, error) {
	if result == nil || result.Cert == nil {
		return nil, fmt.Errorf("CertSpotter lookup has no served leaf")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(s.config.CertSpotterEndpoint), "/")
	if endpoint == "" {
		endpoint = defaultCertSpotterURL
	}
	fingerprint := strings.ToLower(strings.TrimSpace(result.Cert.Fingerprint))
	if fingerprint == "" {
		return nil, fmt.Errorf("CertSpotter lookup has no leaf fingerprint")
	}
	query := endpoint + "?cert_sha256=" + url.QueryEscape(fingerprint) + "&expand=dns_names&expand=issuer"
	entries, err := s.fetchCertSpotterURL(ctx, query)
	if err == nil && ctContainsLeaf(entries, fingerprint, result.Cert.SerialNumber) {
		return entries, nil
	}
	if result.Domain == "" {
		if err != nil {
			return nil, err
		}
		return entries, nil
	}
	domainQuery := endpoint + "?domain=" + url.QueryEscape(result.Domain) + "&include_subdomains=false&match_wildcards=false&expand=dns_names&expand=issuer"
	domainEntries, domainErr := s.fetchCertSpotterURL(ctx, domainQuery)
	if domainErr != nil && err != nil {
		return nil, err
	}
	merged := mergeCTObservations(append(entries, domainEntries...))
	if len(merged) == 0 && domainErr != nil {
		return nil, domainErr
	}
	return merged, nil
}

func (s *Scanner) fetchCertSpotterURL(ctx context.Context, endpoint string) ([]models.CTObservation, error) {
	gate := s.certSpotter
	if gate != nil {
		if value, ok := gate.cached(endpoint, time.Now()); ok {
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
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	ua := "AHCLM-CertMonitor/2.0"
	if s.config != nil && strings.TrimSpace(s.config.UserAgent) != "" {
		ua = s.config.UserAgent
	}
	req.Header.Set("User-Agent", ua)
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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("CertSpotter returned HTTP %d", resp.StatusCode)
	}
	var raw []struct {
		ID         string   `json:"id"`
		CertSHA256 string   `json:"cert_sha256"`
		DNSNames   []string `json:"dns_names"`
		NotBefore  string   `json:"not_before"`
		NotAfter   string   `json:"not_after"`
		Issuer     struct {
			Name string `json:"name"`
		} `json:"issuer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&raw); err != nil {
		return nil, err
	}
	entries := make([]models.CTObservation, 0, len(raw))
	for _, item := range raw {
		entry := models.CTObservation{
			SHA256:     strings.ToLower(strings.TrimSpace(item.CertSHA256)),
			IssuerName: item.Issuer.Name,
			Names:      item.DNSNames,
			Source:     "certspotter",
		}
		for rawValue, target := range map[string]**time.Time{item.NotBefore: &entry.NotBefore, item.NotAfter: &entry.NotAfter} {
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
		if strings.Contains(endpoint, "cert_sha256=") {
			ttl = certificateLookupTTL
		}
		gate.storeFor(endpoint, entries, time.Now(), ttl)
	}
	return entries, nil
}
