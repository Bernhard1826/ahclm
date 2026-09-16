// Package domainlist loads the local domain populations used in addition to
// the ranked Tranco population.
package domainlist

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ahclm/internal/models"
)

const maxLineBytes = 64 * 1024 * 1024

// LoadSources reads and combines all configured local sources. The result is
// normalized, de-duplicated, and sorted for deterministic database updates.
func LoadSources(ctx context.Context, sources []models.LocalListSourceConfig) ([]string, error) {
	seen := make(map[string]struct{})
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		domains, err := LoadSource(ctx, source)
		if err != nil {
			return nil, err
		}
		if len(domains) == 0 {
			return nil, fmt.Errorf("local list source %q contains no valid domains", sourceDisplayName(source))
		}
		for _, domain := range domains {
			seen[domain] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no local list sources configured")
	}
	result := make([]string, 0, len(seen))
	for domain := range seen {
		result = append(result, domain)
	}
	sort.Strings(result)
	return result, nil
}

// LoadSource reads one plain-line or JSONL source. A malformed JSONL record is
// skipped so a single bad record cannot discard an otherwise useful list.
func LoadSource(ctx context.Context, source models.LocalListSourceConfig) ([]string, error) {
	path := strings.TrimSpace(source.Path)
	if path == "" {
		return nil, fmt.Errorf("local list source %q has an empty path", sourceDisplayName(source))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open local list source %q (%s): %w", sourceDisplayName(source), path, err)
	}
	defer file.Close()

	format := strings.ToLower(strings.TrimSpace(source.Format))
	if format == "" || format == "auto" {
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".jsonl" || ext == ".ndjson" {
			format = "jsonl"
		} else {
			format = "lines"
		}
	}

	var domains []string
	switch format {
	case "lines":
		domains, err = loadLines(ctx, file, source.MaxDomains)
	case "jsonl":
		domains, err = loadJSONL(ctx, file, source.MaxDomains)
	default:
		return nil, fmt.Errorf("local list source %q has unsupported format %q", sourceDisplayName(source), source.Format)
	}
	if err != nil {
		return nil, fmt.Errorf("read local list source %q: %w", sourceDisplayName(source), err)
	}
	return domains, nil
}

func loadLines(ctx context.Context, file *os.File, maxDomains int) ([]string, error) {
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 128*1024), maxLineBytes)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if maxDomains > 0 && len(seen) >= maxDomains {
			break
		}
		if domain, ok := NormalizeDomain(scanner.Text()); ok {
			seen[domain] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sortedDomains(seen), nil
}

func loadJSONL(ctx context.Context, file *os.File, maxDomains int) ([]string, error) {
	type record struct {
		Domain  string   `json:"domain"`
		URL     string   `json:"url"`
		Domains []string `json:"domains"`
	}
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 128*1024), maxLineBytes)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if maxDomains > 0 && len(seen) >= maxDomains {
			break
		}
		var item record
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			continue
		}
		candidates := make([]string, 0, 2+len(item.Domains))
		candidates = append(candidates, item.Domain, item.URL)
		candidates = append(candidates, item.Domains...)
		for _, candidate := range candidates {
			if maxDomains > 0 && len(seen) >= maxDomains {
				break
			}
			if domain, ok := NormalizeDomain(candidate); ok {
				seen[domain] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sortedDomains(seen), nil
}

func sortedDomains(seen map[string]struct{}) []string {
	domains := make([]string, 0, len(seen))
	for domain := range seen {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

func sourceDisplayName(source models.LocalListSourceConfig) string {
	if name := strings.TrimSpace(source.Name); name != "" {
		return name
	}
	return strings.TrimSpace(source.Path)
}

// NormalizeDomain converts a domain or URL candidate to a lowercase DNS host.
// It intentionally accepts only DNS hostnames (not IP addresses or arbitrary
// URL paths) because the scanner opens a TLS connection to the resulting host.
func NormalizeDomain(raw string) (string, bool) {
	candidate := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if candidate == "" || strings.HasPrefix(candidate, "#") {
		return "", false
	}

	if strings.Contains(candidate, "://") || strings.HasPrefix(candidate, "//") {
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Host == "" || parsed.User != nil {
			return "", false
		}
		candidate = parsed.Host
	}
	if strings.ContainsAny(candidate, "/?#") || strings.ContainsAny(candidate, " \t\r\n") {
		return "", false
	}
	if strings.Contains(candidate, ":") {
		// Ports and IPv6 literals are not domain-list entries.
		return "", false
	}
	candidate = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(candidate)), ".")
	candidate = strings.TrimPrefix(candidate, "www.")
	if candidate == "" || len(candidate) > 253 || net.ParseIP(candidate) != nil {
		return "", false
	}
	for _, label := range strings.Split(candidate, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", false
		}
	}
	return candidate, true
}
