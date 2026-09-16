// Package tranco fetches a configured Tranco research ranking. Only downloaded,
// timestamped source data is accepted; there is no built-in target list.
package tranco

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ahclm/internal/models"
)

// Fetcher downloads and caches the Tranco list.
type Fetcher struct {
	client *http.Client
	config *models.TrancoConfig

	mu       sync.RWMutex
	cached   map[string]int
	source   string
	listID   string
	cachedAt time.Time
}

// NewFetcher creates a new Tranco fetcher.
func NewFetcher(cfg *models.TrancoConfig) *Fetcher {
	if cfg == nil {
		return &Fetcher{}
	}
	return &Fetcher{
		client: &http.Client{Timeout: cfg.RequestTimeout},
		config: cfg,
	}
}

func (f *Fetcher) maxDomains() int {
	return models.TrancoTopLimit
}

// FetchRanked returns a domain→rank map (1-based), the configured downloaded
// source kind ("zip") and a list identifier. Download failures are returned
// directly; no embedded target list is used.
func (f *Fetcher) FetchRanked() (map[string]int, string, string, error) {
	if f.config == nil || !f.config.Enabled {
		return nil, "", "", fmt.Errorf("tranco source is disabled")
	}
	f.mu.RLock()
	if f.cached != nil && time.Since(f.cachedAt) < f.config.CacheTTL {
		ranked, src, id := copyRanked(f.cached), f.source, f.listID
		f.mu.RUnlock()
		return ranked, src, id, nil
	}
	f.mu.RUnlock()

	ranked, source, listID, err := f.download()
	if err != nil {
		return nil, "", "", err
	}
	if len(ranked) != models.TrancoTopLimit {
		return nil, "", "", fmt.Errorf("tranco source returned %d domains, want exactly %d", len(ranked), models.TrancoTopLimit)
	}

	f.mu.Lock()
	f.cached, f.source, f.listID, f.cachedAt = ranked, source, listID, time.Now()
	f.mu.Unlock()

	return copyRanked(ranked), source, listID, nil
}

// FetchAll returns domains ordered by rank (ascending).
func (f *Fetcher) FetchAll() ([]string, error) {
	ranked, _, _, err := f.FetchRanked()
	if err != nil {
		return nil, err
	}
	return rankedToSlice(ranked), nil
}

func (f *Fetcher) download() (map[string]int, string, string, error) {
	req, err := http.NewRequest(http.MethodGet, f.config.SourceURL, nil)
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("User-Agent", f.config.UserAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("tranco download returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(f.config.MaxResponseBytes)))
	if err != nil {
		return nil, "", "", err
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, "", "", fmt.Errorf("unzip tranco list: %w", err)
	}

	listID := listIDFromURL(resp.Request.URL.String())
	for _, zf := range zr.File {
		if !strings.HasSuffix(strings.ToLower(zf.Name), ".csv") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, "", "", err
		}
		ranked := parseRankedCSV(rc, f.maxDomains())
		rc.Close()
		if len(ranked) == 0 {
			return nil, "", "", fmt.Errorf("empty tranco csv")
		}
		return ranked, "zip", listID, nil
	}
	return nil, "", "", fmt.Errorf("no csv entry found in tranco zip")
}

// parseRankedCSV reads "rank,domain" rows and returns a domain→rank map,
// stopping after max entries.
func parseRankedCSV(r io.Reader, max int) map[string]int {
	ranked := make(map[string]int, max)
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true

	for len(ranked) < max {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 2 {
			continue
		}
		rank, err := strconv.Atoi(strings.TrimSpace(rec[0]))
		if err != nil || rank < 1 || (max > 0 && rank > max) {
			continue // header or malformed row
		}
		domain := strings.ToLower(strings.TrimSpace(rec[1]))
		domain = strings.TrimPrefix(domain, "www.")
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}
		if _, exists := ranked[domain]; !exists {
			ranked[domain] = rank
		}
	}
	return ranked
}

func listIDFromURL(u string) string {
	base := path.Base(u)
	base = strings.TrimSuffix(base, ".zip")
	base = strings.TrimSuffix(base, ".csv")
	if base == "" || base == "top-1m" || base == "/" {
		return time.Now().Format("2006-01-02")
	}
	return base
}

func copyRanked(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func rankedToSlice(m map[string]int) []string {
	type dr struct {
		d string
		r int
	}
	arr := make([]dr, 0, len(m))
	for d, r := range m {
		arr = append(arr, dr{d, r})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].r < arr[j].r })
	out := make([]string, len(arr))
	for i := range arr {
		out[i] = arr[i].d
	}
	return out
}
