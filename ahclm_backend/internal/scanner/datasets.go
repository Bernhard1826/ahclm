package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ahclm/internal/models"
)

const (
	defaultCloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"
	defaultCloudflareIPv6URL = "https://www.cloudflare.com/ips-v6"
	defaultFastlyPublicIPURL = "https://api.fastly.com/public-ip-list"
	defaultCloudfrontIPURL   = "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips"
	defaultAWSIPRangesURL    = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	defaultBunnyEdgeListURL  = "https://api.bunny.net/system/edgeserverlist/plain"
	defaultChromeLogListURL  = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
	defaultAppleLogListURL   = "https://valid.apple.com/ct/log_list/current_log_list.json"
	defaultRIPEstatPrefixURL = "https://stat.ripe.net/data/prefix-overview/data.json"
	defaultCertSpotterURL    = "https://api.certspotter.com/v1/issuances"
	datasetRefreshInterval   = 12 * time.Hour
)

type datasetFetcher struct {
	client *http.Client
	cfg    *models.ScannerConfig
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newDatasetFetcher(cfg *models.ScannerConfig) *datasetFetcher {
	timeout := 20 * time.Second
	if cfg != nil && cfg.Timeout > 0 && cfg.Timeout < timeout {
		timeout = cfg.Timeout
		if timeout < 5*time.Second {
			timeout = 5 * time.Second
		}
	}
	return &datasetFetcher{
		client: &http.Client{Timeout: timeout},
		cfg:    cfg,
	}
}

func (f *datasetFetcher) Start(ctx context.Context) {
	if f == nil {
		return
	}
	refreshCtx, cancel := context.WithCancel(ctx)
	f.cancel = cancel
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.refresh(refreshCtx)
		ticker := time.NewTicker(datasetRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-refreshCtx.Done():
				return
			case <-ticker.C:
				f.refresh(refreshCtx)
			}
		}
	}()
}

func (f *datasetFetcher) Stop() {
	if f == nil {
		return
	}
	if f.cancel != nil {
		f.cancel()
	}
	f.wg.Wait()
}

func (f *datasetFetcher) refresh(ctx context.Context) {
	current := models.CurrentEvidenceDatasets()
	snapshot := models.DatasetSnapshot{
		Prefixes: current.Prefixes,
		Logs:     current.Logs,
	}
	if snapshot.Logs == nil {
		snapshot.Logs = map[string]models.DatasetLog{}
	}
	if f.cfg == nil || f.cfg.CheckOfficialPrefixes {
		var prefixes []models.DatasetPrefix
		if loaded, err := f.loadCloudflare(ctx); err != nil {
			log.Printf("datasets: cloudflare prefixes: %v", err)
		} else {
			prefixes = append(prefixes, loaded...)
		}
		if loaded, err := f.loadFastly(ctx); err != nil {
			log.Printf("datasets: fastly prefixes: %v", err)
		} else {
			prefixes = append(prefixes, loaded...)
		}
		if loaded, err := f.loadCloudfront(ctx); err != nil {
			log.Printf("datasets: cloudfront prefixes: %v", err)
		} else {
			prefixes = append(prefixes, loaded...)
		}
		if loaded, err := f.loadAWSCloudFront(ctx); err != nil {
			log.Printf("datasets: aws cloudfront prefixes: %v", err)
		} else {
			prefixes = append(prefixes, loaded...)
		}
		if loaded, err := f.loadBunny(ctx); err != nil {
			log.Printf("datasets: bunnycdn prefixes: %v", err)
		} else {
			prefixes = append(prefixes, loaded...)
		}
		if len(prefixes) > 0 {
			snapshot.Prefixes = prefixes
		}
	}
	logs := map[string]models.DatasetLog{}
	loadedLogs := false
	if f.cfg == nil || f.cfg.CheckChromeLogList {
		if chrome, err := f.loadChromeLogList(ctx); err != nil {
			log.Printf("datasets: chrome CT log list: %v", err)
		} else {
			logs = models.MergeDatasetLogs(logs, chrome)
			loadedLogs = true
		}
	}
	if f.cfg == nil || f.cfg.CheckAppleLogList {
		if apple, err := f.loadAppleLogList(ctx); err != nil {
			log.Printf("datasets: apple CT log list: %v", err)
		} else {
			logs = models.MergeDatasetLogs(logs, apple)
			loadedLogs = true
		}
	}
	if loadedLogs {
		snapshot.Logs = logs
	}
	models.ReplaceEvidenceDatasets(snapshot)
	log.Printf("datasets: loaded %d official CDN prefixes and %d CT logs (%d Chrome, %d Apple)", len(snapshot.Prefixes), len(snapshot.Logs), models.DatasetLogListCount("chrome"), models.DatasetLogListCount("apple"))
}

func (f *datasetFetcher) loadCloudflare(ctx context.Context) ([]models.DatasetPrefix, error) {
	v4, err := f.fetchLines(ctx, firstNonEmpty(f.cfgValue("cloudflare_ipv4"), defaultCloudflareIPv4URL))
	if err != nil {
		return nil, err
	}
	v6, err := f.fetchLines(ctx, firstNonEmpty(f.cfgValue("cloudflare_ipv6"), defaultCloudflareIPv6URL))
	if err != nil {
		return nil, err
	}
	return append(parseCIDRList(v4, "cloudflare", "cloudflare_ips"), parseCIDRList(v6, "cloudflare", "cloudflare_ips")...), nil
}

func (f *datasetFetcher) loadFastly(ctx context.Context) ([]models.DatasetPrefix, error) {
	raw, err := f.getJSON(ctx, firstNonEmpty(f.cfgValue("fastly_public_ips"), defaultFastlyPublicIPURL))
	if err != nil {
		return nil, err
	}
	var payload struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	return append(parseCIDRList(payload.Addresses, "fastly", "fastly_public_ip_list"), parseCIDRList(payload.IPv6Addresses, "fastly", "fastly_public_ip_list")...), nil
}

func (f *datasetFetcher) loadCloudfront(ctx context.Context) ([]models.DatasetPrefix, error) {
	raw, err := f.getJSON(ctx, firstNonEmpty(f.cfgValue("cloudfront_ips"), defaultCloudfrontIPURL))
	if err != nil {
		return nil, err
	}
	var payload struct {
		CloudFrontGlobalIPList       []string `json:"CLOUDFRONT_GLOBAL_IP_LIST"`
		CloudFrontRegionalEdgeIPList []string `json:"CLOUDFRONT_REGIONAL_EDGE_IP_LIST"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	return append(parseCIDRList(payload.CloudFrontGlobalIPList, "cloudfront", "cloudfront_ip_list"), parseCIDRList(payload.CloudFrontRegionalEdgeIPList, "cloudfront", "cloudfront_ip_list")...), nil
}

func (f *datasetFetcher) loadAWSCloudFront(ctx context.Context) ([]models.DatasetPrefix, error) {
	raw, err := f.getJSON(ctx, firstNonEmpty(f.cfgValue("aws_ip_ranges"), defaultAWSIPRangesURL))
	if err != nil {
		return nil, err
	}
	var payload struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	values := make([]string, 0, 256)
	for _, item := range payload.Prefixes {
		if strings.EqualFold(item.Service, "CLOUDFRONT") {
			values = append(values, item.IPPrefix)
		}
	}
	for _, item := range payload.IPv6Prefixes {
		if strings.EqualFold(item.Service, "CLOUDFRONT") {
			values = append(values, item.IPv6Prefix)
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("aws ip-ranges contained no CLOUDFRONT prefixes")
	}
	return parseCIDRList(values, "cloudfront", "aws_ip_ranges_cloudfront"), nil
}

func (f *datasetFetcher) loadBunny(ctx context.Context) ([]models.DatasetPrefix, error) {
	lines, err := f.fetchLines(ctx, firstNonEmpty(f.cfgValue("bunny_edge_list"), defaultBunnyEdgeListURL))
	if err != nil {
		return nil, err
	}
	loaded := parseCIDRList(lines, "bunnycdn", "bunny_edge_server_list")
	if len(loaded) == 0 {
		return nil, fmt.Errorf("bunny edge list contained no addresses")
	}
	return loaded, nil
}

func (f *datasetFetcher) loadChromeLogList(ctx context.Context) (map[string]models.DatasetLog, error) {
	raw, err := f.getJSON(ctx, firstNonEmpty(f.cfgValue("chrome_log_list"), defaultChromeLogListURL))
	if err != nil {
		return nil, err
	}
	var payload struct {
		Operators []struct {
			Name string `json:"name"`
			Logs []struct {
				Description string                     `json:"description"`
				LogID       string                     `json:"log_id"`
				URL         string                     `json:"url"`
				Key         string                     `json:"key"`
				State       map[string]json.RawMessage `json:"state"`
			} `json:"logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	out := make(map[string]models.DatasetLog)
	for _, operator := range payload.Operators {
		for _, item := range operator.Logs {
			logID := models.NormalizeCTLogID(item.LogID)
			if logID == "" {
				continue
			}
			state := "unknown"
			qualified := false
			for name := range item.State {
				state = name
				if name == "usable" || name == "qualified" || name == "readonly" {
					qualified = true
				}
			}
			out[logID] = models.DatasetLog{
				LogID:        logID,
				URL:          item.URL,
				Operator:     operator.Name,
				State:        state,
				Key:          item.Key,
				Qualified:    qualified,
				ChromeListed: true,
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("chrome log list contained no log IDs")
	}
	return out, nil
}

func (f *datasetFetcher) loadAppleLogList(ctx context.Context) (map[string]models.DatasetLog, error) {
	raw, err := f.getJSON(ctx, firstNonEmpty(f.cfgValue("apple_log_list"), defaultAppleLogListURL))
	if err != nil {
		return nil, err
	}
	var payload struct {
		Operators []struct {
			Name string `json:"name"`
			Logs []struct {
				LogID string                     `json:"log_id"`
				URL   string                     `json:"url"`
				Key   string                     `json:"key"`
				State map[string]json.RawMessage `json:"state"`
			} `json:"logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	out := make(map[string]models.DatasetLog)
	for _, operator := range payload.Operators {
		for _, item := range operator.Logs {
			logID := models.NormalizeCTLogID(item.LogID)
			if logID == "" {
				continue
			}
			state := "unknown"
			usable := false
			for name := range item.State {
				state = name
				if name == "usable" || name == "qualified" || name == "readonly" {
					usable = true
				}
			}
			out[logID] = models.DatasetLog{
				LogID:       logID,
				URL:         item.URL,
				Operator:    operator.Name,
				State:       state,
				Key:         item.Key,
				Qualified:   usable,
				AppleListed: true,
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("apple log list contained no log IDs")
	}
	return out, nil
}

func (f *datasetFetcher) fetchRIPEstat(ctx context.Context, address string) (models.IPDirectoryRecord, error) {
	endpoint := firstNonEmpty(f.cfgValue("ripestat_prefix"), defaultRIPEstatPrefixURL)
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return models.IPDirectoryRecord{}, err
	}
	query := parsed.Query()
	query.Set("resource", address)
	parsed.RawQuery = query.Encode()
	raw, err := f.getJSON(ctx, parsed.String())
	if err != nil {
		return models.IPDirectoryRecord{}, err
	}
	var payload struct {
		Status string `json:"status"`
		Data   struct {
			Resource  string `json:"resource"`
			Announced bool   `json:"announced"`
			ASNs      []struct {
				ASN    int    `json:"asn"`
				Holder string `json:"holder"`
			} `json:"asns"`
			Block struct {
				Resource string `json:"resource"`
				Name     string `json:"name"`
				Desc     string `json:"desc"`
			} `json:"block"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return models.IPDirectoryRecord{}, err
	}
	if payload.Status != "ok" {
		return models.IPDirectoryRecord{}, fmt.Errorf("RIPEstat status %s", payload.Status)
	}
	record := models.IPDirectoryRecord{
		IPAddress: address,
		Prefix:    strings.TrimSpace(payload.Data.Resource),
		NetName:   strings.TrimSpace(payload.Data.Block.Name),
		OrgName:   strings.TrimSpace(payload.Data.Block.Desc),
		Source:    "ripestat",
	}
	if len(payload.Data.ASNs) > 0 {
		record.ASN = payload.Data.ASNs[0].ASN
		if record.ASNName == "" {
			record.ASNName = strings.TrimSpace(payload.Data.ASNs[0].Holder)
		}
		if record.OrgName == "" {
			record.OrgName = record.ASNName
		}
	}
	if record.Prefix == "" {
		record.Prefix = strings.TrimSpace(payload.Data.Block.Resource)
	}
	if record.ASN == 0 && record.Prefix == "" {
		return record, fmt.Errorf("RIPEstat returned no prefix or ASN for %s", address)
	}
	return record, nil
}

func (f *datasetFetcher) cfgValue(key string) string {
	if f == nil || f.cfg == nil {
		return ""
	}
	switch key {
	case "cloudflare_ipv4":
		return f.cfg.CloudflareIPv4URL
	case "cloudflare_ipv6":
		return f.cfg.CloudflareIPv6URL
	case "fastly_public_ips":
		return f.cfg.FastlyPublicIPURL
	case "cloudfront_ips":
		return f.cfg.CloudfrontIPURL
	case "chrome_log_list":
		return f.cfg.ChromeLogListURL
	case "apple_log_list":
		return f.cfg.AppleLogListURL
	case "aws_ip_ranges":
		return f.cfg.AWSIPRangesURL
	case "bunny_edge_list":
		return f.cfg.BunnyEdgeListURL
	case "ripestat_prefix":
		return f.cfg.RIPEstatEndpoint
	default:
		return ""
	}
}

func (f *datasetFetcher) fetchLines(ctx context.Context, endpoint string) ([]string, error) {
	body, err := f.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	out := make([]string, 0, 64)
	scanner := bufio.NewScanner(io.LimitReader(body, 2<<20))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

func (f *datasetFetcher) getJSON(ctx context.Context, endpoint string) ([]byte, error) {
	body, err := f.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(io.LimitReader(body, 8<<20))
}

func (f *datasetFetcher) get(ctx context.Context, endpoint string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	ua := "AHCLM-CertMonitor/2.0"
	if f.cfg != nil && strings.TrimSpace(f.cfg.UserAgent) != "" {
		ua = f.cfg.UserAgent
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32<<10))
		resp.Body.Close()
		return nil, fmt.Errorf("%s returned HTTP %d", endpoint, resp.StatusCode)
	}
	return resp.Body, nil
}

func parseCIDRList(values []string, vendor, source string) []models.DatasetPrefix {
	out := make([]models.DatasetPrefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			if ip := net.ParseIP(value); ip != nil {
				if ip.To4() != nil {
					value += "/32"
				} else {
					value += "/128"
				}
			}
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			continue
		}
		out = append(out, models.DatasetPrefix{Network: network, Vendor: vendor, Source: source})
	}
	return out
}
