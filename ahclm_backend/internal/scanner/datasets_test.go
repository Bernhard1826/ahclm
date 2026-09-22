package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestParseCIDRListAcceptsBareAddresses(t *testing.T) {
	got := parseCIDRList([]string{"1.2.3.4", "2001:db8::1/128", "not-an-ip"}, "fastly", "fastly_public_ip_list")
	if len(got) != 2 {
		t.Fatalf("prefixes = %#v", got)
	}
	if !got[0].Network.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatalf("bare IPv4 was not stored as /32: %s", got[0].Network)
	}
}

func TestOfficialPrefixDatasetOverridesBuiltinLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("192.0.2.0/24\n"))
	}))
	defer server.Close()
	fetcher := newDatasetFetcher(&models.ScannerConfig{Timeout: time.Second})
	fetcher.client = server.Client()
	prefixes, err := fetcher.loadFromLines(context.Background(), server.URL, "cloudflare", "cloudflare_ips")
	if err != nil {
		t.Fatal(err)
	}
	models.ReplaceEvidenceDatasets(models.DatasetSnapshot{Prefixes: prefixes})
	defer models.ReplaceEvidenceDatasets(models.DatasetSnapshot{})
	vendor, source := models.CDNVendorFromAddressSource("192.0.2.8")
	if vendor != "cloudflare" || source != "cloudflare_ips" {
		t.Fatalf("vendor=%q source=%q", vendor, source)
	}
}

func TestAWSIPRangesKeepsOnlyCloudFront(t *testing.T) {
	payload := map[string]any{
		"prefixes": []any{
			map[string]any{"ip_prefix": "192.0.2.0/24", "service": "CLOUDFRONT"},
			map[string]any{"ip_prefix": "198.51.100.0/24", "service": "EC2"},
		},
		"ipv6_prefixes": []any{
			map[string]any{"ipv6_prefix": "2001:db8::/32", "service": "CLOUDFRONT"},
		},
	}
	body, _ := json.Marshal(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer server.Close()
	fetcher := newDatasetFetcher(&models.ScannerConfig{Timeout: time.Second, AWSIPRangesURL: server.URL})
	fetcher.client = server.Client()
	prefixes, err := fetcher.loadAWSCloudFront(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("prefixes = %#v", prefixes)
	}
	models.ReplaceEvidenceDatasets(models.DatasetSnapshot{Prefixes: prefixes})
	defer models.ReplaceEvidenceDatasets(models.DatasetSnapshot{})
	if vendor, source := models.CDNVendorFromAddressSource("192.0.2.9"); vendor != "cloudfront" || source != "aws_ip_ranges_cloudfront" {
		t.Fatalf("cloudfront vendor=%q source=%q", vendor, source)
	}
	if vendor, _ := models.CDNVendorFromAddressSource("198.51.100.9"); vendor != models.CDNVendorNone {
		t.Fatalf("generic EC2 prefix must not name CloudFront, got %q", vendor)
	}
}

func TestChromeAndAppleLogListsAnnotateSCT(t *testing.T) {
	rawID, err := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	logID := base64.StdEncoding.EncodeToString(rawID)
	chromeBody, _ := json.Marshal(map[string]any{
		"operators": []any{map[string]any{
			"name": "Google",
			"logs": []any{map[string]any{
				"log_id": logID,
				"url":    "https://ct.googleapis.com/logs/us1/argon2026/",
				"state":  map[string]any{"usable": map[string]any{}},
			}},
		}},
	})
	appleBody, _ := json.Marshal(map[string]any{
		"operators": []any{map[string]any{
			"name": "Google",
			"logs": []any{map[string]any{
				"log_id": logID,
				"url":    "https://ct.googleapis.com/logs/us1/argon2026/",
				"state":  map[string]any{"usable": map[string]any{}},
			}},
		}},
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/chrome", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(chromeBody)
	})
	mux.HandleFunc("/apple", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(appleBody)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	fetcher := newDatasetFetcher(&models.ScannerConfig{
		Timeout:          time.Second,
		ChromeLogListURL: server.URL + "/chrome",
		AppleLogListURL:  server.URL + "/apple",
	})
	fetcher.client = server.Client()
	chromeLogs, err := fetcher.loadChromeLogList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	appleLogs, err := fetcher.loadAppleLogList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	models.ReplaceEvidenceDatasets(models.DatasetSnapshot{Logs: models.MergeDatasetLogs(chromeLogs, appleLogs)})
	defer models.ReplaceEvidenceDatasets(models.DatasetSnapshot{})
	observation := models.SCTObservation{LogID: hex.EncodeToString(rawID)}
	annotateSCT(&observation)
	if !observation.Qualified || !observation.ChromeListed || !observation.AppleListed {
		t.Fatalf("sct = %#v", observation)
	}
	if observation.Operator != "Google" {
		t.Fatalf("operator = %q", observation.Operator)
	}
}

func TestRIPEstatPrefixOverviewParsesASN(t *testing.T) {
	payload := map[string]any{
		"status": "ok",
		"data": map[string]any{
			"resource":  "1.1.1.0/24",
			"announced": true,
			"asns":      []any{map[string]any{"asn": 13335, "holder": "CLOUDFLARENET"}},
			"block":     map[string]any{"resource": "1.1.1.0/24", "name": "CLOUDFLARENET", "desc": "Cloudflare, Inc."},
		},
	}
	body, _ := json.Marshal(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "1.1.1.1" {
			t.Fatalf("resource = %q", r.URL.Query().Get("resource"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer server.Close()
	fetcher := newDatasetFetcher(&models.ScannerConfig{Timeout: time.Second, RIPEstatEndpoint: server.URL})
	fetcher.client = server.Client()
	record, err := fetcher.fetchRIPEstat(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if record.ASN != 13335 || record.Source != "ripestat" || record.Prefix != "1.1.1.0/24" {
		t.Fatalf("record = %#v", record)
	}
}

func (f *datasetFetcher) loadFromLines(ctx context.Context, endpoint, vendor, source string) ([]models.DatasetPrefix, error) {
	lines, err := f.fetchLines(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return parseCIDRList(lines, vendor, source), nil
}
