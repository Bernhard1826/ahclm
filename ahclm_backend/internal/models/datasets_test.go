package models

import (
	"net"
	"testing"
)

func TestDatasetVendorUsesLongestOfficialPrefix(t *testing.T) {
	_, wide, _ := net.ParseCIDR("192.0.2.0/24")
	_, narrow, _ := net.ParseCIDR("192.0.2.0/28")
	ReplaceEvidenceDatasets(DatasetSnapshot{Prefixes: []DatasetPrefix{
		{Network: wide, Vendor: "fastly", Source: "fastly_public_ip_list"},
		{Network: narrow, Vendor: "cloudflare", Source: "cloudflare_ips"},
	}})
	defer ReplaceEvidenceDatasets(DatasetSnapshot{})
	vendor, source := DatasetVendorFromAddress("192.0.2.1")
	if vendor != "cloudflare" || source != "cloudflare_ips" {
		t.Fatalf("vendor=%q source=%q", vendor, source)
	}
}

func TestDatasetVendorConflictDoesNotNameAVendor(t *testing.T) {
	_, left, _ := net.ParseCIDR("192.0.2.0/24")
	_, right, _ := net.ParseCIDR("192.0.2.0/24")
	ReplaceEvidenceDatasets(DatasetSnapshot{Prefixes: []DatasetPrefix{
		{Network: left, Vendor: "cloudflare", Source: "cloudflare_ips"},
		{Network: right, Vendor: "fastly", Source: "fastly_public_ip_list"},
	}})
	defer ReplaceEvidenceDatasets(DatasetSnapshot{})
	vendor, source := CDNVendorFromAddressSource("192.0.2.8")
	if vendor != CDNVendorNone || source != "official_prefix_conflict" {
		t.Fatalf("vendor=%q source=%q", vendor, source)
	}
}

func TestMergeDatasetLogsUnionsChromeAndApple(t *testing.T) {
	merged := MergeDatasetLogs(map[string]DatasetLog{
		"aa": {LogID: "aa", Operator: "Google", ChromeListed: true, Qualified: true, State: "usable"},
	}, map[string]DatasetLog{
		"aa": {LogID: "aa", AppleListed: true, State: "usable"},
	})
	entry := merged["aa"]
	if !entry.ChromeListed || !entry.AppleListed || !entry.Qualified {
		t.Fatalf("merged = %#v", entry)
	}
}
