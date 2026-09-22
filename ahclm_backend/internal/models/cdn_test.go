package models

import "testing"

func TestCDNVendorFromAddressUsesPublishedPrefixes(t *testing.T) {
	if got := CDNVendorFromAddress("104.16.7.9"); got != "cloudflare" {
		t.Fatalf("104.16.7.9 = %q, want cloudflare", got)
	}
	if got := CDNVendorFromAddress("151.101.1.1"); got != "fastly" {
		t.Fatalf("151.101.1.1 = %q, want fastly", got)
	}
	if got := CDNVendorFromAddress("192.0.2.1"); got != CDNVendorNone {
		t.Fatalf("documentation prefix must stay unidentified, got %q", got)
	}
}

func TestCDNVendorFromNameUsesSuffixNotParent(t *testing.T) {
	if got := CDNVendorFromName("www.example.com.cdn.cloudflare.net"); got != "cloudflare" {
		t.Fatalf("cloudflare CNAME = %q", got)
	}
	if got := CDNVendorFromName("d111111abcdef8.cloudfront.net"); got != "cloudfront" {
		t.Fatalf("cloudfront CNAME = %q", got)
	}
	if got := CDNVendorFromName("cloudflare.com.evil.example"); got != CDNVendorNone {
		t.Fatalf("parent-looking suffix must not identify a vendor, got %q", got)
	}
}

func TestParseHTTPSTargetsDropsThisName(t *testing.T) {
	if got := ParseHTTPSTargets(`1 . alpn="h3,h2"`); len(got) != 0 {
		t.Fatalf("root HTTPS target should be ignored, got %#v", got)
	}
	got := ParseHTTPSTargets("0 dual.example.cdn.cloudflare.net.")
	if len(got) != 1 || got[0] != "dual.example.cdn.cloudflare.net" {
		t.Fatalf("HTTPS alias target = %#v", got)
	}
}

func TestCDNMethodRequiresPrefixCompleteness(t *testing.T) {
	if CDNMethodFor(CDNCompletenessHostname) != "network" {
		t.Fatal("hostname-only evidence must not decide multi-CDN")
	}
	if CDNMethodFor(CDNCompletenessPartial) != "network" {
		t.Fatal("partial prefix coverage must not decide multi-CDN")
	}
	if CDNMethodFor(CDNCompletenessPrefix) != "vendor" {
		t.Fatal("complete prefix coverage should use named vendors")
	}
	if CDNMethodFor(CDNCompletenessDirectory) != "vendor" {
		t.Fatal("complete numbering-authority identification should use named vendors")
	}
}

func TestCDNVendorFromDirectoryUsesCDNSpecificASN(t *testing.T) {
	if got := CDNVendorFromDirectory(13335); got != "cloudflare" {
		t.Fatalf("AS13335 = %q, want cloudflare", got)
	}
	if got := CDNVendorFromDirectory(16509); got != CDNVendorNone {
		t.Fatalf("generic Amazon ASN must not name CloudFront, got %q", got)
	}
	if got := CDNVendorFromDirectory(16509, "AMAZO-CF", "Amazon CloudFront"); got != "cloudfront" {
		t.Fatalf("CloudFront netname inside Amazon ASN = %q", got)
	}
	if got := CDNVendorFromDirectory(0, "Akamai Technologies"); got != "akamai" {
		t.Fatalf("org token = %q", got)
	}
}
