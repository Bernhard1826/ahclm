package models

import (
	"net"
	"strings"
)

// CDNVendorNone is the empty identification: the record or address could not
// be attributed to a named provider.
const CDNVendorNone = ""

// CDN identification completeness. The multi-CDN verdict uses named vendors
// only when every answering endpoint can be attributed; otherwise it stays on
// the IPv4 /16 and IPv6 /32 partition.
const (
	CDNCompletenessNone      = "none"
	CDNCompletenessHostname  = "hostname"
	CDNCompletenessPartial   = "partial"
	CDNCompletenessPrefix    = "prefix"
	CDNCompletenessDirectory = "directory"
	CDNCompletenessBoth      = "both"
)

// CDNEvidence is the vendor reading derived from DNS control-plane records
// (CNAME, HTTPS/SVCB) and from published CDN address space. It never replaces
// the certificate-to-endpoint assignment; it only names the operators.
type CDNEvidence struct {
	Completeness     string            `json:"completeness"`
	Method           string            `json:"method,omitempty"`
	HostnameVendors  []string          `json:"hostname_vendors,omitempty"`
	CNAMEVendors     []string          `json:"cname_vendors,omitempty"`
	HTTPSVendors     []string          `json:"https_vendors,omitempty"`
	HTTPVendors      []string          `json:"http_vendors,omitempty"`
	EndpointVendors  map[string]string `json:"endpoint_vendors,omitempty"`
	DistinctVendors  int               `json:"distinct_vendors"`
	IdentifiedCount  int               `json:"identified_endpoints"`
	Unidentified     []string          `json:"unidentified_endpoints,omitempty"`
	VendorConflicts  int               `json:"vendor_conflicts"`
	CleanVendorSplit bool              `json:"clean_vendor_split"`
	Sources          []string          `json:"sources,omitempty"`
	Note             string            `json:"note,omitempty"`
}

type cdnPrefix struct {
	network *net.IPNet
	vendor  string
}

func mustCIDR(value string) *net.IPNet {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		panic("cdn prefix: " + value + ": " + err.Error())
	}
	return network
}

// Published anycast and edge ranges that are stable enough to name a CDN.
// This is identification, not an inventory of every prefix a provider has ever
// announced; unidentified addresses fall back to the /16 and /32 partition.
var cdnPrefixes = []cdnPrefix{
	{mustCIDR("1.1.1.0/24"), "cloudflare"},
	{mustCIDR("104.16.0.0/12"), "cloudflare"},
	{mustCIDR("104.24.0.0/14"), "cloudflare"},
	{mustCIDR("162.158.0.0/15"), "cloudflare"},
	{mustCIDR("172.64.0.0/13"), "cloudflare"},
	{mustCIDR("173.245.48.0/20"), "cloudflare"},
	{mustCIDR("188.114.96.0/20"), "cloudflare"},
	{mustCIDR("190.93.240.0/20"), "cloudflare"},
	{mustCIDR("197.234.240.0/22"), "cloudflare"},
	{mustCIDR("198.41.128.0/17"), "cloudflare"},
	{mustCIDR("2400:cb00::/32"), "cloudflare"},
	{mustCIDR("2606:4700::/32"), "cloudflare"},
	{mustCIDR("2803:f800::/32"), "cloudflare"},
	{mustCIDR("2a06:98c0::/29"), "cloudflare"},
	{mustCIDR("2c0f:f248::/32"), "cloudflare"},

	{mustCIDR("13.32.0.0/15"), "cloudfront"},
	{mustCIDR("13.35.0.0/16"), "cloudfront"},
	{mustCIDR("13.224.0.0/14"), "cloudfront"},
	{mustCIDR("18.64.0.0/14"), "cloudfront"},
	{mustCIDR("52.84.0.0/15"), "cloudfront"},
	{mustCIDR("54.182.0.0/16"), "cloudfront"},
	{mustCIDR("54.192.0.0/16"), "cloudfront"},
	{mustCIDR("54.230.0.0/16"), "cloudfront"},
	{mustCIDR("54.239.128.0/18"), "cloudfront"},
	{mustCIDR("99.84.0.0/16"), "cloudfront"},
	{mustCIDR("204.246.164.0/22"), "cloudfront"},
	{mustCIDR("205.251.192.0/19"), "cloudfront"},
	{mustCIDR("2600:9000::/28"), "cloudfront"},

	{mustCIDR("23.32.0.0/11"), "akamai"},
	{mustCIDR("23.64.0.0/14"), "akamai"},
	{mustCIDR("23.72.0.0/13"), "akamai"},
	{mustCIDR("104.64.0.0/10"), "akamai"},
	{mustCIDR("172.224.0.0/12"), "akamai"},
	{mustCIDR("184.24.0.0/13"), "akamai"},
	{mustCIDR("184.50.0.0/15"), "akamai"},
	{mustCIDR("184.84.0.0/15"), "akamai"},
	{mustCIDR("2.16.0.0/13"), "akamai"},
	{mustCIDR("2600:1400::/24"), "akamai"},

	{mustCIDR("151.101.0.0/16"), "fastly"},
	{mustCIDR("199.232.0.0/16"), "fastly"},
	{mustCIDR("167.82.0.0/16"), "fastly"},
	{mustCIDR("2a04:4e40::/32"), "fastly"},
	{mustCIDR("2a04:4e42::/32"), "fastly"},

	{mustCIDR("45.133.44.0/24"), "bunnycdn"},
	{mustCIDR("185.93.1.0/24"), "bunnycdn"},
	{mustCIDR("2400:52e0::/32"), "bunnycdn"},
}

var cdnSuffixes = []struct {
	suffix string
	vendor string
}{
	{".cdn.cloudflare.net", "cloudflare"},
	{".cloudflare.net", "cloudflare"},
	{".cloudflare.com", "cloudflare"},
	{".cloudfront.net", "cloudfront"},
	{".akamai.net", "akamai"},
	{".akamaiedge.net", "akamai"},
	{".akamaized.net", "akamai"},
	{".edgekey.net", "akamai"},
	{".edgesuite.net", "akamai"},
	{".fastly.net", "fastly"},
	{".fastlylb.net", "fastly"},
	{".google.com", "google"},
	{".googleusercontent.com", "google"},
	{".ghs.googlehosted.com", "google"},
	{".azureedge.net", "azurecdn"},
	{".azurefd.net", "azurecdn"},
	{".trafficmanager.net", "azurecdn"},
	{".msecnd.net", "azurecdn"},
	{".azurewebsites.net", "azurecdn"},
	{".bunnycdn.com", "bunnycdn"},
	{".b-cdn.net", "bunnycdn"},
	{".hwcdn.net", "stackpath"},
	{".stackpathcdn.com", "stackpath"},
	{".incapdns.net", "imperva"},
	{".cdngc.net", "cdnetworks"},
	{".kxcdn.com", "keycdn"},
	{".cachefly.net", "cachefly"},
	{".llnwd.net", "limelight"},
	{".lldns.net", "limelight"},
	{".ns.cloudflare.com", "cloudflare"},
	{".cloudflare-dns.com", "cloudflare"},
	{".akam.net", "akamai"},
	{".akamai.com", "akamai"},
	{".fastly-dns.net", "fastly"},
}

var httpVendorTokens = []struct {
	token  string
	vendor string
}{
	{"cf-ray", "cloudflare"},
	{"cloudflare", "cloudflare"},
	{"x-amz-cf-id", "cloudfront"},
	{"cloudfront", "cloudfront"},
	{"x-akamai-transformed", "akamai"},
	{"akamai", "akamai"},
	{"x-fastly-request-id", "fastly"},
	{"fastly", "fastly"},
	{"x-azure-ref", "azurecdn"},
	{"x-cache-origin", "azurecdn"},
}

// Numbering-authority ASNs that identify a CDN rather than a general cloud.
// Generic Amazon/Google/Microsoft ASNs are omitted: they mix CDN edges with
// origin VMs, so org/netname tokens have to name the product.
var cdnASNs = map[int]string{
	13335:  "cloudflare",
	209242: "cloudflare",
	394536: "cloudflare",
	20940:  "akamai",
	16625:  "akamai",
	35994:  "akamai",
	34164:  "akamai",
	12222:  "akamai",
	54113:  "fastly",
	15133:  "edgecast",
	15169:  "",
	36040:  "google",
	16509:  "",
	14618:  "",
	8075:   "",
	8068:   "",
	20446:  "stackpath",
	19551:  "imperva",
	60068:  "cdn77",
	36459:  "github",
	139070: "bunnycdn",
}

var directoryVendorTokens = []struct {
	token  string
	vendor string
}{
	{"cloudflare", "cloudflare"},
	{"akamai", "akamai"},
	{"fastly", "fastly"},
	{"cloudfront", "cloudfront"},
	{"incapsula", "imperva"},
	{"imperva", "imperva"},
	{"azure front door", "azurecdn"},
	{"azurefd", "azurecdn"},
	{"microsoft azure cdn", "azurecdn"},
	{"bunnycdn", "bunnycdn"},
	{"bunny.net", "bunnycdn"},
	{"stackpath", "stackpath"},
	{"keycdn", "keycdn"},
	{"cdn77", "cdn77"},
	{"cachefly", "cachefly"},
	{"limelight", "limelight"},
	{"edgio", "limelight"},
	{"edgecast", "edgecast"},
	{"quantil", "quantil"},
	{"cdnetworks", "cdnetworks"},
}

// CDNVendorFromAddress returns a named CDN when the address falls in a
// published provider prefix. Unidentified addresses return CDNVendorNone.
func CDNVendorFromAddress(address string) string {
	vendor, _ := CDNVendorFromAddressSource(address)
	return vendor
}

func CDNVendorFromAddressSource(address string) (vendor, source string) {
	if vendor, source := DatasetVendorFromAddress(address); vendor != CDNVendorNone || source == "official_prefix_conflict" {
		return vendor, source
	}
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return CDNVendorNone, ""
	}
	for _, prefix := range cdnPrefixes {
		if prefix.network.Contains(ip) {
			return prefix.vendor, "builtin_cdn_prefix"
		}
	}
	return CDNVendorNone, ""
}

// CDNVendorFromName returns a named CDN when a DNS name uses a well-known
// provider suffix. The match is on the full name, not on a parent zone, so
// example.cloudflare.com is Cloudflare while cloudflare.com.evil.example is not.
func CDNVendorFromName(name string) string {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if host == "" || host == "." {
		return CDNVendorNone
	}
	for _, item := range cdnSuffixes {
		if host == strings.TrimPrefix(item.suffix, ".") || strings.HasSuffix(host, item.suffix) {
			return item.vendor
		}
	}
	return CDNVendorNone
}

// CDNVendorsFromNames identifies providers from a CNAME or HTTPS target list.
func CDNVendorsFromNames(names []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, name := range names {
		vendor := CDNVendorFromName(name)
		if vendor == CDNVendorNone {
			continue
		}
		if _, ok := seen[vendor]; ok {
			continue
		}
		seen[vendor] = struct{}{}
		out = append(out, vendor)
	}
	return out
}

// CDNVendorFromHTTPFingerprint reads CDN names from Server/Via/provider
// header tokens. It is a hostname-level hint, not a per-address assignment
// unless the fingerprint also records the endpoint IP.
func CDNVendorFromHTTPFingerprint(fp *HTTPFingerprint) []string {
	if fp == nil {
		return nil
	}
	blob := strings.ToLower(strings.Join(append(append([]string{fp.Server, fp.Via, fp.Cache}, fp.ProviderSignals...), fp.Redirect), " "))
	if blob == "" {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, item := range httpVendorTokens {
		if !strings.Contains(blob, item.token) {
			continue
		}
		if _, ok := seen[item.vendor]; ok {
			continue
		}
		seen[item.vendor] = struct{}{}
		out = append(out, item.vendor)
	}
	return out
}

// ParseHTTPSTargets extracts the HTTPS/SVCB TargetName values from a DoH
// presentation-form record. Priority 0 aliases and non-root targets are kept;
// "." (this name) is dropped because it is not a vendor suffix.
func ParseHTTPSTargets(data string) []string {
	fields := strings.Fields(strings.TrimSpace(data))
	if len(fields) < 2 {
		return nil
	}
	target := strings.ToLower(strings.TrimSuffix(fields[1], "."))
	if target == "" || target == "." {
		return nil
	}
	return []string{target}
}

// CDNMethodFor reports which evidence layer the multi-CDN verdict is allowed
// to use. Named vendors are used only when every answering endpoint is
// identified; otherwise the network partition remains the decision layer.
func CDNMethodFor(completeness string) string {
	switch completeness {
	case CDNCompletenessPrefix, CDNCompletenessBoth, CDNCompletenessDirectory:
		return "vendor"
	default:
		return "network"
	}
}

// CDNVendorFromASN returns a named CDN when the autonomous system is a
// CDN-specific network. Empty means the ASN is too generic to name a vendor.
func CDNVendorFromASN(asn int) string {
	if asn <= 0 {
		return CDNVendorNone
	}
	vendor, ok := cdnASNs[asn]
	if !ok {
		return CDNVendorNone
	}
	return vendor
}

// CDNVendorFromDirectory uses ASN first, then org/netname tokens. A generic
// cloud ASN still names a CDN when the network or organisation names the
// product (for example CloudFront inside AS16509).
func CDNVendorFromDirectory(asn int, names ...string) string {
	if vendor := CDNVendorFromASN(asn); vendor != CDNVendorNone {
		return vendor
	}
	return CDNVendorFromText(names...)
}

// CDNVendorFromText matches published CDN product tokens in registry text.
func CDNVendorFromText(names ...string) string {
	blob := strings.ToLower(strings.Join(names, " "))
	if strings.TrimSpace(blob) == "" {
		return CDNVendorNone
	}
	for _, item := range directoryVendorTokens {
		if strings.Contains(blob, item.token) {
			return item.vendor
		}
	}
	return CDNVendorNone
}
