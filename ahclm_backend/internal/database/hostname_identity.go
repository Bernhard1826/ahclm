package database

import (
	"fmt"
	"strings"
)

// nonHTTPSIdentityReason names why a monitored hostname is not a site HTTPS
// identity. NTP pool names, numbered push aliases and CDN/DNS delivery CNAMEs
// fail VerifyHostname because the leaf is issued for the service name, not for
// the alias. That is expected, not a site certificate defect.
func nonHTTPSIdentityReason(domain string) string {
	name := strings.ToLower(strings.TrimSpace(domain))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return ""
	}
	switch {
	case hasDomainSuffix(name, "pool.ntp.org") || name == "pool.ntp.org":
		return fmt.Sprintf("%s is an NTP pool alias. Pool members present their own site certificates, not a certificate for the pool name.", name)
	case isApplePushAlias(name):
		return fmt.Sprintf("%s is an Apple Push numbered or DNS alias. The leaf is issued for courier.push.apple.com, not for this alias.", name)
	case hasDomainSuffix(name, "device-http-dns.ictun.com") || strings.Contains(name, ".device-http-dns."):
		return fmt.Sprintf("%s is a device HTTP-DNS name, not a site HTTPS identity.", name)
	case hasAnyDomainSuffix(name, cdnDeliverySuffixes...):
		return fmt.Sprintf("%s is a CDN or DNS delivery alias. The leaf is issued for the CDN service name, not for this CNAME.", name)
	default:
		return ""
	}
}

func isApplePushAlias(name string) bool {
	if hasDomainSuffix(name, "courier-push-apple.com.akadns.net") {
		return true
	}
	if !hasDomainSuffix(name, "push.apple.com") {
		return false
	}
	head, _, ok := strings.Cut(name, ".")
	if !ok {
		return false
	}
	if strings.HasSuffix(head, "-courier") {
		return true
	}
	return strings.Contains(name, "-courier.")
}

var cdnDeliverySuffixes = []string{
	"akadns.net",
	"akamai.net",
	"akamaiedge.net",
	"akamaihd.net",
	"akamaized.net",
	"alb.aliyuncs.com",
	"alibabadns.com",
	"apple-dns.cn",
	"apple-dns.net",
	"bcelive.com",
	"bdydns.com",
	"bvfcdn.com",
	"bytefcdn.com",
	"cdn.cloudflare.net",
	"cdnmg.com",
	"cdnhwc2.com",
	"cdnhwc3.com",
	"cloudfront.net",
	"delivery.mp.microsoft.com",
	"edgekey.net",
	"edgesuite.net",
	"fastly.net",
	"gccdn.net",
	"ks-cdn.com",
	"ksyuncdn.com",
	"lxdns.com",
	"oss-enet.aliyuncs.com",
	"ourwebpic.com",
	"qlivecdn.com",
	"qtlcdn.com",
	"shifen.com",
	"tcdnlive.com",
	"tdnsstic1.cn",
	"tdnsvod1.cn",
	"tencent-cloud.net",
	"volcfcdndvs.com",
	"wscdns.com",
	"wsdvs.com",
}

func hasAnyDomainSuffix(name string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if hasDomainSuffix(name, suffix) {
			return true
		}
	}
	return strings.Contains(name, ".sched.") && (strings.Contains(name, "tdns") || strings.Contains(name, "kslego") || strings.Contains(name, "vip-dk"))
}

func hasDomainSuffix(name, suffix string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}
