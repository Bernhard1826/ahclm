package models

import "strings"

// MatchCAA compares published CAA issue/issuewild values with the served
// leaf's issuer. Absence is not authorization; a matching issue tag is.
func MatchCAA(records []CAARecord, issuer string) (status, note string) {
	issuer = strings.ToLower(strings.TrimSpace(issuer))
	issue := make([]string, 0)
	issuewild := make([]string, 0)
	for _, record := range records {
		tag := strings.ToLower(strings.TrimSpace(record.Tag))
		value := strings.ToLower(strings.TrimSpace(record.Value))
		value = strings.Trim(value, `"`)
		if i := strings.IndexByte(value, ';'); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
		switch tag {
		case "issue":
			issue = append(issue, value)
		case "issuewild":
			issuewild = append(issuewild, value)
		}
	}
	if len(issue) == 0 && len(issuewild) == 0 {
		return CAAAbsent, "No CAA issue/issuewild records were published, so the CA was not constrained by CAA."
	}
	if issuer == "" {
		return CAAUnknown, "CAA records were published, but the served leaf has no issuer to compare."
	}
	if matchesCAAValues(issue, issuer) || matchesCAAValues(issuewild, issuer) {
		return CAAAuthorized, "CAA authorizes the served issuer (" + issuer + ")."
	}
	if allCAADeny(issue) && allCAADeny(issuewild) {
		return CAAUnauthorized, "CAA forbids issuance, but a certificate was served."
	}
	if knownCAAIssuer(issuer) {
		return CAAUnauthorized, "CAA does not authorize the served issuer (" + issuer + ")."
	}
	return CAAUnknown, "CAA records were published, but the served issuer could not be matched to a known CA domain."
}

func matchesCAAValues(values []string, issuer string) bool {
	for _, value := range values {
		if value == "" || value == ";" {
			continue
		}
		if strings.Contains(issuer, value) {
			return true
		}
		if caDomain := caaDomainForIssuer(issuer); caDomain != "" && (caDomain == value || strings.HasSuffix(value, "."+caDomain) || strings.HasSuffix(caDomain, "."+value)) {
			return true
		}
	}
	return false
}

func allCAADeny(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if value != "" && value != ";" {
			return false
		}
	}
	return true
}

func knownCAAIssuer(issuer string) bool {
	return caaDomainForIssuer(issuer) != ""
}

func caaDomainForIssuer(issuer string) string {
	switch {
	case strings.Contains(issuer, "let's encrypt") || strings.Contains(issuer, "letsencrypt"):
		return "letsencrypt.org"
	case strings.Contains(issuer, "google trust") || strings.Contains(issuer, "pki.goog"):
		return "pki.goog"
	case strings.Contains(issuer, "digicert") || strings.Contains(issuer, "rapidssl") || strings.Contains(issuer, "geotrust") || strings.Contains(issuer, "thawte"):
		return "digicert.com"
	case strings.Contains(issuer, "sectigo") || strings.Contains(issuer, "comodo") || strings.Contains(issuer, "usertrust") || strings.Contains(issuer, "aaa certificate services"):
		return "sectigo.com"
	case strings.Contains(issuer, "amazon") || strings.Contains(issuer, "amazontrust"):
		return "amazon.com"
	case strings.Contains(issuer, "cloudflare"):
		return "cloudflare.com"
	case strings.Contains(issuer, "globalsign"):
		return "globalsign.com"
	case strings.Contains(issuer, "godaddy") || strings.Contains(issuer, "starfield"):
		return "godaddy.com"
	case strings.Contains(issuer, "buypass"):
		return "buypass.com"
	case strings.Contains(issuer, "certainly"):
		return "certainly.com"
	case strings.Contains(issuer, "ssl.com"):
		return "ssl.com"
	case strings.Contains(issuer, "microsoft"):
		return "microsoft.com"
	case strings.Contains(issuer, "zerossl"):
		return "sectigo.com"
	default:
		return ""
	}
}
