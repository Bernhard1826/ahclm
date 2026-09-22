package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"ahclm/internal/models"
)

type directoryCacheEntry struct {
	expires time.Time
	ip      models.IPDirectoryRecord
	domain  models.RDAPNameRecord
}

var (
	directoryCache   = map[string]directoryCacheEntry{}
	directoryCacheMu sync.Mutex
)

const directoryCacheTTL = 6 * time.Hour

func directoryCacheGetIP(address string) (models.IPDirectoryRecord, bool) {
	directoryCacheMu.Lock()
	defer directoryCacheMu.Unlock()
	entry, ok := directoryCache["ip:"+address]
	if !ok || time.Now().After(entry.expires) {
		return models.IPDirectoryRecord{}, false
	}
	return entry.ip, true
}

func directoryCachePutIP(record models.IPDirectoryRecord) {
	if record.IPAddress == "" {
		return
	}
	directoryCacheMu.Lock()
	defer directoryCacheMu.Unlock()
	directoryCache["ip:"+record.IPAddress] = directoryCacheEntry{expires: time.Now().Add(directoryCacheTTL), ip: record}
}

func directoryCacheGetDomain(name string) (models.RDAPNameRecord, bool) {
	directoryCacheMu.Lock()
	defer directoryCacheMu.Unlock()
	entry, ok := directoryCache["domain:"+name]
	if !ok || time.Now().After(entry.expires) {
		return models.RDAPNameRecord{}, false
	}
	return entry.domain, true
}

func directoryCachePutDomain(name string, record models.RDAPNameRecord) {
	if name == "" {
		return
	}
	directoryCacheMu.Lock()
	defer directoryCacheMu.Unlock()
	directoryCache["domain:"+name] = directoryCacheEntry{expires: time.Now().Add(directoryCacheTTL), domain: record}
}

func (s *Scanner) fetchDirectory(ctx context.Context, domain string, addresses []string) (*models.DirectoryObservation, error) {
	observation := &models.DirectoryObservation{CollectedAt: time.Now().UTC(), Status: models.DirectoryUnavailable}
	var firstErr error
	if s.config.CheckRDAP {
		record, err := s.fetchDomainRDAP(ctx, domain)
		if err != nil {
			firstErr = err
		} else if record != nil {
			observation.Domain = record
		}
	}
	seen := make(map[string]struct{})
	limit := 8
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if !models.IsPublicIP(address) {
			continue
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		if len(observation.Endpoints) >= limit {
			break
		}
		record, err := s.lookupIPDirectory(ctx, address)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if record.IPAddress == "" {
			continue
		}
		finalizeIPDirectory(&record)
		record.Vendor = models.CDNVendorFromDirectory(record.ASN, record.ASNName, record.NetName, record.OrgName)
		observation.Endpoints = append(observation.Endpoints, record)
	}
	identified := 0
	for _, endpoint := range observation.Endpoints {
		if endpoint.SourceAgreement == models.DirectoryAgreementConflict {
			continue
		}
		if endpoint.ASN > 0 || endpoint.OrgName != "" || endpoint.NetName != "" {
			identified++
		}
	}
	switch {
	case identified > 0 && identified == len(observation.Endpoints) && len(observation.Endpoints) > 0:
		observation.Status = models.DirectoryIdentified
	case identified > 0 || observation.Domain != nil:
		observation.Status = models.DirectoryPartial
	default:
		observation.Status = models.DirectoryUnavailable
	}
	if observation.Domain == nil && len(observation.Endpoints) == 0 {
		if firstErr != nil {
			return observation, firstErr
		}
		return observation, fmt.Errorf("no RDAP or ASN record returned")
	}
	return observation, nil
}

func (s *Scanner) lookupIPDirectory(ctx context.Context, address string) (models.IPDirectoryRecord, error) {
	if cached, ok := directoryCacheGetIP(address); ok {
		return cached, nil
	}
	record := models.IPDirectoryRecord{IPAddress: address}
	var firstErr error
	if s.config.CheckASN {
		asn, err := s.fetchCymruASN(ctx, address)
		if err != nil {
			firstErr = err
		} else {
			mergeIPDirectory(&record, asn)
		}
	}
	if s.config.CheckRIPEstat && s.datasets != nil {
		ripe, err := s.datasets.fetchRIPEstat(ctx, address)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			mergeIPDirectory(&record, ripe)
		}
	}
	if s.config.CheckRDAP {
		rdap, err := s.fetchIPRDAP(ctx, address)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			mergeIPDirectory(&record, rdap)
		}
	}
	if record.ASN == 0 && record.OrgName == "" && record.NetName == "" && record.Prefix == "" {
		if firstErr != nil {
			return record, firstErr
		}
		return record, fmt.Errorf("no numbering-authority record for %s", address)
	}
	finalizeIPDirectory(&record)
	directoryCachePutIP(record)
	return record, nil
}

func mergeIPDirectory(dst *models.IPDirectoryRecord, src models.IPDirectoryRecord) {
	if dst == nil {
		return
	}
	if src.ASN > 0 {
		if dst.ASN > 0 && dst.ASN != src.ASN {
			dst.ConflictingASNs = uniqueInts(append(dst.ConflictingASNs, dst.ASN, src.ASN))
		} else if dst.ASN == 0 {
			dst.ASN = src.ASN
		}
		if src.Source != "" {
			dst.ASNSources = uniqueStrings(append(dst.ASNSources, src.Source))
		}
	}
	if src.ASNName != "" && dst.ASNName == "" {
		dst.ASNName = src.ASNName
	}
	if src.Prefix != "" && dst.Prefix == "" {
		dst.Prefix = src.Prefix
	}
	if src.Registry != "" && dst.Registry == "" {
		dst.Registry = src.Registry
	}
	if src.Country != "" && dst.Country == "" {
		dst.Country = src.Country
	}
	if src.NetName != "" && dst.NetName == "" {
		dst.NetName = src.NetName
	}
	if src.OrgName != "" && dst.OrgName == "" {
		dst.OrgName = src.OrgName
	}
	if src.Handle != "" && dst.Handle == "" {
		dst.Handle = src.Handle
	}
	if len(src.CIDRs) > 0 {
		dst.CIDRs = uniqueStrings(append(dst.CIDRs, src.CIDRs...))
	}
	if src.Source != "" {
		if dst.Source == "" {
			dst.Source = src.Source
		} else if !strings.Contains(dst.Source, src.Source) {
			dst.Source = dst.Source + "+" + src.Source
		}
	}
}

func finalizeIPDirectory(record *models.IPDirectoryRecord) {
	if record == nil {
		return
	}
	record.ASNSources = uniqueStrings(record.ASNSources)
	record.ConflictingASNs = uniqueInts(record.ConflictingASNs)
	switch {
	case len(record.ConflictingASNs) > 1:
		record.SourceAgreement = models.DirectoryAgreementConflict
	case len(record.ASNSources) >= 2 && record.ASN > 0:
		record.SourceAgreement = models.DirectoryAgreementAgreed
	case record.ASN > 0 || record.OrgName != "" || record.NetName != "":
		record.SourceAgreement = models.DirectoryAgreementSingle
	default:
		record.SourceAgreement = models.DirectoryAgreementNone
	}
}

func uniqueInts(values []int) []int {
	seen := make(map[int]struct{}, len(values))
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (s *Scanner) fetchCymruASN(ctx context.Context, address string) (models.IPDirectoryRecord, error) {
	query, err := cymruOriginName(address)
	if err != nil {
		return models.IPDirectoryRecord{}, err
	}
	answers, err := s.queryDoH(ctx, s.primaryResolver(), query, "TXT")
	if err != nil {
		return models.IPDirectoryRecord{}, err
	}
	record := models.IPDirectoryRecord{IPAddress: address, Source: "cymru"}
	for _, answer := range answers {
		if answer.Type != 16 {
			continue
		}
		fields := splitCymruTXT(answer.Data)
		if len(fields) < 4 {
			continue
		}
		asn, _ := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(fields[0]), "AS"))
		record.ASN = asn
		record.Prefix = strings.TrimSpace(fields[1])
		record.Country = strings.TrimSpace(fields[2])
		record.Registry = strings.ToLower(strings.TrimSpace(fields[3]))
		if len(fields) >= 6 {
			record.ASNName = strings.TrimSpace(fields[5])
		}
		break
	}
	if record.ASN == 0 {
		return record, fmt.Errorf("cymru returned no ASN for %s", address)
	}
	if record.ASNName == "" {
		if name, nameErr := s.fetchCymruASNName(ctx, record.ASN); nameErr == nil {
			record.ASNName = name
		}
	}
	return record, nil
}

func (s *Scanner) fetchCymruASNName(ctx context.Context, asn int) (string, error) {
	answers, err := s.queryDoH(ctx, s.primaryResolver(), fmt.Sprintf("AS%d.asn.cymru.com", asn), "TXT")
	if err != nil {
		return "", err
	}
	for _, answer := range answers {
		if answer.Type != 16 {
			continue
		}
		fields := splitCymruTXT(answer.Data)
		if len(fields) >= 5 {
			return strings.TrimSpace(fields[4]), nil
		}
	}
	return "", fmt.Errorf("cymru returned no AS name for AS%d", asn)
}

func (s *Scanner) fetchIPRDAP(ctx context.Context, address string) (models.IPDirectoryRecord, error) {
	payload, source, err := s.getRDAP(ctx, "/ip/"+url.PathEscape(address))
	if err != nil {
		return models.IPDirectoryRecord{}, err
	}
	record := models.IPDirectoryRecord{IPAddress: address, Source: source}
	record.Handle = strings.TrimSpace(asString(payload["handle"]))
	record.NetName = strings.TrimSpace(firstNonEmpty(asString(payload["name"]), asString(payload["handle"])))
	record.Country = strings.TrimSpace(asString(payload["country"]))
	record.OrgName = rdapEntityName(payload, "registrant", "administrative")
	if record.OrgName == "" {
		record.OrgName = strings.TrimSpace(asString(payload["name"]))
	}
	if start, end := asString(payload["startAddress"]), asString(payload["endAddress"]); start != "" && end != "" {
		record.Prefix = start + "-" + end
	}
	for _, cidr := range rdapCIDRs(payload) {
		record.CIDRs = append(record.CIDRs, cidr)
		if record.Prefix == "" {
			record.Prefix = cidr
		}
	}
	if asn := rdapASN(payload); asn > 0 {
		record.ASN = asn
	}
	return record, nil
}

func (s *Scanner) fetchDomainRDAP(ctx context.Context, domain string) (*models.RDAPNameRecord, error) {
	candidates := rdapDomainCandidates(domain)
	var firstErr error
	for _, candidate := range candidates {
		if cached, ok := directoryCacheGetDomain(candidate); ok {
			copied := cached
			return &copied, nil
		}
		payload, source, err := s.getRDAP(ctx, "/domain/"+url.PathEscape(candidate))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		record := parseDomainRDAP(payload, source)
		if record.LDHName == "" {
			record.LDHName = candidate
		}
		directoryCachePutDomain(candidate, record)
		copied := record
		return &copied, nil
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("RDAP returned no domain record")
	}
	return nil, firstErr
}

func parseDomainRDAP(payload map[string]any, source string) models.RDAPNameRecord {
	record := models.RDAPNameRecord{
		Handle:        strings.TrimSpace(asString(payload["handle"])),
		LDHName:       strings.TrimSpace(firstNonEmpty(asString(payload["ldhName"]), asString(payload["unicodeName"]))),
		Status:        asStringSlice(payload["status"]),
		Registrar:     rdapEntityName(payload, "registrar"),
		RegistrarIANA: rdapPublicID(payload, "IANA"),
		Registrant:    rdapEntityName(payload, "registrant"),
		Nameservers:   rdapNameservers(payload),
		Source:        source,
	}
	for _, event := range rdapEvents(payload) {
		switch event.Action {
		case "registration":
			record.RegisteredAt = event.When
		case "expiration":
			record.ExpiresAt = event.When
		case "last changed", "last update of rdap database":
			if record.UpdatedAt == nil {
				record.UpdatedAt = event.When
			}
		}
	}
	return record
}

type rdapEvent struct {
	Action string
	When   *time.Time
}

func (s *Scanner) getRDAP(ctx context.Context, path string) (map[string]any, string, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(s.config.RDAPEndpoint), "/")
	if endpoint == "" {
		endpoint = "https://rdap.org"
	}
	timeout := s.config.RDAPTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint+path, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", s.config.UserAgent)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32<<10))
		return nil, "", fmt.Errorf("RDAP %s returned HTTP %d", path, resp.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&payload); err != nil {
		return nil, "", err
	}
	source := endpoint
	if resp.Request != nil && resp.Request.URL != nil {
		source = resp.Request.URL.Scheme + "://" + resp.Request.URL.Host
	}
	return payload, source, nil
}

func (s *Scanner) primaryResolver() string {
	if len(s.config.DNSResolvers) > 0 {
		return s.config.DNSResolvers[0]
	}
	return "https://cloudflare-dns.com/dns-query"
}

func cymruOriginName(address string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", address)
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0]), nil
	}
	expanded := ip.To16()
	if expanded == nil {
		return "", fmt.Errorf("invalid IPv6 %q", address)
	}
	nibbles := make([]string, 0, 32)
	hexIP := hexString(expanded)
	for i := len(hexIP) - 1; i >= 0; i-- {
		nibbles = append(nibbles, string(hexIP[i]))
	}
	return strings.Join(nibbles, ".") + ".origin6.asn.cymru.com", nil
}

func hexString(value []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0f]
	}
	return string(out)
}

func splitCymruTXT(value string) []string {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	parts := strings.Split(value, "|")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.TrimSpace(part))
	}
	return out
}

func rdapDomainCandidates(domain string) []string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return nil
	}
	out := []string{domain}
	labels := strings.Split(domain, ".")
	if len(labels) > 2 {
		out = append(out, strings.Join(labels[1:], "."))
	}
	return uniqueStrings(out)
}

func rdapNameservers(payload map[string]any) []string {
	raw, _ := payload["nameservers"].([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		object, _ := item.(map[string]any)
		if object == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(firstNonEmpty(asString(object["ldhName"]), asString(object["unicodeName"])), "."))
		if name != "" {
			out = append(out, name)
		}
	}
	return uniqueStrings(out)
}

func rdapEvents(payload map[string]any) []rdapEvent {
	raw, _ := payload["events"].([]any)
	out := make([]rdapEvent, 0, len(raw))
	for _, item := range raw {
		object, _ := item.(map[string]any)
		if object == nil {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(asString(object["eventAction"])))
		whenRaw := strings.TrimSpace(asString(object["eventDate"]))
		if action == "" || whenRaw == "" {
			continue
		}
		event := rdapEvent{Action: action}
		if parsed, err := time.Parse(time.RFC3339, whenRaw); err == nil {
			value := parsed.UTC()
			event.When = &value
		}
		out = append(out, event)
	}
	return out
}

func rdapEntityName(payload map[string]any, roles ...string) string {
	raw, _ := payload["entities"].([]any)
	wanted := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		wanted[strings.ToLower(role)] = struct{}{}
	}
	fallback := ""
	for _, item := range raw {
		object, _ := item.(map[string]any)
		if object == nil {
			continue
		}
		name := vcardFN(object)
		if name == "" {
			name = strings.TrimSpace(asString(object["handle"]))
		}
		if name == "" {
			continue
		}
		if fallback == "" {
			fallback = name
		}
		for _, role := range asStringSlice(object["roles"]) {
			if _, ok := wanted[strings.ToLower(role)]; ok {
				return name
			}
		}
	}
	if len(roles) == 0 {
		return fallback
	}
	return ""
}

func rdapPublicID(payload map[string]any, kind string) string {
	raw, _ := payload["entities"].([]any)
	kind = strings.ToLower(kind)
	for _, item := range raw {
		object, _ := item.(map[string]any)
		if object == nil {
			continue
		}
		ids, _ := object["publicIds"].([]any)
		for _, id := range ids {
			entry, _ := id.(map[string]any)
			if entry == nil {
				continue
			}
			if strings.EqualFold(asString(entry["type"]), kind) {
				return strings.TrimSpace(asString(entry["identifier"]))
			}
		}
	}
	return ""
}

func rdapCIDRs(payload map[string]any) []string {
	raw, _ := payload["cidr0_cidrs"].([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		object, _ := item.(map[string]any)
		if object == nil {
			continue
		}
		prefix := strings.TrimSpace(asString(object["v4prefix"]))
		length := asString(object["length"])
		if prefix == "" {
			prefix = strings.TrimSpace(asString(object["v6prefix"]))
		}
		if prefix == "" {
			continue
		}
		if length != "" {
			out = append(out, prefix+"/"+length)
		} else {
			out = append(out, prefix)
		}
	}
	return out
}

func rdapASN(payload map[string]any) int {
	if raw, ok := payload["arin_originas0_originautnums"].([]any); ok {
		for _, item := range raw {
			switch value := item.(type) {
			case float64:
				return int(value)
			case json.Number:
				n, _ := value.Int64()
				return int(n)
			case string:
				n, _ := strconv.Atoi(strings.TrimPrefix(value, "AS"))
				if n > 0 {
					return n
				}
			}
		}
	}
	return 0
}

func vcardFN(entity map[string]any) string {
	vcard, _ := entity["vcardArray"].([]any)
	if len(vcard) < 2 {
		return ""
	}
	fields, _ := vcard[1].([]any)
	for _, field := range fields {
		row, _ := field.([]any)
		if len(row) < 4 {
			continue
		}
		if !strings.EqualFold(asString(row[0]), "fn") {
			continue
		}
		return strings.TrimSpace(asString(row[3]))
	}
	return ""
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func asStringSlice(value any) []string {
	raw, _ := value.([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		text := strings.TrimSpace(asString(item))
		if text != "" {
			out = append(out, text)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
