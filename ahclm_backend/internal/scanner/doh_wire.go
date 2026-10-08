package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

var dohWireTypes = map[string]dnsmessage.Type{
	"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "CNAME": dnsmessage.TypeCNAME,
	"NS": dnsmessage.TypeNS, "CAA": dnsmessage.Type(257), "HTTPS": dnsmessage.Type(65),
}

// queryDoHWire performs an RFC 8484 GET (?dns=base64url) and converts the
// answer into the JSON payload shape used by the rest of the scanner. Only the
// record types the scanner reads as data (A, AAAA, CNAME, NS) are decoded;
// other types keep their type and TTL with empty data.
func (s *Scanner) queryDoHWire(ctx context.Context, resolver, domain, recordType string) (dohPayload, error) {
	qtype, ok := dohWireTypes[strings.ToUpper(recordType)]
	if !ok {
		return dohPayload{}, fmt.Errorf("unsupported DoH wire record type %q", recordType)
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(domain, ".") + ".")
	if err != nil {
		return dohPayload{}, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return dohPayload{}, err
	}
	endpoint, err := url.Parse(strings.TrimSpace(resolver))
	if err != nil {
		return dohPayload{}, err
	}
	endpoint.RawQuery = url.Values{"dns": {base64.RawURLEncoding.EncodeToString(packed)}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return dohPayload{}, err
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := (&http.Client{Timeout: s.config.Timeout}).Do(req)
	if err != nil {
		return dohPayload{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return dohPayload{}, fmt.Errorf("DoH resolver returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return dohPayload{}, err
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(body); err != nil {
		return dohPayload{}, err
	}
	payload := dohPayload{Status: int(reply.RCode), AD: reply.AuthenticData}
	if payload.Status != 0 && payload.Status != 3 {
		return dohPayload{}, fmt.Errorf("DNS status %d", payload.Status)
	}
	convert := func(resources []dnsmessage.Resource) []dohAnswer {
		out := make([]dohAnswer, 0, len(resources))
		for _, rr := range resources {
			answer := dohAnswer{Name: rr.Header.Name.String(), Type: int(rr.Header.Type), TTL: int(rr.Header.TTL)}
			switch body := rr.Body.(type) {
			case *dnsmessage.AResource:
				answer.Data = net.IP(body.A[:]).String()
			case *dnsmessage.AAAAResource:
				answer.Data = net.IP(body.AAAA[:]).String()
			case *dnsmessage.CNAMEResource:
				answer.Data = body.CNAME.String()
			case *dnsmessage.NSResource:
				answer.Data = body.NS.String()
			}
			out = append(out, answer)
		}
		return out
	}
	payload.Answer = convert(reply.Answers)
	payload.Authority = convert(reply.Authorities)
	return payload, nil
}
