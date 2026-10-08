package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"ahclm/internal/models"

	"golang.org/x/net/dns/dnsmessage"
)

// enrichAuthoritativeTopology asks the nameservers discovered by independent
// recursive resolvers directly, with recursion disabled. A differing answer
// means the public recursive response cannot be attributed solely to the
// published zone; it may be CDN steering, a resolver view, or an unresolved
// delegation issue. It intentionally does not claim which one.
func (s *Scanner) enrichAuthoritativeTopology(ctx context.Context, domain string, topology *models.TopologySnapshot) {
	if s == nil || topology == nil || len(topology.NSHosts) == 0 {
		return
	}
	nameservers := append([]string(nil), topology.NSHosts...)
	if len(nameservers) > 6 {
		nameservers = nameservers[:6]
	}
	probeCtx, cancel := context.WithTimeout(ctx, minAuthoritativeBudget(s.config.Timeout))
	defer cancel()
	results := make(chan models.AuthoritativeDNSObservation, len(nameservers)*2)
	var wg sync.WaitGroup
	for _, nameserver := range nameservers {
		for _, address := range s.resolveNameserverAddresses(probeCtx, nameserver) {
			wg.Add(1)
			go func(ns, address string) {
				defer wg.Done()
				results <- s.queryAuthoritativeTopology(probeCtx, ns, address, domain)
			}(nameserver, address)
		}
	}
	wg.Wait()
	close(results)
	for result := range results {
		topology.Authoritative = append(topology.Authoritative, result)
		if !result.Success {
			continue
		}
		for _, address := range append(append([]string{}, result.A...), result.AAAA...) {
			if !containsString(topology.AuthoritativeIPs, address) {
				topology.AuthoritativeIPs = append(topology.AuthoritativeIPs, address)
			}
		}
		for _, cname := range result.CNAME {
			if !containsString(topology.AuthoritativeCNAME, cname) {
				topology.AuthoritativeCNAME = append(topology.AuthoritativeCNAME, cname)
			}
		}
	}
	sort.Slice(topology.Authoritative, func(left, right int) bool {
		if topology.Authoritative[left].Nameserver != topology.Authoritative[right].Nameserver {
			return topology.Authoritative[left].Nameserver < topology.Authoritative[right].Nameserver
		}
		return topology.Authoritative[left].Address < topology.Authoritative[right].Address
	})
	sort.Strings(topology.AuthoritativeIPs)
	sort.Strings(topology.AuthoritativeCNAME)
	successful := make([]models.AuthoritativeDNSObservation, 0, len(topology.Authoritative))
	transportUnavailable := false
	for _, observation := range topology.Authoritative {
		if observation.Success {
			successful = append(successful, observation)
		}
		if strings.Contains(observation.Error, "non-public address") || strings.Contains(observation.Error, "network path") {
			transportUnavailable = true
		}
	}
	if len(successful) == 0 {
		if transportUnavailable {
			topology.AuthoritativeComparison = "transport_unavailable"
		} else {
			topology.AuthoritativeComparison = "unavailable"
		}
		return
	}
	authoritySets := make([][]string, 0, len(successful))
	for _, observation := range successful {
		authoritySets = append(authoritySets, authoritativeRRSet(observation))
	}
	authorityConsistent := true
	for index := 1; index < len(authoritySets); index++ {
		if !sameStringSet(authoritySets[0], authoritySets[index]) {
			authorityConsistent = false
			break
		}
	}
	if sameStringSet(topology.AuthoritativeIPs, topology.PublicIPs) && sameStringSet(topology.AuthoritativeCNAME, topology.CNAMEChain) {
		topology.AuthoritativeComparison = "matches_recursive"
		return
	}
	// A recursive resolver normally follows a published CNAME and returns the
	// target address, while a direct authoritative query returns only the
	// CNAME. Treat that as an expected expansion, not a DNS disagreement.
	if len(topology.AuthoritativeIPs) == 0 && len(topology.AuthoritativeCNAME) > 0 &&
		sameStringSet(topology.AuthoritativeCNAME, topology.CNAMEChain) && len(topology.PublicIPs) > 0 {
		topology.AuthoritativeComparison = "cname_expanded"
		return
	}
	if authorityConsistent {
		topology.AuthoritativeComparison = "authoritative_consistent_recursive_diff"
		return
	}
	topology.AuthoritativeComparison = "authoritative_inconsistent"
}

func minAuthoritativeBudget(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > 12*time.Second {
		return 12 * time.Second
	}
	return timeout
}

func (s *Scanner) resolveNameserverAddresses(ctx context.Context, nameserver string) []string {
	v4 := make([]string, 0, 4)
	v6 := make([]string, 0, 4)
	resolvers := append([]string(nil), s.config.DNSResolvers...)
	if len(resolvers) == 0 {
		resolvers = []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"}
	}
	for _, resolver := range resolvers {
		for _, recordType := range []string{"A", "AAAA"} {
			payload, err := s.queryDoHPayload(ctx, resolver, nameserver, recordType)
			if err != nil {
				continue
			}
			for _, answer := range payload.Answer {
				if answer.Type != 1 && answer.Type != 28 {
					continue
				}
				ip := net.ParseIP(strings.TrimSpace(answer.Data))
				if ip == nil || !models.IsPublicIP(ip.String()) {
					continue
				}
				if ip.To4() != nil {
					if !containsString(v4, ip.String()) {
						v4 = append(v4, ip.String())
					}
				} else if !containsString(v6, ip.String()) {
					v6 = append(v6, ip.String())
				}
			}
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	values := v4
	// Prefer IPv4 because many measurement hosts have no IPv6 route. IPv6 is
	// still used when a nameserver publishes no IPv4 address.
	if len(values) == 0 {
		values = v6
	}
	if len(values) > 2 {
		values = values[:2]
	}
	return values
}

func (s *Scanner) queryAuthoritativeTopology(ctx context.Context, nameserver, address, domain string) models.AuthoritativeDNSObservation {
	result := models.AuthoritativeDNSObservation{Nameserver: nameserver, Address: address, Transport: "udp"}
	hadUsableAnswer := false
	for _, recordType := range []string{"A", "AAAA", "CNAME", "HTTPS"} {
		answers, transport, err := queryAuthoritativeDNSWithTransport(ctx, address, domain, recordType)
		if err != nil {
			result.Error = appendRelatedProbeError(result.Error, recordType+": "+err.Error())
			continue
		}
		result.Transport = mergeAuthoritativeTransport(result.Transport, transport)
		// Some restricted networks transparently answer every direct UDP/53
		// query with a synthetic benchmark address. Retry that query over TCP
		// before recording it as an authoritative publication.
		if transport == "udp" && containsNonPublicAddress(answers) {
			if tcpAnswers, tcpTransport, tcpErr := queryAuthoritativeDNSVia(ctx, address, domain, recordType, "tcp"); tcpErr == nil {
				answers = tcpAnswers
				result.Transport = mergeAuthoritativeTransport(result.Transport, tcpTransport)
			} else {
				result.Error = appendRelatedProbeError(result.Error, recordType+": network path returned non-public address; TCP fallback: "+tcpErr.Error())
			}
		}
		for _, answer := range answers {
			switch answer.Type {
			case 1:
				if models.IsPublicIP(answer.Data) && !containsString(result.A, answer.Data) {
					result.A = append(result.A, answer.Data)
					hadUsableAnswer = true
				} else if strings.TrimSpace(answer.Data) != "" {
					result.Error = appendRelatedProbeError(result.Error, "A: non-public address "+strings.TrimSpace(answer.Data))
				}
			case 28:
				if models.IsPublicIP(answer.Data) && !containsString(result.AAAA, answer.Data) {
					result.AAAA = append(result.AAAA, answer.Data)
					hadUsableAnswer = true
				} else if strings.TrimSpace(answer.Data) != "" {
					result.Error = appendRelatedProbeError(result.Error, "AAAA: non-public address "+strings.TrimSpace(answer.Data))
				}
			case 5:
				name := strings.TrimSuffix(strings.ToLower(answer.Data), ".")
				if name != "" && !containsString(result.CNAME, name) {
					result.CNAME = append(result.CNAME, name)
					hadUsableAnswer = true
				}
			case 65:
				for _, target := range models.ParseHTTPSTargets(answer.Data) {
					if !containsString(result.HTTPS, target) {
						result.HTTPS = append(result.HTTPS, target)
					}
				}
			}
		}
	}
	sort.Strings(result.A)
	sort.Strings(result.AAAA)
	sort.Strings(result.CNAME)
	sort.Strings(result.HTTPS)
	result.Success = hadUsableAnswer
	if !result.Success && result.Error == "" {
		result.Error = "authoritative response contained no usable answer"
	}
	return result
}

func queryAuthoritativeDNSWithTransport(ctx context.Context, address, domain, recordType string) ([]dohAnswer, string, error) {
	return queryAuthoritativeDNSVia(ctx, address, domain, recordType, "udp")
}

func queryAuthoritativeDNSVia(ctx context.Context, address, domain, recordType, network string) ([]dohAnswer, string, error) {
	qtype, ok := dohWireTypes[recordType]
	if !ok {
		return nil, network, fmt.Errorf("unsupported record type %q", recordType)
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(domain, ".") + ".")
	if err != nil {
		return nil, network, err
	}
	message := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: false}, Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}}}
	packed, err := message.Pack()
	if err != nil {
		return nil, network, err
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(address, "53"))
	if err != nil {
		return nil, network, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if network == "tcp" {
		if len(packed) > 65535 {
			return nil, network, fmt.Errorf("DNS query is too large")
		}
		frame := make([]byte, 2+len(packed))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(packed)))
		copy(frame[2:], packed)
		if _, err := conn.Write(frame); err != nil {
			return nil, network, err
		}
	} else if _, err := conn.Write(packed); err != nil {
		return nil, network, err
	}
	buffer := make([]byte, 65535)
	var n int
	if network == "tcp" {
		length := make([]byte, 2)
		if _, err := io.ReadFull(conn, length); err != nil {
			return nil, network, err
		}
		frameLength := int(binary.BigEndian.Uint16(length))
		if frameLength <= 0 || frameLength > len(buffer) {
			return nil, network, fmt.Errorf("invalid DNS TCP frame length %d", frameLength)
		}
		if _, err := io.ReadFull(conn, buffer[:frameLength]); err != nil {
			return nil, network, err
		}
		n = frameLength
	} else {
		n, err = conn.Read(buffer)
		if err != nil {
			return nil, network, err
		}
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(buffer[:n]); err != nil {
		return nil, network, err
	}
	if reply.RCode != dnsmessage.RCodeSuccess && reply.RCode != dnsmessage.RCodeNameError {
		return nil, network, fmt.Errorf("DNS status %d", reply.RCode)
	}
	if network == "udp" && reply.Truncated {
		return queryAuthoritativeDNSVia(ctx, address, domain, recordType, "tcp")
	}
	return decodeDNSResources(reply.Answers), network, nil
}

func decodeDNSResources(resources []dnsmessage.Resource) []dohAnswer {
	out := make([]dohAnswer, 0, len(resources))
	for _, resource := range resources {
		answer := dohAnswer{Name: resource.Header.Name.String(), Type: int(resource.Header.Type), TTL: int(resource.Header.TTL)}
		switch value := resource.Body.(type) {
		case *dnsmessage.AResource:
			answer.Data = net.IP(value.A[:]).String()
		case *dnsmessage.AAAAResource:
			answer.Data = net.IP(value.AAAA[:]).String()
		case *dnsmessage.CNAMEResource:
			answer.Data = value.CNAME.String()
		default:
			// Do not let an unknown RR with no decoded payload count as an
			// authoritative answer.
			continue
		}
		out = append(out, answer)
	}
	return out
}

func containsNonPublicAddress(answers []dohAnswer) bool {
	for _, answer := range answers {
		if (answer.Type == 1 || answer.Type == 28) && strings.TrimSpace(answer.Data) != "" && !models.IsPublicIP(answer.Data) {
			return true
		}
	}
	return false
}

func mergeAuthoritativeTransport(current, next string) string {
	if current == "" {
		return next
	}
	if next == "" || current == next {
		return current
	}
	return "mixed"
}

func authoritativeRRSet(observation models.AuthoritativeDNSObservation) []string {
	values := make([]string, 0, len(observation.A)+len(observation.AAAA)+len(observation.CNAME))
	for _, value := range observation.A {
		values = append(values, "A:"+value)
	}
	for _, value := range observation.AAAA {
		values = append(values, "AAAA:"+value)
	}
	for _, value := range observation.CNAME {
		values = append(values, "CNAME:"+value)
	}
	sort.Strings(values)
	return values
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index, value := range left {
		if value != right[index] {
			return false
		}
	}
	return true
}
