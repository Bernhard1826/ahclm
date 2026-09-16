package scanner

import (
	"ahclm/internal/models"
	"crypto/x509"
	"time"
)

// Validation follows capture so invalid certificates remain measurable.
// Trust failures describe this machine's verifier, never universal trust.
func validateChain(domain, ip string, chain []*x509.Certificate, now time.Time) []models.TLSFinding {
	var findings []models.TLSFinding
	if len(chain) == 0 {
		return findings
	}
	leaf := chain[0]
	add := func(code, detail string) {
		findings = append(findings, models.TLSFinding{Code: code, Detail: detail, IPAddress: ip, Fingerprint: models.Fingerprint(leaf)})
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		add("hostname_mismatch", err.Error())
	}
	if now.Before(leaf.NotBefore) {
		add("not_yet_valid", "certificate NotBefore="+leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		add("expired_endpoint", "certificate NotAfter="+leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	// Hostname and leaf validity have separate findings; chain verification
	// additionally checks path constraints, EKU and the local system roots.
	if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil && !now.Before(leaf.NotBefore) && !now.After(leaf.NotAfter) {
		add("local_chain_validation_failed", err.Error())
	}
	return findings
}
