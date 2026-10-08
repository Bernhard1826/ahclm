package scanner

import (
	"context"
	"crypto/x509"
	"time"

	"ahclm/internal/models"
)

// SetProbeHandshakeForTest installs the SNI-aware handshake used by the
// selection matrix. Deep-diagnosis tests use it to exercise the production
// probe path without opening a network connection.
func (s *Scanner) SetProbeHandshakeForTest(hook func(ctx context.Context, domain, address, serverName string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error)) {
	s.probeHandshakeWithSNI = hook
}

// NewProbeScannerForTest builds a scanner whose endpoint survey can run
// without dialling. Callers replace the handshake before probing.
func NewProbeScannerForTest(handshakes int) *Scanner {
	if handshakes <= 0 {
		handshakes = 1
	}
	limit := make(chan struct{}, 4)
	for index := 0; index < 4; index++ {
		limit <- struct{}{}
	}
	return &Scanner{
		config:    &models.ScannerConfig{Timeout: time.Second, MaxEndpointSamples: 8, EndpointHandshakes: handshakes, EndpointProbeConcurrency: 2},
		rateLimit: limit,
		ipv6Route: true,
	}
}
