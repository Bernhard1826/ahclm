package models

import (
	"context"
	"errors"
	"testing"
)

func TestClassifyScanFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "dns", err: errors.New("lookup missing.example: no such host"), want: ScanFailureDNS},
		{name: "endpoint", err: errors.New("TLS handshake failed: EOF"), want: ScanFailureNoEndpoint},
		{name: "network", err: errors.New("dial tcp: i/o timeout"), want: ScanFailureNetwork},
		{name: "tls", err: errors.New("TLS handshake failed: tls: internal error"), want: ScanFailureTLS},
		{name: "canceled", err: context.Canceled, want: ScanFailureCanceled},
		{name: "unknown", err: errors.New("unexpected scanner failure"), want: ScanFailureUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyScanFailure(tt.err); got != tt.want {
				t.Fatalf("class = %q, want %q", got, tt.want)
			}
		})
	}
}
