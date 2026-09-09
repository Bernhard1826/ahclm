package models

import (
	"context"
	"errors"
	"strings"
)

// ClassifyScanFailure maps scanner errors to stable, analysis-friendly
// categories. It is kept in models so both the live scanner and persistence
// repair code use the same classification rules.
func ClassifyScanFailure(errs ...error) string {
	var text strings.Builder
	for _, err := range errs {
		if err == nil {
			continue
		}
		if errors.Is(err, context.Canceled) {
			return ScanFailureCanceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return ScanFailureNetwork
		}
		if text.Len() > 0 {
			text.WriteString("; ")
		}
		text.WriteString(strings.ToLower(err.Error()))
	}

	message := text.String()
	switch {
	case strings.Contains(message, "no such host"), strings.Contains(message, "nxdomain"):
		return ScanFailureDNS
	case strings.Contains(message, "eof"),
		strings.Contains(message, "no certificate"),
		strings.Contains(message, "no peer certificates"):
		return ScanFailureNoEndpoint
	case strings.Contains(message, "timeout"),
		strings.Contains(message, "connection reset"),
		strings.Contains(message, "connection refused"),
		strings.Contains(message, "network is unreachable"):
		return ScanFailureNetwork
	case strings.Contains(message, "tls handshake"),
		strings.Contains(message, "tls:"),
		strings.Contains(message, "unrecognized name"),
		strings.Contains(message, "protocol version"):
		return ScanFailureTLS
	default:
		return ScanFailureUnknown
	}
}
