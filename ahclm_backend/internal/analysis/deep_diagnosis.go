// Package analysis holds experiments that explain a finding after the regular
// scan has recorded it. Nothing in this package runs from the scheduler.
// Targeted probes call the same scanner handshakes the survey already uses,
// so the SNI, empty-SNI and repeat-handshake behavior is not reimplemented.
package analysis

import (
	"context"
	"fmt"
	"time"

	"ahclm/internal/database"
	"ahclm/internal/models"
	"ahclm/internal/scanner"
)

// Experiment names the targeted checks an operator can run for one finding.
// Each one is a single, recorded comparison and is never folded back into the
// scheduled measurement population.
const (
	ExperimentSNISelection    = "sni_selection"
	ExperimentRepeatHandshake = "repeat_handshake"
	ExperimentHTTPRoute       = "http_route"
)

// Request is one deep-diagnosis run. Addresses, when set, restrict the probes
// to the endpoints the finding already named. An empty list uses the domain's
// current public addresses, capped by the scanner's endpoint sample size.
type Request struct {
	Domain     string
	Addresses  []string
	Experiment string
}

// Report is the auditable result of one deep-diagnosis run. It keeps the
// scanner's own probe records and states which causal question they answer.
// A report never claims to be a control-plane log.
type Report struct {
	Domain       string                  `json:"domain"`
	Experiment   string                  `json:"experiment"`
	StartedAt    time.Time               `json:"started_at"`
	Question     string                  `json:"question"`
	Limitation   string                  `json:"limitation"`
	Probes       []models.EndpointProbe  `json:"probes,omitempty"`
	HTTP         *models.HTTPFingerprint `json:"http,omitempty"`
	Observations []string                `json:"observations,omitempty"`
}

// Runner executes targeted experiments against an already constructed scanner.
type Runner struct {
	Scanner *scanner.Scanner
}

// Run performs one experiment. The context bounds the whole run; individual
// handshakes keep the scanner's own timeout.
func (r *Runner) Run(ctx context.Context, request Request) (*Report, error) {
	if r == nil || r.Scanner == nil {
		return nil, fmt.Errorf("deep diagnosis scanner is not configured")
	}
	domain := models.GetDomain(request.Domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	report := &Report{
		Domain:     domain,
		Experiment: request.Experiment,
		StartedAt:  time.Now().UTC(),
		Limitation: "These probes observe what one address returns. They do not read the CDN, controller or CA log, and they do not replace an imported internal-evidence event.",
	}
	addresses := request.Addresses
	switch request.Experiment {
	case ExperimentSNISelection:
		report.Question = "Does this address select a different certificate when the ClientHello carries the domain SNI than when SNI is omitted?"
		report.Probes = r.Scanner.ProbeEndpointsRotated(ctx, domain, addresses, 0)
		for _, probe := range report.Probes {
			if probe.SelectionAnalysis == nil {
				continue
			}
			report.Observations = append(report.Observations, fmt.Sprintf("%s: %s", probe.IPAddress, probe.SelectionAnalysis.Interpretation))
		}
	case ExperimentRepeatHandshake:
		report.Question = "Does repeating the handshake to the same address in one round return more than one leaf?"
		report.Probes = r.Scanner.ProbeEndpointsRotated(ctx, domain, addresses, 0)
		for _, probe := range report.Probes {
			if len(probe.OtherFingerprints) > 0 {
				report.Observations = append(report.Observations, fmt.Sprintf("%s returned %d distinct leaves in %d handshakes", probe.IPAddress, 1+len(probe.OtherFingerprints), probe.Handshakes))
				continue
			}
			report.Observations = append(report.Observations, fmt.Sprintf("%s returned one leaf across %d handshakes", probe.IPAddress, probe.Handshakes))
		}
	case ExperimentHTTPRoute:
		report.Question = "Does an HTTPS request with this Host header land on the same leaf the SNI handshake selected?"
		report.Probes = r.Scanner.ProbeEndpointsRotated(ctx, domain, addresses, 0)
		httpAddress := firstAddress(addresses)
		if httpAddress == "" && len(report.Probes) > 0 {
			httpAddress = report.Probes[0].IPAddress
		}
		fingerprint, err := r.Scanner.ProbeHTTP(ctx, domain, httpAddress)
		if err != nil {
			return nil, err
		}
		report.HTTP = fingerprint
		report.Observations = append(report.Observations, fmt.Sprintf("HTTP %d from %s served leaf %s", fingerprint.StatusCode, fingerprint.IPAddress, fingerprint.TLSFingerprint))
		for _, probe := range report.Probes {
			if probe.IPAddress != fingerprint.IPAddress || !probe.Success || probe.Fingerprint == "" {
				continue
			}
			if probe.Fingerprint == fingerprint.TLSFingerprint {
				report.Observations = append(report.Observations, fmt.Sprintf("HTTP and SNI handshake agree on %s at %s", fingerprint.TLSFingerprint, probe.IPAddress))
			} else {
				report.Observations = append(report.Observations, fmt.Sprintf("HTTP selected %s while the SNI handshake selected %s at %s", fingerprint.TLSFingerprint, probe.Fingerprint, probe.IPAddress))
			}
			break
		}
	default:
		return nil, fmt.Errorf("unknown experiment %q", request.Experiment)
	}
	return report, nil
}

func firstAddress(addresses []string) string {
	for _, address := range addresses {
		if address != "" {
			return address
		}
	}
	return ""
}

// Explain evaluates the internal event sequence without network I/O. It is
// useful for checking an exported batch's ordering, but it has no public
// observation context and therefore must not be read as endpoint correlation.
func Explain(findingType string, events []models.InternalEvidenceEvent) models.InternalEvidenceSummary {
	return database.SummarizeInternalEvidence(events, findingType)
}

// ExplainWithContext applies the stronger API gate to an exported batch. A
// sequence is complete only when its identifiers also occur in retained
// certificate, transition, or endpoint observations.
func ExplainWithContext(findingType string, events []models.InternalEvidenceEvent, certs []models.Certificate, observations []models.CertObservation, snapshots []models.MeasurementSnapshot) models.InternalEvidenceSummary {
	return database.SummarizeInternalEvidenceForContext(events, findingType, certs, observations, snapshots)
}
