package analysis

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"ahclm/internal/database"
	"ahclm/internal/models"
	"ahclm/internal/scanner"
)

func TestExplainStaysAbsentWithoutControlPlaneEvents(t *testing.T) {
	summary := Explain("deployment_failure", nil)
	if summary.Status != "absent" || summary.Determination != "external_only" {
		t.Fatalf("summary = %+v, want absent external-only determination", summary)
	}
	if len(summary.Missing) == 0 {
		t.Fatal("missing evidence was not named")
	}
}

func TestExplainConfirmsCorrelatedChurn(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	events := []models.InternalEvidenceEvent{
		{EventType: database.InternalEventRenewalPolicy, OccurredAt: base, CorrelationID: "renewal-1", SourceSystem: "controller", Status: "evaluated"},
		{EventType: database.InternalEventCertificateIssued, OccurredAt: base.Add(time.Minute), CorrelationID: "renewal-1", SourceSystem: "acme", Status: "succeeded"},
		{EventType: database.InternalEventDeployment, OccurredAt: base.Add(2 * time.Minute), CorrelationID: "renewal-1", SourceSystem: "edge", Status: "succeeded"},
	}
	summary := Explain("frequent_change", events)
	if summary.RootCauseCode != "scheduled_renewal_pipeline" || summary.Status != "complete" {
		t.Fatalf("summary = %+v, want the scheduled renewal sequence", summary)
	}
}

func TestSNIExperimentReusesScannerHandshake(t *testing.T) {
	withSNI := leaf(t, "yale.edu")
	without := leaf(t, "pantheonsite.io")
	sc := scanner.NewProbeScannerForTest(1)
	sc.SetProbeHandshakeForTest(func(_ context.Context, _, _ string, serverName string) ([]*x509.Certificate, []byte, *models.ConnectionInfo, error) {
		if serverName == "" {
			return []*x509.Certificate{without}, nil, &models.ConnectionInfo{}, nil
		}
		return []*x509.Certificate{withSNI}, nil, &models.ConnectionInfo{}, nil
	})
	report, err := (&Runner{Scanner: sc}).Run(context.Background(), Request{Domain: "yale.edu", Addresses: []string{"23.185.0.2"}, Experiment: ExperimentSNISelection})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Probes) != 1 || report.Probes[0].SelectionAnalysis == nil {
		t.Fatalf("probes = %+v, want one analyzed probe", report.Probes)
	}
	if report.Probes[0].SelectionAnalysis.Interpretation != "sni_selects_name_matching_certificate" {
		t.Fatalf("interpretation = %s", report.Probes[0].SelectionAnalysis.Interpretation)
	}
	if report.Limitation == "" {
		t.Fatal("report omitted its evidence limitation")
	}
}

func leaf(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
