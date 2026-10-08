package database

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestCertificateExhibitCarriesFullInventory(t *testing.T) {
	now := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	chain, _ := json.Marshal([]models.ChainEntry{
		{CommonName: "sectigo.com", IssuerCN: "Sectigo Public Server Authentication CA OV R36", NotAfter: now.Add(90 * 24 * time.Hour), IsCA: false},
		{CommonName: "Sectigo Public Server Authentication CA OV R36", IssuerCN: "AAA Certificate Services", NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true},
	})
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	item := models.Anomaly{Domain: "sectigo.com", Type: "same_key"}
	context := diagnosisContext{
		state: &models.DomainCertificate{Domain: "sectigo.com", CurrentFingerprint: "leaf-new", LastEndpointIP: "192.0.2.1"},
		observations: []models.CertObservation{{
			ObservationType: models.ObsSameKey, ObservedAt: now,
			Fingerprint: "leaf-new", PreviousFingerprint: "leaf-old",
			SPKIFingerprint: "spki-same", PreviousSPKIFingerprint: "spki-same",
			IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1",
			ChangeClass: models.ChangeClassReplacement,
		}},
		certificates: map[string]models.Certificate{
			"leaf-new": {
				Fingerprint: "leaf-new", SPKIFingerprint: "spki-same", SerialNumber: "0B066FAD",
				Issuer:   "CN=Sectigo Public Server Authentication CA OV R36,O=Sectigo Limited",
				IssuerCN: "Sectigo Public Server Authentication CA OV R36",
				Subject:  "CN=sectigo.com,O=Sectigo Limited", CommonName: "sectigo.com",
				NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
				SignatureAlgo: "SHA256-RSA", KeyAlgorithm: "RSA", KeySize: 4096, PublicKeyType: "RSA",
				SANs: `["sectigo.com","comodoca.com"]`, ValidityDays: 90, Chain: string(chain),
				RawCert: base64.StdEncoding.EncodeToString(der),
			},
			"leaf-old": {
				Fingerprint: "leaf-old", SPKIFingerprint: "spki-same", SerialNumber: "OLD",
				IssuerCN: "Sectigo Public Server Authentication CA OV R36", CommonName: "sectigo.com",
				NotBefore: now.Add(-30 * 24 * time.Hour), NotAfter: now.Add(60 * 24 * time.Hour),
				KeyAlgorithm: "RSA", KeySize: 4096, ValidityDays: 90,
			},
		},
	}
	diagnosis := inferSameKeyDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	var current *models.CertificateExhibit
	for i := range investigation.Certificates {
		if investigation.Certificates[i].Fingerprint == "leaf-new" {
			current = &investigation.Certificates[i]
			break
		}
	}
	if current == nil {
		t.Fatalf("current leaf missing: %#v", investigation.Certificates)
	}
	if current.Subject == "" || current.Issuer == "" || current.SerialNumber != "0B066FAD" {
		t.Fatalf("subject/issuer/serial not filled: %#v", current)
	}
	if len(current.SANs) != 2 || current.KeySize != 4096 || current.SignatureAlgorithm == "" {
		t.Fatalf("SAN/key/signature incomplete: %#v", current)
	}
	if len(current.Chain) != 2 {
		t.Fatalf("chain = %#v", current.Chain)
	}
	if !strings.Contains(current.PEM, "BEGIN CERTIFICATE") {
		t.Fatalf("PEM missing: %q", current.PEM)
	}
}

func TestInvestigationClassifiesMultiCDNAsExpected(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	endpointMap := mapJSON(map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"})
	snapshots := []models.MeasurementSnapshot{
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
		{FingerprintCount: 2, ResolverAgreement: 0.5, EndpointFingerprintsJSON: endpointMap},
	}
	item := models.Anomaly{Domain: "cdn.example", Type: models.ObsDeploymentFailure}
	diagnosis := inferTopologyDiagnosis(item, diagnosisContext{snapshots: snapshots})
	investigation := buildInvestigation(item, diagnosisContext{snapshots: snapshots}, diagnosis)
	if investigation.FindingClass != models.FindingExpected {
		t.Fatalf("finding class = %q, want expected for a clean multi-provider split", investigation.FindingClass)
	}
	if investigation.WhyProblem == "" || !containsFold(investigation.WhyProblem, "not counted as a problem") {
		t.Fatalf("expected multi-CDN case did not withdraw the problem claim: %#v", investigation)
	}
	if len(investigation.ProviderGroups) != 2 {
		t.Fatalf("provider groups = %d, want 2: %#v", len(investigation.ProviderGroups), investigation.ProviderGroups)
	}
	for _, group := range investigation.ProviderGroups {
		if group.Conflict {
			t.Fatalf("clean partition reported an intra-network conflict: %#v", group)
		}
	}
}

func TestInvestigationFlagsIntraFleetAsIncident(t *testing.T) {
	probes := []models.EndpointProbe{
		{IPAddress: "165.189.150.147", Success: true, Fingerprint: "a", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "names"},
		{IPAddress: "165.189.241.136", Success: true, Fingerprint: "b", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "names"},
	}
	encoded, _ := json.Marshal(probes)
	// Earlier rounds saw the same two leaves on other addresses of the same
	// /16: the network serves two leaves, but no address kept its own, so
	// this is not an independent certificate per endpoint.
	assignment, _ := json.Marshal(map[string]string{"165.189.150.148": "a", "165.189.241.137": "b"})
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	item := models.Anomaly{Domain: "split.example", Type: models.ObsDeploymentFailure}
	context := diagnosisContext{
		observations: []models.CertObservation{{
			ObservationType: models.ObsDeploymentFailure, ObservedAt: now, EndpointProbes: string(encoded),
		}},
		snapshots: []models.MeasurementSnapshot{
			{ObservedAt: now.Add(-24 * time.Hour), FingerprintCount: 2, EndpointFingerprintsJSON: string(assignment)},
			{ObservedAt: now.Add(-48 * time.Hour), FingerprintCount: 2, EndpointFingerprintsJSON: string(assignment)},
		},
	}
	diagnosis := inferTopologyDiagnosis(item, context)
	if diagnosis.PrimaryCode != models.DivergenceIntraFleet && diagnosis.PrimaryCode != models.DivergencePropagating {
		t.Fatalf("primary = %q, want an intra-network incident rather than multi-CDN", diagnosis.PrimaryCode)
	}
	investigation := buildInvestigation(item, context, diagnosis)
	if investigation.FindingClass != models.FindingIncident {
		t.Fatalf("finding class = %q, want incident for intra-network disagreement", investigation.FindingClass)
	}
	if !containsFold(investigation.WhyProblem, "does not explain") && !containsFold(investigation.WhyProblem, "more than one") {
		t.Fatalf("incident write-up did not say why multi-CDN is ruled out: %#v", investigation)
	}
	if len(investigation.ProviderGroups) != 1 || !investigation.ProviderGroups[0].Conflict {
		t.Fatalf("intra-network conflict was not exhibited: %#v", investigation.ProviderGroups)
	}
}

func TestInvestigationShowsSamplingArtifactForFrequentChange(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changes := make([]models.CertObservation, 0, 20)
	for index := 0; index < 20; index++ {
		previous, current := "leaf-a", "leaf-b"
		address := "192.0.2.2"
		if index%2 == 1 {
			previous, current = "leaf-b", "leaf-a"
			address = "192.0.2.1"
		}
		changes = append(changes, changeRow(t0.Add(time.Duration(index*6)*time.Hour), previous, current, "spki-"+previous, "spki-"+current, address))
	}
	item := models.Anomaly{Domain: "pool.example", Type: "frequent_change", OccurrenceCount: 20}
	context := diagnosisContext{observations: changes}
	diagnosis := inferChurnDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if investigation.FindingClass != models.FindingExpected {
		t.Fatalf("finding class = %q, want expected for a concurrently deployed pool", investigation.FindingClass)
	}
	if !containsFold(investigation.WhyProblem, "not counted as frequent change") {
		t.Fatalf("sampling artifact was still presented as frequent change: %#v", investigation)
	}
	if len(investigation.ChangeSequence) == 0 {
		t.Fatal("change sequence exhibit was empty")
	}
	same, different := 0, 0
	for _, change := range investigation.ChangeSequence {
		switch change.Relation {
		case "same_endpoint":
			same++
		case "different_endpoint":
			different++
		}
	}
	if different == 0 {
		t.Fatalf("alternating pool did not exhibit different-endpoint comparisons: %#v", investigation.ChangeSequence)
	}
	if same > different {
		t.Fatalf("alternating pool was exhibited as same-endpoint replacement: same=%d different=%d", same, different)
	}
}

func TestInvestigationNamesPreissuedPipelineFromIssuanceRemaining(t *testing.T) {
	t0 := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	issued := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	changes := make([]models.CertObservation, 0, 8)
	certs := make(map[string]models.Certificate)
	for i := 0; i < 8; i++ {
		oldFP := "leaf-" + string(rune('a'+i))
		newFP := "leaf-" + string(rune('b'+i))
		notBefore := issued.Add(time.Duration(i) * 24 * time.Hour)
		notAfter := notBefore.Add(90 * 24 * time.Hour)
		changes = append(changes, models.CertObservation{
			ObservationType: models.ObsChange, ObservedAt: t0.Add(time.Duration(i) * 24 * time.Hour),
			Fingerprint: newFP, PreviousFingerprint: oldFP, DaysUntilExpiry: 7, IPAddress: "192.0.2.1",
		})
		certs[oldFP] = models.Certificate{Fingerprint: oldFP, Issuer: "CN=DigiCert", IssuerCN: "DigiCert", CommonName: "*.example", ValidityDays: 90, NotBefore: notBefore.Add(-24 * time.Hour), NotAfter: notAfter.Add(-24 * time.Hour)}
		certs[newFP] = models.Certificate{Fingerprint: newFP, Issuer: "CN=DigiCert", IssuerCN: "DigiCert", CommonName: "*.example", ValidityDays: 90, NotBefore: notBefore, NotAfter: notAfter}
	}
	item := models.Anomaly{Domain: "fb.example", Type: "frequent_change", OccurrenceCount: 8}
	context := diagnosisContext{observations: changes, certificates: certs}
	diagnosis := inferChurnDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if investigation.CauseCode != "preissued_rolling_pipeline" {
		t.Fatalf("cause = %q, want pre-issued rolling pipeline: %#v", investigation.CauseCode, investigation)
	}
	if containsFold(investigation.Cause, "public-key") || containsFold(investigation.Cause, "key rotation") {
		t.Fatalf("cause still treats a different public key as the mechanism: %#v", investigation)
	}
	joined := strings.Join(append(append([]string{}, investigation.Facts...), investigation.WhyThisCause...), " ")
	if !containsFold(joined, "day(s) left") && !containsFold(joined, "remain") {
		t.Fatalf("pipeline case file omitted remaining life: %#v", investigation)
	}
	if !containsFold(joined, "issued") && !containsFold(joined, "minted") && !containsFold(joined, "inventory") {
		t.Fatalf("pipeline case file omitted the operational inventory explanation: %#v", investigation)
	}
	for _, ruled := range investigation.RuledOut {
		if containsFold(ruled.Label, "key") && containsFold(ruled.Label, "rotation") {
			t.Fatalf("public-key rotation is still listed as a hypothesis: %#v", investigation.RuledOut)
		}
	}
}

func TestCertificateExhibitsFillMissingLeafFromProbe(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	notBeforeA := now.Add(-30 * 24 * time.Hour)
	notAfterA := now.Add(60 * 24 * time.Hour)
	notBeforeB := now.Add(-10 * 24 * time.Hour)
	notAfterB := now.Add(80 * 24 * time.Hour)
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "leaf-a", IssuerCN: "Let's Encrypt", CommonName: "split.example", KeyAlgorithm: "RSA", SPKIFingerprint: "spki-a", SerialNumber: "aa", SANs: []string{"split.example"}, NotBefore: &notBeforeA, NotAfter: &notAfterA},
		{IPAddress: "192.0.2.2", Success: true, Fingerprint: "leaf-b", IssuerCN: "DigiCert", CommonName: "split.example", KeyAlgorithm: "ECDSA", SPKIFingerprint: "spki-b", SerialNumber: "bb", SANs: []string{"split.example", "www.split.example"}, NotBefore: &notBeforeB, NotAfter: &notAfterB},
	}
	encoded, _ := json.Marshal(probes)
	item := models.Anomaly{Domain: "split.example", Type: models.ObsDeploymentFailure}
	context := diagnosisContext{
		observations: []models.CertObservation{{
			ObservationType: models.ObsDeploymentFailure, ObservedAt: now, EndpointProbes: string(encoded),
		}},
		certificates: map[string]models.Certificate{
			"leaf-a": {Fingerprint: "leaf-a", IssuerCN: "Let's Encrypt", CommonName: "split.example", KeyAlgorithm: "RSA", SPKIFingerprint: "spki-a", SerialNumber: "aa", SANs: `["split.example"]`, ValidityDays: 90, NotBefore: notBeforeA, NotAfter: notAfterA},
		},
	}
	investigation := buildInvestigation(item, context, inferTopologyDiagnosis(item, context))
	got := map[string]models.CertificateExhibit{}
	for _, certificate := range investigation.Certificates {
		got[certificate.Fingerprint] = certificate
	}
	missing, ok := got["leaf-b"]
	if !ok {
		t.Fatalf("probe-only leaf was omitted from the certificate exhibit: %#v", investigation.Certificates)
	}
	if missing.IssuerCN != "DigiCert" || missing.KeyAlgorithm != "ECDSA" || missing.SPKIFingerprint != "spki-b" || missing.CommonName != "split.example" {
		t.Fatalf("probe-only leaf was not filled from the endpoint survey: %#v", missing)
	}
	if missing.SerialNumber != "bb" || strings.Join(missing.SANs, ",") != "split.example,www.split.example" {
		t.Fatalf("probe-only leaf serial/SAN was not copied: %#v", missing)
	}
	if missing.ValidityDays <= 0 || missing.NotBefore == nil || missing.NotAfter == nil {
		t.Fatalf("probe-only leaf validity was not copied: %#v", missing)
	}
}

func TestChangeExhibitsCarryCertificateDeltas(t *testing.T) {
	at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	changes := []models.CertObservation{{
		ObservationType:         models.ObsChange,
		ObservedAt:              at,
		PreviousFingerprint:     "old",
		Fingerprint:             "new",
		PreviousIPAddress:       "192.0.2.10",
		IPAddress:               "192.0.2.10",
		PreviousSPKIFingerprint: "old-key",
		SPKIFingerprint:         "new-key",
	}}
	context := diagnosisContext{
		observations: changes,
		certificates: map[string]models.Certificate{
			"old": {Fingerprint: "old", IssuerCN: "Issuer A", CommonName: "old.example", KeyAlgorithm: "ECDSA", SANs: `["example.com","old.example"]`, SPKIFingerprint: "old-key"},
			"new": {Fingerprint: "new", IssuerCN: "Issuer B", CommonName: "new.example", KeyAlgorithm: "RSA", SANs: `["example.com","new.example"]`, SPKIFingerprint: "new-key"},
		},
	}
	exhibits := changeExhibits(context)
	if len(exhibits) != 1 {
		t.Fatalf("change exhibits = %#v", exhibits)
	}
	got := exhibits[0]
	if !got.IssuerChanged || !got.CommonNameChanged || !got.KeyAlgorithmChanged || !got.PublicKeyChanged {
		t.Fatalf("missing identity delta flags: %#v", got)
	}
	if strings.Join(got.SANsAdded, ",") != "new.example" || strings.Join(got.SANsRemoved, ",") != "old.example" {
		t.Fatalf("SAN delta = +%v -%v", got.SANsAdded, got.SANsRemoved)
	}
	investigation := &models.Investigation{ChangeSequence: exhibits}
	evidence := strings.Join(transitionIdentityEvidence(investigation, "same_endpoint", 3), " ")
	for _, want := range []string{"SAN added: new.example", "SAN removed: old.example", "Issuer A → Issuer B", "ECDSA → RSA", "public key changed"} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("transition evidence %q does not contain %q", evidence, want)
		}
	}
}

func TestDiagnosisTypeForHonoursRequestedFinding(t *testing.T) {
	rows := []models.CertObservation{
		{ObservationType: models.ObsDeploymentFailure},
		{ObservationType: models.ObsChange},
	}
	if got := diagnosisTypeFor("frequent_change", rows); got != "frequent_change" {
		t.Fatalf("requested frequent_change, got %q", got)
	}
	if got := diagnosisTypeFor("deployment_failure", rows); got != models.ObsDeploymentFailure {
		t.Fatalf("requested deployment_failure, got %q", got)
	}
	if got := diagnosisTypeFor("", rows); got != models.ObsDeploymentFailure {
		t.Fatalf("empty request should keep topology preference, got %q", got)
	}
	for _, kind := range []string{"expired_served", "expired_observed", "expiring_soon", "revoked", models.ObsResidual, "unreachable", "measurement_failed", "ari_emergency"} {
		if got := diagnosisTypeFor(kind, rows); got != kind {
			t.Fatalf("requested %s, got %q", kind, got)
		}
	}
}

func TestApplyDiagnosisToFindingSetsFindingClass(t *testing.T) {
	item := models.Anomaly{Type: models.ObsDeploymentFailure, Severity: "warning"}
	diagnosis := models.CauseDiagnosis{
		PrimaryCode:       models.DivergenceIntentionalMultiCDN,
		BenignExplanation: "deliberate multi-provider arrangement",
		Investigation:     &models.Investigation{FindingClass: models.FindingExpected},
	}
	applyDiagnosisToFinding(&item, &diagnosis)
	if item.FindingClass != models.FindingExpected || item.Severity != "info" {
		t.Fatalf("benign finding was not reclassified: %#v", item)
	}
	if isIssueRegisterFinding(item) {
		t.Fatal("expected property must not appear in the Anomalies issue register")
	}
}

func TestApplyDiagnosisToFindingUsesInvestigationProse(t *testing.T) {
	item := models.Anomaly{
		Type:        models.ObsDeploymentFailure,
		Severity:    "warning",
		Description: "Different certificates were observed across sampled endpoints",
		Reason:      "Sampled endpoints presented different leaf fingerprints.",
	}
	diagnosis := models.CauseDiagnosis{
		PrimaryCode:  models.DivergenceStuckRollout,
		PrimaryLabel: "Replacement that did not reach every endpoint",
		Summary:      "At least one endpoint is still serving the replaced certificate.",
		Investigation: &models.Investigation{
			FindingClass: models.FindingIncident,
			Problem:      "2 sampled endpoint(s) served 2 distinct certificate(s) across 1 provider network(s).",
			WhyProblem:   "This is a problem because an active DNS endpoint is still serving the replaced certificate after the propagation window.",
			Cause:        "Replacement that did not reach every endpoint.",
			Facts:        []string{"Addresses fall into 1 provider network(s); 1 of those networks served more than one certificate."},
		},
	}
	applyDiagnosisToFinding(&item, &diagnosis)
	if item.Description != diagnosis.Investigation.Problem {
		t.Fatalf("description = %q, want investigation problem", item.Description)
	}
	if item.Reason != diagnosis.Investigation.Cause {
		t.Fatalf("reason = %q, want investigation cause", item.Reason)
	}
	if len(item.Evidence) != 1 || item.Evidence[0] != diagnosis.Investigation.Facts[0] {
		t.Fatalf("evidence was not replaced with investigation facts: %#v", item.Evidence)
	}
}

func TestSettledDiversityAndDNSRotationAreExpectedProperties(t *testing.T) {
	uniform := map[string]string{"192.0.2.1": "leaf-a", "198.51.100.1": "leaf-a"}
	encoded, _ := json.Marshal(uniform)
	snapshots := []models.MeasurementSnapshot{
		{FingerprintCount: 1, EndpointFingerprintsJSON: string(encoded)},
		{FingerprintCount: 1, EndpointFingerprintsJSON: string(encoded)},
	}
	stale := inferTopologyDiagnosis(models.Anomaly{Type: models.ObsStaleAfterChange}, diagnosisContext{snapshots: snapshots})
	if stale.BenignExplanation == "" {
		t.Fatalf("one-leaf DNS rotation must withdraw the stale-certificate claim: %#v", stale)
	}
	if findingClassOf(stale) != models.FindingExpected {
		t.Fatalf("finding class = %q, want expected for address-pool rotation", findingClassOf(stale))
	}
	item := models.Anomaly{Type: models.ObsStaleAfterChange, FindingClass: findingClassOf(stale), Diagnosis: &stale}
	if isIssueRegisterFinding(item) {
		t.Fatal("DNS rotation must not appear on the Anomalies issue register")
	}

	diversity := inferTopologyDiagnosis(models.Anomaly{Type: models.ObsDeploymentFailure}, diagnosisContext{snapshots: snapshots})
	if diversity.BenignExplanation == "" {
		t.Fatalf("a currently uniform sample must withdraw the diversity claim: %#v", diversity)
	}
	item = models.Anomaly{Type: models.ObsDeploymentFailure, FindingClass: findingClassOf(diversity), Diagnosis: &diversity}
	if isIssueRegisterFinding(item) {
		t.Fatal("settled historical mixed fingerprints must not appear on the Anomalies issue register")
	}
}

func TestUnattributedFrequentChangeIsNotAnIssue(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changes := []models.CertObservation{
		changeRow(t0, "leaf-a", "leaf-b", "spki-a", "spki-b", ""),
		changeRow(t0.Add(24*time.Hour), "leaf-b", "leaf-c", "spki-b", "spki-c", ""),
		changeRow(t0.Add(48*time.Hour), "leaf-c", "leaf-d", "spki-c", "spki-d", ""),
	}
	diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change", OccurrenceCount: 3}, diagnosisContext{observations: changes})
	if diagnosis.BenignExplanation == "" {
		t.Fatalf("a change counter without same-endpoint evidence must withdraw frequent change: %#v", diagnosis)
	}
	item := models.Anomaly{Type: "frequent_change", FindingClass: findingClassOf(diagnosis), Diagnosis: &diagnosis}
	if isIssueRegisterFinding(item) {
		t.Fatal("unattributed change-counter movement must not appear on the Anomalies issue register")
	}
}

func TestIssueRegisterOmitsExpectedAndKeepsProblems(t *testing.T) {
	cases := []struct {
		name string
		item models.Anomaly
		keep bool
	}{
		{name: "incident", item: models.Anomaly{FindingClass: models.FindingIncident}, keep: true},
		{name: "insufficient", item: models.Anomaly{FindingClass: models.FindingInsufficient}, keep: true},
		{name: "unclassified problem", item: models.Anomaly{Type: "revoked"}, keep: true},
		{name: "expected class", item: models.Anomaly{FindingClass: models.FindingExpected}, keep: false},
		{name: "ntp pool name mismatch", item: models.Anomaly{
			Domain: "3.pool.ntp.org",
			Type:   "hostname_mismatch", FindingClass: models.FindingExpected,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: tlsCauseNonHTTPSIdentity, BenignExplanation: "NTP pool alias"},
		}, keep: false},
		{name: "confirmed ntp pool incident is retained", item: models.Anomaly{
			Domain: "2.pool.ntp.org",
			Type:   "frequent_change", FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "incident_driven_reissue", CauseStatus: "established", ChurnShape: &models.ChurnShape{SameEndpointChanges: 2, ProvenSuccessors: 2, ChangeEvents: 12}},
		}, keep: true},
		{name: "Microsoft telemetry endpoint", item: models.Anomaly{
			Domain: "watson.events.data.microsoft.com", Type: models.ObsDeploymentFailure, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceDefectiveEndpoint, Divergence: &models.EndpointDivergence{DistinctLeaves: 2}},
		}, keep: true},
		{name: "Microsoft telemetry subdomain", item: models.Anomaly{
			Domain: "watson.telemetry.microsoft.com", Type: models.ObsDeploymentFailure, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceDefectiveEndpoint, Divergence: &models.EndpointDivergence{DistinctLeaves: 2}},
		}, keep: true},
		{name: "Facebook CDN service name", item: models.Anomaly{
			Domain: "fbcdn.net", Type: models.ObsDeploymentFailure, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceDefectiveEndpoint, Divergence: &models.EndpointDivergence{DistinctLeaves: 2}},
		}, keep: true},
		{name: "TikTok delivery service name", item: models.Anomaly{
			Domain: "tiktokv.com", Type: models.ObsDeploymentFailure, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceDefectiveEndpoint, Divergence: &models.EndpointDivergence{DistinctLeaves: 2}},
		}, keep: true},
		{name: "confirmed Google replacement is retained", item: models.Anomaly{
			Domain: "google.cn", Type: "early_renewal", FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "early_renewal_replacement", CauseStatus: "established", ChurnShape: &models.ChurnShape{SameEndpointChanges: 2, MedianRemainingDays: 64, MedianValidityDays: 83}},
		}, keep: true},
		{name: "site name mismatch", item: models.Anomaly{
			Type: "hostname_mismatch", FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: tlsCauseNameMismatch},
		}, keep: true},
		{name: "benign explanation", item: models.Anomaly{Diagnosis: &models.CauseDiagnosis{BenignExplanation: "intentional multi-CDN"}}, keep: false},
		{name: "expected investigation", item: models.Anomaly{Diagnosis: &models.CauseDiagnosis{Investigation: &models.Investigation{FindingClass: models.FindingExpected}}}, keep: false},
		{name: "historical mixed fingerprints now uniform", item: models.Anomaly{
			Type: models.ObsDeploymentFailure, FindingClass: models.FindingInsufficient,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceUndetermined, Divergence: &models.EndpointDivergence{DistinctLeaves: 1, EndpointsAnswered: 11}},
		}, keep: false},
		{name: "undetermined mixed diversity", item: models.Anomaly{
			Type: models.ObsDeploymentFailure, FindingClass: models.FindingInsufficient,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceUndetermined, Divergence: &models.EndpointDivergence{DistinctLeaves: 2, EndpointsAnswered: 4}},
		}, keep: true},
		{name: "intra-fleet diversity", item: models.Anomaly{
			Type: models.ObsDeploymentFailure, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceIntraFleet, Divergence: &models.EndpointDivergence{DistinctLeaves: 2, IntraGroupConflicts: 1}},
		}, keep: true},
		{name: "deployment same-name CDN pool", item: models.Anomaly{
			Type: models.ObsDeploymentFailure, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceIntraFleet, Divergence: &models.EndpointDivergence{
				DistinctLeaves: 2, FunctionallyEquivalent: true, AddressPools: 1, AddressReturns: 1,
			}},
		}, keep: false},
		{name: "propagating mixed diversity", item: models.Anomaly{
			Type: models.ObsDeploymentFailure, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergencePropagating, Divergence: &models.EndpointDivergence{DistinctLeaves: 2, IntraGroupConflicts: 1}},
		}, keep: true},
		{name: "stale dns rotation one leaf", item: models.Anomaly{
			Type: models.ObsStaleAfterChange, FindingClass: models.FindingInsufficient,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceUndetermined, Divergence: &models.EndpointDivergence{DistinctLeaves: 1, EndpointsAnswered: 12}},
		}, keep: false},
		{name: "stale one leaf even if defective", item: models.Anomaly{
			Type: models.ObsStaleAfterChange, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceDefectiveEndpoint, Divergence: &models.EndpointDivergence{DistinctLeaves: 1, DefectiveEndpoints: []string{"192.0.2.1"}}},
		}, keep: false},
		{name: "stale stuck predecessor", item: models.Anomaly{
			Type: models.ObsStaleAfterChange, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceStuckRollout, Divergence: &models.EndpointDivergence{DistinctLeaves: 2, ActivePredecessorEndpoints: []string{"192.0.2.1"}, StrongEvidence: true}},
		}, keep: true},
		{name: "stale in-flight with active predecessor", item: models.Anomaly{
			Type: models.ObsStaleAfterChange, FindingClass: models.FindingInsufficient,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergencePropagating, Divergence: &models.EndpointDivergence{DistinctLeaves: 2, ActivePredecessorEndpoints: []string{"192.0.2.1"}}},
		}, keep: false},
		{name: "stale mixed leaves without leftover predecessor", item: models.Anomaly{
			Type: models.ObsStaleAfterChange, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceDefectiveEndpoint, Divergence: &models.EndpointDivergence{DistinctLeaves: 2, DefectiveEndpoints: []string{"192.0.2.1"}}},
		}, keep: false},
		{name: "stale intra-fleet without leftover predecessor", item: models.Anomaly{
			Type: models.ObsStaleAfterChange, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceIntraFleet, Divergence: &models.EndpointDivergence{DistinctLeaves: 2, IntraGroupConflicts: 1}},
		}, keep: false},
		{name: "stale same-name CDN pool", item: models.Anomaly{
			Type: models.ObsStaleAfterChange, FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergenceStuckRollout, Divergence: &models.EndpointDivergence{
				DistinctLeaves: 2, FunctionallyEquivalent: true, AddressPools: 1, AddressReturns: 1,
				ActivePredecessorEndpoints: []string{"192.0.2.1"},
			}},
		}, keep: false},
		{name: "stale retired predecessor only", item: models.Anomaly{
			Type: models.ObsStaleAfterChange, FindingClass: models.FindingInsufficient,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: models.DivergencePropagating, Divergence: &models.EndpointDivergence{DistinctLeaves: 2, RetiredPredecessorEndpoints: []string{"192.0.2.1"}}},
		}, keep: false},
		{name: "frequent change without endpoint identity", item: models.Anomaly{
			Type: "frequent_change", FindingClass: models.FindingInsufficient,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "endpoint_attribution_unavailable", ChurnShape: &models.ChurnShape{SameEndpointChanges: 0, ChangeEvents: 12}},
		}, keep: false},
		{name: "frequent change inferred from issuance only", item: models.Anomaly{
			Type: "frequent_change", FindingClass: models.FindingInsufficient,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "automated_renewal_policy", CauseStatus: "inferred", ChurnShape: &models.ChurnShape{SameEndpointChanges: 0, ChangeEvents: 8}},
		}, keep: false},
		{name: "frequent automated renewal is an operational detail", item: models.Anomaly{
			Type: "frequent_change", FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "automated_renewal_policy", CauseStatus: "established", ChurnShape: &models.ChurnShape{SameEndpointChanges: 4, ProvenSuccessors: 4, ChangeEvents: 8}},
		}, keep: false},
		{name: "preissued rolling deployment is an operational detail", item: models.Anomaly{
			Type: "frequent_change", FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "preissued_rolling_pipeline", CauseStatus: "established", ChurnShape: &models.ChurnShape{SameEndpointChanges: 4, ProvenSuccessors: 4, ChangeEvents: 8}},
		}, keep: false},
		{name: "same-key with measured SPKI pair", item: models.Anomaly{
			Type: "same_key", FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "same_key_reissue", CauseStatus: "established", ChurnShape: &models.ChurnShape{ChangeEvents: 2, DistinctLeaves: 3, DistinctSPKIs: 1, SameEndpointChanges: 2}},
		}, keep: true},
		{name: "same-key without retained pair", item: models.Anomaly{
			Type: "same_key", FindingClass: models.FindingInsufficient,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "same_key_unestablished", CauseStatus: "unestablished"},
		}, keep: false},
		{name: "concurrent same-key overlap", item: models.Anomaly{
			Type: "same_key", FindingClass: models.FindingInsufficient,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "concurrent_same_key", CauseStatus: "inferred", ChurnShape: &models.ChurnShape{ChangeEvents: 27, RevisitEvents: 26, DistinctSPKIs: 1, SameEndpointChanges: 0}},
		}, keep: false},
		{name: "early renewal same-address predecessor remaining", item: models.Anomaly{
			Type: "early_renewal", FindingClass: models.FindingIncident,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "early_renewal_replacement", CauseStatus: "established", ChurnShape: &models.ChurnShape{SameEndpointChanges: 2, MedianRemainingDays: 89, MedianValidityDays: 90}},
		}, keep: true},
		{name: "early renewal concurrent leaves", item: models.Anomaly{
			Type: "early_renewal", FindingClass: models.FindingExpected,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "concurrent_multi_certificate_pool", BenignExplanation: "concurrent", ChurnShape: &models.ChurnShape{CrossEndpointChanges: 4, MedianRemainingDays: 89}},
		}, keep: false},
		{name: "early renewal short-lived predecessor", item: models.Anomaly{
			Type: "early_renewal", FindingClass: models.FindingExpected,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "short_lived_certificate_automation", BenignExplanation: "short", ChurnShape: &models.ChurnShape{SameEndpointChanges: 3, MedianValidityDays: 7, MedianRemainingDays: 4}},
		}, keep: false},
		{name: "early renewal successor remaining only", item: models.Anomaly{
			Type: "early_renewal", FindingClass: models.FindingInsufficient,
			Diagnosis: &models.CauseDiagnosis{PrimaryCode: "early_renewal_unestablished", CauseStatus: "unestablished", ChurnShape: &models.ChurnShape{SameEndpointChanges: 0, MedianRemainingDays: 20}},
		}, keep: false},
	}
	for _, test := range cases {
		if got := isIssueRegisterFinding(test.item); got != test.keep {
			t.Fatalf("%s: isIssueRegisterFinding=%v, want %v", test.name, got, test.keep)
		}
	}
}

func TestInvestigationProofIsStepwiseForDiversityStaleAndChurn(t *testing.T) {
	t.Run("intra-fleet diversity is a proven chain", func(t *testing.T) {
		probes := []models.EndpointProbe{
			{IPAddress: "165.189.150.147", Success: true, Fingerprint: "a", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "names"},
			{IPAddress: "165.189.241.136", Success: true, Fingerprint: "b", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "names"},
		}
		encoded, _ := json.Marshal(probes)
		assignment, _ := json.Marshal(map[string]string{"165.189.150.147": "a", "165.189.241.136": "b"})
		now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
		item := models.Anomaly{Domain: "split.example", Type: models.ObsDeploymentFailure}
		context := diagnosisContext{
			observations: []models.CertObservation{{
				ObservationType: models.ObsDeploymentFailure, ObservedAt: now, EndpointProbes: string(encoded),
			}},
			snapshots: []models.MeasurementSnapshot{
				{ObservedAt: now.Add(-24 * time.Hour), FingerprintCount: 2, EndpointFingerprintsJSON: string(assignment)},
				{ObservedAt: now.Add(-48 * time.Hour), FingerprintCount: 2, EndpointFingerprintsJSON: string(assignment)},
			},
		}
		investigation := buildInvestigation(item, context, inferTopologyDiagnosis(item, context))
		if investigation.ProofKind != "proven" {
			t.Fatalf("proof kind = %q, want proven: %#v", investigation.ProofKind, investigation)
		}
		if len(investigation.Inference) != 0 {
			t.Fatalf("intra-fleet still listed an inference: %#v", investigation.Inference)
		}
		if !hasProofLabel(investigation.Proof, "Observed mix") || !hasProofLabel(investigation.Proof, "Same-network disagreement") || !hasProofLabel(investigation.Proof, "Conclusion") {
			t.Fatalf("proven chain omitted a measurement step: %#v", investigation.Proof)
		}
		assertClaimThenEvidence(t, investigation.Proof)
		if !proofEvidenceContains(investigation.Proof, "165.189.150.147") || !proofEvidenceContains(investigation.Proof, "165.189.241.136") {
			t.Fatalf("intra-fleet proof did not cite the disagreeing endpoints: %#v", investigation.Proof)
		}
	})

	t.Run("propagating mix keeps the observation proven and the process inferred", func(t *testing.T) {
		now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
		probes, _ := json.Marshal([]models.EndpointProbe{
			{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n", NotBefore: issuedOld()},
			{IPAddress: "192.0.2.2", Success: true, Fingerprint: "new", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n", NotBefore: issuedNew()},
		})
		item := models.Anomaly{Domain: "cutover.example", Type: models.ObsDeploymentFailure}
		context := diagnosisContext{
			observations: []models.CertObservation{
				{ObservationType: models.ObsChange, ObservedAt: now.Add(-2 * time.Hour), Fingerprint: "new", PreviousFingerprint: "old"},
				{ObservationType: models.ObsDeploymentFailure, ObservedAt: now, Fingerprint: "new", PreviousFingerprint: "old", EndpointProbes: string(probes)},
			},
		}
		diagnosis := inferTopologyDiagnosis(item, context)
		investigation := buildInvestigation(item, context, diagnosis)
		if investigation.ProofKind != "mixed" && investigation.ProofKind != "inferred" {
			t.Fatalf("in-flight mix proof kind = %q, want mixed or inferred: %#v", investigation.ProofKind, investigation)
		}
		if !hasProofLabel(investigation.Proof, "Observed mix") {
			t.Fatalf("the live mix was not proven: %#v", investigation.Proof)
		}
		assertClaimThenEvidence(t, investigation.Proof)
		assertClaimThenEvidence(t, investigation.Inference)
		if len(investigation.Inference) == 0 {
			t.Fatalf("an in-flight assignment was presented as a closed proof: %#v", investigation)
		}
		if diagnosis.PrimaryCode == models.DivergenceStuckRollout && diagnosis.Divergence != nil && diagnosis.Divergence.StrongEvidence {
			t.Fatal("two-hour residue was promoted to a stuck-rollout proof")
		}
		assertNoSharedEvidence(t, investigation.Proof, investigation.Inference)
	})

	t.Run("stale stuck predecessor is a proven chain", func(t *testing.T) {
		testRolloutReference(t, 0.99, repeatHours(10, 100)...)
		mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
		topologyJSON := func(ips []string) string {
			encoded, _ := json.Marshal(models.TopologySnapshot{ConsensusIPs: ips, PublicIPs: ips, ResolverQuorum: 2, ResolverAgreement: 1})
			return string(encoded)
		}
		now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
		assignment := mapJSON(map[string]string{"192.0.2.1": "old", "192.0.2.2": "new"})
		probes, _ := json.Marshal([]models.EndpointProbe{
			{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n", NotBefore: issuedOld()},
			{IPAddress: "192.0.2.2", Success: true, Fingerprint: "new", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n", NotBefore: issuedNew()},
		})
		topology := topologyJSON([]string{"192.0.2.1", "192.0.2.2"})
		item := models.Anomaly{Domain: "stuck.example", Type: models.ObsStaleAfterChange}
		context := diagnosisContext{
			observations: []models.CertObservation{
				{ObservationType: models.ObsChange, ObservedAt: now.Add(-96 * time.Hour), Fingerprint: "new", PreviousFingerprint: "old"},
				{ObservationType: models.ObsStaleAfterChange, ObservedAt: now, Fingerprint: "new", PreviousFingerprint: "old", EndpointProbes: string(probes)},
			},
			snapshots: []models.MeasurementSnapshot{
				{ObservedAt: now.Add(-24 * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: assignment, TopologyJSON: topology},
				{ObservedAt: now.Add(-48 * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: assignment, TopologyJSON: topology},
				{ObservedAt: now.Add(-72 * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: assignment, TopologyJSON: topology},
				{ObservedAt: now.Add(-96 * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: mapJSON(map[string]string{"192.0.2.1": "old", "192.0.2.2": "old"}), TopologyJSON: topology},
			},
		}
		diagnosis := inferTopologyDiagnosis(item, context)
		investigation := buildInvestigation(item, context, diagnosis)
		if diagnosis.Divergence == nil || !diagnosis.Divergence.StrongEvidence {
			t.Fatalf("fixture did not establish a stuck predecessor: %#v", diagnosis.Divergence)
		}
		if investigation.ProofKind != "proven" {
			t.Fatalf("stuck stale proof kind = %q, want proven: %#v", investigation.ProofKind, investigation)
		}
		if !hasProofLabel(investigation.Proof, "Active predecessor") || !hasProofLabel(investigation.Proof, "Conclusion") {
			t.Fatalf("stuck stale omitted a proof step: %#v", investigation.Proof)
		}
		assertClaimThenEvidence(t, investigation.Proof)
		if !proofEvidenceContains(investigation.Proof, "192.0.2.1") {
			t.Fatalf("stuck stale proof did not cite the active predecessor: %#v", investigation.Proof)
		}
		if len(investigation.Inference) != 0 {
			t.Fatalf("a strong-evidence stuck predecessor still listed an inference: %#v", investigation.Inference)
		}
	})

	t.Run("stale in-flight cutover does not repeat proven endpoint lines as inference", func(t *testing.T) {
		now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
		probes, _ := json.Marshal([]models.EndpointProbe{
			{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n", NotBefore: issuedOld()},
			{IPAddress: "192.0.2.2", Success: true, Fingerprint: "new", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n", NotBefore: issuedNew()},
		})
		item := models.Anomaly{Domain: "washingtonpost.example", Type: models.ObsStaleAfterChange}
		context := diagnosisContext{
			observations: []models.CertObservation{
				{ObservationType: models.ObsChange, ObservedAt: now.Add(-4 * time.Hour), Fingerprint: "new", PreviousFingerprint: "old"},
				{ObservationType: models.ObsStaleAfterChange, ObservedAt: now, Fingerprint: "new", PreviousFingerprint: "old", EndpointProbes: string(probes)},
			},
		}
		diagnosis := inferTopologyDiagnosis(item, context)
		investigation := buildInvestigation(item, context, diagnosis)
		if len(investigation.Proof) == 0 || len(investigation.Inference) == 0 {
			t.Fatalf("in-flight stale needs both proof and inference: %#v", investigation)
		}
		if !hasProofLabel(investigation.Proof, "Active predecessor") && !hasProofLabel(investigation.Proof, "Post-change mix") {
			t.Fatalf("in-flight stale omitted a measured proof step: %#v", investigation.Proof)
		}
		if proofEvidenceContains(investigation.Inference, "192.0.2.1") {
			t.Fatalf("inference repeated a proven predecessor endpoint: %#v", investigation.Inference)
		}
		assertNoSharedEvidence(t, investigation.Proof, investigation.Inference)
		if !proofEvidenceContains(investigation.Inference, "Residue") && !proofEvidenceContains(investigation.Inference, "Consecutive") {
			t.Fatalf("inference omitted continuity measurements: %#v", investigation.Inference)
		}
	})

	t.Run("same-endpoint preissued pipeline is a proven chain", func(t *testing.T) {
		t0 := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
		issued := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
		changes := make([]models.CertObservation, 0, 8)
		certs := make(map[string]models.Certificate)
		for i := 0; i < 8; i++ {
			oldFP := "leaf-" + string(rune('a'+i))
			newFP := "leaf-" + string(rune('b'+i))
			notBefore := issued.Add(time.Duration(i) * 24 * time.Hour)
			notAfter := notBefore.Add(90 * 24 * time.Hour)
			changes = append(changes, models.CertObservation{
				ObservationType: models.ObsChange, ObservedAt: t0.Add(time.Duration(i) * 24 * time.Hour),
				Fingerprint: newFP, PreviousFingerprint: oldFP, DaysUntilExpiry: 7, IPAddress: "192.0.2.1",
			})
			certs[oldFP] = models.Certificate{Fingerprint: oldFP, Issuer: "CN=DigiCert", IssuerCN: "DigiCert", CommonName: "*.example", ValidityDays: 90, NotBefore: notBefore.Add(-24 * time.Hour), NotAfter: notAfter.Add(-24 * time.Hour)}
			certs[newFP] = models.Certificate{Fingerprint: newFP, Issuer: "CN=DigiCert", IssuerCN: "DigiCert", CommonName: "*.example", ValidityDays: 90, NotBefore: notBefore, NotAfter: notAfter}
		}
		item := models.Anomaly{Domain: "fb.example", Type: "frequent_change", OccurrenceCount: 8}
		context := diagnosisContext{observations: changes, certificates: certs}
		investigation := buildInvestigation(item, context, inferChurnDiagnosis(item, context))
		if investigation.CauseCode != "preissued_rolling_pipeline" {
			t.Fatalf("cause = %q, want preissued_rolling_pipeline", investigation.CauseCode)
		}
		if investigation.ProofKind != "proven" {
			t.Fatalf("preissued proof kind = %q, want proven: %#v", investigation.ProofKind, investigation)
		}
		if !hasProofLabel(investigation.Proof, "Counted differences") || !hasProofLabel(investigation.Proof, "Endpoint comparison") || !hasProofLabel(investigation.Proof, "Conclusion") {
			t.Fatalf("preissued proof omitted a measurement step: %#v", investigation.Proof)
		}
		assertClaimThenEvidence(t, investigation.Proof)
		if !proofEvidenceContains(investigation.Proof, "192.0.2.1") && !proofEvidenceContains(investigation.Proof, "same-endpoint") && !proofEvidenceContains(investigation.Proof, "same-address") {
			t.Fatalf("preissued proof did not cite the same-address replacements: %#v", investigation.Proof)
		}
		if len(investigation.Inference) != 0 {
			t.Fatalf("same-endpoint preissued pipeline still listed an inference: %#v", investigation.Inference)
		}
	})

	t.Run("unattributed extra issuance stays an inference", func(t *testing.T) {
		diagnosis := models.CauseDiagnosis{
			PrimaryCode:  "automated_renewal_policy",
			PrimaryLabel: "Automated renewal policy",
			CauseStatus:  "inferred",
			ChurnShape:   &models.ChurnShape{ChangeEvents: 8, DistinctLeaves: 8, SameEndpointChanges: 0, UnknownEndpointChanges: 8, MedianRemainingDays: 88, MedianIssuanceAgeDays: 1, MedianValidityDays: 90},
		}
		item := models.Anomaly{Type: "frequent_change"}
		investigation := buildInvestigation(item, diagnosisContext{}, diagnosis)
		if investigation.ProofKind != "mixed" && investigation.ProofKind != "inferred" {
			t.Fatalf("unattributed extra issuance proof kind = %q: %#v", investigation.ProofKind, investigation)
		}
		if len(investigation.Inference) == 0 {
			t.Fatal("missing serving addresses were presented as a closed proof")
		}
		if hasProofLabel(investigation.Proof, "Conclusion") {
			t.Fatalf("an inferred process was written as a proven conclusion: %#v", investigation.Proof)
		}
		assertClaimThenEvidence(t, investigation.Proof)
		assertClaimThenEvidence(t, investigation.Inference)
		if !strings.Contains(investigation.Inference[0].Claim, "88") && !strings.Contains(investigation.Inference[0].Claim, "1") {
			t.Fatalf("inferred extra issuance did not cite remaining life or issuance age: %#v", investigation.Inference[0])
		}
		if !proofEvidenceContains(investigation.Inference, "88") || !proofEvidenceContains(investigation.Inference, "no serving address") {
			t.Fatalf("inferred extra issuance did not rest on measured remaining life and missing addresses: %#v", investigation.Inference)
		}
	})
}

func TestSameKeyProofCitesSPKIAndAddressMeasurements(t *testing.T) {
	t.Run("same-key proof cites SPKI and address measurements", func(t *testing.T) {
		t0 := time.Date(2026, 9, 12, 2, 19, 0, 0, time.UTC)
		t1 := time.Date(2026, 9, 14, 20, 8, 0, 0, time.UTC)
		issued := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
		item := models.Anomaly{Domain: "unicamp.example", Type: "same_key", OccurrenceCount: 2}
		context := diagnosisContext{
			observations: []models.CertObservation{
				{
					ObservationType: models.ObsChange, ObservedAt: t0,
					Fingerprint: "leaf-b", PreviousFingerprint: "leaf-a",
					SPKIFingerprint: "spki-same", PreviousSPKIFingerprint: "spki-same",
					IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1",
					DaysUntilExpiry: 89, ChangeClass: models.ChangeClassUnknown,
				},
				{
					ObservationType: models.ObsSameKey, ObservedAt: t0,
					Fingerprint: "leaf-b", PreviousFingerprint: "leaf-a",
					SPKIFingerprint: "spki-same", PreviousSPKIFingerprint: "spki-same",
					IPAddress: "192.0.2.1",
				},
				{
					ObservationType: models.ObsChange, ObservedAt: t1,
					Fingerprint: "leaf-c", PreviousFingerprint: "leaf-b",
					SPKIFingerprint: "spki-same", PreviousSPKIFingerprint: "spki-same",
					IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1",
					DaysUntilExpiry: 89, ChangeClass: models.ChangeClassReplacement,
				},
				{
					ObservationType: models.ObsSameKey, ObservedAt: t1,
					Fingerprint: "leaf-c", PreviousFingerprint: "leaf-b",
					SPKIFingerprint: "spki-same", PreviousSPKIFingerprint: "spki-same",
					IPAddress: "192.0.2.1",
				},
			},
			certificates: map[string]models.Certificate{
				"leaf-a": {Fingerprint: "leaf-a", SPKIFingerprint: "spki-same", NotBefore: issued.Add(-3 * 24 * time.Hour), NotAfter: issued.Add(86 * 24 * time.Hour)},
				"leaf-b": {Fingerprint: "leaf-b", SPKIFingerprint: "spki-same", NotBefore: issued.Add(-2 * 24 * time.Hour), NotAfter: issued.Add(87 * 24 * time.Hour)},
				"leaf-c": {Fingerprint: "leaf-c", SPKIFingerprint: "spki-same", NotBefore: issued, NotAfter: issued.Add(89 * 24 * time.Hour)},
			},
		}
		diagnosis := inferSameKeyDiagnosis(item, context)
		investigation := buildInvestigation(item, context, diagnosis)
		if diagnosis.PrimaryCode != "same_key_reissue" {
			t.Fatalf("primary = %q, want same_key_reissue", diagnosis.PrimaryCode)
		}
		if diagnosis.CauseStatus != "established" {
			t.Fatalf("cause status = %q, want established", diagnosis.CauseStatus)
		}
		if !hasProofLabel(investigation.Proof, "Leaf changed") || !hasProofLabel(investigation.Proof, "SPKI unchanged") || !hasProofLabel(investigation.Proof, "Same address") {
			t.Fatalf("same-key omitted a measurement step: %#v", investigation.Proof)
		}
		assertClaimThenEvidence(t, investigation.Proof)
		assertClaimThenEvidence(t, investigation.Inference)
		if !proofEvidenceContains(investigation.Proof, "spki-same") || !proofEvidenceContains(investigation.Proof, "192.0.2.1") {
			t.Fatalf("same-key proof did not cite SPKI and address: %#v", investigation.Proof)
		}
		if containsFold(investigation.WhyProblem, "Cloudflare") || containsFold(investigation.Cause, "dashboard") || containsFold(investigation.Cause, "many times per lifetime") {
			t.Fatalf("same-key reused frequent-change narrative: %#v", investigation)
		}
		if len(investigation.Inference) == 0 {
			t.Fatal("same-key omitted the measured remaining-life inference")
		}
		if !proofEvidenceContains(investigation.Inference, "89") {
			t.Fatalf("same-key inference did not rest on remaining life: %#v", investigation.Inference)
		}
		item.FindingClass = findingClassOf(diagnosis)
		item.Diagnosis = &diagnosis
		if !isIssueRegisterFinding(item) {
			t.Fatal("measured same-key replacement must stay on the issue register")
		}
	})

	t.Run("same-key without a serving address stays an inference", func(t *testing.T) {
		t0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
		item := models.Anomaly{Domain: "unattributed.example", Type: "same_key", OccurrenceCount: 1}
		context := diagnosisContext{
			observations: []models.CertObservation{{
				ObservationType: models.ObsSameKey, ObservedAt: t0,
				Fingerprint: "leaf-b", PreviousFingerprint: "leaf-a",
				SPKIFingerprint: "spki-same", PreviousSPKIFingerprint: "spki-same",
			}},
			certificates: map[string]models.Certificate{
				"leaf-a": {Fingerprint: "leaf-a", SPKIFingerprint: "spki-same"},
				"leaf-b": {Fingerprint: "leaf-b", SPKIFingerprint: "spki-same"},
			},
		}
		diagnosis := inferSameKeyDiagnosis(item, context)
		investigation := buildInvestigation(item, context, diagnosis)
		if diagnosis.CauseStatus != "inferred" {
			t.Fatalf("cause status = %q, want inferred without a serving address", diagnosis.CauseStatus)
		}
		if hasProofLabel(investigation.Proof, "Conclusion") {
			t.Fatalf("an unaddressed SPKI pair was written as a closed proof: %#v", investigation.Proof)
		}
		if len(investigation.Inference) == 0 {
			t.Fatal("missing serving address was presented without an inference")
		}
		assertClaimThenEvidence(t, investigation.Proof)
		assertClaimThenEvidence(t, investigation.Inference)
		if containsFold(investigation.WhyProblem, "automated renewal") {
			t.Fatalf("unaddressed same-key reused churn cause text: %#v", investigation)
		}
	})

	t.Run("concurrent same-key cites both addresses", func(t *testing.T) {
		t0 := time.Date(2026, 9, 17, 17, 36, 0, 0, time.UTC)
		item := models.Anomaly{Domain: "oss.example", Type: "same_key", OccurrenceCount: 1}
		context := diagnosisContext{
			observations: []models.CertObservation{
				{
					ObservationType: models.ObsChange, ObservedAt: t0,
					Fingerprint: "leaf-b", PreviousFingerprint: "leaf-a",
					SPKIFingerprint: "spki-same", PreviousSPKIFingerprint: "spki-same",
					IPAddress: "192.0.2.2", PreviousIPAddress: "192.0.2.1",
					ChangeClass: models.ChangeClassCoexisting, DaysUntilExpiry: 29,
				},
				{
					ObservationType: models.ObsSameKey, ObservedAt: t0,
					Fingerprint: "leaf-b", PreviousFingerprint: "leaf-a",
					SPKIFingerprint: "spki-same", PreviousSPKIFingerprint: "spki-same",
					ChangeClass: models.ChangeClassCoexisting,
				},
			},
			certificates: map[string]models.Certificate{
				"leaf-a": {Fingerprint: "leaf-a", SPKIFingerprint: "spki-same"},
				"leaf-b": {Fingerprint: "leaf-b", SPKIFingerprint: "spki-same"},
			},
		}
		diagnosis := inferSameKeyDiagnosis(item, context)
		investigation := buildInvestigation(item, context, diagnosis)
		if diagnosis.PrimaryCode != "concurrent_same_key" {
			t.Fatalf("primary = %q, want concurrent_same_key", diagnosis.PrimaryCode)
		}
		if hasProofLabel(investigation.Proof, "Serving address") {
			t.Fatalf("cross-address pairs were described as missing addresses: %#v", investigation.Proof)
		}
		if !hasProofLabel(investigation.Proof, "Different addresses") {
			t.Fatalf("concurrent same-key omitted the measured address split: %#v", investigation.Proof)
		}
		assertClaimThenEvidence(t, investigation.Proof)
		assertClaimThenEvidence(t, investigation.Inference)
		if !proofEvidenceContains(investigation.Proof, "192.0.2.1") || !proofEvidenceContains(investigation.Proof, "192.0.2.2") {
			t.Fatalf("concurrent same-key did not cite both addresses: %#v", investigation.Proof)
		}
	})
}

func TestEarlyRenewalUsesPredecessorRemainingLife(t *testing.T) {
	t0 := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	item := models.Anomaly{Domain: "early.example", Type: "early_renewal", OccurrenceCount: 1}

	t.Run("same-address predecessor still has more than 30 days", func(t *testing.T) {
		context := diagnosisContext{
			observations: []models.CertObservation{{
				ObservationType: models.ObsChange, ObservedAt: t0,
				Fingerprint: "leaf-new", PreviousFingerprint: "leaf-old",
				IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1",
				DaysUntilExpiry: 89, ChangeClass: models.ChangeClassReplacement,
			}},
			certificates: map[string]models.Certificate{
				"leaf-old": {Fingerprint: "leaf-old", NotBefore: t0.Add(-10 * 24 * time.Hour), NotAfter: t0.Add(80 * 24 * time.Hour)},
				"leaf-new": {Fingerprint: "leaf-new", NotBefore: t0.Add(-2 * time.Hour), NotAfter: t0.Add(89 * 24 * time.Hour)},
			},
		}
		diagnosis := inferEarlyRenewalDiagnosis(item, context)
		investigation := buildInvestigation(item, context, diagnosis)
		if diagnosis.PrimaryCode != "early_renewal_replacement" || diagnosis.CauseStatus != "established" {
			t.Fatalf("primary=%q status=%q, want established early_renewal_replacement: %#v", diagnosis.PrimaryCode, diagnosis.CauseStatus, diagnosis)
		}
		if diagnosis.ChurnShape == nil || diagnosis.ChurnShape.MedianRemainingDays <= 30 {
			t.Fatalf("predecessor remaining life was not the gate: %#v", diagnosis.ChurnShape)
		}
		if !hasProofLabel(investigation.Proof, "Predecessor remaining life") || !hasProofLabel(investigation.Proof, "Same address") {
			t.Fatalf("early renewal omitted a measurement step: %#v", investigation.Proof)
		}
		assertClaimThenEvidence(t, investigation.Proof)
		if !proofEvidenceContains(investigation.Proof, "192.0.2.1") || !proofEvidenceContains(investigation.Proof, "not_after=") {
			t.Fatalf("early renewal proof did not cite address and predecessor NotAfter: %#v", investigation.Proof)
		}
		if containsFold(investigation.Cause, "Cloudflare") || containsFold(investigation.WhyProblem, "many times per lifetime") {
			t.Fatalf("early renewal reused frequent-change narrative: %#v", investigation)
		}
		item.FindingClass = findingClassOf(diagnosis)
		item.Diagnosis = &diagnosis
		if !isIssueRegisterFinding(item) {
			t.Fatal("measured same-address early replacement must stay on the issue register")
		}
	})

	t.Run("successor remaining life alone is not early renewal", func(t *testing.T) {
		context := diagnosisContext{
			observations: []models.CertObservation{{
				ObservationType: models.ObsChange, ObservedAt: t0,
				Fingerprint: "leaf-new", PreviousFingerprint: "leaf-old",
				IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1",
				DaysUntilExpiry: 89, ChangeClass: models.ChangeClassReplacement,
			}},
			certificates: map[string]models.Certificate{
				"leaf-old": {Fingerprint: "leaf-old", NotBefore: t0.Add(-80 * 24 * time.Hour), NotAfter: t0.Add(10 * 24 * time.Hour)},
				"leaf-new": {Fingerprint: "leaf-new", NotBefore: t0.Add(-1 * time.Hour), NotAfter: t0.Add(89 * 24 * time.Hour)},
			},
		}
		diagnosis := inferEarlyRenewalDiagnosis(item, context)
		if diagnosis.PrimaryCode == "early_renewal_replacement" {
			t.Fatalf("a predecessor with 10 days remaining was counted as early: %#v", diagnosis)
		}
		item.FindingClass = findingClassOf(diagnosis)
		item.Diagnosis = &diagnosis
		if isIssueRegisterFinding(item) {
			t.Fatal("ACME-on-schedule replacement of a nearly-due predecessor must not appear as early renewal")
		}
	})

	t.Run("concurrent leaves are not early renewal", func(t *testing.T) {
		context := diagnosisContext{
			observations: []models.CertObservation{{
				ObservationType: models.ObsChange, ObservedAt: t0,
				Fingerprint: "leaf-b", PreviousFingerprint: "leaf-a",
				IPAddress: "192.0.2.2", PreviousIPAddress: "192.0.2.1",
				DaysUntilExpiry: 89, ChangeClass: models.ChangeClassCoexisting,
			}},
			certificates: map[string]models.Certificate{
				"leaf-a": {Fingerprint: "leaf-a", NotBefore: t0.Add(-10 * 24 * time.Hour), NotAfter: t0.Add(80 * 24 * time.Hour)},
				"leaf-b": {Fingerprint: "leaf-b", NotBefore: t0.Add(-1 * time.Hour), NotAfter: t0.Add(89 * 24 * time.Hour)},
			},
		}
		diagnosis := inferEarlyRenewalDiagnosis(item, context)
		if diagnosis.BenignExplanation == "" || diagnosis.PrimaryCode != "concurrent_multi_certificate_pool" {
			t.Fatalf("cross-address pair was not withdrawn: %#v", diagnosis)
		}
		item.FindingClass = findingClassOf(diagnosis)
		item.Diagnosis = &diagnosis
		if isIssueRegisterFinding(item) {
			t.Fatal("concurrent deployment must not appear as early renewal")
		}
	})

	t.Run("short-lived predecessor is not early renewal", func(t *testing.T) {
		context := diagnosisContext{
			observations: []models.CertObservation{{
				ObservationType: models.ObsChange, ObservedAt: t0,
				Fingerprint: "leaf-new", PreviousFingerprint: "leaf-old",
				IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1",
				DaysUntilExpiry: 6, ChangeClass: models.ChangeClassReplacement,
			}},
			certificates: map[string]models.Certificate{
				"leaf-old": {Fingerprint: "leaf-old", NotBefore: t0.Add(-3 * 24 * time.Hour), NotAfter: t0.Add(4 * 24 * time.Hour)},
				"leaf-new": {Fingerprint: "leaf-new", NotBefore: t0, NotAfter: t0.Add(7 * 24 * time.Hour)},
			},
		}
		diagnosis := inferEarlyRenewalDiagnosis(item, context)
		if diagnosis.PrimaryCode != "short_lived_certificate_automation" || diagnosis.BenignExplanation == "" {
			t.Fatalf("7-day predecessor was not withdrawn: %#v", diagnosis)
		}
		item.FindingClass = findingClassOf(diagnosis)
		item.Diagnosis = &diagnosis
		if isIssueRegisterFinding(item) {
			t.Fatal("short-lived cadence must not appear as early renewal")
		}
	})

	t.Run("out-of-range predecessor NotAfter is not remaining life", func(t *testing.T) {
		context := diagnosisContext{
			observations: []models.CertObservation{{
				ObservationType: models.ObsChange, ObservedAt: t0,
				Fingerprint: "leaf-new", PreviousFingerprint: "leaf-old",
				IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1",
				DaysUntilExpiry: 89, ChangeClass: models.ChangeClassReplacement,
			}},
			certificates: map[string]models.Certificate{
				"leaf-old": {Fingerprint: "leaf-old", NotBefore: t0.Add(-10 * 24 * time.Hour), NotAfter: time.Date(12000, 1, 1, 0, 0, 0, 0, time.UTC)},
				"leaf-new": {Fingerprint: "leaf-new", NotBefore: t0.Add(-2 * time.Hour), NotAfter: t0.Add(89 * 24 * time.Hour)},
			},
		}
		diagnosis := inferEarlyRenewalDiagnosis(item, context)
		if diagnosis.PrimaryCode == "early_renewal_replacement" {
			t.Fatalf("year-12000 NotAfter was treated as remaining life: %#v", diagnosis)
		}
		item.FindingClass = findingClassOf(diagnosis)
		item.Diagnosis = &diagnosis
		if isIssueRegisterFinding(item) {
			t.Fatal("invalid certificate dates must not appear as early renewal")
		}
	})
}

func TestSanitizeAnomalyDropsOutOfRangeTimes(t *testing.T) {
	bad := time.Date(12000, 1, 1, 0, 0, 0, 0, time.UTC)
	item := models.Anomaly{
		Domain:     "bad.example",
		Type:       "early_renewal",
		DetectedAt: bad,
		Diagnosis: &models.CauseDiagnosis{
			Investigation: &models.Investigation{
				Certificates: []models.CertificateExhibit{{
					Fingerprint: "leaf",
					NotAfter:    &bad,
				}},
				ChangeSequence: []models.ChangeExhibit{{ObservedAt: bad}},
			},
			EvidenceCase: &models.EvidenceCase{
				GeneratedAt: bad,
				Rounds:      []models.EvidenceRound{{ObservedAt: bad}},
			},
		},
	}
	if _, err := json.Marshal(item); err == nil {
		t.Fatal("expected JSON marshal to fail on year 12000")
	}
	items := []models.Anomaly{item}
	sanitizeAnomalyJSONTimes(items)
	encoded, err := json.Marshal(items[0])
	if err != nil {
		t.Fatalf("sanitize left unmarshalable time: %v", err)
	}
	if strings.Contains(string(encoded), "12000") {
		t.Fatalf("sanitize left year 12000 in JSON: %s", encoded)
	}
}

func assertNoSharedEvidence(t *testing.T, proven, inferred []models.InvestigationProofStep) {
	t.Helper()
	seen := map[string]string{}
	for _, step := range proven {
		for _, line := range step.Evidence {
			seen[line] = step.Label
		}
	}
	for _, step := range inferred {
		for _, line := range step.Evidence {
			if label, ok := seen[line]; ok {
				t.Fatalf("inference %q repeated proven evidence from %q: %s", step.Label, label, line)
			}
		}
	}
}

func assertClaimThenEvidence(t *testing.T, steps []models.InvestigationProofStep) {
	t.Helper()
	for _, step := range steps {
		if strings.TrimSpace(step.Claim) == "" {
			t.Fatalf("proof step has no claim: %#v", step)
		}
		if len(step.Evidence) == 0 {
			t.Fatalf("claim %q was written without the measurements that prove it: %#v", step.Claim, step)
		}
		for _, item := range step.Evidence {
			lower := strings.ToLower(item)
			for _, marker := range []string{"this is a problem", "this is not counted", "cannot reappear", "falsif", "propagation window", "later round"} {
				if strings.Contains(lower, marker) {
					t.Fatalf("claim %q cited narrative instead of a measurement: %q", step.Claim, item)
				}
			}
		}
	}
}

func proofEvidenceContains(steps []models.InvestigationProofStep, needle string) bool {
	needle = strings.ToLower(needle)
	for _, step := range steps {
		for _, item := range step.Evidence {
			if strings.Contains(strings.ToLower(item), needle) {
				return true
			}
		}
	}
	return false
}

func hasProofLabel(steps []models.InvestigationProofStep, label string) bool {
	for _, step := range steps {
		if step.Label == label {
			return true
		}
	}
	return false
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
