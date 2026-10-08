package database

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ahclm/internal/models"
	"ahclm/internal/rollout"
)

// perEndpointFixture reproduces wi.gov on 2026-09-22: two addresses in one /16,
// each with its own leaf from the same issuance, unchanged for several rounds,
// and a lifecycle row whose PreviousFingerprint is the unchanged main leaf.
func perEndpointFixture(sameIssuance bool) (models.Anomaly, diagnosisContext) {
	now := time.Date(2026, 9, 22, 9, 34, 0, 0, time.UTC)
	nb := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	na := time.Date(2027, 3, 17, 23, 59, 59, 0, time.UTC)
	nbOther := nb
	if !sameIssuance {
		nbOther = nb.Add(-30 * 24 * time.Hour)
	}
	probes, _ := json.Marshal([]models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "leaf-a", SPKIFingerprint: "key-a", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n", NotBefore: &nb, NotAfter: &na},
		{IPAddress: "192.0.2.200", Success: true, Fingerprint: "leaf-b", SPKIFingerprint: "key-b", IssuerCN: "CA", KeyAlgorithm: "RSA", SANsHash: "n", NotBefore: &nbOther, NotAfter: &na},
	})
	assignment, _ := json.Marshal(map[string]string{"192.0.2.1": "leaf-a", "192.0.2.200": "leaf-b"})
	topology, _ := json.Marshal(models.TopologySnapshot{ConsensusIPs: []string{"192.0.2.1", "192.0.2.200"}, PublicIPs: []string{"192.0.2.1", "192.0.2.200"}, ResolverQuorum: 2, ResolverAgreement: 1})
	var snapshots []models.MeasurementSnapshot
	for hours := 0; hours <= 32; hours += 8 {
		snapshots = append(snapshots, models.MeasurementSnapshot{ObservedAt: now.Add(-time.Duration(hours) * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, FingerprintCount: 2, EndpointFingerprintsJSON: string(assignment), TopologyJSON: string(topology)})
	}
	context := diagnosisContext{
		observations: []models.CertObservation{
			{ObservationType: models.ObsDeploymentFailure, ObservedAt: now.Add(-20 * time.Hour), Fingerprint: "leaf-a", PreviousFingerprint: "leaf-a", EndpointProbes: string(probes)},
		},
		snapshots: snapshots,
	}
	return models.Anomaly{Domain: "per-endpoint.example", Type: models.ObsDeploymentFailure}, context
}

func TestUnchangedMainLeafIsNotAPredecessor(t *testing.T) {
	item, context := perEndpointFixture(false)
	diagnosis := inferTopologyDiagnosis(item, context)
	d := diagnosis.Divergence
	if d == nil {
		t.Fatal("no divergence")
	}
	if len(d.PredecessorEndpoints) != 0 || d.StrongEvidence || diagnosis.PrimaryCode == models.DivergenceStuckRollout {
		t.Fatalf("the unchanged main-handshake leaf was read as a stuck predecessor: %#v", d)
	}
	// Issuance dates no longer decide: each address kept its own leaf and no
	// address moved between them.
	if diagnosis.PrimaryCode != models.DivergencePerEndpoint {
		t.Fatalf("stable separate lineages = %q, want per-endpoint", diagnosis.PrimaryCode)
	}
}

func TestSameIssuancePerEndpointIsExpected(t *testing.T) {
	item, context := perEndpointFixture(true)
	diagnosis := inferTopologyDiagnosis(item, context)
	d := diagnosis.Divergence
	if d == nil || !d.IndependentLineages || d.StableAddressRounds < minStableAddressRounds {
		t.Fatalf("independent lineages not measured: %#v", d)
	}
	if diagnosis.PrimaryCode != models.DivergencePerEndpoint || diagnosis.BenignExplanation == "" {
		t.Fatalf("primary = %q benign = %q, want per-endpoint expected", diagnosis.PrimaryCode, diagnosis.BenignExplanation)
	}
}

// chase.com's only full survey was a legacy row without certificate fields;
// later rounds must be explained from the snapshot's own full survey.
func TestNewerSnapshotSurveyReplacesLegacyRow(t *testing.T) {
	item, context := perEndpointFixture(true)
	full := context.observations[0].EndpointProbes
	legacy, _ := json.Marshal([]models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "leaf-a"},
		{IPAddress: "192.0.2.200", Success: true, Fingerprint: "leaf-b"},
	})
	context.observations[0].EndpointProbes = string(legacy)
	context.observations[0].ObservedAt = context.snapshots[len(context.snapshots)-1].ObservedAt.Add(-time.Hour)
	context.snapshots[0].EndpointProbesJSON = full
	diagnosis := inferTopologyDiagnosis(item, context)
	if diagnosis.PrimaryCode != models.DivergencePerEndpoint {
		t.Fatalf("primary = %q, want the newer snapshot survey to decide", diagnosis.PrimaryCode)
	}
}

// Fixture issuance dates: a predecessor must be issued before its successor.
func issuedOld() *time.Time { at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC); return &at }
func issuedNew() *time.Time { at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC); return &at }

func rolloutFixture(previousIssuedLater bool, successorRounds int) ([]models.EndpointProbe, []models.MeasurementSnapshot, time.Time) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	oldNB, newNB := issuedOld(), issuedNew()
	if previousIssuedLater {
		oldNB, newNB = newNB, oldNB
	}
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old", IssuerCN: "CA", SANsHash: "n", NotBefore: oldNB},
		{IPAddress: "192.0.2.2", Success: true, Fingerprint: "new", IssuerCN: "CA", SANsHash: "n", NotBefore: newNB},
	}
	topology, _ := json.Marshal(models.TopologySnapshot{ConsensusIPs: []string{"192.0.2.1", "192.0.2.2"}, PublicIPs: []string{"192.0.2.1", "192.0.2.2"}, ResolverQuorum: 2, ResolverAgreement: 1})
	mixed, _ := json.Marshal(map[string]string{"192.0.2.1": "old", "192.0.2.2": "new"})
	onlyOld, _ := json.Marshal(map[string]string{"192.0.2.1": "old", "192.0.2.2": "old"})
	var snapshots []models.MeasurementSnapshot
	for round := 1; round <= 6; round++ {
		assignment := onlyOld
		if round <= successorRounds {
			assignment = mixed
		}
		snapshots = append(snapshots, models.MeasurementSnapshot{ObservedAt: now.Add(-time.Duration(round*12) * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: string(assignment), TopologyJSON: string(topology)})
	}
	return probes, snapshots, now
}

// otheve.beacon.qq.com: the successor appeared in the latest round only. The
// predecessor's earlier rounds alone are not residue after a replacement.
func TestResidueStartsWhenSuccessorAppears(t *testing.T) {
	probes, snapshots, now := rolloutFixture(false, 0)
	d := analyzeEndpointDivergence(probes, snapshots, "old", now, now)
	if d.StrongEvidence || d.Verdict == models.DivergenceStuckRollout || d.PredecessorSpanHours != 0 {
		t.Fatalf("pre-replacement rounds were counted as residue: %#v", d)
	}
	// 192.0.2.2 served "old" in round 6 and "new" from round 5: an observed
	// succession, with the older leaf left on 192.0.2.1 for 60 hours since.
	// Reference: 100 completed rollouts, each certainly done within 10 hours.
	testRolloutReference(t, 0.99, repeatHours(10, 100)...)
	probes, snapshots, now = rolloutFixture(false, 5)
	if d = analyzeEndpointDivergence(probes, snapshots, "old", now.Add(-72*time.Hour), now); !d.StrongEvidence || d.Verdict != models.DivergenceStuckRollout {
		t.Fatalf("an older leaf left for 72 h beside its successor should be stuck: %#v", d)
	}
}

// rkdms.com / cinema-pics: each address always served its own leaf. Without an
// address observed moving from one to the other, neither is a predecessor,
// whatever the issuance dates say.
func TestLeafWithoutObservedSuccessionIsNotAPredecessor(t *testing.T) {
	probes, snapshots, now := rolloutFixture(true, 6)
	d := analyzeEndpointDivergence(probes, snapshots, "old", now.Add(-72*time.Hour), now)
	if len(d.PredecessorEndpoints) != 0 || d.Verdict == models.DivergenceStuckRollout {
		t.Fatalf("a newer leaf was called a predecessor: %#v", d)
	}
}

// dingtalk.com: one address alternating A->B->A is a server pool behind it,
// not two same-endpoint replacements.
func TestSameAddressReturnIsNotAReplacement(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	changes := []models.CertObservation{
		{ObservationType: models.ObsChange, ObservedAt: now, Fingerprint: "b", PreviousFingerprint: "a", IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1"},
		{ObservationType: models.ObsChange, ObservedAt: now.Add(time.Hour), Fingerprint: "a", PreviousFingerprint: "b", IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1"},
		{ObservationType: models.ObsChange, ObservedAt: now.Add(2 * time.Hour), Fingerprint: "b", PreviousFingerprint: "a", IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1"},
	}
	shape := analyzeChurnShape(changes, datedCerts("a", "b"))
	if shape.SameEndpointChanges != 1 || shape.RevisitEvents != 2 {
		t.Fatalf("same-endpoint=%d revisits=%d, want 1 and 2: %#v", shape.SameEndpointChanges, shape.RevisitEvents, shape)
	}
}

func TestSameKeyWithoutSameAddressReplacementLeavesRegister(t *testing.T) {
	item := models.Anomaly{Type: "same_key", Diagnosis: &models.CauseDiagnosis{PrimaryCode: "concurrent_same_key", ChurnShape: &models.ChurnShape{ChangeEvents: 19, RevisitEvents: 18, DistinctSPKIs: 1}}}
	if isIssueRegisterFinding(item) {
		t.Fatal("same-key pool sampling was listed as a same-key replacement")
	}
}

// s3.ssl.qhres2.com: the switch round recorded the predecessor; a later round
// for the same successor must keep following it.
func TestPredecessorCarriesToLaterRoundsOfSameSuccessor(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	probes, _ := json.Marshal([]models.EndpointProbe{{IPAddress: "192.0.2.1", Success: true, Fingerprint: "new"}})
	_, previous, _, _ := latestEndpointSurvey([]models.CertObservation{
		{ObservationType: models.ObsDeploymentFailure, ObservedAt: now, Fingerprint: "new", EndpointProbes: string(probes)},
		{ObservationType: models.ObsDeploymentFailure, ObservedAt: now.Add(-9 * time.Hour), Fingerprint: "new", PreviousFingerprint: "old", EndpointProbes: string(probes)},
		{ObservationType: models.ObsDeploymentFailure, ObservedAt: now.Add(-20 * time.Hour), Fingerprint: "other", PreviousFingerprint: "older", EndpointProbes: string(probes)},
	})
	if previous != "old" {
		t.Fatalf("previous = %q, want the successor's own predecessor", previous)
	}
}

// guzzoni.apple.com: each address renewed its own leaf (a->c on one, b->d on
// the other). The two current leaves are separate lineages, whatever their
// names or issuance times, so the split is per endpoint.
func TestSeparateAddressLineagesArePerEndpoint(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "c", IssuerCN: "CA", SANsHash: "node-1"},
		{IPAddress: "192.0.2.2", Success: true, Fingerprint: "d", IssuerCN: "CA", SANsHash: "node-2"},
	}
	topology, _ := json.Marshal(models.TopologySnapshot{ConsensusIPs: []string{"192.0.2.1", "192.0.2.2"}, PublicIPs: []string{"192.0.2.1", "192.0.2.2"}, ResolverQuorum: 2, ResolverAgreement: 1})
	before, _ := json.Marshal(map[string]string{"192.0.2.1": "a", "192.0.2.2": "b"})
	after, _ := json.Marshal(map[string]string{"192.0.2.1": "c", "192.0.2.2": "d"})
	var snapshots []models.MeasurementSnapshot
	for round := 1; round <= 6; round++ {
		assignment := after
		if round > 4 {
			assignment = before
		}
		snapshots = append(snapshots, models.MeasurementSnapshot{ObservedAt: now.Add(-time.Duration(round*12) * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: string(assignment), TopologyJSON: string(topology)})
	}
	d := analyzeEndpointDivergence(probes, snapshots, "c", now.Add(-72*time.Hour), now)
	if len(d.PredecessorEndpoints) != 0 || !d.IndependentLineages || d.Verdict != models.DivergencePerEndpoint {
		t.Fatalf("separate renewals were not read as per-endpoint certificates: %#v", d)
	}
}

// lws.xuexi.cn: the main handshake and the probe to the same address in one
// round got different self-signed leaves, so the address mints leaves per
// connection and the "change" is not a replacement.
func TestSameRoundSplitAddressIsNotAReplacement(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	var changes []models.CertObservation
	for index, leaf := range []string{"b", "c", "d"} {
		probes, _ := json.Marshal([]models.EndpointProbe{{IPAddress: "192.0.2.1", Success: true, Fingerprint: leaf + "-probe"}})
		changes = append(changes, models.CertObservation{ObservationType: models.ObsChange, ObservedAt: now.Add(time.Duration(index) * time.Hour), Fingerprint: leaf, PreviousFingerprint: "x" + leaf, IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1", EndpointProbes: string(probes)})
	}
	shape := analyzeChurnShape(changes, nil)
	if shape.SameEndpointChanges != 0 || shape.CoexistenceProofs != 3 || shape.Interpretation == models.ChurnTemporalReplacement {
		t.Fatalf("per-connection leaves read as replacements: %#v", shape)
	}
}

// datedCerts issues the named leaves one day apart, in order, so same-address
// changes between them can be read by issuance date.
func datedCerts(leaves ...string) map[string]models.Certificate {
	certs := make(map[string]models.Certificate, len(leaves))
	for index, leaf := range leaves {
		issued := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(index) * 24 * time.Hour)
		certs[leaf] = models.Certificate{Fingerprint: leaf, NotBefore: issued, NotAfter: issued.Add(90 * 24 * time.Hour)}
	}
	return certs
}

// m.me: one new leaf per day. The newest leaf reaching a second address is
// propagation, not a return; only an address stepping back to an older leaf
// is pool evidence, and then both mechanisms are reported.
func TestDailyRotationPropagatingAcrossAddresses(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	certs := datedCerts("d1", "d2", "d3", "d4")
	row := func(hours int, previous, current, address string) models.CertObservation {
		return models.CertObservation{ObservationType: models.ObsChange, ObservedAt: now.Add(time.Duration(hours) * time.Hour), PreviousFingerprint: previous, Fingerprint: current, IPAddress: address, PreviousIPAddress: address}
	}
	progress := []models.CertObservation{
		row(0, "d1", "d2", "192.0.2.1"),
		row(1, "d1", "d2", "192.0.2.2"), // newest leaf reaches the second address
		row(24, "d2", "d3", "192.0.2.1"),
		row(25, "d2", "d3", "192.0.2.2"),
	}
	shape := analyzeChurnShape(progress, certs)
	if shape.RevisitEvents != 0 || shape.SameEndpointChanges != 4 || shape.Interpretation != models.ChurnTemporalReplacement {
		t.Fatalf("daily rotation misread: %#v", shape)
	}
	// 192.0.2.1 served d3, then (unrecorded) d2 again, then d3: a step back.
	mixed := append(append([]models.CertObservation(nil), progress...), row(30, "d2", "d4", "192.0.2.1"))
	shape = analyzeChurnShape(mixed, certs)
	if shape.RevisitEvents != 1 || shape.SameEndpointChanges != 5 || shape.Interpretation != models.ChurnMixed {
		t.Fatalf("step back to an older leaf not reported beside the rotation: %#v", shape)
	}
}

// Without issuance dates a same-address change proves nothing either way.
func TestUndatedSameAddressChangeIsUndetermined(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	changes := []models.CertObservation{
		{ObservationType: models.ObsChange, ObservedAt: now, PreviousFingerprint: "a", Fingerprint: "b", IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1"},
		{ObservationType: models.ObsChange, ObservedAt: now.Add(time.Hour), PreviousFingerprint: "b", Fingerprint: "c", IPAddress: "192.0.2.1", PreviousIPAddress: "192.0.2.1"},
	}
	shape := analyzeChurnShape(changes, nil)
	if shape.SameEndpointChanges != 0 || shape.UndatedEndpointChanges != 2 || shape.Interpretation != models.ChurnUndetermined {
		t.Fatalf("undated changes decided something: %#v", shape)
	}
}

// vp-0405: each address shows the new leaf for a round and then its old leaf
// again. The addresses sit in different /16s, but that is not a stable
// multi-provider split: each address fronts servers holding different leaves.
func TestAddressReturningToOldLeafIsNotAProviderSplit(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old-a"},
		{IPAddress: "198.51.100.1", Success: true, Fingerprint: "old-b"},
	}
	topology, _ := json.Marshal(models.TopologySnapshot{ConsensusIPs: []string{"192.0.2.1", "198.51.100.1"}, PublicIPs: []string{"192.0.2.1", "198.51.100.1"}, ResolverQuorum: 2, ResolverAgreement: 1})
	var snapshots []models.MeasurementSnapshot
	for round, assignment := range []map[string]string{
		{"192.0.2.1": "old-a", "198.51.100.1": "old-b"},
		{"192.0.2.1": "old-a", "198.51.100.1": "new"},
		{"192.0.2.1": "old-a", "198.51.100.1": "old-b"},
		{"192.0.2.1": "new", "198.51.100.1": "old-b"},
		{"192.0.2.1": "old-a", "198.51.100.1": "old-b"},
	} {
		encoded, _ := json.Marshal(assignment)
		snapshots = append(snapshots, models.MeasurementSnapshot{ObservedAt: now.Add(-time.Duration((5-round)*12) * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: string(encoded), TopologyJSON: string(topology)})
	}
	d := analyzeEndpointDivergence(probes, snapshots, "", time.Time{}, now)
	if d.AddressReturns != 2 || d.IndependentLineages || d.Verdict != models.DivergencePropagating {
		t.Fatalf("address pools read as a provider split: %#v", d)
	}
}

// umwatson.events.data.microsoft.com: one renewal reaching three addresses is
// three replacements but one successor, so it is not frequent change.
func TestOneRenewalAcrossAddressesIsNotFrequent(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	var changes []models.CertObservation
	for index, address := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		changes = append(changes, models.CertObservation{ObservationType: models.ObsChange, ObservedAt: now.Add(time.Duration(index) * time.Hour), PreviousFingerprint: "old", Fingerprint: "new", IPAddress: address, PreviousIPAddress: address})
	}
	shape := analyzeChurnShape(changes, datedCerts("old", "new"))
	if shape.SameEndpointChanges != 3 || shape.ProvenSuccessors != 1 {
		t.Fatalf("replacements=%d successors=%d, want 3 and 1", shape.SameEndpointChanges, shape.ProvenSuccessors)
	}
	item := models.Anomaly{Type: "frequent_change", Diagnosis: &models.CauseDiagnosis{PrimaryCode: "automated_renewal_policy", ChurnShape: &shape}}
	if isIssueRegisterFinding(item) {
		t.Fatal("one renewal was listed as frequent change")
	}
}

// testRolloutReference installs a reference built from explicit upper bounds.
func testRolloutReference(t *testing.T, alertShare float64, upperHours ...float64) {
	previous := currentRolloutStandard.Load()
	t.Cleanup(func() { currentRolloutStandard.Store(previous) })
	sorted := append([]float64(nil), upperHours...)
	sortFloats(sorted)
	currentRolloutStandard.Store(&rolloutStandard{alertShare: alertShare, reference: &rollout.Reference{Completed: len(sorted), UpperHours: sorted}})
}

func sortFloats(values []float64) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func repeatHours(hours float64, count int) []float64 {
	values := make([]float64, count)
	for index := range values {
		values[index] = hours
	}
	return values
}

// Stuck is the alert share applied to the measured position: the same overlap
// is stuck against a reference of short rollouts and not stuck against one in
// which rollouts routinely take longer; with no alert share it is never stuck.
func TestStuckFollowsReferencePosition(t *testing.T) {
	probes, snapshots, now := rolloutFixture(false, 5)
	testRolloutReference(t, 0.99, repeatHours(10, 100)...)
	if d := analyzeEndpointDivergence(probes, snapshots, "old", now, now); !d.StrongEvidence || d.ReferenceFinishedWithin != 100 {
		t.Fatalf("overlap beyond every reference rollout was not stuck: %#v", d)
	}
	testRolloutReference(t, 0.99, append(repeatHours(10, 50), repeatHours(200, 50)...)...)
	if d := analyzeEndpointDivergence(probes, snapshots, "old", now, now); d.StrongEvidence || d.ReferenceFinishedWithin != 50 {
		t.Fatalf("overlap inside the reference was called stuck: %#v", d)
	}
	testRolloutReference(t, 0, repeatHours(10, 100)...)
	if d := analyzeEndpointDivergence(probes, snapshots, "old", now, now); d.StrongEvidence {
		t.Fatalf("stuck without a configured alert share: %#v", d)
	}
}

func globalEvidenceJSON(t *testing.T, probes ...models.GlobalHTTPSProbe) string {
	t.Helper()
	encoded, err := json.Marshal(models.GlobalProbeEvidence{HTTPS: probes})
	if err != nil {
		t.Fatalf("marshal global probe evidence: %v", err)
	}
	return string(encoded)
}

func TestGlobalProbesCorroboratePredecessorScope(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	oldNB, newNB := issuedOld(), issuedNew()
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old", IssuerCN: "CA", SANsHash: "names", NotBefore: oldNB},
		{IPAddress: "192.0.2.2", Success: true, Fingerprint: "new", IssuerCN: "CA", SANsHash: "names", NotBefore: newNB},
	}
	mustJSON := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}
		return string(encoded)
	}
	topology := mustJSON(models.TopologySnapshot{ConsensusIPs: []string{"192.0.2.1", "192.0.2.2"}, PublicIPs: []string{"192.0.2.1", "192.0.2.2"}, ResolverQuorum: 2, ResolverAgreement: 1})
	mixed := mustJSON(map[string]string{"192.0.2.1": "old", "192.0.2.2": "new"})
	onlyOld := mustJSON(map[string]string{"192.0.2.1": "old", "192.0.2.2": "old"})
	global := func() string {
		return globalEvidenceJSON(t,
			models.GlobalHTTPSProbe{Location: models.GlobalProbeLocation{Continent: "NA"}, ResolvedAddress: "192.0.2.1", TLSObserved: true, TLSAuthorized: true, Fingerprint: "old"},
			models.GlobalHTTPSProbe{Location: models.GlobalProbeLocation{Continent: "EU"}, ResolvedAddress: "192.0.2.1", TLSObserved: true, TLSAuthorized: true, Fingerprint: "old"},
			models.GlobalHTTPSProbe{Location: models.GlobalProbeLocation{Continent: "AS"}, ResolvedAddress: "192.0.2.2", TLSObserved: true, TLSAuthorized: true, Fingerprint: "new"},
		)
	}
	snapshots := []models.MeasurementSnapshot{
		{ObservedAt: now, ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: mixed, TopologyJSON: topology, GlobalProbesJSON: global()},
		{ObservedAt: now.Add(-24 * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: mixed, TopologyJSON: topology, GlobalProbesJSON: global()},
		{ObservedAt: now.Add(-48 * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: onlyOld, TopologyJSON: topology},
	}
	d := analyzeEndpointDivergence(probes, snapshots, "old", now.Add(-48*time.Hour), now)
	if got := strings.Join(d.GlobalHTTPSRegions, ","); got != "AS,EU,NA" {
		t.Fatalf("global regions = %q, want AS,EU,NA", got)
	}
	if got := strings.Join(d.GlobalPredecessorRegions, ","); got != "EU,NA" {
		t.Fatalf("global predecessor regions = %q, want EU,NA", got)
	}
	if d.GlobalConsecutivePredecessorRounds != 2 || d.GlobalPredecessorSpanHours != 24 {
		t.Fatalf("global predecessor continuity = %d rounds / %.1f h, want 2 / 24: %#v", d.GlobalConsecutivePredecessorRounds, d.GlobalPredecessorSpanHours, d)
	}
}

func TestGlobalProbesOnlyCorroborateMatchingDefectiveLeaf(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "bad", Findings: []models.TLSFinding{{Code: "hostname_mismatch"}}},
		{IPAddress: "192.0.2.2", Success: true, Fingerprint: "good"},
	}
	snapshot := models.MeasurementSnapshot{ObservedAt: now, GlobalProbesJSON: globalEvidenceJSON(t,
		models.GlobalHTTPSProbe{Location: models.GlobalProbeLocation{Continent: "NA"}, ResolvedAddress: "192.0.2.1", TLSObserved: true, TLSAuthorized: false, Fingerprint: "bad"},
		models.GlobalHTTPSProbe{Location: models.GlobalProbeLocation{Continent: "EU"}, ResolvedAddress: "192.0.2.2", TLSObserved: true, TLSAuthorized: false, Fingerprint: "other"},
	)}
	d := analyzeEndpointDivergence(probes, []models.MeasurementSnapshot{snapshot}, "", time.Time{}, now)
	if got := strings.Join(d.GlobalDefectiveRegions, ","); got != "NA" {
		t.Fatalf("global defective regions = %q, want NA", got)
	}
}

// wi.gov: the per-endpoint verdict is expected, but the split is a measured
// fact and the impact says so.
func TestPerEndpointImpactKeepsTheSplitFact(t *testing.T) {
	item, context := perEndpointFixture(true)
	diagnosis := inferTopologyDiagnosis(item, context)
	investigation := buildInvestigation(item, context, diagnosis)
	if investigation.FindingClass != models.FindingExpected || investigation.Impact == nil || investigation.Impact.SeverityCeiling != models.ImpactSplitView {
		t.Fatalf("per-endpoint impact = %#v", investigation.Impact)
	}
}

// onethingpcs: two /16s, one leaf each, but one address was seen moving from
// the old leaf to the new one. That observed replacement outranks the clean
// partition, so it is not a multi-provider split.
func TestObservedReplacementOutranksCleanPartition(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	probes := []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "new", NotBefore: issuedNew()},
		{IPAddress: "198.51.100.1", Success: true, Fingerprint: "old", NotBefore: issuedOld()},
	}
	topology, _ := json.Marshal(models.TopologySnapshot{ConsensusIPs: []string{"192.0.2.1", "198.51.100.1"}, PublicIPs: []string{"192.0.2.1", "198.51.100.1"}, ResolverQuorum: 2, ResolverAgreement: 1})
	var snapshots []models.MeasurementSnapshot
	for round := 1; round <= 6; round++ {
		assignment := map[string]string{"192.0.2.1": "new", "198.51.100.1": "old"}
		if round > 4 {
			assignment["192.0.2.1"] = "old"
		}
		encoded, _ := json.Marshal(assignment)
		snapshots = append(snapshots, models.MeasurementSnapshot{ObservedAt: now.Add(-time.Duration(round*12) * time.Hour), ResolverQuorum: 2, ResolverAgreement: 1, EndpointFingerprintsJSON: string(encoded), TopologyJSON: string(topology)})
	}
	d := analyzeEndpointDivergence(probes, snapshots, "old", now.Add(-48*time.Hour), now)
	if d.IndependentLineages || d.Verdict == models.DivergenceIntentionalMultiCDN || len(d.ActivePredecessorEndpoints) != 1 {
		t.Fatalf("observed replacement was read as a provider split: %#v", d)
	}
}

// A probe whose repeated handshakes gave two leaves is proven in that round to
// front several servers; the proof says so, and the split is not per endpoint
// or multi-provider.
func TestInRoundPoolIsProven(t *testing.T) {
	item, context := perEndpointFixture(true)
	var probes []models.EndpointProbe
	_ = json.Unmarshal([]byte(context.observations[0].EndpointProbes), &probes)
	probes[0].Handshakes = 3
	probes[0].OtherFingerprints = []string{"leaf-z"}
	encoded, _ := json.Marshal(probes)
	context.observations[0].EndpointProbes = string(encoded)
	diagnosis := inferTopologyDiagnosis(item, context)
	d := diagnosis.Divergence
	if d.AddressPools != 1 || d.IndependentLineages || diagnosis.PrimaryCode == models.DivergencePerEndpoint || diagnosis.PrimaryCode == models.DivergenceIntentionalMultiCDN {
		t.Fatalf("in-round pool not used: %#v", d)
	}
	investigation := buildInvestigation(item, context, diagnosis)
	if !hasProofLabel(investigation.Proof, "Several servers behind one address") {
		t.Fatalf("pool proof step missing: %#v", investigation.Proof)
	}
}
