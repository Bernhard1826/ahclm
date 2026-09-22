package scheduler

import (
	"encoding/json"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestTopologyTransitionRequiresResolverQuorum(t *testing.T) {
	old := &models.DomainCertificate{
		ResolvedIPs:               `["192.0.2.1"]`,
		ConsensusIPs:              `["192.0.2.1"]`,
		TopologyResolverQuorum:    1,
		TopologyResolverAgreement: 1,
	}
	result := &models.ScanResult{
		ResolvedIPsKnown: true,
		ResolvedIPs:      []string{"198.51.100.1"},
		Topology: &models.TopologySnapshot{
			ConsensusIPs:      []string{"198.51.100.1"},
			ResolverQuorum:    1,
			ResolverAgreement: 1,
		},
	}
	if topologyTransition(old, result, []string{"192.0.2.1"}, result.ResolvedIPs) {
		t.Fatal("one resolver must not establish a topology transition")
	}
	result.Topology.ResolverQuorum = 3
	result.Topology.ResolverAgreement = 0.67
	old.TopologyResolverQuorum = 3
	old.TopologyResolverAgreement = 0.67
	if !topologyTransition(old, result, []string{"192.0.2.1"}, result.ResolvedIPs) {
		t.Fatal("a quorum-confirmed address change should establish a transition")
	}
}

func TestStaleEndpointEvidenceNeedsOldAndNewCertificates(t *testing.T) {
	now := time.Now()
	dc := &models.DomainCertificate{}
	result := &models.ScanResult{Cert: &models.Certificate{Fingerprint: "new"}, EndpointProbes: []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old"},
		{IPAddress: "198.51.100.1", Success: true, Fingerprint: "new"},
	}, ScannedAt: now}
	if !staleEndpointEvidence(dc, result, "old", []string{"192.0.2.1"}, []string{"198.51.100.1"}) {
		t.Fatal("old edge serving predecessor and new edge serving successor should be stale evidence")
	}
	result.Cert.Fingerprint = "old"
	result.EndpointProbes[1].Fingerprint = "old"
	if staleEndpointEvidence(dc, result, "old", []string{"192.0.2.1"}, []string{"198.51.100.1"}) {
		t.Fatal("a same-leaf topology move must not be classified as stale")
	}
}

func TestDeploymentFailureSuppressesStableCDNDiversity(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	stable := []models.MeasurementSnapshot{
		{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"})},
		{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"})},
		{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"})},
	}
	current := &models.ScanResult{EndpointProbes: []models.EndpointProbe{{IPAddress: "192.0.2.1", Success: true, Fingerprint: "a"}, {IPAddress: "198.51.100.1", Success: true, Fingerprint: "b"}}}
	if deploymentFailureEvidence(&models.DomainCertificate{}, current, stable, "a", false) {
		t.Fatal("stable per-IP CDN diversity must be treated as a baseline")
	}
	transition := append([]models.MeasurementSnapshot{}, stable[1:]...)
	transition = append(transition, models.MeasurementSnapshot{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"192.0.2.1": "c", "198.51.100.1": "b"})})
	changed := &models.ScanResult{EndpointProbes: []models.EndpointProbe{{IPAddress: "192.0.2.1", Success: true, Fingerprint: "a"}, {IPAddress: "198.51.100.1", Success: true, Fingerprint: "c"}}}
	if !deploymentFailureEvidence(&models.DomainCertificate{}, changed, transition, "a", true) {
		t.Fatal("a changed per-IP assignment during replacement should be a rollout candidate")
	}
}

func TestEndpointMapChangedDetectsAddressChurn(t *testing.T) {
	if !endpointMapChanged(map[string]string{"192.0.2.1": "a"}, map[string]string{"198.51.100.1": "a"}) {
		t.Fatal("replacing an endpoint must count as a mapping transition")
	}
}

func TestUpdateEndpointStatesRetainsPerIPHistory(t *testing.T) {
	dc := &models.DomainCertificate{}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	updateEndpointStates(dc, []models.EndpointProbe{{IPAddress: "192.0.2.1", Success: true, Fingerprint: "a"}}, at)
	updateEndpointStates(dc, []models.EndpointProbe{{IPAddress: "192.0.2.1", Success: true, Fingerprint: "b"}}, at.Add(time.Hour))
	var states map[string]models.EndpointState
	if err := json.Unmarshal([]byte(dc.EndpointStates), &states); err != nil {
		t.Fatal(err)
	}
	state := states["192.0.2.1"]
	if state.Observations != 2 || state.Fingerprint != "b" || !state.FirstSeenAt.Equal(at) {
		t.Fatalf("unexpected endpoint state: %#v", state)
	}
}

// A round that reaches the predecessor and the successor at the same time has
// shown the two certificates are deployed concurrently. Counting that as a
// replacement is what inflates the change counter on load-balanced domains.
func TestSameIPReplacementsCountsOnlyOverlappingAddresses(t *testing.T) {
	previous := map[string]models.EndpointState{
		"192.0.2.1":   {IPAddress: "192.0.2.1", Fingerprint: "a"},
		"198.51.100.1": {IPAddress: "198.51.100.1", Fingerprint: "b"},
	}
	got := sameIPReplacements(previous, map[string]string{"192.0.2.1": "c", "203.0.113.1": "d"})
	if len(got) != 1 || got[0].IP != "192.0.2.1" || got[0].Previous != "a" || got[0].Current != "c" {
		t.Fatalf("overlapping replacement = %#v, want one change on 192.0.2.1", got)
	}
	if got := sameIPReplacements(previous, map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"}); len(got) != 0 {
		t.Fatalf("unchanged overlapping leaves must not count: %#v", got)
	}
	if got := sameIPReplacements(previous, map[string]string{"203.0.113.1": "z"}); len(got) != 0 {
		t.Fatalf("a disjoint new address is not a replacement: %#v", got)
	}
	mixed := map[string]string{"192.0.2.1": "a", "198.51.100.1": "b"}
	if got := sameIPReplacements(previous, mixed); len(got) != 0 {
		t.Fatalf("two live addresses keeping their own leaves is not a replacement: %#v", got)
	}
}

func TestCurrentEndpointLeavesPrefersProbeMap(t *testing.T) {
	result := &models.ScanResult{
		Cert: &models.Certificate{Fingerprint: "baseline"},
		ConnectionInfo: &models.ConnectionInfo{IPAddress: "192.0.2.1"},
		EndpointProbes: []models.EndpointProbe{
			{IPAddress: "192.0.2.1", Success: true, Fingerprint: "a"},
			{IPAddress: "198.51.100.1", Success: true, Fingerprint: "b"},
		},
	}
	got := currentEndpointLeaves(result)
	if got["192.0.2.1"] != "a" || got["198.51.100.1"] != "b" {
		t.Fatalf("leaves = %#v", got)
	}
}

func TestClassifyCertificateChangeDetectsConcurrentDeployment(t *testing.T) {
	result := &models.ScanResult{EndpointProbes: []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "old"},
		{IPAddress: "198.51.100.1", Success: true, Fingerprint: "new"},
	}}
	if got := classifyCertificateChange(result, "old", "new", "192.0.2.1", "198.51.100.1"); got != models.ChangeClassCoexisting {
		t.Fatalf("class = %q, want coexisting leaves", got)
	}
	single := &models.ScanResult{EndpointProbes: []models.EndpointProbe{
		{IPAddress: "192.0.2.1", Success: true, Fingerprint: "new"},
	}}
	if got := classifyCertificateChange(single, "old", "new", "192.0.2.1", "192.0.2.1"); got != models.ChangeClassReplacement {
		t.Fatalf("class = %q, want a same-endpoint replacement", got)
	}
	if got := classifyCertificateChange(single, "old", "new", "192.0.2.1", "198.51.100.1"); got != models.ChangeClassEndpointSampling {
		t.Fatalf("class = %q, want endpoint sampling", got)
	}
	if got := classifyCertificateChange(single, "old", "new", "", "198.51.100.1"); got != models.ChangeClassUnknown {
		t.Fatalf("class = %q, want unknown without an endpoint comparison", got)
	}
}

// CDN edge addresses rotate on nearly every query. Keying the stability test on
// the exact address meant a permanently stable arrangement never accumulated a
// single stable round, so every round looked like a fresh transition.
func TestStableEndpointDiversitySurvivesEdgeAddressRotation(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	rotating := []models.MeasurementSnapshot{
		{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"23.43.51.10": "a", "104.16.7.9": "b"})},
		{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"23.43.99.4": "a", "104.16.200.1": "b"})},
	}
	current := map[string]string{"23.43.12.55": "a", "104.16.31.77": "b"}
	if !stableEndpointDiversity(rotating, current, 2) {
		t.Fatal("address rotation inside one allocation must not reset the stability baseline")
	}
	moved := map[string]string{"23.43.12.55": "b", "104.16.31.77": "a"}
	if stableEndpointDiversity(rotating, moved, 2) {
		t.Fatal("swapping which provider serves which certificate is a real assignment change")
	}
}

// The deployment-failure detector must stop re-firing on an arrangement that
// only changed its edge addresses.
func TestDeploymentFailureIgnoresEdgeAddressRotation(t *testing.T) {
	mapJSON := func(value map[string]string) string { encoded, _ := json.Marshal(value); return string(encoded) }
	previous := []models.MeasurementSnapshot{
		{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"23.43.51.10": "a", "104.16.7.9": "b"})},
		{FingerprintCount: 2, EndpointFingerprintsJSON: mapJSON(map[string]string{"23.43.99.4": "a", "104.16.200.1": "b"})},
	}
	rotated := &models.ScanResult{EndpointProbes: []models.EndpointProbe{
		{IPAddress: "23.43.12.55", Success: true, Fingerprint: "a"},
		{IPAddress: "104.16.31.77", Success: true, Fingerprint: "b"},
	}}
	if deploymentFailureEvidence(&models.DomainCertificate{}, rotated, previous, "a", false) {
		t.Fatal("rotating edge addresses under a stable assignment must not raise a deployment finding")
	}
}
