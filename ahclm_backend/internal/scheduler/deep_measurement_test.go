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
