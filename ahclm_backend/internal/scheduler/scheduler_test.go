package scheduler

import (
	"testing"
	"time"

	"ahclm/internal/models"
)

func testCfg() *models.SchedulerConfig {
	return &models.SchedulerConfig{
		Milestones:         []int{30, 14, 10, 7, 3, 1},
		PostExpiryChecks:   []int{1, 3, 7},
		BaselineInterval:   7 * 24 * time.Hour,
		NearExpiryInterval: 6 * time.Hour,
		NearExpiryWindow:   2 * 24 * time.Hour,
		MinGap:             time.Hour,
	}
}

var base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestComputeNextScan_FarFromExpiry_UsesBaseline(t *testing.T) {
	cfg := testCfg()
	notAfter := base.Add(100 * 24 * time.Hour)
	got := computeNextScan(cfg, base, notAfter, nil, nil, false)
	want := base.Add(7 * 24 * time.Hour) // nearest milestone (30d before) is 70d out > baseline
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestComputeNextScan_LandsOnNextMilestone(t *testing.T) {
	cfg := testCfg()
	notAfter := base.Add(8 * 24 * time.Hour) // 8d out → 7d-before milestone is tomorrow
	got := computeNextScan(cfg, base, notAfter, nil, nil, false)
	want := base.Add(1 * 24 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestComputeNextScan_NearExpiryAccelerates(t *testing.T) {
	cfg := testCfg()
	notAfter := base.Add(12 * time.Hour) // within 2 days
	got := computeNextScan(cfg, base, notAfter, nil, nil, false)
	want := base.Add(6 * time.Hour) // near-expiry cadence beats the 12h expiry boundary
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestComputeNextScan_RespectsMinGap(t *testing.T) {
	cfg := testCfg()
	notAfter := base.Add(30 * time.Minute) // expiry boundary sooner than MinGap
	got := computeNextScan(cfg, base, notAfter, nil, nil, false)
	want := base.Add(time.Hour)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestComputeNextScan_AlwaysProgresses(t *testing.T) {
	cfg := testCfg()
	// Long-expired cert: no future milestone; must still schedule in the future.
	notAfter := base.Add(-100 * 24 * time.Hour)
	got := computeNextScan(cfg, base, notAfter, nil, nil, false)
	if !got.After(base) {
		t.Fatalf("next scan %v not after now %v", got, base)
	}
}

func TestComputeNextScan_ExpiredCertificateKeepsNearExpiryCadence(t *testing.T) {
	cfg := testCfg()
	notAfter := base.Add(-100 * 24 * time.Hour)
	got := computeNextScan(cfg, base, notAfter, nil, nil, false)
	want := base.Add(6 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("expired certificate next scan = %v, want %v", got, want)
	}
}

func TestComputeNextScan_AlignsToARIWindow(t *testing.T) {
	cfg := testCfg()
	notAfter := base.Add(100 * 24 * time.Hour) // far off → baseline would win (7d)
	ariStart := base.Add(3 * 24 * time.Hour)   // CA recommends renewal in 3 days
	got := computeNextScan(cfg, base, notAfter, &ariStart, nil, false)
	if !got.Equal(ariStart) {
		t.Fatalf("got %v, want ARI window start %v", got, ariStart)
	}
}

func TestComputeNextScan_AlignsToARINextPoll(t *testing.T) {
	cfg := testCfg()
	notAfter := base.Add(100 * 24 * time.Hour)
	ariNextPoll := base.Add(24 * time.Hour)
	got := computeNextScan(cfg, base, notAfter, nil, &ariNextPoll, false)
	if !got.Equal(ariNextPoll) {
		t.Fatalf("got %v, want ARI next poll %v", got, ariNextPoll)
	}
}

func TestRenewalWatcherUsesIndependentWindowAndARIStart(t *testing.T) {
	now := base
	notAfter := now.Add(20 * time.Hour)
	window := 24 * time.Hour
	if !renewalWatcherEligible(now, notAfter, nil, window) {
		t.Fatal("certificate without ARI should enter watcher window")
	}
	if renewalWatcherEligible(now, now.Add(30*time.Hour), nil, window) {
		t.Fatal("watcher should not use the broader ordinary near-expiry window")
	}
	ariStart := now.Add(time.Hour)
	if renewalWatcherEligible(now, notAfter, &ariStart, window) {
		t.Fatal("watcher must wait for the ARI window start")
	}
	ariStart = now.Add(-time.Hour)
	if !renewalWatcherEligible(now, notAfter, &ariStart, window) {
		t.Fatal("watcher should start after ARI opens inside the expiry window")
	}
	if renewalWatcherEligible(now, now, nil, window) {
		t.Fatal("expired certificate must not start another watcher")
	}
}

func TestComputeNextScanWithEvidence_AlignsToRevocationPoll(t *testing.T) {
	cfg := testCfg()
	notAfter := base.Add(100 * 24 * time.Hour)
	revocationPoll := base.Add(2 * 24 * time.Hour)
	got := computeNextScanWithEvidence(cfg, base, notAfter, nil, nil, &revocationPoll, false)
	if !got.Equal(revocationPoll) {
		t.Fatalf("got %v, want revocation poll %v", got, revocationPoll)
	}
}

func TestEvidenceCandidateAfter(t *testing.T) {
	cert := &models.Certificate{Fingerprint: "same", NotAfter: base.Add(30 * 24 * time.Hour)}
	result := &models.ScanResult{Success: true, Cert: cert}
	active := &models.DomainCertificate{CurrentFingerprint: "same", Status: models.StatusActive, EvidenceStatus: models.EvidenceStatusComplete}
	if evidenceCandidateAfter(active, result, base) {
		t.Fatal("unchanged, healthy, far-from-expiry certificate should not trigger deep evidence")
	}

	changed := *active
	changed.CurrentFingerprint = "old"
	if !evidenceCandidateAfter(&changed, result, base) {
		t.Fatal("certificate fingerprint change should trigger deep evidence")
	}

	pending := *active
	pending.EvidenceStatus = models.EvidenceStatusPending
	if !evidenceCandidateAfter(&pending, result, base) {
		t.Fatal("pending evidence should trigger a retry")
	}

	revoked := *active
	revoked.RevocationStatus = models.RevocationRevoked
	if !evidenceCandidateAfter(&revoked, result, base) {
		t.Fatal("previously revoked certificate should trigger a fresh evidence check")
	}

	nearExpiry := *active
	nearExpiryCert := *cert
	nearExpiryCert.NotAfter = base.Add(7 * 24 * time.Hour)
	nearExpiryResult := &models.ScanResult{Success: true, Cert: &nearExpiryCert}
	if !evidenceCandidateAfter(&nearExpiry, nearExpiryResult, base) {
		t.Fatal("near-expiry certificate should trigger deep evidence")
	}
}

func TestCDNVendorResultRecognizesMultipleProviders(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
	}{
		{name: "www.example.com.cdn.cloudflare.net", want: "cloudflare"},
		{name: "global.prod.fastly.net", want: "fastly"},
		{name: "d111111abcdef8.cloudfront.net", want: "cloudfront"},
	} {
		result := &models.ScanResult{Topology: &models.TopologySnapshot{CNAMEChain: []string{tc.name}}}
		if got := cdnVendorResult(result); got != tc.want {
			t.Errorf("cdnVendorResult(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
	result := &models.ScanResult{Topology: &models.TopologySnapshot{CNAMEChain: []string{
		"global.prod.fastly.net",
		"www.example.com.cdn.cloudflare.net",
	}}}
	if got := cdnVendorResult(result); got != "multi-cdn" {
		t.Fatalf("multi-provider result = %q, want multi-cdn", got)
	}
}

func TestComputeNextScan_EmergencyDensifies(t *testing.T) {
	cfg := testCfg()
	notAfter := base.Add(100 * 24 * time.Hour) // far off → baseline 7d normally
	got := computeNextScan(cfg, base, notAfter, nil, nil, true)
	want := base.Add(6 * time.Hour) // emergency pulls to near-expiry cadence
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v (emergency near-expiry cadence)", got, want)
	}
}

func TestNewObservationSnapshotsRevocationEvidence(t *testing.T) {
	observedAt := base.Add(2 * time.Hour)
	expectedCheckedAt := observedAt.Add(4 * time.Second)
	expectedRevokedAt := observedAt.Add(-time.Hour)
	checkedAt := expectedCheckedAt
	revokedAt := expectedRevokedAt
	result := &models.ScanResult{
		ScannedAt:            observedAt,
		ScanDuration:         4 * time.Second,
		RevocationStatus:     models.RevocationRevoked,
		RevocationCheckedVia: models.CheckedViaCRL,
		RevocationCheckedAt:  &checkedAt,
		RevokedAt:            &revokedAt,
		RevocationReason:     "keyCompromise",
	}
	cert := &models.Certificate{ID: 42, Fingerprint: "certificate-fingerprint"}

	observation := (&Scheduler{}).newObs("example.com", cert, models.ObsRevocationChange, "", 30, result)

	// Mutate the result after snapshotting to ensure the event owns its evidence.
	changedCheckedAt := checkedAt.Add(time.Minute)
	changedRevokedAt := revokedAt.Add(time.Minute)
	*result.RevocationCheckedAt = changedCheckedAt
	*result.RevokedAt = changedRevokedAt
	result.RevocationReason = "superseded"

	if observation.RevocationCheckedVia != models.CheckedViaCRL {
		t.Fatalf("checked via = %q, want %q", observation.RevocationCheckedVia, models.CheckedViaCRL)
	}
	if observation.RevocationCheckedAt == nil || !observation.RevocationCheckedAt.Equal(expectedCheckedAt) {
		t.Fatalf("checked at = %v, want %v", observation.RevocationCheckedAt, expectedCheckedAt)
	}
	if observation.RevokedAt == nil || !observation.RevokedAt.Equal(expectedRevokedAt) {
		t.Fatalf("revoked at = %v, want %v", observation.RevokedAt, expectedRevokedAt)
	}
	if observation.RevocationReason != "keyCompromise" {
		t.Fatalf("reason = %q, want keyCompromise", observation.RevocationReason)
	}
}

func TestWindowChanged(t *testing.T) {
	t0 := base
	t1 := base.Add(2 * time.Hour)
	tSame := base.Add(30 * time.Minute)
	if windowChanged(nil, nil, time.Hour) {
		t.Error("nil→nil should not be a change")
	}
	if !windowChanged(nil, &t0, time.Hour) {
		t.Error("nil→value (first sighting) should be a change")
	}
	if !windowChanged(&t0, &t1, time.Hour) {
		t.Error("2h shift should be a change")
	}
	if windowChanged(&t0, &tSame, time.Hour) {
		t.Error("30m shift should NOT be a change")
	}
}

func TestCrossedMilestones(t *testing.T) {
	cfg := testCfg()

	cases := []struct {
		name       string
		prev, cur  int
		wantLabels []string
	}{
		{"cross 7", 8, 6, []string{"7d_before_expiry"}},
		{"cross 7 and 3", 8, 2, []string{"7d_before_expiry", "3d_before_expiry"}},
		{"cross 1", 2, 1, []string{"1d_before_expiry"}},
		{"no movement", 5, 5, nil},
		{"post-expiry 1d", 1, -2, []string{"1d_after_expiry"}},
		{"expiry into post 1,3", 5, -4, []string{"3d_before_expiry", "1d_before_expiry", "1d_after_expiry", "3d_after_expiry"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := crossedMilestones(cfg, tc.prev, tc.cur)
			if len(got) != len(tc.wantLabels) {
				t.Fatalf("got %d milestones %+v, want %v", len(got), got, tc.wantLabels)
			}
			set := map[string]bool{}
			for _, g := range got {
				set[g.Label] = true
			}
			for _, w := range tc.wantLabels {
				if !set[w] {
					t.Fatalf("missing milestone %s in %+v", w, got)
				}
			}
		})
	}
}

func TestPriorityForExpiry(t *testing.T) {
	if p := priorityForExpiry(base, base.Add(12*time.Hour)); p != 100 {
		t.Fatalf("≤1d priority = %d, want 100", p)
	}
	if p := priorityForExpiry(base, base.Add(200*24*time.Hour)); p != 30 {
		t.Fatalf("far priority = %d, want 30", p)
	}
	if p := priorityForExpiry(base, base.Add(-24*time.Hour)); p != 85 {
		t.Fatalf("expired priority = %d, want 85", p)
	}
}

func TestInconclusiveProbeDoesNotForceRecheck(t *testing.T) {
	if hasActionableTLSFinding([]models.TLSFinding{{Code: "endpoint_probe_inconclusive"}}) {
		t.Fatal("an inconclusive probe forced an hourly recheck")
	}
	if !hasActionableTLSFinding([]models.TLSFinding{{Code: "hostname_mismatch"}}) {
		t.Fatal("a real TLS finding did not force a recheck")
	}
}

func TestRolloutInProgressFromAddressChange(t *testing.T) {
	previous := []models.MeasurementSnapshot{{EndpointFingerprintsJSON: `{"198.18.0.1":"a","8.8.8.8":"a"}`}}
	result := &models.ScanResult{EndpointProbes: []models.EndpointProbe{
		{IPAddress: "198.18.0.1", Success: true, Fingerprint: "a"},
		{IPAddress: "8.8.8.8", Success: true, Fingerprint: "b"},
	}}
	if !rolloutInProgress(result, previous, nil) {
		t.Fatal("an address moving to a new leaf beside the old one is a rollout in progress")
	}
	steady := []models.MeasurementSnapshot{{EndpointFingerprintsJSON: `{"198.18.0.1":"a","8.8.8.8":"b"}`}}
	if rolloutInProgress(result, steady, nil) {
		t.Fatal("a steady two-leaf assignment was treated as a rollout")
	}
}
