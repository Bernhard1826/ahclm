package propagation

import (
	"strings"
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestPropagationObservationsRequireTargetAtEveryConfiguredRegion(t *testing.T) {
	collectedAt := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	evidence := &models.GlobalProbeEvidence{
		CollectedAt: collectedAt,
		HTTPS: []models.GlobalHTTPSProbe{
			{Location: models.GlobalProbeLocation{Continent: "NA", City: "New York"}, Fingerprint: "AA:AA", TLSObserved: true},
			{Location: models.GlobalProbeLocation{Continent: "EU", City: "Paris"}, Fingerprint: "bb", TLSObserved: true},
			{Location: models.GlobalProbeLocation{Continent: "AS", City: "Tokyo"}, Fingerprint: "bb", TLSObserved: true},
			// A second probe in one continent must not add a second vote.
			{Location: models.GlobalProbeLocation{Continent: "NA", City: "Chicago"}, Fingerprint: "bb", TLSObserved: true},
			// A fingerprint without a completed TLS observation cannot count.
			{Location: models.GlobalProbeLocation{Continent: "SA", City: "Sao Paulo"}, Fingerprint: "aa", TLSObserved: false},
		},
	}

	observations, targetCount, expectedCount := propagationObservations(evidence, []string{"NA", "EU", "AS", "SA"}, "aaaa", "bb")
	if len(observations) != 4 {
		t.Fatalf("got %d location observations, want 4", len(observations))
	}
	if targetCount != 1 || expectedCount != 4 {
		t.Fatalf("target coverage = %d/%d, want 1/4", targetCount, expectedCount)
	}
	if observations[0].Fingerprint != "aaaa" || !observations[0].IsTarget {
		t.Fatalf("target fingerprint was not normalized: %#v", observations[0])
	}
	if !observations[1].IsPrevious || !observations[2].IsPrevious {
		t.Fatalf("previous leaves not identified: %#v", observations)
	}
	if observations[3].IsTarget || observations[3].IsPrevious || observations[3].TLSObserved {
		t.Fatalf("unobserved handshake incorrectly counted: %#v", observations[3])
	}
}

func TestNextStableRoundsResetsOnAnyIncompleteRegion(t *testing.T) {
	prior := []models.CDNPropagationRound{
		{RoundNumber: 1, Complete: true},
		{RoundNumber: 2, Complete: false},
		{RoundNumber: 3, Complete: true},
	}
	if got := nextStableRounds(prior, true); got != 2 {
		t.Fatalf("stable rounds = %d, want 2", got)
	}
	if got := nextStableRounds(prior, false); got != 0 {
		t.Fatalf("incomplete round stable count = %d, want 0", got)
	}
}

func TestPropagationWatcherUsesFirstLeafAsPerRegionBaseline(t *testing.T) {
	evidence := &models.GlobalProbeEvidence{CollectedAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC), HTTPS: []models.GlobalHTTPSProbe{
		{Location: models.GlobalProbeLocation{Continent: "NA"}, Fingerprint: "bb", TLSObserved: true},
		{Location: models.GlobalProbeLocation{Continent: "EU"}, Fingerprint: "aa", TLSObserved: true},
	}}
	prior := &models.CDNPropagationReport{Locations: []models.CDNPropagationLocationSummary{
		{LocationKey: "NA", LatestFingerprint: "aa", LastTLSObserved: true},
	}}
	observations, changed, expected := propagationWatcherObservations(evidence, []string{"NA", "EU"}, prior)
	if expected != 2 || changed != 1 {
		t.Fatalf("watcher coverage/change count = %d/%d, want 1 change over 2 regions", changed, expected)
	}
	if !observations[0].FingerprintChanged || observations[0].ChangeFromFingerprint != "aa" || observations[0].Fingerprint != "bb" {
		t.Fatalf("old/new leaf transition was not retained: %#v", observations[0])
	}
	if observations[1].FingerprintChanged || !observations[1].IsPrevious {
		t.Fatalf("first-seen EU leaf should establish its baseline: %#v", observations[1])
	}
}

func TestPropagationWatcherCompletesOnlyAfterEveryRegionChangesAndStabilizes(t *testing.T) {
	configured := []string{"NA", "EU"}
	baseline := &models.CDNPropagationReport{Locations: []models.CDNPropagationLocationSummary{
		{LocationKey: "NA", BaselineFingerprint: "aa", LatestFingerprint: "aa", LastTLSObserved: true},
		{LocationKey: "EU", BaselineFingerprint: "bb", LatestFingerprint: "bb", LastTLSObserved: true},
	}}
	evidence := &models.GlobalProbeEvidence{HTTPS: []models.GlobalHTTPSProbe{
		{Location: models.GlobalProbeLocation{Continent: "NA"}, Fingerprint: "cc", TLSObserved: true},
		{Location: models.GlobalProbeLocation{Continent: "EU"}, Fingerprint: "dd", TLSObserved: true},
	}}
	observations, changed, expected := propagationWatcherObservations(evidence, configured, baseline)
	if changed != expected || watcherRoundStable(observations, configured, baseline) {
		t.Fatalf("first round where all regions change must start, not complete, convergence: changed=%d expected=%d", changed, expected)
	}

	// The next round must repeat the same changed fingerprints in every region.
	priorChanged := &models.CDNPropagationReport{Locations: []models.CDNPropagationLocationSummary{
		{LocationKey: "NA", BaselineFingerprint: "aa", LatestFingerprint: "cc", LastTLSObserved: true},
		{LocationKey: "EU", BaselineFingerprint: "bb", LatestFingerprint: "dd", LastTLSObserved: true},
	}}
	observations, changed, expected = propagationWatcherObservations(evidence, configured, priorChanged)
	if changed != expected || !watcherRoundStable(observations, configured, priorChanged) {
		t.Fatal("repeated changed fingerprints across every region should count as stable")
	}
	stable := nextStableRounds([]models.CDNPropagationRound{{Complete: true}}, watcherRoundStable(observations, configured, priorChanged))
	if stable != 2 {
		t.Fatalf("second consecutive stable round count = %d, want 2", stable)
	}

	// A rollback to the original leaf removes that region from changed coverage
	// and resets the convergence condition.
	rollback := &models.GlobalProbeEvidence{HTTPS: []models.GlobalHTTPSProbe{
		{Location: models.GlobalProbeLocation{Continent: "NA"}, Fingerprint: "aa", TLSObserved: true},
		{Location: models.GlobalProbeLocation{Continent: "EU"}, Fingerprint: "dd", TLSObserved: true},
	}}
	_, changed, expected = propagationWatcherObservations(rollback, configured, baseline)
	if changed == expected {
		t.Fatal("return to the baseline leaf must remove the region from changed coverage")
	}
	if got := nextStableRounds([]models.CDNPropagationRound{{Complete: true}}, false); got != 0 {
		t.Fatalf("unstable round should reset stable counter to 0, got %d", got)
	}
}

func TestOriginRequestRequiresFreshOriginConnectionEvidence(t *testing.T) {
	target := strings.Repeat("ab", 32)
	good := models.GlobalHTTPSProbe{Location: models.GlobalProbeLocation{Continent: "NA"}, Status: "finished", HTTPStatus: 200, TLSObserved: true, TLSAuthorized: true, Fingerprint: "edge-cert", OriginFingerprint: target, RequestNonce: "fresh", OriginProbeNonce: "fresh", OriginTLSResumed: "false"}
	for _, tc := range []struct {
		name   string
		mutate func(*models.GlobalHTTPSProbe)
		want   bool
	}{
		{"fresh target", func(p *models.GlobalHTTPSProbe) {}, true},
		{"cached response", func(p *models.GlobalHTTPSProbe) { p.OriginProbeNonce = "stale" }, false},
		{"old origin connection", func(p *models.GlobalHTTPSProbe) { p.OriginFingerprint = strings.Repeat("cd", 32) }, false},
		{"HTTP only", func(p *models.GlobalHTTPSProbe) { p.OriginFingerprint = "" }, false},
		{"resumed TLS", func(p *models.GlobalHTTPSProbe) { p.OriginTLSResumed = "true" }, false},
		{"missing full handshake evidence", func(p *models.GlobalHTTPSProbe) { p.OriginTLSResumed = "" }, false},
		{"TLS error", func(p *models.GlobalHTTPSProbe) { p.TLSAuthorized = false }, false},
		{"origin failure", func(p *models.GlobalHTTPSProbe) { p.HTTPStatus = 525 }, false},
		{"unfinished", func(p *models.GlobalHTTPSProbe) { p.Status = "in-progress" }, false},
		{"provider error", func(p *models.GlobalHTTPSProbe) { p.Error = "connection reset" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := good
			tc.mutate(&probe)
			evidence := &models.GlobalProbeEvidence{HTTPS: []models.GlobalHTTPSProbe{probe}}
			rows, count, expected := originRequestObservations(evidence, []string{"NA", "EU"}, 200, target)
			if expected != 2 || len(rows) != 2 {
				t.Fatalf("missing regions must be retained: %+v", rows)
			}
			byKey := map[string]models.CDNPropagationObservation{}
			for _, row := range rows {
				byKey[row.LocationKey] = row
			}
			if byKey["NA"].OriginVerified != tc.want || byKey["NA"].IsTarget != tc.want || (count == 1) != tc.want {
				t.Fatalf("incorrect origin proof: %+v", rows)
			}
			if byKey["EU"].IsTarget || byKey["EU"].Error == "" {
				t.Fatalf("missing EU result falsely counted: %+v", rows)
			}
		})
	}
	rows, count, _ := originRequestObservations(nil, []string{"NA"}, 200, target)
	if count != 0 || len(rows) != 1 {
		t.Fatal("nil evidence lost missing region")
	}
}

func TestAutomaticPropagationVendorPolicy(t *testing.T) {
	cfg := &models.CDNPropagationConfig{Enabled: true, AutoStartOnChange: true, CDNOnly: true}
	for _, vendor := range []string{"cloudflare", "fastly", "akamai", "cloudfront", "multi-cdn"} {
		if !automaticPropagationAllowed(cfg, vendor) {
			t.Errorf("identified vendor %q was rejected with cdn_only enabled", vendor)
		}
	}
	if automaticPropagationAllowed(cfg, " ") {
		t.Fatal("empty vendor was accepted with cdn_only enabled")
	}
	cfg.CDNOnly = false
	if !automaticPropagationAllowed(cfg, "") {
		t.Fatal("unknown vendor was rejected with cdn_only disabled")
	}
	cfg.AutoStartOnChange = false
	if automaticPropagationAllowed(cfg, "fastly") {
		t.Fatal("automatic propagation was allowed when auto-start is disabled")
	}
}
