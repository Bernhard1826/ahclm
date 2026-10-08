// Package propagation runs bounded, independent multi-region HTTPS rounds for
// certificate replacements observed at CDN-backed domains.
package propagation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"ahclm/internal/database"
	"ahclm/internal/models"
)

// GlobalProber is the narrow scanner capability required by this worker. It
// keeps the lifecycle logic testable without making tests call Globalping.
type GlobalProber interface {
	MeasureGlobalHTTPS(context.Context, string, []string) (*models.GlobalProbeEvidence, error)
	MeasureGlobalHTTPSWithTarget(context.Context, string, string, []string) (*models.GlobalProbeEvidence, error)
	MeasureGlobalHTTPSPath(context.Context, string, string, string, []string) (*models.GlobalProbeEvidence, error)
}

type Manager struct {
	cfg    *models.CDNPropagationConfig
	db     *database.Database
	prober GlobalProber

	runMu   sync.Mutex
	startMu sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	wake    chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	nowFn   func() time.Time
}

func NewManager(cfg *models.CDNPropagationConfig, db *database.Database, prober GlobalProber) *Manager {
	return &Manager{cfg: cfg, db: db, prober: prober, nowFn: time.Now, wake: make(chan struct{}, 1)}
}

func (m *Manager) WatchWindow() time.Duration {
	if m == nil || m.cfg == nil {
		return 0
	}
	return m.cfg.WatchWindow
}

func (m *Manager) now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nowFn == nil {
		return time.Now().UTC()
	}
	return m.nowFn().UTC()
}

// Start launches the due-round worker. A manager can be constructed in tests
// without starting it; API-triggered experiments can still be created and
// measured by RunDue.
func (m *Manager) Start(parent context.Context) error {
	if m == nil {
		return nil
	}
	if m.db == nil || m.prober == nil {
		return fmt.Errorf("propagation manager requires database and global prober")
	}
	if parent == nil {
		parent = context.Background()
	}
	m.ctx, m.cancel = context.WithCancel(parent)
	m.wg.Add(1)
	go m.loop()
	return nil
}

func (m *Manager) Stop() {
	if m == nil {
		return
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

func (m *Manager) loop() {
	defer m.wg.Done()
	for {
		_ = m.RunDue(m.ctx)
		if m.ctx.Err() != nil {
			return
		}
		delay := time.Minute
		if at, err := m.db.NextCDNPropagationMeasureAt(); err == nil && at != nil {
			until := at.Sub(m.now())
			if until < delay {
				delay = until
			}
		}
		if delay < time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-m.ctx.Done():
			timer.Stop()
			return
		case <-m.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// StartExperiment creates an explicit measurement plan. The source timestamp
// is optional; when absent the local start time is used and labeled as such.
func (m *Manager) StartExperiment(req models.CDNPropagationStartRequest) (*models.CDNPropagationExperiment, error) {
	if m == nil || m.db == nil {
		return nil, fmt.Errorf("propagation manager is unavailable")
	}
	m.startMu.Lock()
	defer m.startMu.Unlock()
	if err := req.Validate(); err != nil {
		return nil, err
	}
	requestedHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Domain)), ".")
	req.Domain = models.GetDomain(req.Domain)
	layer := models.NormalizePropagationCertificateLayer(req.CertificateLayer)
	if layer == "" {
		return nil, fmt.Errorf("certificate_layer must be edge, origin, or origin_via_cdn")
	}
	req.CertificateLayer = layer
	if strings.TrimSpace(req.ProbeTarget) == "" {
		req.ProbeTarget = req.Domain
		if req.CertificateLayer == models.CDNPropagationLayerOriginViaCDN {
			req.ProbeTarget = requestedHost
		}
	} else if req.CertificateLayer == models.CDNPropagationLayerOrigin {
		req.ProbeTarget = strings.TrimSpace(req.ProbeTarget)
	} else if req.CertificateLayer == models.CDNPropagationLayerOriginViaCDN {
		req.ProbeTarget = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.ProbeTarget)), ".")
	} else {
		req.ProbeTarget = models.GetDomain(req.ProbeTarget)
	}
	if req.WatchChanges {
		req.TargetFingerprint = ""
	}
	if req.CertificateLayer == models.CDNPropagationLayerEdge {
		req.ProbeHost = req.Domain
	} else if req.CertificateLayer == models.CDNPropagationLayerOriginViaCDN {
		req.ProbeHost = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.ProbeHost)), ".")
		if req.ProbeHost == "" {
			req.ProbeHost = req.ProbeTarget
		}
	} else {
		req.ProbeHost = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.ProbeHost)), ".")
	}
	req.ProbePath = strings.TrimSpace(req.ProbePath)
	if req.CertificateLayer == models.CDNPropagationLayerOriginViaCDN && req.ExpectedHTTPStatus == 0 {
		req.ExpectedHTTPStatus = 200
	}
	req.TargetFingerprint = normalizeFingerprint(req.TargetFingerprint)
	req.PreviousFingerprint = normalizeFingerprint(req.PreviousFingerprint)
	if req.Domain == "" {
		return nil, fmt.Errorf("invalid domain")
	}
	if active, err := m.db.FindActiveCDNPropagation(req.Domain, req.TargetFingerprint, req.CertificateLayer, req.ProbeTarget, req.ProbeHost, req.ProbePath, req.ExpectedHTTPStatus, req.SourceUpdatedAt); err != nil {
		return nil, err
	} else if active != nil {
		return active, nil
	}
	maxActive := 32
	if m.cfg != nil && m.cfg.MaxActive > 0 {
		maxActive = m.cfg.MaxActive
	}
	activeCount, err := m.db.CountActiveCDNPropagationExperiments()
	if err != nil {
		return nil, err
	}
	status := models.CDNPropagationRunning
	if activeCount >= int64(maxActive) {
		status = models.CDNPropagationQueued
	}
	now := m.now()
	latestSourceTime := now.Add(5 * time.Minute)
	if req.CertificateLayer == models.CDNPropagationLayerOriginViaCDN {
		latestSourceTime = now
	}
	if req.SourceUpdatedAt != nil && req.SourceUpdatedAt.After(latestSourceTime) {
		return nil, fmt.Errorf("source_updated_at must not be in the future")
	}
	sourceAt := now
	basis := strings.TrimSpace(req.SourceTimeBasis)
	if req.SourceUpdatedAt != nil && !req.SourceUpdatedAt.IsZero() {
		sourceAt = req.SourceUpdatedAt.UTC()
		if basis == "" {
			basis = "operator_input"
		}
	} else if basis == "" {
		basis = "monitor_start"
	}
	locations := models.NormalizePropagationLocations(req.Locations)
	if len(locations) == 0 && m.cfg != nil {
		locations = models.NormalizePropagationLocations(m.cfg.Locations)
	}
	if len(locations) == 0 {
		return nil, fmt.Errorf("at least one propagation location is required")
	}
	poll := req.PollIntervalSeconds
	if poll <= 0 && m.cfg != nil {
		poll = int(m.cfg.PollInterval / time.Second)
	}
	if poll <= 0 {
		poll = 600
	}
	maxDuration := req.MaxDurationSeconds
	if maxDuration <= 0 && m.cfg != nil {
		maxDuration = int(m.cfg.MaxDuration / time.Second)
	}
	if maxDuration <= 0 {
		maxDuration = 72 * 60 * 60
	}
	stable := req.StableRounds
	if stable <= 0 && m.cfg != nil {
		stable = m.cfg.StableRounds
	}
	if stable <= 0 {
		stable = 2
	}
	locationsJSON, _ := json.Marshal(locations)
	experiment := &models.CDNPropagationExperiment{
		Domain:               req.Domain,
		Vendor:               strings.TrimSpace(req.Vendor),
		CertificateLayer:     req.CertificateLayer,
		ProbeTarget:          req.ProbeTarget,
		ProbeHost:            req.ProbeHost,
		ProbePath:            req.ProbePath,
		ExpectedHTTPStatus:   req.ExpectedHTTPStatus,
		WatchChanges:         req.WatchChanges,
		WatchNotAfter:        req.WatchNotAfter,
		Status:               status,
		PreviousFingerprint:  req.PreviousFingerprint,
		TargetFingerprint:    req.TargetFingerprint,
		SourceUpdatedAt:      sourceAt,
		SourceTimeBasis:      basis,
		StartedAt:            now,
		NextMeasureAt:        now,
		PollIntervalSeconds:  int64(poll),
		MaxDurationSeconds:   int64(maxDuration),
		StableRoundsRequired: stable,
		ExpectedLocations:    len(locations),
		LocationsJSON:        string(locationsJSON),
	}
	if err := m.db.CreateCDNPropagationExperiment(experiment); err != nil {
		return nil, err
	}
	m.wakeWorker()
	return experiment, nil
}

func (m *Manager) wakeWorker() {
	if m == nil || m.wake == nil {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// StartRenewalWatcher starts an unknown-target edge watcher during an
// existing renewal window. It is idempotent while a watcher is active.
// When CDNOnly is enabled, the scheduler must have identified a CDN vendor.
func (m *Manager) StartRenewalWatcher(domain, vendor string, watchSince, notAfter time.Time) (*models.CDNPropagationExperiment, error) {
	if m == nil || !automaticPropagationAllowed(m.cfg, vendor) {
		return nil, nil
	}
	if m.db == nil {
		return nil, fmt.Errorf("propagation manager requires a database")
	}
	if notAfter.IsZero() || !notAfter.After(m.now()) {
		return nil, nil
	}
	if existing, err := m.db.FindLatestCDNPropagationWatcher(domain); err != nil {
		return nil, err
	} else if existing != nil {
		if existing.Status == models.CDNPropagationRunning || existing.WatchNotAfter != nil && existing.WatchNotAfter.Equal(notAfter) {
			return existing, nil
		}
	}
	vendor = strings.TrimSpace(vendor)
	startedAt := m.now()
	// The watcher intentionally starts only in the final configured window,
	// which can be well after the CA's ARI window opened. Use the time we
	// actually begin Globalping observations; retaining the earlier ARI start
	// would imply measurements existed before the watcher was running.
	if watchSince.IsZero() || watchSince.Before(startedAt) {
		watchSince = startedAt
	}
	notAfter = notAfter.UTC()
	return m.StartExperiment(models.CDNPropagationStartRequest{
		Domain:           domain,
		Vendor:           vendor,
		CertificateLayer: models.CDNPropagationLayerEdge,
		ProbeTarget:      domain,
		WatchChanges:     true,
		WatchNotAfter:    &notAfter,
		SourceUpdatedAt:  &watchSince,
		SourceTimeBasis:  "ari_or_near_expiry_watch_started",
	})
}

// StartOnCertificateChange is called by the lifecycle scheduler after a same
// endpoint replacement. It measures CDN changes from the monitor's observed
// transition unless an operator has supplied a source-side timestamp through
// StartExperiment.
func (m *Manager) StartOnCertificateChange(domain, previous, target string, observedAt time.Time, vendor string) (*models.CDNPropagationExperiment, error) {
	if m == nil || !automaticPropagationAllowed(m.cfg, vendor) {
		return nil, nil
	}
	return m.StartExperiment(models.CDNPropagationStartRequest{
		Domain:              domain,
		Vendor:              vendor,
		CertificateLayer:    models.CDNPropagationLayerEdge,
		ProbeTarget:         domain,
		PreviousFingerprint: previous,
		TargetFingerprint:   target,
		SourceUpdatedAt:     &observedAt,
		SourceTimeBasis:     "monitor_observed",
	})
}

func automaticPropagationAllowed(cfg *models.CDNPropagationConfig, vendor string) bool {
	if cfg == nil || !cfg.Enabled || !cfg.AutoStartOnChange {
		return false
	}
	return !cfg.CDNOnly || strings.TrimSpace(vendor) != ""
}

func (m *Manager) RunDue(ctx context.Context) error {
	if m == nil || m.db == nil || m.prober == nil {
		return fmt.Errorf("propagation manager is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.runMu.Lock()
	defer m.runMu.Unlock()
	limit := 32
	if m.cfg != nil && m.cfg.MaxActive > 0 {
		limit = m.cfg.MaxActive
	}
	m.startMu.Lock()
	activeCount, err := m.db.CountActiveCDNPropagationExperiments()
	if err != nil {
		m.startMu.Unlock()
		return err
	}
	available := limit - int(activeCount)
	if available > 0 {
		queued, queueErr := m.db.GetQueuedCDNPropagationExperiments(available)
		if queueErr != nil {
			m.startMu.Unlock()
			return queueErr
		}
		for _, experiment := range queued {
			if err := m.db.ActivateQueuedCDNPropagationExperiment(experiment.ID, m.now()); err != nil {
				m.startMu.Unlock()
				return err
			}
		}
	}
	m.startMu.Unlock()
	experiments, err := m.db.GetDueCDNPropagationExperiments(m.now(), limit)
	if err != nil {
		return err
	}
	for i := range experiments {
		if err := m.measureOne(ctx, &experiments[i]); err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

func (m *Manager) measureOne(parent context.Context, experiment *models.CDNPropagationExperiment) error {
	now := m.now()
	if experiment == nil || experiment.Status != models.CDNPropagationRunning {
		return nil
	}
	if experiment.MaxDurationSeconds > 0 && now.After(experiment.StartedAt.Add(time.Duration(experiment.MaxDurationSeconds)*time.Second)) {
		m.wakeWorker()
		return m.db.UpdateRunningCDNPropagationExperiment(experiment.ID, map[string]interface{}{
			"status":            models.CDNPropagationTimeout,
			"completed_at":      now,
			"completion_reason": "maximum experiment duration reached",
			"next_measure_at":   now,
		})
	}
	timeout := 45 * time.Second
	if m.cfg != nil && m.cfg.Timeout > 0 {
		timeout = m.cfg.Timeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var configured []string
	_ = json.Unmarshal([]byte(experiment.LocationsJSON), &configured)
	probeTarget := strings.TrimSpace(experiment.ProbeTarget)
	if probeTarget == "" {
		probeTarget = experiment.Domain
	}
	var evidence *models.GlobalProbeEvidence
	var err error
	probeHost := strings.TrimSpace(experiment.ProbeHost)
	if experiment.CertificateLayer == models.CDNPropagationLayerOrigin {
		evidence, err = m.prober.MeasureGlobalHTTPSWithTarget(ctx, probeTarget, probeHost, configured)
	} else if experiment.CertificateLayer == models.CDNPropagationLayerOriginViaCDN {
		evidence, err = m.prober.MeasureGlobalHTTPSPath(ctx, probeTarget, probeHost, experiment.ProbePath, configured)
	} else {
		evidence, err = m.prober.MeasureGlobalHTTPS(ctx, probeTarget, configured)
	}
	if err == nil && evidence == nil {
		err = fmt.Errorf("global probe returned no evidence")
	}
	if err != nil {
		next := now.Add(time.Duration(experiment.PollIntervalSeconds) * time.Second)
		round := &models.CDNPropagationRound{
			RoundNumber:   experiment.Rounds + 1,
			ObservedAt:    now,
			Status:        "provider_error",
			ExpectedCount: experiment.ExpectedLocations,
			Error:         truncate(err.Error(), 1000),
		}
		if updateErr := m.db.SaveCDNPropagationRound(experiment.ID, round, nil, map[string]interface{}{
			"last_attempted_at": now,
			"next_measure_at":   next,
			"rounds":            experiment.Rounds + 1,
			"stable_rounds":     0,
			"last_error":        truncate(err.Error(), 1000),
		}); updateErr != nil {
			return updateErr
		}
		return err
	}
	if evidence == nil {
		return fmt.Errorf("global probe returned no evidence")
	}
	if evidence.CollectedAt.IsZero() {
		evidence.CollectedAt = now
	}

	var observations []models.CDNPropagationObservation
	var targetCount, expectedCount int
	var watcherPrior *models.CDNPropagationReport
	if experiment.CertificateLayer == models.CDNPropagationLayerOriginViaCDN {
		observations, targetCount, expectedCount = originRequestObservations(evidence, configured, experiment.ExpectedHTTPStatus, experiment.TargetFingerprint)
	} else if experiment.WatchChanges {
		if prior, reportErr := m.db.GetCDNPropagationReport(experiment.ID); reportErr == nil {
			watcherPrior = prior
		}
		observations, targetCount, expectedCount = propagationWatcherObservations(evidence, configured, watcherPrior)
	} else {
		observations, targetCount, expectedCount = propagationObservations(evidence, configured, experiment.TargetFingerprint, experiment.PreviousFingerprint)
	}
	allChanged := expectedCount > 0 && targetCount == expectedCount
	watcherStableRound := false
	if experiment.WatchChanges {
		watcherStableRound = watcherRoundStable(observations, configured, watcherPrior)
	}
	currentComplete := allChanged
	if experiment.WatchChanges {
		currentComplete = watcherStableRound
	}
	round := &models.CDNPropagationRound{
		RoundNumber:   experiment.Rounds + 1,
		ObservedAt:    evidence.CollectedAt,
		MeasurementID: evidence.HTTPSMeasurementID,
		Status:        "complete",
		AnsweredCount: countAnswered(observations),
		TargetCount:   targetCount,
		PreviousCount: countPrevious(observations),
		ExpectedCount: expectedCount,
		Complete:      currentComplete,
	}
	idsJSON, _ := json.Marshal(evidence.HTTPSMeasurementIDs)
	round.MeasurementIDsJSON = string(idsJSON)
	round.Error = truncate(evidence.Error, 1000)
	if experiment.WatchChanges {
		round.Status = "watching"
	} else if currentComplete {
		round.Status = "all_target"
		if experiment.CertificateLayer == models.CDNPropagationLayerOriginViaCDN {
			round.Status = "origin_verified"
		}
	} else if round.AnsweredCount == 0 {
		round.Status = "no_answer"
	}
	stable := 0
	if experiment.WatchChanges {
		var priorRounds []models.CDNPropagationRound
		if watcherPrior != nil {
			priorRounds = watcherPrior.Rounds
		}
		stable = nextStableRounds(priorRounds, watcherStableRound)
	} else {
		var priorRounds []models.CDNPropagationRound
		if prior, err := m.db.GetCDNPropagationReport(experiment.ID); err == nil {
			priorRounds = prior.Rounds
		}
		stable = nextStableRounds(priorRounds, currentComplete)
	}
	next := now.Add(time.Duration(experiment.PollIntervalSeconds) * time.Second)
	updates := map[string]interface{}{
		"last_attempted_at": now,
		"last_measured_at":  now,
		"next_measure_at":   next,
		"rounds":            experiment.Rounds + 1,
		"stable_rounds":     stable,
		"last_error":        truncate(evidence.Error, 1000),
	}
	if !experiment.WatchChanges && currentComplete && stable >= experiment.StableRoundsRequired {
		updates["status"] = models.CDNPropagationComplete
		updates["completed_at"] = evidence.CollectedAt
		if experiment.CertificateLayer == models.CDNPropagationLayerOriginViaCDN {
			updates["completion_reason"] = "all sampled regions verified fresh origin responses on TLS connections using the target certificate for stable rounds"
		} else {
			updates["completion_reason"] = "all configured locations served target for stable rounds"
		}
		updates["next_measure_at"] = evidence.CollectedAt
	}
	if experiment.WatchChanges && currentComplete && stable >= experiment.StableRoundsRequired {
		updates["status"] = models.CDNPropagationComplete
		updates["completed_at"] = evidence.CollectedAt
		updates["completion_reason"] = "all configured locations changed from baseline and served stable fingerprints for required rounds"
		updates["next_measure_at"] = evidence.CollectedAt
	}
	if err := m.db.SaveCDNPropagationRound(experiment.ID, round, observations, updates); err != nil {
		return err
	}
	// Recompute current regional coverage after the immutable round is stored.
	if report, err := m.db.GetCDNPropagationReport(experiment.ID); err == nil {
		targets := 0
		for _, location := range report.Locations {
			if location.State == "target" || location.State == "changed" || location.State == "request_ok" {
				targets++
			}
		}
		_ = m.db.UpdateCDNPropagationExperiment(experiment.ID, map[string]interface{}{
			"target_locations":   targets,
			"observed_locations": countObservedLocations(report.Locations),
		})
	}
	if _, completed := updates["status"]; completed {
		m.wakeWorker()
	}
	return nil
}

func originRequestObservations(evidence *models.GlobalProbeEvidence, configured []string, expectedStatus int, targetFingerprint string) ([]models.CDNPropagationObservation, int, int) {
	if expectedStatus == 0 {
		expectedStatus = http.StatusOK
	}
	observations := make([]models.CDNPropagationObservation, 0, len(configured))
	byContinent := make(map[string]models.GlobalHTTPSProbe)
	if evidence != nil {
		for _, probe := range evidence.HTTPS {
			continent := strings.ToUpper(strings.TrimSpace(probe.Location.Continent))
			if continent != "" {
				byContinent[continent] = probe
			}
		}
	}
	for _, continent := range models.NormalizePropagationLocations(configured) {
		probe, ok := byContinent[continent]
		if !ok {
			probe.Location.Continent = continent
			probe.Error = "no probe result for configured region"
		}
		succeeded := probe.Status == "finished" && probe.Error == "" && probe.TLSError == "" && probe.TLSObserved && probe.TLSAuthorized && probe.HTTPStatus == expectedStatus
		originFingerprint := normalizeFingerprint(probe.OriginFingerprint)
		if _, err := hex.DecodeString(originFingerprint); err != nil || len(originFingerprint) != 64 {
			originFingerprint = ""
		}
		responseNonce := probe.OriginProbeNonce
		if len(responseNonce) > 64 {
			responseNonce = ""
		}
		resumed := probe.OriginTLSResumed
		if resumed != "true" && resumed != "false" {
			resumed = ""
		}
		verified := succeeded && probe.RequestNonce != "" && probe.OriginProbeNonce == probe.RequestNonce && probe.OriginTLSResumed == "false" && originFingerprint == normalizeFingerprint(targetFingerprint) && len(originFingerprint) == 64
		problem := strings.TrimSpace(probe.Error + " " + probe.TLSError)
		if succeeded && !verified {
			problem = "HTTP succeeded but fresh origin handshake with the target certificate is not verified"
		}
		observations = append(observations, models.CDNPropagationObservation{
			ObservedAt:  originProbeTime(probe, evidence),
			LocationKey: models.PropagationLocationKey(probe.Location),
			Continent:   probe.Location.Continent, Region: probe.Location.Region, Country: probe.Location.Country,
			City: probe.Location.City, ASN: probe.Location.ASN, Network: probe.Location.Network,
			ResolvedAddress: probe.ResolvedAddress, Fingerprint: normalizeFingerprint(probe.Fingerprint),
			Status: probe.Status, TLSObserved: probe.TLSObserved, TLSAuthorized: probe.TLSAuthorized,
			HTTPStatus: probe.HTTPStatus, RequestSucceeded: succeeded, IsTarget: verified, OriginVerified: verified,
			OriginFingerprint: originFingerprint, ProbeNonce: responseNonce,
			RequestNonce: probe.RequestNonce, OriginTLSResumed: resumed, MeasurementID: probe.MeasurementID,
			Error: truncate(problem, 1000),
		})
	}
	return observations, countVerifiedOrigins(observations), len(models.NormalizePropagationLocations(configured))
}

func originProbeTime(probe models.GlobalHTTPSProbe, evidence *models.GlobalProbeEvidence) time.Time {
	if probe.ObservedAt != nil && !probe.ObservedAt.IsZero() {
		return *probe.ObservedAt
	}
	return evidenceTime(evidence)
}

func evidenceTime(evidence *models.GlobalProbeEvidence) time.Time {
	if evidence != nil && !evidence.CollectedAt.IsZero() {
		return evidence.CollectedAt
	}
	return time.Now().UTC()
}

func countVerifiedOrigins(observations []models.CDNPropagationObservation) int {
	count := 0
	for _, observation := range observations {
		if observation.OriginVerified {
			count++
		}
	}
	return count
}

func propagationWatcherObservations(evidence *models.GlobalProbeEvidence, configured []string, prior *models.CDNPropagationReport) ([]models.CDNPropagationObservation, int, int) {
	observations, _, expected := propagationObservations(evidence, configured, "", "")
	previous := make(map[string]string)
	if prior != nil {
		for _, location := range prior.Locations {
			if location.LastTLSObserved && location.LatestFingerprint != "" {
				previous[location.LocationKey] = normalizeFingerprint(location.LatestFingerprint)
			}
		}
	}
	changedLocations := 0
	baseline := make(map[string]string)
	if prior != nil {
		for _, location := range prior.Locations {
			fingerprint := normalizeFingerprint(location.BaselineFingerprint)
			if fingerprint == "" {
				fingerprint = normalizeFingerprint(location.LatestFingerprint)
			}
			if fingerprint != "" {
				baseline[location.LocationKey] = fingerprint
			}
		}
	}
	for i := range observations {
		current := normalizeFingerprint(observations[i].Fingerprint)
		old := previous[observations[i].LocationKey]
		if current == "" || !observations[i].TLSObserved {
			continue
		}
		// Every successful leaf is a retained observation that can bound when a
		// later change first appeared, including the first baseline round.
		observations[i].IsPrevious = true
		if old == "" {
			baseline[observations[i].LocationKey] = current
			continue
		}
		if baseline[observations[i].LocationKey] == "" {
			baseline[observations[i].LocationKey] = old
		}
		if current != old {
			observations[i].FingerprintChanged = true
			observations[i].ChangeFromFingerprint = old
		}
		if current != baseline[observations[i].LocationKey] {
			observations[i].IsTarget = true
			changedLocations++
		}
	}
	return observations, changedLocations, expected
}

// watcherRoundStable is true only when every configured region has changed
// from its first successful fingerprint and repeats its immediately previous
// fingerprint in this round. The first round on which the last region changes
// is a transition, not a stable round.
func watcherRoundStable(observations []models.CDNPropagationObservation, configured []string, prior *models.CDNPropagationReport) bool {
	if prior == nil {
		return false
	}
	current := make(map[string]models.CDNPropagationObservation, len(observations))
	for _, observation := range observations {
		current[observation.LocationKey] = observation
	}
	priorLocations := make(map[string]models.CDNPropagationLocationSummary, len(prior.Locations))
	for _, location := range prior.Locations {
		priorLocations[location.LocationKey] = location
	}
	locations := models.NormalizePropagationLocations(configured)
	if len(locations) == 0 {
		return false
	}
	for _, key := range locations {
		observation, ok := current[key]
		previous, hasPrevious := priorLocations[key]
		baseline := normalizeFingerprint(previous.BaselineFingerprint)
		if !ok || !hasPrevious || !observation.TLSObserved || observation.Fingerprint == "" || !previous.LastTLSObserved || previous.LatestFingerprint == "" || baseline == "" {
			return false
		}
		fingerprint := normalizeFingerprint(observation.Fingerprint)
		if fingerprint == baseline || fingerprint != normalizeFingerprint(previous.LatestFingerprint) {
			return false
		}
	}
	return true
}

func countAnswered(observations []models.CDNPropagationObservation) int {
	count := 0
	for _, observation := range observations {
		if observation.TLSObserved {
			count++
		}
	}
	return count
}

func propagationObservations(evidence *models.GlobalProbeEvidence, configured []string, targetFingerprint, previousFingerprint string) ([]models.CDNPropagationObservation, int, int) {
	if evidence == nil {
		return nil, 0, len(models.NormalizePropagationLocations(configured))
	}
	configuredSet := make(map[string]struct{})
	for _, location := range models.NormalizePropagationLocations(configured) {
		configuredSet[location] = struct{}{}
	}
	seen := make(map[string]struct{})
	observations := make([]models.CDNPropagationObservation, 0, len(evidence.HTTPS))
	targets := make(map[string]struct{})
	for _, probe := range evidence.HTTPS {
		locationKey := models.PropagationLocationKey(probe.Location)
		// A provider can return more than one probe in a continent. Keep the
		// first result per completion bucket so one round cannot over-count a
		// location's vote.
		if _, duplicate := seen[locationKey]; duplicate {
			continue
		}
		seen[locationKey] = struct{}{}
		fingerprint := normalizeFingerprint(probe.Fingerprint)
		_, expected := configuredSet[locationKey]
		isTarget := expected && probe.TLSObserved && fingerprint != "" && fingerprint == normalizeFingerprint(targetFingerprint)
		isPrevious := expected && probe.TLSObserved && fingerprint != "" && previousFingerprint != "" && fingerprint == normalizeFingerprint(previousFingerprint)
		if isTarget {
			targets[locationKey] = struct{}{}
		}
		observations = append(observations, models.CDNPropagationObservation{
			ObservedAt:      evidence.CollectedAt,
			LocationKey:     locationKey,
			Continent:       strings.ToUpper(strings.TrimSpace(probe.Location.Continent)),
			Region:          probe.Location.Region,
			Country:         probe.Location.Country,
			City:            probe.Location.City,
			ASN:             probe.Location.ASN,
			Network:         probe.Location.Network,
			ResolvedAddress: probe.ResolvedAddress,
			Fingerprint:     fingerprint,
			Status:          probe.Status,
			TLSObserved:     probe.TLSObserved,
			TLSAuthorized:   probe.TLSAuthorized,
			HTTPStatus:      probe.HTTPStatus,
			IsTarget:        isTarget,
			IsPrevious:      isPrevious,
			Error:           truncate(strings.TrimSpace(probe.Error+" "+probe.TLSError), 1000),
		})
	}
	return observations, len(targets), len(configuredSet)
}

func nextStableRounds(previous []models.CDNPropagationRound, currentComplete bool) int {
	if !currentComplete {
		return 0
	}
	stable := 1
	for i := len(previous) - 1; i >= 0 && previous[i].Complete; i-- {
		stable++
	}
	return stable
}

func countPrevious(observations []models.CDNPropagationObservation) int {
	count := 0
	for _, observation := range observations {
		if observation.IsPrevious {
			count++
		}
	}
	return count
}

func countObservedLocations(locations []models.CDNPropagationLocationSummary) int {
	count := 0
	for _, location := range locations {
		if location.AnsweredRounds > 0 {
			count++
		}
	}
	return count
}

func normalizeFingerprint(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
