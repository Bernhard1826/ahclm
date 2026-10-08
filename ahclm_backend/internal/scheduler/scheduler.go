package scheduler

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ahclm/internal/database"
	"ahclm/internal/domainlist"
	"ahclm/internal/models"
	"ahclm/internal/propagation"
	"ahclm/internal/scanner"
	"ahclm/internal/tranco"
)

// Scheduler drives adaptive certificate scanning. Instead of a static queue it
// works off each domain's persisted NextScanAt, which is recomputed after every
// scan to cluster around certificate-expiry milestones.
type Scheduler struct {
	config     *models.SchedulerConfig
	scanCfg    *models.ScannerConfig
	db         *database.Database
	scanner    *scanner.Scanner
	tranco     *tranco.Fetcher
	localLists *models.LocalListsConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	running    sync.Map // domain -> struct{} currently in flight
	runningN   int64
	paused     atomic.Bool
	trancoMu   sync.Mutex // serializes refreshes and population pruning
	dispatchMu sync.Mutex // closes the pause/dispatch race during refresh

	nowFn       func() time.Time
	afterCommit func(func())
	resultErr   error

	onScanComplete func(*models.ScanResult)
	onAlert        func(*models.WebhookPayload)
	propagation    *propagation.Manager
}

// SetLocalLists supplies the optional file-backed population. It is set by
// main after configuration has been loaded, keeping the scheduler constructor
// compatible with existing callers and tests.
func (s *Scheduler) SetLocalLists(cfg *models.LocalListsConfig) {
	s.localLists = cfg
}

// SetPropagationManager attaches the independent CDN propagation worker. The
// scheduler only creates an experiment after a same-endpoint replacement; the
// worker owns all Globalping calls and follow-up rounds.
func (s *Scheduler) SetPropagationManager(manager *propagation.Manager) {
	s.propagation = manager
}

const (
	// Unreachable targets remain in the active observation queue: failure means
	// that the current endpoint state is unknown, not that the service retired.
	unreachablePriority = 70
)

// NewScheduler creates a new adaptive scheduler.
func NewScheduler(
	cfg *models.SchedulerConfig,
	scanCfg *models.ScannerConfig,
	db *database.Database,
	scan *scanner.Scanner,
	trancoFetcher *tranco.Fetcher,
) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		config:  cfg,
		scanCfg: scanCfg,
		db:      db,
		scanner: scan,
		tranco:  trancoFetcher,
		ctx:     ctx,
		cancel:  cancel,
		nowFn:   time.Now,
	}
}

func (s *Scheduler) now() time.Time { return s.nowFn() }

func (s *Scheduler) workers() int {
	if s.scanCfg != nil && s.scanCfg.Workers > 0 {
		return s.scanCfg.Workers
	}
	return 1
}

// Start launches the background scheduling loop.
func (s *Scheduler) Start() error {
	if !s.config.Enabled {
		return nil
	}
	if reactivated, err := s.db.ReactivateLegacyDormantDomains(s.now()); err != nil {
		log.Printf("scheduler: reactivate legacy dormant domains: %v", err)
	} else if reactivated > 0 {
		log.Printf("scheduler: requeued %d legacy dormant domains for active observation", reactivated)
	}
	s.wg.Add(1)
	go s.loop()
	return nil
}

// Stop cancels the loop and waits for in-flight scans.
func (s *Scheduler) Stop() {
	s.cancel()
	s.wg.Wait()
}

func (s *Scheduler) Pause()         { s.paused.Store(true) }
func (s *Scheduler) Resume()        { s.paused.Store(false) }
func (s *Scheduler) IsPaused() bool { return s.paused.Load() }

func (s *Scheduler) loop() {
	defer s.wg.Done()
	sem := make(chan struct{}, s.workers())

	ticker := time.NewTicker(s.config.TickInterval)
	defer ticker.Stop()

	if !s.paused.Load() {
		s.dispatchDue(sem)
	}
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if !s.paused.Load() {
				s.dispatchDue(sem)
			}
		}
	}
}

// dispatchDue selects due domains (respecting the daily budget) and scans them
// through a bounded worker pool.
func (s *Scheduler) dispatchDue(sem chan struct{}) {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()

	remaining := s.dailyBudgetRemaining()
	if remaining <= 0 {
		return
	}
	limit := s.workers() * 4
	if int64(limit) > remaining {
		limit = int(remaining)
	}

	due, err := s.db.GetDueDomains(s.now(), limit)
	if err != nil {
		log.Printf("scheduler: get due domains: %v", err)
		return
	}

	for i := range due {
		dc := due[i]
		if _, busy := s.running.LoadOrStore(dc.Domain, struct{}{}); busy {
			continue
		}
		select {
		case <-s.ctx.Done():
			s.running.Delete(dc.Domain)
			return
		case sem <- struct{}{}:
		}
		s.wg.Add(1)
		atomic.AddInt64(&s.runningN, 1)
		go func(d models.DomainCertificate) {
			defer s.wg.Done()
			defer func() { <-sem }()
			defer atomic.AddInt64(&s.runningN, -1)
			defer s.running.Delete(d.Domain)
			s.scanOne(&d)
		}(dc)
	}
}

func (s *Scheduler) dailyBudgetRemaining() int64 {
	used := s.db.GetTodayStat().TotalScans
	rem := int64(s.config.MaxDailyScans) - int64(used)
	if rem < 0 {
		return 0
	}
	return rem
}

func (s *Scheduler) scanOne(dc *models.DomainCertificate) {
	ctx, cancel := context.WithTimeout(s.ctx, s.config.ScanTimeout)
	defer cancel()

	job := s.startJob(dc.Domain, scanReason(dc, s.now(), s.config.ARIPollDueTolerance), dc.NextScanAt)
	result, err := s.scanForScheduler(ctx, dc)
	if err != nil {
		result = &models.ScanResult{
			Domain:                dc.Domain,
			Success:               false,
			Error:                 err.Error(),
			FailureClass:          scanner.FailureClassForError(err),
			ScannedAt:             s.now(),
			RevocationStatus:      models.RevocationNotChecked,
			RevocationCheckedVia:  models.CheckedViaNone,
			EvidenceStatus:        models.EvidenceStatusNotApplicable,
			EvidencePendingReason: "No certificate was obtained for evidence enrichment.",
		}
	}
	s.processResult(dc, result)
	s.finishJob(job, result)
}

// processResult is the hybrid-storage write path: it decides which meaningful
// events occurred, appends observations only for those, updates the domain's
// current state and recomputes NextScanAt.
func (s *Scheduler) processResult(dc *models.DomainCertificate, result *models.ScanResult) {
	if dc == nil || result == nil {
		return
	}
	var committed models.DomainCertificate
	var effects []func()
	err := s.db.WithDomainScanTransaction(dc.Domain, func(db *database.Database, current *models.DomainCertificate) error {
		worker := &Scheduler{config: s.config, scanCfg: s.scanCfg, db: db, nowFn: s.nowFn, propagation: s.propagation}
		worker.afterCommit = func(effect func()) { effects = append(effects, effect) }
		if s.onAlert != nil {
			worker.onAlert = func(p *models.WebhookPayload) { effects = append(effects, func() { s.onAlert(p) }) }
		}
		if s.onScanComplete != nil {
			worker.onScanComplete = func(r *models.ScanResult) { effects = append(effects, func() { s.onScanComplete(r) }) }
		}
		observed := result.ScannedAt
		if observed.IsZero() {
			observed = s.now()
			result.ScannedAt = observed
		}
		latest := current.LastScannedAt
		if current.LastObservationAt != nil {
			latest = *current.LastObservationAt
		}
		if !latest.IsZero() && observed.Before(latest) {
			// Retain late evidence, but do not turn it into a backwards change or
			// replace the state from a newer observation.
			if result.Success {
				if _, _, err := db.UpsertCertificate(result.Cert); err != nil {
					return err
				}
				snapshotState := *current
				worker.recordMeasurement(&snapshotState, result, "late_result")
			}
			current.ScanCount++
			stat := models.DailyScanStat{TotalScans: 1}
			if result.Success {
				stat.SuccessfulScans = 1
				stat.TotalScanMs = result.ScanDuration.Milliseconds()
			} else {
				stat.FailedScans = 1
			}
			if err := db.SaveDomainCertificate(current); err != nil {
				return err
			}
			if err := db.BumpDailyStat(stat); err != nil {
				return err
			}
			if worker.onScanComplete != nil {
				worker.onScanComplete(result)
			}
		} else {
			current.LastObservationAt = &observed
			worker.processCurrentResult(current, result)
		}
		committed = *current
		return worker.resultErr
	})
	if err != nil {
		log.Printf("scheduler: commit result for %s: %v", dc.Domain, err)
		return
	}
	*dc = committed
	for _, effect := range effects {
		effect()
	}
}

func (s *Scheduler) processCurrentResult(dc *models.DomainCertificate, result *models.ScanResult) {
	now := s.now()
	stat := models.DailyScanStat{TotalScans: 1}

	// ---- Failure path ----------------------------------------------------
	if !result.Success {
		stat.FailedScans = 1
		if result.FailureClass == "" {
			result.FailureClass = scanner.FailureClassForError(fmt.Errorf("%s", result.Error))
		}
		dc.ConsecutiveFailures++
		dc.LastError = result.Error
		dc.LastFailureClass = result.FailureClass
		dc.LastScannedAt = now
		dc.ScanCount++
		if dc.CurrentFingerprint == "" {
			dc.EvidenceStatus = models.EvidenceStatusNotApplicable
			dc.EvidencePendingReason = "No certificate was obtained for evidence enrichment."
		}
		if dc.Status != models.StatusUnreachable && dc.ConsecutiveFailures >= 3 {
			dc.Status = models.StatusUnreachable
			s.appendObs(&models.CertObservation{
				Domain: dc.Domain, ObservationType: models.ObsUnreachable,
				ObservedAt: now, Notes: truncate(result.Error, 480),
			})
		}
		dc.NextScanAt = now.Add(s.failureBackoff(dc.ConsecutiveFailures))
		if dc.ConsecutiveFailures < 3 && s.config.MinGap > 0 {
			dc.NextScanAt = now.Add(s.config.MinGap)
		}
		dc.Priority = unreachablePriority
		s.save(dc)
		if err := s.db.BumpDailyStat(stat); err != nil {
			s.resultErr = err
		}
		if s.onScanComplete != nil {
			s.onScanComplete(result)
		}
		return
	}

	// ---- Success path ----------------------------------------------------
	stat.SuccessfulScans = 1
	stat.TotalScanMs = result.ScanDuration.Milliseconds()

	if dc.Status == models.StatusUnreachable {
		s.appendObs(&models.CertObservation{
			Domain: dc.Domain, ObservationType: models.ObsReappear, ObservedAt: now,
		})
	}
	dc.ConsecutiveFailures = 0
	dc.LastError = ""
	dc.LastFailureClass = ""

	cert, isNew, err := s.db.UpsertCertificate(result.Cert)
	if err != nil {
		s.resultErr = err
		log.Printf("scheduler: upsert certificate for %s: %v", dc.Domain, err)
		return
	}
	if isNew {
		stat.NewCerts = 1
	}
	// Replacement observations must carry the persisted certificate ID even
	// when this leaf was already known from another domain or earlier round.
	result.Cert = cert

	// All entry points (including manual scans) retain findings from every
	// correct-SNI handshake, not just the initial connection.
	for _, probe := range result.EndpointProbes {
		for _, finding := range probe.Findings {
			found := false
			for _, existing := range result.TLSFindings {
				if existing.Code == finding.Code && existing.IPAddress == finding.IPAddress && existing.Fingerprint == finding.Fingerprint {
					found = true
					break
				}
			}
			if !found {
				result.TLSFindings = append(result.TLSFindings, finding)
			}
		}
	}
	curDays := models.DaysUntil(cert.NotAfter, now)
	findingsJSON, _ := json.Marshal(result.TLSFindings)
	if string(findingsJSON) != dc.TLSFindings && (len(result.TLSFindings) > 0 || (dc.TLSFindings != "" && dc.TLSFindings != "null" && dc.TLSFindings != "[]")) {
		obs := s.newObs(dc.Domain, cert, "tls_validation_change", "", curDays, result)
		obs.Notes = string(findingsJSON)
		s.appendObs(obs)
	}
	dc.TLSFindings = string(findingsJSON)
	checked := result.ScannedAt
	dc.TLSCheckedAt = &checked
	hasPrev := dc.ScanCount > 0 && dc.CurrentFingerprint != ""
	prevFP := dc.CurrentFingerprint
	prevDays := dc.LastDaysUntilExpiry
	certificateChanged := hasPrev && prevFP != cert.Fingerprint
	previousEndpointStates := parseEndpointStatesJSON(dc.EndpointStates)
	if len(previousEndpointStates) == 0 && strings.TrimSpace(dc.LastEndpointIP) != "" && prevFP != "" {
		previousEndpointStates[dc.LastEndpointIP] = models.EndpointState{
			IPAddress: dc.LastEndpointIP, Fingerprint: prevFP,
		}
	}
	previousIPs := parseIPs(dc.ResolvedIPs)
	dnsIPs := append([]string(nil), result.ResolvedIPs...)
	currentIPs := append([]string(nil), dnsIPs...)
	if len(currentIPs) == 0 && result.ConnectionInfo != nil && result.ConnectionInfo.IPAddress != "" {
		currentIPs = []string{result.ConnectionInfo.IPAddress}
	}
	sort.Strings(currentIPs)
	topologyChanged := topologyTransition(dc, result, previousIPs, dnsIPs)
	if result.DeepEvidence != nil {
		result.DeepEvidence.EndpointProbes = append([]models.EndpointProbe(nil), result.EndpointProbes...)
		result.DeepEvidence.Topology = result.Topology
	}
	// Persist the measurement before mutating the domain row. The previous row
	// is then available as a control when classifying stable CDN diversity versus
	// a live rollout.
	previousSnapshots := s.recordMeasurement(dc, result, measurementTrigger(result, certificateChanged, topologyChanged))
	result.MeasurementTrigger = measurementTrigger(result, certificateChanged, topologyChanged)
	if result.Topology != nil {
		dc.ConsensusIPs = marshalString(result.Topology.ConsensusIPs)
		dc.TopologyCNAMEs = strings.Join(result.Topology.CNAMEChain, ",")
		dc.TopologyHash = result.Topology.TopologyHash
		dc.TopologyResolverQuorum = result.Topology.ResolverQuorum
		dc.TopologyResolverAgreement = result.Topology.ResolverAgreement
	}

	replacements := withoutSplitAddresses(withoutReturningLeaves(sameIPReplacements(previousEndpointStates, currentEndpointLeaves(result)), previousSnapshots), result)
	switch {
	case !hasPrev:
		s.appendObs(s.newObs(dc.Domain, cert, models.ObsInitial, "", curDays, result))
	case len(replacements) > 0:
		stat.ChangesDetected = 1
		dc.ChangeCount += len(replacements)
		dc.LastChangedAt = &now
		for _, replacement := range replacements {
			next := s.endpointCertificate(replacement, result)
			endpointResult := *result
			endpointResult.Cert = next
			endpointResult.ConnectionInfo = &models.ConnectionInfo{IPAddress: replacement.IP}
			// The main handshake's revocation verdict is not evidence for a
			// different endpoint leaf.
			if next.Fingerprint != cert.Fingerprint {
				endpointResult.RevocationStatus = models.RevocationNotChecked
				endpointResult.RevocationCheckedVia = models.CheckedViaNone
				endpointResult.RevocationCheckedAt = nil
				endpointResult.RevokedAt = nil
				endpointResult.RevocationReason = ""
			}
			days := 0
			if !next.NotAfter.IsZero() {
				days = models.DaysUntil(next.NotAfter, now)
			}
			obs := s.newObs(dc.Domain, next, models.ObsChange, "", days, &endpointResult)
			obs.PreviousFingerprint = replacement.Previous
			obs.PreviousIPAddress = replacement.IP
			obs.ChangeClass = models.ChangeClassReplacement
			obs.Notes = "Same endpoint " + replacement.IP + " served a different leaf than in the previous round."
			if previous, err := s.db.GetCertificateByFingerprint(replacement.Previous); err == nil {
				obs.PreviousSPKIFingerprint = previous.SPKIFingerprint
				if obs.PreviousSPKIFingerprint == "" {
					obs.PreviousSPKIFingerprint = models.SPKIFingerprintFromRaw(previous.RawCert)
				}
			}
			s.appendObs(obs)
			if obs.PreviousSPKIFingerprint != "" && obs.PreviousSPKIFingerprint == next.SPKIFingerprint {
				sameKey := *obs
				sameKey.ID = 0
				sameKey.ObservationType = models.ObsSameKey
				sameKey.Notes = "The leaf changed at this endpoint while its SPKI remained unchanged; this is not evidence of private-key compromise."
				s.appendObs(&sameKey)
			}
			s.fireAlert("certificate_changed", dc.Domain, next, "", "Certificate changed on endpoint "+replacement.IP)
		}
	}

	// A stale event requires a quorum-confirmed DNS transition *and* direct
	// evidence that an old edge is still serving the predecessor while a new edge
	// serves the successor. A changed RRset by itself is not a stale certificate.
	if hasPrev && topologyChanged && cert.NotAfter.After(now) && staleEndpointEvidence(dc, result, prevFP, previousIPs, dnsIPs) {
		obs := s.newObs(dc.Domain, cert, models.ObsStaleAfterChange, "", curDays, result)
		obs.PreviousResolvedIPs = dc.ResolvedIPs
		obs.Notes = "A still-valid leaf remained observable after the resolver's public A/AAAA set changed; this is a DNS/IP-set proxy, not proof of global control-plane change."
		if len(result.EndpointProbes) > 0 {
			encoded, _ := json.Marshal(result.EndpointProbes)
			obs.EndpointProbes = string(encoded)
		}
		s.appendObs(obs)
	}
	if len(result.EndpointProbes) > 0 {
		if deploymentFailureEvidence(dc, result, previousSnapshots, prevFP, certificateChanged) {
			obs := s.newObs(dc.Domain, cert, models.ObsDeploymentFailure, "", curDays, result)
			encoded, _ := json.Marshal(result.EndpointProbes)
			obs.EndpointProbes = string(encoded)
			// Only a leaf the main handshake actually moved away from is a
			// predecessor. The unchanged main-handshake leaf is the leaf of the
			// first sorted address, not an older certificate.
			if certificateChanged {
				obs.PreviousFingerprint = prevFP
			}
			obs.Notes = "Sampled current DNS endpoints served different leaf fingerprints. This proves certificate diversity, not deployment failure; intentional CDN or dual-certificate configurations may explain it."
			s.appendObs(obs)
		}
	}
	// Residual is measured only after a CA revocation timestamp is known and a
	// later TLS observation serves the same leaf. Each observation is a direct
	// lower bound; no estimated successor timing is mixed into this event.
	if dc.ResidualFingerprint != "" && dc.ResidualFingerprint == cert.Fingerprint && dc.ResidualRevokedAt != nil && now.After(*dc.ResidualRevokedAt) {
		obs := s.newObs(dc.Domain, cert, models.ObsResidual, "", curDays, result)
		obs.ResidualDurationSeconds = int64(now.Sub(*dc.ResidualRevokedAt).Seconds())
		obs.Notes = fmt.Sprintf("The revoked leaf was still served %.1f hours after the CA revocation timestamp; direct lower bound at this observed endpoint.", now.Sub(*dc.ResidualRevokedAt).Hours())
		dc.ResidualObservationCount++
		dc.ResidualLastSeenAt = &now
		s.appendObs(obs)
	}

	// Expiry crossing.
	if hasPrev && prevDays >= 0 && curDays < 0 {
		s.appendObs(s.newObs(dc.Domain, cert, models.ObsExpiry, "", curDays, result))
	}

	// Milestone crossings (recorded once per domain+certificate+milestone).
	if hasPrev {
		for _, mc := range crossedMilestones(s.config, prevDays, curDays) {
			if s.db.MilestoneRecorded(dc.Domain, cert.Fingerprint, mc.Label) {
				continue
			}
			obs := s.newObs(dc.Domain, cert, models.ObsMilestone, mc.Label, curDays, result)
			s.appendObs(obs)
			stat.MilestoneScans++
			if mc.Before {
				s.fireAlert("certificate_expiring", dc.Domain, cert, mc.Label,
					fmt.Sprintf("Certificate for %s reached %s", dc.Domain, mc.Label))
			}
		}
	}

	// Revocation transition.
	// Revocation evidence belongs to a specific certificate. Do not carry the
	// previous certificate's status/check timestamp across a replacement while
	// the staged enrichment pass is still pending.
	if certificateChanged {
		dc.RevocationStatus = models.RevocationNotChecked
		dc.RevocationCheckedVia = models.CheckedViaNone
		dc.RevocationCheckedAt = nil
		dc.RevocationNextCheckAt = nil
		dc.RevokedAt = nil
		dc.RevocationReason = ""
		dc.OCSPCheckedAt = nil
	}
	newRev := result.RevocationStatus
	if newRev == models.RevocationGood || newRev == models.RevocationRevoked {
		known := dc.RevocationStatus == models.RevocationGood || dc.RevocationStatus == models.RevocationRevoked
		if !known || dc.RevocationStatus != newRev {
			obs := s.newObs(dc.Domain, cert, models.ObsRevocationChange, "", curDays, result)
			obs.RevocationStatus = newRev
			s.appendObs(obs)
			if newRev == models.RevocationRevoked {
				stat.RevocationsDetected = 1
				s.fireAlert("certificate_revoked", dc.Domain, cert, "",
					fmt.Sprintf("Certificate for %s is REVOKED (%s)", dc.Domain, result.RevocationReason))
			}
		}
		dc.RevocationStatus = newRev
	} else if dc.RevocationStatus == "" || dc.RevocationStatus == models.RevocationNotChecked {
		dc.RevocationStatus = newRev
	}

	// ---- ARI (CA-recommended renewal window) ----------------------------
	if result.ARI != nil {
		ariInfo := result.ARI
		if ariInfo.Status == models.ARIStatusOK {
			dc.ARISupported = true
			dc.ARIStatus = models.ARIStatusOK
			dc.ARIExplanationURL = ariInfo.ExplanationURL
			dc.ARICheckedAt = &now
			if ariInfo.NextPollAt != nil && ariInfo.NextPollAt.After(now) {
				np := *ariInfo.NextPollAt
				dc.ARINextPollAt = &np
			} else if ariInfo.RetryAfterSecs > 0 {
				np := now.Add(time.Duration(ariInfo.RetryAfterSecs) * time.Second)
				dc.ARINextPollAt = &np
			} else if s.config.ARIPollInterval > 0 {
				np := now.Add(s.config.ARIPollInterval)
				dc.ARINextPollAt = &np
			}
			// Window first seen or materially shifted → record a time-series event.
			if windowChanged(dc.ARIWindowStart, ariInfo.WindowStart, s.config.ARIChangeThreshold) {
				obs := s.newObs(dc.Domain, cert, models.ObsARIWindow, "", curDays, result)
				obs.ARIWindowStart = ariInfo.WindowStart
				obs.ARIWindowEnd = ariInfo.WindowEnd
				s.appendObs(obs)
			}
			// Emergency: CA pulled the window forward to "now" ahead of schedule.
			emergency := false
			if ariInfo.WindowStart != nil {
				emergency = models.ARIIsEmergency(now, cert.NotBefore, cert.NotAfter, *ariInfo.WindowStart)
			}
			if emergency && !dc.ARIEmergency {
				obs := s.newObs(dc.Domain, cert, models.ObsARIEmergency, "", curDays, result)
				obs.ARIWindowStart = ariInfo.WindowStart
				obs.ARIWindowEnd = ariInfo.WindowEnd
				obs.Notes = "CA pulled ARI renewal window forward to now — likely mass-revocation signal"
				s.appendObs(obs)
				s.fireAlert("certificate_ari_emergency", dc.Domain, cert, "",
					fmt.Sprintf("ARI emergency for %s: CA now recommends immediate renewal", dc.Domain))
			}
			dc.ARIEmergency = emergency
			dc.ARIWindowStart = ariInfo.WindowStart
			dc.ARIWindowEnd = ariInfo.WindowEnd
		} else {
			dc.ARIStatus = ariInfo.Status
			dc.ARISupported = ariInfo.Status != models.ARIStatusUnsupported
			dc.ARICheckedAt = &now
			if ariInfo.NextPollAt != nil && ariInfo.NextPollAt.After(now) {
				np := *ariInfo.NextPollAt
				dc.ARINextPollAt = &np
			} else if dc.ARISupported && s.config.ARIPollInterval > 0 {
				np := now.Add(s.config.ARIPollInterval)
				dc.ARINextPollAt = &np
			} else {
				dc.ARINextPollAt = nil
			}
		}
	}

	// ---- Update current state -------------------------------------------
	dc.Status = models.StatusActive
	dc.CurrentCertificateID = cert.ID
	dc.CurrentFingerprint = cert.Fingerprint
	if result.RevocationCheckedVia != models.CheckedViaNone {
		dc.RevocationCheckedVia = result.RevocationCheckedVia
	}
	if result.RevocationCheckedAt != nil {
		dc.RevocationCheckedAt = copyObservationTime(result.RevocationCheckedAt)
	}
	if result.RevokedAt != nil {
		dc.RevokedAt = result.RevokedAt
		dc.RevocationReason = result.RevocationReason
	} else if certificateChanged || result.RevocationStatus == models.RevocationGood {
		dc.RevokedAt = nil
		dc.RevocationReason = ""
	}
	if result.RevocationStatus == models.RevocationRevoked && result.RevokedAt != nil {
		if dc.ResidualFingerprint == cert.Fingerprint && dc.ResidualRevokedAt != nil {
			// Preserve the original CA timestamp while polling the same incident.
		} else {
			dc.ResidualFingerprint = cert.Fingerprint
			dc.ResidualRevokedAt = copyObservationTime(result.RevokedAt)
			dc.ResidualFirstSeenAt = &now
			dc.ResidualLastSeenAt = nil
			dc.ResidualObservationCount = 0
		}
		next := now.Add(s.config.MinGap)
		dc.ResidualNextCheckAt = &next
	} else if certificateChanged || dc.ResidualFingerprint == cert.Fingerprint {
		// Unknown/not-checked evidence must not erase an open residual incident;
		// only a successor or a positive CA status closes the tracking state.
		if certificateChanged || result.RevocationStatus == models.RevocationGood {
			dc.ResidualFingerprint = ""
			dc.ResidualRevokedAt = nil
			dc.ResidualFirstSeenAt = nil
			dc.ResidualLastSeenAt = nil
			dc.ResidualObservationCount = 0
			dc.ResidualNextCheckAt = nil
		}
	}
	if result.ResolvedIPsKnown && len(currentIPs) > 0 {
		encoded, _ := json.Marshal(currentIPs)
		if dc.ResolvedIPs == "" || topologyChanged {
			dc.LastDNSObservedAt = &now
		}
		dc.ResolvedIPs = string(encoded)
	}
	if result.RevocationCheckedVia == models.CheckedViaStapledOCSP || result.RevocationCheckedVia == models.CheckedViaOCSP {
		checked := now
		dc.OCSPCheckedAt = &checked
	}
	if result.EvidenceStatus == "" {
		result.EvidenceStatus = models.EvidenceStatusUnknown
	}
	dc.EvidenceStatus = result.EvidenceStatus
	dc.EvidencePendingReason = result.EvidencePendingReason
	switch result.EvidenceStatus {
	case models.EvidenceStatusComplete, models.EvidenceStatusNotApplicable:
		checked := now
		dc.EvidenceCheckedAt = &checked
		if s.scanCfg != nil && s.scanCfg.CheckRevocation && result.EvidenceStatus == models.EvidenceStatusComplete {
			next := now.Add(s.config.RevocationPollInterval)
			dc.RevocationNextCheckAt = &next
		}
	case models.EvidenceStatusPending:
		if s.scanCfg != nil && s.scanCfg.CheckRevocation {
			next := now.Add(s.config.MinGap)
			dc.RevocationNextCheckAt = &next
		}
	case models.EvidenceStatusBaseline:
		if s.scanCfg != nil && s.scanCfg.CheckRevocation && dc.RevocationNextCheckAt == nil {
			next := now.Add(s.config.RevocationPollInterval)
			dc.RevocationNextCheckAt = &next
		}
	}
	if dc.FirstSeenAt.IsZero() {
		dc.FirstSeenAt = now
	}
	dc.LastScannedAt = now
	dc.LastDaysUntilExpiry = curDays
	dc.ScanCount++
	// Record which endpoint produced this certificate so the next scan can tell a
	// replacement on one server apart from a different server answering.
	if result.ConnectionInfo != nil && result.ConnectionInfo.IPAddress != "" {
		dc.LastEndpointIP = result.ConnectionInfo.IPAddress
	}

	var ariNextPoll *time.Time
	if s.scanCfg != nil && s.scanCfg.CheckARI && dc.ARISupported {
		ariNextPoll = dc.ARINextPollAt
	}
	dc.NextScanAt = computeNextScanWithEvidence(s.config, now, cert.NotAfter, dc.ARIWindowStart, ariNextPoll, dc.RevocationNextCheckAt, dc.ARIEmergency)
	// Recheck soon only when a later round can add evidence: a real TLS
	// finding, or a rollout in progress whose duration and ordering are only
	// as precise as the gap between rounds. An inconclusive probe (timeout,
	// sampling cap) or an address this vantage cannot reach does not get
	// better by being asked again an hour later.
	rolloutActive := rolloutInProgress(result, previousSnapshots, replacements)
	if hasActionableTLSFinding(result.TLSFindings) || rolloutActive {
		recheck := now.Add(s.config.MinGap)
		if recheck.Before(dc.NextScanAt) {
			dc.NextScanAt = recheck
		}
	}
	if dc.ResidualNextCheckAt != nil && dc.ResidualNextCheckAt.Before(dc.NextScanAt) {
		dc.NextScanAt = *dc.ResidualNextCheckAt
	}
	dc.Priority = priorityForExpiry(now, cert.NotAfter)
	// A rollout in progress is measured only while it lasts: queue its
	// recheck ahead of routine baseline rounds so the hour gap is kept.
	if rolloutActive && dc.Priority < rolloutPriority {
		dc.Priority = rolloutPriority
	}
	if dc.RevocationStatus == models.RevocationRevoked && dc.Priority < 95 {
		dc.Priority = 95
	}
	if dc.ARIEmergency && dc.Priority < 95 {
		dc.Priority = 95
	}
	s.save(dc)
	propagate := func() {
		if s.propagation != nil {
			if renewalWatcherEligible(now, cert.NotAfter, dc.ARIWindowStart, s.propagation.WatchWindow()) {
				watchSince := now
				if dc.ARIWindowStart != nil && !now.Before(*dc.ARIWindowStart) {
					watchSince = *dc.ARIWindowStart
				}
				vendor := cdnVendorResult(result)
				if _, err := s.propagation.StartRenewalWatcher(dc.Domain, vendor, watchSince, cert.NotAfter); err != nil {
					log.Printf("scheduler: start CDN edge watcher for %s (%s): %v", dc.Domain, vendor, err)
				}
			}
		}
		if len(replacements) > 0 && s.propagation != nil {
			replacement := replacements[0]
			if _, err := s.propagation.StartOnCertificateChange(dc.Domain, replacement.Previous, replacement.Current, now, cdnVendorResult(result)); err != nil {
				log.Printf("scheduler: start CDN propagation experiment for %s: %v", dc.Domain, err)
			}
		}
	}
	if s.afterCommit != nil {
		s.afterCommit(propagate)
	} else {
		propagate()
	}
	if err := s.db.BumpDailyStat(stat); err != nil {
		s.resultErr = err
	}
	if s.onScanComplete != nil {
		s.onScanComplete(result)
	}
}

func renewalWatcherEligible(now, notAfter time.Time, ariWindowStart *time.Time, watchWindow time.Duration) bool {
	remaining := notAfter.Sub(now)
	if watchWindow <= 0 || remaining <= 0 || remaining > watchWindow {
		return false
	}
	return ariWindowStart == nil || !now.Before(*ariWindowStart)
}

// classifyCertificateChange decides what a fingerprint difference between two
// consecutive scans demonstrates.
//
// The difference is only a replacement in time when the same endpoint served
// both leaves and the predecessor is no longer answering anywhere in this
// round. When the round can still reach the predecessor on another address, the
// two certificates are deployed at the same time and the "change" is an artifact
// of which server answered.
type sameIPReplacement struct {
	IP       string
	Previous string
	Current  string
}

func (s *Scheduler) endpointCertificate(replacement sameIPReplacement, result *models.ScanResult) *models.Certificate {
	if result.Cert != nil && result.Cert.Fingerprint == replacement.Current {
		return result.Cert
	}
	if cert, err := s.db.GetCertificateByFingerprint(replacement.Current); err == nil {
		return cert
	}
	cert := &models.Certificate{Fingerprint: replacement.Current}
	for _, p := range result.EndpointProbes {
		if p.IPAddress != replacement.IP || p.Fingerprint != replacement.Current {
			continue
		}
		cert.SPKIFingerprint = p.SPKIFingerprint
		cert.CommonName, cert.IssuerCN, cert.SerialNumber = p.CommonName, p.IssuerCN, p.SerialNumber
		cert.SANs = marshalString(p.SANs)
		if p.NotBefore != nil {
			cert.NotBefore = *p.NotBefore
		}
		if p.NotAfter != nil {
			cert.NotAfter = *p.NotAfter
		}
	}
	return cert
}

func parseEndpointStatesJSON(raw string) map[string]models.EndpointState {
	states := make(map[string]models.EndpointState)
	if strings.TrimSpace(raw) == "" {
		return states
	}
	_ = json.Unmarshal([]byte(raw), &states)
	return states
}

func currentEndpointLeaves(result *models.ScanResult) map[string]string {
	leaves := make(map[string]string)
	if result == nil {
		return leaves
	}
	for ip, fingerprint := range endpointFingerprintSet(result.EndpointProbes) {
		leaves[ip] = fingerprint
	}
	if result.Cert != nil && result.ConnectionInfo != nil {
		ip := strings.TrimSpace(result.ConnectionInfo.IPAddress)
		if ip != "" && result.Cert.Fingerprint != "" {
			if _, exists := leaves[ip]; !exists {
				leaves[ip] = result.Cert.Fingerprint
			}
		}
	}
	return leaves
}

// sameIPReplacements counts only overlapping addresses whose leaf changed.
// A new IP has no previous leaf, so it is not a replacement. A retired IP is
// a topology event, not a certificate replacement.
func sameIPReplacements(previous map[string]models.EndpointState, current map[string]string) []sameIPReplacement {
	if len(previous) == 0 || len(current) == 0 {
		return nil
	}
	var replacements []sameIPReplacement
	for ip, nowLeaf := range current {
		ip = strings.TrimSpace(ip)
		nowLeaf = strings.TrimSpace(nowLeaf)
		if ip == "" || nowLeaf == "" {
			continue
		}
		state, ok := previous[ip]
		if !ok {
			continue
		}
		was := strings.TrimSpace(state.Fingerprint)
		if was == "" || was == nowLeaf {
			continue
		}
		replacements = append(replacements, sameIPReplacement{IP: ip, Previous: was, Current: nowLeaf})
	}
	sort.Slice(replacements, func(i, j int) bool { return replacements[i].IP < replacements[j].IP })
	return replacements
}

// withoutReturningLeaves drops "replacements" whose new leaf this same address
// already served in a retained earlier round. Renewal does not return to a
// retired certificate; an address switching back to one is a pool of servers
// behind that address being sampled. The newest leaf reaching another address
// is propagation and is kept.
func withoutReturningLeaves(replacements []sameIPReplacement, previous []models.MeasurementSnapshot) []sameIPReplacement {
	if len(replacements) == 0 || len(previous) == 0 {
		return replacements
	}
	served := make(map[string]map[string]struct{})
	for _, snapshot := range previous {
		for address, leaf := range endpointFingerprintSetFromSnapshot(snapshot) {
			if served[address] == nil {
				served[address] = make(map[string]struct{})
			}
			served[address][leaf] = struct{}{}
		}
		var probes []models.EndpointProbe
		if json.Unmarshal([]byte(snapshot.EndpointProbesJSON), &probes) == nil {
			for _, p := range probes {
				if !p.Success || p.IPAddress == "" {
					continue
				}
				if served[p.IPAddress] == nil {
					served[p.IPAddress] = map[string]struct{}{}
				}
				for _, fp := range append([]string{p.Fingerprint}, p.OtherFingerprints...) {
					if fp != "" {
						served[p.IPAddress][fp] = struct{}{}
					}
				}
			}
		}
	}
	kept := replacements[:0]
	for _, replacement := range replacements {
		if _, returning := served[replacement.IP][replacement.Current]; !returning {
			kept = append(kept, replacement)
		}
	}
	return kept
}

// withoutSplitAddresses drops addresses that gave the main handshake and the
// endpoint probe different leaves in this round: the address serves several
// leaves at once, so its difference from the last round is not a replacement.
func withoutSplitAddresses(replacements []sameIPReplacement, result *models.ScanResult) []sameIPReplacement {
	if len(replacements) == 0 || result == nil || result.Cert == nil || result.ConnectionInfo == nil {
		return replacements
	}
	mainIP := strings.TrimSpace(result.ConnectionInfo.IPAddress)
	split := make(map[string]bool)
	for _, probe := range result.EndpointProbes {
		if !probe.Success || probe.Fingerprint == "" {
			continue
		}
		// Several handshakes to this address in this round gave different
		// leaves, or the main handshake and the probe disagreed on it.
		if len(probe.OtherFingerprints) > 0 || (probe.IPAddress == mainIP && probe.Fingerprint != result.Cert.Fingerprint) {
			split[probe.IPAddress] = true
		}
	}
	if len(split) == 0 {
		return replacements
	}
	kept := replacements[:0]
	for _, replacement := range replacements {
		if !split[replacement.IP] {
			kept = append(kept, replacement)
		}
	}
	return kept
}

func classifyCertificateChange(result *models.ScanResult, previousFingerprint, currentFingerprint, previousIP, currentIP string) string {
	if previousFingerprint == "" || currentFingerprint == "" || previousFingerprint == currentFingerprint {
		return models.ChangeClassUnknown
	}
	sawPrevious, sawCurrent := false, false
	for _, probe := range result.EndpointProbes {
		if !probe.Success || probe.Fingerprint == "" {
			continue
		}
		if probe.Fingerprint == previousFingerprint {
			sawPrevious = true
		}
		if probe.Fingerprint == currentFingerprint {
			sawCurrent = true
		}
	}
	if sawPrevious && sawCurrent {
		return models.ChangeClassCoexisting
	}
	if previousIP == "" || currentIP == "" {
		return models.ChangeClassUnknown
	}
	if previousIP == currentIP {
		return models.ChangeClassReplacement
	}
	return models.ChangeClassEndpointSampling
}

func measurementTrigger(result *models.ScanResult, certificateChanged, topologyChanged bool) string {
	if result == nil {
		return "unknown"
	}
	if result.MeasurementTrigger != "" {
		return result.MeasurementTrigger
	}
	if len(result.EndpointProbes) > 0 {
		return "endpoint_survey"
	}
	if certificateChanged {
		return "certificate_change"
	}
	if topologyChanged {
		return "topology_change"
	}
	if result.DeepEvidence != nil {
		return "deep_poll"
	}
	return "baseline"
}

func topologyTransition(dc *models.DomainCertificate, result *models.ScanResult, previousIPs, currentIPs []string) bool {
	if dc == nil || result == nil || !result.ResolvedIPsKnown || len(previousIPs) == 0 || len(currentIPs) == 0 {
		return false
	}
	if result.Topology == nil {
		return !sameIPs(previousIPs, currentIPs)
	}
	oldConsensus := parseIPs(dc.ConsensusIPs)
	newConsensus := append([]string(nil), result.Topology.ConsensusIPs...)
	if len(oldConsensus) > 0 && len(newConsensus) > 0 {
		if sameIPs(oldConsensus, newConsensus) {
			// A CNAME control-plane change with a stable address set is still a
			// meaningful transition, but only when multiple resolvers agree.
			return dc.TopologyResolverQuorum >= 2 && result.Topology.ResolverQuorum >= 2 &&
				dc.TopologyCNAMEs != strings.Join(result.Topology.CNAMEChain, ",")
		}
		return dc.TopologyResolverQuorum >= 2 && result.Topology.ResolverQuorum >= 2 &&
			dc.TopologyResolverAgreement >= 0.5 && result.Topology.ResolverAgreement >= 0.5
	}
	// Backward-compatible fallback for rows written before resolver quorum was
	// persisted. Do not call a one-resolver RRset change a global transition.
	return !sameIPs(previousIPs, currentIPs) && result.Topology.ResolverQuorum >= 2 && result.Topology.ResolverAgreement >= 0.5
}

func staleEndpointEvidence(dc *models.DomainCertificate, result *models.ScanResult, previousFingerprint string, previousIPs, currentIPs []string) bool {
	if dc == nil || result == nil || previousFingerprint == "" || result.Cert == nil {
		return false
	}
	oldSet := make(map[string]struct{}, len(previousIPs))
	for _, ip := range previousIPs {
		oldSet[ip] = struct{}{}
	}
	newSet := make(map[string]struct{}, len(currentIPs))
	for _, ip := range currentIPs {
		newSet[ip] = struct{}{}
	}
	oldPredecessor := false
	newSuccessor := false
	for _, probe := range result.EndpointProbes {
		if !probe.Success || probe.Fingerprint == "" {
			continue
		}
		_, wasOld := oldSet[probe.IPAddress]
		_, isNew := newSet[probe.IPAddress]
		if wasOld && probe.Fingerprint == previousFingerprint {
			oldPredecessor = true
		}
		// The successor must be the leaf captured by the main SNI handshake.
		// Any arbitrary different certificate on a new IP is not enough to
		// establish that the topology change moved the current deployment.
		if isNew && probe.Fingerprint == result.Cert.Fingerprint && probe.Fingerprint != previousFingerprint {
			newSuccessor = true
		}
	}
	return oldPredecessor && newSuccessor
}

func deploymentFailureEvidence(dc *models.DomainCertificate, result *models.ScanResult, previous []models.MeasurementSnapshot, previousFingerprint string, certificateChanged bool) bool {
	if result == nil || !hasMixedDeployment(result.EndpointProbes) {
		return false
	}
	current := endpointFingerprintSet(result.EndpointProbes)
	if len(current) < 2 {
		return false
	}
	// Stable heterogeneity is the expected shape of many CDNs and dual-cert
	// deployments. Require at least two earlier rounds with the same per-IP map
	// before suppressing an event; this also handles a newly introduced edge.
	if stableEndpointDiversity(previous, current, 2) {
		return false
	}
	if len(previous) == 0 {
		return false
	}
	priorMixed := 0
	for _, snapshot := range previous {
		if snapshot.FingerprintCount >= 2 {
			priorMixed++
		}
	}
	if priorMixed == 0 {
		// A first multi-edge survey establishes a CDN baseline, not a failed
		// rollout. Upgrade only when the same round also contains the known
		// predecessor and a certificate replacement was observed.
		if !certificateChanged || previousFingerprint == "" {
			return false
		}
		containsPredecessor := false
		for _, fingerprint := range current {
			if fingerprint == previousFingerprint {
				containsPredecessor = true
				break
			}
		}
		if !containsPredecessor {
			return false
		}
	}
	for _, prior := range previous {
		before := endpointFingerprintSetFromSnapshot(prior)
		if endpointMapChanged(before, current) {
			return true
		}
	}
	// A cert replacement that leaves the predecessor on one sampled edge is a
	// rollout signal even if the map was not present in the immediately previous
	// deep row (for example after a baseline-only interval).
	if certificateChanged && previousFingerprint != "" {
		for _, fp := range current {
			if fp == previousFingerprint {
				return true
			}
		}
	}
	return false
}

func endpointFingerprintSet(probes []models.EndpointProbe) map[string]string {
	result := make(map[string]string)
	for _, probe := range probes {
		if probe.Success && probe.IPAddress != "" && probe.Fingerprint != "" {
			result[probe.IPAddress] = probe.Fingerprint
		}
	}
	return result
}

func endpointFingerprintSetFromSnapshot(snapshot models.MeasurementSnapshot) map[string]string {
	result := make(map[string]string)
	if strings.TrimSpace(snapshot.EndpointFingerprintsJSON) == "" {
		return result
	}
	_ = json.Unmarshal([]byte(snapshot.EndpointFingerprintsJSON), &result)
	return result
}

// endpointMapChanged reports whether the provider-to-certificate assignment
// moved between two rounds.
//
// Address identity is deliberately not the unit of comparison. A CDN hands out
// a different edge address on nearly every query, so comparing addresses
// reports a transition every round and makes a steady state indistinguishable
// from a rollout. What has to move for this to be a deployment transition is
// which provider network serves which certificate, or a provider entering or
// leaving the answer entirely.
func endpointMapChanged(before, after map[string]string) bool {
	beforeSignature := models.ProviderAssignmentSignature(before)
	afterSignature := models.ProviderAssignmentSignature(after)
	if beforeSignature == "" || afterSignature == "" {
		return len(before) != len(after)
	}
	return beforeSignature != afterSignature
}

// stableEndpointDiversity reports whether the current per-endpoint certificate
// assignment has already been seen in enough earlier rounds to be the
// deployment's steady state rather than a transition.
//
// The comparison is by provider network allocation, not by exact address. A CDN
// answers from a different edge address on nearly every query, so an
// address-keyed comparison never matches twice and a permanently stable
// arrangement looks like a fresh transition every round. Grouping by allocation
// keeps what is actually stable — which provider serves which certificate — and
// discards the part that rotates by design.
func stableEndpointDiversity(previous []models.MeasurementSnapshot, current map[string]string, needed int) bool {
	if len(current) < 2 || needed <= 0 {
		return false
	}
	signature := models.ProviderAssignmentSignature(current)
	if signature == "" {
		return false
	}
	matched := 0
	for _, snapshot := range previous {
		before := endpointFingerprintSetFromSnapshot(snapshot)
		if len(before) < 2 {
			continue
		}
		if models.ProviderAssignmentSignature(before) != signature {
			continue
		}
		matched++
		if matched >= needed {
			return true
		}
	}
	return false
}

func (s *Scheduler) recordMeasurement(dc *models.DomainCertificate, result *models.ScanResult, trigger string) []models.MeasurementSnapshot {
	if s.db == nil || dc == nil || result == nil {
		return nil
	}
	previous, err := s.db.GetMeasurementSnapshots(dc.Domain, 24)
	if err != nil {
		log.Printf("scheduler: load measurement history for %s: %v", dc.Domain, err)
	}
	observedAt := result.ScannedAt
	if observedAt.IsZero() {
		observedAt = s.now()
	}
	endpoints := make([]models.EndpointProbe, 0, len(result.EndpointProbes)+1)
	seenIPs := make(map[string]struct{})
	for _, probe := range result.EndpointProbes {
		endpoints = append(endpoints, probe)
		seenIPs[probe.IPAddress] = struct{}{}
	}
	if result.Cert != nil && result.ConnectionInfo != nil && result.ConnectionInfo.IPAddress != "" {
		if _, exists := seenIPs[result.ConnectionInfo.IPAddress]; !exists {
			endpoints = append(endpoints, models.EndpointProbe{
				IPAddress:       result.ConnectionInfo.IPAddress,
				Success:         true,
				Fingerprint:     result.Cert.Fingerprint,
				SPKIFingerprint: result.Cert.SPKIFingerprint,
				IssuerCN:        result.Cert.IssuerCN,
				CommonName:      result.Cert.CommonName,
				SerialNumber:    result.Cert.SerialNumber,
				SANs:            models.ParseSANs(result.Cert.SANs),
				KeyAlgorithm:    result.Cert.KeyAlgorithm,
				KeySize:         result.Cert.KeySize,
				SANsHash:        models.SANSetHash(models.ParseSANs(result.Cert.SANs)),
			})
		}
	}
	for _, probe := range endpoints {
		leaves := append([]models.EndpointProbe{probe}, probe.OtherLeaves...)
		for _, leaf := range leaves {
			der, err := base64.StdEncoding.DecodeString(leaf.RawCert)
			if err != nil || len(der) == 0 {
				continue
			}
			parsed, err := x509.ParseCertificate(der)
			if err != nil || models.Fingerprint(parsed) != leaf.Fingerprint {
				continue
			}
			if _, _, err := s.db.UpsertCertificate(models.FromX509Cert(parsed, observedAt)); err != nil {
				s.resultErr = err
				log.Printf("scheduler: store endpoint leaf: %v", err)
			}
		}
	}
	fingerprintMap := endpointFingerprintSet(endpoints)
	allFingerprints := make(map[string]struct{})
	for _, fp := range fingerprintMap {
		allFingerprints[fp] = struct{}{}
	}
	for _, probe := range endpoints {
		if !probe.Success {
			continue
		}
		for _, fp := range probe.OtherFingerprints {
			if fp != "" {
				allFingerprints[fp] = struct{}{}
			}
		}
	}
	snapshot := models.MeasurementSnapshot{
		Domain: dc.Domain, ObservedAt: observedAt, Trigger: trigger,
		ResolverQuorum: topologyQuorum(result), ResolverAgreement: topologyAgreement(result),
		EndpointCount: len(endpoints), SuccessfulEndpointCount: len(fingerprintMap), FingerprintCount: len(allFingerprints),
	}
	if result.Cert != nil {
		snapshot.CertificateFingerprint = result.Cert.Fingerprint
		snapshot.SPKIFingerprint = result.Cert.SPKIFingerprint
	}
	if result.Topology != nil {
		snapshot.TopologyHash = result.Topology.TopologyHash
		snapshot.TopologyJSON = marshalString(result.Topology)
	}
	snapshot.EndpointFingerprintsJSON = marshalString(fingerprintMap)
	if len(endpoints) > 0 {
		snapshot.EndpointProbesJSON = marshalString(endpoints)
	}
	if result.DeepEvidence != nil {
		snapshot.CAAJSON = marshalString(result.DeepEvidence.CAA)
		snapshot.CTJSON = marshalString(result.DeepEvidence.CT)
		snapshot.SCTJSON = marshalString(result.DeepEvidence.SCTs)
		snapshot.HTTPJSON = marshalString(result.DeepEvidence.HTTP)
		snapshot.DirectoryJSON = marshalString(result.DeepEvidence.Directory)
		snapshot.RelatedNamesJSON = marshalString(result.DeepEvidence.RelatedNames)
		snapshot.GlobalProbesJSON = marshalString(result.DeepEvidence.GlobalProbes)
		snapshot.ErrorsJSON = marshalString(result.DeepEvidence.Errors)
	}
	if strings.TrimSpace(snapshot.SCTJSON) == "" && result.ConnectionInfo != nil && len(result.ConnectionInfo.SCTs) > 0 {
		snapshot.SCTJSON = marshalString(result.ConnectionInfo.SCTs)
	}
	if err := s.db.SaveMeasurementSnapshot(&snapshot); err != nil {
		s.resultErr = err
		log.Printf("scheduler: save measurement snapshot for %s: %v", dc.Domain, err)
	}
	// Maintain a compact per-address state on the domain row for fast API reads.
	updateEndpointStates(dc, endpoints, observedAt)
	if len(result.EndpointProbes) > 0 {
		at := observedAt
		dc.LastEndpointProbeAt = &at
	}
	if result.DeepEvidence != nil {
		at := observedAt
		dc.LastDeepMeasurementAt = &at
	}
	splitAddress := false
	for _, p := range endpoints {
		if p.Success && len(p.OtherFingerprints) > 0 {
			splitAddress = true
		}
	}
	if splitAddress {
		dc.EndpointDiversityStatus = "concurrent_leaves"
		dc.EndpointDiversityRounds = 0
	} else if len(fingerprintMap) == 0 {
		dc.EndpointDiversityStatus = "unknown"
	} else if len(allFingerprints) < 2 {
		dc.EndpointDiversityStatus = "uniform"
		dc.EndpointDiversityRounds = 0
	} else if stableEndpointDiversity(previous, fingerprintMap, 2) {
		dc.EndpointDiversityStatus = "stable_cdn_diversity"
		dc.EndpointDiversityRounds++
	} else {
		dc.EndpointDiversityStatus = "transitioning"
		dc.EndpointDiversityRounds = 1
	}
	return previous
}

func topologyQuorum(result *models.ScanResult) int {
	if result != nil && result.Topology != nil {
		return result.Topology.ResolverQuorum
	}
	return 0
}

func topologyAgreement(result *models.ScanResult) float64 {
	if result != nil && result.Topology != nil {
		return result.Topology.ResolverAgreement
	}
	return 0
}

func marshalString(value interface{}) string {
	if value == nil {
		return ""
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func updateEndpointStates(dc *models.DomainCertificate, endpoints []models.EndpointProbe, observedAt time.Time) {
	if dc == nil {
		return
	}
	states := make(map[string]models.EndpointState)
	if strings.TrimSpace(dc.EndpointStates) != "" {
		_ = json.Unmarshal([]byte(dc.EndpointStates), &states)
	}
	for _, probe := range endpoints {
		ip := strings.TrimSpace(probe.IPAddress)
		if ip == "" {
			continue
		}
		state := states[ip]
		if state.IPAddress == "" {
			state.IPAddress = ip
			state.FirstSeenAt = observedAt
		}
		state.LastSeenAt = observedAt
		state.Observations++
		state.LastSuccess = probe.Success
		if probe.Success {
			state.Fingerprint = probe.Fingerprint
			state.SPKIFingerprint = probe.SPKIFingerprint
			state.IssuerCN = probe.IssuerCN
			state.CommonName = probe.CommonName
		} else {
			state.Failures++
		}
		states[ip] = state
	}
	dc.EndpointStates = marshalString(states)
}

func (s *Scheduler) newObs(domain string, cert *models.Certificate, obsType, milestone string, days int, r *models.ScanResult) *models.CertObservation {
	obs := &models.CertObservation{
		Domain:                domain,
		CertificateID:         cert.ID,
		Fingerprint:           cert.Fingerprint,
		ObservedAt:            r.ScannedAt,
		ObservationType:       obsType,
		Milestone:             milestone,
		DaysUntilExpiry:       days,
		RevocationStatus:      r.RevocationStatus,
		RevocationCheckedVia:  r.RevocationCheckedVia,
		RevocationCheckedAt:   copyObservationTime(r.RevocationCheckedAt),
		RevokedAt:             copyObservationTime(r.RevokedAt),
		RevocationReason:      r.RevocationReason,
		EvidenceStatus:        r.EvidenceStatus,
		EvidencePendingReason: r.EvidencePendingReason,
		SPKIFingerprint:       cert.SPKIFingerprint,
		ScanDurationMs:        r.ScanDuration.Milliseconds(),
		// Tag the row with the rule generation that produced it. Detection rules
		// have been tightened over time and the analysis layer must not extend
		// the current rules' guarantees to rows an older rule wrote.
		DetectorVersion: models.DetectorCurrent,
	}
	if r.ConnectionInfo != nil {
		obs.TLSVersion = r.ConnectionInfo.TLSVersion
		obs.CipherSuite = r.ConnectionInfo.CipherSuite
		obs.IPAddress = r.ConnectionInfo.IPAddress
	}
	if len(r.ResolvedIPs) > 0 {
		encoded, _ := json.Marshal(r.ResolvedIPs)
		obs.ResolvedIPs = string(encoded)
	}
	if len(r.EndpointProbes) > 0 {
		obs.EndpointProbes = marshalString(r.EndpointProbes)
	}
	if r.DeepEvidence != nil {
		obs.DeepEvidence = marshalString(r.DeepEvidence)
	}
	return obs
}

func parseIPs(raw string) []string {
	var encoded []string
	if json.Unmarshal([]byte(raw), &encoded) != nil {
		return nil
	}
	values := make([]string, 0, len(encoded))
	for _, value := range encoded {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil || !models.IsPublicIP(ip.String()) {
			continue
		}
		values = append(values, ip.String())
	}
	sort.Strings(values)
	return values
}

func sameIPs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if strings.TrimSpace(left[i]) != strings.TrimSpace(right[i]) {
			return false
		}
	}
	return true
}

func copyObservationTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func (s *Scheduler) appendObs(obs *models.CertObservation) {
	if err := s.db.AppendObservation(obs); err != nil {
		s.resultErr = err
		log.Printf("scheduler: append observation (%s/%s): %v", obs.Domain, obs.ObservationType, err)
	}
}

func (s *Scheduler) save(dc *models.DomainCertificate) {
	if err := s.db.SaveDomainCertificate(dc); err != nil {
		s.resultErr = err
		log.Printf("scheduler: save domain %s: %v", dc.Domain, err)
	}
}

func cdnVendorResult(result *models.ScanResult) string {
	if result == nil {
		return ""
	}
	var vendors []string
	if result.Topology != nil {
		vendors = append(vendors, models.CDNVendorsFromNames(result.Topology.CNAMEChain)...)
		vendors = append(vendors, models.CDNVendorsFromNames(result.Topology.HTTPSTargets)...)
		vendors = append(vendors, models.CDNVendorsFromNames(result.Topology.NSHosts)...)
	}
	if result.DeepEvidence != nil {
		vendors = append(vendors, models.CDNVendorFromHTTPFingerprint(result.DeepEvidence.HTTP)...)
		if result.DeepEvidence.Directory != nil {
			for _, endpoint := range result.DeepEvidence.Directory.Endpoints {
				if endpoint.Vendor != "" {
					vendors = append(vendors, endpoint.Vendor)
				}
			}
		}
	}
	for _, endpoint := range result.EndpointProbes {
		if vendor := models.CDNVendorFromAddress(endpoint.IPAddress); vendor != "" {
			vendors = append(vendors, vendor)
		}
	}
	if result.ConnectionInfo != nil {
		if vendor := models.CDNVendorFromAddress(result.ConnectionInfo.IPAddress); vendor != "" {
			vendors = append(vendors, vendor)
		}
	}
	sort.Strings(vendors)
	first := ""
	for i, vendor := range vendors {
		if vendor == "" || (i > 0 && vendor == vendors[i-1]) {
			continue
		}
		if first != "" {
			return "multi-cdn"
		}
		first = vendor
	}
	return first
}

// rolloutPriority queues rechecks of a rollout in progress ahead of routine
// baseline rounds (30) and of certificates more than a week from expiry.
const rolloutPriority = 75

func hasActionableTLSFinding(findings []models.TLSFinding) bool {
	for _, finding := range findings {
		if finding.Code != "endpoint_probe_inconclusive" {
			return true
		}
	}
	return false
}

// rolloutInProgress reports whether this round shows a certificate change
// still moving across the domain's addresses: an address replaced its leaf
// since its last observation, or several leaves are served and at least one
// address serves a different leaf than in the previous round.
func rolloutInProgress(result *models.ScanResult, previous []models.MeasurementSnapshot, replacements []sameIPReplacement) bool {
	if result == nil {
		return false
	}
	if len(replacements) > 0 {
		return true
	}
	if !hasMixedDeployment(result.EndpointProbes) || len(previous) == 0 {
		return false
	}
	before := endpointFingerprintSetFromSnapshot(previous[0])
	for address, leaf := range endpointFingerprintSet(result.EndpointProbes) {
		if was, ok := before[address]; ok && was != leaf {
			return true
		}
	}
	return false
}

func hasMixedDeployment(probes []models.EndpointProbe) bool {
	seen := map[string]struct{}{}
	for _, probe := range probes {
		if probe.Success && probe.Fingerprint != "" {
			seen[probe.Fingerprint] = struct{}{}
		}
	}
	return len(seen) > 1
}

func (s *Scheduler) fireAlert(kind, domain string, cert *models.Certificate, milestone, msg string) {
	if s.onAlert == nil {
		return
	}
	s.onAlert(&models.WebhookPayload{
		Type: kind, Domain: domain, Certificate: cert,
		Milestone: milestone, Message: msg, Timestamp: s.now(),
	})
}

func (s *Scheduler) startJob(domain, reason string, scheduledAt time.Time) *models.ScanJob {
	if s.db == nil {
		return nil
	}
	started := s.now()
	if scheduledAt.IsZero() {
		scheduledAt = started
	}
	job := &models.ScanJob{
		Domain:      domain,
		Reason:      reason,
		ScheduledAt: scheduledAt,
		StartedAt:   &started,
		Status:      models.ScanJobRunning,
	}
	if err := s.db.CreateScanJob(job); err != nil {
		log.Printf("scheduler: create scan job for %s: %v", domain, err)
		return nil
	}
	return job
}

func (s *Scheduler) finishJob(job *models.ScanJob, result *models.ScanResult) {
	if s.db == nil || job == nil {
		return
	}
	if err := s.db.FinishScanJob(job.ID, result); err != nil {
		log.Printf("scheduler: finish scan job %d: %v", job.ID, err)
	}
}

// scanForScheduler runs the cheap TLS baseline first and enriches only when the
// domain is a candidate or a low-frequency evidence poll is due.
func (s *Scheduler) scanForScheduler(ctx context.Context, dc *models.DomainCertificate) (*models.ScanResult, error) {
	now := s.now()
	due := s.evidenceDueBefore(dc, now)
	if due {
		// The scheduler's low-frequency evidence poll is a deliberate deep round,
		// even when the leaf happens not to change.
	}
	result, err := s.scanner.ScanBaselineWithRetry(ctx, dc.Domain)
	if err != nil {
		return result, err
	}
	if result == nil {
		return nil, fmt.Errorf("scanner returned nil result")
	}
	if !result.Success {
		return result, nil
	}
	if due || evidenceCandidateAfter(dc, result, now) {
		result.MeasurementTrigger = "candidate"
		s.scanner.Enrich(ctx, result)
		s.attachRelatedNameEvidence(ctx, dc, result)
	}
	if endpointProbeCandidate(dc, result) {
		// Probe both sides of a topology transition. Retired addresses are not
		// part of the current DNS answer, but they are exactly where stale edge
		// configuration can be proven or falsified.
		result.EndpointProbes = s.scanner.ProbeEndpointsRotated(ctx, dc.Domain, appendUniqueIPs(parseIPs(dc.ResolvedIPs), result.ResolvedIPs...), dc.ScanCount)
		result.MeasurementTrigger = "endpoint_survey"
		for _, probe := range result.EndpointProbes {
			// An address this vantage cannot reach is unobserved, not a
			// failed endpoint; it is kept on the probe, not raised as a finding.
			if !probe.Success && !probe.Unobservable {
				result.TLSFindings = append(result.TLSFindings, models.TLSFinding{Code: "endpoint_probe_inconclusive", Detail: "Additional endpoint probe did not obtain a certificate: " + probe.Error, IPAddress: probe.IPAddress})
			}
			for _, finding := range probe.Findings {
				duplicate := false
				for _, existing := range result.TLSFindings {
					if existing.Code == finding.Code && existing.IPAddress == finding.IPAddress && existing.Fingerprint == finding.Fingerprint {
						duplicate = true
						break
					}
				}
				if !duplicate {
					result.TLSFindings = append(result.TLSFindings, finding)
				}
			}
		}
		if len(appendUniqueIPs(parseIPs(dc.ResolvedIPs), result.ResolvedIPs...)) > len(result.EndpointProbes) {
			result.TLSFindings = append(result.TLSFindings, models.TLSFinding{Code: "endpoint_probe_inconclusive", Detail: "Endpoint sampling cap reached; untested addresses remain unknown"})
		}
	}
	return result, nil
}

func endpointProbeCandidate(dc *models.DomainCertificate, result *models.ScanResult) bool {
	if dc == nil || result == nil || !result.Success || result.Cert == nil {
		return false
	}
	if len(result.TLSFindings) > 0 || len(result.ResolvedIPs) > 1 {
		return true
	}
	if dc.CurrentFingerprint != "" && dc.CurrentFingerprint != result.Cert.Fingerprint {
		return true
	}
	previous := parseIPs(dc.ResolvedIPs)
	if !result.ResolvedIPsKnown {
		return false
	}
	current := result.ResolvedIPs
	return len(previous) > 0 && len(current) > 0 && !sameIPs(previous, current)
}

func appendUniqueIPs(values []string, more ...string) []string {
	for _, value := range more {
		if strings.TrimSpace(value) == "" {
			continue
		}
		found := false
		for _, existing := range values {
			if strings.TrimSpace(existing) == strings.TrimSpace(value) {
				found = true
				break
			}
		}
		if !found {
			values = append(values, strings.TrimSpace(value))
		}
	}
	sort.Strings(values)
	return values
}

func (s *Scheduler) evidenceDueBefore(dc *models.DomainCertificate, now time.Time) bool {
	if dc == nil {
		return false
	}
	if dc.ARIEmergency {
		return true
	}
	if dc.RevocationNextCheckAt != nil && !dc.RevocationNextCheckAt.After(now) {
		return true
	}
	if dc.ResidualNextCheckAt != nil && !dc.ResidualNextCheckAt.After(now) {
		return true
	}
	return dc.ARINextPollAt != nil && !dc.ARINextPollAt.After(now)
}

func evidenceCandidateAfter(dc *models.DomainCertificate, result *models.ScanResult, now time.Time) bool {
	if dc == nil || result == nil || !result.Success || result.Cert == nil {
		return false
	}
	if dc.EvidenceStatus == models.EvidenceStatusPending {
		return true
	}
	if dc.RevocationStatus == models.RevocationRevoked || dc.ResidualFingerprint != "" {
		return true
	}
	if dc.CurrentFingerprint == "" {
		return models.DaysUntil(result.Cert.NotAfter, now) <= 7
	}
	if dc.Status == models.StatusUnreachable || dc.CurrentFingerprint != result.Cert.Fingerprint {
		return true
	}
	return models.DaysUntil(result.Cert.NotAfter, now) <= 7
}

func (s *Scheduler) failureBackoff(failures int) time.Duration {
	d := time.Duration(failures) * s.config.FailureBackoffUnit
	if d > s.config.FailureBackoffMax {
		d = s.config.FailureBackoffMax
	}
	if d < s.config.MinGap {
		d = s.config.MinGap
	}
	return d
}

// ---------------------------------------------------------------------------
// On-demand operations (API)
// ---------------------------------------------------------------------------

// ScanNow performs an explicit full scan and persists the result. Routine
// background scheduling uses scanForScheduler's baseline-first path; a manual
// request is an intentional operator action and includes deep evidence.
func (s *Scheduler) ScanNow(domain string) (*models.ScanResult, error) {
	s.trancoMu.Lock()
	defer s.trancoMu.Unlock()

	domain = models.GetDomain(domain)
	dc, err := s.db.GetOrInitDomain(domain)
	if err != nil {
		return nil, err
	}
	job := s.startJob(domain, "manual_scan", s.now())
	ctx, cancel := context.WithTimeout(context.Background(), s.config.ScanTimeout)
	defer cancel()
	result, err := s.scanner.ScanFreshWithRetry(ctx, domain)
	if err != nil {
		result = &models.ScanResult{
			Domain:                domain,
			Success:               false,
			Error:                 err.Error(),
			FailureClass:          scanner.FailureClassForError(err),
			ScannedAt:             s.now(),
			RevocationStatus:      models.RevocationNotChecked,
			RevocationCheckedVia:  models.CheckedViaNone,
			EvidenceStatus:        models.EvidenceStatusNotApplicable,
			EvidencePendingReason: "No certificate was obtained for evidence enrichment.",
		}
	}
	if result != nil && result.Success && (dc.CurrentFingerprint == "" || dc.CurrentFingerprint != result.Cert.Fingerprint || endpointProbeCandidate(dc, result)) {
		result.EndpointProbes = s.scanner.ProbeEndpointsRotated(ctx, domain, appendUniqueIPs(parseIPs(dc.ResolvedIPs), result.ResolvedIPs...), dc.ScanCount)
	}
	if result != nil && result.Success {
		s.attachRelatedNameEvidence(ctx, dc, result)
	}
	s.processResult(dc, result)
	s.finishJob(job, result)
	return result, nil
}

// attachRelatedNameEvidence follows certificate SAN transitions outward to
// the current public DNS/TLS/HTTP state of those names. This runs only during
// a deep/manual round and stays bounded by scanner.related_name_probe_limit.
func (s *Scheduler) attachRelatedNameEvidence(ctx context.Context, dc *models.DomainCertificate, result *models.ScanResult) {
	if s == nil || s.db == nil || s.scanner == nil || dc == nil || result == nil || result.DeepEvidence == nil || s.scanCfg == nil || s.scanCfg.RelatedNameProbeLimit <= 0 {
		return
	}
	// Ask for a wider historical window than one probe round. The scanner
	// rotates over it using ScanCount, so large preview-name sets are covered
	// over successive deep measurements without unbounded fan-out.
	candidates, err := s.db.GetRelatedNameCandidates(dc.Domain, s.scanCfg.RelatedNameProbeLimit*8)
	if err != nil {
		result.DeepEvidence.Errors = append(result.DeepEvidence.Errors, "related SAN candidates: "+err.Error())
		return
	}
	if len(candidates) == 0 {
		return
	}
	rotation := dc.ScanCount
	for _, candidate := range candidates {
		if candidate.NeedsPriorityProbe {
			// Resolve incomplete public evidence first; only rotate once every
			// changed name has a conclusive public DNS outcome.
			rotation = 0
			break
		}
	}
	// Root scans can spend their complete deadline on CT or revocation. Changed
	// SAN follow-up gets its own bounded budget so a timeout there is recorded
	// as a root-scan limitation, not as a false statement about the subdomain.
	probeCtx, cancel := context.WithTimeout(context.Background(), s.scanCfg.RelatedNameProbeTimeout)
	defer cancel()
	result.DeepEvidence.RelatedNames = s.scanner.ProbeRelatedNames(probeCtx, dc.Domain, candidates, rotation, result.Topology, result.Cert, result.DeepEvidence.HTTP)
}

// ScanBatchNow scans many domains concurrently and persists each result. Batch
// scans are explicit operator actions, so each item receives a full scan.
func (s *Scheduler) ScanBatchNow(domains []string, workers int) ([]*models.ScanResult, []error) {
	if workers <= 0 {
		return nil, []error{fmt.Errorf("batch workers must be positive")}
	}
	s.trancoMu.Lock()
	defer s.trancoMu.Unlock()

	var (
		mu      sync.Mutex
		results []*models.ScanResult
		errs    []error
		wg      sync.WaitGroup
		sem     = make(chan struct{}, workers)
	)
	for _, domain := range domains {
		wg.Add(1)
		go func(raw string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			d := models.GetDomain(raw)
			dc, err := s.db.GetOrInitDomain(d)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			job := s.startJob(d, "manual_batch_scan", s.now())
			ctx, cancel := context.WithTimeout(context.Background(), s.config.ScanTimeout)
			result, err := s.scanner.ScanFreshWithRetry(ctx, d)
			if err != nil {
				result = &models.ScanResult{
					Domain:                d,
					Success:               false,
					Error:                 err.Error(),
					FailureClass:          scanner.FailureClassForError(err),
					ScannedAt:             s.now(),
					RevocationStatus:      models.RevocationNotChecked,
					RevocationCheckedVia:  models.CheckedViaNone,
					EvidenceStatus:        models.EvidenceStatusNotApplicable,
					EvidencePendingReason: "No certificate was obtained for evidence enrichment.",
				}
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			// An explicit batch scan is an operator-requested evidence round, so
			// sample endpoints even when the leaf and single-address topology look
			// unchanged. This is how one-address cases receive SNI/no-SNI controls.
			if result != nil && result.Success && result.Cert != nil {
				result.EndpointProbes = s.scanner.ProbeEndpointsRotated(ctx, d, appendUniqueIPs(parseIPs(dc.ResolvedIPs), result.ResolvedIPs...), dc.ScanCount)
				s.attachRelatedNameEvidence(ctx, dc, result)
			}
			cancel()
			s.processResult(dc, result)
			s.finishJob(job, result)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(domain)
	}
	wg.Wait()
	return results, errs
}

// ScheduleTrancoScans refreshes the ranked Tranco portion of the monitoring
// population. Refreshes are serialized and quiesce in-flight scans before
// pruning stale non-local rows.
func (s *Scheduler) ScheduleTrancoScans() (int, error) {
	s.trancoMu.Lock()
	defer s.trancoMu.Unlock()

	if s.tranco == nil {
		return 0, fmt.Errorf("tranco fetcher not configured")
	}
	wasPaused := s.IsPaused()
	s.Pause()
	defer func() {
		if !wasPaused {
			s.Resume()
		}
	}()
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	if err := s.waitForIdle(); err != nil {
		return 0, fmt.Errorf("wait for active scans before Tranco refresh: %w", err)
	}

	ranked, source, listID, err := s.tranco.FetchRanked()
	if err != nil {
		return 0, fmt.Errorf("failed to fetch Tranco list: %w", err)
	}
	n, err := s.db.RegisterTrancoDomains(ranked)
	if err != nil {
		return 0, err
	}
	_ = s.db.SaveTrancoList(&models.TrancoList{
		ListID: listID, Source: source,
		Date:  s.now().Format("2006-01-02"),
		Count: n, FetchedAt: s.now(),
	})
	log.Printf("scheduler: registered %d Tranco domains (source=%s, list=%s)", n, source, listID)
	return n, nil
}

// RefreshLocalLists reloads every configured local source and atomically
// replaces their combined membership. Parsing happens before scans are paused,
// so an unreadable or malformed source cannot interrupt existing monitoring.
func (s *Scheduler) RefreshLocalLists(ctx context.Context) (int, error) {
	if s.localLists == nil || !s.localLists.Enabled {
		return 0, fmt.Errorf("local list sources are not enabled")
	}
	domains, err := domainlist.LoadSources(ctx, s.localLists.Sources)
	if err != nil {
		return 0, err
	}

	s.trancoMu.Lock()
	defer s.trancoMu.Unlock()
	wasPaused := s.IsPaused()
	s.Pause()
	defer func() {
		if !wasPaused {
			s.Resume()
		}
	}()
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	if err := s.waitForIdle(); err != nil {
		return 0, fmt.Errorf("wait for active scans before local-list refresh: %w", err)
	}
	n, err := s.db.RegisterLocalDomains(domains)
	if err != nil {
		return 0, err
	}
	log.Printf("scheduler: registered %d domains from local lists", n)
	return n, nil
}

func (s *Scheduler) waitForIdle() error {
	if atomic.LoadInt64(&s.runningN) == 0 {
		return nil
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if atomic.LoadInt64(&s.runningN) == 0 {
			return nil
		}
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-ticker.C:
		}
	}
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

func (s *Scheduler) GetQueueStatus() *models.ScanQueue {
	today := s.db.GetTodayStat()
	return &models.ScanQueue{
		Pending:   int(s.db.CountDueDomains(s.now())),
		Running:   int(atomic.LoadInt64(&s.runningN)),
		Completed: today.SuccessfulScans,
		Failed:    today.FailedScans,
	}
}

func (s *Scheduler) GetPendingCount() int {
	return int(s.db.CountDueDomains(s.now()))
}

func (s *Scheduler) SetOnScanComplete(fn func(*models.ScanResult)) { s.onScanComplete = fn }
func (s *Scheduler) SetOnAlert(fn func(*models.WebhookPayload))    { s.onAlert = fn }

// ---------------------------------------------------------------------------
// Pure scheduling logic (unit-tested)
// ---------------------------------------------------------------------------

type milestoneCross struct {
	Label  string
	Days   int
	Before bool
}

// crossedMilestones returns the milestones passed when days-until-expiry moved
// from prevDays down to curDays.
func crossedMilestones(cfg *models.SchedulerConfig, prevDays, curDays int) []milestoneCross {
	var out []milestoneCross
	for _, m := range cfg.Milestones {
		if prevDays > m && curDays <= m && m >= 0 {
			out = append(out, milestoneCross{models.MilestoneLabel(m, true), m, true})
		}
	}
	for _, p := range cfg.PostExpiryChecks {
		thr := -p
		if prevDays > thr && curDays <= thr {
			out = append(out, milestoneCross{models.MilestoneLabel(p, false), p, false})
		}
	}
	return out
}

// computeNextScan returns the next scan time for a domain. It picks the nearest
// future expiry milestone (or the baseline cadence, whichever is sooner),
// additionally aligns to the CA-recommended ARI renewal window start when known,
// accelerates near the expiry instant, and pulls the scan much closer when the
// CA has flagged an emergency renewal — never scanning more often than MinGap.
func computeNextScan(cfg *models.SchedulerConfig, now, notAfter time.Time, ariWindowStart, ariNextPollAt *time.Time, emergency bool) time.Time {
	return computeNextScanWithEvidence(cfg, now, notAfter, ariWindowStart, ariNextPollAt, nil, emergency)
}

func computeNextScanWithEvidence(cfg *models.SchedulerConfig, now, notAfter time.Time, ariWindowStart, ariNextPollAt, revocationNextCheckAt *time.Time, emergency bool) time.Time {
	const day = 24 * time.Hour

	next := now.Add(cfg.BaselineInterval)

	consider := func(b time.Time) {
		if b.After(now) && b.Before(next) {
			next = b
		}
	}
	for _, m := range cfg.Milestones {
		consider(notAfter.Add(-time.Duration(m) * day))
	}
	consider(notAfter)
	for _, p := range cfg.PostExpiryChecks {
		consider(notAfter.Add(time.Duration(p) * day))
	}

	// Land a scan right at the CA's recommended renewal window start, to catch
	// the renewal as it happens rather than at the next hard-coded milestone.
	if ariWindowStart != nil {
		consider(*ariWindowStart)
	}
	// ARI clients are expected to poll renewalInfo periodically. For the MVP we
	// use the normal scan path for that poll, which is acceptable at Top-N
	// scale and keeps certificate/ARI state consistent.
	if ariNextPollAt != nil {
		consider(*ariNextPollAt)
	}
	if revocationNextCheckAt != nil {
		consider(*revocationNextCheckAt)
	}

	if absDuration(notAfter.Sub(now)) <= cfg.NearExpiryWindow {
		if cand := now.Add(cfg.NearExpiryInterval); cand.Before(next) {
			next = cand
		}
	}
	// An expired certificate that is still being served is an active security
	// finding. Keep probing it at the near-expiry cadence indefinitely instead
	// of downgrading it to a historical/low-frequency state after checkpoints.
	if !notAfter.After(now) {
		if cand := now.Add(cfg.NearExpiryInterval); cand.Before(next) {
			next = cand
		}
	}

	// Emergency (CA pulled the window to now) — densify to catch the reissue /
	// revocation quickly, regardless of how far off expiry still is.
	if emergency {
		if cand := now.Add(cfg.NearExpiryInterval); cand.Before(next) {
			next = cand
		}
	}

	if lower := now.Add(cfg.MinGap); next.Before(lower) {
		next = lower
	}
	return next
}

// windowChanged reports whether the ARI window start is newly present or has
// moved by more than an hour since the previously-recorded window.
func windowChanged(prev, cur *time.Time, threshold time.Duration) bool {
	if cur == nil {
		return false
	}
	if prev == nil {
		return true
	}
	return absDuration(cur.Sub(*prev)) > threshold
}

func scanReason(dc *models.DomainCertificate, now time.Time, pollDueTolerance time.Duration) string {
	if dc.CurrentFingerprint == "" || dc.ScanCount == 0 {
		return "initial_scan"
	}
	if dc.ARIEmergency {
		return "ari_emergency_followup"
	}
	if dc.RevocationNextCheckAt != nil && !dc.RevocationNextCheckAt.After(now.Add(pollDueTolerance)) {
		return "revocation_poll"
	}
	if dc.ARINextPollAt != nil && !dc.ARINextPollAt.After(now.Add(pollDueTolerance)) {
		return "ari_poll"
	}
	days := dc.LastDaysUntilExpiry
	switch {
	case days < 0:
		return "post_expiry_check"
	case days <= 1:
		return "expiry_1d_check"
	case days <= 3:
		return "expiry_3d_check"
	case days <= 7:
		return "expiry_7d_check"
	case days <= 10:
		return "expiry_10d_check"
	case days <= 30:
		return "expiry_30d_check"
	default:
		return "baseline_rescan"
	}
}

func priorityForExpiry(now, notAfter time.Time) int {
	switch d := models.DaysUntil(notAfter, now); {
	case d < 0:
		return 85
	case d <= 1:
		return 100
	case d <= 3:
		return 90
	case d <= 7:
		return 80
	case d <= 10:
		return 70
	case d <= 14:
		return 60
	case d <= 30:
		return 50
	default:
		return 30
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func maxInt(xs []int) int {
	m := 0
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
