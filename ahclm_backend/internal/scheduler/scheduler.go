package scheduler

import (
	"context"
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
	"ahclm/internal/models"
	"ahclm/internal/scanner"
	"ahclm/internal/tranco"
)

// Scheduler drives adaptive certificate scanning. Instead of a static queue it
// works off each domain's persisted NextScanAt, which is recomputed after every
// scan to cluster around certificate-expiry milestones.
type Scheduler struct {
	config  *models.SchedulerConfig
	scanCfg *models.ScannerConfig
	db      *database.Database
	scanner *scanner.Scanner
	tranco  *tranco.Fetcher

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	running  sync.Map // domain -> struct{} currently in flight
	runningN int64
	paused   atomic.Bool

	nowFn func() time.Time

	onScanComplete func(*models.ScanResult)
	onAlert        func(*models.WebhookPayload)
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
		dc.Priority = unreachablePriority
		s.save(dc)
		_ = s.db.BumpDailyStat(stat)
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
		log.Printf("scheduler: upsert certificate for %s: %v", dc.Domain, err)
		return
	}
	if isNew {
		stat.NewCerts = 1
	}

	curDays := models.DaysUntil(cert.NotAfter, now)
	hasPrev := dc.ScanCount > 0 && dc.CurrentFingerprint != ""
	prevFP := dc.CurrentFingerprint
	prevDays := dc.LastDaysUntilExpiry
	certificateChanged := hasPrev && prevFP != cert.Fingerprint
	previousIPs := parseIPs(dc.ResolvedIPs)
	dnsIPs := append([]string(nil), result.ResolvedIPs...)
	currentIPs := append([]string(nil), dnsIPs...)
	if len(currentIPs) == 0 && result.ConnectionInfo != nil && result.ConnectionInfo.IPAddress != "" {
		currentIPs = []string{result.ConnectionInfo.IPAddress}
	}
	sort.Strings(currentIPs)
	topologyChanged := result.ResolvedIPsKnown && len(previousIPs) > 0 && len(dnsIPs) > 0 && !sameIPs(previousIPs, dnsIPs)

	switch {
	case !hasPrev:
		s.appendObs(s.newObs(dc.Domain, cert, models.ObsInitial, "", curDays, result))
	case certificateChanged:
		stat.ChangesDetected = 1
		dc.ChangeCount++
		dc.LastChangedAt = &now
		obs := s.newObs(dc.Domain, cert, models.ObsChange, "", curDays, result)
		obs.PreviousFingerprint = prevFP
		if previous, e := s.db.GetCertificateByFingerprint(prevFP); e == nil {
			obs.PreviousSPKIFingerprint = previous.SPKIFingerprint
			if obs.PreviousSPKIFingerprint == "" {
				obs.PreviousSPKIFingerprint = models.SPKIFingerprintFromRaw(previous.RawCert)
			}
		}
		s.appendObs(obs)
		if obs.PreviousSPKIFingerprint != "" && obs.PreviousSPKIFingerprint == cert.SPKIFingerprint {
			sameKey := s.newObs(dc.Domain, cert, models.ObsSameKey, "", curDays, result)
			sameKey.PreviousFingerprint = prevFP
			sameKey.PreviousSPKIFingerprint = obs.PreviousSPKIFingerprint
			sameKey.Notes = "The leaf certificate changed while the SPKI fingerprint remained unchanged; this confirms same-key replacement, not private-key compromise."
			s.appendObs(sameKey)
		}
		s.fireAlert("certificate_changed", dc.Domain, cert, "",
			fmt.Sprintf("Certificate for %s changed", dc.Domain))
	}
	// A valid predecessor still served after a resolved public IP-set change is
	// the observable stale-after-change proxy used by the lifecycle literature.
	// The event is explicitly scoped to this resolver and does not claim a global
	// hosting or control-plane transition.
	if hasPrev && !certificateChanged && topologyChanged && cert.NotAfter.After(now) {
		obs := s.newObs(dc.Domain, cert, models.ObsStaleAfterChange, "", curDays, result)
		obs.PreviousResolvedIPs = dc.ResolvedIPs
		obs.Notes = "A still-valid leaf remained observable after the resolver's public A/AAAA set changed; this is a DNS/IP-set proxy, not proof of global control-plane change."
		if len(result.EndpointProbes) > 0 {
			encoded, _ := json.Marshal(result.EndpointProbes)
			obs.EndpointProbes = string(encoded)
		}
		s.appendObs(obs)
	}
	if certificateChanged || topologyChanged {
		if hasMixedDeployment(result.EndpointProbes) {
			obs := s.newObs(dc.Domain, cert, models.ObsDeploymentFailure, "", curDays, result)
			encoded, _ := json.Marshal(result.EndpointProbes)
			obs.EndpointProbes = string(encoded)
			obs.PreviousFingerprint = prevFP
			obs.Notes = "Multiple currently resolved endpoints served different leaf fingerprints during a candidate follow-up; this confirms an observed partial deployment, not global deployment failure."
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
	} else if result.RevocationStatus != models.RevocationRevoked {
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

	var ariNextPoll *time.Time
	if s.scanCfg != nil && s.scanCfg.CheckARI && dc.ARISupported {
		ariNextPoll = dc.ARINextPollAt
	}
	dc.NextScanAt = computeNextScanWithEvidence(s.config, now, cert.NotAfter, dc.ARIWindowStart, ariNextPoll, dc.RevocationNextCheckAt, dc.ARIEmergency)
	if dc.ResidualNextCheckAt != nil && dc.ResidualNextCheckAt.Before(dc.NextScanAt) {
		dc.NextScanAt = *dc.ResidualNextCheckAt
	}
	dc.Priority = priorityForExpiry(now, cert.NotAfter)
	if dc.RevocationStatus == models.RevocationRevoked && dc.Priority < 95 {
		dc.Priority = 95
	}
	if dc.ARIEmergency && dc.Priority < 95 {
		dc.Priority = 95
	}
	s.save(dc)
	_ = s.db.BumpDailyStat(stat)
	if s.onScanComplete != nil {
		s.onScanComplete(result)
	}
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
		log.Printf("scheduler: append observation (%s/%s): %v", obs.Domain, obs.ObservationType, err)
	}
}

func (s *Scheduler) save(dc *models.DomainCertificate) {
	if err := s.db.SaveDomainCertificate(dc); err != nil {
		log.Printf("scheduler: save domain %s: %v", dc.Domain, err)
	}
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
		s.scanner.Enrich(ctx, result)
	}
	if endpointProbeCandidate(dc, result) {
		result.EndpointProbes = s.scanner.ProbeEndpoints(ctx, dc.Domain, appendUniqueIPs(parseIPs(dc.ResolvedIPs), result.ResolvedIPs...))
	}
	return result, nil
}

func endpointProbeCandidate(dc *models.DomainCertificate, result *models.ScanResult) bool {
	if dc == nil || result == nil || !result.Success || result.Cert == nil {
		return false
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
	domain = models.GetDomain(domain)
	dc, err := s.db.GetOrInitDomain(domain)
	if err != nil {
		return nil, err
	}
	job := s.startJob(domain, "manual_scan", s.now())
	ctx, cancel := context.WithTimeout(context.Background(), s.config.ScanTimeout)
	defer cancel()
	result, err := s.scanner.ScanWithRetry(ctx, domain)
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
		result.EndpointProbes = s.scanner.ProbeEndpoints(ctx, domain, appendUniqueIPs(parseIPs(dc.ResolvedIPs), result.ResolvedIPs...))
	}
	s.processResult(dc, result)
	s.finishJob(job, result)
	return result, nil
}

// ScanBatchNow scans many domains concurrently and persists each result. Batch
// scans are explicit operator actions, so each item receives a full scan.
func (s *Scheduler) ScanBatchNow(domains []string, workers int) ([]*models.ScanResult, []error) {
	if workers <= 0 {
		return nil, []error{fmt.Errorf("batch workers must be positive")}
	}
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
			result, err := s.scanner.ScanWithRetry(ctx, d)
			cancel()
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
			if result != nil && result.Success && (dc.CurrentFingerprint == "" || dc.CurrentFingerprint != result.Cert.Fingerprint || endpointProbeCandidate(dc, result)) {
				result.EndpointProbes = s.scanner.ProbeEndpoints(ctx, d, appendUniqueIPs(parseIPs(dc.ResolvedIPs), result.ResolvedIPs...))
			}
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

// ScheduleTrancoScans fetches the Tranco list and registers its domains.
func (s *Scheduler) ScheduleTrancoScans() (int, error) {
	if s.tranco == nil {
		return 0, fmt.Errorf("tranco fetcher not configured")
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
	// use the normal scan path for that poll, which is acceptable at Top-1000
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
