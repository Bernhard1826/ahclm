package database

import (
	"encoding/json"
	"net"
	"sort"
	"strings"
	"time"

	"ahclm/internal/models"

	"gorm.io/gorm"
)

// CreateCDNPropagationExperiment persists a new propagation control row only
// for a domain in the current monitoring population.
func (d *Database) CreateCDNPropagationExperiment(experiment *models.CDNPropagationExperiment) error {
	if experiment == nil {
		return ErrDomainNotMonitored
	}
	experiment.Domain = models.GetDomain(experiment.Domain)
	if experiment.Domain == "" {
		return ErrDomainNotMonitored
	}
	var enrolled int64
	if err := d.db.Model(&models.DomainCertificate{}).Where("domain = ? AND "+monitoredPredicate, experiment.Domain).Count(&enrolled).Error; err != nil {
		return err
	}
	if enrolled == 0 {
		return ErrDomainNotMonitored
	}
	if experiment.Status == "" {
		experiment.Status = models.CDNPropagationRunning
	}
	return d.db.Create(experiment).Error
}

// GetDueCDNPropagationExperiments returns active experiments whose next
// Globalping round is due. The propagation manager caps how many are started.
func (d *Database) GetDueCDNPropagationExperiments(now time.Time, limit int) ([]models.CDNPropagationExperiment, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var experiments []models.CDNPropagationExperiment
	err := d.db.Where("status = ? AND next_measure_at <= ?", models.CDNPropagationRunning, now).
		Order("next_measure_at ASC, id ASC").Limit(limit).Find(&experiments).Error
	return experiments, err
}

// NextCDNPropagationMeasureAt lets manual 30-second experiments wake sooner
// than the configured automatic scan cadence.
func (d *Database) NextCDNPropagationMeasureAt() (*time.Time, error) {
	var result struct{ At *time.Time }
	err := d.db.Model(&models.CDNPropagationExperiment{}).Select("MIN(next_measure_at) AS at").Where("status = ?", models.CDNPropagationRunning).Scan(&result).Error
	return result.At, err
}

func (d *Database) GetQueuedCDNPropagationExperiments(limit int) ([]models.CDNPropagationExperiment, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var experiments []models.CDNPropagationExperiment
	err := d.db.Where("status = ?", models.CDNPropagationQueued).
		Order("created_at ASC, id ASC").Limit(limit).Find(&experiments).Error
	return experiments, err
}

func (d *Database) ActivateQueuedCDNPropagationExperiment(id uint, at time.Time) error {
	return d.db.Model(&models.CDNPropagationExperiment{}).
		Where("id = ? AND status = ?", id, models.CDNPropagationQueued).
		Updates(map[string]interface{}{
			"status":          models.CDNPropagationRunning,
			"started_at":      at,
			"next_measure_at": at,
		}).Error
}

// FindActiveCDNPropagation prevents duplicate automatic experiments for the
// same domain and target leaf while allowing a later rotation to start a new
// control row.
func (d *Database) FindActiveCDNPropagation(domain, targetFingerprint, certificateLayer, probeTarget, probeHost, probePath string, expectedHTTPStatus int, sourceUpdatedAt *time.Time) (*models.CDNPropagationExperiment, error) {
	var experiment models.CDNPropagationExperiment
	layer := models.NormalizePropagationCertificateLayer(certificateLayer)
	if layer == "" {
		layer = models.CDNPropagationLayerEdge
	}
	probeTarget = strings.TrimSpace(probeTarget)
	if ip := net.ParseIP(probeTarget); ip != nil {
		probeTarget = ip.String()
	} else {
		probeTarget = strings.TrimSuffix(strings.ToLower(probeTarget), ".")
		if probeTarget == "" {
			probeTarget = models.GetDomain(domain)
		}
	}
	probeHost = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(probeHost)), ".")
	// Older edge rows predate certificate_layer/probe_target columns. Treat
	// NULL/empty values as the public-domain edge target for duplicate checks.
	q := d.db.Where("domain = ? AND target_fingerprint = ? AND status IN ?", models.GetDomain(domain), strings.ToLower(strings.ReplaceAll(strings.TrimSpace(targetFingerprint), ":", "")), []string{models.CDNPropagationRunning, models.CDNPropagationQueued})
	if layer == models.CDNPropagationLayerEdge {
		q = q.Where("COALESCE(NULLIF(certificate_layer, ''), 'edge') = ?", layer).
			Where("(probe_target = ? OR COALESCE(probe_target, '') = '') AND (probe_host = ? OR COALESCE(probe_host, '') = '')", probeTarget, probeHost)
	} else {
		q = q.Where("certificate_layer = ? AND probe_target = ? AND probe_host = ?", layer, probeTarget, probeHost)
	}
	q = q.Where("COALESCE(probe_path, '') = ?", strings.TrimSpace(probePath))
	if layer == models.CDNPropagationLayerOriginViaCDN {
		q = q.Where("expected_http_status = ? AND source_updated_at = ?", expectedHTTPStatus, sourceUpdatedAt)
	}
	err := q.Order("id DESC").First(&experiment).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &experiment, nil
}

// FindLatestCDNPropagationWatcher returns the most recent unknown-target edge
// watcher for a domain, regardless of terminal status. The caller compares
// WatchNotAfter to avoid reopening a completed watch in the same expiry cycle.
func (d *Database) FindLatestCDNPropagationWatcher(domain string) (*models.CDNPropagationExperiment, error) {
	var experiment models.CDNPropagationExperiment
	err := d.db.Where("domain = ? AND watch_changes = ? AND certificate_layer = ?", models.GetDomain(domain), true, models.CDNPropagationLayerEdge).
		Order("started_at DESC, id DESC").First(&experiment).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &experiment, nil
}

func (d *Database) CountActiveCDNPropagationExperiments() (int64, error) {
	var count int64
	err := d.db.Model(&models.CDNPropagationExperiment{}).Where("status = ?", models.CDNPropagationRunning).Count(&count).Error
	return count, err
}

func (d *Database) GetCDNPropagationExperiment(id uint) (*models.CDNPropagationExperiment, error) {
	var experiment models.CDNPropagationExperiment
	if err := d.db.First(&experiment, id).Error; err != nil {
		return nil, err
	}
	return &experiment, nil
}

func (d *Database) ListCDNPropagationExperiments(domain, status string, limit int) ([]models.CDNPropagationExperiment, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := d.db.Model(&models.CDNPropagationExperiment{}).Order("created_at DESC, id DESC").Limit(limit)
	if domain = models.GetDomain(domain); domain != "" {
		q = q.Where("domain = ?", domain)
	}
	if status = strings.TrimSpace(status); status != "" {
		q = q.Where("status = ?", status)
	}
	var experiments []models.CDNPropagationExperiment
	return experiments, q.Find(&experiments).Error
}

// UpdateCDNPropagationExperiment applies only explicitly supplied columns so
// false/zero values remain meaningful state transitions.
func (d *Database) UpdateCDNPropagationExperiment(id uint, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}
	return d.db.Model(&models.CDNPropagationExperiment{}).Where("id = ?", id).Updates(updates).Error
}

func (d *Database) UpdateRunningCDNPropagationExperiment(id uint, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}
	return d.db.Model(&models.CDNPropagationExperiment{}).Where("id = ? AND status = ?", id, models.CDNPropagationRunning).Updates(updates).Error
}

func (d *Database) CancelCDNPropagationExperiment(id uint, at time.Time) error {
	return d.db.Model(&models.CDNPropagationExperiment{}).Where("id = ? AND status IN ?", id, []string{models.CDNPropagationRunning, models.CDNPropagationQueued}).Updates(map[string]interface{}{
		"status":            models.CDNPropagationCanceled,
		"completed_at":      at,
		"completion_reason": "canceled by operator",
		"next_measure_at":   at,
	}).Error
}

// SaveCDNPropagationRound commits the raw round and all regional observations
// together with the control-row state. A partially written round would make a
// regional lag look like a real edge result, so this is one transaction.
func (d *Database) SaveCDNPropagationRound(experimentID uint, round *models.CDNPropagationRound, observations []models.CDNPropagationObservation, updates map[string]interface{}) error {
	if round == nil {
		return nil
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		round.ExperimentID = experimentID
		if len(updates) > 0 {
			result := tx.Model(&models.CDNPropagationExperiment{}).Where("id = ? AND status = ?", experimentID, models.CDNPropagationRunning).Updates(updates)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 0 {
				return nil
			}
		}
		if err := tx.Create(round).Error; err != nil {
			return err
		}
		for i := range observations {
			observations[i].ExperimentID = experimentID
			observations[i].RoundID = round.ID
			if err := tx.Create(&observations[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// GetCDNPropagationReport builds the operator-facing summary from immutable
// rounds and regional rows. It is deliberately computed at read time so a
// report can be regenerated after an interrupted worker restart.
func (d *Database) GetCDNPropagationReport(id uint) (*models.CDNPropagationReport, error) {
	experiment, err := d.GetCDNPropagationExperiment(id)
	if err != nil {
		return nil, err
	}
	var rounds []models.CDNPropagationRound
	if err := d.db.Where("experiment_id = ?", id).Order("round_number ASC, id ASC").Find(&rounds).Error; err != nil {
		return nil, err
	}
	var observations []models.CDNPropagationObservation
	if err := d.db.Where("experiment_id = ?", id).Order("observed_at ASC, id ASC").Find(&observations).Error; err != nil {
		return nil, err
	}

	return BuildCDNPropagationReport(experiment, rounds, observations), nil
}

// BuildCDNPropagationReport derives results solely from durable measurement evidence.
func BuildCDNPropagationReport(experiment *models.CDNPropagationExperiment, rounds []models.CDNPropagationRound, observations []models.CDNPropagationObservation) *models.CDNPropagationReport {
	locations := make(map[string]models.CDNPropagationLocationSummary)
	roundTargets := make(map[uint]map[string]struct{})
	firstFingerprints := make(map[string]string)
	type changeGroup struct {
		item       models.CDNPropagationChangeSummary
		regionSeen map[string]time.Time
	}
	changeGroups := make(map[string]*changeGroup)
	var configured []string
	_ = json.Unmarshal([]byte(experiment.LocationsJSON), &configured)
	for _, location := range models.NormalizePropagationLocations(configured) {
		locations[location] = models.CDNPropagationLocationSummary{LocationKey: location, Continent: location, State: "unknown"}
	}
	for _, observation := range observations {
		key := strings.TrimSpace(observation.LocationKey)
		if key == "" {
			key = strings.ToUpper(strings.TrimSpace(observation.Continent))
		}
		if key == "" {
			key = "unknown"
		}
		item := locations[key]
		if item.LocationKey == "" {
			item.LocationKey = key
		}
		if observation.TLSObserved && observation.Fingerprint != "" && firstFingerprints[key] == "" {
			firstFingerprints[key] = observation.Fingerprint
			item.BaselineFingerprint = observation.Fingerprint
		}
		if item.Continent == "" {
			item.Continent = observation.Continent
		}
		if item.FirstObservedAt == nil || observation.ObservedAt.Before(*item.FirstObservedAt) {
			at := observation.ObservedAt
			item.FirstObservedAt = &at
		}
		if item.LastObservedAt == nil || observation.ObservedAt.After(*item.LastObservedAt) {
			at := observation.ObservedAt
			item.LastObservedAt = &at
			item.LatestFingerprint = observation.Fingerprint
			item.LastTLSObserved = observation.TLSObserved
			item.LastRequestSucceeded = observation.RequestSucceeded
			item.LastOriginVerified = observation.OriginVerified
			item.LastOriginFingerprint = observation.OriginFingerprint
			item.LastError = observation.Error
			item.LastHTTPStatus = observation.HTTPStatus
			item.Region, item.Country, item.City, item.ASN, item.Network = observation.Region, observation.Country, observation.City, observation.ASN, observation.Network
		}
		if observation.RequestSucceeded && (item.FirstRequestSuccessAt == nil || observation.ObservedAt.Before(*item.FirstRequestSuccessAt)) {
			at := observation.ObservedAt
			item.FirstRequestSuccessAt = &at
		}
		if observation.TLSObserved {
			item.AnsweredRounds++
		}
		if observation.IsTarget {
			item.TargetSeen = true
			if roundTargets[observation.RoundID] == nil {
				roundTargets[observation.RoundID] = make(map[string]struct{})
			}
			roundTargets[observation.RoundID][key] = struct{}{}
			if item.FirstTargetAt == nil || observation.ObservedAt.Before(*item.FirstTargetAt) {
				at := observation.ObservedAt
				item.FirstTargetAt = &at
			}
		}
		if observation.IsPrevious {
			item.PreviousSeen = true
			if item.LastPreviousAt == nil || observation.ObservedAt.After(*item.LastPreviousAt) {
				at := observation.ObservedAt
				item.LastPreviousAt = &at
			}
		}
		if observation.FingerprintChanged && observation.ChangeFromFingerprint != "" && observation.Fingerprint != "" {
			groupKey := observation.ChangeFromFingerprint + "\x00" + observation.Fingerprint
			group := changeGroups[groupKey]
			if group == nil {
				group = &changeGroup{item: models.CDNPropagationChangeSummary{
					PreviousFingerprint: observation.ChangeFromFingerprint,
					Fingerprint:         observation.Fingerprint,
					FirstSeenAt:         observation.ObservedAt,
					LastSeenAt:          observation.ObservedAt,
				}, regionSeen: make(map[string]time.Time)}
				changeGroups[groupKey] = group
			}
			if observation.ObservedAt.Before(group.item.FirstSeenAt) {
				group.item.FirstSeenAt = observation.ObservedAt
			}
			if observation.ObservedAt.After(group.item.LastSeenAt) {
				group.item.LastSeenAt = observation.ObservedAt
			}
			if at, ok := group.regionSeen[key]; !ok || observation.ObservedAt.Before(at) {
				group.regionSeen[key] = observation.ObservedAt
			}
		}
		locations[key] = item
	}
	// Keep the old certificate bound tied to observations before the first
	// target. A later rollback must not make the reported interval invert.
	firstTargetByLocation := make(map[string]time.Time)
	for _, observation := range observations {
		if !observation.IsTarget {
			continue
		}
		key := strings.TrimSpace(observation.LocationKey)
		if key == "" {
			key = strings.ToUpper(strings.TrimSpace(observation.Continent))
		}
		if key == "" {
			key = "unknown"
		}
		if at, ok := firstTargetByLocation[key]; !ok || observation.ObservedAt.Before(at) {
			firstTargetByLocation[key] = observation.ObservedAt
		}
	}
	previousBeforeTarget := make(map[string]time.Time)
	for _, observation := range observations {
		if !observation.IsPrevious {
			continue
		}
		key := strings.TrimSpace(observation.LocationKey)
		if key == "" {
			key = strings.ToUpper(strings.TrimSpace(observation.Continent))
		}
		if key == "" {
			key = "unknown"
		}
		if targetAt, hasTarget := firstTargetByLocation[key]; hasTarget && !observation.ObservedAt.Before(targetAt) {
			continue
		}
		if at, ok := previousBeforeTarget[key]; !ok || observation.ObservedAt.After(at) {
			previousBeforeTarget[key] = observation.ObservedAt
		}
	}

	ordered := make([]models.CDNPropagationLocationSummary, 0, len(locations))
	var firstTarget *time.Time
	var targetTimes []time.Time
	targetLocations := 0
	for _, item := range locations {
		if experiment.CertificateLayer == models.CDNPropagationLayerOriginViaCDN {
			switch {
			case item.LastObservedAt == nil:
				item.State = "unknown"
			case item.LastOriginVerified:
				item.State = "request_ok"
			case item.LastRequestSucceeded:
				item.State = "origin_unverified"
			default:
				item.State = "request_error"
			}
			if item.LastOriginVerified {
				targetLocations++
			}
		} else if experiment.WatchChanges {
			switch {
			case item.LastObservedAt == nil:
				item.State = "unknown"
			case !item.LastTLSObserved:
				item.State = "unreachable"
			case firstFingerprints[item.LocationKey] != "" && item.LatestFingerprint != firstFingerprints[item.LocationKey]:
				item.State = "changed"
				targetLocations++
			default:
				item.State = "baseline"
			}
		} else {
			switch {
			case item.LastObservedAt == nil:
				item.State = "unknown"
			case !item.LastTLSObserved:
				item.State = "unreachable"
			case item.LatestFingerprint == experiment.TargetFingerprint:
				item.State = "target"
				targetLocations++
			case experiment.PreviousFingerprint != "" && item.LatestFingerprint == experiment.PreviousFingerprint:
				item.State = "previous"
			default:
				item.State = "other"
			}
		}
		if item.FirstTargetAt != nil {
			seconds := item.FirstTargetAt.Sub(experiment.SourceUpdatedAt).Seconds()
			item.LatencySeconds = &seconds
		}
		if previousAt, ok := previousBeforeTarget[item.LocationKey]; ok {
			seconds := previousAt.Sub(experiment.SourceUpdatedAt).Seconds()
			item.LatencyLowerSeconds = &seconds
		}
		if item.FirstTargetAt != nil {
			at := *item.FirstTargetAt
			if firstTarget == nil || at.Before(*firstTarget) {
				firstTarget = &at
			}
			targetTimes = append(targetTimes, at)
		}
		ordered = append(ordered, item)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].LocationKey < ordered[j].LocationKey })

	expectedKeys := make(map[string]struct{}, len(configured))
	for _, location := range models.NormalizePropagationLocations(configured) {
		expectedKeys[location] = struct{}{}
	}
	var allRegionsTarget *time.Time
	if len(expectedKeys) > 0 {
		for _, round := range rounds {
			targets := roundTargets[round.ID]
			if len(targets) < len(expectedKeys) {
				continue
			}
			complete := true
			for key := range expectedKeys {
				if _, ok := targets[key]; !ok {
					complete = false
					break
				}
			}
			if complete {
				at := round.ObservedAt
				allRegionsTarget = &at
				break
			}
		}
	}

	changes := make([]models.CDNPropagationChangeSummary, 0, len(changeGroups))
	for _, group := range changeGroups {
		var earliest, latest time.Time
		for key, at := range group.regionSeen {
			group.item.Regions = append(group.item.Regions, key)
			if earliest.IsZero() || at.Before(earliest) {
				earliest = at
			}
			if at.After(latest) {
				latest = at
			}
		}
		sort.Strings(group.item.Regions)
		if !earliest.IsZero() && !latest.IsZero() {
			group.item.FirstSeenSpreadSecs = latest.Sub(earliest).Seconds()
		}
		changes = append(changes, group.item)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].FirstSeenAt.Before(changes[j].FirstSeenAt) })
	report := &models.CDNPropagationReport{Experiment: *experiment, Rounds: rounds, Locations: ordered, Changes: changes, FirstTargetAt: firstTarget, AllRegionsTargetAt: allRegionsTarget, CompletedAt: experiment.CompletedAt}
	if firstTarget != nil {
		seconds := firstTarget.Sub(experiment.SourceUpdatedAt).Seconds()
		report.SourceToFirstSeconds = &seconds
	}
	if experiment.Status == models.CDNPropagationComplete && experiment.CompletedAt != nil {
		seconds := experiment.CompletedAt.Sub(experiment.SourceUpdatedAt).Seconds()
		report.SourceToCompleteSeconds = &seconds
	}
	if allRegionsTarget != nil {
		seconds := allRegionsTarget.Sub(experiment.SourceUpdatedAt).Seconds()
		report.SourceToAllRegionsSeconds = &seconds
	}
	if len(targetTimes) > 1 {
		sort.Slice(targetTimes, func(i, j int) bool { return targetTimes[i].Before(targetTimes[j]) })
		spread := targetTimes[len(targetTimes)-1].Sub(targetTimes[0]).Seconds()
		report.SynchronizationSpreadSeconds = &spread
	}
	expected := experiment.ExpectedLocations
	if expected <= 0 {
		expected = len(ordered)
	}
	if experiment.Status == models.CDNPropagationQueued {
		report.SyncState = models.CDNPropagationQueued
		report.Interpretation = "The experiment is saved and waiting for an active Globalping slot."
	} else if experiment.CertificateLayer == models.CDNPropagationLayerOriginViaCDN {
		switch {
		case experiment.Status == models.CDNPropagationComplete && expected > 0 && targetLocations >= expected:
			report.SyncState = "origin_verified"
			report.Interpretation = "All sampled regions returned a fresh origin response over a TLS connection using the target origin certificate for the required stable rounds. These are observation upper bounds, including polling and queue delay, not global CDN deployment times. Trust depends on the controlled origin endpoint and CDN TLS configuration."
		case experiment.Status == models.CDNPropagationTimeout:
			report.SyncState = "incomplete"
			report.Interpretation = "The experiment reached its time limit before every sampled region verified the target origin certificate. Missing or failed regions remain unresolved."
		case experiment.Status == models.CDNPropagationCanceled:
			report.SyncState = "canceled"
			report.Interpretation = "The experiment was canceled before every sampled region verified the target origin certificate."
		default:
			report.SyncState = "in_progress"
			report.Interpretation = "The experiment checks a fresh nonce and the origin TLS connection certificate through the CDN; HTTP success alone does not verify certificate adoption."
		}
	} else if experiment.WatchChanges && experiment.Status == models.CDNPropagationRunning {
		report.SyncState = "watching"
		report.Interpretation = "This baseline watcher records each location's initial leaf and reports later fingerprint changes with first-seen times. The region spread applies only to observed probes, not every CDN point of presence."
	} else if experiment.WatchChanges && experiment.Status == models.CDNPropagationTimeout {
		report.SyncState = "watch_ended"
		report.Interpretation = "The baseline watcher reached its configured time limit. Its recorded changes and first-seen times describe only the sampled locations and observation interval."
	} else if experiment.Status == models.CDNPropagationComplete && expected > 0 && targetLocations >= expected {
		spread := float64(0)
		if report.SynchronizationSpreadSeconds != nil {
			spread = *report.SynchronizationSpreadSeconds
		}
		threshold := float64(propagationMaxInt64(1, experiment.PollIntervalSeconds) * int64(propagationMaxInt(1, experiment.StableRoundsRequired)))
		if spread <= threshold {
			report.SyncState = "synchronized"
			report.Interpretation = "All configured regions served the target certificate for the required stable rounds; the observed first-seen spread is within the polling bound."
		} else {
			report.SyncState = "regional_lag"
			report.Interpretation = "All configured regions eventually served the target certificate, but their first-seen times show a measurable regional lag."
		}
	} else if experiment.Status == models.CDNPropagationTimeout {
		report.SyncState = "incomplete"
		report.Interpretation = "The experiment reached its time limit before every configured region served the target certificate; missing regions remain unknown rather than being treated as old."
	} else if experiment.Status == models.CDNPropagationCanceled {
		report.SyncState = "canceled"
		report.Interpretation = "The experiment was canceled before regional propagation was confirmed."
	} else if experiment.Status == models.CDNPropagationFailed {
		report.SyncState = "failed"
		report.Interpretation = "The experiment failed before regional propagation was confirmed."
	} else {
		report.SyncState = "in_progress"
		report.Interpretation = "The experiment is still collecting independent regional HTTPS observations; completion requires every configured region to serve the target for the stable-round threshold."
	}
	return report
}

func propagationMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func propagationMaxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
