package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"ahclm/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// Database handles all persistence operations.
type Database struct {
	db  *gorm.DB
	cfg *models.DatabaseConfig
}

// New connects to PostgreSQL (creating the target database if needed),
// migrates the schema and returns a ready Database.
func New(cfg *models.DatabaseConfig) (*Database, error) {
	if err := ensureDatabase(cfg); err != nil {
		return nil, err
	}

	// ErrRecordNotFound is a normal, handled control-flow signal here (a new
	// fingerprint in UpsertCertificate, a first-seen domain in GetOrInitDomain,
	// etc.), so silence it in the logger — otherwise every new/changed cert
	// prints a scary-looking "record not found" line. Real errors still log.
	gormLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	db, err := gorm.Open(postgres.Open(cfg.DSN(cfg.Database)), &gorm.Config{
		Logger: gormLogger,
		// The CurrentCertificate association is only used for Preload; we don't
		// want a hard FK constraint (a domain may legitimately have no current
		// certificate yet, i.e. current_certificate_id = 0).
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying db: %w", err)
	}
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConnections)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConnections)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	if err := db.AutoMigrate(
		&models.Certificate{},
		&models.DomainCertificate{},
		&models.CertObservation{},
		&models.DailyScanStat{},
		&models.TrancoList{},
		&models.ScanJob{},
		&models.ARICacheEntry{},
		&models.CRLCacheEntry{},
		&models.CertificateAlert{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	createIndexes(db)
	if repaired, err := repairScanJobMetadata(db); err != nil {
		log.Printf("warning: could not repair scan job metadata: %v", err)
	} else if repaired > 0 {
		log.Printf("repaired %d scan metadata rows", repaired)
	}
	if repaired, err := repairEvidenceMetadata(db); err != nil {
		log.Printf("warning: could not repair evidence metadata: %v", err)
	} else if repaired > 0 {
		log.Printf("normalized %d historical evidence status rows", repaired)
	}

	return &Database{db: db, cfg: cfg}, nil
}

// ensureDatabase connects to the maintenance "postgres" database and creates
// the target database if it does not already exist.
func ensureDatabase(cfg *models.DatabaseConfig) error {
	admin, err := gorm.Open(postgres.Open(cfg.DSN("postgres")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to maintenance database: %w", err)
	}
	defer func() {
		if s, e := admin.DB(); e == nil {
			_ = s.Close()
		}
	}()

	var exists bool
	if err := admin.Raw("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = ?)", cfg.Database).Scan(&exists).Error; err != nil {
		return fmt.Errorf("failed to check database existence: %w", err)
	}
	if !exists {
		// Database identifiers cannot be parameterized; the name comes from config.
		if err := admin.Exec(fmt.Sprintf("CREATE DATABASE %q", cfg.Database)).Error; err != nil {
			return fmt.Errorf("failed to create database %q: %w", cfg.Database, err)
		}
	}
	return nil
}

// createIndexes adds indexes that GORM tags can't express (partial unique) and
// drops the auto-created FK constraint that a fresh (cert-less) domain violates.
func createIndexes(db *gorm.DB) {
	db.Exec(`ALTER TABLE domain_certificates DROP CONSTRAINT IF EXISTS fk_domain_certificates_current_certificate`)
	// Each domain records an expiry milestone at most once for a given
	// certificate. The domain is required here because one SAN/CDN certificate
	// can be deployed by many monitored sites.
	db.Exec(`DROP INDEX IF EXISTS uq_obs_milestone`)
	db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uq_obs_milestone
		ON cert_observations (domain, fingerprint, milestone)
		WHERE observation_type = 'milestone'`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_obs_domain_time
		ON cert_observations (domain, observed_at DESC)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_dc_next_scan
		ON domain_certificates (next_scan_at)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_scan_jobs_domain_started
		ON scan_jobs (domain, started_at DESC)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_ari_cache_expiry
		ON ari_cache_entries (expires_at)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_crl_cache_expiry
		ON crl_cache_entries (expires_at)`)
}

// repairScanJobMetadata fixes rows written before metadata normalization was
// added. The operation is idempotent and runs before the scheduler starts.
func repairScanJobMetadata(db *gorm.DB) (int64, error) {
	var repaired int64

	// A clock adjustment or an older writer can leave an impossible interval.
	// Preserve the only defensible lower bound for the completion time.
	timestamps := db.Exec(`
		UPDATE scan_jobs
		SET finished_at = started_at, updated_at = now()
		WHERE started_at IS NOT NULL
		  AND finished_at IS NOT NULL
		  AND finished_at < started_at`)
	if timestamps.Error != nil {
		return repaired, timestamps.Error
	}
	repaired += timestamps.RowsAffected

	var jobs []models.ScanJob
	if err := db.Where("success = ? AND (failure_class IS NULL OR failure_class = '')", false).Find(&jobs).Error; err != nil {
		return repaired, err
	}
	byClass := make(map[string][]uint)
	for _, job := range jobs {
		class := models.ClassifyScanFailure(errors.New(job.Error))
		byClass[class] = append(byClass[class], job.ID)
	}
	for class, ids := range byClass {
		result := db.Model(&models.ScanJob{}).
			Where("id IN ? AND (failure_class IS NULL OR failure_class = '')", ids).
			Update("failure_class", class)
		if result.Error != nil {
			return repaired, result.Error
		}
		repaired += result.RowsAffected
	}

	var domains []models.DomainCertificate
	if err := db.Where("last_error <> ? AND (last_failure_class IS NULL OR last_failure_class = '')", "").Find(&domains).Error; err != nil {
		return repaired, err
	}
	byClass = make(map[string][]uint)
	for _, domain := range domains {
		class := models.ClassifyScanFailure(errors.New(domain.LastError))
		byClass[class] = append(byClass[class], domain.ID)
	}
	for class, ids := range byClass {
		result := db.Model(&models.DomainCertificate{}).
			Where("id IN ? AND (last_failure_class IS NULL OR last_failure_class = '')", ids).
			Update("last_failure_class", class)
		if result.Error != nil {
			return repaired, result.Error
		}
		repaired += result.RowsAffected
	}

	return repaired, nil
}

// repairEvidenceMetadata gives rows written by older binaries an explicit
// evidence state. Empty strings mean that the staged evidence pipeline has no
// durable status for that historical observation; they are not equivalent to
// a completed external check.
func repairEvidenceMetadata(db *gorm.DB) (int64, error) {
	var repaired int64

	// Older AHCLM versions already persisted the result of OCSP/CRL/ARI checks,
	// but did not persist the staged-pipeline status. Preserve that meaning as
	// complete instead of downgrading known historical evidence to unknown.
	completeDomain := db.Model(&models.DomainCertificate{}).
		Where("(evidence_status IS NULL OR evidence_status = '' OR evidence_status = ?) AND ((revocation_checked_via IS NOT NULL AND revocation_checked_via <> '' AND revocation_checked_via <> ?) OR revocation_checked_at IS NOT NULL OR ari_checked_at IS NOT NULL)", models.EvidenceStatusUnknown, models.CheckedViaNone).
		Update("evidence_status", models.EvidenceStatusComplete)
	if completeDomain.Error != nil {
		return repaired, completeDomain.Error
	}
	repaired += completeDomain.RowsAffected

	completeObservation := db.Model(&models.CertObservation{}).
		Where("(evidence_status IS NULL OR evidence_status = '' OR evidence_status = ?) AND ((revocation_checked_via IS NOT NULL AND revocation_checked_via <> '' AND revocation_checked_via <> ?) OR revocation_checked_at IS NOT NULL OR ari_window_start IS NOT NULL OR ari_window_end IS NOT NULL)", models.EvidenceStatusUnknown, models.CheckedViaNone).
		Update("evidence_status", models.EvidenceStatusComplete)
	if completeObservation.Error != nil {
		return repaired, completeObservation.Error
	}
	repaired += completeObservation.RowsAffected

	for _, model := range []interface{}{&models.DomainCertificate{}, &models.CertObservation{}} {
		result := db.Model(model).
			Where("evidence_status IS NULL OR evidence_status = ''").
			Update("evidence_status", models.EvidenceStatusUnknown)
		if result.Error != nil {
			return repaired, result.Error
		}
		repaired += result.RowsAffected
	}
	return repaired, nil
}

// Close closes the database connection.
func (d *Database) Close() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Ping verifies connectivity.
func (d *Database) Ping() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

// GetDatabaseSize returns a human-readable size of the current database.
func (d *Database) GetDatabaseSize() string {
	var size string
	if err := d.db.Raw("SELECT pg_size_pretty(pg_database_size(current_database()))").Scan(&size).Error; err != nil {
		return "unknown"
	}
	return size
}

// ---------------------------------------------------------------------------
// Certificate (distinct physical certs)
// ---------------------------------------------------------------------------

// UpsertCertificate inserts the certificate if its fingerprint is new, else
// refreshes LastSeenAt. Returns the persisted row and whether it was created.
func (d *Database) UpsertCertificate(cert *models.Certificate) (*models.Certificate, bool, error) {
	var existing models.Certificate
	err := d.db.Where("fingerprint = ?", cert.Fingerprint).First(&existing).Error
	if err == nil {
		updates := map[string]interface{}{"last_seen_at": cert.LastSeenAt}
		if existing.SPKIFingerprint == "" && cert.SPKIFingerprint != "" {
			updates["spki_fingerprint"] = cert.SPKIFingerprint
			existing.SPKIFingerprint = cert.SPKIFingerprint
		}
		// Backfill the chain on certs first recorded before chain capture existed.
		if existing.Chain == "" && cert.Chain != "" {
			updates["chain"] = cert.Chain
			existing.Chain = cert.Chain
		}
		d.db.Model(&existing).Updates(updates)
		existing.LastSeenAt = cert.LastSeenAt
		return &existing, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, err
	}
	if cert.FirstSeenAt.IsZero() {
		cert.FirstSeenAt = cert.LastSeenAt
	}
	if err := d.db.Create(cert).Error; err != nil {
		// Possible race with a concurrent insert of the same fingerprint.
		var again models.Certificate
		if d.db.Where("fingerprint = ?", cert.Fingerprint).First(&again).Error == nil {
			return &again, false, nil
		}
		return nil, false, err
	}
	return cert, true, nil
}

func (d *Database) GetCertificateByID(id uint) (*models.Certificate, error) {
	var cert models.Certificate
	if err := d.db.First(&cert, id).Error; err != nil {
		return nil, err
	}
	return &cert, nil
}

// GetCertificateByFingerprint returns the retained certificate needed to
// compare consecutive leaf SPKIs when classifying a replacement.
func (d *Database) GetCertificateByFingerprint(fingerprint string) (*models.Certificate, error) {
	var cert models.Certificate
	if err := d.db.Where("fingerprint = ?", fingerprint).First(&cert).Error; err != nil {
		return nil, err
	}
	return &cert, nil
}

// ListCertificates returns distinct certificates with pagination/filtering.
func (d *Database) ListCertificates(f *models.CertificateFilter) ([]models.Certificate, int64, error) {
	var certs []models.Certificate
	var total int64

	q := d.db.Model(&models.Certificate{})
	if f.Issuer != "" {
		q = q.Where("issuer ILIKE ?", "%"+f.Issuer+"%")
	}
	if f.Domain != "" {
		q = q.Where("common_name ILIKE ? OR sans ILIKE ?", "%"+f.Domain+"%", "%"+f.Domain+"%")
	}
	if f.ExpiringDays > 0 {
		q = q.Where("not_after > now() AND not_after <= ?", time.Now().AddDate(0, 0, f.ExpiringDays))
	}
	if f.Expired {
		q = q.Where("not_after < now()")
	}
	q.Count(&total)

	order := fmt.Sprintf("%s %s", safeSort(f.SortBy, "not_after"), safeOrder(f.SortOrder))
	offset := (f.Page - 1) * f.PerPage
	if err := q.Order(order).Offset(offset).Limit(f.PerPage).Find(&certs).Error; err != nil {
		return nil, 0, err
	}
	return certs, total, nil
}

// ---------------------------------------------------------------------------
// DomainCertificate (per-domain current state + scheduling)
// ---------------------------------------------------------------------------

// SaveDomainCertificate creates or updates a domain row (associations omitted;
// certificates are persisted separately via UpsertCertificate).
func (d *Database) SaveDomainCertificate(dc *models.DomainCertificate) error {
	return d.db.Omit("CurrentCertificate").Save(dc).Error
}

// GetDomainCertificate loads a domain row with its current certificate.
func (d *Database) GetDomainCertificate(domain string) (*models.DomainCertificate, error) {
	var dc models.DomainCertificate
	err := d.db.Preload("CurrentCertificate").Where("domain = ?", domain).First(&dc).Error
	if err != nil {
		return nil, err
	}
	return &dc, nil
}

// GetOrInitDomain returns the domain row, creating a due-now one if absent.
func (d *Database) GetOrInitDomain(domain string) (*models.DomainCertificate, error) {
	dc, err := d.GetDomainCertificate(domain)
	if err == nil {
		return dc, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	now := time.Now()
	dc = &models.DomainCertificate{
		Domain:           domain,
		Status:           models.StatusActive,
		RevocationStatus: models.RevocationNotChecked,
		FirstSeenAt:      now,
		NextScanAt:       now,
		Priority:         40,
	}
	if err := d.db.Create(dc).Error; err != nil {
		return nil, err
	}
	return dc, nil
}

// GetDueDomains returns domains whose next_scan_at is due, highest priority first.
func (d *Database) GetDueDomains(now time.Time, limit int) ([]models.DomainCertificate, error) {
	var dcs []models.DomainCertificate
	err := d.db.Where("next_scan_at <= ?", now).
		Order("priority DESC, next_scan_at ASC").
		Limit(limit).Find(&dcs).Error
	return dcs, err
}

// ReactivateLegacyDormantDomains migrates the old expiry-based dormant state
// back into the active observation queue. Expiry alone never proves that a
// service was retired, so these rows must be probed again immediately.
func (d *Database) ReactivateLegacyDormantDomains(now time.Time) (int64, error) {
	result := d.db.Model(&models.DomainCertificate{}).
		Where("status = ?", models.StatusDormant).
		Updates(map[string]interface{}{
			"status":       models.StatusActive,
			"next_scan_at": now,
			"priority":     85,
		})
	return result.RowsAffected, result.Error
}

// CountDueDomains counts domains currently due for scanning.
func (d *Database) CountDueDomains(now time.Time) int64 {
	var c int64
	d.db.Model(&models.DomainCertificate{}).Where("next_scan_at <= ?", now).Count(&c)
	return c
}

// ListDomains returns domain rows (with current cert) paginated/filtered.
func (d *Database) ListDomains(f *models.CertificateFilter) ([]models.DomainCertificate, int64, error) {
	var dcs []models.DomainCertificate
	var total int64

	q := d.db.Model(&models.DomainCertificate{})
	if f.Domain != "" {
		q = q.Where("domain ILIKE ?", "%"+f.Domain+"%")
	}
	if f.Status != "" {
		q = q.Where("status = ?", f.Status)
	}
	if f.Revocation != "" {
		q = q.Where("revocation_status = ?", f.Revocation)
	}
	q.Count(&total)

	order := fmt.Sprintf("%s %s", safeSort(f.SortBy, "tranco_rank"), safeOrder(f.SortOrder))
	offset := (f.Page - 1) * f.PerPage
	err := q.Preload("CurrentCertificate").Order(order).Offset(offset).Limit(f.PerPage).Find(&dcs).Error
	if err != nil {
		return nil, 0, err
	}
	return dcs, total, nil
}

// GetExpiringDomains returns active domains whose deployed cert expires within days.
func (d *Database) GetExpiringDomains(days int) ([]models.DomainCertificate, error) {
	var dcs []models.DomainCertificate
	cutoff := time.Now().AddDate(0, 0, days)
	err := d.db.Preload("CurrentCertificate").
		Joins("JOIN certificates c ON c.id = domain_certificates.current_certificate_id").
		Where("domain_certificates.status = ? AND c.not_after > now() AND c.not_after <= ?", models.StatusActive, cutoff).
		Order("c.not_after ASC").Find(&dcs).Error
	return dcs, err
}

// GetExpiredDomains returns active domains currently serving an expired certificate.
func (d *Database) GetExpiredDomains() ([]models.DomainCertificate, error) {
	var dcs []models.DomainCertificate
	err := d.db.Preload("CurrentCertificate").
		Joins("JOIN certificates c ON c.id = domain_certificates.current_certificate_id").
		Where("domain_certificates.status = ? AND c.not_after < now()", models.StatusActive).
		Order("c.not_after DESC").Find(&dcs).Error
	return dcs, err
}

// GetRevokedDomains returns active domains whose deployed cert is revoked.
func (d *Database) GetRevokedDomains() ([]models.DomainCertificate, error) {
	var dcs []models.DomainCertificate
	err := d.db.Preload("CurrentCertificate").
		Where("status = ? AND revocation_status = ?", models.StatusActive, models.RevocationRevoked).
		Order("revoked_at DESC").Find(&dcs).Error
	return dcs, err
}

// GetUpcomingSchedule returns the soonest scheduled scans.
func (d *Database) GetUpcomingSchedule(limit int) ([]models.DomainCertificate, error) {
	var dcs []models.DomainCertificate
	err := d.db.Preload("CurrentCertificate").
		Order("next_scan_at ASC").Limit(limit).Find(&dcs).Error
	return dcs, err
}

// ---------------------------------------------------------------------------
// Observations (time-series)
// ---------------------------------------------------------------------------

// AppendObservation writes one observation. Milestone duplicates are ignored
// via the partial unique index.
func (d *Database) AppendObservation(obs *models.CertObservation) error {
	if obs.CreatedAt.IsZero() {
		obs.CreatedAt = time.Now()
	}
	tx := d.db
	if obs.ObservationType == models.ObsMilestone {
		tx = tx.Clauses(clause.OnConflict{DoNothing: true})
	}
	return tx.Create(obs).Error
}

// MilestoneRecorded reports whether a domain has already recorded a milestone
// for the currently deployed certificate.
func (d *Database) MilestoneRecorded(domain, fingerprint, milestone string) bool {
	var c int64
	d.db.Model(&models.CertObservation{}).
		Where("domain = ? AND fingerprint = ? AND milestone = ? AND observation_type = ?",
			domain, fingerprint, milestone, models.ObsMilestone).Count(&c)
	return c > 0
}

// GetDomainTimeline returns a domain's observation history, newest first.
func (d *Database) GetDomainTimeline(domain string, limit int) ([]models.CertObservation, error) {
	var obs []models.CertObservation
	q := d.db.Where("domain = ?", domain).Order("observed_at DESC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	err := q.Find(&obs).Error
	return obs, err
}

// ---------------------------------------------------------------------------
// Daily statistics (in-place counters)
// ---------------------------------------------------------------------------

// BumpDailyStat atomically increments today's counters.
func (d *Database) BumpDailyStat(delta models.DailyScanStat) error {
	date := time.Now().Format("2006-01-02")
	return d.db.Exec(`
		INSERT INTO daily_scan_stats
			(date, total_scans, successful_scans, failed_scans, changes_detected,
			 revocations_detected, new_certs, milestone_scans, total_scan_ms, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, now())
		ON CONFLICT (date) DO UPDATE SET
			total_scans          = daily_scan_stats.total_scans + EXCLUDED.total_scans,
			successful_scans     = daily_scan_stats.successful_scans + EXCLUDED.successful_scans,
			failed_scans         = daily_scan_stats.failed_scans + EXCLUDED.failed_scans,
			changes_detected     = daily_scan_stats.changes_detected + EXCLUDED.changes_detected,
			revocations_detected = daily_scan_stats.revocations_detected + EXCLUDED.revocations_detected,
			new_certs            = daily_scan_stats.new_certs + EXCLUDED.new_certs,
			milestone_scans      = daily_scan_stats.milestone_scans + EXCLUDED.milestone_scans,
			total_scan_ms        = daily_scan_stats.total_scan_ms + EXCLUDED.total_scan_ms,
			updated_at           = now()`,
		date, delta.TotalScans, delta.SuccessfulScans, delta.FailedScans, delta.ChangesDetected,
		delta.RevocationsDetected, delta.NewCerts, delta.MilestoneScans, delta.TotalScanMs).Error
}

func (d *Database) GetTodayStat() *models.DailyScanStat {
	var s models.DailyScanStat
	date := time.Now().Format("2006-01-02")
	if err := d.db.Where("date = ?", date).First(&s).Error; err != nil {
		return &models.DailyScanStat{Date: date}
	}
	s.AverageScanMs = avgMs(s.TotalScanMs, s.SuccessfulScans)
	return &s
}

func (d *Database) GetDailyStats(start, end time.Time) ([]models.DailyScanStat, error) {
	var stats []models.DailyScanStat
	err := d.db.Where("date BETWEEN ? AND ?", start.Format("2006-01-02"), end.Format("2006-01-02")).
		Order("date ASC").Find(&stats).Error
	for i := range stats {
		stats[i].AverageScanMs = avgMs(stats[i].TotalScanMs, stats[i].SuccessfulScans)
	}
	return stats, err
}

// ---------------------------------------------------------------------------
// Tranco
// ---------------------------------------------------------------------------

// SaveTrancoList records list metadata.
func (d *Database) SaveTrancoList(list *models.TrancoList) error {
	return d.db.Create(list).Error
}

func (d *Database) GetLatestTrancoList() (*models.TrancoList, error) {
	var list models.TrancoList
	err := d.db.Order("fetched_at DESC").First(&list).Error
	if err != nil {
		return nil, err
	}
	return &list, nil
}

// RegisterTrancoDomains upserts ranked domains. Existing rows keep their
// schedule; only the rank is refreshed. New rows are due immediately.
func (d *Database) RegisterTrancoDomains(ranked map[string]int) (int, error) {
	if len(ranked) == 0 {
		return 0, nil
	}
	now := time.Now()
	rows := make([]models.DomainCertificate, 0, len(ranked))
	for domain, rank := range ranked {
		rows = append(rows, models.DomainCertificate{
			Domain:           domain,
			TrancoRank:       rank,
			Status:           models.StatusActive,
			RevocationStatus: models.RevocationNotChecked,
			FirstSeenAt:      now,
			NextScanAt:       now,
			Priority:         40,
		})
	}
	// Insert in batches; on conflict only refresh the rank (preserve schedule).
	err := d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "domain"}},
		DoUpdates: clause.AssignmentColumns([]string{"tranco_rank", "updated_at"}),
	}).CreateInBatches(rows, 500).Error
	return len(rows), err
}

// ---------------------------------------------------------------------------
// Scan jobs (audit trail)
// ---------------------------------------------------------------------------

func (d *Database) CreateScanJob(job *models.ScanJob) error {
	if job.Status == "" {
		job.Status = models.ScanJobRunning
	}
	return d.db.Create(job).Error
}

func (d *Database) FinishScanJob(jobID uint, result *models.ScanResult) error {
	if jobID == 0 {
		return nil
	}
	finishedAt := time.Now()
	var job models.ScanJob
	if err := d.db.Select("started_at").Where("id = ?", jobID).First(&job).Error; err == nil {
		finishedAt = normalizedFinishTime(job.StartedAt, finishedAt)
	}
	updates := map[string]interface{}{
		"finished_at": &finishedAt,
		"status":      models.ScanJobFailed,
		"success":     false,
	}
	if result != nil {
		updates["success"] = result.Success
		if result.Success {
			updates["status"] = models.ScanJobSucceeded
		}
		if result.Cert != nil {
			updates["fingerprint"] = result.Cert.Fingerprint
		}
		updates["revocation_status"] = result.RevocationStatus
		updates["failure_class"] = result.FailureClass
		if result.ARI != nil {
			updates["ari_status"] = result.ARI.Status
		}
		updates["scan_duration_ms"] = result.ScanDuration.Milliseconds()
		if !result.Success {
			updates["error"] = result.Error
		}
	}
	return d.db.Model(&models.ScanJob{}).Where("id = ?", jobID).Updates(updates).Error
}

func normalizedFinishTime(startedAt *time.Time, finishedAt time.Time) time.Time {
	if startedAt != nil && finishedAt.Before(*startedAt) {
		return *startedAt
	}
	return finishedAt
}

func (d *Database) ListScanJobs(limit int) ([]models.ScanJob, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var jobs []models.ScanJob
	err := d.db.Order("created_at DESC").Limit(limit).Find(&jobs).Error
	return jobs, err
}

// ---------------------------------------------------------------------------
// Persistent ARI / CRL caches
// ---------------------------------------------------------------------------

// GetARICache returns a non-expired ARI response for an RFC 9773 certificate
// identifier. A cache miss is represented by (nil, nil).
func (d *Database) GetARICache(identifier string, now time.Time) (*models.ARICacheEntry, error) {
	var entry models.ARICacheEntry
	err := d.db.Where("ari_identifier = ? AND expires_at > ?", identifier, now).First(&entry).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func (d *Database) SaveARICache(entry *models.ARICacheEntry) error {
	return d.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "ari_identifier"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"source", "status", "window_start", "window_end", "explanation_url",
			"retry_after_secs", "fetched_at", "expires_at", "updated_at",
		}),
	}).Create(entry).Error
}

// GetCRLCache returns a non-expired CRL payload for a distribution-point URL.
// The caller must still parse and verify the CRL against the certificate issuer.
func (d *Database) GetCRLCache(url string, now time.Time) (*models.CRLCacheEntry, error) {
	var entry models.CRLCacheEntry
	err := d.db.Where("url = ? AND expires_at > ?", url, now).First(&entry).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func (d *Database) SaveCRLCache(entry *models.CRLCacheEntry) error {
	return d.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "url"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"raw_der", "this_update", "next_update", "fetched_at", "expires_at", "updated_at",
		}),
	}).Create(entry).Error
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

func (d *Database) CreateAlert(a *models.CertificateAlert) error { return d.db.Create(a).Error }

func (d *Database) GetAlerts() ([]models.CertificateAlert, error) {
	var a []models.CertificateAlert
	err := d.db.Order("interval_days ASC").Find(&a).Error
	return a, err
}

func (d *Database) GetEnabledAlerts() ([]models.CertificateAlert, error) {
	var a []models.CertificateAlert
	err := d.db.Where("is_enabled = ?", true).Find(&a).Error
	return a, err
}

func (d *Database) UpdateAlert(a *models.CertificateAlert) error { return d.db.Save(a).Error }

func (d *Database) DeleteAlert(id uint) error {
	return d.db.Delete(&models.CertificateAlert{}, id).Error
}

// ---------------------------------------------------------------------------
// System stats & analysis
// ---------------------------------------------------------------------------

func (d *Database) GetSystemStats() *models.SystemStats {
	s := &models.SystemStats{DatabaseSize: d.GetDatabaseSize()}

	d.db.Model(&models.Certificate{}).Count(&s.TotalCertificates)
	d.db.Model(&models.DomainCertificate{}).Count(&s.TotalDomains)
	d.db.Model(&models.DomainCertificate{}).Where("status = ?", models.StatusActive).Count(&s.ActiveDomains)
	d.db.Model(&models.CertObservation{}).Count(&s.Observations)
	d.db.Model(&models.DomainCertificate{}).
		Where("status = ? AND revocation_status = ?", models.StatusActive, models.RevocationRevoked).
		Count(&s.RevokedCerts)
	s.DueNow = d.CountDueDomains(time.Now())

	s.ExpiringCerts7d = d.countExpiring(7)
	s.ExpiringCerts30d = d.countExpiring(30)
	d.db.Model(&models.DomainCertificate{}).
		Joins("JOIN certificates c ON c.id = domain_certificates.current_certificate_id").
		Where("domain_certificates.status = ? AND c.not_after < now()", models.StatusActive).
		Count(&s.ExpiredCerts)

	today := d.GetTodayStat()
	s.TodayScans = today.TotalScans
	s.ChangedToday = today.ChangesDetected
	s.AverageScanTimeMs = today.AverageScanMs

	return s
}

func (d *Database) countExpiring(days int) int64 {
	var c int64
	cutoff := time.Now().AddDate(0, 0, days)
	d.db.Model(&models.DomainCertificate{}).
		Joins("JOIN certificates c ON c.id = domain_certificates.current_certificate_id").
		Where("c.not_after > now() AND c.not_after <= ?", cutoff).Count(&c)
	return c
}

// anomalyCause carries one cause classification for a finding. A finding is
// either confirmed by direct observations or inferred from weaker evidence;
// it is never both. Reason and Evidence remain compatibility fields; the
// structured fields are the source of truth for new clients.
type anomalyCause struct {
	confirmedReason   string
	inferredReason    string
	confirmedEvidence []string
	inferredEvidence  []string
	evidenceStatus    string
	pendingReason     string
}

func (cause anomalyCause) apply(anomaly *models.Anomaly) {
	confirmed := strings.TrimSpace(cause.confirmedReason)
	inferred := strings.TrimSpace(cause.inferredReason)
	confirmedEvidence := uniqueAnomalyEvidence(cause.confirmedEvidence)
	inferredEvidence := uniqueAnomalyEvidence(cause.inferredEvidence)
	status := strings.TrimSpace(cause.evidenceStatus)
	if status == "" {
		status = models.EvidenceStatusUnknown
	}
	// Direct evidence wins when both fields are supplied by a legacy cause
	// builder. The public cause record never exposes both interpretations.
	hasConfirmed := confirmed != "" || len(confirmedEvidence) > 0
	hasInferred := inferred != "" || len(inferredEvidence) > 0
	switch {
	case hasConfirmed:
		anomaly.CauseClassification = "confirmed"
		inferred = ""
		inferredEvidence = nil
	case hasInferred:
		anomaly.CauseClassification = "inferred"
		confirmed = ""
		confirmedEvidence = nil
	default:
		anomaly.CauseClassification = "unknown"
		confirmed = ""
		inferred = ""
		confirmedEvidence = nil
		inferredEvidence = nil
	}
	anomaly.ConfirmedReason = confirmed
	anomaly.InferredReason = inferred
	anomaly.ConfirmedEvidence = append([]string{}, confirmedEvidence...)
	anomaly.InferredEvidence = append([]string{}, inferredEvidence...)
	anomaly.EvidenceStatus = status
	anomaly.EvidencePendingReason = cause.pendingReason
	anomaly.Evidence = append([]string{}, confirmedEvidence...)
	if anomaly.CauseClassification == "inferred" {
		anomaly.Evidence = append([]string{}, inferredEvidence...)
	}
	switch {
	case confirmed != "":
		anomaly.Reason = confirmed
	case inferred != "":
		anomaly.Reason = inferred
	default:
		anomaly.Reason = "No cause detail recorded."
	}
}

func withAnomalyCause(anomaly models.Anomaly, cause anomalyCause) models.Anomaly {
	cause.apply(&anomaly)
	return anomaly
}

func withDomainEvidence(cause anomalyCause, dc models.DomainCertificate) anomalyCause {
	cause.evidenceStatus = firstNonEmpty(dc.EvidenceStatus, models.EvidenceStatusUnknown)
	cause.pendingReason = dc.EvidencePendingReason
	return cause
}

func withObservationEvidence(cause anomalyCause, observation models.CertObservation) anomalyCause {
	cause.evidenceStatus = firstNonEmpty(observation.EvidenceStatus, models.EvidenceStatusUnknown)
	cause.pendingReason = observation.EvidencePendingReason
	return cause
}

func uniqueAnomalyEvidence(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// GetAnomalies surfaces one explainable finding per domain and type. Counts are
// derived from durable ScanJob records (one scheduled/manual monitoring
// operation; scanner retries are not counted as separate monitoring rounds).
func (d *Database) GetAnomalies(limit int) ([]models.Anomaly, error) {
	out := make([]models.Anomaly, 0)
	now := time.Now()
	appendFinding := func(a models.Anomaly, fallback int) error {
		if a.OccurrenceCount <= 0 {
			a.OccurrenceCount = fallback
			if a.OccurrenceCount <= 0 {
				a.OccurrenceCount = 1
			}
		}
		out = append(out, a)
		return nil
	}

	var revoked []models.DomainCertificate
	if err := d.db.Where("status = ? AND revocation_status = ?", models.StatusActive, models.RevocationRevoked).Find(&revoked).Error; err != nil {
		return nil, err
	}
	for _, dc := range revoked {
		cause := anomalyCause{
			confirmedReason:   "The current certificate was reported as revoked by the retained revocation check.",
			confirmedEvidence: []string{"revocation_status=" + dc.RevocationStatus, "checked_via=" + firstNonEmpty(dc.RevocationCheckedVia, "unknown")},
		}
		if dc.RevocationReason != "" {
			cause.inferredReason = fmt.Sprintf("The CA-reported revocation reason is %q; this is a CA classification and does not prove the operator's intent.", dc.RevocationReason)
			revocationReason := "revocation_reason=" + dc.RevocationReason
			cause.confirmedEvidence = append(cause.confirmedEvidence, revocationReason)
			cause.inferredEvidence = []string{revocationReason, "interpretation=ca_reason_not_operator_intent"}
		}
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: dc.Domain, Type: "revoked", Severity: "critical",
			Description: "The currently deployed certificate is revoked",
			Fingerprint: dc.CurrentFingerprint, OccurrenceCount: 1, DetectedAt: firstTime(dc.RevokedAt, now),
		}, withDomainEvidence(cause, dc)), 1); err != nil {
			return nil, err
		}
	}

	var expired []models.DomainCertificate
	if err := d.db.Preload("CurrentCertificate").Joins("JOIN certificates c ON c.id = domain_certificates.current_certificate_id").
		Where("domain_certificates.status = ? AND c.not_after < now()", models.StatusActive).Find(&expired).Error; err != nil {
		return nil, err
	}
	for _, dc := range expired {
		cert := dc.CurrentCertificate
		days := 0
		if cert != nil {
			days = models.DaysUntil(cert.NotAfter, now)
		}
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: dc.Domain, Type: "expired_served", Severity: "critical",
			Description: "The domain is still serving an expired certificate",
			Fingerprint: dc.CurrentFingerprint, OccurrenceCount: 1, DetectedAt: now,
		}, withDomainEvidence(anomalyCause{
			confirmedReason:   fmt.Sprintf("A successful TLS handshake returned a certificate whose NotAfter time had passed by %d day(s).", -days),
			confirmedEvidence: []string{fmt.Sprintf("not_after=%s", certTime(cert)), "status=" + dc.Status},
			inferredReason:    "The endpoint likely has an outdated deployment or missed renewal; certificate expiry alone does not prove that the domain is retired.",
			inferredEvidence:  []string{fmt.Sprintf("not_after=%s", certTime(cert)), "status=" + dc.Status, "inference=outdated_deployment_or_missing_renewal"},
		}, dc)), 1); err != nil {
			return nil, err
		}
	}

	// Legacy dormant rows are shown as historical evidence, never as proof of retirement.
	var legacy []models.DomainCertificate
	if err := d.db.Preload("CurrentCertificate").Joins("JOIN certificates c ON c.id = domain_certificates.current_certificate_id").
		Where("domain_certificates.status = ? AND c.not_after < now()", models.StatusDormant).Find(&legacy).Error; err != nil {
		return nil, err
	}
	for _, dc := range legacy {
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: dc.Domain, Type: "expired_observed", Severity: "info",
			Description: "A previous collector observed an expired certificate for this domain",
			Fingerprint: dc.CurrentFingerprint, OccurrenceCount: 1, DetectedAt: dc.LastScannedAt,
		}, withDomainEvidence(anomalyCause{
			confirmedReason:   "A previous collector recorded an expired certificate while the row was marked dormant.",
			confirmedEvidence: []string{"legacy_status=dormant", "last_scanned_at=" + dc.LastScannedAt.Format(time.RFC3339)},
			inferredReason:    "The domain may have changed state since that observation; expiry alone cannot establish that it is offline.",
			inferredEvidence:  []string{"legacy_status=dormant", "last_scanned_at=" + dc.LastScannedAt.Format(time.RFC3339), "inference=offline_status_not_established"},
		}, dc)), 1); err != nil {
			return nil, err
		}
	}

	// Active near-expiry certificates are actionable warnings, not failures.
	expiring, err := d.GetExpiringDomains(7)
	if err != nil {
		return nil, err
	}
	for _, dc := range expiring {
		cert := dc.CurrentCertificate
		if cert == nil {
			continue
		}
		days := models.DaysUntil(cert.NotAfter, now)
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: dc.Domain, Type: "expiring_soon", Severity: "warning",
			Description: fmt.Sprintf("The certificate expires within %d days", days),
			Fingerprint: dc.CurrentFingerprint, OccurrenceCount: 1, DetectedAt: now,
		}, withDomainEvidence(anomalyCause{
			confirmedReason:   "The currently deployed certificate is inside the seven-day expiry window.",
			confirmedEvidence: []string{fmt.Sprintf("not_after=%s", cert.NotAfter.Format(time.RFC3339)), fmt.Sprintf("days_until_expiry=%d", days)},
			inferredReason:    "Renewal or deployment attention may be required before expiry.",
			inferredEvidence:  []string{fmt.Sprintf("not_after=%s", cert.NotAfter.Format(time.RFC3339)), fmt.Sprintf("days_until_expiry=%d", days), "inference=renewal_attention_recommended"},
		}, dc)), 1); err != nil {
			return nil, err
		}
	}

	// Early renewals are grouped by domain so the UI reports the number of
	// observed replacements instead of one indistinguishable row per event.
	var earlyRows []models.CertObservation
	if err := d.db.Where("observation_type = ? AND days_until_expiry > 30", models.ObsChange).Order("observed_at DESC").Find(&earlyRows).Error; err != nil {
		return nil, err
	}
	earlyByDomain := map[string][]models.CertObservation{}
	for _, row := range earlyRows {
		earlyByDomain[row.Domain] = append(earlyByDomain[row.Domain], row)
	}
	for domain, rows := range earlyByDomain {
		latest := rows[0]
		cause := d.certificateChangeCause(domain, latest)
		cause.confirmedReason = fmt.Sprintf("Observed %d early renewal(s); the latest occurred %d days before expiry. %s", len(rows), latest.DaysUntilExpiry, cause.confirmedReason)
		replacementEvents := fmt.Sprintf("replacement_events=%d", len(rows))
		cause.confirmedEvidence = append([]string{replacementEvents}, cause.confirmedEvidence...)
		cause.inferredEvidence = append([]string{replacementEvents}, cause.inferredEvidence...)
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: domain, Type: "early_renewal", Severity: "info",
			Description: fmt.Sprintf("The certificate was replaced more than 30 days before expiry (%d observation(s))", len(rows)),
			Fingerprint: latest.Fingerprint, OccurrenceCount: len(rows), DetectedAt: latest.ObservedAt,
		}, withObservationEvidence(cause, latest)), len(rows)); err != nil {
			return nil, err
		}
	}

	// Lifecycle-specific findings are derived from append-only event rows. They
	// remain visible after the current certificate has changed, which is
	// necessary for residual and stale-after-change history.
	var lifecycleRows []models.CertObservation
	if err := d.db.Where("observation_type IN ?", []string{models.ObsSameKey, models.ObsStaleAfterChange, models.ObsResidual, models.ObsDeploymentFailure}).
		Order("observed_at DESC").Find(&lifecycleRows).Error; err != nil {
		return nil, err
	}
	type lifecycleGroup struct {
		rows []models.CertObservation
	}
	groups := map[string]*lifecycleGroup{}
	for _, row := range lifecycleRows {
		key := row.Domain + "\x00" + row.ObservationType
		if groups[key] == nil {
			groups[key] = &lifecycleGroup{}
		}
		groups[key].rows = append(groups[key].rows, row)
	}
	for _, group := range groups {
		if len(group.rows) == 0 {
			continue
		}
		latest := group.rows[0]
		count := len(group.rows)
		cause := lifecycleCause(latest, count)
		severity := "info"
		switch latest.ObservationType {
		case models.ObsStaleAfterChange, models.ObsResidual, models.ObsDeploymentFailure:
			severity = "warning"
		}
		description := lifecycleDescription(latest.ObservationType, count)
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: latest.Domain, Type: latest.ObservationType, Severity: severity,
			Description: description, Fingerprint: latest.Fingerprint,
			OccurrenceCount: count, DetectedAt: latest.ObservedAt,
		}, cause), count); err != nil {
			return nil, err
		}
	}

	var churny []models.DomainCertificate
	if err := d.db.Where("change_count >= ?", 3).Order("change_count DESC").Find(&churny).Error; err != nil {
		return nil, err
	}
	for _, dc := range churny {
		var latest models.CertObservation
		_ = d.db.Where("domain = ? AND observation_type = ?", dc.Domain, models.ObsChange).Order("observed_at DESC").First(&latest).Error
		cause := d.certificateChangeCause(dc.Domain, latest)
		cause.confirmedReason = fmt.Sprintf("Observed %d certificate replacement(s) during the monitoring period. %s", dc.ChangeCount, cause.confirmedReason)
		certificateChanges := fmt.Sprintf("certificate_changes=%d", dc.ChangeCount)
		cause.confirmedEvidence = append([]string{certificateChanges}, cause.confirmedEvidence...)
		cause.inferredEvidence = append([]string{certificateChanges}, cause.inferredEvidence...)
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: dc.Domain, Type: "frequent_change", Severity: "warning",
			Description: fmt.Sprintf("The certificate changed %d times during the monitoring period", dc.ChangeCount),
			Fingerprint: dc.CurrentFingerprint, OccurrenceCount: dc.ChangeCount, DetectedAt: firstTimePtr(latest.ObservedAt, now),
		}, withObservationEvidence(cause, latest)), dc.ChangeCount); err != nil {
			return nil, err
		}
	}

	var unreachable []models.DomainCertificate
	if err := d.db.Where("status = ?", models.StatusUnreachable).Order("consecutive_failures DESC").Find(&unreachable).Error; err != nil {
		return nil, err
	}
	for _, dc := range unreachable {
		failure := dc.LastFailureClass
		if failure == "" {
			failure = "unknown"
		}
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: dc.Domain, Type: "unreachable", Severity: "warning",
			Description:     "Repeated monitoring did not obtain a TLS certificate",
			OccurrenceCount: dc.ConsecutiveFailures, DetectedAt: firstTimePtr(dc.LastScannedAt, now),
		}, anomalyCause{
			evidenceStatus:    models.EvidenceStatusNotApplicable,
			pendingReason:     "A failed TLS attempt has no certificate evidence to enrich.",
			confirmedReason:   fmt.Sprintf("The latest monitoring attempt failed to obtain a TLS certificate and was classified as %s.", failure),
			confirmedEvidence: []string{"failure_class=" + failure, "latest_error=" + firstNonEmpty(dc.LastError, "no specific error recorded"), fmt.Sprintf("consecutive_failures=%d", dc.ConsecutiveFailures)},
			inferredReason:    "This is a vantage-specific observation and does not prove that the domain has been taken offline.",
			inferredEvidence:  []string{"failure_class=" + failure, "latest_error=" + firstNonEmpty(dc.LastError, "no specific error recorded"), fmt.Sprintf("consecutive_failures=%d", dc.ConsecutiveFailures), "inference=service_retirement_not_established"},
		}), dc.ConsecutiveFailures); err != nil {
			return nil, err
		}
	}

	var ariEmerg []models.DomainCertificate
	if err := d.db.Where("status = ? AND ari_emergency = ?", models.StatusActive, true).Find(&ariEmerg).Error; err != nil {
		return nil, err
	}
	for _, dc := range ariEmerg {
		at := now
		if dc.ARICheckedAt != nil {
			at = *dc.ARICheckedAt
		}
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: dc.Domain, Type: "ari_emergency", Severity: "critical",
			Description: "The CA moved the ARI renewal window to the present",
			Fingerprint: dc.CurrentFingerprint, OccurrenceCount: 1, DetectedAt: at,
		}, withDomainEvidence(anomalyCause{
			confirmedReason:   "The CA's ARI response moved the renewal window to the present.",
			confirmedEvidence: []string{"ari_emergency=true", "checked_at=" + at.Format(time.RFC3339)},
			inferredReason:    "This may indicate urgent renewal pressure or a broader CA incident; it does not establish the operator's intent.",
			inferredEvidence:  []string{"ari_emergency=true", "checked_at=" + at.Format(time.RFC3339), "inference=urgent_renewal_or_ca_incident"},
		}, dc)), 1); err != nil {
			return nil, err
		}
	}

	if err := d.decorateAnomalies(out); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		rank := map[string]int{"critical": 0, "warning": 1, "info": 2}
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		if out[i].OccurrenceCount != out[j].OccurrenceCount {
			return out[i].OccurrenceCount > out[j].OccurrenceCount
		}
		return out[i].Domain < out[j].Domain
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

type monitoringEvidence struct {
	total, successful, failed int64
	first, last               time.Time
}

func (d *Database) decorateAnomalies(items []models.Anomaly) error {
	if len(items) == 0 {
		return nil
	}
	domains := make([]string, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		if item.Domain != "" && !seen[item.Domain] {
			seen[item.Domain] = true
			domains = append(domains, item.Domain)
		}
	}
	type coverageRow struct {
		Domain          string    `gorm:"column:domain"`
		Total           int64     `gorm:"column:total"`
		Successful      int64     `gorm:"column:successful"`
		FirstObservedAt time.Time `gorm:"column:first_observed_at"`
		LastObservedAt  time.Time `gorm:"column:last_observed_at"`
	}
	var rows []coverageRow
	if err := d.db.Model(&models.ScanJob{}).Select(`domain,
		COUNT(*) AS total,
		SUM(CASE WHEN success THEN 1 ELSE 0 END) AS successful,
		MIN(COALESCE(started_at, created_at)) AS first_observed_at,
		MAX(COALESCE(finished_at, started_at, created_at)) AS last_observed_at`).
		Where("domain IN ?", domains).Group("domain").Scan(&rows).Error; err != nil {
		return err
	}
	coverage := make(map[string]monitoringEvidence, len(rows))
	for _, row := range rows {
		coverage[row.Domain] = monitoringEvidence{total: row.Total, successful: row.Successful, failed: row.Total - row.Successful, first: row.FirstObservedAt, last: row.LastObservedAt}
	}
	var domainStates []models.DomainCertificate
	if err := d.db.Select("domain", "scan_count").Where("domain IN ?", domains).Find(&domainStates).Error; err != nil {
		return err
	}
	scanCounts := make(map[string]int, len(domainStates))
	for _, state := range domainStates {
		scanCounts[state.Domain] = state.ScanCount
	}
	// Persistent conditions are counted against the actual successful scan
	// observations that still support the current finding. This keeps
	// occurrence_count meaningful instead of returning a hard-coded one for a
	// certificate that was observed repeatedly.
	var currentStates []models.DomainCertificate
	if err := d.db.Preload("CurrentCertificate").Where("domain IN ?", domains).Find(&currentStates).Error; err != nil {
		return err
	}
	currentByDomain := make(map[string]models.DomainCertificate, len(currentStates))
	for _, state := range currentStates {
		currentByDomain[state.Domain] = state
	}
	var jobs []models.ScanJob
	if err := d.db.Where("domain IN ? AND success = ?", domains, true).Find(&jobs).Error; err != nil {
		return err
	}
	persistentOccurrences := make(map[string]map[string]int, len(domains))
	failedOccurrences := make(map[string]int, len(domains))
	for _, job := range jobs {
		state, ok := currentByDomain[job.Domain]
		if !ok || state.CurrentCertificate == nil {
			continue
		}
		at := job.CreatedAt
		if job.FinishedAt != nil {
			at = *job.FinishedAt
		} else if job.StartedAt != nil {
			at = *job.StartedAt
		}
		cert := state.CurrentCertificate
		if job.Fingerprint != "" && job.Fingerprint != state.CurrentFingerprint {
			continue
		}
		if job.Fingerprint == "" {
			continue
		}
		if persistentOccurrences[job.Domain] == nil {
			persistentOccurrences[job.Domain] = map[string]int{}
		}
		if cert.NotAfter.Before(at) {
			persistentOccurrences[job.Domain]["expired_served"]++
		} else if cert.NotAfter.After(at) && cert.NotAfter.Sub(at) <= 7*24*time.Hour {
			persistentOccurrences[job.Domain]["expiring_soon"]++
		}
		if strings.EqualFold(job.RevocationStatus, models.RevocationRevoked) {
			persistentOccurrences[job.Domain]["revoked"]++
		}
	}
	var failedJobs []models.ScanJob
	if err := d.db.Where("domain IN ? AND status = ?", domains, models.ScanJobFailed).Find(&failedJobs).Error; err != nil {
		return err
	}
	for _, job := range failedJobs {
		failedOccurrences[job.Domain]++
	}
	for index := range items {
		item := &items[index]
		evidence := coverage[item.Domain]
		if scanCounts[item.Domain] > int(evidence.total) {
			evidence.total = int64(scanCounts[item.Domain])
		}
		if item.MonitoringCount > int(evidence.total) {
			evidence.total = int64(item.MonitoringCount)
		}
		if evidence.total == 0 {
			evidence.total = int64(item.OccurrenceCount)
		}
		if item.Type == "unreachable" && evidence.failed == 0 {
			evidence.failed = int64(item.OccurrenceCount)
		}
		if item.Type == "unreachable" && failedOccurrences[item.Domain] > item.OccurrenceCount {
			item.OccurrenceCount = failedOccurrences[item.Domain]
		}
		if occurrences := persistentOccurrences[item.Domain]; occurrences != nil {
			if count := occurrences[item.Type]; count > 0 {
				item.OccurrenceCount = count
			}
		}
		item.MonitoringCount = int(evidence.total)
		item.SuccessfulMonitoringCount = int(evidence.successful)
		item.FailedMonitoringCount = int(evidence.failed)
		if !evidence.first.IsZero() {
			item.FirstObservedAt = &evidence.first
		} else if item.FirstObservedAt == nil && !item.DetectedAt.IsZero() {
			at := item.DetectedAt
			item.FirstObservedAt = &at
		}
		if !evidence.last.IsZero() {
			item.LastObservedAt = &evidence.last
		} else if item.LastObservedAt == nil && !item.DetectedAt.IsZero() {
			at := item.DetectedAt
			item.LastObservedAt = &at
		}
		item.EvidenceScope = "ScanJob counts one scheduled or manual monitoring operation; internal scanner retries are not counted as additional monitoring rounds. Reasons are observed evidence, not operator-intent attribution."
		if item.EvidenceStatus == "" {
			item.EvidenceStatus = models.EvidenceStatusUnknown
		}
	}
	return nil
}

func (d *Database) certificateChangeCause(domain string, observation models.CertObservation) anomalyCause {
	if observation.Fingerprint == "" {
		return anomalyCause{
			confirmedReason:   "A certificate replacement observation was recorded, but the latest fingerprint is incomplete.",
			confirmedEvidence: []string{"fingerprint=missing"},
			inferredReason:    "The specific replacement cause cannot be determined from the retained certificate fields.",
			inferredEvidence:  []string{"fingerprint=missing", "inference=insufficient_certificate_fields"},
		}
	}
	var current, previous models.Certificate
	if d.db.Where("fingerprint = ?", observation.Fingerprint).First(&current).Error != nil {
		return anomalyCause{
			confirmedReason:   "A certificate fingerprint change was confirmed, but the current certificate fields are unavailable for cause analysis.",
			confirmedEvidence: []string{"new_fingerprint=" + observation.Fingerprint},
			inferredReason:    "The key-change or reissuance cause cannot be determined without the current certificate fields.",
			inferredEvidence:  []string{"new_fingerprint=" + observation.Fingerprint, "inference=insufficient_certificate_fields"},
		}
	}
	if observation.PreviousFingerprint == "" || d.db.Where("fingerprint = ?", observation.PreviousFingerprint).First(&previous).Error != nil {
		return anomalyCause{
			confirmedReason:   "A certificate fingerprint change was confirmed, but the previous certificate fields are unavailable to determine whether the key changed.",
			confirmedEvidence: []string{"new_fingerprint=" + observation.Fingerprint},
			inferredReason:    "The replacement cause cannot be classified as same-key reissuance or key rotation without the previous certificate fields.",
			inferredEvidence:  []string{"new_fingerprint=" + observation.Fingerprint, "inference=insufficient_previous_certificate_fields"},
		}
	}
	oldSPKI, newSPKI := certificateSPKI(&previous), certificateSPKI(&current)
	confirmedEvidence := []string{"previous_fingerprint=" + previous.Fingerprint, "new_fingerprint=" + current.Fingerprint}
	var confirmedParts []string
	var inferredReason string
	if oldSPKI != "" && newSPKI != "" && oldSPKI == newSPKI {
		confirmedEvidence = append(confirmedEvidence, "spki=unchanged")
		confirmedParts = []string{"The certificate fingerprint changed while the SPKI remained unchanged"}
		inferredReason = "This is consistent with certificate reissuance or replacement using the same public key; public observations cannot establish the operator's intent."
	} else {
		confirmedEvidence = append(confirmedEvidence, "spki=changed")
		confirmedParts = []string{"The certificate fingerprint and SPKI both changed"}
		inferredReason = "This is consistent with a key rotation; public observations cannot establish the operator's intent."
	}
	appendCertificateFieldDifferences(&confirmedParts, &confirmedEvidence, &previous, &current)
	return anomalyCause{
		confirmedReason:   strings.Join(confirmedParts, "; ") + ".",
		confirmedEvidence: confirmedEvidence,
		inferredReason:    inferredReason,
		inferredEvidence:  append(append([]string{}, confirmedEvidence...), "interpretation=public_certificate_fields_only"),
	}
}

func lifecycleDescription(kind string, count int) string {
	switch kind {
	case models.ObsSameKey:
		return fmt.Sprintf("The certificate changed while the public key stayed the same (%d observed event(s))", count)
	case models.ObsStaleAfterChange:
		return fmt.Sprintf("A still-valid certificate remained after a DNS/IP-set change (%d observed event(s))", count)
	case models.ObsResidual:
		return fmt.Sprintf("A revoked certificate remained observable after revocation (%d observed follow-up(s))", count)
	case models.ObsDeploymentFailure:
		return fmt.Sprintf("Different certificates were observed across sampled endpoints during a rollout (%d observed event(s))", count)
	default:
		return fmt.Sprintf("Lifecycle event observed (%d event(s))", count)
	}
}

func lifecycleCause(row models.CertObservation, count int) anomalyCause {
	cause := anomalyCause{evidenceStatus: firstNonEmpty(row.EvidenceStatus, models.EvidenceStatusUnknown)}
	base := []string{"observation_type=" + row.ObservationType, fmt.Sprintf("observed_at=%s", row.ObservedAt.Format(time.RFC3339)), fmt.Sprintf("observed_events=%d", count)}
	switch row.ObservationType {
	case models.ObsSameKey:
		cause.confirmedReason = "A new leaf certificate was observed with the same SPKI fingerprint as its predecessor. This confirms same-key replacement at the observed endpoint."
		cause.confirmedEvidence = append(base, "spki=unchanged", "previous_fingerprint="+row.PreviousFingerprint, "new_fingerprint="+row.Fingerprint)
		cause.inferredReason = "The operator likely reissued or replaced the certificate without rotating the public key; public evidence cannot establish intent or private-key exposure."
		cause.inferredEvidence = append([]string{}, cause.confirmedEvidence...)
		cause.inferredEvidence = append(cause.inferredEvidence, "interpretation=reissuance_or_replacement_without_key_rotation")
	case models.ObsStaleAfterChange:
		cause.confirmedReason = "The same still-valid leaf remained observable after the resolver's public A/AAAA set changed. This confirms a DNS/IP-set transition followed by continued certificate service at this vantage."
		cause.confirmedEvidence = append(base, "certificate_valid_at_observation=true", "dns_signal=resolved_public_ip_set_changed")
		if row.ResolvedIPs != "" {
			cause.confirmedEvidence = append(cause.confirmedEvidence, "resolved_ips="+row.ResolvedIPs)
		}
		if row.PreviousResolvedIPs != "" {
			cause.confirmedEvidence = append(cause.confirmedEvidence, "previous_resolved_ips="+row.PreviousResolvedIPs)
		}
		cause.inferredReason = "This is consistent with a stale certificate after hosting or control-plane change, but DNS/IP-set change alone does not prove registrant transfer, provider exit, or private-key retention."
		cause.inferredEvidence = append([]string{}, cause.confirmedEvidence...)
		cause.inferredEvidence = append(cause.inferredEvidence, "interpretation=dns_ip_set_stale_proxy", "scope=single_resolver_and_observed_tls_endpoint")
	case models.ObsResidual:
		duration := time.Duration(row.ResidualDurationSeconds) * time.Second
		cause.confirmedReason = fmt.Sprintf("The revoked leaf was observed again %.1f hours after the CA revocation timestamp. This is a direct lower bound for residual service at the observed endpoint.", duration.Hours())
		cause.confirmedEvidence = append(base, "revocation_status=revoked", "measurement=direct_lower_bound", fmt.Sprintf("residual_duration_seconds=%d", row.ResidualDurationSeconds))
		if row.RevokedAt != nil {
			cause.confirmedEvidence = append(cause.confirmedEvidence, "revoked_at="+row.RevokedAt.Format(time.RFC3339))
		}
		cause.inferredReason = "The endpoint likely retained an obsolete certificate configuration after CA revocation; this observation does not establish how many other edges or clients accepted it."
		cause.inferredEvidence = append([]string{}, cause.confirmedEvidence...)
		cause.inferredEvidence = append(cause.inferredEvidence, "interpretation=endpoint_configuration_lag", "scope=observed_endpoint_only")
	case models.ObsDeploymentFailure:
		cause.confirmedReason = "A candidate follow-up observed more than one leaf fingerprint across the currently resolved endpoint set. This confirms an observed partial deployment during the sampled interval."
		cause.confirmedEvidence = append(base, "measurement=multi_endpoint_tls_probe", "deployment_state=mixed_leaf_fingerprints", "previous_fingerprint="+row.PreviousFingerprint, "current_fingerprint="+row.Fingerprint)
		if row.EndpointProbes != "" {
			cause.confirmedEvidence = append(cause.confirmedEvidence, "endpoint_probes="+row.EndpointProbes)
		}
		cause.inferredReason = "The rollout may have been incomplete or edge-local; public probes cannot prove a global deployment failure without an authoritative edge inventory or testbed control-plane record."
		cause.inferredEvidence = append([]string{}, cause.confirmedEvidence...)
		cause.inferredEvidence = append(cause.inferredEvidence, "interpretation=partial_rollout_or_edge_lag", "scope=sampled_resolved_endpoints")
	}
	return cause
}

func appendCertificateFieldDifferences(parts *[]string, evidence *[]string, previous, current *models.Certificate) {
	if previous.Issuer != current.Issuer {
		*parts = append(*parts, "issuer changed")
		*evidence = append(*evidence, "issuer=changed")
	}
	if previous.CommonName != current.CommonName {
		*parts = append(*parts, "Common Name changed")
		*evidence = append(*evidence, "common_name=changed")
	}
	if normalizedSANs(previous.SANs) != normalizedSANs(current.SANs) {
		*parts = append(*parts, "SAN set changed")
		*evidence = append(*evidence, "sans=changed")
	}
	if previous.NotAfter.Sub(previous.NotBefore) != current.NotAfter.Sub(current.NotBefore) {
		*parts = append(*parts, "validity period changed")
		*evidence = append(*evidence, "validity_period=changed")
	}
}

func certificateSPKI(cert *models.Certificate) string {
	if cert == nil {
		return ""
	}
	if cert.SPKIFingerprint != "" {
		return cert.SPKIFingerprint
	}
	return models.SPKIFingerprintFromRaw(cert.RawCert)
}

func normalizedSANs(raw string) string {
	var values []string
	if json.Unmarshal([]byte(raw), &values) != nil {
		return strings.TrimSpace(raw)
	}
	for i := range values {
		values[i] = strings.ToLower(strings.TrimSpace(values[i]))
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func certTime(cert *models.Certificate) string {
	if cert == nil {
		return "unknown"
	}
	return cert.NotAfter.Format(time.RFC3339)
}

func firstTime(value *time.Time, fallback time.Time) time.Time {
	if value != nil {
		return *value
	}
	return fallback
}

func firstTimePtr(value time.Time, fallback time.Time) time.Time {
	if !value.IsZero() {
		return value
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// GetLastScanTime returns the most recent scan timestamp across domains.
func (d *Database) GetLastScanTime() time.Time {
	var dc models.DomainCertificate
	if err := d.db.Order("last_scanned_at DESC").First(&dc).Error; err != nil {
		return time.Time{}
	}
	return dc.LastScannedAt
}

// GetPatterns computes population-level regularities across currently deployed
// certificates for the analysis view.
func (d *Database) GetPatterns() *models.Patterns {
	p := &models.Patterns{}
	// Only active rows represent a currently deployed certificate. Unreachable
	// and dormant rows retain their last certificate for history, but including
	// them here makes issuer, key and cadence distributions look current when
	// they are not.
	const deployed = `FROM domain_certificates dc JOIN certificates c ON c.id = dc.current_certificate_id WHERE dc.current_certificate_id <> 0 AND dc.status = 'active'`

	d.db.Model(&models.DomainCertificate{}).
		Where("current_certificate_id <> 0 AND status = ?", models.StatusActive).
		Count(&p.TotalDeployed)

	// CA / issuer distribution.
	d.db.Raw(`SELECT c.issuer_cn AS label, count(*) AS count ` + deployed +
		` AND c.issuer_cn <> '' GROUP BY c.issuer_cn ORDER BY count DESC LIMIT 12`).Scan(&p.Issuers)

	// Key algorithm + size distribution.
	d.db.Raw(`SELECT (c.key_algorithm || '-' || c.key_size) AS label, count(*) AS count ` + deployed +
		` GROUP BY label ORDER BY count DESC LIMIT 10`).Scan(&p.KeyTypes)

	// Validity-period (certificate lifetime) distribution.
	var vb []models.LabelCount
	d.db.Raw(`SELECT CASE
			WHEN c.validity_days <= 90  THEN '<=90d'
			WHEN c.validity_days <= 100 THEN '91-100d'
			WHEN c.validity_days <= 180 THEN '101-180d'
			WHEN c.validity_days <= 366 THEN '181-366d'
			WHEN c.validity_days <= 398 THEN '367-398d'
			ELSE '>398d' END AS label, count(*) AS count ` + deployed + ` GROUP BY label`).Scan(&vb)
	p.ValidityBuckets = orderBuckets(vb, []string{"<=90d", "91-100d", "101-180d", "181-366d", "367-398d", ">398d"})

	// Renewal lead-time: how long before expiry certificates are replaced.
	var rl []models.LabelCount
	d.db.Raw(`SELECT CASE
			WHEN days_until_expiry < 0  THEN 'after expiry'
			WHEN days_until_expiry <= 3  THEN '0-3d before'
			WHEN days_until_expiry <= 7  THEN '4-7d before'
			WHEN days_until_expiry <= 14 THEN '8-14d before'
			WHEN days_until_expiry <= 30 THEN '15-30d before'
			ELSE '>30d before' END AS label, count(*) AS count
		FROM cert_observations WHERE observation_type = 'change' GROUP BY label`).Scan(&rl)
	p.RenewalLeadTime = orderBuckets(rl, []string{"after expiry", "0-3d before", "4-7d before", "8-14d before", "15-30d before", ">30d before"})

	// Adaptive cadence scatter: days-to-expiry vs hours-to-next-scan.
	d.db.Raw(`SELECT dc.domain AS domain,
			EXTRACT(EPOCH FROM (c.not_after - now())) / 86400 AS days_until_expiry,
			EXTRACT(EPOCH FROM (dc.next_scan_at - now())) / 3600 AS next_scan_hours
		` + deployed + ` ORDER BY days_until_expiry ASC LIMIT 500`).Scan(&p.Cadence)

	// ARI window position: where in the certificate lifetime the CA-recommended
	// renewal window starts (NotBefore=0, NotAfter=1). Verifies the "last 1/3"
	// (≈0.667) regularity; anything <0.5 is an early/urgent (emergency) window.
	var aw []models.LabelCount
	d.db.Raw(`SELECT CASE
			WHEN frac < 0.5 THEN '<0.5 (early/urgent)'
			WHEN frac < 0.6 THEN '0.5-0.6'
			WHEN frac < 0.7 THEN '0.6-0.7 (normal)'
			WHEN frac < 0.8 THEN '0.7-0.8'
			ELSE '>0.8' END AS label, count(*) AS count
		FROM (
			SELECT EXTRACT(EPOCH FROM (dc.ari_window_start - c.not_before)) /
			       NULLIF(EXTRACT(EPOCH FROM (c.not_after - c.not_before)), 0) AS frac
			FROM domain_certificates dc JOIN certificates c ON c.id = dc.current_certificate_id
			WHERE dc.current_certificate_id <> 0 AND dc.ari_window_start IS NOT NULL
		) t WHERE frac IS NOT NULL GROUP BY label`).Scan(&aw)
	p.ARIWindows = orderBuckets(aw, []string{"<0.5 (early/urgent)", "0.5-0.6", "0.6-0.7 (normal)", "0.7-0.8", ">0.8"})

	return p
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func avgMs(totalMs int64, n int) float64 {
	if n <= 0 {
		return 0
	}
	return float64(totalMs) / float64(n)
}

// orderBuckets reorders sparse bucket counts into a fixed label order, filling
// missing buckets with zero so histograms show the full range.
func orderBuckets(in []models.LabelCount, order []string) []models.LabelCount {
	counts := make(map[string]int64, len(in))
	for _, x := range in {
		counts[x.Label] = x.Count
	}
	out := make([]models.LabelCount, 0, len(order))
	for i, lbl := range order {
		out = append(out, models.LabelCount{Label: lbl, Count: counts[lbl], Order: i})
	}
	return out
}

var allowedSort = map[string]bool{
	"not_after": true, "tranco_rank": true, "last_scanned_at": true,
	"next_scan_at": true, "change_count": true, "domain": true, "first_seen_at": true,
}

func safeSort(col, def string) string {
	if allowedSort[col] {
		return col
	}
	return def
}

func safeOrder(o string) string {
	if o == "asc" || o == "ASC" {
		return "ASC"
	}
	return "DESC"
}
