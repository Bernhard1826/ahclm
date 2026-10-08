package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
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

	// Keep a coherent anomaly snapshot for concurrent index requests instead of
	// rebuilding the full monitored population once per page.
	anomalyCacheMu sync.Mutex
	// The issue-register index does not need the longitudinal diagnosis joins
	// used by the detail endpoint. Keep its raw finding snapshot separately so
	// a summary request never waits for the full evidence build.
	anomalySummaryCache         []models.Anomaly
	anomalySummaryCacheAt       time.Time
	anomalySummaryInvalidatedAt time.Time
}

// A cold issue-register build is substantially slower than one minute on the
// full monitoring population. Keep its coherent snapshot for five minutes so
// concurrent paginated API requests reuse it instead of each rebuilding the
// full result after the short TTL expires.
const anomalyCacheTTL = 5 * time.Minute

// Measurements update many rows while a scan batch is running. Coalesce those
// invalidations so paginated index reads can share one snapshot instead of
// rebuilding it after each completed scan.
const anomalySummaryRefreshCooldown = 30 * time.Second

// ErrDomainNotMonitored is returned when an operation targets a host outside
// the current combined monitoring population (Tranco plus local lists). The
// old name is retained as an alias below so existing API clients continue to
// receive the same sentinel.
var ErrDomainNotMonitored = errors.New("domain is not in the current monitoring population")

// ErrDomainNotInTranco is kept for source compatibility with earlier callers.
var ErrDomainNotInTranco = ErrDomainNotMonitored

// Production monitoring includes the current Tranco Top-10000 population and
// the union of successfully refreshed local-list sources.
const monitoredPredicate = "(tranco_rank BETWEEN 1 AND 10000 OR local_list_member = TRUE)"
const monitoredPredicateQualified = "(domain_certificates.tranco_rank BETWEEN 1 AND 10000 OR domain_certificates.local_list_member = TRUE)"
const monitoredDomainSubquery = "domain IN (SELECT domain FROM domain_certificates WHERE " + monitoredPredicate + ")"

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
		&models.MeasurementSnapshot{},
		&models.InternalEvidenceEvent{},
		&models.CDNPropagationExperiment{},
		&models.CDNPropagationRound{},
		&models.CDNPropagationObservation{},
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
	logBackfill(backfillObservationProvenance(db))

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
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_measurement_snapshots_domain_time
		ON measurement_snapshots (domain, observed_at DESC)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_internal_evidence_domain_time
		ON internal_evidence_events (domain, occurred_at ASC, id ASC)`)
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
	if cert == nil || cert.Fingerprint == "" {
		return nil, false, fmt.Errorf("certificate fingerprint is required")
	}
	var existing models.Certificate
	err := d.db.Where("fingerprint = ?", cert.Fingerprint).First(&existing).Error
	if err == nil {
		updates := map[string]interface{}{}
		if !cert.LastSeenAt.IsZero() {
			updates["last_seen_at"] = gorm.Expr("GREATEST(last_seen_at, ?)", cert.LastSeenAt)
		}
		if !cert.FirstSeenAt.IsZero() {
			updates["first_seen_at"] = gorm.Expr("LEAST(first_seen_at, ?)", cert.FirstSeenAt)
		}
		if existing.SPKIFingerprint == "" && cert.SPKIFingerprint != "" {
			updates["spki_fingerprint"] = cert.SPKIFingerprint
			existing.SPKIFingerprint = cert.SPKIFingerprint
		}
		// Backfill the chain on certs first recorded before chain capture existed.
		if existing.Chain == "" && cert.Chain != "" {
			updates["chain"] = cert.Chain
			existing.Chain = cert.Chain
		}
		if err := d.db.Model(&existing).Updates(updates).Error; err != nil {
			return nil, false, err
		}
		if cert.LastSeenAt.After(existing.LastSeenAt) {
			existing.LastSeenAt = cert.LastSeenAt
		}
		if !cert.FirstSeenAt.IsZero() && cert.FirstSeenAt.Before(existing.FirstSeenAt) {
			existing.FirstSeenAt = cert.FirstSeenAt
		}
		return &existing, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, err
	}
	if cert.FirstSeenAt.IsZero() {
		cert.FirstSeenAt = cert.LastSeenAt
	}
	// Do not abort an enclosing PostgreSQL scan transaction on an insert race.
	created := d.db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "fingerprint"}}, DoNothing: true}).Create(cert)
	if created.Error != nil {
		return nil, false, created.Error
	}
	if created.RowsAffected == 0 {
		return d.UpsertCertificate(cert)
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
		q = q.Where("(common_name ILIKE ? OR sans ILIKE ?)", "%"+f.Domain+"%", "%"+f.Domain+"%")
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
// WithDomainScanTransaction serializes scan commits across workers and
// processes. The callback always receives the current row under a row lock.
func (d *Database) WithDomainScanTransaction(domain string, apply func(*Database, *models.DomainCertificate) error) error {
	err := d.db.Transaction(func(tx *gorm.DB) error {
		var current models.DomainCertificate
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("domain = ? AND "+monitoredPredicate, models.GetDomain(domain)).First(&current).Error; err != nil {
			return err
		}
		return apply(&Database{db: tx, cfg: d.cfg}, &current)
	})
	if err == nil {
		d.invalidateAnomalyCache()
	}
	return err
}

func (d *Database) SaveDomainCertificate(dc *models.DomainCertificate) error {
	if dc == nil {
		return ErrDomainNotInTranco
	}
	dc.Domain = models.GetDomain(dc.Domain)
	if dc.Domain == "" || dc.TrancoRank < 0 || dc.TrancoRank > models.TrancoTopLimit {
		return ErrDomainNotMonitored
	}
	if dc.TrancoRank == 0 && !dc.LocalListMember {
		return ErrDomainNotInTranco
	}
	var enrolled int64
	if err := d.db.Model(&models.DomainCertificate{}).
		Where("domain = ? AND "+monitoredPredicate, dc.Domain).
		Count(&enrolled).Error; err != nil {
		return err
	}
	if enrolled == 0 {
		return ErrDomainNotInTranco
	}
	if err := d.db.Omit("CurrentCertificate").Save(dc).Error; err != nil {
		return err
	}
	d.invalidateAnomalyCache()
	return nil
}

// GetDomainCertificate loads a domain row with its current certificate.
func (d *Database) GetDomainCertificate(domain string) (*models.DomainCertificate, error) {
	domain = models.GetDomain(domain)
	var dc models.DomainCertificate
	err := d.db.Preload("CurrentCertificate").Where("domain = ? AND "+monitoredPredicate, domain).First(&dc).Error
	if err != nil {
		return nil, err
	}
	return &dc, nil
}

// GetOrInitDomain returns an enrolled domain from the current combined
// monitoring population. Manual/ad-hoc hosts are rejected instead of being
// inserted.
func (d *Database) GetOrInitDomain(domain string) (*models.DomainCertificate, error) {
	domain = models.GetDomain(domain)
	if domain == "" {
		return nil, ErrDomainNotMonitored
	}
	dc, err := d.GetDomainCertificate(domain)
	if err == nil {
		return dc, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	return nil, ErrDomainNotMonitored
}

// GetDueDomains returns domains whose next_scan_at is due, highest priority first.
func (d *Database) GetDueDomains(now time.Time, limit int) ([]models.DomainCertificate, error) {
	var dcs []models.DomainCertificate
	err := d.db.Where(monitoredPredicate+" AND next_scan_at <= ?", now).
		Order("priority DESC, next_scan_at ASC").
		Limit(limit).Find(&dcs).Error
	return dcs, err
}

// ReactivateLegacyDormantDomains migrates the old expiry-based dormant state
// back into the active observation queue. Expiry alone never proves that a
// service was retired, so these rows must be probed again immediately.
func (d *Database) ReactivateLegacyDormantDomains(now time.Time) (int64, error) {
	result := d.db.Model(&models.DomainCertificate{}).
		Where(monitoredPredicate+" AND status = ?", models.StatusDormant).
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
	d.db.Model(&models.DomainCertificate{}).Where(monitoredPredicate+" AND next_scan_at <= ?", now).Count(&c)
	return c
}

// ListDomains returns domain rows (with current cert) paginated/filtered.
func (d *Database) ListDomains(f *models.CertificateFilter) ([]models.DomainCertificate, int64, error) {
	var dcs []models.DomainCertificate
	var total int64

	q := d.db.Model(&models.DomainCertificate{})
	q = q.Where(monitoredPredicate)
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
		Where(monitoredPredicateQualified+" AND domain_certificates.status = ? AND c.not_after > now() AND c.not_after <= ?", models.StatusActive, cutoff).
		Order("c.not_after ASC").Find(&dcs).Error
	return dcs, err
}

// GetExpiredDomains returns active domains currently serving an expired certificate.
func (d *Database) GetExpiredDomains() ([]models.DomainCertificate, error) {
	var dcs []models.DomainCertificate
	err := d.db.Preload("CurrentCertificate").
		Joins("JOIN certificates c ON c.id = domain_certificates.current_certificate_id").
		Where(monitoredPredicateQualified+" AND domain_certificates.status = ? AND c.not_after < now()", models.StatusActive).
		Order("c.not_after DESC").Find(&dcs).Error
	return dcs, err
}

// GetRevokedDomains returns active domains whose deployed cert is revoked.
func (d *Database) GetRevokedDomains() ([]models.DomainCertificate, error) {
	var dcs []models.DomainCertificate
	err := d.db.Preload("CurrentCertificate").
		Where(monitoredPredicate+" AND status = ? AND revocation_status = ?", models.StatusActive, models.RevocationRevoked).
		Order("revoked_at DESC").Find(&dcs).Error
	return dcs, err
}

// GetUpcomingSchedule returns the soonest scheduled scans.
func (d *Database) GetUpcomingSchedule(limit int) ([]models.DomainCertificate, error) {
	var dcs []models.DomainCertificate
	err := d.db.Preload("CurrentCertificate").
		Where(monitoredPredicate).Order("next_scan_at ASC").Limit(limit).Find(&dcs).Error
	return dcs, err
}

// ---------------------------------------------------------------------------
// Observations (time-series)
// ---------------------------------------------------------------------------

// AppendObservation writes one observation. Milestone duplicates are ignored
// via the partial unique index.
func (d *Database) AppendObservation(obs *models.CertObservation) error {
	if obs == nil {
		return ErrDomainNotMonitored
	}
	obs.Domain = models.GetDomain(obs.Domain)
	if obs.Domain == "" {
		return ErrDomainNotMonitored
	}
	var enrolled int64
	if err := d.db.Model(&models.DomainCertificate{}).Where("domain = ? AND "+monitoredPredicate, obs.Domain).Count(&enrolled).Error; err != nil {
		return err
	}
	if enrolled == 0 {
		return ErrDomainNotMonitored
	}
	if obs.CreatedAt.IsZero() {
		obs.CreatedAt = time.Now()
	}
	tx := d.db
	if obs.ObservationType == models.ObsMilestone {
		tx = tx.Clauses(clause.OnConflict{DoNothing: true})
	}
	if err := tx.Create(obs).Error; err != nil {
		return err
	}
	d.invalidateAnomalyCache()
	return nil
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
	domain = models.GetDomain(domain)
	if _, err := d.GetDomainCertificate(domain); err != nil {
		return nil, err
	}
	var obs []models.CertObservation
	q := d.db.Where("domain = ?", domain).Order("observed_at DESC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	err := q.Find(&obs).Error
	return obs, err
}

// SaveMeasurementSnapshot appends a bounded evidence round. Snapshots are
// intentionally not de-duplicated: unchanged rounds are the control needed to
// establish persistence and to avoid mistaking a CDN's normal fan-out for a
// deployment incident.
func (d *Database) SaveMeasurementSnapshot(snapshot *models.MeasurementSnapshot) error {
	if snapshot == nil {
		return ErrDomainNotMonitored
	}
	snapshot.Domain = models.GetDomain(snapshot.Domain)
	if snapshot.Domain == "" {
		return ErrDomainNotMonitored
	}
	var enrolled int64
	if err := d.db.Model(&models.DomainCertificate{}).Where("domain = ? AND "+monitoredPredicate, snapshot.Domain).Count(&enrolled).Error; err != nil {
		return err
	}
	if enrolled == 0 {
		return ErrDomainNotMonitored
	}
	if snapshot.CreatedAt.IsZero() {
		snapshot.CreatedAt = time.Now().UTC()
	}
	if err := d.db.Create(snapshot).Error; err != nil {
		return err
	}
	d.invalidateAnomalyCache()
	return nil
}

func (d *Database) GetMeasurementSnapshots(domain string, limit int) ([]models.MeasurementSnapshot, error) {
	domain = models.GetDomain(domain)
	if _, err := d.GetDomainCertificate(domain); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	var snapshots []models.MeasurementSnapshot
	err := d.db.Where("domain = ?", domain).Order("observed_at DESC, id DESC").Limit(limit).Find(&snapshots).Error
	return snapshots, err
}

// GetDomainDiagnosis returns the same evidence-backed assessment used by the
// anomaly index, allowing a domain detail page or an operator API call to
// inspect the full hypothesis ranking without waiting for a new scan.
//
// anomalyType selects which finding the case file is built for. Without it the
// function used to prefer a topology row whenever one existed, so a frequent-
// change inspector received the wrong evidence chain.
func (d *Database) GetDomainDiagnosis(domain string) (*models.CauseDiagnosis, error) {
	return d.GetDomainDiagnosisFor(domain, "")
}

func (d *Database) GetDomainDiagnosisFor(domain, anomalyType string) (*models.CauseDiagnosis, error) {
	dc, err := d.GetDomainCertificate(domain)
	if err != nil {
		return nil, err
	}
	snapshots, err := d.GetMeasurementSnapshots(domain, 120)
	if err != nil {
		return nil, err
	}
	var observations []models.CertObservation
	if err := d.db.Where("domain = ? AND observation_type IN ?", domain, []string{models.ObsChange, models.ObsSameKey, models.ObsStaleAfterChange, models.ObsDeploymentFailure, models.ObsResidual, models.ObsARIWindow, models.ObsARIEmergency}).Order("observed_at DESC, id DESC").Find(&observations).Error; err != nil {
		return nil, err
	}
	internalEvents, err := d.GetInternalEvidence(domain, 500)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	fingerprints := make(map[string]struct{})
	for _, observation := range observations {
		if observation.Fingerprint != "" {
			fingerprints[observation.Fingerprint] = struct{}{}
		}
		if observation.PreviousFingerprint != "" {
			fingerprints[observation.PreviousFingerprint] = struct{}{}
		}
	}
	if dc != nil {
		for _, fingerprint := range collectTLSFindingFingerprints([]models.DomainCertificate{*dc}) {
			fingerprints[fingerprint] = struct{}{}
		}
		if dc.ResidualFingerprint != "" {
			fingerprints[dc.ResidualFingerprint] = struct{}{}
		}
	}
	certs := make(map[string]models.Certificate)
	if len(fingerprints) > 0 {
		values := make([]string, 0, len(fingerprints))
		for fingerprint := range fingerprints {
			values = append(values, fingerprint)
		}
		var rows []models.Certificate
		if err := d.db.Where("fingerprint IN ?", values).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			certs[row.Fingerprint] = row
		}
	}
	item := models.Anomaly{Domain: domain, Type: diagnosisTypeFor(anomalyType, observations), Reason: "No certificate-change anomaly has been recorded."}
	if isTLSValidationType(anomalyType) {
		item.Type = anomalyType
		if dc != nil && dc.TLSCheckedAt != nil {
			item.DetectedAt = *dc.TLSCheckedAt
		}
		if dc != nil {
			item.Fingerprint = dc.CurrentFingerprint
		}
	}
	if isCertificateConditionType(anomalyType) {
		item.Type = anomalyType
		seedCertificateConditionAnomaly(&item, dc)
	}
	for _, observation := range observations {
		if observation.ObservationType == item.Type {
			item.Reason = observation.Notes
			item.Fingerprint = observation.Fingerprint
			item.DetectedAt = observation.ObservedAt
			break
		}
	}
	if item.Type == "frequent_change" {
		changes := 0
		for _, observation := range observations {
			if observation.ObservationType != models.ObsChange {
				continue
			}
			if observation.ChangeClass == "" || observation.ChangeClass == models.ChangeClassReplacement {
				changes++
			}
		}
		item.OccurrenceCount = changes
		if dc != nil && dc.ChangeCount > item.OccurrenceCount {
			item.OccurrenceCount = dc.ChangeCount
		}
	}
	context := diagnosisContext{state: dc, snapshots: snapshots, observations: observations, certificates: certs, internalEvidence: internalEvents}
	diagnosis := inferDiagnosis(item, context)
	applyInternalEvidence(&diagnosis, SummarizeInternalEvidenceForContext(internalEvents, item.Type, certSlice(certs), observations, snapshots))
	diagnosis.EvidenceCase = buildEvidenceCase(item, context, diagnosis)
	diagnosis.Investigation = buildInvestigation(item, context, diagnosis)
	return &diagnosis, nil
}

func diagnosisTypeFor(requested string, observations []models.CertObservation) string {
	requested = strings.TrimSpace(requested)
	switch requested {
	case "frequent_change", "early_renewal", "same_key", models.ObsStaleAfterChange, models.ObsDeploymentFailure:
		return requested
	}
	if isTLSValidationType(requested) || isCertificateConditionType(requested) {
		return requested
	}
	for _, observation := range observations {
		if observation.ObservationType == models.ObsDeploymentFailure || observation.ObservationType == models.ObsStaleAfterChange {
			return observation.ObservationType
		}
	}
	return "frequent_change"
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

// RegisterTrancoDomains updates the ranked Tranco portion of the monitoring
// population. Local-list rows are preserved across refreshes.
func (d *Database) RegisterTrancoDomains(ranked map[string]int) (int, error) {
	normalized := normalizeTrancoRanks(ranked)
	if len(normalized) != models.TrancoTopLimit {
		return 0, fmt.Errorf("cannot register %d Tranco domains; exactly %d are required", len(normalized), models.TrancoTopLimit)
	}
	seenRanks := make(map[int]struct{}, len(normalized))
	for _, rank := range normalized {
		seenRanks[rank] = struct{}{}
	}
	for rank := 1; rank <= models.TrancoTopLimit; rank++ {
		if _, ok := seenRanks[rank]; !ok {
			return 0, fmt.Errorf("cannot register Tranco population with missing rank %d", rank)
		}
	}
	now := time.Now()
	rows := make([]models.DomainCertificate, 0, len(normalized))
	for domain, rank := range normalized {
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
	domains := make([]string, 0, len(rows))
	for _, row := range rows {
		domains = append(domains, row.Domain)
	}

	var pruned int64
	err := d.db.Transaction(func(tx *gorm.DB) error {
		// Insert in batches; on conflict only refresh the rank (preserve schedule).
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "domain"}},
			DoUpdates: clause.AssignmentColumns([]string{"tranco_rank", "updated_at"}),
		}).CreateInBatches(rows, 500).Error; err != nil {
			return err
		}

		var err error
		pruned, err = pruneNonTrancoRows(tx, domains)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("register Tranco population: %w", err)
	}
	if pruned > 0 {
		log.Printf("database: pruned %d stale monitoring rows", pruned)
	}
	return len(rows), nil
}

// normalizeTrancoRanks canonicalizes downloaded names and keeps the best rank
// when malformed input contains the same host more than once.
func normalizeTrancoRanks(ranked map[string]int) map[string]int {
	normalized := make(map[string]int, len(ranked))
	for rawDomain, rank := range ranked {
		if rank <= 0 || rank > models.TrancoTopLimit {
			continue
		}
		domain := models.GetDomain(rawDomain)
		if domain == "" {
			continue
		}
		if previous, exists := normalized[domain]; !exists || rank < previous {
			normalized[domain] = rank
		}
	}
	return normalized
}

// pruneNonTrancoRows removes monitoring data outside the freshly fetched
// Tranco list and current local-list membership. Historical TrancoList metadata
// and certificates still referenced by retained observations are preserved.
func pruneNonTrancoRows(tx *gorm.DB, domains []string) (int64, error) {
	var pruned int64
	for _, table := range []string{"cert_observations", "scan_jobs", "measurement_snapshots"} {
		result := tx.Exec("DELETE FROM "+table+" WHERE domain NOT IN ? AND domain NOT IN (SELECT domain FROM domain_certificates WHERE local_list_member = TRUE)", domains)
		if result.Error != nil {
			return pruned, result.Error
		}
		pruned += result.RowsAffected
	}
	result := tx.Exec("DELETE FROM domain_certificates WHERE domain NOT IN ? AND local_list_member = FALSE", domains)
	if result.Error != nil {
		return pruned, result.Error
	}
	pruned += result.RowsAffected

	// A certificate may have been seen on several retained domains or in their
	// observation history. Remove only rows with no remaining reference.
	result = tx.Exec(`DELETE FROM certificates c
		WHERE NOT EXISTS (
			SELECT 1 FROM domain_certificates dc
			WHERE dc.current_certificate_id = c.id
		)
		AND NOT EXISTS (
			SELECT 1 FROM cert_observations co
			WHERE co.certificate_id = c.id OR co.fingerprint = c.fingerprint
		)`)
	if result.Error != nil {
		return pruned, result.Error
	}
	return pruned, nil
}

// RegisterLocalDomains replaces the union of local-list membership with a
// successfully loaded domain set. Existing schedule, certificate, and
// observation state is retained; new rows become due immediately. Tranco rank
// is never changed by this operation.
func (d *Database) RegisterLocalDomains(domains []string) (int, error) {
	normalized := normalizeLocalDomains(domains)
	if len(normalized) == 0 {
		return 0, fmt.Errorf("cannot register an empty local domain population")
	}
	now := time.Now()
	rows := make([]models.DomainCertificate, 0, len(normalized))
	for _, domain := range normalized {
		rows = append(rows, models.DomainCertificate{
			Domain:           domain,
			LocalListMember:  true,
			Status:           models.StatusActive,
			RevocationStatus: models.RevocationNotChecked,
			FirstSeenAt:      now,
			NextScanAt:       now,
			Priority:         40,
		})
	}

	err := d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "domain"}},
			DoUpdates: clause.Assignments(map[string]interface{}{"local_list_member": true, "updated_at": now}),
		}).CreateInBatches(rows, 1000).Error; err != nil {
			return err
		}

		// The configured set is bounded (currently 20,000 across both sources),
		// so PostgreSQL can clear stale membership in one statement. This avoids
		// loading every prior local-list row into memory when a large list is
		// intentionally reduced.
		cleanup := tx.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Error)})
		if err := cleanup.Model(&models.DomainCertificate{}).
			Where("local_list_member = TRUE AND domain NOT IN ?", normalized).
			Updates(map[string]interface{}{"local_list_member": false, "updated_at": now}).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("register local domain population: %w", err)
	}
	return len(rows), nil
}

func normalizeLocalDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	for _, raw := range domains {
		domain := models.GetDomain(raw)
		if domain == "" || strings.ContainsAny(domain, "/?#: \t\r\n") {
			continue
		}
		if _, exists := seen[domain]; !exists {
			seen[domain] = struct{}{}
		}
	}
	normalized := make([]string, 0, len(seen))
	for domain := range seen {
		normalized = append(normalized, domain)
	}
	sort.Strings(normalized)
	return normalized
}

// ---------------------------------------------------------------------------
// Scan jobs (audit trail)
// ---------------------------------------------------------------------------

func (d *Database) CreateScanJob(job *models.ScanJob) error {
	if job == nil {
		return ErrDomainNotMonitored
	}
	job.Domain = models.GetDomain(job.Domain)
	if job.Domain == "" {
		return ErrDomainNotMonitored
	}
	var enrolled int64
	if err := d.db.Model(&models.DomainCertificate{}).
		Where("domain = ? AND "+monitoredPredicate, job.Domain).
		Count(&enrolled).Error; err != nil {
		return err
	}
	if enrolled == 0 {
		return ErrDomainNotMonitored
	}
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
	if err := d.db.Model(&models.ScanJob{}).Where("id = ?", jobID).Updates(updates).Error; err != nil {
		return err
	}
	d.invalidateAnomalyCache()
	return nil
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
	err := d.db.Where(monitoredDomainSubquery).Order("created_at DESC").Limit(limit).Find(&jobs).Error
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
	d.db.Model(&models.DomainCertificate{}).Where(monitoredPredicate).Count(&s.TotalDomains)
	d.db.Model(&models.DomainCertificate{}).Where(monitoredPredicate+" AND status = ?", models.StatusActive).Count(&s.ActiveDomains)
	d.db.Model(&models.CertObservation{}).
		Where("domain IN (SELECT domain FROM domain_certificates WHERE " + monitoredPredicate + ")").Count(&s.Observations)
	d.db.Model(&models.DomainCertificate{}).
		Where(monitoredPredicate+" AND status = ? AND revocation_status = ?", models.StatusActive, models.RevocationRevoked).
		Count(&s.RevokedCerts)
	s.DueNow = d.CountDueDomains(time.Now())

	s.ExpiringCerts7d = d.countExpiring(7)
	s.ExpiringCerts30d = d.countExpiring(30)
	d.db.Model(&models.DomainCertificate{}).
		Joins("JOIN certificates c ON c.id = domain_certificates.current_certificate_id").
		Where(monitoredPredicateQualified+" AND domain_certificates.status = ? AND c.not_after < now()", models.StatusActive).
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
		Where(monitoredPredicateQualified+" AND c.not_after > now() AND c.not_after <= ?", cutoff).Count(&c)
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

// GetAnomalies surfaces one observed finding per domain and type for the issue
// register. Counts are derived from durable ScanJob records (one scheduled or
// manual monitoring operation; scanner retries are not separate rounds). The
// issue-register response contains the measured condition and retained
// evidence; causal diagnosis is served by the explicit domain endpoint.
func (d *Database) GetAnomalies(limit int) ([]models.Anomaly, error) {
	return d.getAnomalies(limit, false)
}

// getAnomalies builds the shared finding set. Summary callers still run the
// lifecycle evidence gate, but strip the causal diagnosis before responding.
func (d *Database) getAnomalies(limit int, decorate bool) ([]models.Anomaly, error) {
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
	var validated []models.DomainCertificate
	if err := d.db.Select("domain", "current_fingerprint", "tls_checked_at", "tls_findings").
		Where(monitoredPredicate+" AND status = ? AND tls_checked_at IS NOT NULL AND tls_findings NOT IN ('', 'null', '[]')", models.StatusActive).
		Find(&validated).Error; err != nil {
		return nil, err
	}
	for _, dc := range validated {
		var findings []models.TLSFinding
		if json.Unmarshal([]byte(dc.TLSFindings), &findings) != nil {
			continue
		}
		grouped := map[string][]models.TLSFinding{}
		for _, finding := range findings {
			grouped[finding.Code] = append(grouped[finding.Code], finding)
		}
		for code, rows := range grouped {
			if decorate {
				out = append(out, seedTLSValidationAnomaly(dc, code, rows))
			} else {
				item := seedTLSValidationObservation(dc, code, rows)
				// Some names in the corpus are service aliases or non-HTTPS
				// identities. The TLS verifier can establish that distinction without
				// loading longitudinal endpoint history, so do not report those as
				// deterministic site certificate defects.
				if code == "hostname_mismatch" {
					diagnosis := inferTLSValidationDiagnosis(item, diagnosisContext{state: &dc})
					if diagnosis.BenignExplanation != "" {
						continue
					}
				}
				out = append(out, item)
			}
		}
	}

	var revoked []models.DomainCertificate
	if err := d.db.Select("domain", "status", "current_fingerprint", "revoked_at", "revocation_status", "revocation_checked_via", "revocation_reason", "evidence_status", "evidence_pending_reason").
		Where(monitoredPredicate+" AND status IN ? AND revocation_status = ?", criticalDomainStatuses(), models.RevocationRevoked).
		Find(&revoked).Error; err != nil {
		return nil, err
	}
	for _, dc := range revoked {
		cause := anomalyCause{
			confirmedReason:   "The current certificate was reported as revoked by the retained revocation check.",
			confirmedEvidence: []string{"revocation_status=" + dc.RevocationStatus, "checked_via=" + firstNonEmpty(dc.RevocationCheckedVia, "unknown")},
		}
		description := "The currently deployed certificate is revoked"
		if dc.Status == models.StatusUnreachable {
			description = "The last successfully observed certificate is revoked; current endpoint revalidation is pending"
			cause.confirmedReason = "The last successful TLS measurement reported the certificate as revoked; subsequent endpoint measurements are unreachable, so the finding remains critical pending revalidation."
			cause.confirmedEvidence = append(cause.confirmedEvidence, "last_known_status=unreachable", "revalidation=pending")
		}
		if dc.RevocationReason != "" {
			cause.inferredReason = fmt.Sprintf("The CA-reported revocation reason is %q; this is a CA classification and does not prove the operator's intent.", dc.RevocationReason)
			revocationReason := "revocation_reason=" + dc.RevocationReason
			cause.confirmedEvidence = append(cause.confirmedEvidence, revocationReason)
			cause.inferredEvidence = []string{revocationReason, "interpretation=ca_reason_not_operator_intent"}
		}
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: dc.Domain, Type: "revoked", Severity: "critical",
			Description: description,
			Fingerprint: dc.CurrentFingerprint, OccurrenceCount: 1, DetectedAt: firstTime(dc.RevokedAt, now),
		}, withDomainEvidence(cause, dc)), 1); err != nil {
			return nil, err
		}
	}

	var expired []models.DomainCertificate
	if err := d.db.Select("domain_certificates.domain", "domain_certificates.status", "domain_certificates.current_certificate_id", "domain_certificates.current_fingerprint", "domain_certificates.last_scanned_at", "domain_certificates.evidence_status", "domain_certificates.evidence_pending_reason").
		Preload("CurrentCertificate", func(tx *gorm.DB) *gorm.DB { return tx.Select("id", "not_after") }).
		Joins("JOIN certificates c ON c.id = domain_certificates.current_certificate_id").
		Where(monitoredPredicateQualified+" AND domain_certificates.status IN ? AND c.not_after < now() AND domain_certificates.last_scanned_at > c.not_after", criticalDomainStatuses()).Find(&expired).Error; err != nil {
		return nil, err
	}
	for _, dc := range expired {
		cert := dc.CurrentCertificate
		days := 0
		if cert != nil {
			days = models.DaysUntil(cert.NotAfter, now)
		}
		description := "The domain is still serving an expired certificate"
		cause := anomalyCause{
			confirmedReason:   fmt.Sprintf("A successful TLS handshake returned a certificate whose NotAfter time had passed by %d day(s).", -days),
			confirmedEvidence: []string{fmt.Sprintf("not_after=%s", certTime(cert)), "status=" + dc.Status},
			inferredReason:    "The endpoint likely has an outdated deployment or missed renewal; certificate expiry alone does not prove that the domain is retired.",
			inferredEvidence:  []string{fmt.Sprintf("not_after=%s", certTime(cert)), "status=" + dc.Status, "inference=outdated_deployment_or_missing_renewal"},
		}
		if dc.Status == models.StatusUnreachable {
			description = "The last successfully observed certificate was expired; current endpoint revalidation is pending"
			cause.confirmedReason = fmt.Sprintf("A successful TLS handshake last returned a certificate whose NotAfter time had passed by %d day(s); subsequent endpoint measurements are unreachable, so the finding remains critical pending revalidation.", -days)
			cause.confirmedEvidence = append(cause.confirmedEvidence, "last_known_status=unreachable", "revalidation=pending")
		}
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: dc.Domain, Type: "expired_served", Severity: "critical",
			Description: description,
			Fingerprint: dc.CurrentFingerprint, OccurrenceCount: 1, DetectedAt: firstTimePtr(dc.LastScannedAt, now),
		}, withDomainEvidence(cause, dc)), 1); err != nil {
			return nil, err
		}
	}

	// Legacy dormant rows are shown as historical evidence, never as proof of retirement.
	var legacy []models.DomainCertificate
	if err := d.db.Select("domain_certificates.domain", "domain_certificates.status", "domain_certificates.current_certificate_id", "domain_certificates.current_fingerprint", "domain_certificates.last_scanned_at", "domain_certificates.evidence_status", "domain_certificates.evidence_pending_reason").
		Preload("CurrentCertificate", func(tx *gorm.DB) *gorm.DB { return tx.Select("id", "not_after") }).
		Joins("JOIN certificates c ON c.id = domain_certificates.current_certificate_id").
		Where(monitoredPredicateQualified+" AND domain_certificates.status = ? AND c.not_after < now()", models.StatusDormant).Find(&legacy).Error; err != nil {
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

	// Early renewals are grouped by domain so the UI reports the number of
	// observed replacements instead of one indistinguishable row per event.
	type earlyRenewalRow struct {
		models.CertObservation
		ReplacementEvents int64 `gorm:"column:replacement_events"`
		DistinctLeaves    int64 `gorm:"column:distinct_leaves"`
	}
	var earlyRows []earlyRenewalRow
	if err := d.db.Raw(`
		WITH early AS (
			SELECT id, domain, fingerprint, observed_at, days_until_expiry,
				previous_fingerprint, evidence_status, evidence_pending_reason
			FROM cert_observations
			WHERE domain IN (SELECT domain FROM domain_certificates WHERE tranco_rank BETWEEN 1 AND 10000 OR local_list_member = TRUE)
				AND observation_type = ? AND days_until_expiry > 30
		), counts AS (
			SELECT domain, COUNT(*) AS replacement_events,
				COUNT(DISTINCT NULLIF(fingerprint, '')) AS distinct_leaves
			FROM early GROUP BY domain
		), latest AS (
			SELECT DISTINCT ON (domain) * FROM early
			ORDER BY domain, observed_at DESC, id DESC
		)
		SELECT latest.*, counts.replacement_events, counts.distinct_leaves
		FROM latest JOIN counts USING (domain)`, models.ObsChange).Scan(&earlyRows).Error; err != nil {
		return nil, err
	}
	for _, row := range earlyRows {
		latest := row.CertObservation
		domain := latest.Domain
		count := int(row.ReplacementEvents)
		distinctLeaves := int(row.DistinctLeaves)
		cause := anomalyCause{}
		if decorate {
			cause = d.certificateChangeCause(domain, latest)
		} else {
			cause = summaryObservationCause(latest)
		}
		cause.confirmedReason = fmt.Sprintf("Observed %d early renewal(s); the latest occurred %d days before expiry. %s", count, latest.DaysUntilExpiry, cause.confirmedReason)
		replacementEvents := fmt.Sprintf("replacement_events=%d", count)
		distinctLeavesEvidence := fmt.Sprintf("distinct_replacement_leaves=%d", distinctLeaves)
		cause.confirmedEvidence = append([]string{replacementEvents}, cause.confirmedEvidence...)
		cause.confirmedEvidence = append([]string{distinctLeavesEvidence}, cause.confirmedEvidence...)
		cause.inferredEvidence = append([]string{replacementEvents}, cause.inferredEvidence...)
		cause.inferredEvidence = append([]string{distinctLeavesEvidence}, cause.inferredEvidence...)
		if distinctLeaves <= 2 {
			cause.confirmedEvidence = append(cause.confirmedEvidence, "replacement_pool_shape=true")
			cause.inferredEvidence = append(cause.inferredEvidence, "replacement_pool_shape=true")
		}
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: domain, Type: "early_renewal", Severity: "info",
			Description: fmt.Sprintf("The certificate was replaced more than 30 days before expiry (%d observation(s))", count),
			Fingerprint: latest.Fingerprint, OccurrenceCount: count, DetectedAt: latest.ObservedAt,
		}, withObservationEvidence(cause, latest)), count); err != nil {
			return nil, err
		}
	}
	// Lifecycle-specific findings are derived from append-only event rows.
	// Revoked residual-service observations are the same finding as a
	// currently revoked leaf, so they are not listed as a second issue type.
	// Mixed-endpoint and stale-after-change rows are still loaded here so
	// diagnosis can inspect them; GetAnomalies then drops the ones that are
	// no longer a live problem.
	type lifecycleSummaryRow struct {
		models.CertObservation
		OccurrenceCount int64 `gorm:"column:occurrence_count"`
	}
	var lifecycleRows []lifecycleSummaryRow
	if err := d.db.Raw(`
		WITH lifecycle AS (
			SELECT id, domain, observed_at, observation_type, previous_fingerprint, fingerprint,
				previous_ip_address, ip_address, resolved_ips, previous_resolved_ips,
				endpoint_probes, evidence_status
			FROM cert_observations
			WHERE domain IN (SELECT domain FROM domain_certificates WHERE tranco_rank BETWEEN 1 AND 10000 OR local_list_member = TRUE)
				AND observation_type IN ?
		)
		SELECT DISTINCT ON (domain, observation_type) lifecycle.*,
			COUNT(*) OVER (PARTITION BY domain, observation_type) AS occurrence_count
		FROM lifecycle
		ORDER BY domain, observation_type, observed_at DESC, id DESC`,
		[]string{models.ObsSameKey, models.ObsStaleAfterChange, models.ObsDeploymentFailure}).Scan(&lifecycleRows).Error; err != nil {
		return nil, err
	}
	for _, row := range lifecycleRows {
		latest := row.CertObservation
		count := int(row.OccurrenceCount)
		cause := lifecycleCause(latest, count)
		severity := "info"
		switch latest.ObservationType {
		case models.ObsStaleAfterChange, models.ObsDeploymentFailure:
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

	if decorate {
		var churny []models.DomainCertificate
		if err := d.db.Select("domain", "change_count", "current_fingerprint", "last_scanned_at").
			Where(monitoredPredicate+" AND change_count >= ?", 3).Order("change_count DESC").Find(&churny).Error; err != nil {
			return nil, err
		}
		for _, dc := range churny {
			var replacementCount int64
			if err := d.db.Model(&models.CertObservation{}).
				Where("domain = ? AND observation_type = ? AND change_class = ?", dc.Domain, models.ObsChange, models.ChangeClassReplacement).
				Count(&replacementCount).Error; err != nil {
				return nil, err
			}
			if replacementCount < 3 {
				continue
			}
			var latest models.CertObservation
			_ = d.db.Where("domain = ? AND observation_type = ? AND change_class = ?", dc.Domain, models.ObsChange, models.ChangeClassReplacement).Order("observed_at DESC").First(&latest).Error
			cause := d.certificateChangeCause(dc.Domain, latest)
			certificateChanges := fmt.Sprintf("same_ip_replacements=%d", replacementCount)
			cause.confirmedEvidence = append([]string{certificateChanges}, cause.confirmedEvidence...)
			cause.inferredEvidence = append([]string{certificateChanges}, cause.inferredEvidence...)
			if err := appendFinding(withAnomalyCause(models.Anomaly{
				Domain: dc.Domain, Type: "frequent_change", Severity: "warning",
				Description: fmt.Sprintf("The same endpoint replaced its leaf %d times during the monitoring period", replacementCount),
				Fingerprint: dc.CurrentFingerprint, OccurrenceCount: int(replacementCount), DetectedAt: firstTimePtr(latest.ObservedAt, now),
			}, withObservationEvidence(cause, latest)), int(replacementCount)); err != nil {
				return nil, err
			}
		}
	} else {
		type frequentChangeRow struct {
			Domain                    string    `gorm:"column:domain"`
			CurrentFingerprint        string    `gorm:"column:current_fingerprint"`
			LastScannedAt             time.Time `gorm:"column:last_scanned_at"`
			ReplacementCount          int64     `gorm:"column:replacement_count"`
			DistinctReplacementLeaves int64     `gorm:"column:distinct_replacement_leaves"`
		}
		var churny []frequentChangeRow
		if err := d.db.Table("domain_certificates AS dc").
			Joins("JOIN cert_observations AS co ON co.domain = dc.domain").
			Select(`dc.domain AS domain, dc.current_fingerprint AS current_fingerprint,
				dc.last_scanned_at AS last_scanned_at, COUNT(co.id) AS replacement_count,
				COUNT(DISTINCT co.fingerprint) AS distinct_replacement_leaves`).
			Where("(dc.tranco_rank BETWEEN 1 AND 10000 OR dc.local_list_member = TRUE) AND dc.change_count >= ? AND co.observation_type = ? AND co.change_class = ?", 3, models.ObsChange, models.ChangeClassReplacement).
			Group("dc.domain, dc.current_fingerprint, dc.last_scanned_at").
			Having("COUNT(co.id) >= ?", 3).Scan(&churny).Error; err != nil {
			return nil, err
		}
		for _, row := range churny {
			replacementCount := int(row.ReplacementCount)
			candidate := models.Anomaly{
				Domain: row.Domain, Type: "frequent_change", Severity: "warning",
				Description: fmt.Sprintf("The same endpoint replaced its leaf %d times during the monitoring period", replacementCount),
				Fingerprint: row.CurrentFingerprint, OccurrenceCount: replacementCount, DetectedAt: firstTimePtr(row.LastScannedAt, now),
			}
			cause := anomalyCause{
				inferredReason:   "Repeated certificate changes were observed; endpoint attribution and renewal mechanism are pending longitudinal diagnosis.",
				inferredEvidence: []string{fmt.Sprintf("same_ip_replacements=%d", replacementCount), fmt.Sprintf("distinct_replacement_leaves=%d", row.DistinctReplacementLeaves), "inference=insufficient_longitudinal_evidence"},
			}
			if row.DistinctReplacementLeaves <= 2 {
				cause.inferredEvidence = append(cause.inferredEvidence, "replacement_pool_shape=true")
			}
			if err := appendFinding(withAnomalyCause(candidate, cause), replacementCount); err != nil {
				return nil, err
			}
		}
	}

	var ariEmerg []models.DomainCertificate
	if err := d.db.Select("domain", "status", "ari_checked_at", "current_fingerprint", "evidence_status", "evidence_pending_reason").
		Where(monitoredPredicate+" AND status IN ? AND ari_emergency = ?", criticalDomainStatuses(), true).Find(&ariEmerg).Error; err != nil {
		return nil, err
	}
	for _, dc := range ariEmerg {
		at := now
		if dc.ARICheckedAt != nil {
			at = *dc.ARICheckedAt
		}
		description := "The CA moved the ARI renewal window to the present"
		cause := anomalyCause{
			confirmedReason:   "The CA's ARI response moved the renewal window to the present.",
			confirmedEvidence: []string{"ari_emergency=true", "checked_at=" + at.Format(time.RFC3339)},
			inferredReason:    "This may indicate urgent renewal pressure or a broader CA incident; it does not establish the operator's intent.",
			inferredEvidence:  []string{"ari_emergency=true", "checked_at=" + at.Format(time.RFC3339), "inference=urgent_renewal_or_ca_incident"},
		}
		if dc.Status == models.StatusUnreachable {
			description = "The last successful measurement found an ARI emergency; current endpoint revalidation is pending"
			cause.confirmedReason = "The last successful CA ARI response moved the renewal window to the present; subsequent endpoint measurements are unreachable, so the finding remains critical pending revalidation."
			cause.confirmedEvidence = append(cause.confirmedEvidence, "last_known_status=unreachable", "revalidation=pending")
		}
		if err := appendFinding(withAnomalyCause(models.Anomaly{
			Domain: dc.Domain, Type: "ari_emergency", Severity: "critical",
			Description: description,
			Fingerprint: dc.CurrentFingerprint, OccurrenceCount: 1, DetectedAt: at,
		}, withDomainEvidence(cause, dc)), 1); err != nil {
			return nil, err
		}
	}

	if decorate {
		if err := d.decorateAnomalies(out); err != nil {
			return nil, err
		}
		if err := d.decorateDiagnoses(out); err != nil {
			return nil, err
		}
	} else {
		// The summary issue gate depends on retained finding evidence and event
		// counts, all of which are already present. Apply it before monitoring
		// decoration so excluded service aliases and non-issues do not pull their
		// full scan history into the expensive aggregate query.
		classifySummaryFindings(out)
		candidates := out[:0]
		for _, item := range out {
			if isIssueRegisterFinding(item) {
				candidates = append(candidates, item)
			}
		}
		out = candidates
		// The issue register still needs the durable monitoring window. This is
		// observation metadata, not causal diagnosis, and lets the UI show how
		// many scheduled/manual rounds support each finding.
		if err := d.decorateAnomalies(out); err != nil {
			return nil, err
		}
	}
	kept := out[:0]
	for _, item := range out {
		if isIssueRegisterFinding(item) {
			kept = append(kept, item)
		}
	}
	out = kept
	if !decorate {
		stripAnomalyAnalysis(out)
	}
	sanitizeAnomalyJSONTimes(out)
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

// stripAnomalyAnalysis keeps the issue-register response limited to observed
// conditions and retained evidence. Cause diagnoses remain available through
// the explicit domain-diagnosis endpoint, but are not built into this list.
func stripAnomalyAnalysis(items []models.Anomaly) {
	for index := range items {
		item := &items[index]
		item.EvidenceClass = anomalyEvidenceClass(*item)
		item.Evidence = observedAnomalyEvidence(item.Evidence)
		item.ConfirmedEvidence = observedAnomalyEvidence(item.ConfirmedEvidence)
		if len(item.Evidence) == 0 && len(item.ConfirmedEvidence) > 0 {
			item.Evidence = append([]string(nil), item.ConfirmedEvidence...)
		}
		item.Reason = ""
		item.CauseClassification = ""
		item.ConfirmedReason = ""
		item.InferredReason = ""
		item.InferredEvidence = nil
		item.EvidenceScope = ""
		item.EvidenceStatus = ""
		if strings.Contains(strings.ToLower(item.EvidencePendingReason), "summary index") {
			item.EvidencePendingReason = "Additional longitudinal endpoint evidence is not included in this summary."
		}
		item.Diagnosis = nil
		item.FindingClass = ""
	}
}

// anomalyEvidenceClass translates the internal issue-register decision into a
// small public classification. The frontend uses this to distinguish a
// directly demonstrated condition from a retained candidate whose evidence is
// still accumulating; no causal diagnosis is exposed here.
func anomalyEvidenceClass(item models.Anomaly) string {
	switch item.FindingClass {
	case models.FindingIncident:
		return "deterministic"
	case models.FindingInsufficient:
		return "speculative"
	}
	switch item.Type {
	case "revoked", "expired_served", "expired_observed", "hostname_mismatch", "expired_endpoint", "local_chain_validation_failed", "not_yet_valid", "ari_emergency":
		return "deterministic"
	default:
		return "speculative"
	}
}

func classifySummaryFindings(items []models.Anomaly) {
	for index := range items {
		item := &items[index]
		switch item.Type {
		case models.ObsDeploymentFailure:
			// A mixed-leaf row is deterministic when one of its retained
			// endpoint probes directly recorded a certificate defect. This is
			// stronger than the generic "mixed fingerprints" candidate gate:
			// the probe contains the queried name, the returned leaf and the
			// failed hostname/validity/chain check.
			if hasDirectEndpointDefectEvidence(item.Evidence) || hasDirectEndpointDefectEvidence(item.ConfirmedEvidence) {
				item.FindingClass = models.FindingIncident
				continue
			}
			// Repeated mixed-endpoint observations with retained endpoint probes
			// are useful candidates, but do not by themselves prove a rollout
			// defect. Keep them as speculative until the detail view establishes
			// endpoint structure and continuity.
			if item.OccurrenceCount >= 2 && hasAnomalyEvidence(item.Evidence, "endpoint_probes=") {
				item.FindingClass = models.FindingInsufficient
			}
		case models.ObsStaleAfterChange:
			// A DNS set change alone is not stale certificate evidence. Repeated
			// observations with retained endpoint probes are enough to keep a
			// candidate, while an explicit retired/current endpoint comparison
			// upgrades it to a deterministic finding.
			if item.OccurrenceCount >= 2 && hasAnomalyEvidence(item.Evidence, "endpoint_probes=") {
				if hasAnomalyEvidence(item.Evidence, "endpoint_comparison=different_endpoint") {
					item.FindingClass = models.FindingIncident
				} else {
					item.FindingClass = models.FindingInsufficient
				}
			}
		case models.ObsSameKey:
			if item.OccurrenceCount < 2 {
				continue
			}
			previous := anomalyEvidenceValue(item.Evidence, "previous_fingerprint=")
			current := anomalyEvidenceValue(item.Evidence, "new_fingerprint=")
			if previous == "" || current == "" || previous == current {
				// A same-key detector row with an unchanged leaf is not a
				// certificate replacement and must not enter the register.
				continue
			}
			if hasAnomalyEvidence(item.Evidence, "endpoint_comparison=same_endpoint") {
				item.FindingClass = models.FindingIncident
			} else if hasAnomalyEvidence(item.Evidence, "endpoint_comparison=") {
				item.FindingClass = models.FindingInsufficient
			}
		case "frequent_change", "early_renewal":
			if item.OccurrenceCount >= 2 && !hasAnomalyEvidence(item.Evidence, "replacement_pool_shape=true") {
				if anomalyEvidenceInt(item.Evidence, "distinct_replacement_leaves=") >= 3 {
					// Multiple distinct leaves repeatedly replaced at the same
					// observed endpoint establish the reported churn phenomenon.
					item.FindingClass = models.FindingIncident
				} else {
					item.FindingClass = models.FindingInsufficient
				}
			}
		}
	}
}

// hasDirectEndpointDefectEvidence identifies evidence that the TLS probe itself
// rejected a certificate for the requested name or validity/chain rules. It is
// intentionally based on recorded probe output rather than a diagnosis label,
// so the summary endpoint can preserve a deterministic classification without
// exposing causal analysis.
func hasDirectEndpointDefectEvidence(values []string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, "defective_endpoints=") && strings.TrimSpace(strings.TrimPrefix(value, "defective_endpoints=")) != "" {
			return true
		}
		if !strings.HasPrefix(value, "endpoint_probes=") {
			continue
		}
		var probes []struct {
			models.EndpointProbe
			CoversRequestedName *bool `json:"covers_requested_name"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(value, "endpoint_probes=")), &probes); err != nil {
			continue
		}
		for _, probe := range probes {
			if !probe.Success || probe.Unobservable || probe.Fingerprint == "" {
				continue
			}
			// Only the primary handshake demonstrates what the requested name
			// received. Failed probes and no-SNI controls also carry false
			// hostname checks, but do not prove a defect in that handshake.
			if probe.CoversRequestedName != nil && !*probe.CoversRequestedName {
				return true
			}
			for _, finding := range probe.Findings {
				if _, defective := defectiveFindingCodes[finding.Code]; defective {
					return true
				}
			}
		}
	}
	return false
}

func hasAnomalyEvidence(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func anomalyEvidenceValue(values []string, prefix string) string {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(value, prefix))
		}
	}
	return ""
}

func anomalyEvidenceInt(values []string, prefix string) int {
	value := anomalyEvidenceValue(values, prefix)
	parsed, _ := strconv.Atoi(value)
	return parsed
}

func observedAnomalyEvidence(values []string) []string {
	filtered := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		lower := strings.ToLower(value)
		if value == "" || strings.Contains(lower, "inference=") || strings.Contains(lower, "inferred") {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		filtered = append(filtered, value)
	}
	return filtered
}

// GetAnomaliesPage keeps the issue-register set behind the database boundary
// and applies type/domain filtering and pagination after raw observation
// collection. Suppressed service names are already omitted by GetAnomalies.
// The old limit-only API silently discarded everything after its cap, which
// made the UI unable to distinguish "no more findings" from "not returned".
func (d *Database) GetAnomaliesPage(page, perPage int, typeFilter, domainFilter string) ([]models.Anomaly, int, error) {
	all, err := d.cachedAnomalySummary()
	if err != nil {
		return nil, 0, err
	}
	filtered := make([]models.Anomaly, 0, len(all))
	for _, item := range all {
		if typeFilter != "" && item.Type != typeFilter {
			continue
		}
		if domainFilter != "" && item.Domain != domainFilter {
			continue
		}
		filtered = append(filtered, item)
	}
	total := len(filtered)
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 100
	}
	start := (page - 1) * perPage
	if start >= total {
		return []models.Anomaly{}, total, nil
	}
	end := start + perPage
	if end > total {
		end = total
	}
	return append([]models.Anomaly(nil), filtered[start:end]...), total, nil
}

// GetAnomaliesSummaryPage serves the issue-register index as compact observed
// findings and retained evidence. It never embeds the domain diagnosis object.
func (d *Database) GetAnomaliesSummaryPage(page, perPage int, typeFilter, domainFilter string) ([]models.Anomaly, int, error) {
	all, err := d.cachedAnomalySummary()
	if err != nil {
		return nil, 0, err
	}
	filtered := make([]models.Anomaly, 0, len(all))
	for _, item := range all {
		if typeFilter != "" && item.Type != typeFilter {
			continue
		}
		if domainFilter != "" && item.Domain != domainFilter {
			continue
		}
		filtered = append(filtered, item)
	}
	total := len(filtered)
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 100
	}
	start := (page - 1) * perPage
	if start >= total {
		return []models.Anomaly{}, total, nil
	}
	end := start + perPage
	if end > total {
		end = total
	}
	return append([]models.Anomaly(nil), filtered[start:end]...), total, nil
}

func (d *Database) cachedAnomalySummary() ([]models.Anomaly, error) {
	d.anomalyCacheMu.Lock()
	defer d.anomalyCacheMu.Unlock()
	now := time.Now()
	if d.anomalySummaryCache != nil && now.Sub(d.anomalySummaryCacheAt) < anomalyCacheTTL {
		if d.anomalySummaryInvalidatedAt.IsZero() || now.Sub(d.anomalySummaryInvalidatedAt) < anomalySummaryRefreshCooldown {
			return d.anomalySummaryCache, nil
		}
	}
	all, err := d.getAnomalies(0, false)
	if err != nil {
		return nil, err
	}
	d.anomalySummaryCache = append([]models.Anomaly(nil), all...)
	d.anomalySummaryCacheAt = time.Now()
	d.anomalySummaryInvalidatedAt = time.Time{}
	return d.anomalySummaryCache, nil
}

func (d *Database) invalidateAnomalyCache() {
	d.anomalyCacheMu.Lock()
	// Measurements can complete in a burst. Mark the summary stale once and
	// rebuild at most every 30 seconds; this bounds issue-register lag while
	// keeping concurrent page requests on one coherent snapshot.
	if d.anomalySummaryCache != nil && d.anomalySummaryInvalidatedAt.IsZero() {
		d.anomalySummaryInvalidatedAt = time.Now()
	}
	d.anomalyCacheMu.Unlock()
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
	// Keep the full scan history in PostgreSQL. Loading every matching ScanJob
	// into Go made an anomaly-page cache miss transfer and allocate hundreds of
	// thousands of rows even though the page only needs per-domain counts.
	type scanAggregateRow struct {
		Domain          string       `gorm:"column:domain"`
		ScanCount       int          `gorm:"column:scan_count"`
		Total           int64        `gorm:"column:total"`
		Successful      int64        `gorm:"column:successful"`
		Failed          int64        `gorm:"column:failed"`
		ExpiredServed   int64        `gorm:"column:expired_served"`
		ExpiringSoon    int64        `gorm:"column:expiring_soon"`
		Revoked         int64        `gorm:"column:revoked"`
		FirstObservedAt sql.NullTime `gorm:"column:first_observed_at"`
		LastObservedAt  sql.NullTime `gorm:"column:last_observed_at"`
	}
	const observedAt = `CASE
		WHEN sj.finished_at IS NOT NULL THEN sj.finished_at
		WHEN sj.started_at IS NOT NULL THEN sj.started_at
		ELSE sj.created_at
	END`
	var rows []scanAggregateRow
	if err := d.db.Table("domain_certificates AS dc").
		Joins("LEFT JOIN scan_jobs AS sj ON sj.domain = dc.domain").
		Joins("LEFT JOIN certificates AS c ON c.id = dc.current_certificate_id").
		Select(`dc.domain AS domain,
			dc.scan_count AS scan_count,
			COUNT(sj.id) AS total,
			COALESCE(SUM(CASE WHEN sj.success THEN 1 ELSE 0 END), 0) AS successful,
			COALESCE(SUM(CASE WHEN sj.status = ? THEN 1 ELSE 0 END), 0) AS failed,
			MIN(CASE WHEN sj.id IS NOT NULL THEN COALESCE(sj.started_at, sj.created_at) END) AS first_observed_at,
			MAX(CASE WHEN sj.id IS NOT NULL THEN COALESCE(sj.finished_at, sj.started_at, sj.created_at) END) AS last_observed_at,
			COALESCE(SUM(CASE WHEN sj.success AND sj.fingerprint <> '' AND sj.fingerprint = dc.current_fingerprint AND c.not_after < `+observedAt+` THEN 1 ELSE 0 END), 0) AS expired_served,
			COALESCE(SUM(CASE WHEN sj.success AND sj.fingerprint <> '' AND sj.fingerprint = dc.current_fingerprint AND c.not_after > `+observedAt+` AND c.not_after <= `+observedAt+` + INTERVAL '168 hours' THEN 1 ELSE 0 END), 0) AS expiring_soon,
			COALESCE(SUM(CASE WHEN sj.success AND sj.fingerprint <> '' AND sj.fingerprint = dc.current_fingerprint AND LOWER(sj.revocation_status) = LOWER(?) THEN 1 ELSE 0 END), 0) AS revoked`, models.ScanJobFailed, models.RevocationRevoked).
		Where("dc.domain IN ? AND (dc.tranco_rank BETWEEN 1 AND 10000 OR dc.local_list_member = TRUE)", domains).
		Group("dc.domain, dc.scan_count, dc.current_fingerprint, c.not_after").
		Scan(&rows).Error; err != nil {
		return err
	}
	coverage := make(map[string]monitoringEvidence, len(rows))
	scanCounts := make(map[string]int, len(rows))
	persistentOccurrences := make(map[string]map[string]int, len(rows))
	failedOccurrences := make(map[string]int, len(rows))
	for _, row := range rows {
		evidence := monitoringEvidence{total: row.Total, successful: row.Successful, failed: row.Total - row.Successful}
		if row.FirstObservedAt.Valid {
			evidence.first = row.FirstObservedAt.Time
		}
		if row.LastObservedAt.Valid {
			evidence.last = row.LastObservedAt.Time
		}
		coverage[row.Domain] = evidence
		scanCounts[row.Domain] = row.ScanCount
		failedOccurrences[row.Domain] = int(row.Failed)
		persistentOccurrences[row.Domain] = map[string]int{
			"expired_served": int(row.ExpiredServed),
			"expiring_soon":  int(row.ExpiringSoon),
			"revoked":        int(row.Revoked),
		}
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

// criticalDomainStatuses keeps a confirmed certificate incident visible while
// the scheduler is retrying the endpoint. Unreachable is a measurement state,
// not proof that the previously observed critical condition disappeared.
func criticalDomainStatuses() []string {
	return []string{models.StatusActive, models.StatusUnreachable}
}

// decorateDiagnoses builds a ranked mechanism assessment from the retained
// longitudinal evidence. The assessment intentionally separates direct facts
// from the best-supported explanation: public measurements can identify a
// mechanism class, but cannot observe an operator's private intent.
func (d *Database) decorateDiagnoses(items []models.Anomaly) error {
	if len(items) == 0 {
		return nil
	}
	// Most issue-register rows are direct certificate conditions (for example
	// an expired or revoked leaf) and do not need the endpoint-divergence
	// investigation below. Running the longitudinal snapshot/observation join
	// for every one of those rows turned a paginated index request into a
	// multi-minute query on a large monitoring population. Diagnose only the
	// lifecycle findings whose issue-register classification depends on that
	// evidence, then merge the enriched rows back into the complete finding
	// list. The detail endpoint can still build a full diagnosis on demand.
	if subset := anomalyDiagnosisSubset(items); len(subset) < len(items) {
		if len(subset) == 0 {
			return nil
		}
		if err := d.decorateDiagnoses(subset); err != nil {
			return err
		}
		byKey := make(map[string]models.Anomaly, len(subset))
		for _, item := range subset {
			byKey[anomalyDiagnosisKey(item)] = item
		}
		for index := range items {
			if enriched, ok := byKey[anomalyDiagnosisKey(items[index])]; ok {
				items[index] = enriched
			}
		}
		return nil
	}
	domains := make([]string, 0)
	seen := make(map[string]struct{})
	for _, item := range items {
		if _, ok := seen[item.Domain]; ok || item.Domain == "" {
			continue
		}
		seen[item.Domain] = struct{}{}
		domains = append(domains, item.Domain)
	}
	if len(domains) == 0 {
		return nil
	}
	var states []models.DomainCertificate
	if err := d.db.Preload("CurrentCertificate").Where("domain IN ? AND "+monitoredPredicate, domains).Find(&states).Error; err != nil {
		return err
	}
	stateByDomain := make(map[string]models.DomainCertificate, len(states))
	for _, state := range states {
		stateByDomain[state.Domain] = state
	}
	// The window function keeps the query bounded per domain even when the
	// monitor has been running for months.
	var snapshots []models.MeasurementSnapshot
	if err := d.db.Raw(`SELECT id, domain, observed_at, trigger,
 certificate_fingerprint, spki_fingerprint, topology_hash,
 resolver_quorum, resolver_agreement, endpoint_count,
 successful_endpoint_count, fingerprint_count, topology_json,
 endpoint_fingerprints_json, endpoint_probes_json, caa_json, ct_json, http_json, directory_json, related_names_json, errors_json,
 created_at FROM (SELECT ms.*, ROW_NUMBER() OVER (PARTITION BY domain ORDER BY observed_at DESC, id DESC) AS rn
	 FROM measurement_snapshots ms WHERE ms.domain IN ? AND ms.domain IN (SELECT domain FROM domain_certificates WHERE `+monitoredPredicate+`)) ranked WHERE rn <= 120`, domains).Scan(&snapshots).Error; err != nil {
		// A pre-migration database may not yet have the optional table. The
		// lifecycle finding remains valid; expose an explicit incomplete diagnosis.
		if !strings.Contains(strings.ToLower(err.Error()), "measurement_snapshots") {
			return err
		}
	}
	snapshotsByDomain := make(map[string][]models.MeasurementSnapshot)
	for _, snapshot := range snapshots {
		snapshotsByDomain[snapshot.Domain] = append(snapshotsByDomain[snapshot.Domain], snapshot)
	}
	var observations []models.CertObservation
	if err := d.db.Where("domain IN ? AND "+monitoredDomainSubquery+" AND observation_type IN ?", domains, []string{models.ObsChange, models.ObsSameKey, models.ObsStaleAfterChange, models.ObsDeploymentFailure, models.ObsResidual, models.ObsARIWindow, models.ObsARIEmergency}).Order("observed_at DESC, id DESC").Find(&observations).Error; err != nil {
		return err
	}
	observationsByDomain := make(map[string][]models.CertObservation)
	fingerprints := make(map[string]struct{})
	for _, observation := range observations {
		observationsByDomain[observation.Domain] = append(observationsByDomain[observation.Domain], observation)
		if observation.Fingerprint != "" {
			fingerprints[observation.Fingerprint] = struct{}{}
		}
		if observation.PreviousFingerprint != "" {
			fingerprints[observation.PreviousFingerprint] = struct{}{}
		}
	}
	for _, fingerprint := range collectTLSFindingFingerprints(states) {
		fingerprints[fingerprint] = struct{}{}
	}
	for _, state := range states {
		if state.ResidualFingerprint != "" {
			fingerprints[state.ResidualFingerprint] = struct{}{}
		}
	}
	var internalEvidence []models.InternalEvidenceEvent
	if err := d.db.Where("domain IN ? AND "+monitoredDomainSubquery, domains).Order("occurred_at ASC, id ASC").Find(&internalEvidence).Error; err != nil {
		// Keep the anomaly index usable while a database is being upgraded from
		// a schema that predates imported control-plane evidence.
		if !strings.Contains(strings.ToLower(err.Error()), "internal_evidence_events") {
			return err
		}
	}
	internalByDomain := make(map[string][]models.InternalEvidenceEvent)
	for _, event := range internalEvidence {
		internalByDomain[event.Domain] = append(internalByDomain[event.Domain], event)
	}
	certByFingerprint := make(map[string]models.Certificate)
	if len(fingerprints) > 0 {
		values := make([]string, 0, len(fingerprints))
		for fingerprint := range fingerprints {
			values = append(values, fingerprint)
		}
		var certs []models.Certificate
		if err := d.db.Where("fingerprint IN ?", values).Find(&certs).Error; err != nil {
			return err
		}
		for _, cert := range certs {
			certByFingerprint[cert.Fingerprint] = cert
		}
	}
	for index := range items {
		state, hasState := stateByDomain[items[index].Domain]
		context := diagnosisContext{
			state:            nil,
			snapshots:        snapshotsByDomain[items[index].Domain],
			observations:     observationsByDomain[items[index].Domain],
			certificates:     certByFingerprint,
			internalEvidence: internalByDomain[items[index].Domain],
		}
		if hasState {
			context.state = &state
		}
		diagnosis := inferDiagnosis(items[index], context)
		applyInternalEvidence(&diagnosis, SummarizeInternalEvidenceForContext(context.internalEvidence, items[index].Type, certSlice(context.certificates), context.observations, context.snapshots))
		attachInvestigation(items[index], context, &diagnosis)
		items[index].Diagnosis = &diagnosis
		applyDiagnosisToFinding(&items[index], &diagnosis)
	}
	return nil
}

func anomalyDiagnosisSubset(items []models.Anomaly) []models.Anomaly {
	result := make([]models.Anomaly, 0, len(items))
	for _, item := range items {
		switch item.Type {
		case models.ObsDeploymentFailure, models.ObsStaleAfterChange, "frequent_change", "same_key", "early_renewal":
			result = append(result, item)
		}
	}
	return result
}

func anomalyDiagnosisKey(item models.Anomaly) string {
	return item.Domain + "\x00" + item.Type
}

// applyDiagnosisToFinding lets the discriminating analysis change the finding it
// explains. Leaving the two decoupled is what allowed a finding to be presented
// as a warning while its own diagnosis said the arrangement was deliberate and
// working as designed; a reader then has to overrule the severity by hand, and a
// count of warnings means nothing.
func applyDiagnosisToFinding(item *models.Anomaly, diagnosis *models.CauseDiagnosis) {
	if item == nil || diagnosis == nil {
		return
	}
	item.FindingClass = findingClassOf(*diagnosis)
	// The raw change-row count includes pool sampling and one renewal reaching
	// several addresses; count the distinct successors actually proven.
	if item.Type == "frequent_change" && diagnosis.ChurnShape != nil {
		item.OccurrenceCount = diagnosis.ChurnShape.ProvenSuccessors
	}
	if diagnosis.Investigation != nil && diagnosis.Investigation.FindingClass != "" {
		item.FindingClass = diagnosis.Investigation.FindingClass
	}
	if diagnosis.Investigation != nil {
		if diagnosis.Investigation.Problem != "" {
			item.Description = diagnosis.Investigation.Problem
		}
		if diagnosis.Investigation.Cause != "" {
			item.Reason = diagnosis.Investigation.Cause
			if item.CauseClassification == "confirmed" {
				item.ConfirmedReason = diagnosis.Investigation.Cause
			} else {
				item.InferredReason = diagnosis.Investigation.Cause
			}
		}
		if len(diagnosis.Investigation.Facts) > 0 {
			item.Evidence = append([]string{}, diagnosis.Investigation.Facts...)
			if item.CauseClassification == "confirmed" {
				item.ConfirmedEvidence = append([]string{}, diagnosis.Investigation.Facts...)
			} else {
				item.InferredEvidence = append([]string{}, diagnosis.Investigation.Facts...)
			}
		}
	}
	if diagnosis.BenignExplanation == "" {
		return
	}
	// Withdraw the problem claim. GetAnomalies then drops expected rows from
	// the issue register; domain diagnosis APIs still expose the write-up.
	item.Severity = "info"
	item.Reason = diagnosis.BenignExplanation + " " + item.Reason
	if item.CauseClassification == "confirmed" {
		item.ConfirmedReason = diagnosis.BenignExplanation + " " + item.ConfirmedReason
	} else {
		item.InferredReason = diagnosis.BenignExplanation + " " + item.InferredReason
	}
	marker := "diagnosis=" + diagnosis.PrimaryCode
	item.Evidence = append(item.Evidence, marker, "expected_deployment_property=true")
	if item.CauseClassification == "confirmed" {
		item.ConfirmedEvidence = append(item.ConfirmedEvidence, marker, "expected_deployment_property=true")
	} else {
		item.InferredEvidence = append(item.InferredEvidence, marker, "expected_deployment_property=true")
	}
}

type diagnosisContext struct {
	state            *models.DomainCertificate
	snapshots        []models.MeasurementSnapshot
	observations     []models.CertObservation
	certificates     map[string]models.Certificate
	internalEvidence []models.InternalEvidenceEvent
}

// buildEvidenceCase materializes the retained rounds behind a diagnosis. It
// deliberately preserves what was unknown: an address absent from the DNS
// consensus is not promoted to an active endpoint merely because it answered a
// direct probe, and missing topology JSON remains a missing-evidence condition.
func buildEvidenceCase(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis) *models.EvidenceCase {
	return buildEvidenceCaseWithLimit(item, context, diagnosis, 24)
}

func buildCompactEvidenceCase(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis) *models.EvidenceCase {
	return buildEvidenceCaseWithLimit(item, context, diagnosis, 0)
}

func buildEvidenceCaseWithLimit(item models.Anomaly, context diagnosisContext, diagnosis models.CauseDiagnosis, maxRounds int) *models.EvidenceCase {
	caseFile := &models.EvidenceCase{
		Domain:             item.Domain,
		AnomalyType:        item.Type,
		Status:             "insufficient",
		GeneratedAt:        time.Now().UTC(),
		ConfidenceCeiling:  "low",
		Rounds:             make([]models.EvidenceRound, 0, minInt(len(context.snapshots), maxRounds)),
		SupportingEvidence: []string{},
		Contradictions:     []string{},
		MissingEvidence:    []string{},
		ReversalConditions: []string{},
	}
	if diagnosis.Corroboration != nil {
		caseFile.ConfidenceCeiling = diagnosis.Corroboration.ConfidenceCeiling
	}

	latestProbes := currentEndpointSurvey(context)
	probeByIP := make(map[string]models.EndpointProbe, len(latestProbes))
	for _, probe := range latestProbes {
		if probe.IPAddress != "" {
			probeByIP[probe.IPAddress] = probe
		}
	}
	for index, snapshot := range context.snapshots {
		if index >= maxRounds {
			break
		}
		assignment := snapshotEndpointMap(snapshot)
		active, activeKnown := snapshotActiveIPsFor(snapshot)
		round := models.EvidenceRound{
			ObservedAt:        snapshot.ObservedAt,
			Trigger:           snapshot.Trigger,
			ResolverQuorum:    snapshot.ResolverQuorum,
			ResolverAgreement: snapshot.ResolverAgreement,
			ConsensusIPs:      sortedEvidenceSet(active),
			Endpoints:         make([]models.EvidenceEndpoint, 0, len(assignment)),
		}
		if activeKnown && len(active) > 0 {
			answered := 0
			for address := range active {
				if _, ok := assignment[address]; ok {
					answered++
				}
			}
			round.EndpointCoverage = roundEvidence(float64(answered) / float64(len(active)))
		} else if snapshot.EndpointCount > 0 {
			round.EndpointCoverage = roundEvidence(float64(snapshot.SuccessfulEndpointCount) / float64(snapshot.EndpointCount))
		}
		if index > 0 {
			previous := context.snapshots[index-1]
			round.TopologyChanged = snapshot.TopologyHash != "" && previous.TopologyHash != "" && snapshot.TopologyHash != previous.TopologyHash
		}
		for address, fingerprint := range assignment {
			endpoint := models.EvidenceEndpoint{
				IPAddress:     address,
				ProviderGroup: providerGroup(address),
				Fingerprint:   fingerprint,
				Success:       fingerprint != "",
				ActiveDNS:     activeKnown && hasEvidenceAddress(active, address),
			}
			// EndpointProbe metadata is retained for the latest lifecycle survey;
			// never copy it into older rounds or overwrite their historical leaf.
			if index == 0 {
				if probe, ok := probeByIP[address]; ok {
					endpoint.Success = probe.Success
					endpoint.Fingerprint = fingerprint
					endpoint.RequestedSNI = probe.RequestedSNI
					endpoint.SPKIFingerprint = probe.SPKIFingerprint
					endpoint.IssuerCN = probe.IssuerCN
					endpoint.KeyAlgorithm = probe.KeyAlgorithm
					endpoint.SANsHash = probe.SANsHash
					endpoint.Error = probe.Error
					if probe.SelectionAnalysis != nil {
						endpoint.DefaultFingerprint = probe.SelectionAnalysis.DefaultFingerprint
						endpoint.SelectionInterpretation = probe.SelectionAnalysis.Interpretation
					}
				}
			}
			round.Endpoints = append(round.Endpoints, endpoint)
		}
		sort.Slice(round.Endpoints, func(left, right int) bool { return round.Endpoints[left].IPAddress < round.Endpoints[right].IPAddress })
		caseFile.Rounds = append(caseFile.Rounds, round)
	}
	if maxRounds > 0 && len(caseFile.Rounds) == 0 && len(latestProbes) > 0 {
		round := models.EvidenceRound{ObservedAt: latestObservedAt(context.observations, nil), Trigger: "endpoint_survey", EndpointCoverage: 1}
		for _, probe := range latestProbes {
			endpoint := models.EvidenceEndpoint{
				IPAddress: probe.IPAddress, ProviderGroup: providerGroup(probe.IPAddress), Fingerprint: probe.Fingerprint,
				RequestedSNI: probe.RequestedSNI, SPKIFingerprint: probe.SPKIFingerprint, IssuerCN: probe.IssuerCN, KeyAlgorithm: probe.KeyAlgorithm,
				SANsHash: probe.SANsHash, Success: probe.Success, ActiveDNS: false, Error: probe.Error,
			}
			if probe.SelectionAnalysis != nil {
				endpoint.DefaultFingerprint = probe.SelectionAnalysis.DefaultFingerprint
				endpoint.SelectionInterpretation = probe.SelectionAnalysis.Interpretation
			}
			round.Endpoints = append(round.Endpoints, endpoint)
		}
		caseFile.Rounds = append(caseFile.Rounds, round)
	}

	caseFile.SupportingEvidence = append(caseFile.SupportingEvidence, investigationFacts(item, context, diagnosis)...)
	if diagnosis.Divergence != nil {
		caseFile.MissingEvidence = append(caseFile.MissingEvidence, diagnosis.Divergence.MissingEvidence...)
		caseFile.ReversalConditions = append(caseFile.ReversalConditions, diagnosis.Divergence.ReversalConditions...)
	}
	if len(diagnosis.Hypotheses) > 1 {
		for _, hypothesis := range diagnosis.Hypotheses[1:] {
			if len(caseFile.Contradictions) >= 3 {
				break
			}
			reason := ruledOutReason(hypothesis)
			if reason == "" {
				continue
			}
			caseFile.Contradictions = append(caseFile.Contradictions, "Not "+strings.ToLower(hypothesis.Label)+": "+reason)
		}
	}
	caseFile.MissingEvidence = append(caseFile.MissingEvidence, diagnosis.MeasurementPlan...)
	if len(caseFile.Rounds) == 0 {
		caseFile.MissingEvidence = append(caseFile.MissingEvidence, "no retained measurement round contains endpoint and DNS evidence")
	}
	if len(caseFile.ReversalConditions) == 0 {
		caseFile.ReversalConditions = append(caseFile.ReversalConditions, "a later independent round that changes the endpoint-to-certificate assignment")
	}
	caseFile.SupportingEvidence = uniqueEvidenceStrings(caseFile.SupportingEvidence)
	caseFile.Contradictions = uniqueEvidenceStrings(caseFile.Contradictions)
	caseFile.MissingEvidence = uniqueEvidenceStrings(caseFile.MissingEvidence)
	caseFile.ReversalConditions = uniqueEvidenceStrings(caseFile.ReversalConditions)
	if diagnosis.BenignExplanation != "" {
		caseFile.Status = "benign"
	} else if diagnosis.Divergence != nil && diagnosis.Divergence.StrongEvidence {
		caseFile.Status = "strong"
	} else if len(caseFile.Rounds) > 0 {
		caseFile.Status = "observed"
	}
	return caseFile
}

func hasEvidenceAddress(values map[string]struct{}, address string) bool {
	_, ok := values[address]
	return ok
}

func inferDiagnosis(item models.Anomaly, context diagnosisContext) models.CauseDiagnosis {
	switch item.Type {
	case "same_key":
		return inferSameKeyDiagnosis(item, context)
	case "early_renewal":
		return inferEarlyRenewalDiagnosis(item, context)
	case "frequent_change":
		return inferChurnDiagnosis(item, context)
	case models.ObsStaleAfterChange, models.ObsDeploymentFailure:
		return inferTopologyDiagnosis(item, context)
	default:
		if isTLSValidationType(item.Type) {
			return inferTLSValidationDiagnosis(item, context)
		}
		if isCertificateConditionType(item.Type) {
			return inferCertificateConditionDiagnosis(item, context)
		}
		return inferBasicDiagnosis(item, context)
	}
}

func inferBasicDiagnosis(item models.Anomaly, context diagnosisContext) models.CauseDiagnosis {
	rounds := len(context.snapshots)
	confidence := "low"
	if rounds >= 6 {
		confidence = "medium"
	}
	summary := item.Reason
	if summary == "" || summary == "No cause detail recorded." {
		summary = "The measured condition is real at the observed vantage, but the retained evidence is insufficient to identify an operational mechanism."
	}
	return models.CauseDiagnosis{
		PrimaryCode:          "insufficient_longitudinal_evidence",
		PrimaryLabel:         "Insufficient longitudinal evidence",
		CauseStatus:          "unestablished",
		Confidence:           confidence,
		Summary:              summary,
		EvidenceCompleteness: completenessScore(rounds, len(context.observations), context.state != nil),
		Hypotheses:           []models.CauseHypothesis{},
		MeasuredRounds:       rounds,
		TransitionRounds:     len(context.observations),
		MeasurementPlan:      []string{"Collect at least three additional independent resolver and endpoint rounds before attributing an operational cause."},
	}
}

const earlyRenewalLeadDays = 30

func inferEarlyRenewalDiagnosis(item models.Anomaly, context diagnosisContext) models.CauseDiagnosis {
	pairs := collectEarlyRenewalPairs(context)
	earlySame := make([]earlyRenewalPair, 0, len(pairs))
	concurrent, unknown, shortLived := 0, 0, 0
	predRemaining := make([]int, 0, len(pairs))
	predValidity := make([]int, 0, len(pairs))
	succAge := make([]int, 0, len(pairs))
	leaves := map[string]struct{}{}
	evidence := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		leaves[pair.previousLeaf] = struct{}{}
		leaves[pair.leaf] = struct{}{}
		if pair.predecessorValidityDays > 0 {
			predValidity = append(predValidity, pair.predecessorValidityDays)
		}
		if pair.predecessorValidityDays > 0 && pair.predecessorValidityDays <= earlyRenewalLeadDays {
			shortLived++
			continue
		}
		if pair.predecessorRemainingDays <= earlyRenewalLeadDays {
			continue
		}
		evidence = append(evidence, pair.evidenceLine())
		predRemaining = append(predRemaining, pair.predecessorRemainingDays)
		if pair.successorAgeKnown {
			succAge = append(succAge, pair.successorIssuanceAgeDays)
		}
		switch {
		case pair.coexisting || pair.relation == "different_endpoint":
			concurrent++
		case pair.relation != "same_endpoint":
			unknown++
		default:
			earlySame = append(earlySame, pair)
		}
	}

	medianPredRemaining := medianInt(predRemaining)
	medianPredValidity := medianInt(predValidity)
	medianSuccAge := medianInt(succAge)
	shape := models.ChurnShape{
		ChangeEvents:           len(pairs),
		DistinctLeaves:         len(leaves),
		SameEndpointChanges:    len(earlySame),
		CrossEndpointChanges:   concurrent,
		UnknownEndpointChanges: unknown,
		CoexistenceProofs:      concurrent,
		EffectiveReplacements:  len(earlySame),
		MedianRemainingDays:    medianPredRemaining,
		MedianValidityDays:     medianPredValidity,
		MedianIssuanceAgeDays:  medianSuccAge,
	}

	switch {
	case len(earlySame) > 0:
		shape.MedianRemainingDays = medianInt(predecessorRemaining(earlySame))
		shape.MedianValidityDays = medianInt(predecessorValidity(earlySame))
		summary := fmt.Sprintf("%d same-address replacement(s) retired a predecessor that still had %d day(s) remaining of a %d-day lifetime.", len(earlySame), shape.MedianRemainingDays, maxInt(shape.MedianValidityDays, 0))
		if medianSuccAge >= 0 && len(succAge) > 0 {
			summary += fmt.Sprintf(" The successor's issuance age at observation was %d day(s).", medianSuccAge)
		}
		return models.CauseDiagnosis{
			PrimaryCode:          "early_renewal_replacement",
			PrimaryLabel:         "Predecessor replaced more than 30 days before expiry",
			CauseStatus:          "established",
			Confidence:           "high",
			Summary:              summary,
			EvidenceCompleteness: completenessScore(len(context.snapshots), len(earlySame), context.state != nil),
			Hypotheses: []models.CauseHypothesis{{
				Code:      "early_renewal_replacement",
				Label:     "Predecessor replaced more than 30 days before expiry",
				Score:     1,
				Evidence:  evidenceForPairs(earlySame),
				Rationale: fmt.Sprintf("The predecessor NotAfter minus the observation time is %d day(s), which is more than %d, and consecutive scans shared the serving address.", shape.MedianRemainingDays, earlyRenewalLeadDays),
			}},
			MeasuredRounds:   len(context.snapshots),
			TransitionRounds: len(earlySame),
			ChurnShape:       &shape,
			MeasurementPlan: []string{
				"a later same-address replacement whose predecessor remaining life is 30 days or fewer overturns this as an early replacement",
			},
		}
	case concurrent > 0 && len(earlySame) == 0 && unknown == 0:
		benign := fmt.Sprintf("Leaf fingerprints differed while a predecessor still had %d day(s) remaining, but the two leaves were observed on different addresses or in the same round, so this is concurrent deployment, not a replacement in time.", medianPredRemaining)
		return models.CauseDiagnosis{
			PrimaryCode:          "concurrent_multi_certificate_pool",
			PrimaryLabel:         "Concurrent certificates, not an early replacement",
			CauseStatus:          "established",
			Confidence:           "medium",
			Summary:              benign,
			BenignExplanation:    benign,
			EvidenceCompleteness: completenessScore(len(context.snapshots), concurrent, context.state != nil),
			MeasuredRounds:       len(context.snapshots),
			ChurnShape:           &shape,
		}
	case shortLived > 0 && len(earlySame) == 0:
		benign := fmt.Sprintf("The predecessor lifetime is %d day(s), so replacing it is the designed short-lived cadence, not an early renewal of a long-lived certificate.", medianPredValidity)
		return models.CauseDiagnosis{
			PrimaryCode:          "short_lived_certificate_automation",
			PrimaryLabel:         "Short-lived certificate cadence",
			CauseStatus:          "established",
			Confidence:           "medium",
			Summary:              benign,
			BenignExplanation:    benign,
			EvidenceCompleteness: completenessScore(len(context.snapshots), shortLived, context.state != nil),
			MeasuredRounds:       len(context.snapshots),
			ChurnShape:           &shape,
		}
	default:
		summary := "No retained same-address replacement has a predecessor NotAfter more than 30 days after the observation."
		if unknown > 0 {
			summary = fmt.Sprintf("%d leaf change(s) have a predecessor with more than 30 days remaining, but the serving address was not retained, so replacement in time is not proven.", unknown)
		}
		if medianPredRemaining > 0 && medianPredRemaining <= earlyRenewalLeadDays {
			summary = fmt.Sprintf("The predecessor remaining life at the observed leaf change is %d day(s), which is not more than 30.", medianPredRemaining)
		}
		return models.CauseDiagnosis{
			PrimaryCode:          "early_renewal_unestablished",
			PrimaryLabel:         "Early replacement not established",
			CauseStatus:          "unestablished",
			Confidence:           "low",
			Summary:              summary,
			EvidenceCompleteness: completenessScore(len(context.snapshots), len(pairs), context.state != nil),
			MeasuredRounds:       len(context.snapshots),
			ChurnShape:           &shape,
			MeasurementPlan: []string{
				"retain previous and current serving addresses on the replacement row",
				"retain the predecessor NotAfter so remaining life can be computed at observation time",
			},
		}
	}
}

type earlyRenewalPair struct {
	observedAt               time.Time
	previousLeaf             string
	leaf                     string
	ipAddress                string
	previousIP               string
	relation                 string
	coexisting               bool
	predecessorRemainingDays int
	predecessorValidityDays  int
	predecessorNotAfter      time.Time
	successorIssuanceAgeDays int
	successorAgeKnown        bool
	successorRemainingDays   int
}

func (pair earlyRenewalPair) evidenceLine() string {
	line := fmt.Sprintf("%s leaf %s → %s; predecessor remaining life %d day(s) (not_after=%s)",
		pair.observedAt.UTC().Format(time.RFC3339),
		shortProofFP(pair.previousLeaf),
		shortProofFP(pair.leaf),
		pair.predecessorRemainingDays,
		pair.predecessorNotAfter.UTC().Format(time.RFC3339),
	)
	if pair.predecessorValidityDays > 0 {
		line += fmt.Sprintf("; predecessor lifetime %d day(s)", pair.predecessorValidityDays)
	}
	switch {
	case pair.ipAddress != "" && pair.relation == "same_endpoint":
		line += "; same address " + pair.ipAddress
	case pair.ipAddress != "" && pair.previousIP != "" && pair.relation == "different_endpoint":
		line += "; addresses " + pair.previousIP + " → " + pair.ipAddress
	case pair.ipAddress != "":
		line += "; serving address " + pair.ipAddress + " (previous address not retained)"
	default:
		line += "; serving address not retained"
	}
	if pair.successorAgeKnown {
		line += fmt.Sprintf("; successor issuance age %d day(s)", pair.successorIssuanceAgeDays)
	}
	if pair.successorRemainingDays > 0 {
		line += fmt.Sprintf("; successor remaining life %d day(s)", pair.successorRemainingDays)
	}
	return line
}

func collectEarlyRenewalPairs(context diagnosisContext) []earlyRenewalPair {
	changes := make([]models.CertObservation, 0)
	for _, observation := range context.observations {
		if observation.ObservationType == models.ObsChange {
			changes = append(changes, observation)
		}
	}
	sort.SliceStable(changes, func(left, right int) bool {
		return changes[left].ObservedAt.Before(changes[right].ObservedAt)
	})
	recoverChangeEndpoints(changes, context.snapshots)
	pairs := make([]earlyRenewalPair, 0, len(changes))
	for index, change := range changes {
		if change.Fingerprint == "" || change.PreviousFingerprint == "" || change.Fingerprint == change.PreviousFingerprint {
			continue
		}
		previous, ok := context.certificates[change.PreviousFingerprint]
		if !ok || previous.NotAfter.IsZero() || change.ObservedAt.IsZero() {
			continue
		}
		if !jsonableTime(previous.NotAfter) || !jsonableTime(change.ObservedAt) {
			continue
		}
		pair := earlyRenewalPair{
			observedAt:               change.ObservedAt,
			previousLeaf:             change.PreviousFingerprint,
			leaf:                     change.Fingerprint,
			ipAddress:                strings.TrimSpace(change.IPAddress),
			previousIP:               strings.TrimSpace(change.PreviousIPAddress),
			coexisting:               change.ChangeClass == models.ChangeClassCoexisting || coexistingLeaves(change),
			predecessorRemainingDays: models.DaysUntil(previous.NotAfter, change.ObservedAt),
			predecessorNotAfter:      previous.NotAfter,
		}
		if jsonableTime(previous.NotBefore) && !previous.NotBefore.IsZero() && previous.NotAfter.After(previous.NotBefore) {
			pair.predecessorValidityDays = int(previous.NotAfter.Sub(previous.NotBefore).Hours() / 24)
		}
		if current, ok := context.certificates[change.Fingerprint]; ok {
			if jsonableTime(current.NotBefore) && !current.NotBefore.IsZero() {
				pair.successorAgeKnown = true
				age := int(change.ObservedAt.Sub(current.NotBefore).Hours() / 24)
				if age < 0 {
					age = 0
				}
				pair.successorIssuanceAgeDays = age
			}
			if jsonableTime(current.NotAfter) && !current.NotAfter.IsZero() {
				pair.successorRemainingDays = models.DaysUntil(current.NotAfter, change.ObservedAt)
			}
		}
		if pair.successorRemainingDays == 0 && change.DaysUntilExpiry > 0 {
			pair.successorRemainingDays = change.DaysUntilExpiry
		}
		switch endpointRelation(changes, index) {
		case endpointSame:
			pair.relation = "same_endpoint"
			if pair.previousIP == "" && index > 0 {
				pair.previousIP = strings.TrimSpace(changes[index-1].IPAddress)
			}
		case endpointDifferent:
			pair.relation = "different_endpoint"
		default:
			pair.relation = sameKeyRelation(pair.previousIP, pair.ipAddress, change.ChangeClass)
		}
		if pair.coexisting && pair.relation == "same_endpoint" {
			pair.relation = "different_endpoint"
		}
		pairs = append(pairs, pair)
	}
	return pairs
}

func predecessorRemaining(pairs []earlyRenewalPair) []int {
	out := make([]int, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, pair.predecessorRemainingDays)
	}
	return out
}

func predecessorValidity(pairs []earlyRenewalPair) []int {
	out := make([]int, 0, len(pairs))
	for _, pair := range pairs {
		if pair.predecessorValidityDays > 0 {
			out = append(out, pair.predecessorValidityDays)
		}
	}
	return out
}

func evidenceForPairs(pairs []earlyRenewalPair) []string {
	out := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, pair.evidenceLine())
	}
	return out
}

func inferSameKeyDiagnosis(item models.Anomaly, context diagnosisContext) models.CauseDiagnosis {
	pairs := collectSameKeyPairs(context)
	if len(pairs) == 0 {
		return models.CauseDiagnosis{
			PrimaryCode:          "same_key_unestablished",
			PrimaryLabel:         "Same-key comparison not retained",
			CauseStatus:          "unestablished",
			Confidence:           "low",
			Summary:              "A same-key finding was raised, but no retained pair has both a new leaf fingerprint and a previous SPKI fingerprint.",
			EvidenceCompleteness: completenessScore(len(context.snapshots), 0, context.state != nil),
			MeasuredRounds:       len(context.snapshots),
			MeasurementPlan:      []string{"retain previous and current leaf fingerprints and SPKI fingerprints on the replacement row"},
		}
	}

	sameEndpoint, unknownEndpoint, differentEndpoint, coexisting, revisits, undated := 0, 0, 0, 0, 0, 0
	remaining := make([]int, 0, len(pairs))
	issuanceAge := make([]int, 0, len(pairs))
	leaves := map[string]struct{}{}
	spkis := map[string]struct{}{}
	evidence := make([]string, 0, len(pairs)*2)
	for _, pair := range pairs {
		leaves[pair.previousLeaf] = struct{}{}
		leaves[pair.leaf] = struct{}{}
		if pair.spki != "" {
			spkis[pair.spki] = struct{}{}
		}
		// Only a same-address change to a later-issued leaf is a replacement.
		// Two leaves at once on one address, a return, or a step to an older
		// leaf is a pool; an undated same-address change decides nothing.
		switch pair.kind {
		case changeReplacement:
			sameEndpoint++
		case changePool:
			revisits++
			differentEndpoint++
		case changeUndated:
			undated++
		case changeOtherAddr:
			differentEndpoint++
		default:
			unknownEndpoint++
		}
		if pair.coexisting {
			coexisting++
		}
		if pair.remainingDays > 0 {
			remaining = append(remaining, pair.remainingDays)
		}
		if pair.issuanceAgeDays >= 0 && pair.leafNotBeforeKnown {
			issuanceAge = append(issuanceAge, pair.issuanceAgeDays)
		}
		evidence = append(evidence, pair.evidenceLine())
	}

	medianRemaining := medianInt(remaining)
	medianAge := medianInt(issuanceAge)
	status := "inferred"
	code := "same_key_reissue"
	label := "Successor issued or deployed with the predecessor public key"
	switch {
	case (coexisting > 0 || revisits > 0) && sameEndpoint == 0:
		code = "concurrent_same_key"
		label = "Same public key on concurrently observed leaves"
		status = "inferred"
	case sameEndpoint > 0:
		status = "established"
	}

	summary := fmt.Sprintf("%d leaf change(s) kept the same public key across %d distinct leaf certificate(s) and %d distinct SPKI(s).", len(pairs), len(leaves), maxInt(len(spkis), 1))
	if sameEndpoint > 0 {
		summary += fmt.Sprintf(" %d comparison(s) were on the same serving address.", sameEndpoint)
	}
	if medianRemaining > 0 {
		summary += fmt.Sprintf(" At those replacements the successor still had %d day(s) remaining.", medianRemaining)
	}

	shape := models.ChurnShape{
		ChangeEvents:           len(pairs),
		DistinctLeaves:         len(leaves),
		DistinctSPKIs:          maxInt(len(spkis), 1),
		SameEndpointChanges:    sameEndpoint,
		CrossEndpointChanges:   differentEndpoint,
		UnknownEndpointChanges: unknownEndpoint,
		CoexistenceProofs:      coexisting,
		RevisitEvents:          revisits,
		UndatedEndpointChanges: undated,
		EffectiveReplacements:  len(pairs) - revisits,
		MedianRemainingDays:    medianRemaining,
		MedianIssuanceAgeDays:  medianAge,
	}

	return models.CauseDiagnosis{
		PrimaryCode:          code,
		PrimaryLabel:         label,
		CauseStatus:          status,
		Confidence:           sameKeyConfidence(sameEndpoint, len(pairs)),
		Summary:              summary,
		EvidenceCompleteness: completenessScore(len(context.snapshots), len(pairs), context.state != nil),
		Hypotheses: []models.CauseHypothesis{{
			Code:      code,
			Label:     label,
			Score:     1,
			Evidence:  evidence,
			Rationale: sameKeyRationale(code, sameEndpoint, medianRemaining, medianAge),
		}},
		MeasuredRounds:   len(context.snapshots),
		TransitionRounds: len(pairs),
		ChurnShape:       &shape,
		MeasurementPlan: []string{
			"a later same-address pair whose SPKI fingerprints differ overturns key reuse",
			"predecessor and successor observed together on different addresses is concurrent deployment, not replacement in time",
		},
	}
}

type sameKeyPair struct {
	observedAt         time.Time
	previousLeaf       string
	leaf               string
	spki               string
	previousSPKI       string
	ipAddress          string
	previousIP         string
	relation           string
	coexisting         bool
	remainingDays      int
	issuanceAgeDays    int
	leafNotBeforeKnown bool
	// kind is the change reading of the underlying change row (classifyChanges).
	kind string
}

func (pair sameKeyPair) evidenceLine() string {
	line := fmt.Sprintf("%s leaf %s → %s; SPKI %s → %s",
		pair.observedAt.UTC().Format(time.RFC3339),
		shortProofFP(pair.previousLeaf),
		shortProofFP(pair.leaf),
		shortProofFP(pair.previousSPKI),
		shortProofFP(pair.spki),
	)
	switch {
	case pair.ipAddress != "" && pair.relation == "same_endpoint":
		line += "; same address " + pair.ipAddress
	case pair.ipAddress != "" && pair.previousIP != "" && pair.relation == "different_endpoint":
		line += "; addresses " + pair.previousIP + " → " + pair.ipAddress
	case pair.ipAddress != "":
		line += "; serving address " + pair.ipAddress + " (previous address not retained)"
	default:
		line += "; serving address not retained"
	}
	if pair.remainingDays > 0 {
		line += fmt.Sprintf("; successor remaining life %d day(s)", pair.remainingDays)
	}
	if pair.leafNotBeforeKnown {
		line += fmt.Sprintf("; successor issuance age %d day(s)", pair.issuanceAgeDays)
	}
	return line
}

func collectSameKeyPairs(context diagnosisContext) []sameKeyPair {
	changes := make([]models.CertObservation, 0)
	sameKeyRows := make([]models.CertObservation, 0)
	for _, observation := range context.observations {
		switch observation.ObservationType {
		case models.ObsSameKey:
			sameKeyRows = append(sameKeyRows, observation)
		case models.ObsChange:
			changes = append(changes, observation)
		}
	}
	sort.SliceStable(changes, func(left, right int) bool {
		return changes[left].ObservedAt.Before(changes[right].ObservedAt)
	})
	sort.SliceStable(sameKeyRows, func(left, right int) bool {
		return sameKeyRows[left].ObservedAt.Before(sameKeyRows[right].ObservedAt)
	})
	recoverChangeEndpoints(changes, context.snapshots)
	dates := leafIssuanceDates(context.certificates, context.observations, context.snapshots)
	readings := classifyChanges(changes, dates)

	candidates := sameKeyRows
	if len(candidates) == 0 {
		for _, change := range changes {
			if sameKeySPKI(change, context) {
				candidates = append(candidates, change)
			}
		}
	}
	pairs := make([]sameKeyPair, 0, len(candidates))
	for _, row := range candidates {
		changeIndex := matchingChangeIndex(changes, row)
		source := row
		if changeIndex >= 0 {
			source = changes[changeIndex]
		}
		previousSPKI, spki := pairSPKIs(source, context)
		if previousSPKI == "" || spki == "" || previousSPKI != spki || source.Fingerprint == "" || source.PreviousFingerprint == "" || source.Fingerprint == source.PreviousFingerprint {
			continue
		}
		pair := sameKeyPair{
			observedAt:    source.ObservedAt,
			previousLeaf:  source.PreviousFingerprint,
			leaf:          source.Fingerprint,
			previousSPKI:  previousSPKI,
			spki:          spki,
			ipAddress:     firstNonEmpty(source.IPAddress, row.IPAddress),
			previousIP:    firstNonEmpty(source.PreviousIPAddress, row.PreviousIPAddress),
			coexisting:    source.ChangeClass == models.ChangeClassCoexisting || row.ChangeClass == models.ChangeClassCoexisting,
			remainingDays: source.DaysUntilExpiry,
		}
		if pair.remainingDays == 0 && row.DaysUntilExpiry > 0 {
			pair.remainingDays = row.DaysUntilExpiry
		}
		pair.kind = changeUnknownAddr
		if changeIndex >= 0 {
			pair.kind = readings[changeIndex].Kind
			switch endpointRelation(changes, changeIndex) {
			case endpointSame:
				pair.relation = "same_endpoint"
				if pair.previousIP == "" && changeIndex > 0 {
					pair.previousIP = strings.TrimSpace(changes[changeIndex-1].IPAddress)
				}
			case endpointDifferent:
				pair.relation = "different_endpoint"
			default:
				pair.relation = sameKeyRelation(pair.previousIP, pair.ipAddress, source.ChangeClass)
			}
		} else {
			pair.relation = sameKeyRelation(pair.previousIP, pair.ipAddress, source.ChangeClass)
			// No change row to read the address history from: decide the
			// same-address case by issuance order alone.
			switch pair.relation {
			case "same_endpoint":
				previousIssued, previousKnown := dates[pair.previousLeaf]
				currentIssued, currentKnown := dates[pair.leaf]
				switch {
				case previousKnown && currentKnown && currentIssued.After(previousIssued):
					pair.kind = changeReplacement
				case previousKnown && currentKnown:
					pair.kind = changePool
				default:
					pair.kind = changeUndated
				}
			case "different_endpoint":
				pair.kind = changeOtherAddr
			}
		}
		if cert, ok := context.certificates[pair.leaf]; ok && !cert.NotBefore.IsZero() && !source.ObservedAt.IsZero() {
			pair.leafNotBeforeKnown = true
			age := int(source.ObservedAt.Sub(cert.NotBefore).Hours() / 24)
			if age < 0 {
				age = 0
			}
			pair.issuanceAgeDays = age
			if pair.remainingDays == 0 && !cert.NotAfter.IsZero() && cert.NotAfter.After(source.ObservedAt) {
				pair.remainingDays = int(cert.NotAfter.Sub(source.ObservedAt).Hours() / 24)
			}
		}
		pairs = append(pairs, pair)
	}
	return pairs
}

func matchingChangeIndex(changes []models.CertObservation, row models.CertObservation) int {
	for index := range changes {
		change := changes[index]
		if change.Fingerprint == row.Fingerprint && change.PreviousFingerprint == row.PreviousFingerprint {
			if change.ObservedAt.Equal(row.ObservedAt) || change.ObservedAt.Truncate(time.Second).Equal(row.ObservedAt.Truncate(time.Second)) {
				return index
			}
		}
	}
	for index := range changes {
		change := changes[index]
		if change.Fingerprint == row.Fingerprint && change.PreviousFingerprint == row.PreviousFingerprint {
			return index
		}
	}
	return -1
}

func pairSPKIs(row models.CertObservation, context diagnosisContext) (previous, current string) {
	previous = strings.TrimSpace(row.PreviousSPKIFingerprint)
	current = strings.TrimSpace(row.SPKIFingerprint)
	if previous == "" {
		if cert, ok := context.certificates[row.PreviousFingerprint]; ok {
			previous = certificateSPKI(&cert)
		}
	}
	if current == "" {
		if cert, ok := context.certificates[row.Fingerprint]; ok {
			current = certificateSPKI(&cert)
		}
		if current == "" {
			current = strings.TrimSpace(row.SPKIFingerprint)
		}
	}
	return previous, current
}

func sameKeySPKI(row models.CertObservation, context diagnosisContext) bool {
	previous, current := pairSPKIs(row, context)
	return previous != "" && current != "" && previous == current && row.Fingerprint != "" && row.PreviousFingerprint != "" && row.Fingerprint != row.PreviousFingerprint
}

func sameKeyRelation(previousIP, ip, changeClass string) string {
	if changeClass == models.ChangeClassCoexisting {
		return "different_endpoint"
	}
	previousIP = strings.TrimSpace(previousIP)
	ip = strings.TrimSpace(ip)
	if previousIP != "" && ip != "" {
		if previousIP == ip {
			return "same_endpoint"
		}
		return "different_endpoint"
	}
	return "unknown"
}

func sameKeyConfidence(sameEndpoint, pairs int) string {
	if sameEndpoint > 0 && pairs >= 2 {
		return "high"
	}
	if sameEndpoint > 0 || pairs >= 2 {
		return "medium"
	}
	return "low"
}

func sameKeyRationale(code string, sameEndpoint, remaining, issuanceAge int) string {
	switch code {
	case "concurrent_same_key":
		return "Predecessor and successor were observed in the same round, so the shared SPKI is concurrent deployment of two leaves, not a replacement that kept the key."
	default:
		if sameEndpoint > 0 && remaining > 0 {
			return fmt.Sprintf("The same address served a new leaf with the predecessor SPKI while that successor still had %d day(s) remaining and issuance age %d day(s).", remaining, issuanceAge)
		}
		if sameEndpoint > 0 {
			return "The same address served a new leaf whose SPKI fingerprint equals the predecessor."
		}
		return "The new leaf fingerprint differs from the previous leaf while both certificates share one SPKI fingerprint. The serving address was not retained on every pair."
	}
}

func inferChurnDiagnosis(item models.Anomaly, context diagnosisContext) models.CauseDiagnosis {
	changes := make([]models.CertObservation, 0)
	for _, observation := range context.observations {
		if observation.ObservationType == models.ObsChange {
			changes = append(changes, observation)
		}
	}
	// Query order is not part of the inference contract. Sort explicitly before
	// calculating cadence so callers and tests cannot invert the intervals.
	sort.SliceStable(changes, func(left, right int) bool {
		return changes[left].ObservedAt.Before(changes[right].ObservedAt)
	})
	// A single replacement (or no replacement at all) is an observation, not
	// a longitudinal pattern. Do not let neutral/default feature values create
	// a spurious causal winner such as key rotation before there are intervals
	// to compare.
	if len(changes) < 2 {
		return insufficientChurnDiagnosis(len(changes), len(context.snapshots), context.state != nil)
	}

	// Establish what the change sequence actually demonstrates before deriving
	// anything from consecutive pairs. Every pairwise signal below compares
	// sample N with sample N-1, which only describes the deployment's history
	// when consecutive samples came from the same endpoint.
	shape := analyzeChurnShapeWithSnapshots(changes, context.certificates, context.snapshots)
	artifact := shape.Interpretation == models.ChurnSpatialMultiplexing
	window := changes[len(changes)-1].ObservedAt.Sub(changes[0].ObservedAt)
	ctCoverage, ctEntries, ctIssuances, ctStatus, ctNote := analyzeCTCorroboration(context.snapshots, shape, window)

	intervalHours, regularity := changeCadence(changes)
	nearExpiry, _ := renewalLeadSignal(changes)
	_, issuerChangeRatio, sanChangeRatio, validityChangeRatio := certificateTransitionSignals(changes, context.certificates)
	ariAlignment := ariAlignmentSignal(context.observations, changes, context.state)
	topologyChanges, endpointChanges := topologySignals(context.snapshots)
	caaCoverage, caaChanges := caaSignals(context.snapshots)
	httpCoverage, httpChanges := httpSignals(context.snapshots)
	incidentSignal := 0.0
	if item.Type == "revoked" {
		incidentSignal = 1
	}
	for _, observation := range context.observations {
		if observation.ObservationType == models.ObsARIEmergency || observation.RevocationStatus == models.RevocationRevoked {
			incidentSignal = math.Max(incidentSignal, 1)
		}
	}

	coexistScore := float64(minInt(shape.CoexistenceProofs, 3)) / 3
	revisitScore := math.Min(shape.RevisitRatio/0.5, 1)
	alternationScore := float64(minInt(shape.AlternationEvents, 5)) / 5
	crossEndpointScore := 0.0
	if shape.ChangeEvents > 0 {
		crossEndpointScore = float64(shape.CrossEndpointChanges) / float64(shape.ChangeEvents)
	}
	monotone := boolScore(shape.RevisitEvents == 0)
	shortValidity := 0.0
	switch {
	case shape.MedianValidityDays > 0 && shape.MedianValidityDays <= 14:
		shortValidity = 1
	case shape.MedianValidityDays > 0 && shape.MedianValidityDays <= 30:
		shortValidity = 0.5
	}
	inventoryAge := 0.0
	if shape.MedianValidityDays > 0 && shape.MedianIssuanceAgeDays > 0 {
		inventoryAge = clampScore(float64(shape.MedianIssuanceAgeDays) / float64(shape.MedianValidityDays))
	}
	tightRemaining := 0.0
	if shape.MedianRemainingDays > 0 && shape.MedianRemainingDays <= 14 && shape.RemainingSpreadDays <= 3 {
		tightRemaining = 1
	} else if shape.MedianRemainingDays > 0 && shape.MedianRemainingDays <= 21 && shape.RemainingSpreadDays <= 7 {
		tightRemaining = 0.6
	}
	staggeredIssuance := 0.0
	if shape.DistinctIssuanceDays >= 4 && shape.IssuanceCadenceDays > 0 && shape.IssuanceCadenceDays <= 3 {
		staggeredIssuance = 1
	} else if shape.DistinctIssuanceDays >= 3 && shape.IssuanceCadenceDays > 0 && shape.IssuanceCadenceDays <= 7 {
		staggeredIssuance = 0.6
	}
	freshIssuance := 0.0
	if shape.DistinctIssuanceDays > 0 {
		switch {
		case shape.MedianIssuanceAgeDays <= 7:
			freshIssuance = 1
		case shape.MedianIssuanceAgeDays <= 21:
			freshIssuance = 0.5
		}
	}
	stableIdentity := clampScore((shape.SameIssuerFraction + shape.SameNameFraction) / 2)
	if shape.SameIssuerFraction == 0 && shape.SameNameFraction == 0 && issuerChangeRatio == 0 {
		stableIdentity = 0.5
	}

	// Concurrent deployment is established by falsification, not by weighing
	// preferences: a leaf that reappears after being "replaced", or a round that
	// saw predecessor and successor together, is incompatible with renewal.
	pool := clampScore(0.04 + 0.42*coexistScore + 0.28*revisitScore + 0.12*alternationScore + 0.08*crossEndpointScore + 0.12*boolScore(ctStatus == models.CTContradicted))
	if artifact {
		pool = clampScore(math.Max(pool, 0.50+0.25*coexistScore+0.15*revisitScore+0.10*alternationScore))
	}
	shortLived := clampScore(0.04 + 0.42*monotone*shortValidity + 0.24*shortValidity + 0.18*regularity + 0.12*monotone)
	if shortValidity >= 0.5 && freshIssuance >= 0.5 && shape.MedianValidityDays <= 30 {
		shortLived = clampScore(math.Max(shortLived, 0.72))
	}
	// A tight remaining-life window is evidence of a scheduled replacement, not
	// a contradiction of automation. A different public key is not scored as a
	// cause: it is the default output of new issuance.
	automated := clampScore(0.08 + 0.28*regularity + 0.16*freshIssuance + 0.14*staggeredIssuance*freshIssuance + 0.12*(1-issuerChangeRatio) + 0.10*ariAlignment + 0.08*boolScore(ctStatus == models.CTCorroborated) + 0.08*tightRemaining*(1-inventoryAge) + 0.06*nearExpiry*freshIssuance)
	// Pre-issued inventory is only named when the served leaf is already old
	// and close to expiry. Daily issuance of a still-fresh 90-day certificate
	// is replacement-time automation, not a rolling stockpile.
	pipeline := 0.0
	if inventoryAge >= 0.4 && tightRemaining >= 0.6 {
		pipeline = clampScore(0.10 + 0.32*inventoryAge + 0.24*tightRemaining + 0.14*staggeredIssuance + 0.10*boolScore(shape.IssuanceMonotone) + 0.10*stableIdentity)
	}
	unresolved := shape.Interpretation == models.ChurnUndetermined ||
		(shape.SameEndpointChanges == 0 && shape.CrossEndpointChanges == 0)
	migration := clampScore(0.05 + 0.42*issuerChangeRatio + 0.18*validityChangeRatio + 0.14*sanChangeRatio + 0.11*float64(minInt(topologyChanges, 3))/3 + 0.10*caaChanges + 0.08*caaCoverage)
	deployment := clampScore(0.04 + 0.45*endpointChanges + 0.26*float64(minInt(topologyChanges, 3))/3 + 0.14*sanChangeRatio + 0.08*httpChanges + 0.05*httpCoverage)
	if freshIssuance >= 0.5 && inventoryAge < 0.4 {
		// Daily issuance of a still-fresh certificate is replacement-time
		// automation. Endpoint-map churn is then the consequence of that
		// replacement, not a separate rollout cause.
		deployment = clampScore(deployment * 0.35)
	}
	if issuerChangeRatio < 0.5 {
		migration = clampScore(migration * 0.35)
	}
	// "Incident-driven" is a causal label, not a synonym for an unexpectedly
	// early replacement.  It must have an independently retained incident
	// signal (revocation or ARI emergency); otherwise the honest result is a
	// replacement whose private trigger is not established.
	incident := 0.0
	if incidentSignal > 0 {
		incident = clampScore(0.05 + 0.82*incidentSignal + 0.13*(1-nearExpiry))
	}

	artifactNote := "Not evaluable: the change sequence is spatially multiplexed, so consecutive samples come from different servers and this pairwise signal describes the sampling, not the deployment's history."
	unattributedNote := "Not established: no serving address was retained for these comparisons, so it is unknown whether consecutive samples came from the same server."
	automatedContradictions := []string{ftoaEvidence("issuer_change_fraction", issuerChangeRatio)}
	if inventoryAge >= 0.5 && tightRemaining >= 0.6 {
		automatedContradictions = append(automatedContradictions, "The served certificates were issued weeks earlier and only a few days remain, so this is inventory being rolled forward rather than a certificate issued at replacement time.")
	}
	pipelineContradictions := []string{itoaEvidence("median_issuance_age_days", shape.MedianIssuanceAgeDays), itoaEvidence("median_remaining_days", shape.MedianRemainingDays)}
	if freshIssuance >= 0.5 && inventoryAge < 0.4 {
		pipelineContradictions = append(pipelineContradictions, "A recently issued certificate being served near replacement is the signature of issuance at replacement time, not of a pre-issued inventory.")
	}
	migrationContradictions := []string{ftoaEvidence("issuer_change_fraction", issuerChangeRatio), ftoaEvidence("same_issuer_fraction", shape.SameIssuerFraction)}
	switch {
	case artifact:
		automated = clampScore(automated * 0.40)
		pipeline = clampScore(pipeline * 0.35)
		migration = clampScore(migration * 0.60)
		automatedContradictions = append([]string{artifactNote}, automatedContradictions...)
		pipelineContradictions = append([]string{artifactNote}, pipelineContradictions...)
		migrationContradictions = append([]string{artifactNote}, migrationContradictions...)
	case unresolved:
		// Endpoint identity is missing, but issuance dates and remaining life
		// are still a shape that can be read as a best-supported inference.
		// Topology/SAN churn cannot name a rollout or CA-migration process
		// without a same-endpoint comparison.
		automated = clampScore(automated * 0.90)
		pipeline = clampScore(pipeline * 0.90)
		migration = clampScore(migration * 0.35)
		deployment = clampScore(deployment * 0.20)
		automatedContradictions = append([]string{unattributedNote}, automatedContradictions...)
		pipelineContradictions = append([]string{unattributedNote}, pipelineContradictions...)
		migrationContradictions = append([]string{unattributedNote}, migrationContradictions...)
	}
	unknownFraction := 0.0
	if shape.ChangeEvents > 0 {
		unknownFraction = float64(shape.UnknownEndpointChanges) / float64(shape.ChangeEvents)
	}
	unattributed := clampScore(0.10 + 0.55*boolScore(unresolved) + 0.25*unknownFraction)
	mechanismSupport := math.Max(math.Max(automated, pipeline), math.Max(migration, math.Max(deployment, incident)))
	if unresolved && mechanismSupport >= 0.40 {
		unattributed = clampScore(unattributed * 0.35)
	}
	unexplained := 0.0
	if !artifact && shape.Interpretation == models.ChurnTemporalReplacement && mechanismSupport < 0.45 {
		unexplained = clampScore(0.55 + 0.20*boolScore(shape.SameEndpointChanges > 0) + 0.10*monotone)
	} else if unresolved && mechanismSupport < 0.40 {
		unexplained = clampScore(0.40 + 0.15*monotone)
	}

	hypotheses := []models.CauseHypothesis{
		{Code: "concurrent_multi_certificate_pool", Label: "Concurrently deployed certificate pool", Score: pool, Confidence: scoreConfidence(pool, shape.EffectiveReplacements, len(context.snapshots)), Rationale: "Several certificates are deployed at the same time and each scan samples whichever server answered, so the change counter measures the sampling process rather than replacement in time.", Evidence: churnShapeEvidence(shape), Contradictions: []string{"A strictly monotone sequence measured from one endpoint would refute concurrent deployment."}},
		{Code: "short_lived_certificate_automation", Label: "Short-lived certificate automation", Score: shortLived, Confidence: scoreConfidence(shortLived, shape.EffectiveReplacements, len(context.snapshots)), Rationale: "Every leaf is new, never recurs, and the certificates' own validity period is short, which is the expected output of short-lived certificate issuance.", Evidence: []string{itoaEvidence("median_validity_days", shape.MedianValidityDays), itoaEvidence("revisit_events", shape.RevisitEvents), ftoaEvidence("mean_interval_hours", intervalHours), ftoaEvidence("replacements_per_validity_period", shape.ReplacementsPerValidityPeriod)}, Contradictions: []string{"A long certificate validity period would make frequent replacement unexpected rather than routine."}},
		{Code: "preissued_rolling_pipeline", Label: "Pre-issued rolling certificate pipeline", Score: pipeline, Confidence: scoreConfidence(pipeline, shape.EffectiveReplacements, len(context.snapshots)), Rationale: "Certificates are minted weeks before they are served and only pushed to the endpoint when a few days remain, so a different already-old leaf appears each day instead of one certificate finishing its lifetime.", Evidence: []string{itoaEvidence("median_issuance_age_days", shape.MedianIssuanceAgeDays), itoaEvidence("median_remaining_days", shape.MedianRemainingDays), ftoaEvidence("remaining_spread_days", shape.RemainingSpreadDays), itoaEvidence("distinct_issuance_days", shape.DistinctIssuanceDays), ftoaEvidence("issuance_cadence_days", shape.IssuanceCadenceDays), ftoaEvidence("same_issuer_fraction", shape.SameIssuerFraction), itoaEvidence("same_endpoint_changes", shape.SameEndpointChanges)}, Contradictions: pipelineContradictions},
		{Code: "automated_renewal_policy", Label: "Automated renewal at replacement time", Score: automated, Confidence: scoreConfidence(automated, shape.EffectiveReplacements, len(context.snapshots)), Rationale: "A still-fresh 90-day certificate is being re-issued at replacement time instead of being used until near expiry, so issuance is running many times per lifetime.", Evidence: []string{itoaEvidence("effective_replacements", shape.EffectiveReplacements), ftoaEvidence("mean_interval_hours", intervalHours), ftoaEvidence("cadence_cv_score", regularity), itoaEvidence("median_remaining_days", shape.MedianRemainingDays), itoaEvidence("median_issuance_age_days", shape.MedianIssuanceAgeDays), ftoaEvidence("ari_alignment", ariAlignment), "ct_status=" + ctStatus}, Contradictions: automatedContradictions},
		{Code: "ca_or_policy_migration", Label: "CA or certificate-policy migration", Score: migration, Confidence: scoreConfidence(migration, shape.EffectiveReplacements, len(context.snapshots)), Rationale: "The CA family or the certificate name changed with the replacements. On a CDN-fronted name this is usually the CDN failing over between Google Trust Services and Let's Encrypt, not the site switching vendors.", Evidence: []string{ftoaEvidence("issuer_change_fraction", issuerChangeRatio), ftoaEvidence("validity_change_fraction", validityChangeRatio), ftoaEvidence("san_change_fraction", sanChangeRatio), itoaEvidence("topology_transition_rounds", topologyChanges), ftoaEvidence("caa_coverage", caaCoverage), ftoaEvidence("caa_policy_change_fraction", caaChanges)}, Contradictions: migrationContradictions},
		{Code: "edge_or_deployment_rollout", Label: "Edge deployment or rollout process", Score: deployment, Confidence: scoreConfidence(deployment, shape.EffectiveReplacements, len(context.snapshots)), Rationale: "A retained address kept answering after its leaf changed, or successive endpoint surveys show a certificate moving across the same IPs.", Evidence: []string{ftoaEvidence("endpoint_transition_score", endpointChanges), itoaEvidence("topology_transition_rounds", topologyChanges), ftoaEvidence("http_coverage", httpCoverage), ftoaEvidence("http_edge_change_fraction", httpChanges)}, Contradictions: []string{"An address set that rotates while every overlapping IP keeps the same leaf is VIP churn, not a certificate rollout."}},
		{Code: "incident_driven_reissue", Label: "Revocation or emergency-driven reissuance", Score: incident, Confidence: scoreConfidence(incident, shape.EffectiveReplacements, len(context.snapshots)), Rationale: "A retained certificate revocation or CA emergency-renewal signal precedes or coincides with the replacement sequence. It proves the trigger signal, not its private operational cause.", Evidence: incidentTriggerEvidence(context, incidentSignal), Contradictions: []string{"No retained revocation or emergency signal."}},
		{Code: "replacement_mechanism_unestablished", Label: "Replacement in time; mechanism not established", Score: unexplained, Confidence: "low", Rationale: "Same-endpoint samples served different certificates, so these are replacements in time, but issuance dates, remaining life, issuer change and incident signals do not identify the operational process.", Evidence: []string{itoaEvidence("same_endpoint_changes", shape.SameEndpointChanges), itoaEvidence("median_remaining_days", shape.MedianRemainingDays), itoaEvidence("median_issuance_age_days", shape.MedianIssuanceAgeDays), ftoaEvidence("issuer_change_fraction", issuerChangeRatio)}, Contradictions: []string{"A tight remaining-life window with staggered older issuance dates, or a recently issued certificate at replacement time, would name the process."}},
		{Code: "endpoint_attribution_unavailable", Label: "Endpoint attribution unavailable", Score: unattributed, Confidence: "low", Rationale: "The changes are real differences between consecutive samples, but no serving address was retained for them, so whether they are replacements in time or different servers answering cannot be established.", Evidence: []string{itoaEvidence("unknown_endpoint_changes", shape.UnknownEndpointChanges), itoaEvidence("same_endpoint_changes", shape.SameEndpointChanges), itoaEvidence("cross_endpoint_changes", shape.CrossEndpointChanges), itoaEvidence("revisit_events", shape.RevisitEvents)}, Contradictions: []string{"A single same-endpoint comparison, or one round that observed two leaves at once, would resolve this."}},
	}
	// As with the endpoint structure, the discriminating test decides the primary
	// reading rather than competing with the weighted scores. A revisit or a
	// concurrent observation falsifies the renewal reading outright, and a
	// sequence with no endpoint attribution cannot name a mechanism at all.
	forced := ""
	if shape.Interpretation == models.ChurnSpatialMultiplexing {
		forced = "concurrent_multi_certificate_pool"
	}
	sort.SliceStable(hypotheses, func(left, right int) bool {
		if forced != "" {
			leftForced := hypotheses[left].Code == forced
			rightForced := hypotheses[right].Code == forced
			if leftForced != rightForced {
				return leftForced
			}
		}
		return hypotheses[left].Score > hypotheses[right].Score
	})
	primary := hypotheses[0]
	if forced == "" && (unresolved || shape.SameEndpointChanges == 0) {
		primary = preferUnresolvedIssuanceCause(hypotheses, automated, pipeline, shortLived, freshIssuance)
		sort.SliceStable(hypotheses, func(left, right int) bool {
			if hypotheses[left].Code == primary.Code && hypotheses[right].Code != primary.Code {
				return true
			}
			if hypotheses[right].Code == primary.Code && hypotheses[left].Code != primary.Code {
				return false
			}
			return hypotheses[left].Score > hypotheses[right].Score
		})
	}

	corroboration := &models.EvidenceCorroboration{
		CTCoverage: ctCoverage, CTEntries: ctEntries, CTIssuanceEvents: ctIssuances, CTStatus: ctStatus, CTNote: ctNote,
		CAACoverage: caaCoverage, HTTPCoverage: httpCoverage,
		EndpointCoverage:  endpointCoverage(context.snapshots),
		ResolverAgreement: latestResolverAgreement(context.snapshots),
	}
	attachIndependentCorroboration(corroboration, context)
	corroboration.ConfidenceCeiling = confidenceCeiling(corroboration,
		shape.Interpretation != models.ChurnUndetermined,
		// A certificate seen again after it was "replaced", or two leaves seen in
		// one round, is a direct observation that settles the question. So is a
		// comparison made against the same endpoint.
		shape.CoexistenceProofs > 0 || shape.RevisitEvents > 0 || shape.SameEndpointChanges > 0)

	provenance := evidenceProvenance(changes)
	confidence := capConfidence(primary.Confidence, corroboration.ConfidenceCeiling)
	if provenance.LegacyDominated {
		confidence = capConfidence(confidence, "medium")
	}
	for index := range hypotheses {
		hypotheses[index].Confidence = capConfidence(hypotheses[index].Confidence, corroboration.ConfidenceCeiling)
	}

	status := causeStatusOf(primary.Code, shape, unresolved)
	if status == "inferred" {
		confidence = capConfidence(confidence, "low")
		primary.Confidence = confidence
	}
	summary := churnSummary(primary, shape, ctStatus, ctNote, len(context.snapshots), status)
	benign := ""
	switch primary.Code {
	case "concurrent_multi_certificate_pool":
		benign = "The certificate is not changing frequently. " + itoa(shape.DistinctLeaves) + " certificate(s) are deployed at the same time and monitoring sampled them in turn, which the raw change counter reports as " + itoa(shape.ChangeEvents) + " changes."
	case "short_lived_certificate_automation":
		benign = "Replacement at this cadence is the designed behaviour of short-lived certificates with a median validity of " + itoa(shape.MedianValidityDays) + " day(s), not an anomaly."
	}
	if item.Type == "frequent_change" && shape.SameEndpointChanges == 0 {
		switch primary.Code {
		case "concurrent_multi_certificate_pool", "short_lived_certificate_automation":
		default:
			benign = "The change counter moved, but consecutive samples were not shown to come from the same endpoint, so frequent change is not established."
		}
	}

	return models.CauseDiagnosis{
		PrimaryCode: primary.Code, PrimaryLabel: primary.Label, Confidence: confidence, Summary: summary,
		EvidenceCompleteness: completenessScore(len(context.snapshots), shape.EffectiveReplacements, context.state != nil), Hypotheses: hypotheses,
		MeasurementPlan: churnMeasurementPlan(shape, ctStatus, status),
		MeasuredRounds:  len(context.snapshots), TransitionRounds: shape.EffectiveReplacements,
		ChurnShape:        &shape,
		Provenance:        provenance,
		Corroboration:     corroboration,
		BenignExplanation: benign,
		CauseStatus:       status,
	}
}

func preferUnresolvedIssuanceCause(hypotheses []models.CauseHypothesis, automated, pipeline, shortLived, freshIssuance float64) models.CauseHypothesis {
	pick := func(code string) models.CauseHypothesis {
		for _, hypothesis := range hypotheses {
			if hypothesis.Code == code {
				return hypothesis
			}
		}
		return hypotheses[0]
	}
	switch {
	case shortLived >= 0.55 && shortLived+0.05 >= automated:
		return pick("short_lived_certificate_automation")
	case pipeline >= 0.40 && pipeline >= automated:
		return pick("preissued_rolling_pipeline")
	case automated >= 0.35 && freshIssuance >= 0.5:
		return pick("automated_renewal_policy")
	default:
		return pick("endpoint_attribution_unavailable")
	}
}

func causeStatusOf(code string, shape models.ChurnShape, unresolved bool) string {
	switch code {
	case "endpoint_attribution_unavailable", "replacement_mechanism_unestablished", "insufficient_longitudinal_evidence":
		return "unestablished"
	case "concurrent_multi_certificate_pool", "short_lived_certificate_automation":
		if unresolved || shape.SameEndpointChanges == 0 {
			return "inferred"
		}
		return "established"
	}
	if unresolved || shape.SameEndpointChanges == 0 {
		return "inferred"
	}
	return "established"
}

// incidentTriggerEvidence preserves the externally observable event that is
// allowed to name an incident-driven reissuance.  A revoked certificate does
// not reveal why the CA revoked it, and an ARI emergency does not reveal the
// operator action, so both are stated as trigger signals rather than private
// root causes.
func incidentTriggerEvidence(context diagnosisContext, signal float64) []string {
	evidence := []string{ftoaEvidence("incident_signal", signal)}
	for _, observation := range context.observations {
		if observation.RevocationStatus == models.RevocationRevoked {
			line := "revocation_observed"
			if observation.Fingerprint != "" {
				line += " fingerprint=" + observation.Fingerprint
			}
			if !observation.ObservedAt.IsZero() {
				line += " observed_at=" + observation.ObservedAt.UTC().Format(time.RFC3339)
			}
			if observation.RevocationReason != "" {
				line += " reason=" + observation.RevocationReason
			}
			evidence = append(evidence, line)
		}
		if observation.ObservationType == models.ObsARIEmergency {
			line := "ari_emergency_observed"
			if !observation.ObservedAt.IsZero() {
				line += " observed_at=" + observation.ObservedAt.UTC().Format(time.RFC3339)
			}
			evidence = append(evidence, line)
		}
	}
	return uniqueEvidenceStrings(evidence)
}

func churnSummary(primary models.CauseHypothesis, shape models.ChurnShape, ctStatus, ctNote string, rounds int, status string) string {
	lead := "Most consistent with " + strings.ToLower(primary.Label)
	switch status {
	case "inferred":
		lead = "Inferred from issuance and remaining-life shape as " + strings.ToLower(primary.Label) + "; same-endpoint replacement is not established"
	case "unestablished":
		lead = "No operational process is established"
	}
	parts := []string{lead + ": " + primary.Rationale}
	switch shape.Interpretation {
	case models.ChurnSpatialMultiplexing:
		parts = append(parts, fmt.Sprintf("Monitoring counted %d changes, but only %d distinct certificates were ever seen and %d of those changes returned to a certificate observed earlier; a replaced certificate cannot come back, so at most %d replacement(s) occurred.",
			shape.ChangeEvents, shape.DistinctLeaves, shape.RevisitEvents, shape.EffectiveReplacements))
		if shape.CoexistenceProofs > 0 {
			parts = append(parts, fmt.Sprintf("%d round(s) observed the predecessor and the successor at the same time on different endpoints, which is direct evidence of concurrent deployment.", shape.CoexistenceProofs))
		}
	case models.ChurnMixed:
		parts = append(parts, fmt.Sprintf("Monitoring counted %d changes across %d distinct certificates; %d change(s) were measured from a different endpoint than the preceding one, so the sequence mixes replacement with endpoint sampling.",
			shape.ChangeEvents, shape.DistinctLeaves, shape.CrossEndpointChanges))
	case models.ChurnTemporalReplacement:
		parts = append(parts, fmt.Sprintf("The sequence is monotone across %d distinct certificates with %d same-endpoint comparison(s), so these are replacements in time.",
			shape.DistinctLeaves, shape.SameEndpointChanges))
		if primary.Code == "preissued_rolling_pipeline" && shape.MedianIssuanceAgeDays > 0 {
			parts = append(parts, fmt.Sprintf("The served leaves had already been issued for %d day(s) and only %d day(s) remained, across %d issuance day(s).",
				shape.MedianIssuanceAgeDays, shape.MedianRemainingDays, shape.DistinctIssuanceDays))
		}
		if primary.Code == "automated_renewal_policy" && shape.MedianIssuanceAgeDays > 0 {
			parts = append(parts, fmt.Sprintf("The served leaves were issued %d day(s) before they appeared, with %d day(s) remaining.",
				shape.MedianIssuanceAgeDays, shape.MedianRemainingDays))
		}
	default:
		parts = append(parts, "The retained endpoint identity is insufficient to establish whether the differences are replacements in time or different servers answering.")
	}
	if ctStatus != models.CTUnavailable && ctNote != "" {
		parts = append(parts, ctNote)
	} else {
		parts = append(parts, "Certificate Transparency was unavailable, so the replacement count has no independent check.")
	}
	parts = append(parts, fmt.Sprintf("Evidence spans %d retained measurement round(s); this is a mechanism inference, not a claim about private operator intent.", rounds))
	return strings.Join(parts, " ")
}

func churnMeasurementPlan(shape models.ChurnShape, ctStatus, status string) []string {
	plan := make([]string, 0, 4)
	if status == "inferred" || shape.Interpretation != models.ChurnTemporalReplacement {
		plan = append(plan,
			"Probe every resolved address in the same round with the same SNI and retain per-address fingerprints; concurrent certificates are proven or refuted in one round.",
			"Compare successive certificates only between samples taken from the same address.")
	}
	if ctStatus != models.CTCorroborated {
		plan = append(plan, "Retrieve Certificate Transparency for this name, including by served leaf fingerprint, and compare logged issuance timestamps with the observed change times.")
	}
	if shape.MedianValidityDays == 0 {
		plan = append(plan, "Retain the certificate validity period so the replacement rate can be normalized by certificate lifetime.")
	}
	if shape.MedianIssuanceAgeDays == 0 || shape.MedianRemainingDays == 0 {
		plan = append(plan, "Retain issuance dates and remaining life at each replacement so a pre-issued inventory can be separated from issuance at replacement time.")
	}
	if len(plan) == 0 {
		plan = append(plan, "Continue same-endpoint sampling and correlate the next issuance with CT entry time, CAA policy and the CA's ARI window.")
	}
	return plan
}

func insufficientChurnDiagnosis(transitions, rounds int, state bool) models.CauseDiagnosis {
	return models.CauseDiagnosis{
		PrimaryCode:          "insufficient_longitudinal_evidence",
		PrimaryLabel:         "Insufficient longitudinal evidence",
		CauseStatus:          "unestablished",
		Confidence:           "low",
		Summary:              fmt.Sprintf("Only %d certificate replacement event(s) are retained; at least two replacement intervals and three measurement rounds are required before assigning an operational mechanism.", transitions),
		EvidenceCompleteness: completenessScore(rounds, transitions, state),
		Hypotheses: []models.CauseHypothesis{{
			Code:       "insufficient_longitudinal_evidence",
			Label:      "Need more longitudinal evidence",
			Score:      1,
			Confidence: "low",
			Rationale:  "The observed count cannot distinguish renewal cadence, key policy, issuer migration or edge rollout.",
			Evidence: []string{
				fmt.Sprintf("replacement_events=%d", transitions),
				fmt.Sprintf("measurement_rounds=%d", rounds),
			},
			Contradictions: []string{"No causal mechanism is established from a single transition."},
		}},
		MeasurementPlan: []string{
			"Collect at least three independent resolver and endpoint rounds.",
			"Retain old/current IP sets and compare per-IP SPKI, issuer, SAN and validity.",
			"Correlate the next replacement with CT entry time, CAA policy and ARI.",
		},
		MeasuredRounds:   rounds,
		TransitionRounds: transitions,
	}
}

func inferTopologyDiagnosis(item models.Anomaly, context diagnosisContext) models.CauseDiagnosis {
	topologyChanges, endpointChanges := topologySignals(context.snapshots)
	resolverAgreement := latestResolverAgreement(context.snapshots)

	// The structural analysis needs the full endpoint survey (issuer, key
	// algorithm, name coverage and per-endpoint validation), which only the
	// lifecycle observation retains. The snapshot series carries addresses and
	// fingerprints only, and is used for the stability history.
	probes, previousFingerprint, replacedAt, surveyAt := latestEndpointSurvey(context.observations)
	history := context.snapshots
	// Snapshots now retain the full survey of every round. Prefer a newer one:
	// a lifecycle row is only written when the assignment changes, so it can be
	// days older than the round being explained. The row's predecessor still
	// applies; it must pass the age and continuity gates on the newer survey.
	if snapshotProbes, at := latestSnapshotSurvey(context.snapshots); len(snapshotProbes) > 0 && at.After(surveyAt) {
		probes = snapshotProbes
	}
	if len(probes) == 0 && len(context.snapshots) > 0 {
		// Lifecycle rows do not always retain a full survey. The snapshot series
		// still carries the address-to-certificate assignment, which is enough for
		// the partition and stability tests. Issuer, key algorithm and name
		// coverage stay unknown, so the dual-certificate reading simply cannot
		// fire rather than being guessed at.
		probes = probesFromSnapshot(context.snapshots[0])
		history = context.snapshots[1:]
	}
	now := latestObservedAt(context.observations, context.snapshots)
	divergence := analyzeEndpointDivergence(probes, history, previousFingerprint, replacedAt, now)

	benignVerdict := divergenceIsBenign(divergence.Verdict)
	vendorComplete := divergence.CDN != nil && models.CDNMethodFor(divergence.CDN.Completeness) == "vendor"
	namedMultiCDN := vendorComplete && divergence.CDN.DistinctVendors >= 2 && divergence.CDN.CleanVendorSplit && divergence.StableRounds >= minStableMultiProviderRounds && divergence.IndependentLineages && divergence.AddressReturns == 0 && divergence.AddressPools == 0
	namedSameVendor := vendorComplete && (divergence.CDN.DistinctVendors == 1 || divergence.CDN.VendorConflicts > 0)
	multiCDN := clampScore(0.05 + 0.45*boolScore((stableMultiProviderPartition(divergence) && !namedSameVendor) || namedMultiCDN) +
		0.30*boolScore(divergence.StableRounds >= 2) + 0.20*boolScore(divergence.FunctionallyEquivalent))
	dualCert := clampScore(0.03 + 0.62*boolScore(divergence.DualCertificateSplit) + 0.20*boolScore(divergence.FunctionallyEquivalent) + 0.15*boolScore(divergence.StableRounds >= 1))
	sameVendorConflict := namedSameVendor && divergence.CDN != nil && (divergence.CDN.VendorConflicts > 0 || divergence.DistinctLeaves >= 2)
	conflictCount := divergence.IntraGroupConflicts
	if sameVendorConflict && conflictCount < 1 {
		conflictCount = 1
	}
	intraFleet := clampScore(0.05 + 0.50*boolScore(divergence.IntraGroupConflicts > 0 || sameVendorConflict) +
		0.25*boolScore(divergence.StableRounds >= 2) + 0.20*math.Min(float64(conflictCount)/2, 1))
	stuckRollout := clampScore(0.05 + 0.45*boolScore(len(divergence.PredecessorEndpoints) > 0) +
		0.30*boolScore(divergence.StrongEvidence) + 0.20*endpointChanges)
	defective := clampScore(0.02 + 0.88*boolScore(len(divergence.DefectiveEndpoints) > 0))
	rollout := clampScore(0.08 + 0.45*endpointChanges + 0.25*float64(minInt(topologyChanges, 3))/3 +
		0.20*boolScore(len(divergence.PredecessorEndpoints) > 0 && !divergence.StrongEvidence))
	staleScore := 0.0
	if item.Type == models.ObsStaleAfterChange {
		// A DNS answer-set difference is the normal behaviour of an address pool.
		// It only supports a cutover reading when the endpoint assignment moved
		// with it, so the address change alone no longer carries this hypothesis.
		staleScore = clampScore(0.20 + 0.45*endpointChanges + 0.20*float64(minInt(topologyChanges, 3))/3 +
			0.15*boolScore(len(divergence.PredecessorEndpoints) > 0))
	}
	perEndpoint := clampScore(0.02 + 0.60*boolScore(divergence.IndependentLineages) + 0.20*boolScore(divergence.StableAddressRounds >= minStableAddressRounds) + 0.18*boolScore(divergence.FunctionallyEquivalent))
	coverage := clampScore(0.70 * (1 - boolScore(divergence.EndpointsAnswered >= 2 && len(context.snapshots) >= 3)))

	hypotheses := []models.CauseHypothesis{
		{Code: models.DivergenceIntentionalMultiCDN, Label: "Intentional multi-provider deployment", Score: multiCDN, Rationale: multiCDNRationale(divergence), Evidence: divergenceEvidence(divergence), Contradictions: []string{"This case has two certificates inside one named CDN or one provider network, so it is not a deliberate split across providers."}},
		{Code: models.DivergenceDualCertificate, Label: "Intentional dual-certificate deployment", Score: dualCert, Rationale: "The leaves differ only by public-key algorithm while covering the same names from the same issuer, which is how an RSA plus ECDSA pair is served.", Evidence: []string{itoaEvidence("distinct_key_algorithms", divergence.DistinctKeyAlgos), itoaEvidence("distinct_issuers", divergence.DistinctIssuers), itoaEvidence("distinct_san_sets", divergence.DistinctSANSets)}, Contradictions: []string{"Differing issuers or name sets would make this something other than an algorithm pair."}},
		{Code: models.DivergencePerEndpoint, Label: "Independent certificate per endpoint", Score: perEndpoint, Rationale: "Each address kept its own leaf across rounds, every leaf is valid for the name, and no address was ever seen moving from one of these leaves to another, so none of them is a predecessor.", Evidence: []string{"independent_lineages=" + boolText(divergence.IndependentLineages), itoaEvidence("stable_address_rounds", divergence.StableAddressRounds), ftoaEvidence("stable_address_span_hours", divergence.StableAddressSpanHours)}, Contradictions: []string{"An address observed moving from one of these leaves to another would make this a rollout instead."}},
		{Code: models.DivergenceIntraFleet, Label: "Inconsistency inside one provider network", Score: intraFleet, Rationale: intraFleetRationale(divergence), Evidence: []string{itoaEvidence("intra_group_conflicts", divergence.IntraGroupConflicts), itoaEvidence("network_groups", divergence.NetworkGroups), itoaEvidence("stable_rounds", divergence.StableRounds)}, Contradictions: []string{"A later round that partitions the certificates onto separately named CDNs would make this look like a deliberate split instead."}},
		{Code: models.DivergenceStuckRollout, Label: "Replacement that did not reach every endpoint", Score: stuckRollout, Rationale: "An address was observed moving from the predecessor to another leaf while an active DNS address still serves the predecessor, and that overlap is longer than the configured share of completed rollouts took.", Evidence: []string{itoaEvidence("predecessor_endpoints", len(divergence.PredecessorEndpoints)), ftoaEvidence("proven_overlap_hours", divergence.PredecessorSpanHours), itoaEvidence("reference_completed", divergence.ReferenceCompleted), ftoaEvidence("reference_share", divergence.ReferenceShare), ftoaEvidence("alert_share", divergence.AlertShare)}, Contradictions: []string{"The predecessor leaving active DNS in a later round would make this a finished rollout."}},
		{Code: models.DivergenceDefectiveEndpoint, Label: "Endpoint serving a certificate invalid for the name", Score: defective, Rationale: "An endpoint presented a certificate that is expired, not yet valid, name-mismatched or fails chain validation, which is a defect independent of how the endpoints are distributed.", Evidence: []string{itoaEvidence("defective_endpoints", len(divergence.DefectiveEndpoints))}, Contradictions: []string{"All endpoints presenting currently valid certificates for the name would remove this reading."}},
		{Code: models.DivergencePropagating, Label: "Rollout in progress", Score: rollout, Rationale: "The endpoint-to-certificate assignment changed recently and has not yet settled.", Evidence: []string{ftoaEvidence("endpoint_transition_score", endpointChanges), itoaEvidence("topology_transition_rounds", topologyChanges)}, Contradictions: []string{"A stable assignment across rounds argues the arrangement is the steady state."}},
		{Code: models.DivergenceUndetermined, Label: "Insufficient endpoint coverage", Score: coverage, Rationale: "The endpoint sample or resolver set is too small to tell a deliberate arrangement from an inconsistent one.", Evidence: []string{itoaEvidence("endpoints_answered", divergence.EndpointsAnswered), itoaEvidence("measurement_rounds", len(context.snapshots)), ftoaEvidence("resolver_agreement", resolverAgreement)}, Contradictions: []string{"Additional independent endpoint rounds reduce this uncertainty."}},
	}
	if staleScore > 0 {
		hypotheses = append(hypotheses, models.CauseHypothesis{Code: "dns_cutover_before_tls_deployment", Label: "DNS cutover before TLS deployment", Score: staleScore, Rationale: "The endpoint assignment moved together with the address set, leaving a prior edge on the old leaf while a new edge exposed the successor.", Evidence: []string{itoaEvidence("topology_transition_rounds", topologyChanges), ftoaEvidence("endpoint_transition_score", endpointChanges), itoaEvidence("predecessor_endpoints", len(divergence.PredecessorEndpoints))}, Contradictions: []string{"An address set that rotates inside one provider network without moving the certificate assignment is edge rotation, not a cutover."}})
	}
	// The structural verdict is a decision taken from direct measurements, not a
	// preference among weighted guesses. It selects the primary hypothesis in
	// every case, including when it concluded the evidence is insufficient —
	// otherwise a benign-looking score can head a finding whose structure was
	// never actually confirmed, and the reported cause and the reported severity
	// end up disagreeing.
	sort.SliceStable(hypotheses, func(left, right int) bool {
		leftIsVerdict := hypotheses[left].Code == divergence.Verdict
		rightIsVerdict := hypotheses[right].Code == divergence.Verdict
		if leftIsVerdict != rightIsVerdict {
			return leftIsVerdict
		}
		return hypotheses[left].Score > hypotheses[right].Score
	})
	primary := hypotheses[0]

	ctCoverage, ctEntries, ctIssuances, ctStatus, ctNote := analyzeCTCorroboration(context.snapshots, models.ChurnShape{}, 30*24*time.Hour)
	corroboration := &models.EvidenceCorroboration{
		CTCoverage: ctCoverage, CTEntries: ctEntries, CTIssuanceEvents: ctIssuances, CTStatus: ctStatus, CTNote: ctNote,
		EndpointCoverage:  endpointCoverage(context.snapshots),
		ResolverAgreement: resolverAgreement,
	}
	corroboration.CAACoverage, _ = caaSignals(context.snapshots)
	corroboration.HTTPCoverage, _ = httpSignals(context.snapshots)
	attachIndependentCorroboration(corroboration, context)
	attachGlobalProbeCorroboration(corroboration, divergence)
	corroboration.ConfidenceCeiling = confidenceCeiling(corroboration,
		divergence.Verdict != models.DivergenceUndetermined,
		divergence.EndpointsAnswered >= 2)
	provenance := evidenceProvenance(lifecycleRowsOfType(context.observations, item.Type))
	confidence := capConfidence(scoreConfidence(primary.Score, divergence.EndpointsAnswered, len(context.snapshots)), corroboration.ConfidenceCeiling)
	if provenance.LegacyDominated {
		confidence = capConfidence(confidence, "medium")
	}
	for index := range hypotheses {
		hypotheses[index].Confidence = capConfidence(scoreConfidence(hypotheses[index].Score, divergence.EndpointsAnswered, len(context.snapshots)), corroboration.ConfidenceCeiling)
	}

	benign := ""
	if benignVerdict {
		switch divergence.Verdict {
		case models.DivergenceIntentionalMultiCDN:
			benign = multiCDNBenign(divergence)
		case models.DivergencePerEndpoint:
			benign = fmt.Sprintf("Each of %d endpoint(s) kept its own certificate for %d round(s) over %.1f hours, all %d leaves are valid for the name, and no address was ever seen moving from one of these leaves to another. Each endpoint holds its own certificate; none is a leftover predecessor.", divergence.EndpointsAnswered, divergence.StableAddressRounds, divergence.StableAddressSpanHours, divergence.DistinctLeaves)
		case models.DivergenceDualCertificate:
			benign = "The endpoints serve the same names from the same issuer under " + itoa(divergence.DistinctKeyAlgos) + " public-key algorithms, which is a deliberate dual-certificate arrangement rather than an inconsistent deployment."
		}
	} else if item.Type == models.ObsStaleAfterChange && divergence.DistinctLeaves < 2 && len(divergence.ActivePredecessorEndpoints) == 0 && !divergence.StrongEvidence {
		benign = "The current sampled endpoints serve one certificate. A DNS/IP-set change without a leftover predecessor is address-pool rotation, not a stale certificate after topology change."
	} else if item.Type == models.ObsDeploymentFailure && divergence.DistinctLeaves < 2 {
		benign = "The current sampled endpoints serve one certificate. An earlier mixed-fingerprint observation is historical and does not establish live certificate diversity."
	}

	return models.CauseDiagnosis{
		PrimaryCode: primary.Code, PrimaryLabel: primary.Label, Confidence: confidence,
		Summary:              divergenceSummary(primary, divergence, len(context.snapshots), topologyChanges),
		EvidenceCompleteness: completenessScore(len(context.snapshots), divergence.EndpointsAnswered, context.state != nil),
		Hypotheses:           hypotheses,
		MeasurementPlan:      divergenceMeasurementPlan(divergence),
		MeasuredRounds:       len(context.snapshots), TransitionRounds: topologyChanges,
		Divergence:        &divergence,
		CauseStatus:       topologyCauseStatus(divergence, benign),
		Provenance:        provenance,
		Corroboration:     corroboration,
		BenignExplanation: benign,
	}
}

func topologyCauseStatus(divergence models.EndpointDivergence, benign string) string {
	if benign != "" {
		return "established"
	}
	switch divergence.Verdict {
	case models.DivergenceStuckRollout:
		if divergence.StrongEvidence {
			return "established"
		}
		return "inferred"
	case models.DivergenceIntraFleet, models.DivergenceDefectiveEndpoint:
		return "established"
	case models.DivergencePropagating, models.DivergenceUndetermined:
		return "inferred"
	case models.DivergenceIntentionalMultiCDN, models.DivergenceDualCertificate, models.DivergencePerEndpoint:
		return "established"
	default:
		if divergence.Verdict == "dns_cutover_before_tls_deployment" {
			return "inferred"
		}
		return "unestablished"
	}
}

func multiCDNRationale(divergence models.EndpointDivergence) string {
	if divergence.CDN != nil && models.CDNMethodFor(divergence.CDN.Completeness) == "vendor" && divergence.CDN.DistinctVendors >= 2 {
		return "Each named CDN served one certificate consistently, so the diversity is between providers rather than inside any one of them."
	}
	return "Each provider network served one certificate consistently and the assignment held across independent rounds, so the diversity is between providers rather than inside any one of them. Vendors were not identified for every endpoint, so the reading uses the IPv4 /16 and IPv6 /32 partition."
}

func intraFleetRationale(divergence models.EndpointDivergence) string {
	if divergence.CDN != nil && models.CDNMethodFor(divergence.CDN.Completeness) == "vendor" && (divergence.CDN.DistinctVendors == 1 || divergence.CDN.VendorConflicts > 0) {
		return "Addresses attributed to the same named CDN served different certificates, which no between-provider arrangement explains."
	}
	return "Addresses inside the same network allocation served different certificates, which no between-provider arrangement explains."
}

func multiCDNBenign(divergence models.EndpointDivergence) string {
	text := "The endpoints are distributed across " + itoa(divergence.NetworkGroups) + " provider networks, each consistently serving its own certificate for " + itoa(divergence.StableRounds) + " earlier round(s). This is a deliberate multi-provider arrangement, not an inconsistent deployment."
	if divergence.CDN != nil && models.CDNMethodFor(divergence.CDN.Completeness) == "vendor" && divergence.CDN.DistinctVendors >= 2 {
		text = "The endpoints are distributed across " + itoa(divergence.CDN.DistinctVendors) + " named CDNs, each consistently serving its own certificate for " + itoa(divergence.StableRounds) + " earlier round(s). This is a deliberate multi-provider arrangement, not an inconsistent deployment."
	}
	if len(divergence.DefectiveEndpoints) > 0 {
		text += " A certificate that is not valid for the name on " + strings.Join(divergence.DefectiveEndpoints, ", ") + " is a separate TLS finding, not evidence that the split itself is a deployment failure."
	}
	return text
}

func divergenceSummary(primary models.CauseHypothesis, divergence models.EndpointDivergence, rounds, topologyChanges int) string {
	parts := []string{"Most consistent with " + strings.ToLower(primary.Label) + ": " + primary.Rationale}
	if divergence.EndpointsAnswered >= 2 {
		parts = append(parts, fmt.Sprintf("%d endpoint(s) answered with %d distinct certificate(s) across %d provider network(s); %d network(s) served more than one certificate.",
			divergence.EndpointsAnswered, divergence.DistinctLeaves, divergence.NetworkGroups, divergence.IntraGroupConflicts))
		if divergence.StableRounds > 0 {
			parts = append(parts, fmt.Sprintf("The same provider-to-certificate assignment held in %d earlier round(s), compared by network allocation so that edge address rotation does not reset it.", divergence.StableRounds))
		}
		if len(divergence.DefectiveEndpoints) > 0 {
			parts = append(parts, fmt.Sprintf("%d endpoint(s) served a certificate that is not currently valid for the queried name.", len(divergence.DefectiveEndpoints)))
		}
	} else {
		parts = append(parts, "Fewer than two endpoints answered, so the structure of the diversity could not be measured.")
	}
	if divergence.GlobalProbeRounds > 0 {
		switch {
		case len(divergence.GlobalPredecessorRegions) > 0:
			parts = append(parts, fmt.Sprintf("The latest retained multi-region HTTPS round also reached the predecessor from %d region(s) (%s).", len(divergence.GlobalPredecessorRegions), strings.Join(divergence.GlobalPredecessorRegions, ", ")))
		case len(divergence.GlobalDefectiveRegions) > 0:
			parts = append(parts, fmt.Sprintf("The latest retained multi-region HTTPS round also rejected the locally defective leaf from %d region(s) (%s).", len(divergence.GlobalDefectiveRegions), strings.Join(divergence.GlobalDefectiveRegions, ", ")))
		default:
			parts = append(parts, fmt.Sprintf("The latest retained multi-region HTTPS round covered %d region(s), but did not match the local predecessor or defective leaf.", len(divergence.GlobalHTTPSRegions)))
		}
	}
	parts = append(parts, fmt.Sprintf("Evidence uses %d retained round(s) and %d topology transition(s); mixed certificates alone are never treated as a deployment failure.", rounds, topologyChanges))
	return strings.Join(parts, " ")
}

func divergenceMeasurementPlan(divergence models.EndpointDivergence) []string {
	plan := make([]string, 0, 3)
	if divergence.EndpointsAnswered < 2 {
		plan = append(plan, "Widen the endpoint survey until at least two addresses answer in the same round; one endpoint cannot show a distribution.")
	}
	if divergence.DistinctKeyAlgos == 0 {
		plan = append(plan, "Retain the public-key algorithm per endpoint so an RSA plus ECDSA pair is not reported as inconsistent deployment.")
	}
	if divergence.StableRounds < 2 {
		plan = append(plan, "Repeat the survey for two further rounds; a deliberate arrangement keeps its provider-to-certificate assignment while a rollout does not.")
	}
	if len(divergence.PredecessorEndpoints) > 0 {
		plan = append(plan, "Re-probe the endpoints still serving the predecessor; every further round either extends the proven overlap or shows the rollout finished.")
	}
	if divergence.GlobalProbeRounds == 0 {
		plan = append(plan, "Collect multi-region HTTPS probes so a local predecessor or invalid leaf can be distinguished from a region-scoped edge result.")
	} else if len(divergence.GlobalPredecessorRegions) == 0 && len(divergence.GlobalDefectiveRegions) == 0 {
		plan = append(plan, "Repeat the multi-region HTTPS probes after the next endpoint round; no latest remote result matched the local predecessor or defective leaf.")
	}
	if divergence.CDN == nil || models.CDNMethodFor(divergence.CDN.Completeness) != "vendor" {
		plan = append(plan, "Look up RDAP and ASN for every answering address, and retain NS names, so unnamed /16 and /32 partitions can be replaced with numbering-authority identities.")
	}
	if len(plan) == 0 {
		plan = append(plan, "Continue per-network endpoint sampling and compare issuer, key algorithm and name coverage across providers.")
	}
	return plan
}

// latestEndpointSurvey returns the most recent retained endpoint survey along
// with the fingerprint it replaced and when that replacement was first seen.
func latestEndpointSurvey(observations []models.CertObservation) ([]models.EndpointProbe, string, time.Time, time.Time) {
	var best models.CertObservation
	found := false
	for _, observation := range observations {
		if strings.TrimSpace(observation.EndpointProbes) == "" {
			continue
		}
		// Several lifecycle rows are written for one round; on a tie keep the
		// row that recorded a replacement so its predecessor is not lost.
		tieWithPredecessor := found && observation.ObservedAt.Equal(best.ObservedAt) &&
			best.PreviousFingerprint == "" && observation.PreviousFingerprint != "" && observation.PreviousFingerprint != observation.Fingerprint
		if !found || observation.ObservedAt.After(best.ObservedAt) || tieWithPredecessor {
			best = observation
			found = true
		}
	}
	if !found {
		return nil, "", time.Time{}, time.Time{}
	}
	var probes []models.EndpointProbe
	if json.Unmarshal([]byte(best.EndpointProbes), &probes) != nil {
		return nil, "", time.Time{}, time.Time{}
	}
	replacedAt := time.Time{}
	previous := best.PreviousFingerprint
	// Rows written before the detector fix stored the unchanged main-handshake
	// leaf as PreviousFingerprint. A leaf cannot be its own predecessor.
	if previous == best.Fingerprint {
		previous = ""
	}
	// Only the round in which the main handshake switched leaves records the
	// predecessor. Later rounds for the same successor inherit it; the age and
	// continuity gates still decide whether it is left behind.
	if previous == "" {
		var latest time.Time
		for _, observation := range observations {
			candidate := observation.PreviousFingerprint
			if observation.Fingerprint != best.Fingerprint || candidate == "" || candidate == observation.Fingerprint {
				continue
			}
			if observation.ObservedAt.After(latest) {
				latest, previous = observation.ObservedAt, candidate
			}
		}
	}
	if previous != "" {
		replacedAt = firstObservationOf(observations, best.Fingerprint)
	}
	return probes, previous, replacedAt, best.ObservedAt
}

// currentEndpointSurvey is the survey the diagnosis explains: the newest of
// the latest lifecycle survey and the latest snapshot survey.
func currentEndpointSurvey(context diagnosisContext) []models.EndpointProbe {
	probes, _, _, at := latestEndpointSurvey(context.observations)
	if snapshotProbes, snapshotAt := latestSnapshotSurvey(context.snapshots); len(snapshotProbes) > 0 && snapshotAt.After(at) {
		return snapshotProbes
	}
	return probes
}

// latestSnapshotSurvey returns the newest snapshot's full endpoint survey.
func latestSnapshotSurvey(snapshots []models.MeasurementSnapshot) ([]models.EndpointProbe, time.Time) {
	var newest *models.MeasurementSnapshot
	for index := range snapshots {
		raw := strings.TrimSpace(snapshots[index].EndpointProbesJSON)
		if raw == "" || raw == "null" {
			continue
		}
		if newest == nil || snapshots[index].ObservedAt.After(newest.ObservedAt) {
			newest = &snapshots[index]
		}
	}
	if newest == nil {
		return nil, time.Time{}
	}
	var probes []models.EndpointProbe
	if json.Unmarshal([]byte(newest.EndpointProbesJSON), &probes) != nil {
		return nil, time.Time{}
	}
	return probes, newest.ObservedAt
}

func firstObservationOf(observations []models.CertObservation, fingerprint string) time.Time {
	earliest := time.Time{}
	for _, observation := range observations {
		if observation.Fingerprint != fingerprint {
			continue
		}
		if earliest.IsZero() || observation.ObservedAt.Before(earliest) {
			earliest = observation.ObservedAt
		}
	}
	return earliest
}

func latestObservedAt(observations []models.CertObservation, snapshots []models.MeasurementSnapshot) time.Time {
	latest := time.Time{}
	for _, observation := range observations {
		if observation.ObservedAt.After(latest) {
			latest = observation.ObservedAt
		}
	}
	for _, snapshot := range snapshots {
		if snapshot.ObservedAt.After(latest) {
			latest = snapshot.ObservedAt
		}
	}
	return latest
}

func lifecycleRowsOfType(observations []models.CertObservation, observationType string) []models.CertObservation {
	rows := make([]models.CertObservation, 0, len(observations))
	for _, observation := range observations {
		if observation.ObservationType == observationType {
			rows = append(rows, observation)
		}
	}
	return rows
}

func changeCadence(changes []models.CertObservation) (float64, float64) {
	if len(changes) < 2 {
		return 0, 0
	}
	intervals := make([]float64, 0, len(changes)-1)
	for index := 1; index < len(changes); index++ {
		hours := changes[index].ObservedAt.Sub(changes[index-1].ObservedAt).Hours()
		if hours > 0 {
			intervals = append(intervals, hours)
		}
	}
	if len(intervals) == 0 {
		return 0, 0
	}
	mean := 0.0
	for _, value := range intervals {
		mean += value
	}
	mean /= float64(len(intervals))
	variance := 0.0
	for _, value := range intervals {
		variance += (value - mean) * (value - mean)
	}
	variance /= float64(len(intervals))
	cv := math.Sqrt(variance) / math.Max(mean, 1)
	return mean, clampScore(1 / (1 + cv))
}

func renewalLeadSignal(changes []models.CertObservation) (float64, float64) {
	if len(changes) == 0 {
		return 0, 0
	}
	values := make([]float64, 0, len(changes))
	for _, change := range changes {
		values = append(values, float64(change.DaysUntilExpiry))
	}
	mean := 0.0
	for _, value := range values {
		mean += value
	}
	mean /= float64(len(values))
	variance := 0.0
	for _, value := range values {
		variance += (value - mean) * (value - mean)
	}
	variance /= float64(len(values))
	spread := math.Sqrt(variance)
	near := 0
	for _, value := range values {
		if value >= 0 && value <= 45 {
			near++
		}
	}
	return float64(near) / float64(len(values)), spread / 1
}

func certificateTransitionSignals(changes []models.CertObservation, certs map[string]models.Certificate) (sameKey, issuer, sans, validity float64) {
	if len(changes) == 0 {
		return 0, 0, 0, 0
	}
	same, knownKeys := 0, 0
	issuerChanges, sanChanges, validityChanges := 0, 0, 0
	for _, change := range changes {
		if change.PreviousSPKIFingerprint != "" && change.SPKIFingerprint != "" {
			knownKeys++
			if change.PreviousSPKIFingerprint == change.SPKIFingerprint {
				same++
			}
		}
		oldCert, oldOK := certs[change.PreviousFingerprint]
		newCert, newOK := certs[change.Fingerprint]
		if oldOK && newOK {
			if issuerFamily(oldCert) != issuerFamily(newCert) {
				issuerChanges++
			}
			if normalizedSANs(oldCert.SANs) != normalizedSANs(newCert.SANs) {
				sanChanges++
			}
			if oldCert.NotAfter.Sub(oldCert.NotBefore) != newCert.NotAfter.Sub(newCert.NotBefore) {
				validityChanges++
			}
		}
	}
	denominator := float64(len(changes))
	// Unknown SPKI comparisons are neutral, rather than evidence of a key
	// change. This prevents sparse historical rows from manufacturing a key-
	// rotation explanation.
	sameKey = 0.5
	if knownKeys > 0 {
		sameKey = float64(same) / float64(knownKeys)
	}
	return sameKey, float64(issuerChanges) / denominator, float64(sanChanges) / denominator, float64(validityChanges) / denominator
}

func ariAlignmentSignal(observations []models.CertObservation, changes []models.CertObservation, state *models.DomainCertificate) float64 {
	if state == nil || state.ARICheckedAt == nil {
		return 0
	}
	if state.ARIWindowStart == nil || len(changes) == 0 {
		return 0.25
	}
	window := state.ARIWindowStart.Sub(changes[len(changes)-1].ObservedAt).Hours()
	if math.Abs(window) <= 72 {
		return 1
	}
	_ = observations
	return 0
}

func diagnosisEndpointFingerprintSetFromSnapshot(snapshot models.MeasurementSnapshot) map[string]string {
	result := make(map[string]string)
	if strings.TrimSpace(snapshot.EndpointFingerprintsJSON) == "" {
		return result
	}
	_ = json.Unmarshal([]byte(snapshot.EndpointFingerprintsJSON), &result)
	return result
}

func overlappingFingerprintReplacements(before, after map[string]string) int {
	count := 0
	for ip, fingerprint := range before {
		next, ok := after[ip]
		if !ok || fingerprint == "" || next == "" {
			continue
		}
		if next != fingerprint {
			count++
		}
	}
	return count
}

func topologySignals(snapshots []models.MeasurementSnapshot) (topologyChanges int, endpointChanges float64) {
	if len(snapshots) < 2 {
		return 0, 0
	}
	// Address-set churn (anycast VIP rotation) is not a certificate rollout.
	// Only a fingerprint change on an IP that answered in both rounds is
	// replacement evidence, and that is counted separately from edge rollout.
	replacementComparisons := 0
	addressSetChanges := 0
	for index := 1; index < len(snapshots); index++ {
		if snapshots[index].TopologyHash != "" && snapshots[index-1].TopologyHash != "" && snapshots[index].TopologyHash != snapshots[index-1].TopologyHash {
			topologyChanges++
		}
		before := diagnosisEndpointFingerprintSetFromSnapshot(snapshots[index])
		after := diagnosisEndpointFingerprintSetFromSnapshot(snapshots[index-1])
		if len(before) == 0 || len(after) == 0 {
			continue
		}
		if overlappingFingerprintReplacements(before, after) > 0 {
			replacementComparisons++
		}
		if diagnosisAddressSetChanged(before, after) && overlappingFingerprintReplacements(before, after) == 0 {
			addressSetChanges++
		}
	}
	_ = addressSetChanges
	if replacementComparisons > 0 {
		endpointChanges = float64(replacementComparisons) / float64(len(snapshots)-1)
	}
	return topologyChanges, endpointChanges
}

func diagnosisAddressSetChanged(before, after map[string]string) bool {
	if len(before) != len(after) {
		return true
	}
	for ip := range before {
		if _, ok := after[ip]; !ok {
			return true
		}
	}
	for ip := range after {
		if _, ok := before[ip]; !ok {
			return true
		}
	}
	return false
}

// caaSignals turns the retained CAA documents into a stable policy signature.
// A resolver failure is not interpreted as policy removal, so only adjacent
// rounds with two valid documents contribute to the change fraction.
func caaSignals(snapshots []models.MeasurementSnapshot) (coverage, changes float64) {
	if len(snapshots) == 0 {
		return 0, 0
	}
	signatures := make([]string, len(snapshots))
	valid := make([]bool, len(snapshots))
	for index, snapshot := range snapshots {
		var records []models.CAARecord
		if strings.TrimSpace(snapshot.CAAJSON) == "" || snapshot.CAAJSON == "null" {
			continue
		}
		if err := json.Unmarshal([]byte(snapshot.CAAJSON), &records); err != nil || len(records) == 0 {
			continue
		}
		parts := make([]string, 0, len(records))
		for _, record := range records {
			parts = append(parts, fmt.Sprintf("%d|%s|%s", record.Flag, strings.ToLower(strings.TrimSpace(record.Tag)), strings.TrimSpace(record.Value)))
		}
		sort.Strings(parts)
		signatures[index] = strings.Join(parts, ";")
		valid[index] = true
	}
	validCount := 0
	for _, ok := range valid {
		if ok {
			validCount++
		}
	}
	coverage = float64(validCount) / float64(len(snapshots))
	comparisons, changed := 0, 0
	for index := 1; index < len(signatures); index++ {
		if !valid[index-1] || !valid[index] {
			continue
		}
		comparisons++
		if signatures[index-1] != signatures[index] {
			changed++
		}
	}
	if comparisons > 0 {
		changes = float64(changed) / float64(comparisons)
	}
	return coverage, changes
}

// httpSignals compares the observed edge fingerprint (headers and redirect)
// across rounds. It is deliberately a change signal, not a vendor classifier:
// a CDN header change can corroborate an edge rollout without proving which
// provider made the change.
func httpSignals(snapshots []models.MeasurementSnapshot) (coverage, changes float64) {
	if len(snapshots) == 0 {
		return 0, 0
	}
	signatures := make([]string, len(snapshots))
	valid := make([]bool, len(snapshots))
	for index, snapshot := range snapshots {
		var fingerprint models.HTTPFingerprint
		if strings.TrimSpace(snapshot.HTTPJSON) == "" || snapshot.HTTPJSON == "null" {
			continue
		}
		if err := json.Unmarshal([]byte(snapshot.HTTPJSON), &fingerprint); err != nil {
			continue
		}
		if fingerprint.IPAddress == "" && fingerprint.Server == "" && fingerprint.Via == "" && fingerprint.Cache == "" && len(fingerprint.ProviderSignals) == 0 && fingerprint.Redirect == "" {
			continue
		}
		providers := append([]string(nil), fingerprint.ProviderSignals...)
		sort.Strings(providers)
		// The address itself is excluded: DNS/topology signals already measure
		// edge movement, while this signature should capture HTTP behavior or
		// provider configuration changes at the observed edge.
		signatures[index] = fmt.Sprintf("%d|%s|%s|%s|%s|%s", fingerprint.StatusCode, fingerprint.Server, fingerprint.Via, fingerprint.Cache, strings.Join(providers, ","), fingerprint.Redirect)
		valid[index] = true
	}
	validCount := 0
	for _, ok := range valid {
		if ok {
			validCount++
		}
	}
	coverage = float64(validCount) / float64(len(snapshots))
	comparisons, changed := 0, 0
	for index := 1; index < len(signatures); index++ {
		if !valid[index-1] || !valid[index] {
			continue
		}
		comparisons++
		if signatures[index-1] != signatures[index] {
			changed++
		}
	}
	if comparisons > 0 {
		changes = float64(changed) / float64(comparisons)
	}
	return coverage, changes
}

func completenessScore(rounds, transitions int, state bool) float64 {
	score := 0.0
	if rounds > 0 {
		score += math.Min(float64(rounds)/6, 1) * 0.45
	}
	if transitions > 0 {
		score += math.Min(float64(transitions)/4, 1) * 0.35
	}
	if state {
		score += 0.20
	}
	return math.Round(score*100) / 100
}

func scoreConfidence(score float64, transitions, rounds int) string {
	if score >= 0.70 && transitions >= 3 && rounds >= 5 {
		return "high"
	}
	if score >= 0.45 && transitions >= 2 && rounds >= 3 {
		return "medium"
	}
	return "low"
}

func clampScore(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return math.Round(value*100) / 100
}

func boolScore(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func (d *Database) certificateChangeCause(domain string, observation models.CertObservation) anomalyCause {
	if observation.Fingerprint == "" {
		return anomalyCause{
			inferredReason:   "The replacement cannot be described because the latest certificate fingerprint is incomplete.",
			inferredEvidence: []string{"fingerprint=missing", "inference=insufficient_certificate_fields"},
		}
	}
	var current, previous models.Certificate
	if d.db.Where("fingerprint = ?", observation.Fingerprint).First(&current).Error != nil {
		return anomalyCause{
			inferredReason:   "The replacement cannot be described because the current certificate fields are unavailable.",
			inferredEvidence: []string{"new_fingerprint=" + observation.Fingerprint, "inference=insufficient_certificate_fields"},
		}
	}
	if observation.PreviousFingerprint == "" || d.db.Where("fingerprint = ?", observation.PreviousFingerprint).First(&previous).Error != nil {
		return anomalyCause{
			inferredReason:   "A different leaf was observed, but the predecessor certificate was not retained, so issuance dates and remaining life cannot be compared.",
			inferredEvidence: []string{"new_fingerprint=" + observation.Fingerprint, "inference=insufficient_previous_certificate_fields"},
		}
	}
	confirmedEvidence := []string{"previous_fingerprint=" + previous.Fingerprint, "new_fingerprint=" + current.Fingerprint}
	oldSPKI, newSPKI := certificateSPKI(&previous), certificateSPKI(&current)
	if oldSPKI != "" && newSPKI != "" {
		if oldSPKI == newSPKI {
			confirmedEvidence = append(confirmedEvidence, "spki=unchanged")
		} else {
			confirmedEvidence = append(confirmedEvidence, "spki=changed")
		}
	}
	var confirmedParts []string
	if !previous.NotBefore.IsZero() && !current.NotBefore.IsZero() {
		confirmedParts = append(confirmedParts, fmt.Sprintf("predecessor issued %s, successor issued %s", previous.NotBefore.UTC().Format("2006-01-02"), current.NotBefore.UTC().Format("2006-01-02")))
		confirmedEvidence = append(confirmedEvidence, "previous_not_before="+previous.NotBefore.UTC().Format(time.RFC3339), "new_not_before="+current.NotBefore.UTC().Format(time.RFC3339))
	}
	if observation.DaysUntilExpiry > 0 {
		confirmedParts = append(confirmedParts, fmt.Sprintf("the successor had %d day(s) remaining when it was observed", observation.DaysUntilExpiry))
		confirmedEvidence = append(confirmedEvidence, fmt.Sprintf("days_until_expiry=%d", observation.DaysUntilExpiry))
	}
	appendCertificateFieldDifferences(&confirmedParts, &confirmedEvidence, &previous, &current)
	if len(confirmedParts) == 0 {
		confirmedParts = []string{"A different leaf certificate was observed; a pairwise public-key comparison is not a cause"}
	}
	return anomalyCause{
		confirmedReason:   strings.Join(confirmedParts, "; ") + ".",
		confirmedEvidence: confirmedEvidence,
	}
}

func summaryObservationCause(observation models.CertObservation) anomalyCause {
	return anomalyCause{
		inferredReason:   "A certificate replacement was observed; endpoint attribution and issuance details are pending longitudinal diagnosis.",
		inferredEvidence: []string{"new_fingerprint=" + firstNonEmpty(observation.Fingerprint, "missing"), "inference=insufficient_longitudinal_evidence"},
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
		return fmt.Sprintf("Different certificates were observed across sampled endpoints (%d observed event(s))", count)
	default:
		return fmt.Sprintf("Lifecycle event observed (%d event(s))", count)
	}
}

// appendEndpointPairEvidence adds the endpoint that served the predecessor leaf
// and the endpoint observed in this round. Both are needed to recheck any
// "same endpoint" claim after the fact; either may be absent on rows written
// before the endpoint pair was persisted.
func appendEndpointPairEvidence(evidence []string, row models.CertObservation) []string {
	if row.PreviousIPAddress != "" {
		evidence = append(evidence, "previous_endpoint_ip="+row.PreviousIPAddress)
	}
	if row.IPAddress != "" {
		evidence = append(evidence, "observed_endpoint_ip="+row.IPAddress)
	}
	if row.PreviousIPAddress != "" && row.IPAddress != "" {
		if row.PreviousIPAddress == row.IPAddress {
			evidence = append(evidence, "endpoint_comparison=same_endpoint")
		} else {
			evidence = append(evidence, "endpoint_comparison=different_endpoint")
		}
	} else {
		evidence = append(evidence, "endpoint_comparison=unknown")
	}
	return evidence
}

func lifecycleCause(row models.CertObservation, count int) anomalyCause {
	cause := anomalyCause{evidenceStatus: firstNonEmpty(row.EvidenceStatus, models.EvidenceStatusUnknown)}
	base := []string{"observation_type=" + row.ObservationType, fmt.Sprintf("observed_at=%s", row.ObservedAt.Format(time.RFC3339)), fmt.Sprintf("observed_events=%d", count)}
	switch row.ObservationType {
	case models.ObsSameKey:
		cause.confirmedReason = "A new leaf certificate was observed with the same SPKI fingerprint as its predecessor. This confirms same-key replacement at the observed endpoint."
		cause.confirmedEvidence = append(base, "spki=unchanged", "previous_fingerprint="+row.PreviousFingerprint, "new_fingerprint="+row.Fingerprint)
		// The reason above names "the observed endpoint", so the endpoint pair
		// has to travel with the evidence; otherwise the claim cannot be
		// rechecked from the finding alone.
		cause.confirmedEvidence = appendEndpointPairEvidence(cause.confirmedEvidence, row)
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
		// staleEndpointEvidence() only records this event when a retired address
		// still served the predecessor while a current address served the
		// successor. Those probes are the actual proof, so surface them here the
		// way deployment_failure already does instead of leaving the finding
		// resting on set inequality alone.
		cause.confirmedEvidence = appendEndpointPairEvidence(cause.confirmedEvidence, row)
		if row.EndpointProbes != "" {
			cause.confirmedEvidence = append(cause.confirmedEvidence, "endpoint_probes="+row.EndpointProbes)
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
		cause.confirmedReason = "Sampled endpoints of this name served different leaf certificates in the same measurement round."
		cause.confirmedEvidence = append(base, "measurement=multi_endpoint_tls_probe", "deployment_state=mixed_leaf_fingerprints", "previous_fingerprint="+row.PreviousFingerprint, "current_fingerprint="+row.Fingerprint)
		if row.EndpointProbes != "" {
			cause.confirmedEvidence = append(cause.confirmedEvidence, "endpoint_probes="+row.EndpointProbes)
		}
		cause.inferredReason = "Whether this is a stuck rollout, an intra-network inconsistency, or a still-settling replacement is decided from the endpoint structure, not from mixed fingerprints alone."
		cause.inferredEvidence = append([]string{}, cause.confirmedEvidence...)
		cause.inferredEvidence = append(cause.inferredEvidence, "interpretation=awaiting_endpoint_structure", "scope=sampled_resolved_endpoints")
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
	if !jsonableTime(cert.NotAfter) {
		return "invalid"
	}
	return cert.NotAfter.Format(time.RFC3339)
}

// jsonableTime is encoding/json's Time.MarshalJSON range: year in [0, 9999].
// Dates outside that range cannot be serialized and also cannot be used as
// remaining-life evidence.
func jsonableTime(value time.Time) bool {
	if value.IsZero() {
		return true
	}
	year := value.Year()
	return year >= 0 && year < 10000
}

func jsonableTimePtr(value *time.Time) *time.Time {
	if value == nil || !jsonableTime(*value) {
		return nil
	}
	return value
}

func sanitizeAnomalyJSONTimes(items []models.Anomaly) {
	for index := range items {
		if !jsonableTime(items[index].DetectedAt) {
			items[index].DetectedAt = time.Time{}
		}
		items[index].FirstObservedAt = jsonableTimePtr(items[index].FirstObservedAt)
		items[index].LastObservedAt = jsonableTimePtr(items[index].LastObservedAt)
		if items[index].Diagnosis == nil {
			continue
		}
		if investigation := items[index].Diagnosis.Investigation; investigation != nil {
			for certIndex := range investigation.Certificates {
				investigation.Certificates[certIndex].NotBefore = jsonableTimePtr(investigation.Certificates[certIndex].NotBefore)
				investigation.Certificates[certIndex].NotAfter = jsonableTimePtr(investigation.Certificates[certIndex].NotAfter)
			}
			for changeIndex := range investigation.ChangeSequence {
				if !jsonableTime(investigation.ChangeSequence[changeIndex].ObservedAt) {
					investigation.ChangeSequence[changeIndex].ObservedAt = time.Time{}
				}
			}
		}
		if caseFile := items[index].Diagnosis.EvidenceCase; caseFile != nil {
			if !jsonableTime(caseFile.GeneratedAt) {
				caseFile.GeneratedAt = time.Time{}
			}
			for roundIndex := range caseFile.Rounds {
				if !jsonableTime(caseFile.Rounds[roundIndex].ObservedAt) {
					caseFile.Rounds[roundIndex].ObservedAt = time.Time{}
				}
			}
		}
	}
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
	if err := d.db.Where(monitoredPredicate).Order("last_scanned_at DESC").First(&dc).Error; err != nil {
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
	const deployed = `FROM domain_certificates dc JOIN certificates c ON c.id = dc.current_certificate_id WHERE (dc.tranco_rank BETWEEN 1 AND 10000 OR dc.local_list_member = TRUE) AND dc.current_certificate_id <> 0 AND dc.status = 'active'`

	d.db.Model(&models.DomainCertificate{}).
		Where(monitoredPredicate+" AND current_certificate_id <> 0 AND status = ?", models.StatusActive).
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
		FROM cert_observations WHERE observation_type = 'change'
		  AND domain IN (SELECT domain FROM domain_certificates WHERE ` + monitoredPredicate + `)
		GROUP BY label`).Scan(&rl)
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
				WHERE (dc.tranco_rank BETWEEN 1 AND 10000 OR dc.local_list_member = TRUE) AND dc.current_certificate_id <> 0 AND dc.ari_window_start IS NOT NULL
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
