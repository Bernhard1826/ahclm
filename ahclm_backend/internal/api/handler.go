package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	deepanalysis "ahclm/internal/analysis"
	"ahclm/internal/database"
	"ahclm/internal/models"
	"ahclm/internal/propagation"
	"ahclm/internal/scanner"
	"ahclm/internal/scheduler"
	"ahclm/internal/tranco"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Handler serves the REST API.
type Handler struct {
	db           *database.Database
	scanner      *scanner.Scanner
	scheduler    *scheduler.Scheduler
	deepAnalysis *deepanalysis.Runner
	tranco       *tranco.Fetcher
	config       *models.Config
	propagation  *propagation.Manager
	startTime    time.Time
}

// SetPropagationManager attaches the optional CDN propagation experiment
// service while preserving NewHandler's existing constructor contract.
func (h *Handler) SetPropagationManager(manager *propagation.Manager) {
	h.propagation = manager
}

// NewHandler creates a new API handler.
func NewHandler(db *database.Database, scan *scanner.Scanner, sched *scheduler.Scheduler, tr *tranco.Fetcher, cfg *models.Config) *Handler {
	return &Handler{
		db:           db,
		scanner:      scan,
		scheduler:    sched,
		deepAnalysis: &deepanalysis.Runner{Scanner: scan},
		tranco:       tr,
		config:       cfg,
		startTime:    time.Now(),
	}
}

// SetupRouter wires all routes.
func (h *Handler) SetupRouter() *gin.Engine {
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:  h.config.Server.CORSOrigins,
		AllowMethods:  []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:  []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders: []string{"Content-Length"},
		MaxAge:        h.config.Server.CORSMaxAge,
	}))

	api := r.Group("/api")
	{
		api.GET("/health", h.health)
		api.GET("/config", h.runtimeConfig)
		api.GET("/stats", h.systemStats)

		// Domains (lifecycle state)
		api.GET("/domains", h.listDomains)
		api.GET("/domains/:domain", h.getDomain)
		api.GET("/domains/:domain/observations", h.getDomainObservations)
		api.GET("/domains/:domain/measurements", h.getDomainMeasurements)

		// Certificates (distinct certs inventory)
		api.GET("/certificates", h.listCertificates)
		api.GET("/certificates/expiring", h.expiringCertificates)
		api.GET("/certificates/expired", h.expiredCertificates)

		// Revocation & analysis
		api.GET("/revocations", h.revocations)
		api.GET("/analysis/anomalies", h.anomalies)
		api.GET("/analysis/diagnosis", h.diagnosis)
		api.GET("/analysis/patterns", h.patterns)
		api.GET("/analysis/key-cycle", h.keyCycle)
		api.GET("/analysis/mechanism-inference", h.mechanismInference)
		api.GET("/analysis/internal-evidence", h.listInternalEvidence)
		api.POST("/analysis/internal-evidence", h.importInternalEvidence)
		api.POST("/analysis/deep-probes", h.deepProbes)

		// Scanning
		api.POST("/scan", h.scanDomain)
		api.POST("/scan/batch", h.scanBatch)
		api.GET("/scan/status", h.scanStatus)
		api.GET("/scan/jobs", h.scanJobs)

		// CDN certificate propagation experiments
		api.GET("/cdn-propagation/config", h.cdnPropagationConfig)
		api.GET("/cdn-propagation", h.listCDNPropagation)
		api.POST("/cdn-propagation", h.startCDNPropagation)
		api.GET("/cdn-propagation/experiments/:id", h.getCDNPropagation)
		api.POST("/cdn-propagation/experiments/:id/cancel", h.cancelCDNPropagation)

		// Scheduler
		api.GET("/scheduler/status", h.schedulerStatus)
		api.POST("/scheduler/pause", h.pauseScheduler)
		api.POST("/scheduler/resume", h.resumeScheduler)
		api.POST("/scheduler/tranco", h.triggerTranco)
		api.POST("/scheduler/local-lists", h.triggerLocalLists)
		api.GET("/schedule/upcoming", h.upcomingSchedule)

		// Alerts
		api.GET("/alerts", h.getAlerts)
		api.POST("/alerts", h.createAlert)
		api.PUT("/alerts/:id", h.updateAlert)
		api.DELETE("/alerts/:id", h.deleteAlert)

		// Tranco
		api.GET("/tranco/latest", h.trancoLatest)
		api.POST("/tranco/fetch", h.triggerTranco)

		// Statistics
		api.GET("/statistics/daily", h.dailyStatistics)
	}

	return r
}

// ---------------------------------------------------------------------------
// Health & stats
// ---------------------------------------------------------------------------

func (h *Handler) health(c *gin.Context) {
	hc := &models.HealthCheck{
		Status:     "healthy",
		Database:   "connected",
		Scanner:    "ready",
		Scheduler:  "running",
		Tranco:     "disabled",
		LastScanAt: h.db.GetLastScanTime(),
	}
	if err := h.db.Ping(); err != nil {
		hc.Status = "degraded"
		hc.Database = "error"
		hc.Errors = append(hc.Errors, err.Error())
	}
	if h.scheduler != nil && h.scheduler.IsPaused() {
		hc.Scheduler = "paused"
	}
	if h.config.Tranco.Enabled {
		hc.Tranco = "ready"
	}
	h.ok(c, hc)
}

// runtimeConfig exposes non-secret effective settings so the UI can display
// what was actually loaded. Credentials and passwords are never serialized.
func (h *Handler) runtimeConfig(c *gin.Context) {
	cfg := h.config
	h.ok(c, gin.H{
		"server":      gin.H{"host": cfg.Server.Host, "port": cfg.Server.Port, "cors": cfg.Server.CORS, "cors_origins": cfg.Server.CORSOrigins},
		"database":    gin.H{"host": cfg.Database.Host, "port": cfg.Database.Port, "database": cfg.Database.Database, "sslmode": cfg.Database.SSLMode, "max_open_connections": cfg.Database.MaxOpenConnections, "max_idle_connections": cfg.Database.MaxIdleConnections, "conn_max_lifetime": cfg.Database.ConnMaxLifetime.String()},
		"scanner":     gin.H{"tls_port": cfg.Scanner.TLSPort, "timeout": cfg.Scanner.Timeout.String(), "workers": cfg.Scanner.Workers, "rate_limit": cfg.Scanner.RateLimit, "check_revocation": cfg.Scanner.CheckRevocation, "check_crl": cfg.Scanner.CheckCRL, "check_ari": cfg.Scanner.CheckARI, "dns_resolvers": cfg.Scanner.DNSResolvers, "max_endpoint_samples": cfg.Scanner.MaxEndpointSamples, "endpoint_handshakes": cfg.Scanner.EndpointHandshakes, "endpoint_probe_concurrency": cfg.Scanner.EndpointProbeConcurrency, "related_name_probe_limit": cfg.Scanner.RelatedNameProbeLimit, "related_name_probe_timeout": cfg.Scanner.RelatedNameProbeTimeout.String(), "check_caa": cfg.Scanner.CheckCAA, "check_ct": cfg.Scanner.CheckCT, "ct_endpoint": cfg.Scanner.CTEndpoint, "check_http_fingerprint": cfg.Scanner.CheckHTTPFingerprint, "check_rdap": cfg.Scanner.CheckRDAP, "rdap_endpoint": cfg.Scanner.RDAPEndpoint, "check_asn": cfg.Scanner.CheckASN, "check_ripestat": cfg.Scanner.CheckRIPEstat, "check_official_prefixes": cfg.Scanner.CheckOfficialPrefixes, "check_chrome_log_list": cfg.Scanner.CheckChromeLogList, "check_apple_log_list": cfg.Scanner.CheckAppleLogList, "check_sct_inclusion": cfg.Scanner.CheckSCTInclusion, "check_certspotter": cfg.Scanner.CheckCertSpotter, "official_cdn_prefixes": models.DatasetPrefixCount(), "chrome_ct_logs": models.DatasetLogListCount("chrome"), "apple_ct_logs": models.DatasetLogListCount("apple")},
		"scheduler":   gin.H{"enabled": cfg.Scheduler.Enabled, "milestones": cfg.Scheduler.Milestones, "post_expiry_checks": cfg.Scheduler.PostExpiryChecks, "baseline_interval": cfg.Scheduler.BaselineInterval.String(), "near_expiry_interval": cfg.Scheduler.NearExpiryInterval.String(), "min_gap": cfg.Scheduler.MinGap.String(), "ari_poll_interval": cfg.Scheduler.ARIPollInterval.String(), "revocation_poll_interval": cfg.Scheduler.RevocationPollInterval.String(), "max_daily_scans": cfg.Scheduler.MaxDailyScans},
		"propagation": gin.H{"enabled": cfg.Propagation.Enabled, "auto_start_on_change": cfg.Propagation.AutoStartOnChange, "cdn_only": cfg.Propagation.CDNOnly, "watch_window": cfg.Propagation.WatchWindow.String(), "poll_interval": cfg.Propagation.PollInterval.String(), "max_duration": cfg.Propagation.MaxDuration.String(), "stable_rounds": cfg.Propagation.StableRounds, "locations": models.NormalizePropagationLocations(cfg.Propagation.Locations), "timeout": cfg.Propagation.Timeout.String(), "max_active": cfg.Propagation.MaxActive},
		"tranco":      gin.H{"enabled": cfg.Tranco.Enabled, "source_url": cfg.Tranco.SourceURL, "max_domains": cfg.Tranco.MaxDomains, "refresh_interval": cfg.Tranco.RefreshInterval.String(), "fetch_on_start": cfg.Tranco.FetchOnStart},
		"local_lists": gin.H{"enabled": cfg.LocalLists.Enabled, "refresh_interval": cfg.LocalLists.RefreshInterval.String(), "fetch_on_start": cfg.LocalLists.FetchOnStart, "sources": cfg.LocalLists.Sources},
	})
}

func (h *Handler) systemStats(c *gin.Context) {
	stats := h.db.GetSystemStats()
	stats.StartTime = h.startTime
	stats.Uptime = time.Since(h.startTime).Round(time.Second).String()
	if h.scheduler != nil {
		q := h.scheduler.GetQueueStatus()
		stats.QueueDepth = q.Pending + q.Running
	}
	h.ok(c, stats)
}

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

func (h *Handler) listDomains(c *gin.Context) {
	f := h.filter(c)
	dcs, total, err := h.db.ListDomains(f)
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	views := make([]models.DomainView, 0, len(dcs))
	for i := range dcs {
		views = append(views, toDomainView(&dcs[i]))
	}
	h.paginated(c, views, f.Page, f.PerPage, total)
}

func (h *Handler) getDomain(c *gin.Context) {
	domain := models.GetDomain(c.Param("domain"))
	dc, err := h.db.GetDomainCertificate(domain)
	if err != nil {
		h.fail(c, http.StatusNotFound, fmt.Errorf("domain not found"))
		return
	}
	response := gin.H{
		"domain":              dc,
		"view":                toDomainView(dc),
		"current_certificate": dc.CurrentCertificate,
	}
	h.ok(c, response)
}

func (h *Handler) getDomainObservations(c *gin.Context) {
	domain := models.GetDomain(c.Param("domain"))
	limit := queryInt(c, "limit", 200)
	obs, err := h.db.GetDomainTimeline(domain, limit)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrDomainNotMonitored) {
			h.fail(c, http.StatusNotFound, fmt.Errorf("domain not found"))
			return
		}
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"domain": domain, "count": len(obs), "observations": obs})
}

func (h *Handler) getDomainMeasurements(c *gin.Context) {
	domain := models.GetDomain(c.Param("domain"))
	limit := queryInt(c, "limit", 120)
	snapshots, err := h.db.GetMeasurementSnapshots(domain, limit)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrDomainNotMonitored) {
			h.fail(c, http.StatusNotFound, fmt.Errorf("domain not found"))
			return
		}
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"domain": domain, "count": len(snapshots), "measurements": snapshots})
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

func (h *Handler) listCertificates(c *gin.Context) {
	f := h.filter(c)
	certs, total, err := h.db.ListCertificates(f)
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.paginated(c, certs, f.Page, f.PerPage, total)
}

func (h *Handler) expiringCertificates(c *gin.Context) {
	days := queryInt(c, "days", 7)
	dcs, err := h.db.GetExpiringDomains(days)
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"days": days, "count": len(dcs), "domains": domainViews(dcs)})
}

func (h *Handler) expiredCertificates(c *gin.Context) {
	dcs, err := h.db.GetExpiredDomains()
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"count": len(dcs), "domains": domainViews(dcs)})
}

// ---------------------------------------------------------------------------
// Revocation & analysis
// ---------------------------------------------------------------------------

func (h *Handler) revocations(c *gin.Context) {
	dcs, err := h.db.GetRevokedDomains()
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"count": len(dcs), "domains": domainViews(dcs)})
}

func (h *Handler) anomalies(c *gin.Context) {
	perPage := queryInt(c, "per_page", 0)
	if perPage == 0 {
		// Preserve compatibility with existing clients that send limit while
		// making the server-side result complete and explicitly paginated.
		perPage = queryInt(c, "limit", 100)
	}
	perPage = clamp(perPage, 1, 500)
	page := queryInt(c, "page", 1)
	if page < 1 {
		page = 1
	}
	var items []models.Anomaly
	var total int
	var err error
	if c.Query("summary") == "1" || strings.EqualFold(c.Query("summary"), "true") {
		items, total, err = h.db.GetAnomaliesSummaryPage(page, perPage, c.Query("type"), models.GetDomain(c.Query("domain")))
	} else {
		items, total, err = h.db.GetAnomaliesPage(page, perPage, c.Query("type"), models.GetDomain(c.Query("domain")))
	}
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	compact := c.Query("compact") == "1" || strings.EqualFold(c.Query("compact"), "true")
	if compact {
		for i := range items {
			items[i].Evidence = nil
			items[i].ConfirmedEvidence = nil
			items[i].InferredEvidence = nil
		}
	}
	totalPages := 0
	if total > 0 {
		totalPages = (total + perPage - 1) / perPage
	}
	h.ok(c, gin.H{"count": total, "page": page, "per_page": perPage, "total_pages": totalPages, "anomalies": items})
}

func (h *Handler) diagnosis(c *gin.Context) {
	domain := models.GetDomain(c.Query("domain"))
	if domain == "" {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("domain is required"))
		return
	}
	diagnosis, err := h.db.GetDomainDiagnosisFor(domain, c.Query("type"))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.fail(c, http.StatusNotFound, fmt.Errorf("domain not found"))
			return
		}
		h.fail(c, http.StatusInternalServerError, fmt.Errorf("load diagnosis: %w", err))
		return
	}
	h.ok(c, gin.H{"domain": domain, "type": diagnosisTypeLabel(c.Query("type")), "diagnosis": diagnosis})
}

func diagnosisTypeLabel(requested string) string {
	if strings.TrimSpace(requested) == "" {
		return ""
	}
	return requested
}

func (h *Handler) patterns(c *gin.Context) {
	h.ok(c, h.db.GetPatterns())
}

func (h *Handler) keyCycle(c *gin.Context) {
	domain := models.GetDomain(c.Query("domain"))
	if domain == "" {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("domain is required"))
		return
	}
	cycle, err := h.db.GetPublicKeyDeploymentCycle(domain)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.fail(c, http.StatusNotFound, fmt.Errorf("domain not found"))
			return
		}
		h.fail(c, http.StatusInternalServerError, fmt.Errorf("load key cycle: %w", err))
		return
	}
	h.ok(c, gin.H{"domain": domain, "key_cycle": cycle})
}

func (h *Handler) mechanismInference(c *gin.Context) {
	domain := models.GetDomain(c.Query("domain"))
	if domain == "" {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("domain is required"))
		return
	}
	observations, err := h.db.GetDomainTimeline(domain, 1000)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.fail(c, http.StatusNotFound, fmt.Errorf("domain not found"))
			return
		}
		h.fail(c, http.StatusInternalServerError, fmt.Errorf("load observations: %w", err))
		return
	}
	snapshots, err := h.db.GetMeasurementSnapshots(domain, 20)
	if err != nil {
		h.fail(c, http.StatusInternalServerError, fmt.Errorf("load measurements: %w", err))
		return
	}
	var probes []models.EndpointProbe
	for _, snapshot := range snapshots {
		if strings.TrimSpace(snapshot.EndpointProbesJSON) == "" {
			continue
		}
		if err := json.Unmarshal([]byte(snapshot.EndpointProbesJSON), &probes); err == nil {
			break
		}
		probes = nil
	}
	seen := map[string]struct{}{}
	for _, observation := range observations {
		if observation.Fingerprint != "" {
			seen[observation.Fingerprint] = struct{}{}
		}
		if observation.PreviousFingerprint != "" {
			seen[observation.PreviousFingerprint] = struct{}{}
		}
	}
	for _, probe := range probes {
		if probe.Fingerprint != "" {
			seen[probe.Fingerprint] = struct{}{}
		}
	}
	certs := make([]models.Certificate, 0, len(seen))
	for fingerprint := range seen {
		cert, err := h.db.GetCertificateByFingerprint(fingerprint)
		if err != nil || cert == nil {
			continue
		}
		certs = append(certs, *cert)
	}
	report := deepanalysis.InferMechanisms(domain, certs, observations, probes)
	h.ok(c, gin.H{"domain": domain, "mechanism_inference": report})
}

func (h *Handler) listInternalEvidence(c *gin.Context) {
	domain := models.GetDomain(c.Query("domain"))
	if domain == "" {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("domain is required"))
		return
	}
	events, err := h.db.GetInternalEvidence(domain, queryInt(c, "limit", 500))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.fail(c, http.StatusNotFound, fmt.Errorf("domain not found"))
			return
		}
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"domain": domain, "count": len(events), "events": events})
}

func (h *Handler) importInternalEvidence(c *gin.Context) {
	var body struct {
		Events []models.InternalEvidenceEvent `json:"events"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	if len(body.Events) == 0 {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("events is required"))
		return
	}
	if err := h.db.CreateInternalEvidenceBatch(body.Events); err != nil {
		if errors.Is(err, database.ErrDomainNotMonitored) {
			h.fail(c, http.StatusNotFound, err)
			return
		}
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	h.ok(c, gin.H{"imported": len(body.Events)})
}

// deepProbes runs a deliberately operator-triggered experiment. Scheduled
// survey measurements remain in the scanner/scheduler path; these probes are
// returned as an auditable report for explaining one already observed finding.
func (h *Handler) deepProbes(c *gin.Context) {
	if h.deepAnalysis == nil {
		h.fail(c, http.StatusServiceUnavailable, fmt.Errorf("deep diagnosis is unavailable"))
		return
	}
	var req struct {
		Domain     string   `json:"domain" binding:"required"`
		Addresses  []string `json:"addresses"`
		Experiment string   `json:"experiment" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	domain := models.GetDomain(req.Domain)
	if err := scanner.ValidateDomain(domain); err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	if len(req.Addresses) > 32 {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("at most 32 addresses may be probed"))
		return
	}
	for _, address := range req.Addresses {
		if !models.IsPublicIP(address) {
			h.fail(c, http.StatusBadRequest, fmt.Errorf("address %q is not a public IP", address))
			return
		}
	}
	if req.Experiment != deepanalysis.ExperimentSNISelection && req.Experiment != deepanalysis.ExperimentRepeatHandshake && req.Experiment != deepanalysis.ExperimentHTTPRoute {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("unknown experiment %q", req.Experiment))
		return
	}
	timeout := 2 * time.Minute
	if h.config != nil && h.config.Scanner.Timeout > 0 {
		timeout = h.config.Scanner.Timeout * 8
		if timeout < 30*time.Second {
			timeout = 30 * time.Second
		}
		if timeout > 5*time.Minute {
			timeout = 5 * time.Minute
		}
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
	defer cancel()
	report, err := h.deepAnalysis.Run(ctx, deepanalysis.Request{Domain: domain, Addresses: req.Addresses, Experiment: req.Experiment})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			h.fail(c, http.StatusGatewayTimeout, fmt.Errorf("deep diagnosis timed out after %s", timeout.Round(time.Second)))
			return
		}
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	h.ok(c, report)
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

func (h *Handler) scanDomain(c *gin.Context) {
	var req struct {
		Domain string `json:"domain" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	if err := scanner.ValidateDomain(req.Domain); err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	result, err := h.scheduler.ScanNow(req.Domain)
	if err != nil {
		if errors.Is(err, database.ErrDomainNotMonitored) {
			h.fail(c, http.StatusNotFound, fmt.Errorf("domain is not in the current monitoring population"))
			return
		}
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, result)
}

func (h *Handler) scanBatch(c *gin.Context) {
	var req struct {
		Domains []string `json:"domains" binding:"required"`
		Workers int      `json:"workers"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	results, errs := h.scheduler.ScanBatchNow(req.Domains, req.Workers)
	errStrs := make([]string, 0, len(errs))
	succeeded := 0
	for _, e := range errs {
		errStrs = append(errStrs, e.Error())
	}
	for _, result := range results {
		if result != nil && result.Success {
			succeeded++
		}
	}
	h.ok(c, gin.H{"total": len(req.Domains), "succeeded": succeeded, "results": results, "errors": errStrs})
}

func (h *Handler) scanStatus(c *gin.Context) {
	if h.scheduler == nil {
		h.ok(c, &models.ScanQueue{})
		return
	}
	h.ok(c, h.scheduler.GetQueueStatus())
}

func (h *Handler) scanJobs(c *gin.Context) {
	jobs, err := h.db.ListScanJobs(clamp(queryInt(c, "limit", 100), 1, 1000))
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"count": len(jobs), "jobs": jobs})
}

func (h *Handler) cdnPropagationConfig(c *gin.Context) {
	cfg := h.config.Propagation
	h.ok(c, gin.H{
		"enabled":                           cfg.Enabled,
		"auto_start_on_change":              cfg.AutoStartOnChange,
		"cdn_only":                          cfg.CDNOnly,
		"watch_window_seconds":              int64(cfg.WatchWindow / time.Second),
		"poll_interval_seconds":             int64(cfg.PollInterval / time.Second),
		"max_duration_seconds":              int64(cfg.MaxDuration / time.Second),
		"stable_rounds":                     cfg.StableRounds,
		"locations":                         models.NormalizePropagationLocations(cfg.Locations),
		"certificate_layers":                []string{models.CDNPropagationLayerEdge, models.CDNPropagationLayerOrigin, models.CDNPropagationLayerOriginViaCDN},
		"provider":                          "Globalping",
		"origin_probe_target_required":      true,
		"origin_probe_target_type":          "public_ip",
		"origin_probe_host_role":            "TLS SNI and HTTP Host",
		"probe_path_cache_busting":          true,
		"origin_certificate_proof_required": true,
		"origin_probe_path":                 "/.well-known/ahclm-origin",
		"max_active":                        cfg.MaxActive,
		"requires_monitored_domain":         true,
	})
}

func (h *Handler) listCDNPropagation(c *gin.Context) {
	items, err := h.db.ListCDNPropagationExperiments(c.Query("domain"), c.Query("status"), clamp(queryInt(c, "limit", 100), 1, 500))
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"count": len(items), "experiments": items})
}

func (h *Handler) startCDNPropagation(c *gin.Context) {
	if h.propagation == nil {
		h.fail(c, http.StatusServiceUnavailable, fmt.Errorf("CDN propagation measurement is unavailable"))
		return
	}
	var req models.CDNPropagationStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	if err := scanner.ValidateDomain(req.Domain); err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	experiment, err := h.propagation.StartExperiment(req)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, database.ErrDomainNotMonitored) {
			status = http.StatusNotFound
		}
		h.fail(c, status, err)
		return
	}
	report, err := h.db.GetCDNPropagationReport(experiment.ID)
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusCreated, models.APIResponse{Success: true, Data: report, Timestamp: time.Now()})
}

func (h *Handler) getCDNPropagation(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("invalid experiment id"))
		return
	}
	report, err := h.db.GetCDNPropagationReport(uint(id))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.fail(c, http.StatusNotFound, fmt.Errorf("CDN propagation experiment not found"))
			return
		}
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, report)
}

func (h *Handler) cancelCDNPropagation(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("invalid experiment id"))
		return
	}
	if _, err := h.db.GetCDNPropagationExperiment(uint(id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.fail(c, http.StatusNotFound, fmt.Errorf("CDN propagation experiment not found"))
			return
		}
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	if err := h.db.CancelCDNPropagationExperiment(uint(id), time.Now().UTC()); err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	experiment, err := h.db.GetCDNPropagationExperiment(uint(id))
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"status": experiment.Status})
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

func (h *Handler) schedulerStatus(c *gin.Context) {
	if h.scheduler == nil {
		h.ok(c, gin.H{"enabled": false})
		return
	}
	h.ok(c, gin.H{
		"enabled":      h.config.Scheduler.Enabled,
		"paused":       h.scheduler.IsPaused(),
		"queue_status": h.scheduler.GetQueueStatus(),
		"pending":      h.scheduler.GetPendingCount(),
		"milestones":   h.config.Scheduler.Milestones,
	})
}

func (h *Handler) pauseScheduler(c *gin.Context) {
	if h.scheduler != nil {
		h.scheduler.Pause()
	}
	h.ok(c, gin.H{"status": "paused"})
}

func (h *Handler) resumeScheduler(c *gin.Context) {
	if h.scheduler != nil {
		h.scheduler.Resume()
	}
	h.ok(c, gin.H{"status": "resumed"})
}

func (h *Handler) triggerTranco(c *gin.Context) {
	if h.scheduler == nil {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("scheduler not configured"))
		return
	}
	n, err := h.scheduler.ScheduleTrancoScans()
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"status": "registered", "domains": n})
}

func (h *Handler) triggerLocalLists(c *gin.Context) {
	if h.scheduler == nil {
		h.fail(c, http.StatusBadRequest, fmt.Errorf("scheduler not configured"))
		return
	}
	n, err := h.scheduler.RefreshLocalLists(c.Request.Context())
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"status": "registered", "domains": n})
}

func (h *Handler) upcomingSchedule(c *gin.Context) {
	limit := queryInt(c, "limit", 100)
	dcs, err := h.db.GetUpcomingSchedule(limit)
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	now := time.Now()
	entries := make([]models.ScheduleEntry, 0, len(dcs))
	for i := range dcs {
		dc := &dcs[i]
		e := models.ScheduleEntry{
			Domain:             dc.Domain,
			NextScanAt:         dc.NextScanAt,
			InSeconds:          int64(dc.NextScanAt.Sub(now).Seconds()),
			Priority:           dc.Priority,
			CurrentFingerprint: dc.CurrentFingerprint,
		}
		if dc.CurrentCertificate != nil {
			e.DaysUntilExpiry = models.DaysUntil(dc.CurrentCertificate.NotAfter, now)
			e.Reason = scheduleReason(dc.CurrentCertificate.NotAfter, now)
		} else {
			e.Reason = "initial scan"
		}
		entries = append(entries, e)
	}
	h.ok(c, gin.H{"count": len(entries), "schedule": entries})
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

func (h *Handler) getAlerts(c *gin.Context) {
	alerts, err := h.db.GetAlerts()
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, alerts)
}

func (h *Handler) createAlert(c *gin.Context) {
	var a models.CertificateAlert
	if err := c.ShouldBindJSON(&a); err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	if err := h.db.CreateAlert(&a); err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusCreated, models.APIResponse{Success: true, Data: a, Timestamp: time.Now()})
}

func (h *Handler) updateAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	var a models.CertificateAlert
	if err := c.ShouldBindJSON(&a); err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	a.ID = uint(id)
	if err := h.db.UpdateAlert(&a); err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, a)
}

func (h *Handler) deleteAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		h.fail(c, http.StatusBadRequest, err)
		return
	}
	if err := h.db.DeleteAlert(uint(id)); err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, gin.H{"deleted": true})
}

// ---------------------------------------------------------------------------
// Tranco & statistics
// ---------------------------------------------------------------------------

func (h *Handler) trancoLatest(c *gin.Context) {
	list, err := h.db.GetLatestTrancoList()
	if err != nil {
		h.fail(c, http.StatusNotFound, fmt.Errorf("no tranco list fetched yet"))
		return
	}
	h.ok(c, list)
}

func (h *Handler) dailyStatistics(c *gin.Context) {
	end := time.Now()
	start := end.AddDate(0, 0, -30)
	if s := c.Query("start"); s != "" {
		if t, err := time.Parse("2006-01-02", s); err == nil {
			start = t
		}
	}
	if e := c.Query("end"); e != "" {
		if t, err := time.Parse("2006-01-02", e); err == nil {
			end = t
		}
	}
	stats, err := h.db.GetDailyStats(start, end)
	if err != nil {
		h.fail(c, http.StatusInternalServerError, err)
		return
	}
	h.ok(c, stats)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (h *Handler) filter(c *gin.Context) *models.CertificateFilter {
	return &models.CertificateFilter{
		Domain:       c.Query("domain"),
		Issuer:       c.Query("issuer"),
		Status:       c.Query("status"),
		Revocation:   c.Query("revocation"),
		ExpiringDays: queryInt(c, "expiring_days", 0),
		Expired:      c.Query("expired") == "true",
		Page:         queryInt(c, "page", 1),
		PerPage:      clamp(queryInt(c, "per_page", 50), 1, 500),
		SortBy:       c.DefaultQuery("sort_by", ""),
		SortOrder:    c.DefaultQuery("sort_order", "desc"),
	}
}

func (h *Handler) ok(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, models.APIResponse{Success: true, Data: data, Timestamp: time.Now()})
}

func (h *Handler) fail(c *gin.Context, status int, err error) {
	c.JSON(status, models.APIResponse{Success: false, Error: err.Error(), Timestamp: time.Now()})
}

func (h *Handler) paginated(c *gin.Context, data interface{}, page, perPage int, total int64) {
	totalPages := 0
	if perPage > 0 {
		totalPages = int((total + int64(perPage) - 1) / int64(perPage))
	}
	c.JSON(http.StatusOK, models.PaginatedResponse{
		Success: true,
		Data:    data,
		Pagination: models.Pagination{
			Page: page, PerPage: perPage, Total: total, TotalPages: totalPages,
		},
	})
}

func toDomainView(dc *models.DomainCertificate) models.DomainView {
	v := models.DomainView{
		Domain:                dc.Domain,
		TrancoRank:            dc.TrancoRank,
		LocalListMember:       dc.LocalListMember,
		Status:                dc.Status,
		RevocationStatus:      dc.RevocationStatus,
		CurrentFingerprint:    dc.CurrentFingerprint,
		LastScannedAt:         dc.LastScannedAt,
		NextScanAt:            dc.NextScanAt,
		LastChangedAt:         dc.LastChangedAt,
		ChangeCount:           dc.ChangeCount,
		ScanCount:             dc.ScanCount,
		ARIStatus:             dc.ARIStatus,
		ARIWindowStart:        dc.ARIWindowStart,
		ARIWindowEnd:          dc.ARIWindowEnd,
		ARIEmergency:          dc.ARIEmergency,
		EvidenceStatus:        evidenceStatusValue(dc.EvidenceStatus),
		EvidencePendingReason: dc.EvidencePendingReason,
	}
	if dc.CurrentCertificate != nil {
		cert := dc.CurrentCertificate
		na := cert.NotAfter
		v.Issuer = cert.IssuerCN
		v.NotAfter = &na
		v.DaysUntilExpiry = models.DaysUntil(cert.NotAfter, time.Now())
		v.ExpirationStatus = models.ExpirationStatus(cert.NotAfter, time.Now())
	}
	return v
}

func evidenceStatusValue(value string) string {
	if value == "" {
		return models.EvidenceStatusUnknown
	}
	return value
}

func domainViews(dcs []models.DomainCertificate) []models.DomainView {
	out := make([]models.DomainView, 0, len(dcs))
	for i := range dcs {
		out = append(out, toDomainView(&dcs[i]))
	}
	return out
}

func scheduleReason(notAfter, now time.Time) string {
	d := models.DaysUntil(notAfter, now)
	switch {
	case d < 0:
		return "post-expiry check"
	case d <= 1:
		return "expires within 1 day"
	case d <= 7:
		return fmt.Sprintf("expiry milestone (~%dd)", d)
	case d <= 30:
		return fmt.Sprintf("approaching expiry (~%dd)", d)
	default:
		return "baseline rescan"
	}
}

func queryInt(c *gin.Context, key string, def int) int {
	if v := c.Query(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
