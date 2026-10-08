package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ahclm/internal/alerts"
	"ahclm/internal/api"
	"ahclm/internal/database"
	"ahclm/internal/models"
	"ahclm/internal/propagation"
	"ahclm/internal/scanner"
	"ahclm/internal/scheduler"
	"ahclm/internal/tranco"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

var (
	configPath string
	printVer   bool
)

const version = "2.0.0"

func init() {
	flag.StringVar(&configPath, "config", "", "Path to required config file")
	flag.BoolVar(&printVer, "version", false, "Print version and exit")
}

func main() {
	flag.Parse()
	if printVer {
		fmt.Printf("AHCLM - Adaptive HTTPS Certificate Lifecycle Monitor v%s\n", version)
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	log.Printf("Starting AHCLM v%s", version)
	log.Printf("API server: %s:%d", cfg.Server.Host, cfg.Server.Port)

	// Database (PostgreSQL; the target DB is created automatically if missing).
	db, err := database.New(&cfg.Database)
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}
	defer db.Close()
	log.Printf("Database connected: %s@%s:%d/%s", cfg.Database.User, cfg.Database.Host, cfg.Database.Port, cfg.Database.Database)

	// Scanner.
	scan, err := scanner.NewScanner(&cfg.Scanner, db)
	if err != nil {
		log.Fatalf("failed to initialize scanner: %v", err)
	}
	defer scan.Close()
	log.Printf("Scanner ready (workers=%d, revocation=%v, crl=%v)", cfg.Scanner.Workers, cfg.Scanner.CheckRevocation, cfg.Scanner.CheckCRL)

	// Tranco fetcher + scheduler.
	trancoFetcher := tranco.NewFetcher(&cfg.Tranco)
	sched := scheduler.NewScheduler(&cfg.Scheduler, &cfg.Scanner, db, scan, trancoFetcher)
	sched.SetLocalLists(&cfg.LocalLists)
	propagationManager := propagation.NewManager(&cfg.Propagation, db, scan)
	sched.SetPropagationManager(propagationManager)

	notifier := alerts.NewNotifier(&cfg.Alerts, db)
	sched.SetOnAlert(notifier.Handle)
	sched.SetOnScanComplete(func(r *models.ScanResult) {
		status := "ok"
		if !r.Success {
			failureClass := r.FailureClass
			if failureClass == "" {
				failureClass = models.ScanFailureUnknown
			}
			status = "fail[" + failureClass + "]:" + r.Error
		}
		log.Printf("scan %s [%s] rev=%s %dms", r.Domain, status, r.RevocationStatus, r.ScanDuration.Milliseconds())
	})

	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()
	// Open rollouts are placed in the measured distribution of completed ones;
	// the alert share applied to that position is an operator standard.
	database.SetRolloutAlertShare(cfg.Analysis.RolloutAlertShare)
	db.StartRolloutReference(appCtx, cfg.Analysis.RolloutReferenceRefresh)

	// Synchronize the population before the scheduler can dispatch anything.
	// A failed initial fetch is fatal: running with an old or manually seeded
	// ranked population would violate the configured monitoring contract.
	if cfg.Tranco.Enabled && cfg.Tranco.FetchOnStart {
		log.Printf("fetching Tranco top %d ...", cfg.Tranco.MaxDomains)
		n, err := sched.ScheduleTrancoScans()
		if err != nil {
			log.Fatalf("initial Tranco fetch failed: %v", err)
		}
		log.Printf("Tranco: %d domains registered for scanning", n)
	}
	if cfg.LocalLists.Enabled && cfg.LocalLists.FetchOnStart {
		log.Printf("loading %d local domain lists ...", len(cfg.LocalLists.Sources))
		n, err := sched.RefreshLocalLists(appCtx)
		if err != nil {
			log.Fatalf("initial local list refresh failed: %v", err)
		}
		log.Printf("local lists: %d domains registered for scanning", n)
	}
	if err := propagationManager.Start(appCtx); err != nil {
		log.Fatalf("failed to start CDN propagation worker: %v", err)
	}
	if cfg.Propagation.Enabled {
		log.Printf("CDN propagation worker started (locations=%v, interval=%s)", models.NormalizePropagationLocations(cfg.Propagation.Locations), cfg.Propagation.PollInterval)
	} else {
		log.Printf("CDN propagation worker ready for manually requested experiments")
	}

	if err := sched.Start(); err != nil {
		log.Fatalf("failed to start scheduler: %v", err)
	}
	log.Printf("Scheduler started (milestones=%v, baseline=%s)", cfg.Scheduler.Milestones, cfg.Scheduler.BaselineInterval)

	// Refresh the Tranco list daily. Each refresh quiesces scans while it
	// removes domains that fell out of the current Top-N list.
	if cfg.Tranco.Enabled {
		go trancoRefreshLoop(appCtx, sched, cfg.Tranco.RefreshInterval)
	}
	if cfg.LocalLists.Enabled {
		go localListsRefreshLoop(appCtx, sched, cfg.LocalLists.RefreshInterval)
	}

	// HTTP server.
	handler := api.NewHandler(db, scan, sched, trancoFetcher, cfg)
	handler.SetPropagationManager(propagationManager)
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      handler.SetupRouter(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}
	go func() {
		log.Printf("API listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()
	// Build the issue-register snapshot before a user opens the anomaly page.
	// This work is intentionally asynchronous so it does not delay health checks
	// or API startup; concurrent page requests share the same cache build.
	go func() {
		startedAt := time.Now()
		if _, _, err := db.GetAnomaliesSummaryPage(1, 1, "", ""); err != nil {
			log.Printf("anomaly summary cache warm failed: %v", err)
			return
		}
		log.Printf("anomaly summary cache warmed in %s", time.Since(startedAt).Round(time.Millisecond))
	}()

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down ...")

	appCancel()
	propagationManager.Stop()
	sched.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("forced shutdown: %v", err)
	}
	log.Println("stopped")
}

func trancoRefreshLoop(ctx context.Context, sched *scheduler.Scheduler, refreshInterval time.Duration) {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := sched.ScheduleTrancoScans(); err != nil {
				log.Printf("scheduled Tranco refresh failed: %v", err)
			}
		}
	}
}

func localListsRefreshLoop(ctx context.Context, sched *scheduler.Scheduler, refreshInterval time.Duration) {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := sched.RefreshLocalLists(ctx); err != nil {
				log.Printf("scheduled local list refresh failed: %v", err)
			}
		}
	}
}

// loadConfig requires an explicit configuration file, then applies the small
// set of documented deployment environment overrides. It never synthesizes a
// runnable configuration from built-in values.
func loadConfig() (*models.Config, error) {
	path := strings.TrimSpace(configPath)
	if path == "" {
		path = firstEnv("AHCLM_CONFIG_FILE")
	}
	if path == "" {
		return nil, fmt.Errorf("--config or AHCLM_CONFIG_FILE is required")
	}

	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	cfg := &models.Config{}
	hook := viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
	))
	if err := v.Unmarshal(cfg, hook); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", v.ConfigFileUsed(), err)
	}
	configDir := filepath.Dir(v.ConfigFileUsed())
	for i := range cfg.LocalLists.Sources {
		if path := strings.TrimSpace(cfg.LocalLists.Sources[i].Path); path != "" && !filepath.IsAbs(path) {
			cfg.LocalLists.Sources[i].Path = filepath.Clean(filepath.Join(configDir, path))
		}
	}
	log.Printf("loaded config from %s", v.ConfigFileUsed())

	// Environment overrides.
	if v := firstEnv("AHCLM_BACKEND_HOST", "AHCLM_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if err := setEnvInt(firstEnv("AHCLM_BACKEND_PORT", "AHCLM_PORT"), "AHCLM_BACKEND_PORT", &cfg.Server.Port); err != nil {
		return nil, err
	}
	if v := firstEnv("AHCLM_DB_HOST", "AHCLM_DATABASE_HOST"); v != "" {
		cfg.Database.Host = v
	}
	if err := setEnvInt(firstEnv("AHCLM_DB_PORT", "AHCLM_DATABASE_PORT"), "AHCLM_DB_PORT", &cfg.Database.Port); err != nil {
		return nil, err
	}
	if v := firstEnv("AHCLM_DB_USER", "AHCLM_DATABASE_USER"); v != "" {
		cfg.Database.User = v
	}
	if v := firstEnv("AHCLM_DB_PASSWORD", "AHCLM_DATABASE_PASSWORD"); v != "" {
		cfg.Database.Password = v
	}
	if v := firstEnv("AHCLM_DB_NAME", "AHCLM_DATABASE_NAME"); v != "" {
		cfg.Database.Database = v
	}
	if err := setEnvInt(firstEnv("AHCLM_WORKERS"), "AHCLM_WORKERS", &cfg.Scanner.Workers); err != nil {
		return nil, err
	}
	if v := firstEnv("AHCLM_GLOBALPING_TOKEN"); v != "" {
		cfg.Scanner.GlobalProbeToken = v
	}
	return cfg, nil
}

func setEnvInt(raw, name string, target *int) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s must be an integer: %w", name, err)
	}
	*target = value
	return nil
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}
