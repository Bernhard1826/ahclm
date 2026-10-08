package propagation

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"ahclm/internal/database"
	"ahclm/internal/models"
	"github.com/jackc/pgx/v5"
)

type integrationProber struct {
	measure func() (*models.GlobalProbeEvidence, error)
}

func (p *integrationProber) MeasureGlobalHTTPS(context.Context, string, []string) (*models.GlobalProbeEvidence, error) {
	return p.measure()
}
func (p *integrationProber) MeasureGlobalHTTPSWithTarget(context.Context, string, string, []string) (*models.GlobalProbeEvidence, error) {
	return p.measure()
}
func (p *integrationProber) MeasureGlobalHTTPSPath(context.Context, string, string, string, []string) (*models.GlobalProbeEvidence, error) {
	return p.measure()
}

func isolatedPostgres(t *testing.T) *database.Database {
	t.Helper()
	dsn := os.Getenv("AHCLM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set AHCLM_TEST_POSTGRES_DSN to run against a disposable PostgreSQL database")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test PostgreSQL DSN")
	}
	admin, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal("cannot connect to test PostgreSQL")
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("ahclm_test_propagation_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+identifier); err != nil {
			t.Error(err)
		}
	})
	db, err := database.New(&models.DatabaseConfig{Host: cfg.Host, Port: int(cfg.Port), User: cfg.User, Password: cfg.Password, Database: name, SSLMode: "disable", MaxOpenConnections: 4, MaxIdleConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestQueuePersistenceAndOriginProofPostgres(t *testing.T) {
	db := isolatedPostgres(t)
	if _, err := db.RegisterLocalDomains([]string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	source := now
	target := strings.Repeat("ab", 32)
	probe := &integrationProber{}
	cfg := &models.CDNPropagationConfig{MaxActive: 1, PollInterval: 30 * time.Second, MaxDuration: time.Hour, StableRounds: 2, Locations: []string{"AS", "EU"}}
	manager := NewManager(cfg, db, probe)
	manager.nowFn = func() time.Time { return now }
	first, err := manager.StartExperiment(models.CDNPropagationStartRequest{Domain: "example.com", TargetFingerprint: target, MaxDurationSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	req := models.CDNPropagationStartRequest{Domain: "www.example.com", CertificateLayer: models.CDNPropagationLayerOriginViaCDN, TargetFingerprint: target, SourceUpdatedAt: &source, ProbePath: "/.well-known/ahclm-origin"}
	queued, err := manager.StartExperiment(req)
	if err != nil {
		t.Fatal(err)
	}
	if queued.Status != models.CDNPropagationQueued || queued.ProbeTarget != "www.example.com" || queued.ProbeHost != "www.example.com" {
		t.Fatalf("queue or hostname lost: %+v", queued)
	}
	duplicate, err := manager.StartExperiment(req)
	if err != nil || duplicate.ID != queued.ID {
		t.Fatalf("duplicate event was not idempotent: %+v %v", duplicate, err)
	}
	otherSource := source.Add(-time.Second)
	req.SourceUpdatedAt = &otherSource
	other, err := manager.StartExperiment(req)
	if err != nil || other.ID == queued.ID {
		t.Fatal("distinct source update incorrectly deduplicated")
	}
	if err := db.CancelCDNPropagationExperiment(other.ID, now); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the manager to prove the pending experiment survives restart.
	manager = NewManager(cfg, db, probe)
	manager.nowFn = func() time.Time { return now }
	now = now.Add(2 * time.Minute)
	if err := manager.RunDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	ended, err := db.GetCDNPropagationExperiment(first.ID)
	if err != nil || ended.Status != models.CDNPropagationTimeout {
		t.Fatal("expired experiment did not release its slot")
	}
	proof := false
	probe.measure = func() (*models.GlobalProbeEvidence, error) {
		evidence := &models.GlobalProbeEvidence{CollectedAt: now}
		for _, region := range cfg.Locations {
			p := models.GlobalHTTPSProbe{Location: models.GlobalProbeLocation{Continent: region}, Status: "finished", TLSObserved: true, TLSAuthorized: true, HTTPStatus: 200}
			if proof {
				p.RequestNonce = "fresh"
				p.OriginProbeNonce = "fresh"
				p.OriginFingerprint = target
				p.OriginTLSResumed = "false"
			}
			evidence.HTTPS = append(evidence.HTTPS, p)
		}
		return evidence, nil
	}
	if err := manager.RunDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	report, err := db.GetCDNPropagationReport(queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Experiment.Status != models.CDNPropagationRunning || report.FirstTargetAt != nil || !report.Experiment.SourceUpdatedAt.Equal(source) || !report.Experiment.StartedAt.Equal(now) {
		t.Fatalf("HTTP-only response or queue timing misclassified: %+v", report)
	}
	proof = true
	for i := 0; i < 2; i++ {
		now = now.Add(30 * time.Second)
		if err := manager.RunDue(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	report, err = db.GetCDNPropagationReport(queued.ID)
	if err != nil || report.Experiment.Status != models.CDNPropagationComplete || report.SyncState != "origin_verified" || report.Experiment.Rounds != 3 {
		t.Fatalf("origin proof did not complete: %+v %v", report, err)
	}
	// A later cancellation must not relabel an already completed measurement.
	if err := db.CancelCDNPropagationExperiment(queued.ID, now); err != nil {
		t.Fatal(err)
	}
	completed, _ := db.GetCDNPropagationExperiment(queued.ID)
	if completed.Status != models.CDNPropagationComplete {
		t.Fatal("completed result was overwritten by cancellation")
	}
	if err := manager.RunDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	canceled, _ := db.GetCDNPropagationExperiment(other.ID)
	if canceled.Status != models.CDNPropagationCanceled || canceled.Rounds != 0 {
		t.Fatal("canceled queued experiment was activated")
	}
}
