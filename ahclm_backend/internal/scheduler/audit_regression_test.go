package scheduler

import (
	"ahclm/internal/database"
	"ahclm/internal/models"
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func auditDatabase(t *testing.T) *database.Database {
	t.Helper()
	dsn := os.Getenv("AHCLM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable database access")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	admin, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal("cannot connect to test PostgreSQL")
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("ahclm_code_audit_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(context.Background(), "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+quoted); err != nil {
			t.Error(err)
		}
	})
	db, err := database.New(&models.DatabaseConfig{Host: cfg.Host, Port: int(cfg.Port), User: cfg.User, Password: cfg.Password, Database: name, SSLMode: "disable", MaxOpenConnections: 4, MaxIdleConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err = db.RegisterLocalDomains([]string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	return db
}

func auditCert(letter string, now time.Time) *models.Certificate {
	return &models.Certificate{Fingerprint: strings.Repeat(letter, 64), SPKIFingerprint: strings.Repeat("e", 64), CommonName: "example.com", SANs: `["example.com"]`, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), FirstSeenAt: now, LastSeenAt: now}
}

func auditSeed(t *testing.T, db *database.Database, now time.Time, cert *models.Certificate) (*Scheduler, *models.DomainCertificate) {
	t.Helper()
	saved, _, err := db.UpsertCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	dc, err := db.GetDomainCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	dc.CurrentCertificateID = saved.ID
	dc.CurrentFingerprint = saved.Fingerprint
	dc.ScanCount = 1
	dc.LastScannedAt = now.Add(-time.Hour)
	dc.LastDaysUntilExpiry = 90
	dc.LastEndpointIP = "1.1.1.1"
	dc.Status = models.StatusActive
	dc.EndpointStates = marshalString(map[string]models.EndpointState{"1.1.1.1": {IPAddress: "1.1.1.1", Fingerprint: saved.Fingerprint}})
	if err := db.SaveDomainCertificate(dc); err != nil {
		t.Fatal(err)
	}
	s := NewScheduler(testCfg(), &models.ScannerConfig{}, db, nil, nil)
	s.nowFn = func() time.Time { return now }
	return s, dc
}

func auditResult(cert *models.Certificate, now time.Time) *models.ScanResult {
	return &models.ScanResult{Domain: "example.com", Success: true, Cert: cert, ScannedAt: now, ConnectionInfo: &models.ConnectionInfo{IPAddress: "1.1.1.1"}, RevocationStatus: models.RevocationNotChecked, RevocationCheckedVia: models.CheckedViaNone, EvidenceStatus: models.EvidenceStatusBaseline}
}

func TestCodeAuditSecondaryEndpointChangeMustUseItsOwnLeaf(t *testing.T) {
	db := auditDatabase(t)
	now := time.Now().UTC()
	a, b, c := auditCert("a", now), auditCert("b", now), auditCert("c", now)
	s, dc := auditSeed(t, db, now, a)
	if _, _, err := db.UpsertCertificate(b); err != nil {
		t.Fatal(err)
	}
	dc.EndpointStates = marshalString(map[string]models.EndpointState{"1.1.1.1": {IPAddress: "1.1.1.1", Fingerprint: a.Fingerprint}, "8.8.8.8": {IPAddress: "8.8.8.8", Fingerprint: b.Fingerprint}})
	if err := db.SaveDomainCertificate(dc); err != nil {
		t.Fatal(err)
	}
	r := auditResult(a, now)
	r.EndpointProbes = []models.EndpointProbe{{IPAddress: "1.1.1.1", Success: true, Fingerprint: a.Fingerprint}, {IPAddress: "8.8.8.8", Success: true, Fingerprint: c.Fingerprint}}
	s.processResult(dc, r)
	obs, err := db.GetDomainTimeline("example.com", 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range obs {
		if x.ObservationType == models.ObsChange {
			found = true
			if x.IPAddress != "8.8.8.8" || x.Fingerprint != c.Fingerprint {
				t.Errorf("actual rotation B->C at 8.8.8.8; stored previous=%s current=%s previous_ip=%s ip=%s class=%s", x.PreviousFingerprint, x.Fingerprint, x.PreviousIPAddress, x.IPAddress, x.ChangeClass)
			}
		}
	}
	if !found {
		t.Fatal("no change row")
	}
}

func TestCodeAuditRepeatedLeavesMustNotProduceUniformSnapshot(t *testing.T) {
	db := auditDatabase(t)
	now := time.Now().UTC()
	a, b := auditCert("a", now), auditCert("b", now)
	s, dc := auditSeed(t, db, now, a)
	r := auditResult(a, now)
	r.EndpointProbes = []models.EndpointProbe{{IPAddress: "1.1.1.1", Success: true, Fingerprint: a.Fingerprint, OtherFingerprints: []string{b.Fingerprint}, Handshakes: 2}}
	s.recordMeasurement(dc, r, "audit")
	ss, err := db.GetMeasurementSnapshots("example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) != 1 {
		t.Fatal(ss)
	}
	if ss[0].FingerprintCount != 2 || dc.EndpointDiversityStatus == "uniform" {
		t.Errorf("two leaves on same IP: fingerprint_count=%d diversity=%s", ss[0].FingerprintCount, dc.EndpointDiversityStatus)
	}
}

func TestCodeAuditBaselineMustPreserveKnownRevocationTime(t *testing.T) {
	db := auditDatabase(t)
	now := time.Now().UTC()
	a := auditCert("a", now)
	s, dc := auditSeed(t, db, now, a)
	revoked := now.Add(-time.Hour)
	dc.RevocationStatus = models.RevocationRevoked
	dc.RevokedAt = &revoked
	dc.RevocationReason = "keyCompromise"
	dc.RevocationCheckedVia = models.CheckedViaOCSP
	dc.RevocationCheckedAt = &revoked
	if err := db.SaveDomainCertificate(dc); err != nil {
		t.Fatal(err)
	}
	s.processResult(dc, auditResult(a, now))
	got, err := db.GetDomainCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil || got.RevocationReason != "keyCompromise" {
		t.Errorf("unchanged leaf, no fresh check: status=%s revoked_at=%v reason=%q", got.RevocationStatus, got.RevokedAt, got.RevocationReason)
	}
}

func TestCodeAuditLateResultMustNotOverwriteNewerObservation(t *testing.T) {
	db := auditDatabase(t)
	now := time.Now().UTC()
	a, b, c := auditCert("a", now), auditCert("b", now), auditCert("c", now)
	s, first := auditSeed(t, db, now, a)
	second, err := db.GetDomainCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Two in-flight scans each read the initial row. Newer observation commits first.
	s.processResult(first, auditResult(c, now))
	s.processResult(second, auditResult(b, now.Add(-time.Minute)))
	got, err := db.GetDomainCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentFingerprint != c.Fingerprint || got.ScanCount != 3 {
		t.Errorf("older result overwrote newer current; current=%s want=%s scan_count=%d want=3", got.CurrentFingerprint, c.Fingerprint, got.ScanCount)
	}
}

func TestConcurrentScanCommitsPreserveNewestStateAndAllCounts(t *testing.T) {
	db := auditDatabase(t)
	now := time.Now().UTC()
	s, _ := auditSeed(t, db, now, auditCert("a", now))
	const count = 8
	states := make([]*models.DomainCertificate, count)
	for i := range states {
		var err error
		states[i], err = db.GetDomainCertificate("example.com")
		if err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			at := now.Add(time.Duration(i) * time.Second)
			leaf := auditCert(fmt.Sprintf("%x", i+1), at)
			s.processResult(states[i], auditResult(leaf, at))
		}(i)
	}
	close(start)
	wg.Wait()
	got, err := db.GetDomainCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.ScanCount != count+1 || got.CurrentFingerprint != strings.Repeat("8", 64) {
		t.Fatalf("concurrent commits lost state: count=%d fingerprint=%s", got.ScanCount, got.CurrentFingerprint)
	}
	snapshots, err := db.GetMeasurementSnapshots("example.com", 100)
	if err != nil || len(snapshots) != count {
		t.Fatalf("observations lost: %d, %v", len(snapshots), err)
	}
}

func TestMultipleEndpointChangesHaveIndependentLeavesAndKeys(t *testing.T) {
	db := auditDatabase(t)
	now := time.Now().UTC()
	a, b, c, d := auditCert("a", now), auditCert("b", now), auditCert("c", now), auditCert("d", now)
	c.SPKIFingerprint = strings.Repeat("f", 64) // A->C changes key; B->D preserves it.
	s, dc := auditSeed(t, db, now, a)
	for _, cert := range []*models.Certificate{b, c, d} {
		if _, _, err := db.UpsertCertificate(cert); err != nil {
			t.Fatal(err)
		}
	}
	dc.EndpointStates = marshalString(map[string]models.EndpointState{"1.1.1.1": {IPAddress: "1.1.1.1", Fingerprint: a.Fingerprint}, "8.8.8.8": {IPAddress: "8.8.8.8", Fingerprint: b.Fingerprint}})
	if err := db.SaveDomainCertificate(dc); err != nil {
		t.Fatal(err)
	}
	r := auditResult(c, now)
	c.ID = 0 // a TLS capture does not know an already stored certificate's ID
	r.EndpointProbes = []models.EndpointProbe{{IPAddress: "1.1.1.1", Success: true, Fingerprint: c.Fingerprint}, {IPAddress: "8.8.8.8", Success: true, Fingerprint: d.Fingerprint}}
	s.processResult(dc, r)
	obs, err := db.GetDomainTimeline("example.com", 100)
	if err != nil {
		t.Fatal(err)
	}
	changes, sameKey := 0, 0
	for _, o := range obs {
		if o.ObservationType == models.ObsChange {
			changes++
			if o.CertificateID == 0 {
				t.Fatal("known leaf lost its stored certificate ID")
			}
			if o.IPAddress != o.PreviousIPAddress {
				t.Fatal("cross-endpoint replacement")
			}
			if o.IPAddress == "1.1.1.1" && (o.PreviousFingerprint != a.Fingerprint || o.Fingerprint != c.Fingerprint) {
				t.Fatal("wrong first transition")
			}
			if o.IPAddress == "8.8.8.8" && (o.PreviousFingerprint != b.Fingerprint || o.Fingerprint != d.Fingerprint) {
				t.Fatal("wrong second transition")
			}
		}
		if o.ObservationType == models.ObsSameKey {
			sameKey++
			if o.IPAddress != "8.8.8.8" || o.Fingerprint != d.Fingerprint {
				t.Fatal("same-key claim used wrong leaf")
			}
		}
	}
	if changes != 2 || sameKey != 1 {
		t.Fatalf("changes=%d sameKey=%d", changes, sameKey)
	}
}
