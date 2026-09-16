// cost-audit exports a minimal read-only snapshot and replays cost-related
// probability evaluation without running migrations, scans or the scheduler.
package main

import (
	"ahclm/internal/cost"
	"ahclm/internal/models"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"runtime"
	"sort"
	"time"
)

type snapshot struct {
	AsOf time.Time        `json:"as_of"`
	Jobs []models.ScanJob `json:"jobs"`
}
type domainResult struct {
	Domain     string                      `json:"domain"`
	Validation *models.CostValidation      `json:"validation"`
	Runs       []models.CostObservationRun `json:"runs"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	cfgPath := flag.String("config", "config.yaml", "configuration for read-only export")
	input := flag.String("input", "", "replay snapshot; no database access")
	export := flag.String("export", "", "new snapshot path; existing files are not overwritten")
	output := flag.String("output", "", "new report path")
	cutoff := flag.String("as-of", "", "required RFC3339 export cutoff")
	flag.Parse()
	var s snapshot
	var raw []byte
	var err error
	if *input != "" {
		raw, err = os.ReadFile(*input)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &s); err != nil {
			return err
		}
	} else {
		if *export == "" || *cutoff == "" {
			return fmt.Errorf("export requires --export and --as-of")
		}
		s.AsOf, err = time.Parse(time.RFC3339, *cutoff)
		if err != nil {
			return err
		}
		v := viper.New()
		v.SetConfigFile(*cfgPath)
		if err = v.ReadInConfig(); err != nil {
			return err
		}
		var cfg models.Config
		if err = v.Unmarshal(&cfg); err != nil {
			return err
		}
		db, e := gorm.Open(postgres.Open(cfg.Database.DSN(cfg.Database.Database)), &gorm.Config{})
		if e != nil {
			return e
		}
		conn, e := db.DB()
		if e != nil {
			return e
		}
		defer conn.Close()
		err = db.Transaction(func(tx *gorm.DB) error {
			return tx.Raw(`SELECT id, domain, started_at, finished_at, success, revocation_status FROM
    (SELECT id, domain, started_at, finished_at, success, revocation_status,
     row_number() OVER (PARTITION BY domain ORDER BY started_at DESC,id DESC) AS rn
     FROM scan_jobs WHERE started_at >= ? AND finished_at <= ? AND finished_at >= started_at) q
     WHERE rn <= 500 ORDER BY domain, finished_at, id`, s.AsOf.Add(-30*24*time.Hour), s.AsOf).Scan(&s.Jobs).Error
		}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
		if err != nil {
			return err
		}
		raw, err = json.Marshal(s)
		if err != nil {
			return err
		}
		if err = writeNew(*export, raw); err != nil {
			return err
		}
	}
	if s.AsOf.IsZero() {
		return fmt.Errorf("snapshot has no cutoff")
	}
	grouped := map[string][]models.ScanJob{}
	for _, j := range s.Jobs {
		grouped[j.Domain] = append(grouped[j.Domain], j)
	}
	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]domainResult, 0, len(names))
	samples := 0
	weighted, baseline, persistence := 0.0, 0.0, 0.0
	macro := 0.0
	evaluable := 0
	for _, name := range names {
		r := cost.AuditHistory(grouped[name], s.AsOf)
		rows = append(rows, domainResult{name, r.Validation, r.ObservationRuns})
		if r.Validation != nil {
			v := r.Validation
			samples += v.Samples
			weighted += v.BrierScore * float64(v.Samples)
			baseline += v.BaselineBrier * float64(v.Samples)
			persistence += v.PersistenceBrier * float64(v.Samples)
			macro += v.BrierScore
			evaluable++
		}
	}
	if samples > 0 {
		weighted /= float64(samples)
		baseline /= float64(samples)
		persistence /= float64(samples)
	}
	if evaluable > 0 {
		macro /= float64(evaluable)
	}
	hash := sha256.Sum256(raw)
	report := struct {
		Version, GoVersion, SnapshotSHA256                           string
		AsOf                                                         time.Time
		Domains, EvaluableDomains, Samples                           int
		MicroBrier, MacroBrier, AlwaysSuccessBrier, PersistenceBrier float64
		Results                                                      []domainResult
	}{"conditional-cost-v2", runtime.Version(), hex.EncodeToString(hash[:]), s.AsOf, len(names), evaluable, samples, weighted, macro, baseline, persistence, rows}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if *output != "" {
		if err = writeNew(*output, data); err != nil {
			return err
		}
	} else {
		fmt.Println(string(data))
	}
	fmt.Fprintf(os.Stderr, "domains=%d evaluable=%d rounds=%d micro_brier=%.6f macro_brier=%.6f always_success=%.6f persistence=%.6f sha256=%s\n", len(names), evaluable, samples, weighted, macro, baseline, persistence, report.SnapshotSHA256)
	return nil
}
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, e := f.Write(data)
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}
