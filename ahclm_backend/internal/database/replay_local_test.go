package database

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"ahclm/internal/models"
)

type apiObservations struct {
	Data struct {
		Observations []models.CertObservation `json:"observations"`
	} `json:"data"`
}

// TestReplayLocalCaptures runs the analysis over observation timelines captured
// from a live deployment. It is skipped unless AHCLM_REPLAY_DIR points at them.
func TestReplayLocalCaptures(t *testing.T) {
	dir := os.Getenv("AHCLM_REPLAY_DIR")
	if dir == "" {
		t.Skip("set AHCLM_REPLAY_DIR to replay captured timelines")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	type row struct {
		domain  string
		shape   models.ChurnShape
		primary string
		benign  bool
		conf    string
	}
	rows := make([]row, 0, len(files))
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var payload apiObservations
		if json.Unmarshal(raw, &payload) != nil {
			continue
		}
		observations := payload.Data.Observations
		changes := 0
		for _, observation := range observations {
			if observation.ObservationType == models.ObsChange {
				changes++
			}
		}
		if changes < 2 {
			continue
		}
		diagnosis := inferChurnDiagnosis(models.Anomaly{Type: "frequent_change"}, diagnosisContext{observations: observations})
		domain := filepath.Base(file)
		domain = domain[:len(domain)-len(".json")]
		rows = append(rows, row{domain, *diagnosis.ChurnShape, diagnosis.PrimaryCode, diagnosis.BenignExplanation != "", diagnosis.Confidence})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].shape.RevisitEvents > rows[j].shape.RevisitEvents })

	counts := map[string]int{}
	primaries := map[string]int{}
	confidences := map[string]int{}
	benign, pipeline, unexplained := 0, 0, 0
	for _, r := range rows {
		counts[r.shape.Interpretation]++
		primaries[r.primary]++
		confidences[r.conf]++
		if r.benign {
			benign++
		}
		if r.primary == "preissued_rolling_pipeline" {
			pipeline++
		}
		if r.primary == "replacement_mechanism_unestablished" {
			unexplained++
		}
		if r.primary == "key_security_rotation" {
			t.Errorf("%s still uses public-key change as a cause", r.domain)
		}
	}
	t.Logf("replayed %d domains", len(rows))
	t.Logf("interpretation: %v", counts)
	t.Logf("primary cause : %v", primaries)
	t.Logf("confidence    : %v", confidences)
	t.Logf("withdrawn as expected behaviour: %d   rolling pipeline: %d   unestablished: %d", benign, pipeline, unexplained)
	t.Log("worst offenders:")
	for _, r := range rows[:minInt(12, len(rows))] {
		t.Logf("  %-26s changes=%3d distinct=%2d revisits=%3d effective=%2d -> %-34s %s benign=%v",
			r.domain, r.shape.ChangeEvents, r.shape.DistinctLeaves, r.shape.RevisitEvents,
			r.shape.EffectiveReplacements, r.primary, r.conf, r.benign)
	}
}
