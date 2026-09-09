package database

import (
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestAnomalyCauseIsMutuallyExclusive(t *testing.T) {
	confirmed := withAnomalyCause(models.Anomaly{}, anomalyCause{
		confirmedReason:   "direct observation",
		confirmedEvidence: []string{"fact=true"},
		inferredReason:    "interpretation",
		inferredEvidence:  []string{"inference=possible"},
	})
	if confirmed.CauseClassification != "confirmed" || confirmed.InferredReason != "" || len(confirmed.InferredEvidence) != 0 {
		t.Fatalf("confirmed cause was not exclusive: %#v", confirmed)
	}
	inferred := withAnomalyCause(models.Anomaly{}, anomalyCause{
		inferredReason:   "interpretation",
		inferredEvidence: []string{"inference=possible"},
	})
	if inferred.CauseClassification != "inferred" || inferred.ConfirmedReason != "" || len(inferred.ConfirmedEvidence) != 0 {
		t.Fatalf("inferred cause was not exclusive: %#v", inferred)
	}
}

func TestNormalizedFinishTimeClampsClockReversal(t *testing.T) {
	started := time.Date(2026, time.August, 3, 20, 0, 1, 0, time.UTC)
	finished := started.Add(-time.Millisecond)
	if got := normalizedFinishTime(&started, finished); !got.Equal(started) {
		t.Fatalf("finish time = %v, want %v", got, started)
	}
}

func TestNormalizedFinishTimePreservesValidFinish(t *testing.T) {
	started := time.Date(2026, time.August, 3, 20, 0, 1, 0, time.UTC)
	finished := started.Add(time.Second)
	if got := normalizedFinishTime(&started, finished); !got.Equal(finished) {
		t.Fatalf("finish time = %v, want %v", got, finished)
	}
}
