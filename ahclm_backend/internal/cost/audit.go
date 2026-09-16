package cost

import (
	"ahclm/internal/models"
	"time"
)

// AuditHistory shares the production evaluator without classifying a current
// certificate from a historical snapshot of monitoring rounds.
func AuditHistory(jobs []models.ScanJob, asOf time.Time) models.CostBreakdown {
	r := models.CostBreakdown{}
	applyIntervals(&r, models.CostEvidence{ScanJobs: jobs}, models.CostConfig{WeightLowerMultiplier: 1, WeightUpperMultiplier: 1}, asOf)
	return r
}
