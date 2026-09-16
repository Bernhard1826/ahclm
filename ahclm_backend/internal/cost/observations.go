package cost

import "ahclm/internal/models"

// Sampled runs retain unresolved tails and missing checks. They do not imply
// that a condition held continuously between probes, nor identify its cause.
func observationRuns(jobs []models.ScanJob) []models.CostObservationRun {
	var result []models.CostObservationRun
	for _, condition := range []string{"probe_failure", "revoked_leaf_observed"} {
		var active *models.CostObservationRun
		previousClear := false
		for _, j := range jobs {
			known, bad := true, !j.Success
			if condition == "revoked_leaf_observed" {
				known = j.Success && (j.RevocationStatus == models.RevocationRevoked || j.RevocationStatus == models.RevocationGood)
				bad = j.RevocationStatus == models.RevocationRevoked
			}
			if !known {
				if active != nil {
					active.EvidenceGap = true
				}
				previousClear = false
				continue
			}
			if bad {
				if active == nil {
					active = &models.CostObservationRun{Condition: condition, FirstObserved: *j.FinishedAt, LeftTruncated: !previousClear, RightCensored: true}
				}
				active.LastObserved = *j.FinishedAt
			} else {
				if active != nil {
					clear := *j.FinishedAt
					active.FirstClear = &clear
					active.RightCensored = false
					result = append(result, *active)
					active = nil
				}
			}
			previousClear = !bad
		}
		if active != nil {
			result = append(result, *active)
		}
	}
	return result
}
