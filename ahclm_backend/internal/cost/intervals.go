package cost

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"ahclm/internal/models"
)

// These are sensitivity envelopes conditional on the listed operations, not
// confidence intervals for total money. Historical rates only price probes.
func applyIntervals(r *models.CostBreakdown, e models.CostEvidence, cfg models.CostConfig, now time.Time) {
	r.MethodVersion = "conditional-cost-v2"
	lo, hi := cfg.WeightLowerMultiplier, cfg.WeightUpperMultiplier
	if lo <= 0 || hi < lo || lo > 1 || hi < 1 || math.IsNaN(lo) || math.IsNaN(hi) || math.IsInf(hi, 0) {
		lo, hi = 1, 1
		r.Unknowns = append(r.Unknowns, "Weight range unavailable: envelope is conditional on fixed configured weights")
	}
	jobs := validJobs(e.ScanJobs, now)
	r.ObservationRuns = observationRuns(jobs)
	fail := 0
	for _, j := range jobs {
		if !j.Success {
			fail++
		}
	}
	pl, pu := wilson(fail, len(jobs))
	bound := func(items []models.CostLineItem) {
		for i := range items {
			x := &items[i]
			x.Lower, x.Upper = x.Amount*lo, x.Amount*hi
			x.IntervalKind = "weight_scenario"
			if strings.Contains(x.Code, "exposure") || x.Code == "expired_service_after_expiry" || x.Code == "expiry_incident" {
				x.Lower = 0
				x.IntervalKind = "duration_and_weight_scenario"
				x.Basis += "; duration ranges from immediate resolution to persistence for the stated horizon; zero is a possible scenario, not an observed absence of cost"
			}
			if x.Code == "additional_probe" {
				x.Lower, x.Upper = pl*cfg.ActiveMeasurementCost*lo, pu*cfg.ActiveMeasurementCost*hi
				x.IntervalKind = "probability_and_weight_scenario"
				x.Basis += "; rate bounds use a 95% Wilson interval under independent, stationary rounds; total cost envelope has no 95% coverage claim"
			}
		}
	}
	bound(r.WaitItems)
	bound(r.RotateItems)
	if len(jobs) == 0 {
		probe := models.CostLineItem{Code: "additional_probe_unknown", Label: "Possible additional active measurement", Upper: cfg.ActiveMeasurementCost * hi, Method: "unknown_probability", IntervalKind: "action_and_weight_scenario", Basis: "No usable history: one optional extra probe has probability bounded only by 0 and 1"}
		r.WaitItems = append(r.WaitItems, probe)
		r.RotateItems = append(r.RotateItems, probe)
	}
	baseLow, baseHigh, base := 0.0, 0.0, 0.0
	for _, x := range r.RotateItems {
		baseLow += x.Lower
		baseHigh += x.Upper
		base += x.Amount
	}
	// Include the terminal obligation in the wait policy, within the same
	// accounting horizon. It is a reserved operation cost, not a claim that
	// deployment has already completed at the horizon boundary.
	deferredLow := 0.0
	if r.HardConstraint {
		deferredLow = baseLow
	}
	r.WaitItems = append(r.WaitItems, models.CostLineItem{Code: "deferred_replacement", Label: "Replacement obligation at next measurement", Lower: deferredLow, Upper: baseHigh, Amount: base, Method: "conditional_scenario", IntervalKind: "action_and_weight_scenario", Basis: "Includes issuance, CT, deployment, verification and one optional additional probe if replacement remains necessary; mandatory remediation reserves the full operation cost"})
	exposureHigh := 0.0
	for _, x := range r.WaitItems {
		if strings.Contains(x.Code, "exposure") || x.Code == "expired_service_after_expiry" || x.Code == "expiry_incident" {
			exposureHigh += x.Upper
		}
	}
	if exposureHigh > 0 {
		r.RotateItems = append(r.RotateItems, models.CostLineItem{Code: "deployment_period_exposure", Label: "Exposure before replacement becomes effective", Upper: exposureHigh, Method: "conditional_scenario", IntervalKind: "duration_and_weight_scenario", Basis: "Same observation horizon as waiting; resolution may occur immediately or remain incomplete through the horizon. Public probes do not reveal rollout start or completion times."})
	}
	r.WaitLower, r.WaitUpper, r.RotateLower, r.RotateUpper = 0, 0, 0, 0
	r.WaitCost, r.RotateCost = 0, 0
	for _, x := range r.WaitItems {
		r.WaitCost += x.Amount
		r.WaitLower += x.Lower
		r.WaitUpper += x.Upper
	}
	for _, x := range r.RotateItems {
		r.RotateCost += x.Amount
		r.RotateLower += x.Lower
		r.RotateUpper += x.Upper
	}
	// Shared normalized operation prices are the same in both policies.
	// R-W = (1-q)*B + E_R-E_W - M. The optional verification probe
	// is part of B in both policies; M is the extra wait measurement.
	monitorLow, monitorHigh := 0.0, 0.0
	for _, x := range r.WaitItems {
		if x.Code == "active_measurement" || x.Code == "additional_probe" || x.Code == "additional_probe_unknown" {
			monitorLow += x.Lower
			monitorHigh += x.Upper
		}
	}
	r.DeltaLower = -exposureHigh - monitorHigh
	r.DeltaUpper = exposureHigh - monitorLow
	if !r.HardConstraint {
		r.DeltaUpper += baseHigh
	}
	r.DeltaBasis = "Delta = replacement - waiting = (1-q)B + exposure_R - exposure_W - wait_measurement. Shared operation weights are coupled; q=1 for the mandatory replacement scenario, otherwise q is unidentifiable in [0,1]. Exposure ranges independently from 0 to the common horizon. These are outer bounds conditional on specified weights and operations."
	r.Comparison = "overlap"
	if r.DeltaUpper < 0 {
		r.Comparison = "replace_lower"
	}
	if r.DeltaLower > 0 {
		r.Comparison = "wait_lower"
	}
	if r.WaitHorizonHours <= 0 {
		r.Comparison = "insufficient_horizon"
	}
	r.Sensitivity = []string{
		fmt.Sprintf("Normalized cost weights vary from %.2fx to %.2fx; these are explicit sensitivity assumptions, not learned prices", lo, hi),
		"Exposure duration and deployment effectiveness dominate overlap; public monitoring cannot establish the counterfactual outcome of an unperformed replacement",
		"Cost advantage requires the coupled difference envelope to exclude zero; mandatory remediation is a separate safety decision",
		"CT weight is per additional certificate, covering monitoring burden; it is not a CT log submission fee",
	}
	r.Sensitivity = append(r.Sensitivity, "For common exposure weight w and known saved exposure duration d>0, replacement breaks even at w=((1-q)B-M)/d. If d or q is unidentified, no numeric threshold is justified.")
	r.Basis = "Forward costs through the next scheduled measurement, including the terminal replacement obligation. Past costs are excluded. Bounds are conditional sensitivity envelopes, not absolute limits or calibrated monetary prediction intervals."
	r.Unknowns = append(r.Unknowns, "Unobserved rollout retries, rollback and business losses are outside the quantified envelope; bounds are not bounds on all possible costs")
	// Prequential validation: each prediction uses only earlier completed rounds.
	if len(jobs) > 10 {
		v := &models.CostValidation{Basis: "At each target start, use only rounds completed strictly earlier; 10-round warm-up. Brier compared with always-success and last known outcome. Descriptive retained-window audit; does not validate causal effects, total costs or interval coverage."}
		for _, j := range jobs {
			f, n, last := 0, 0, 0.0
			for _, past := range jobs {
				if !past.FinishedAt.Before(*j.StartedAt) {
					break
				}
				n++
				last = 0
				if !past.Success {
					f++
					last = 1
				}
			}
			y := 0.0
			if !j.Success {
				y = 1
			}
			if n >= 10 {
				p := float64(f+1) / float64(n+2)
				v.BrierScore += (p - y) * (p - y)
				v.BaselineBrier += y
				v.PersistenceBrier += (last - y) * (last - y)
				if y == 1 {
					v.FailureCount++
				}
				v.Samples++
			}
		}
		if v.Samples == 0 {
			return
		}
		v.BrierScore /= float64(v.Samples)
		v.BaselineBrier /= float64(v.Samples)
		v.PersistenceBrier /= float64(v.Samples)
		r.Validation = v
	}
}

func validJobs(jobs []models.ScanJob, now time.Time) []models.ScanJob {
	result := make([]models.ScanJob, 0, len(jobs))
	seen := map[uint]bool{}
	for _, j := range jobs {
		if j.StartedAt == nil || j.FinishedAt == nil || j.FinishedAt.Before(*j.StartedAt) || j.FinishedAt.After(now) || j.StartedAt.Before(now.Add(-30*24*time.Hour)) {
			continue
		}
		if j.ID != 0 && seen[j.ID] {
			continue
		}
		seen[j.ID] = true
		result = append(result, j)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].FinishedAt.Equal(*result[j].FinishedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].FinishedAt.Before(*result[j].FinishedAt)
	})
	return result
}

func wilson(k, n int) (float64, float64) {
	if n == 0 {
		return 0, 1
	}
	p := float64(k) / float64(n)
	z := 1.959963984540054
	d := 1 + z*z/float64(n)
	c := (p + z*z/(2*float64(n))) / d
	h := z * math.Sqrt(p*(1-p)/float64(n)+z*z/(4*float64(n*n))) / d
	return math.Max(0, c-h), math.Min(1, c+h)
}
