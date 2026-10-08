package scanner

import (
	"sync"
	"time"
)

// globalProbeScanBudget limits Globalping tests requested as enrichment for
// routine certificate scans. Propagation measurements use their own bounded
// worker and must not be starved by a large initial domain scan.
type globalProbeScanBudget struct {
	mu       sync.Mutex
	maxTests int
	used     []globalProbeBudgetEntry
}

type globalProbeBudgetEntry struct {
	at    time.Time
	tests int
}

func newGlobalProbeScanBudget(maxTests int) *globalProbeScanBudget {
	return &globalProbeScanBudget{maxTests: maxTests}
}

// reserve records a conservative rolling-hour reservation. Failed provider
// requests remain charged locally because their consumption can be ambiguous.
func (b *globalProbeScanBudget) reserve(now time.Time, tests int) (bool, int) {
	if b == nil || b.maxTests <= 0 || tests <= 0 {
		return true, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := now.Add(-time.Hour)
	kept := b.used[:0]
	used := 0
	for _, entry := range b.used {
		if entry.at.After(cutoff) {
			kept = append(kept, entry)
			used += entry.tests
		}
	}
	b.used = kept
	if used+tests > b.maxTests {
		remaining := b.maxTests - used
		if remaining < 0 {
			remaining = 0
		}
		return false, remaining
	}
	b.used = append(b.used, globalProbeBudgetEntry{at: now, tests: tests})
	return true, b.maxTests - used - tests
}
