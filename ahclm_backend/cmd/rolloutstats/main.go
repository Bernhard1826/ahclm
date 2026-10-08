// Command rolloutstats measures, read-only, how long certificate rollouts take
// in the retained measurement snapshots. The definitions live in package
// rollout, which the backend uses for the same reference distribution.
package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"time"

	"ahclm/internal/rollout"

	"github.com/jackc/pgx/v5"
)

func main() {
	dsn := os.Getenv("AHCLM_DSN")
	if dsn == "" {
		dsn = "postgres://postgres:123456@localhost:15432/ahclm?sslmode=disable"
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Rollback(ctx)

	issued := loadIssuance(ctx, tx)

	rows, err := tx.Query(ctx, `SELECT domain, observed_at, COALESCE(endpoint_fingerprints_json,''), COALESCE(topology_json,''), COALESCE(endpoint_probes_json,'')
		FROM measurement_snapshots ORDER BY domain, observed_at, id`)
	if err != nil {
		log.Fatal(err)
	}
	var events []rollout.Event
	var gaps []float64
	current := ""
	var rounds []rollout.Round
	flush := func() {
		if current != "" && len(rounds) > 0 {
			events = append(events, rollout.AnalyzeDomain(current, rounds, issued)...)
			for index := 1; index < len(rounds); index++ {
				gaps = append(gaps, rounds[index].At.Sub(rounds[index-1].At).Hours())
			}
		}
		rounds = rounds[:0]
	}
	for rows.Next() {
		var domain, assignmentJSON, topologyJSON, probesJSON string
		var at time.Time
		if err := rows.Scan(&domain, &at, &assignmentJSON, &topologyJSON, &probesJSON); err != nil {
			log.Fatal(err)
		}
		if domain != current {
			flush()
			current = domain
		}
		rollout.AddIssuance(probesJSON, issued)
		leaves := rollout.ActiveLeaves(assignmentJSON, topologyJSON)
		if len(leaves) == 0 {
			continue
		}
		rounds = append(rounds, rollout.Round{At: at, Leaves: leaves, Pooled: rollout.PooledFromProbes(probesJSON)})
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	flush()
	report(events, gaps)
}

func loadIssuance(ctx context.Context, tx pgx.Tx) map[string]time.Time {
	issued := make(map[string]time.Time)
	rows, err := tx.Query(ctx, `SELECT fingerprint, not_before FROM certificates`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var fingerprint string
		var notBefore time.Time
		if rows.Scan(&fingerprint, &notBefore) == nil && !notBefore.IsZero() {
			issued[fingerprint] = notBefore.UTC()
		}
	}
	return issued
}

func quantiles(values []float64) string {
	if len(values) == 0 {
		return "n=0"
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	at := func(q float64) float64 {
		index := int(math.Ceil(q*float64(len(sorted)))) - 1
		if index < 0 {
			index = 0
		}
		return sorted[index]
	}
	return fmt.Sprintf("n=%d p50=%.1f p75=%.1f p90=%.1f p95=%.1f p99=%.1f max=%.1f", len(sorted), at(0.5), at(0.75), at(0.9), at(0.95), at(0.99), sorted[len(sorted)-1])
}

func report(events []rollout.Event, gaps []float64) {
	var clean, pooled, open, done, undated, unsettled []rollout.Event
	for _, e := range events {
		if e.Pool {
			pooled = append(pooled, e)
			continue
		}
		if e.Reappeared {
			unsettled = append(unsettled, e)
			continue
		}
		clean = append(clean, e)
		if !e.Dated {
			undated = append(undated, e)
		}
		if e.Open {
			open = append(open, e)
		} else {
			done = append(done, e)
		}
	}
	fmt.Printf("replacement events: %d (pool, excluded: %d; predecessor reappeared after an apparent completion, excluded: %d); clean: %d (undated: %d); completed: %d; still open: %d\n",
		len(events), len(pooled), len(unsettled), len(clean), len(undated), len(done), len(open))
	fmt.Println("scan gap between consecutive rounds (h):", quantiles(gaps))
	var lower, upper, gap []float64
	zeroOverlap := 0
	for _, e := range done {
		lower = append(lower, e.LowerHours)
		upper = append(upper, e.UpperHours)
		gap = append(gap, e.ScanGapHours)
		if e.LowerHours == 0 {
			zeroOverlap++
		}
	}
	fmt.Println("completed: proven overlap / lower bound (h):", quantiles(lower))
	fmt.Println("completed: upper bound (h):              ", quantiles(upper))
	fmt.Println("completed: scan gap before start (h):    ", quantiles(gap))
	fmt.Printf("completed with no round showing both leaves live: %d of %d\n", zeroOverlap, len(done))
	// What the completed rollouts prove, per duration H:
	//   certainly within H: upper bound <= H (done before H even at the latest)
	//   certainly beyond H: lower bound >= H (both leaves seen live H apart)
	//   unresolved: the sampling cannot tell.
	for _, hours := range []float64{6, 12, 24, 48, 72} {
		within, beyond := 0, 0
		for _, e := range done {
			if e.UpperHours <= hours {
				within++
			}
			if e.LowerHours >= hours {
				beyond++
			}
		}
		fmt.Printf("  H=%2.0fh: certainly within %d (%.1f%%), certainly beyond %d (%.1f%%), unresolved %d (%.1f%%)\n", hours,
			within, 100*float64(within)/float64(len(done)), beyond, 100*float64(beyond)/float64(len(done)),
			len(done)-within-beyond, 100*float64(len(done)-within-beyond)/float64(len(done)))
	}
	var overlapOnly []float64
	pairs := map[string]struct{}{}
	for _, e := range done {
		pairs[e.Previous+">"+e.Successor] = struct{}{}
		if e.LowerHours > 0 {
			overlapOnly = append(overlapOnly, e.LowerHours)
		}
	}
	fmt.Println("completed with some proven overlap: overlap (h):", quantiles(overlapOnly))
	fmt.Printf("distinct predecessor->successor certificate pairs among completed: %d\n", len(pairs))
	var openLower []float64
	for _, e := range open {
		openLower = append(openLower, e.LowerHours)
	}
	fmt.Println("open: time since start, lower bound (h):  ", quantiles(openLower))
	sort.Slice(open, func(i, j int) bool { return open[i].LowerHours > open[j].LowerHours })
	for index, e := range open {
		if index >= 15 {
			break
		}
		// Completed rollouts that were certainly finished within this open
		// rollout's proven age: the open one is already longer than these.
		exceeded := 0
		for _, d := range done {
			if d.UpperHours <= e.LowerHours {
				exceeded++
			}
		}
		fmt.Printf("  open %-45s %s -> %s  >= %.1f h  dated=%v  longer than %d of %d completed (%.1f%%)\n", e.Domain, short(e.Previous), short(e.Successor), e.LowerHours, e.Dated, exceeded, len(done), 100*float64(exceeded)/float64(len(done)))
	}
	sort.Slice(done, func(i, j int) bool { return done[i].LowerHours > done[j].LowerHours })
	for index, e := range done {
		if index >= 10 {
			break
		}
		fmt.Printf("  done %-45s %s -> %s  overlap >= %.1f h, <= %.1f h\n", e.Domain, short(e.Previous), short(e.Successor), e.LowerHours, e.UpperHours)
	}
}

func short(value string) string {
	if len(value) > 8 {
		return value[:8]
	}
	return value
}
