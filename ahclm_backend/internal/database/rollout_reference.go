package database

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"ahclm/internal/models"
	"ahclm/internal/rollout"
)

// rolloutStandard is the reference distribution of completed rollouts plus the
// operator's alert share. The diagnosis compares an open rollout's proven
// overlap with it instead of with a fixed number of hours.
type rolloutStandard struct {
	reference  *rollout.Reference
	alertShare float64
}

var currentRolloutStandard atomic.Pointer[rolloutStandard]

func loadRolloutStandard() *rolloutStandard { return currentRolloutStandard.Load() }

// SetRolloutAlertShare records the operator's alert share (0 disables the
// stuck verdict). It keeps the current reference.
func SetRolloutAlertShare(share float64) {
	next := &rolloutStandard{alertShare: share}
	if current := loadRolloutStandard(); current != nil {
		next.reference = current.reference
	}
	currentRolloutStandard.Store(next)
}

func setRolloutReference(reference *rollout.Reference) {
	next := &rolloutStandard{reference: reference}
	if current := loadRolloutStandard(); current != nil {
		next.alertShare = current.alertShare
	}
	currentRolloutStandard.Store(next)
}

// RolloutPosition describes an open rollout against the reference.
type rolloutPosition struct {
	known          bool // a reference is available
	finishedWithin int  // completed rollouts that certainly finished within the overlap
	completed      int
	share          float64
	alertShare     float64
	beyondAlert    bool // share exceeds the operator's alert share (alertShare > 0)
	reference      *rollout.Reference
}

func positionOfOverlap(hours float64) rolloutPosition {
	standard := loadRolloutStandard()
	if standard == nil || standard.reference == nil || standard.reference.Completed == 0 {
		return rolloutPosition{}
	}
	count, share := standard.reference.FinishedWithin(hours)
	return rolloutPosition{
		known: true, finishedWithin: count, completed: standard.reference.Completed,
		share: share, alertShare: standard.alertShare, reference: standard.reference,
		beyondAlert: standard.alertShare > 0 && share > standard.alertShare,
	}
}

// ComputeRolloutReference rebuilds the reference distribution from every
// retained snapshot. It only reads.
func (d *Database) ComputeRolloutReference(ctx context.Context) (*rollout.Reference, error) {
	issued := make(map[string]time.Time)
	var certs []models.Certificate
	if err := d.db.WithContext(ctx).Select("fingerprint", "not_before").Find(&certs).Error; err != nil {
		return nil, err
	}
	for _, cert := range certs {
		if !cert.NotBefore.IsZero() {
			issued[cert.Fingerprint] = cert.NotBefore.UTC()
		}
	}
	rows, err := d.db.WithContext(ctx).Model(&models.MeasurementSnapshot{}).
		Select("domain", "observed_at", "endpoint_fingerprints_json", "topology_json", "endpoint_probes_json").
		Order("domain, observed_at, id").Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []rollout.Event
	var rounds []rollout.Round
	var first, last time.Time
	current := ""
	flush := func() {
		if current != "" && len(rounds) > 0 {
			events = append(events, rollout.AnalyzeDomain(current, rounds, issued)...)
		}
		rounds = rounds[:0]
	}
	for rows.Next() {
		var domain string
		var at time.Time
		var assignment, topology, probes *string
		if err := rows.Scan(&domain, &at, &assignment, &topology, &probes); err != nil {
			return nil, err
		}
		if domain != current {
			flush()
			current = domain
		}
		if first.IsZero() || at.Before(first) {
			first = at
		}
		if at.After(last) {
			last = at
		}
		if probes != nil {
			rollout.AddIssuance(*probes, issued)
		}
		if assignment == nil || topology == nil {
			continue
		}
		if leaves := rollout.ActiveLeaves(*assignment, *topology); len(leaves) > 0 {
			round := rollout.Round{At: at, Leaves: leaves}
			if probes != nil {
				round.Pooled = rollout.PooledFromProbes(*probes)
			}
			rounds = append(rounds, round)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	flush()
	return rollout.BuildReference(events, first, last, time.Now()), nil
}

// StartRolloutReference computes the reference now and then every interval.
func (d *Database) StartRolloutReference(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	refresh := func() {
		started := time.Now()
		reference, err := d.ComputeRolloutReference(ctx)
		if err != nil {
			log.Printf("rollout reference: %v", err)
			return
		}
		setRolloutReference(reference)
		log.Printf("rollout reference: %d completed rollouts (%d distinct pairs, %d pool, %d unsettled, %d open) over %s..%s in %s",
			reference.Completed, reference.DistinctPairs, reference.Pool, reference.Unsettled, reference.Open,
			reference.WindowStart.Format(time.RFC3339), reference.WindowEnd.Format(time.RFC3339), time.Since(started).Round(time.Second))
	}
	go func() {
		refresh()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
}
