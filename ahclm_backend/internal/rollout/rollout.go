// Package rollout measures certificate rollouts from retained endpoint surveys
// and keeps the reference distribution that open rollouts are compared with.
//
// Every duration is reported as the interval the sampling can prove, never as
// a point estimate:
//
//   - Active address: in the round's resolver consensus (consensus_ips, falling
//     back to public_ips). Only addresses that answered TLS are observed; the
//     rest are unknown, not absent.
//   - Replacement P -> S: an active address served P at one observation and S
//     at its next. When both NotBefore dates are known, S must be issued after
//     P; otherwise the event is kept and marked undated.
//   - Pool: an address later went S -> P, or returned to P after serving S.
//     Renewal never returns to a retired leaf; pool events are excluded.
//   - Start: first round in which any active address served S.
//   - Completion: first later round in which no answering active address
//     served P. If P is seen again afterwards the event is unsettled and
//     excluded.
//   - Lower bound (proven overlap): last round P was seen minus the start.
//   - Upper bound: completion minus the last round before S appeared.
//   - Open: P still served in the latest round; only a lower bound exists.
//   - Left-censored: S already present in the first retained round; excluded.
package rollout

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Round is one measurement of a domain: active answering address -> leaf.
// Pooled lists, per address, the other leaves that address presented within
// the same round's repeated handshakes.
type Round struct {
	At     time.Time
	Leaves map[string]string
	Pooled map[string][]string
}

// PooledFromProbes extracts, per address, the extra leaves a snapshot's full
// endpoint survey recorded from repeated handshakes.
func PooledFromProbes(probesJSON string) map[string][]string {
	if strings.TrimSpace(probesJSON) == "" || probesJSON == "null" {
		return nil
	}
	var probes []struct {
		IPAddress         string   `json:"ip_address"`
		Fingerprint       string   `json:"fingerprint"`
		OtherFingerprints []string `json:"other_fingerprints"`
	}
	if json.Unmarshal([]byte(probesJSON), &probes) != nil {
		return nil
	}
	var pooled map[string][]string
	for _, probe := range probes {
		if len(probe.OtherFingerprints) == 0 {
			continue
		}
		if pooled == nil {
			pooled = make(map[string][]string)
		}
		pooled[probe.IPAddress] = append([]string{probe.Fingerprint}, probe.OtherFingerprints...)
	}
	return pooled
}

// Event is one replacement P -> S within a domain.
type Event struct {
	Domain, Previous, Successor string
	Dated, Pool, Open           bool
	Reappeared                  bool
	LowerHours, UpperHours      float64 // UpperHours < 0 when open
	ScanGapHours                float64
}

// ActiveLeaves reduces a snapshot to its active answering addresses.
func ActiveLeaves(assignmentJSON, topologyJSON string) map[string]string {
	assignment := map[string]string{}
	if json.Unmarshal([]byte(assignmentJSON), &assignment) != nil {
		return nil
	}
	var topology struct {
		ConsensusIPs []string `json:"consensus_ips"`
		PublicIPs    []string `json:"public_ips"`
	}
	_ = json.Unmarshal([]byte(topologyJSON), &topology)
	active := topology.ConsensusIPs
	if len(active) == 0 {
		active = topology.PublicIPs
	}
	leaves := make(map[string]string)
	for _, address := range active {
		if leaf := assignment[address]; leaf != "" {
			leaves[address] = leaf
		}
	}
	return leaves
}

// AddIssuance records NotBefore per leaf from a snapshot's full endpoint survey.
func AddIssuance(probesJSON string, issued map[string]time.Time) {
	if strings.TrimSpace(probesJSON) == "" || probesJSON == "null" {
		return
	}
	var probes []struct {
		Fingerprint string     `json:"fingerprint"`
		NotBefore   *time.Time `json:"not_before"`
	}
	if json.Unmarshal([]byte(probesJSON), &probes) != nil {
		return
	}
	for _, probe := range probes {
		if probe.Fingerprint != "" && probe.NotBefore != nil {
			issued[probe.Fingerprint] = probe.NotBefore.UTC()
		}
	}
}

// AnalyzeDomain finds every replacement in one domain's rounds (oldest first).
func AnalyzeDomain(domain string, rounds []Round, issued map[string]time.Time) []Event {
	type observation struct{ leaf string }
	byAddress := make(map[string][]observation)
	for _, r := range rounds {
		for address, leaf := range r.Leaves {
			byAddress[address] = append(byAddress[address], observation{leaf})
		}
	}
	type pair struct{ previous, successor string }
	successions := make(map[pair]struct{})
	pool := make(map[pair]bool)
	for _, sequence := range byAddress {
		first := map[string]int{}
		for position, obs := range sequence {
			if position > 0 && sequence[position-1].leaf != obs.leaf {
				successions[pair{sequence[position-1].leaf, obs.leaf}] = struct{}{}
			}
			if _, ok := first[obs.leaf]; !ok {
				first[obs.leaf] = position
			}
		}
		for position := 1; position < len(sequence); position++ {
			leaf, prior := sequence[position].leaf, sequence[position-1].leaf
			if prior != leaf && first[leaf] < position-1 {
				pool[pair{prior, leaf}] = true
				pool[pair{leaf, prior}] = true
			}
		}
	}
	var events []Event
	// One address presenting both leaves within a round is a server pool,
	// proven in that round rather than inferred across rounds.
	for _, r := range rounds {
		for _, leaves := range r.Pooled {
			for _, a := range leaves {
				for _, b := range leaves {
					if a != b {
						pool[pair{a, b}] = true
					}
				}
			}
		}
	}
	for p := range successions {
		if _, reverse := successions[pair{p.successor, p.previous}]; reverse {
			pool[p] = true
		}
		e := Event{Domain: domain, Previous: p.previous, Successor: p.successor, Pool: pool[p]}
		previousIssued, previousKnown := issued[p.previous]
		successorIssued, successorKnown := issued[p.successor]
		if previousKnown && successorKnown {
			if !successorIssued.After(previousIssued) {
				continue // not a replacement in time
			}
			e.Dated = true
		}
		start := -1
		for index, r := range rounds {
			if containsLeaf(r.Leaves, p.successor) {
				start = index
				break
			}
		}
		if start <= 0 {
			continue // left-censored
		}
		before := start - 1
		lastPrevious, done := -1, -1
		for index := start; index < len(rounds); index++ {
			if containsLeaf(rounds[index].Leaves, p.previous) {
				lastPrevious = index
				continue
			}
			done = index
			break
		}
		if done >= 0 {
			for index := done + 1; index < len(rounds); index++ {
				if containsLeaf(rounds[index].Leaves, p.previous) {
					e.Reappeared = true
					break
				}
			}
		}
		e.ScanGapHours = rounds[start].At.Sub(rounds[before].At).Hours()
		if lastPrevious >= 0 {
			e.LowerHours = rounds[lastPrevious].At.Sub(rounds[start].At).Hours()
		}
		if done < 0 {
			e.Open = true
			e.UpperHours = -1
			e.LowerHours = rounds[len(rounds)-1].At.Sub(rounds[start].At).Hours()
		} else {
			e.UpperHours = rounds[done].At.Sub(rounds[before].At).Hours()
		}
		events = append(events, e)
	}
	return events
}

func containsLeaf(leaves map[string]string, leaf string) bool {
	for _, value := range leaves {
		if value == leaf {
			return true
		}
	}
	return false
}

// Reference is the distribution of completed rollouts that an open rollout is
// compared with. UpperHours is sorted ascending.
type Reference struct {
	ComputedAt    time.Time `json:"computed_at"`
	WindowStart   time.Time `json:"window_start"`
	WindowEnd     time.Time `json:"window_end"`
	Completed     int       `json:"completed"`
	DistinctPairs int       `json:"distinct_pairs"`
	Pool          int       `json:"pool_excluded"`
	Unsettled     int       `json:"unsettled_excluded"`
	Open          int       `json:"open"`
	UpperHours    []float64 `json:"-"`
}

// BuildReference keeps completed, non-pool, settled events.
func BuildReference(events []Event, windowStart, windowEnd, computedAt time.Time) *Reference {
	reference := &Reference{ComputedAt: computedAt, WindowStart: windowStart, WindowEnd: windowEnd}
	pairs := map[string]struct{}{}
	for _, e := range events {
		switch {
		case e.Pool:
			reference.Pool++
		case e.Reappeared:
			reference.Unsettled++
		case e.Open:
			reference.Open++
		default:
			reference.Completed++
			reference.UpperHours = append(reference.UpperHours, e.UpperHours)
			pairs[e.Previous+">"+e.Successor] = struct{}{}
		}
	}
	reference.DistinctPairs = len(pairs)
	sort.Float64s(reference.UpperHours)
	return reference
}

// FinishedWithin returns how many completed rollouts certainly finished within
// the given hours (their upper bound is not longer), and that share.
func (r *Reference) FinishedWithin(hours float64) (int, float64) {
	if r == nil || r.Completed == 0 {
		return 0, 0
	}
	count := sort.Search(len(r.UpperHours), func(index int) bool { return r.UpperHours[index] > hours })
	return count, float64(count) / float64(r.Completed)
}
