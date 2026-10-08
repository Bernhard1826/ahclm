package database

import (
	"encoding/json"
	"strings"
	"time"

	"ahclm/internal/models"
)

// Kinds of one retained certificate difference, decided from what the address
// itself served rather than from a ratio over the whole sequence.
const (
	changeReplacement = "replacement"     // same address, successor issued later
	changePool        = "pool"            // same address serves more than one leaf at a time
	changeUndated     = "undated"         // same address, issuance dates not retained
	changeOtherAddr   = "other_address"   // successor answered on a different address
	changeUnknownAddr = "unknown_address" // serving address not retained
)

type changeReading struct {
	Kind string
	// Regression is true when the predecessor recorded on this row is older
	// than a leaf the same address had already served: between the two rows
	// the address went back to an older certificate.
	Regression bool
}

// leafIssuanceDates collects NotBefore per leaf fingerprint from stored
// certificates and from every retained endpoint survey.
func leafIssuanceDates(certs map[string]models.Certificate, observations []models.CertObservation, snapshots []models.MeasurementSnapshot) map[string]time.Time {
	dates := make(map[string]time.Time)
	for fingerprint, cert := range certs {
		if !cert.NotBefore.IsZero() {
			dates[fingerprint] = cert.NotBefore.UTC()
		}
	}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || raw == "null" {
			return
		}
		var probes []models.EndpointProbe
		if json.Unmarshal([]byte(raw), &probes) != nil {
			return
		}
		for _, probe := range probes {
			if probe.Fingerprint != "" && probe.NotBefore != nil {
				dates[probe.Fingerprint] = probe.NotBefore.UTC()
			}
		}
	}
	for _, observation := range observations {
		add(observation.EndpointProbes)
	}
	for _, snapshot := range snapshots {
		add(snapshot.EndpointProbesJSON)
	}
	return dates
}

// classifyChanges reads each change row (sorted oldest-first) against the
// history of the address that served it:
//
//   - the address gave two handshakes in the same round different leaves,
//     returned to a leaf it already served, or moved to a leaf issued no later
//     than the predecessor: several leaves are served at once (pool);
//   - the successor was issued later: a replacement in time;
//   - dates unknown: undated, which decides nothing.
func classifyChanges(changes []models.CertObservation, dates map[string]time.Time) []changeReading {
	type history struct {
		served map[string]struct{}
		newest time.Time
	}
	byAddress := make(map[string]*history)
	remember := func(address string, leaves ...string) {
		if address == "" {
			return
		}
		h := byAddress[address]
		if h == nil {
			h = &history{served: make(map[string]struct{})}
			byAddress[address] = h
		}
		for _, leaf := range leaves {
			if leaf == "" {
				continue
			}
			h.served[leaf] = struct{}{}
			if issued, ok := dates[leaf]; ok && issued.After(h.newest) {
				h.newest = issued
			}
		}
	}
	readings := make([]changeReading, len(changes))
	for index, change := range changes {
		previous := strings.TrimSpace(change.PreviousFingerprint)
		current := strings.TrimSpace(change.Fingerprint)
		address := strings.TrimSpace(change.IPAddress)
		relation := endpointRelation(changes, index)
		reading := changeReading{}
		switch relation {
		case endpointDifferent:
			reading.Kind = changeOtherAddr
			remember(address, current)
		case endpointUnknown:
			reading.Kind = changeUnknownAddr
			remember(address, current)
		default:
			h := byAddress[address]
			previousIssued, previousKnown := dates[previous]
			currentIssued, currentKnown := dates[current]
			if h != nil && previousKnown && previousIssued.Before(h.newest) {
				reading.Regression = true
			}
			returning := false
			if h != nil {
				_, returning = h.served[current]
			}
			switch {
			case sameRoundAddressSplit(change), returning:
				// Two leaves in one round, or back to a leaf this address
				// already served: renewal never returns to a retired leaf.
				reading.Kind = changePool
			case previousKnown && currentKnown && currentIssued.After(previousIssued):
				reading.Kind = changeReplacement
			case previousKnown && currentKnown:
				reading.Kind = changePool
			default:
				reading.Kind = changeUndated
			}
			remember(address, previous, current)
		}
		readings[index] = reading
	}
	return readings
}
