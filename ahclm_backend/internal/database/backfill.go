package database

import (
	"encoding/json"
	"log"
	"strings"

	"gorm.io/gorm"

	"ahclm/internal/models"
)

// backfillObservationProvenance annotates rows written before the detection
// rules were tightened.
//
// Two things have to be true for a historical finding to be readable:
//
//  1. It must say which rule generation produced it. Aggregating legacy rows
//     with current ones silently lends the current rules' guarantees to
//     evidence that was never held to them.
//  2. A "change" row must say whether it demonstrated a replacement in time.
//     That is recomputable after the fact: rows that retained their own endpoint
//     survey can be checked for the predecessor still answering in the same
//     round, and rows that retained the serving address can be compared with the
//     address that served the predecessor.
//
// Neither step deletes or rewrites a measurement. Only the interpretation
// columns are filled in.
func backfillObservationProvenance(db *gorm.DB) (int64, error) {
	var updated int64

	tagged := db.Model(&models.CertObservation{}).
		Where("detector_version IS NULL OR detector_version = ''").
		Update("detector_version", models.DetectorLegacy)
	if tagged.Error != nil {
		return updated, tagged.Error
	}
	updated += tagged.RowsAffected

	classified, err := backfillChangeClass(db)
	if err != nil {
		return updated, err
	}
	updated += classified
	recovered, err := backfillRecoveredEndpoints(db)
	if err != nil {
		return updated, err
	}
	updated += recovered
	return updated, nil
}

// backfillRecoveredEndpoints copies serving addresses from retained round
// snapshots onto change rows that omitted them. Only appearances within a few
// hours of the change are used, so a later scan cannot rewrite an older event.
func backfillRecoveredEndpoints(db *gorm.DB) (int64, error) {
	var domains []string
	if err := db.Model(&models.CertObservation{}).
		Where("observation_type = ? AND (ip_address IS NULL OR ip_address = '')", models.ObsChange).
		Distinct().Pluck("domain", &domains).Error; err != nil {
		return 0, err
	}
	var updated int64
	for _, domain := range domains {
		var rows []models.CertObservation
		if err := db.Where("domain = ? AND observation_type = ?", domain, models.ObsChange).
			Order("observed_at ASC, id ASC").Find(&rows).Error; err != nil {
			return updated, err
		}
		var snapshots []models.MeasurementSnapshot
		if err := db.Where("domain = ?", domain).Order("observed_at DESC").Find(&snapshots).Error; err != nil {
			return updated, err
		}
		if recoverChangeEndpoints(rows, snapshots) == 0 {
			continue
		}
		for _, row := range rows {
			if strings.TrimSpace(row.IPAddress) == "" {
				continue
			}
			result := db.Model(&models.CertObservation{}).Where("id = ? AND (ip_address IS NULL OR ip_address = '')", row.ID).
				Update("ip_address", row.IPAddress)
			if result.Error != nil {
				return updated, result.Error
			}
			updated += result.RowsAffected
		}
	}
	return updated, nil
}

// backfillChangeClass recomputes, per domain, what each historical change row
// demonstrated. It walks each domain's change sequence oldest-first because the
// address that served the predecessor is the address recorded on the preceding
// change row.
//
// The previous address is deliberately not written back: the analysis derives it
// from the preceding row anyway, so storing it would add a per-row write to
// startup for no extra information. Only the verdict is persisted, batched by
// class so each domain costs a handful of statements rather than one per row.
func backfillChangeClass(db *gorm.DB) (int64, error) {
	var domains []string
	if err := db.Model(&models.CertObservation{}).
		Where("observation_type = ? AND (change_class IS NULL OR change_class = '')", models.ObsChange).
		Distinct().Pluck("domain", &domains).Error; err != nil {
		return 0, err
	}
	var updated int64
	for _, domain := range domains {
		var rows []models.CertObservation
		if err := db.Where("domain = ? AND observation_type = ?", domain, models.ObsChange).
			Order("observed_at ASC, id ASC").Find(&rows).Error; err != nil {
			return updated, err
		}
		byClass := make(map[string][]uint, 4)
		for index, row := range rows {
			if strings.TrimSpace(row.ChangeClass) != "" {
				continue
			}
			previousIP := strings.TrimSpace(row.PreviousIPAddress)
			if previousIP == "" && index > 0 {
				previousIP = strings.TrimSpace(rows[index-1].IPAddress)
			}
			class := replayChangeClass(row, previousIP)
			byClass[class] = append(byClass[class], row.ID)
		}
		for class, ids := range byClass {
			for _, batch := range chunkIDs(ids, 500) {
				result := db.Model(&models.CertObservation{}).Where("id IN ?", batch).
					Update("change_class", class)
				if result.Error != nil {
					return updated, result.Error
				}
				updated += result.RowsAffected
			}
		}
	}
	return updated, nil
}

func chunkIDs(ids []uint, size int) [][]uint {
	if size <= 0 || len(ids) <= size {
		return [][]uint{ids}
	}
	chunks := make([][]uint, 0, (len(ids)+size-1)/size)
	for start := 0; start < len(ids); start += size {
		end := start + size
		if end > len(ids) {
			end = len(ids)
		}
		chunks = append(chunks, ids[start:end])
	}
	return chunks
}

// replayChangeClass applies the current classification to a stored row using
// only what that row already retained.
func replayChangeClass(row models.CertObservation, previousIP string) string {
	previous := strings.TrimSpace(row.PreviousFingerprint)
	current := strings.TrimSpace(row.Fingerprint)
	if previous == "" || current == "" || previous == current {
		return models.ChangeClassUnknown
	}
	if probes := decodeProbes(row.EndpointProbes); len(probes) > 0 {
		sawPrevious, sawCurrent := false, false
		for _, probe := range probes {
			if !probe.Success || probe.Fingerprint == "" {
				continue
			}
			if probe.Fingerprint == previous {
				sawPrevious = true
			}
			if probe.Fingerprint == current {
				sawCurrent = true
			}
		}
		if sawPrevious && sawCurrent {
			return models.ChangeClassCoexisting
		}
	}
	currentIP := strings.TrimSpace(row.IPAddress)
	if previousIP == "" || currentIP == "" {
		return models.ChangeClassUnknown
	}
	if previousIP == currentIP {
		return models.ChangeClassReplacement
	}
	return models.ChangeClassEndpointSampling
}

func decodeProbes(raw string) []models.EndpointProbe {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var probes []models.EndpointProbe
	if json.Unmarshal([]byte(raw), &probes) != nil {
		return nil
	}
	return probes
}

func logBackfill(updated int64, err error) {
	if err != nil {
		log.Printf("warning: could not annotate observation provenance: %v", err)
		return
	}
	if updated > 0 {
		log.Printf("annotated %d observation rows with detector provenance and change classification", updated)
	}
}
