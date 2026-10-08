package database

import (
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestOriginReportSeparatesHTTPAvailabilityFromCertificateAdoption(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 1, 0, 0, 0, time.UTC)
	completeAt := t0.Add(90 * time.Second)
	experiment := &models.CDNPropagationExperiment{CertificateLayer: models.CDNPropagationLayerOriginViaCDN, SourceUpdatedAt: t0, Status: models.CDNPropagationRunning, ExpectedLocations: 2, LocationsJSON: `["AS","EU"]`}
	rows := []models.CDNPropagationObservation{
		{RoundID: 1, LocationKey: "AS", ObservedAt: t0.Add(30 * time.Second), RequestSucceeded: true, TLSObserved: true},
		{RoundID: 1, LocationKey: "EU", ObservedAt: t0.Add(30 * time.Second), RequestSucceeded: true, TLSObserved: true},
		{RoundID: 2, LocationKey: "AS", ObservedAt: t0.Add(60 * time.Second), RequestSucceeded: true, TLSObserved: true, IsTarget: true, OriginVerified: true, OriginFingerprint: "new"},
		{RoundID: 2, LocationKey: "EU", ObservedAt: t0.Add(60 * time.Second), RequestSucceeded: true, TLSObserved: true},
	}
	rounds := []models.CDNPropagationRound{{ID: 1, ObservedAt: t0.Add(30 * time.Second)}, {ID: 2, ObservedAt: t0.Add(60 * time.Second)}}
	report := BuildCDNPropagationReport(experiment, rounds, rows)
	if report.SourceToFirstSeconds == nil || *report.SourceToFirstSeconds != 60 || report.AllRegionsTargetAt != nil {
		t.Fatalf("HTTP success counted as certificate adoption: %+v", report)
	}
	if report.Locations[0].State != "request_ok" || report.Locations[1].State != "origin_unverified" {
		t.Fatalf("states: %+v", report.Locations)
	}
	for _, key := range []string{"AS", "EU"} {
		rows = append(rows, models.CDNPropagationObservation{RoundID: 3, LocationKey: key, ObservedAt: completeAt, RequestSucceeded: true, TLSObserved: true, IsTarget: true, OriginVerified: true})
	}
	rounds = append(rounds, models.CDNPropagationRound{ID: 3, ObservedAt: completeAt})
	experiment.Status = models.CDNPropagationComplete
	experiment.CompletedAt = &completeAt
	report = BuildCDNPropagationReport(experiment, rounds, rows)
	if report.SyncState != "origin_verified" || report.SourceToAllRegionsSeconds == nil || *report.SourceToAllRegionsSeconds != 90 {
		t.Fatalf("missing verified report: %+v", report)
	}
	experiment.Status = models.CDNPropagationCanceled
	report = BuildCDNPropagationReport(experiment, rounds, rows)
	if report.SourceToCompleteSeconds != nil {
		t.Fatal("cancellation time reported as stable confirmation")
	}
}
