package database

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"ahclm/internal/models"
)

// BuildPublicKeyDeploymentCycle reconstructs the public lifecycle of the
// leaves and SPKIs observed for one domain. Public sightings constrain the
// deployment interval but do not identify the exact deployment instant: an imported key_generated, certificate_issued, deployment,
// or key_retired event is the only source allowed to name an exact instant.
func BuildPublicKeyDeploymentCycle(domain string, certs []models.Certificate, observations []models.CertObservation, snapshots []models.MeasurementSnapshot, events []models.InternalEvidenceEvent) models.PublicKeyDeploymentCycle {
	domain = models.GetDomain(domain)
	cycle := models.PublicKeyDeploymentCycle{
		Domain:        domain,
		GeneratedAt:   time.Now().UTC(),
		Status:        "external_only",
		Determination: "public_observation_bounds_only",
		Events:        []models.PublicKeyDeploymentEvent{},
		MissingEvidence: []string{
			"密钥管理系统中的密钥生成记录（key_generated）",
			"通过证书指纹关联的签发记录（certificate_issued）",
			"通过证书指纹或 SPKI 关联的部署记录（deployment）",
			"若旧密钥已撤下，需要密钥退役或回滚记录（key_retired / rollback）",
		},
	}

	byFingerprint := map[string]models.Certificate{}
	for _, cert := range certs {
		if cert.Fingerprint == "" {
			continue
		}
		byFingerprint[cert.Fingerprint] = cert
	}

	type leafSighting struct {
		at          time.Time
		fingerprint string
		previous    string
		spki        string
		ip          string
		lowerBound  bool
		source      string
		detail      string
	}
	var sightings []leafSighting

	for _, cert := range certs {
		if cert.Fingerprint == "" {
			continue
		}
		if !cert.NotBefore.IsZero() {
			sightings = append(sightings, leafSighting{
				at: cert.NotBefore.UTC(), fingerprint: cert.Fingerprint, spki: cert.SPKIFingerprint,
				lowerBound: true, source: "certificate_not_before",
				detail: "NotBefore 是证书有效期起始时间，无法单独确定部署时间",
			})
		}
		if !cert.FirstSeenAt.IsZero() {
			sightings = append(sightings, leafSighting{
				at: cert.FirstSeenAt.UTC(), fingerprint: cert.Fingerprint, spki: cert.SPKIFingerprint,
				source: "certificate_first_seen",
				detail: "本监测系统首次存储该叶证书的时间",
			})
		}
	}

	orderedObs := append([]models.CertObservation(nil), observations...)
	sort.SliceStable(orderedObs, func(i, j int) bool {
		if orderedObs[i].ObservedAt.Equal(orderedObs[j].ObservedAt) {
			return orderedObs[i].ID < orderedObs[j].ID
		}
		return orderedObs[i].ObservedAt.Before(orderedObs[j].ObservedAt)
	})
	for _, observation := range orderedObs {
		if observation.Fingerprint == "" || observation.ObservedAt.IsZero() {
			continue
		}
		if observation.ObservationType != models.ObsChange && observation.ObservationType != models.ObsSameKey && observation.ObservationType != "" && observation.PreviousFingerprint == "" {
			continue
		}
		spki := observation.SPKIFingerprint
		if spki == "" {
			if cert, ok := byFingerprint[observation.Fingerprint]; ok {
				spki = cert.SPKIFingerprint
			}
		}
		detail := "公开观测到的证书切换"
		if observation.SPKIFingerprint != "" && observation.PreviousSPKIFingerprint != "" && observation.SPKIFingerprint == observation.PreviousSPKIFingerprint {
			detail = "叶证书变更而 SPKI 不变：同钥替换"
			cycle.SameKeyReplacements++
		}
		sightings = append(sightings, leafSighting{
			at: observation.ObservedAt.UTC(), fingerprint: observation.Fingerprint, previous: observation.PreviousFingerprint, spki: spki,
			ip: observation.IPAddress, source: "observation", detail: detail,
		})
	}

	orderedSnaps := append([]models.MeasurementSnapshot(nil), snapshots...)
	sort.SliceStable(orderedSnaps, func(i, j int) bool { return orderedSnaps[i].ObservedAt.Before(orderedSnaps[j].ObservedAt) })
	stableRounds := 0
	currentStableRounds := 0
	var previousAssignment string
	var firstStableAt *time.Time
	var stableStartAt *time.Time
	totalEndpointSamples := 0
	successfulEndpointSamples := 0
	for _, snapshot := range orderedSnaps {
		assignment := snapshot.TopologyHash
		if strings.TrimSpace(snapshot.EndpointProbesJSON) == "" {
			currentStableRounds = 0
			continue
		}
		var probes []models.EndpointProbe
		if json.Unmarshal([]byte(snapshot.EndpointProbesJSON), &probes) != nil {
			currentStableRounds = 0
			continue
		}
		assignmentMap := map[string]string{}
		roundLeaves := map[string]struct{}{}
		for _, probe := range probes {
			totalEndpointSamples++
			if !probe.Success || probe.Fingerprint == "" || probe.IPAddress == "" {
				continue
			}
			successfulEndpointSamples++
			assignmentMap[probe.IPAddress] = probe.Fingerprint
			roundLeaves[probe.Fingerprint] = struct{}{}
			for _, fp := range probe.OtherFingerprints {
				if fp == "" {
					continue
				}
				roundLeaves[fp] = struct{}{}
				sightings = append(sightings, leafSighting{at: snapshot.ObservedAt.UTC(), fingerprint: fp, ip: probe.IPAddress, source: "endpoint_snapshot", detail: "同一地址重复握手提供的另一张叶证书"})
			}

			spki := probe.SPKIFingerprint
			if cert, ok := byFingerprint[probe.Fingerprint]; ok && spki == "" {
				spki = cert.SPKIFingerprint
			}
			sightings = append(sightings, leafSighting{
				at: snapshot.ObservedAt.UTC(), fingerprint: probe.Fingerprint, spki: spki,
				ip: probe.IPAddress, source: "endpoint_snapshot",
				detail: "该地址在此轮提供此叶证书",
			})
		}
		if len(assignmentMap) > 0 {
			assignment = models.ProviderAssignmentSignature(assignmentMap)
		}
		if len(roundLeaves) == 1 && len(assignmentMap) > 0 && assignment != "" && assignment == previousAssignment {
			currentStableRounds++
		} else if len(roundLeaves) == 1 && len(assignmentMap) > 0 && assignment != "" {
			currentStableRounds = 1
			at := snapshot.ObservedAt.UTC()
			stableStartAt = &at
		} else {
			currentStableRounds = 0
			stableStartAt = nil
		}
		if currentStableRounds > stableRounds {
			stableRounds = currentStableRounds
		}
		if currentStableRounds >= 2 && firstStableAt == nil && stableStartAt != nil {
			at := snapshot.ObservedAt.UTC()
			firstStableAt = &at
		}
		previousAssignment = assignment
	}

	eventMatches := func(event models.InternalEvidenceEvent) bool {
		if event.Fingerprint != "" {
			_, ok := byFingerprint[event.Fingerprint]
			return ok
		}
		if event.SPKIFingerprint != "" {
			for _, cert := range byFingerprint {
				if cert.SPKIFingerprint == event.SPKIFingerprint {
					return true
				}
			}
		}
		return false
	}
	for _, event := range events {
		if !internalEventSucceeded(event) || !eventMatches(event) || (event.Domain != "" && models.GetDomain(event.Domain) != domain) {
			continue
		}
		kind := ""
		switch strings.ToLower(strings.TrimSpace(event.EventType)) {
		case InternalEventKeyGenerated:
			kind = "key_generated"
		case InternalEventCertificateIssued:
			kind = "certificate_issued"
		case InternalEventDeployment:
			kind = "deployed"
		case InternalEventRollback:
			kind = "rolled_back"
		case InternalEventKeyRetired:
			kind = "key_retired"
		default:
			continue
		}
		sightings = append(sightings, leafSighting{
			at: event.OccurredAt.UTC(), fingerprint: event.Fingerprint, spki: event.SPKIFingerprint,
			ip: event.IPAddress, source: "internal_evidence:" + event.SourceSystem, detail: event.Detail,
		})
		cycle.Events = append(cycle.Events, models.PublicKeyDeploymentEvent{
			At: event.OccurredAt.UTC(), Kind: kind, Fingerprint: event.Fingerprint, SPKI: event.SPKIFingerprint,
			IPAddress: event.IPAddress, Source: event.SourceSystem, EvidenceID: event.ID, Detail: event.Detail,
		})
	}

	var firstIssuedExact, firstDeployed, firstRetired *time.Time

	for _, event := range events {
		if !internalEventSucceeded(event) || !eventMatches(event) || (event.Domain != "" && models.GetDomain(event.Domain) != domain) {
			continue
		}
		related := false
		if event.Fingerprint != "" {
			_, related = byFingerprint[event.Fingerprint]
		}
		if !related && event.SPKIFingerprint != "" {
			for _, cert := range byFingerprint {
				if cert.SPKIFingerprint == event.SPKIFingerprint {
					related = true
					break
				}
			}
		}

		if !related {
			continue
		}
		at := event.OccurredAt.UTC()
		switch strings.ToLower(strings.TrimSpace(event.EventType)) {
		case InternalEventCertificateIssued:
			if firstIssuedExact == nil || at.Before(*firstIssuedExact) {
				firstIssuedExact = &at
			}
		case InternalEventDeployment:
			if firstDeployed == nil || at.Before(*firstDeployed) {
				firstDeployed = &at
			}
		case InternalEventKeyRetired:
			if firstRetired == nil || at.Before(*firstRetired) {
				firstRetired = &at
			}
		}
	}

	sort.SliceStable(sightings, func(i, j int) bool { return sightings[i].at.Before(sightings[j].at) })
	seenLeaf := map[string]struct{}{}
	seenKey := map[string]struct{}{}
	addresses := map[string]struct{}{}
	var firstIssued, firstPublic, lastChange *time.Time
	lastPublicByLeaf := map[string]time.Time{}
	var successorGap *float64
	for _, sighting := range sightings {
		if sighting.fingerprint != "" {
			if _, ok := seenLeaf[sighting.fingerprint]; !ok {
				seenLeaf[sighting.fingerprint] = struct{}{}
				kind := "leaf_first_observed"
				if sighting.lowerBound {
					kind = "not_before_lower_bound"
				}
				if sighting.source == "certificate_first_seen" {
					kind = "leaf_first_stored"
				}
				cycle.Events = append(cycle.Events, models.PublicKeyDeploymentEvent{
					At: sighting.at, Kind: kind, Fingerprint: sighting.fingerprint, Previous: sighting.previous, SPKI: sighting.spki,
					IPAddress: sighting.ip, Source: sighting.source, LowerBound: sighting.lowerBound, Detail: sighting.detail,
				})
			}
			if sighting.source == "observation" && sighting.previous != "" {
				cycle.Events = append(cycle.Events, models.PublicKeyDeploymentEvent{
					At: sighting.at, Kind: "public_transition", Fingerprint: sighting.fingerprint,
					Previous: sighting.previous, SPKI: sighting.spki, IPAddress: sighting.ip,
					Source: sighting.source, LowerBound: true, Detail: "公开观测限定了切换时间范围，无法给出精确部署时刻",
				})
			}
		}
		if sighting.spki != "" {
			seenKey[sighting.spki] = struct{}{}
		}
		if sighting.ip != "" {
			addresses[sighting.ip] = struct{}{}
		}
		if sighting.source == "certificate_not_before" && (firstIssued == nil || sighting.at.Before(*firstIssued)) {
			at := sighting.at
			firstIssued = &at
		}
		if (sighting.source == "certificate_first_seen" || sighting.source == "observation" || sighting.source == "endpoint_snapshot") && (firstPublic == nil || sighting.at.Before(*firstPublic)) {
			at := sighting.at
			firstPublic = &at
		}
		if sighting.source == "observation" && (lastChange == nil || sighting.at.After(*lastChange)) {
			at := sighting.at
			lastChange = &at
		}
		if sighting.source == "observation" && sighting.previous != "" {
			if previousAt, ok := lastPublicByLeaf[sighting.previous]; ok && !sighting.at.Before(previousAt) {
				seconds := sighting.at.Sub(previousAt).Seconds()
				if successorGap == nil || seconds < *successorGap {
					successorGap = &seconds
				}
			}
		}
		if sighting.source == "observation" || sighting.source == "endpoint_snapshot" || sighting.source == "certificate_first_seen" {
			if previousAt, ok := lastPublicByLeaf[sighting.fingerprint]; !ok || sighting.at.After(previousAt) {
				lastPublicByLeaf[sighting.fingerprint] = sighting.at
			}
		}
	}

	sort.SliceStable(cycle.Events, func(i, j int) bool {
		if cycle.Events[i].At.Equal(cycle.Events[j].At) {
			return cycle.Events[i].Kind < cycle.Events[j].Kind
		}
		return cycle.Events[i].At.Before(cycle.Events[j].At)
	})

	cycle.CertificateCount = len(seenLeaf)
	cycle.PublicKeyCount = len(seenKey)
	cycle.Metrics.FirstIssuedAt = firstIssued
	cycle.Metrics.FirstIssuedExactAt = firstIssuedExact
	cycle.Metrics.FirstDeployedAt = firstDeployed
	cycle.Metrics.FirstRetiredAt = firstRetired
	cycle.Metrics.FirstPublicObservedAt = firstPublic
	cycle.Metrics.LastChangeAt = lastChange
	cycle.Metrics.AddressCount = len(addresses)
	cycle.Metrics.StableRoundCount = stableRounds
	if totalEndpointSamples > 0 {
		cycle.Metrics.AddressCoverage = float64(successfulEndpointSamples) / float64(totalEndpointSamples)
	}
	if firstStableAt != nil && firstPublic != nil && !firstStableAt.Before(*firstPublic) {
		seconds := firstStableAt.Sub(*firstPublic).Seconds()
		cycle.Metrics.FirstPublicToStableSeconds = &seconds
	}
	cycle.Metrics.SuccessorToPreviousRetirementSec = successorGap
	cycle.Metrics.IssuanceToFirstPublicBasis = "not_before"
	issuanceStart := firstIssued
	if firstIssuedExact != nil {
		issuanceStart = firstIssuedExact
		cycle.Metrics.IssuanceToFirstPublicBasis = "exact_issuance"
	}
	if issuanceStart != nil && firstPublic != nil && !firstPublic.Before(*issuanceStart) {
		seconds := firstPublic.Sub(*issuanceStart).Seconds()
		cycle.Metrics.IssuanceToFirstPublicSeconds = &seconds
	}
	if firstDeployed != nil && firstPublic != nil && !firstPublic.Before(*firstDeployed) {
		seconds := firstPublic.Sub(*firstDeployed).Seconds()
		cycle.Metrics.DeploymentToFirstPublicSeconds = &seconds
	}
	if firstPublic != nil && lastChange != nil && lastChange.After(*firstPublic) {
		seconds := lastChange.Sub(*firstPublic).Seconds()
		cycle.Metrics.ObservedSpanSeconds = &seconds
	}
	// "Current" is the latest public observation, not the latest NotBefore.
	var latest time.Time
	latestLeaves := map[string]string{}
	for _, sighting := range sightings {
		if sighting.source != "observation" && sighting.source != "endpoint_snapshot" && sighting.source != "certificate_first_seen" {
			continue
		}
		if sighting.at.IsZero() || sighting.fingerprint == "" {
			continue
		}
		if sighting.at.After(latest) {
			latest = sighting.at
			latestLeaves = map[string]string{}
		}
		if sighting.at.Equal(latest) {
			latestLeaves[sighting.fingerprint] = sighting.spki
		}
	}
	if len(latestLeaves) == 1 {
		for fp, spki := range latestLeaves {
			cycle.CurrentFingerprint = fp
			cycle.CurrentSPKI = spki
			if spki == "" {
				cycle.CurrentSPKI = byFingerprint[fp].SPKIFingerprint
			}
		}
	}

	summary := SummarizeInternalEvidenceForContext(events, "frequent_change", certs, observations, snapshots)
	cycle.InternalEvidence = &summary
	if summary.Status == "complete" {
		cycle.Status = "complete"
		cycle.Determination = summary.RootCauseCode
		cycle.MissingEvidence = nil
	} else if summary.Status == "partial" {
		cycle.Status = "partial"
		cycle.Determination = "control_plane_events_present_but_not_correlated"
	}
	return cycle
}

// GetPublicKeyDeploymentCycle loads the retained certificates, transitions,
// endpoint snapshots and imported control-plane events for one monitored
// domain and returns the reconstructed lifecycle.
func (d *Database) GetPublicKeyDeploymentCycle(domain string) (*models.PublicKeyDeploymentCycle, error) {
	domain = models.GetDomain(domain)
	if _, err := d.GetDomainCertificate(domain); err != nil {
		return nil, err
	}
	var observations []models.CertObservation
	if err := d.db.Where("domain = ?", domain).Order("observed_at ASC, id ASC").Find(&observations).Error; err != nil {
		return nil, err
	}
	fingerprints := map[string]struct{}{}
	for _, observation := range observations {
		if observation.Fingerprint != "" {
			fingerprints[observation.Fingerprint] = struct{}{}
		}
		if observation.PreviousFingerprint != "" {
			fingerprints[observation.PreviousFingerprint] = struct{}{}
		}
	}
	snapshots, err := d.GetMeasurementSnapshots(domain, 400)
	if err != nil {
		return nil, err
	}
	events, err := d.GetInternalEvidence(domain, 1000)
	if err != nil {
		return nil, err
	}
	for _, snapshot := range snapshots {
		if snapshot.CertificateFingerprint != "" {
			fingerprints[snapshot.CertificateFingerprint] = struct{}{}
		}
	}
	var certs []models.Certificate
	if len(fingerprints) > 0 {
		values := make([]string, 0, len(fingerprints))
		for fingerprint := range fingerprints {
			values = append(values, fingerprint)
		}
		if err := d.db.Where("fingerprint IN ?", values).Find(&certs).Error; err != nil {
			return nil, err
		}
	}
	cycle := BuildPublicKeyDeploymentCycle(domain, certs, observations, snapshots, events)
	return &cycle, nil
}
