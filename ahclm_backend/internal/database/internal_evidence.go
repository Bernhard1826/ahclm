package database

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"ahclm/internal/models"

	"gorm.io/gorm"
)

// Internal event types are intentionally broad. A vendor adapter can preserve
// its native event name while still mapping the event to one of these causal
// roles in SummarizeInternalEvidence.
const (
	InternalEventAddressPool       = "address_pool_membership"
	InternalEventHostnameBinding   = "hostname_binding"
	InternalEventDNSChange         = "dns_change"
	InternalEventEdgePublish       = "edge_publish"
	InternalEventEdgeServeCheck    = "edge_serve_check"
	InternalEventCertificateIssued = "certificate_issued"
	InternalEventKeyGenerated      = "key_generated"
	InternalEventDeployment        = "deployment"
	InternalEventRollback          = "rollback"
	InternalEventRenewalPolicy     = "renewal_policy"
	InternalEventCAOrder           = "ca_order"
	InternalEventKeyRetired        = "key_retired"
)

// CreateInternalEvidence stores one operator-supplied control-plane record.
// It deliberately requires a monitored domain so imported logs cannot create
// a second population that the active measurement system never observed.
func (d *Database) CreateInternalEvidence(event *models.InternalEvidenceEvent) error {
	if event == nil {
		return fmt.Errorf("internal evidence event is nil")
	}
	if err := validateInternalEvidence(event); err != nil {
		return err
	}
	event.Domain = models.GetDomain(event.Domain)
	var enrolled int64
	if err := d.db.Model(&models.DomainCertificate{}).Where("domain = ? AND "+monitoredPredicate, event.Domain).Count(&enrolled).Error; err != nil {
		return err
	}
	if enrolled == 0 {
		return ErrDomainNotMonitored
	}
	if event.IngestedAt.IsZero() {
		event.IngestedAt = time.Now().UTC()
	}
	if err := d.db.Create(event).Error; err != nil {
		return err
	}
	d.invalidateAnomalyCache()
	return nil
}

// CreateInternalEvidenceBatch writes an exported log batch atomically. A
// single invalid row rejects the batch, which prevents a partial causal record
// from being mistaken for a complete control-plane trace.
func (d *Database) CreateInternalEvidenceBatch(events []models.InternalEvidenceEvent) error {
	if len(events) == 0 {
		return nil
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		for index := range events {
			event := &events[index]
			if err := validateInternalEvidence(event); err != nil {
				return fmt.Errorf("internal evidence row %d: %w", index, err)
			}
			event.Domain = models.GetDomain(event.Domain)
			var enrolled int64
			if err := tx.Model(&models.DomainCertificate{}).Where("domain = ? AND "+monitoredPredicate, event.Domain).Count(&enrolled).Error; err != nil {
				return err
			}
			if enrolled == 0 {
				return ErrDomainNotMonitored
			}
			if event.IngestedAt.IsZero() {
				event.IngestedAt = time.Now().UTC()
			}
			if err := tx.Create(event).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Database) GetInternalEvidence(domain string, limit int) ([]models.InternalEvidenceEvent, error) {
	domain = models.GetDomain(domain)
	if _, err := d.GetDomainCertificate(domain); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	var events []models.InternalEvidenceEvent
	err := d.db.Where("domain = ?", domain).Order("occurred_at ASC, id ASC").Limit(limit).Find(&events).Error
	return events, err
}

// SummarizeInternalEvidence is the deterministic causal gate shared by the
// API and the offline deep-diagnosis experiment. A public symptom is never
// promoted to an internal cause unless the matching control-plane sequence is
// present and correlated by domain, address/fingerprint, or correlation ID.
func SummarizeInternalEvidence(events []models.InternalEvidenceEvent, findingType string) models.InternalEvidenceSummary {
	summary := models.InternalEvidenceSummary{
		Status:             "absent",
		Determination:      "external_only",
		Confidence:         "low",
		EventCount:         len(events),
		Evidence:           []string{},
		Missing:            []string{},
		NextRequiredEvents: []string{},
	}
	if len(events) == 0 {
		summary.Missing = internalEvidenceRequirements(findingType)
		summary.NextRequiredEvents = append([]string(nil), summary.Missing...)
		return summary
	}

	sources := make(map[string]struct{})
	types := make(map[string]struct{})
	for _, event := range events {
		if source := strings.TrimSpace(event.SourceSystem); source != "" {
			sources[source] = struct{}{}
		}
		if eventType := strings.TrimSpace(event.EventType); eventType != "" {
			types[eventType] = struct{}{}
		}
		if summary.LastEventAt == nil || event.OccurredAt.After(*summary.LastEventAt) {
			at := event.OccurredAt
			summary.LastEventAt = &at
		}
	}
	summary.SourceSystems = sortedSet(sources)
	summary.EventTypes = sortedSet(types)

	lookup := make(map[string][]models.InternalEvidenceEvent)
	for _, event := range events {
		if event.OccurredAt.IsZero() || strings.TrimSpace(event.SourceSystem) == "" {
			continue
		}
		lookup[strings.ToLower(strings.TrimSpace(event.EventType))] = append(lookup[strings.ToLower(strings.TrimSpace(event.EventType))], event)
	}

	var code, label, conclusion string
	var correlated int
	switch normalizeFindingType(findingType) {
	case "hostname_mismatch", "deployment_failure", models.ObsStaleAfterChange:
		code, label, conclusion, correlated = summarizeNameBinding(lookup)
	case "frequent_change", "early_renewal", "same_key":
		code, label, conclusion, correlated = summarizeChurn(lookup)
	default:
		code, label, conclusion, correlated = summarizeGeneric(lookup)
	}
	summary.CorrelatedEvents = correlated
	if code != "" && correlated > 0 {
		summary.Status = "complete"
		summary.Determination = "internal_cause_identified"
		summary.RootCauseCode = code
		summary.RootCauseLabel = label
		summary.Conclusion = conclusion
		summary.Confidence = "high"
		summary.Evidence = internalEvidenceLines(causalSupportingEvents(lookup, code), code, 8)
		return summary
	}
	summary.Status = "partial"
	summary.Determination = "control_plane_events_present_but_not_correlated"
	summary.Confidence = "low"
	summary.Missing = internalEvidenceRequirements(findingType)
	summary.NextRequiredEvents = append([]string(nil), summary.Missing...)
	summary.Evidence = internalEvidenceLines(events, "", 8)
	return summary
}

// SummarizeInternalEvidenceForContext applies the causal sequence to the
// public observations retained for the same domain. A control-plane sequence
// can only become complete when at least one of its identifying keys (leaf,
// SPKI, endpoint address, or a correlation ID shared with such an event) is
// also present in the measured context.
func SummarizeInternalEvidenceForContext(events []models.InternalEvidenceEvent, findingType string, certs []models.Certificate, observations []models.CertObservation, snapshots []models.MeasurementSnapshot) models.InternalEvidenceSummary {
	if len(events) == 0 {
		return SummarizeInternalEvidence(events, findingType)
	}
	fingerprints := map[string]struct{}{}
	spkis := map[string]struct{}{}
	addresses := map[string]struct{}{}
	for _, cert := range certs {
		if cert.Fingerprint != "" {
			fingerprints[cert.Fingerprint] = struct{}{}
		}
		if cert.SPKIFingerprint != "" {
			spkis[cert.SPKIFingerprint] = struct{}{}
		}
	}
	for _, observation := range observations {
		for _, value := range []string{observation.Fingerprint, observation.PreviousFingerprint} {
			if value != "" {
				fingerprints[value] = struct{}{}
			}
		}
		for _, value := range []string{observation.SPKIFingerprint, observation.PreviousSPKIFingerprint} {
			if value != "" {
				spkis[value] = struct{}{}
			}
		}
		if observation.IPAddress != "" {
			addresses[observation.IPAddress] = struct{}{}
		}
	}
	for _, snapshot := range snapshots {
		if snapshot.CertificateFingerprint != "" {
			fingerprints[snapshot.CertificateFingerprint] = struct{}{}
		}
		var probes []models.EndpointProbe
		if snapshot.EndpointProbesJSON == "" || json.Unmarshal([]byte(snapshot.EndpointProbesJSON), &probes) != nil {
			continue
		}
		for _, probe := range probes {
			if probe.Fingerprint != "" {
				fingerprints[probe.Fingerprint] = struct{}{}
			}
			if probe.SPKIFingerprint != "" {
				spkis[probe.SPKIFingerprint] = struct{}{}
			}
			if probe.IPAddress != "" {
				addresses[probe.IPAddress] = struct{}{}
			}
		}
	}
	matchedIDs := map[string]struct{}{}
	matched := make([]bool, len(events))
	conflicting := make([]bool, len(events))
	var latestPublic time.Time
	for _, observation := range observations {
		if observation.ObservedAt.After(latestPublic) {
			latestPublic = observation.ObservedAt
		}
	}
	for _, snapshot := range snapshots {
		if snapshot.ObservedAt.After(latestPublic) {
			latestPublic = snapshot.ObservedAt
		}
	}
	for index, event := range events {
		_, fp := fingerprints[event.Fingerprint]
		_, spki := spkis[event.SPKIFingerprint]
		_, ip := addresses[event.IPAddress]
		conflicting[index] = (event.IPAddress != "" && len(addresses) > 0 && !ip) ||
			(event.Fingerprint != "" && len(fingerprints) > 0 && !fp) ||
			(event.SPKIFingerprint != "" && len(spkis) > 0 && !spki) ||
			(!latestPublic.IsZero() && event.OccurredAt.After(latestPublic))
		matched[index] = !conflicting[index] && ((event.Fingerprint != "" && fp) || (event.SPKIFingerprint != "" && spki) || (event.IPAddress != "" && ip))
		if matched[index] && event.CorrelationID != "" {
			matchedIDs[event.CorrelationID] = struct{}{}
		}
	}
	for index, event := range events {
		if !matched[index] && !conflicting[index] && event.CorrelationID != "" {
			_, matched[index] = matchedIDs[event.CorrelationID]
		}
	}
	// Only matched events may supply the cause; an unrelated matched event
	// cannot substitute for the event that actually supports the conclusion.
	var relevant []models.InternalEvidenceEvent
	for i, event := range events {
		if matched[i] {
			relevant = append(relevant, event)
		}
	}
	summary := SummarizeInternalEvidence(relevant, findingType)
	summary.EventCount = len(events)
	if len(relevant) == 0 {
		summary.Status = "partial"
		summary.Determination = "control_plane_events_present_but_not_correlated"
		summary.Missing = append(summary.Missing, "event fingerprint/SPKI/IP matching the public observation")
		summary.NextRequiredEvents = append([]string(nil), summary.Missing...)
	}
	return summary
}

func applyInternalEvidence(diagnosis *models.CauseDiagnosis, summary models.InternalEvidenceSummary) {
	if diagnosis == nil {
		return
	}
	diagnosis.InternalEvidence = &summary
	if summary.Status != "complete" || summary.RootCauseCode == "" {
		return
	}
	// The measured phenomenon keeps its own primary_code. The imported event
	// sequence supplies the previously missing operational cause and upgrades
	// only the causal status, summary and confidence.
	diagnosis.CauseStatus = "established"
	diagnosis.Confidence = "high"
	diagnosis.Summary = summary.Conclusion
	diagnosis.MeasurementPlan = nil
}

func normalizeFindingType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == models.ObsDeploymentFailure {
		return "deployment_failure"
	}
	if value == models.ObsStaleAfterChange {
		return "stale_after_change"
	}
	return value
}

func summarizeNameBinding(lookup map[string][]models.InternalEvidenceEvent) (string, string, string, int) {
	pool := latestInternalEvent(lookup[InternalEventAddressPool])
	bindings := lookup[InternalEventHostnameBinding]
	publish := latestInternalEvent(lookup[InternalEventEdgePublish])
	serve := latestInternalEvent(lookup[InternalEventEdgeServeCheck])
	if pool != nil && statusIn(pool, "excluded", "removed", "not_expected", "inactive") {
		return "address_pool_membership_excluded", "Public address was not an intended member of the hostname pool", "The control-plane record marks the answering address as excluded from the hostname's public address pool; the externally observed wrong certificate is therefore a stale or unintended public address publication.", 1
	}
	if binding := latestInternalEvent(bindings); binding != nil {
		if statusIn(binding, "missing", "not_applied", "failed", "rejected") || (internalEventSucceeded(*binding) && actionIn(binding, "unbind", "remove", "delete")) {
			return "hostname_binding_not_published", "Hostname-to-certificate binding was not published", "The latest correlated hostname binding record reports that the expected binding was missing or rejected.", 1
		}
	}
	if publish != nil && statusIn(publish, "failed", "error", "rolled_back") {
		return "edge_publish_failed", "Edge certificate publish failed", "The binding existed, but the edge publish record reports failure or rollback for the certificate version correlated with the defective endpoint.", 1
	}
	binding := latestInternalEvent(bindings)
	if binding != nil && !internalEventSucceeded(*binding) {
		binding = nil
	}
	if serve != nil && statusIn(serve, "mismatch", "wrong_certificate", "failed") && binding != nil && publish != nil && internalEventSucceeded(*publish) && temporalOrder(binding, publish, serve) {
		return "edge_runtime_or_cache_stale", "Edge runtime served an older configuration after a successful publish", "The control plane records a successful binding and edge publish, followed by a serving check that still returned the wrong certificate; the remaining responsibility is the edge runtime/cache path.", 3
	}
	return "", "", "", 0
}

func summarizeChurn(lookup map[string][]models.InternalEvidenceEvent) (string, string, string, int) {
	rollbacks := lookup[InternalEventRollback]
	if len(rollbacks) > 0 {
		event := latestInternalEvent(rollbacks)
		if event != nil && statusIn(event, "succeeded", "complete", "applied") {
			return "rollback_triggered_replacement", "Rollback or recovery action triggered the replacement", "A control-plane rollback/recovery event is correlated with the certificate transition; the frequent change is therefore attributed to that release action rather than inferred from cadence alone.", 1
		}
	}
	policy := latestInternalEvent(lookup[InternalEventRenewalPolicy])
	issued := latestInternalEvent(lookup[InternalEventCertificateIssued])
	deployed := latestInternalEvent(lookup[InternalEventDeployment])
	if policy != nil && issued != nil && deployed != nil && internalEventSucceeded(*policy) && internalEventSucceeded(*issued) && internalEventSucceeded(*deployed) && temporalOrder(policy, issued, deployed) {
		return "scheduled_renewal_pipeline", "Scheduled certificate renewal pipeline", "The policy evaluation, certificate issuance, and deployment records form a correlated sequence for the observed replacement; the private trigger is identified as scheduled renewal automation.", 3
	}
	if issued != nil && deployed != nil && internalEventSucceeded(*issued) && internalEventSucceeded(*deployed) && temporalOrder(issued, deployed) {
		return "certificate_issued_then_deployed", "Certificate issuance followed by deployment", "The internal records show the observed certificate being issued and then deployed. This identifies the replacement pipeline, while leaving its higher-level trigger unspecified.", 2
	}
	if order := latestInternalEvent(lookup[InternalEventCAOrder]); order != nil && issued != nil && internalEventSucceeded(*order) && internalEventSucceeded(*issued) && temporalOrder(order, issued) {
		return "ca_order_driven_replacement", "CA order drove the replacement", "A CA/ACME order is correlated with the issued certificate and explains the certificate creation step behind the observed change.", 2
	}
	return "", "", "", 0
}

func summarizeGeneric(lookup map[string][]models.InternalEvidenceEvent) (string, string, string, int) {
	if event := latestInternalEvent(lookup[InternalEventKeyGenerated]); event != nil {
		if issued := latestInternalEvent(lookup[InternalEventCertificateIssued]); issued != nil && internalEventSucceeded(*event) && internalEventSucceeded(*issued) && temporalOrder(event, issued) {
			return "key_generation_and_issuance_recorded", "Key generation and certificate issuance recorded", "The imported key-management and CA records identify the key-generation-to-issuance sequence.", 2
		}
	}
	return "", "", "", 0
}

func temporalOrder(events ...*models.InternalEvidenceEvent) bool {
	if len(events) == 0 {
		return false
	}
	var previous time.Time
	correlation, domain := "", ""
	for _, event := range events {
		if event == nil || event.OccurredAt.IsZero() {
			return false
		}
		if !previous.IsZero() && event.OccurredAt.Before(previous) {
			return false
		}
		if event.CorrelationID != "" {
			if correlation != "" && correlation != event.CorrelationID {
				return false
			}
			correlation = event.CorrelationID
		}
		if event.Domain != "" {
			if domain != "" && domain != event.Domain {
				return false
			}
			domain = event.Domain
		}
		previous = event.OccurredAt
	}
	// The sequence must form one connected certificate/task trace. A shared
	// address alone is insufficient: it can host many unrelated operations.
	connected := make([]bool, len(events))
	connected[0] = true
	for pass := 0; pass < len(events); pass++ {
		for i, a := range events {
			if !connected[i] {
				continue
			}
			for j, b := range events {
				if a.Domain != "" && b.Domain != "" && a.Domain != b.Domain {
					continue
				}
				if a.CorrelationID != "" && b.CorrelationID != "" && a.CorrelationID != b.CorrelationID {
					continue
				}
				if (a.CorrelationID != "" && a.CorrelationID == b.CorrelationID) ||
					(a.Fingerprint != "" && a.Fingerprint == b.Fingerprint) ||
					(a.SPKIFingerprint != "" && a.SPKIFingerprint == b.SPKIFingerprint) {
					connected[j] = true
				}
			}
		}
	}
	for _, ok := range connected {
		if !ok {
			return false
		}
	}
	return true
}

func internalEventSucceeded(event models.InternalEvidenceEvent) bool {
	if event.OccurredAt.IsZero() || strings.TrimSpace(event.SourceSystem) == "" {
		return false
	}
	if event.EventType == InternalEventRenewalPolicy && statusIn(&event, "evaluated") {
		return true
	}
	return statusIn(&event, "succeeded", "complete", "completed", "applied", "published", "active", "issued", "deployed", "retired")
}

func latestInternalEvent(events []models.InternalEvidenceEvent) *models.InternalEvidenceEvent {
	if len(events) == 0 {
		return nil
	}
	sorted := append([]models.InternalEvidenceEvent(nil), events...)
	sort.SliceStable(sorted, func(left, right int) bool {
		if sorted[left].OccurredAt.Equal(sorted[right].OccurredAt) {
			return sorted[left].ID > sorted[right].ID
		}
		return sorted[left].OccurredAt.After(sorted[right].OccurredAt)
	})
	return &sorted[0]
}

func statusIn(event *models.InternalEvidenceEvent, values ...string) bool {
	if event == nil {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(event.Status))
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func actionIn(event *models.InternalEvidenceEvent, values ...string) bool {
	if event == nil {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(event.Action))
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func internalEvidenceRequirements(findingType string) []string {
	switch normalizeFindingType(findingType) {
	case "hostname_mismatch", "deployment_failure", "stale_after_change":
		return []string{"address_pool_membership", "hostname_binding", "edge_publish or deployment result", "edge_serve_check correlated with the endpoint IP"}
	case "frequent_change", "early_renewal", "same_key":
		return []string{"certificate_controller or CA order/issuance record", "deployment event correlated by fingerprint or correlation_id", "rollback/operator-change record if applicable"}
	default:
		return []string{"source-system event correlated by fingerprint, SPKI, address, or correlation_id"}
	}
}

func causalSupportingEvents(lookup map[string][]models.InternalEvidenceEvent, code string) []models.InternalEvidenceEvent {
	types := map[string][]string{
		"address_pool_membership_excluded":     {InternalEventAddressPool},
		"hostname_binding_not_published":       {InternalEventHostnameBinding},
		"edge_publish_failed":                  {InternalEventEdgePublish},
		"edge_runtime_or_cache_stale":          {InternalEventHostnameBinding, InternalEventEdgePublish, InternalEventEdgeServeCheck},
		"rollback_triggered_replacement":       {InternalEventRollback},
		"scheduled_renewal_pipeline":           {InternalEventRenewalPolicy, InternalEventCertificateIssued, InternalEventDeployment},
		"certificate_issued_then_deployed":     {InternalEventCertificateIssued, InternalEventDeployment},
		"ca_order_driven_replacement":          {InternalEventCAOrder, InternalEventCertificateIssued},
		"key_generation_and_issuance_recorded": {InternalEventKeyGenerated, InternalEventCertificateIssued},
	}
	var out []models.InternalEvidenceEvent
	for _, kind := range types[code] {
		if event := latestInternalEvent(lookup[kind]); event != nil {
			out = append(out, *event)
		}
	}
	return out
}

func internalEvidenceLines(events []models.InternalEvidenceEvent, code string, limit int) []string {
	lines := make([]string, 0, len(events))
	for _, event := range events {
		line := fmt.Sprintf("event#%d %s/%s at %s", event.ID, event.SourceSystem, event.EventType, event.OccurredAt.UTC().Format(time.RFC3339))
		if event.IPAddress != "" {
			line += " ip=" + event.IPAddress
		}
		if event.Fingerprint != "" {
			line += " leaf=" + event.Fingerprint
		}
		if event.Status != "" {
			line += " status=" + event.Status
		}
		if event.CorrelationID != "" {
			line += " correlation=" + event.CorrelationID
		}
		if code != "" {
			line += " supports=" + code
		}
		lines = append(lines, line)
		if len(lines) >= limit {
			break
		}
	}
	return lines
}

func sortedSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func certSlice(values map[string]models.Certificate) []models.Certificate {
	result := make([]models.Certificate, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func validateInternalEvidence(event *models.InternalEvidenceEvent) error {
	if event == nil {
		return fmt.Errorf("internal evidence event is nil")
	}
	if models.GetDomain(event.Domain) == "" {
		return fmt.Errorf("domain is required")
	}
	if event.OccurredAt.IsZero() {
		return fmt.Errorf("occurred_at is required")
	}
	if strings.TrimSpace(event.EventType) == "" {
		return fmt.Errorf("event_type is required")
	}
	if strings.TrimSpace(event.SourceSystem) == "" {
		return fmt.Errorf("source_system is required")
	}
	if strings.TrimSpace(event.SourceRecordID) == "" && strings.TrimSpace(event.CorrelationID) == "" && strings.TrimSpace(event.Fingerprint) == "" && strings.TrimSpace(event.SPKIFingerprint) == "" && strings.TrimSpace(event.IPAddress) == "" && strings.TrimSpace(event.Hostname) == "" {
		return fmt.Errorf("source_record_id, correlation_id, fingerprint, SPKI, IP address, or hostname is required to correlate an internal event")
	}
	for field, value := range map[string]string{
		"fingerprint": event.Fingerprint, "previous_fingerprint": event.PreviousFingerprint,
		"spki_fingerprint": event.SPKIFingerprint, "previous_spki_fingerprint": event.PreviousSPKIFingerprint,
	} {
		if value == "" {
			continue
		}
		compact := strings.ReplaceAll(strings.TrimSpace(value), ":", "")
		if len(compact) != 64 {
			return fmt.Errorf("%s must be a SHA-256 fingerprint", field)
		}
		if _, err := hex.DecodeString(compact); err != nil {
			return fmt.Errorf("%s must be hexadecimal", field)
		}
	}
	if event.RawPayload != "" && !json.Valid([]byte(event.RawPayload)) {
		return fmt.Errorf("raw_payload must be valid JSON")
	}
	return nil
}
