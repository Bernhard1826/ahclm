package database

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"ahclm/internal/models"
)

// GetRelatedNameCandidates returns public measurement targets taken from
// names that entered or left certificates for one monitored root. It does not
// enumerate arbitrary subdomains: every returned name is grounded in a
// retained certificate transition.
func (d *Database) GetRelatedNameCandidates(domain string, limit int) ([]models.RelatedNameCandidate, error) {
	domain = models.GetDomain(domain)
	if domain == "" {
		return nil, ErrDomainNotMonitored
	}
	if _, err := d.GetDomainCertificate(domain); err != nil {
		return nil, err
	}
	var observations []models.CertObservation
	if err := d.db.Where("domain = ? AND observation_type = ?", domain, models.ObsChange).
		Order("observed_at ASC, id ASC").Limit(240).Find(&observations).Error; err != nil {
		return nil, err
	}
	fingerprints := make(map[string]struct{})
	for _, observation := range observations {
		if observation.Fingerprint != "" {
			fingerprints[observation.Fingerprint] = struct{}{}
		}
		if observation.PreviousFingerprint != "" {
			fingerprints[observation.PreviousFingerprint] = struct{}{}
		}
	}
	certificates := make(map[string]models.Certificate)
	if len(fingerprints) > 0 {
		values := make([]string, 0, len(fingerprints))
		for fingerprint := range fingerprints {
			values = append(values, fingerprint)
		}
		var rows []models.Certificate
		if err := d.db.Where("fingerprint IN ?", values).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, certificate := range rows {
			certificates[certificate.Fingerprint] = certificate
		}
	}
	candidates := relatedNameCandidates(domain, observations, certificates, limit)
	if len(candidates) == 0 {
		return nil, nil
	}
	var snapshots []models.MeasurementSnapshot
	if err := d.db.Select("observed_at", "related_names_json").
		Where("domain = ? AND related_names_json <> ''", domain).
		Order("observed_at DESC, id DESC").Limit(300).Find(&snapshots).Error; err != nil {
		return nil, err
	}
	markRelatedNameProbePriorities(candidates, snapshots)
	sort.SliceStable(candidates, func(left, right int) bool {
		return candidates[left].NeedsPriorityProbe && !candidates[right].NeedsPriorityProbe
	})
	return candidates, nil
}

func markRelatedNameProbePriorities(candidates []models.RelatedNameCandidate, snapshots []models.MeasurementSnapshot) {
	latest := make(map[string]models.RelatedNameProbe, len(candidates))
	for _, snapshot := range snapshots {
		if strings.TrimSpace(snapshot.RelatedNamesJSON) == "" || snapshot.RelatedNamesJSON == "null" || snapshot.RelatedNamesJSON == "[]" {
			continue
		}
		var probes []models.RelatedNameProbe
		if json.Unmarshal([]byte(snapshot.RelatedNamesJSON), &probes) != nil {
			continue
		}
		for _, probe := range probes {
			probe.Name = models.GetDomain(probe.Name)
			if probe.Name == "" {
				continue
			}
			previous, found := latest[probe.Name]
			if !found || probe.ProbedAt.After(previous.ProbedAt) {
				latest[probe.Name] = probe
			}
		}
	}
	for index := range candidates {
		probe, found := latest[candidates[index].Name]
		candidates[index].NeedsPriorityProbe = !found || probe.DNSStatus == "inconclusive"
	}
}

func relatedNameCandidates(root string, observations []models.CertObservation, certificates map[string]models.Certificate, limit int) []models.RelatedNameCandidate {
	root = models.GetDomain(root)
	if root == "" {
		return nil
	}
	byName := make(map[string]*models.RelatedNameCandidate)
	for _, observation := range observations {
		previous, previousOK := certificates[strings.TrimSpace(observation.PreviousFingerprint)]
		current, currentOK := certificates[strings.TrimSpace(observation.Fingerprint)]
		if !previousOK || !currentOK {
			continue
		}
		previousNames := normalizedCertificateNames(models.ParseSANs(previous.SANs))
		currentNames := normalizedCertificateNames(models.ParseSANs(current.SANs))
		for _, name := range certificateNameDifference(currentNames, previousNames) {
			recordRelatedNameCandidate(byName, root, name, observation.ObservedAt, true)
		}
		for _, name := range certificateNameDifference(previousNames, currentNames) {
			recordRelatedNameCandidate(byName, root, name, observation.ObservedAt, false)
		}
	}
	out := make([]models.RelatedNameCandidate, 0, len(byName))
	for _, candidate := range byName {
		out = append(out, *candidate)
	}
	sort.Slice(out, func(left, right int) bool {
		if out[left].BranchLikeLabel != out[right].BranchLikeLabel {
			return out[left].BranchLikeLabel
		}
		leftTransient := out[left].RemovedCount > 0
		rightTransient := out[right].RemovedCount > 0
		if leftTransient != rightTransient {
			return leftTransient
		}
		if !out[left].LastObservedAt.Equal(out[right].LastObservedAt) {
			return out[left].LastObservedAt.After(out[right].LastObservedAt)
		}
		if out[left].AddedCount != out[right].AddedCount {
			return out[left].AddedCount > out[right].AddedCount
		}
		return out[left].Name < out[right].Name
	})
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func recordRelatedNameCandidate(byName map[string]*models.RelatedNameCandidate, root, name string, observedAt time.Time, added bool) {
	name = models.GetDomain(name)
	if !isRelatedName(root, name) {
		return
	}
	candidate := byName[name]
	if candidate == nil {
		candidate = &models.RelatedNameCandidate{Name: name, FirstObservedAt: observedAt, LastObservedAt: observedAt, BranchLikeLabel: branchLikeName(root, name)}
		byName[name] = candidate
	}
	if candidate.FirstObservedAt.IsZero() || (!observedAt.IsZero() && observedAt.Before(candidate.FirstObservedAt)) {
		candidate.FirstObservedAt = observedAt
	}
	if observedAt.After(candidate.LastObservedAt) {
		candidate.LastObservedAt = observedAt
	}
	if added {
		candidate.AddedCount++
	} else {
		candidate.RemovedCount++
	}
}

func isRelatedName(root, name string) bool {
	if root == "" || name == "" || name == root || strings.HasPrefix(name, "*.") {
		return false
	}
	return strings.HasSuffix(name, "."+root)
}

func branchLikeName(root, name string) bool {
	label := strings.TrimSuffix(strings.TrimSuffix(name, "."+root), ".")
	label = strings.ToLower(label)
	for _, marker := range []string{"preview", "feat-", "feature-", "fix-", "refactor-", "chore-", "branch-", "review-", "pr-", "pull-", "staging-"} {
		if strings.Contains(label, marker) {
			return true
		}
	}
	return false
}
