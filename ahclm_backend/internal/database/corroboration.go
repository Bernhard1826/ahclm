package database

import (
	"encoding/json"
	"strings"

	"ahclm/internal/models"
)

func attachIndependentCorroboration(corroboration *models.EvidenceCorroboration, context diagnosisContext) {
	if corroboration == nil {
		return
	}
	snapshots := context.snapshots
	corroboration.SCTPresented, corroboration.SCTCount, corroboration.SCTLogCount, corroboration.SCTQualifiedLogs, corroboration.SCTAppleLogs, corroboration.SCTInclusionProofs, corroboration.SCTNote = analyzeSCTCorroboration(snapshots)
	corroboration.DirectoryCoverage, corroboration.DirectoryStatus, corroboration.DirectoryNote = analyzeDirectoryCorroboration(snapshots)
	corroboration.NSCoverage = nsCoverage(snapshots)
	corroboration.NSRDAPAgreement, corroboration.DirectoryNote = analyzeNSRDAPAgreement(snapshots, corroboration.DirectoryNote)
	corroboration.DNSSECValidated, corroboration.DNSSECNote = analyzeDNSSEC(snapshots)
	if corroboration.CAAStatus == "" {
		corroboration.CAAStatus, corroboration.CAANote = analyzeCAACorroboration(snapshots, context)
	}
	if corroboration.TimingNote == "" {
		corroboration.TimingNote = analyzeTimingCorroboration(snapshots, context)
	}
}

func analyzeSCTCorroboration(snapshots []models.MeasurementSnapshot) (presented bool, count, logs, qualified, apple, included int, note string) {
	if len(snapshots) == 0 {
		return false, 0, 0, 0, 0, 0, "No measurement rounds retained handshake SCTs."
	}
	logIDs := make(map[string]struct{})
	qualifiedIDs := make(map[string]struct{})
	appleIDs := make(map[string]struct{})
	includedIDs := make(map[string]struct{})
	operators := make(map[string]struct{})
	withSCT := 0
	for _, snapshot := range snapshots {
		observations := snapshotSCTs(snapshot)
		if len(observations) == 0 {
			continue
		}
		withSCT++
		count += len(observations)
		for _, observation := range observations {
			if observation.LogID == "" {
				continue
			}
			logIDs[observation.LogID] = struct{}{}
			if observation.ChromeListed && (observation.Qualified || observation.LogState == "usable" || observation.LogState == "qualified") {
				qualifiedIDs[observation.LogID] = struct{}{}
			}
			if observation.AppleListed {
				appleIDs[observation.LogID] = struct{}{}
			}
			if observation.Inclusion == models.SCTInclusionProven {
				includedIDs[observation.LogID] = struct{}{}
			}
			if observation.Operator != "" {
				operators[observation.Operator] = struct{}{}
			}
		}
	}
	logs = len(logIDs)
	qualified = len(qualifiedIDs)
	apple = len(appleIDs)
	included = len(includedIDs)
	if withSCT == 0 {
		return false, 0, 0, 0, 0, 0, "The TLS handshake did not present Signed Certificate Timestamps, so Certificate Transparency logging of the served leaf was not proven at the endpoint."
	}
	note = "The TLS handshake presented " + itoa(count) + " Signed Certificate Timestamp(s) from " + itoa(logs) + " CT log(s)"
	if qualified > 0 {
		note += ", " + itoa(qualified) + " of which appear in Chrome's qualified/usable log list"
	}
	if apple > 0 {
		note += ", " + itoa(apple) + " of which appear in Apple's CT log list"
	}
	if included > 0 {
		note += ", and " + itoa(included) + " Merkle inclusion proof(s) confirmed the served leaf in the named log"
	}
	if len(operators) > 0 {
		note += " (" + strings.Join(sortedSourceSet(operators), ", ") + ")"
	}
	if included > 0 {
		note += ", proving the served leaf was logged."
	} else {
		note += ", proving the served leaf was submitted to Certificate Transparency."
	}
	return true, count, logs, qualified, apple, included, note
}

func analyzeDirectoryCorroboration(snapshots []models.MeasurementSnapshot) (coverage float64, status, note string) {
	status = models.DirectoryUnavailable
	if len(snapshots) == 0 {
		return 0, status, "No measurement rounds retained RDAP or ASN documents."
	}
	withDirectory := 0
	identified := 0
	partial := 0
	var latest *models.DirectoryObservation
	for _, snapshot := range snapshots {
		observation := snapshotDirectory(snapshot)
		if observation == nil {
			continue
		}
		withDirectory++
		if latest == nil {
			latest = observation
		}
		switch observation.Status {
		case models.DirectoryIdentified:
			identified++
		case models.DirectoryPartial:
			partial++
		}
	}
	coverage = round2(float64(withDirectory) / float64(len(snapshots)))
	if latest == nil {
		return coverage, models.DirectoryUnavailable, "RDAP and ASN lookups were not retained, so endpoint operators have no numbering-authority check."
	}
	asns := make(map[int]struct{})
	orgs := make(map[string]struct{})
	agreed := 0
	conflicts := 0
	for _, endpoint := range latest.Endpoints {
		if endpoint.SourceAgreement == models.DirectoryAgreementConflict {
			conflicts++
		}
		if endpoint.SourceAgreement == models.DirectoryAgreementAgreed {
			agreed++
		}
		if endpoint.ASN > 0 {
			asns[endpoint.ASN] = struct{}{}
		}
		if name := strings.TrimSpace(endpoint.OrgName); name != "" {
			orgs[name] = struct{}{}
		} else if name := strings.TrimSpace(endpoint.NetName); name != "" {
			orgs[name] = struct{}{}
		}
	}
	switch {
	case conflicts > 0:
		status = models.DirectoryPartial
		note = "Independent numbering-authority sources disagree on ASN for " + itoa(conflicts) + " endpoint(s), so operator identity is not proven."
	case identified > 0 || latest.Status == models.DirectoryIdentified:
		status = models.DirectoryIdentified
		note = "Numbering-authority records identified " + itoa(len(asns)) + " ASN(s) and " + itoa(len(orgs)) + " organisation(s) for the answering endpoints."
		if agreed > 0 {
			note += " " + itoa(agreed) + " endpoint(s) have the same ASN from independent sources (Cymru, RIPEstat or RDAP)."
		}
	case partial > 0 || latest.Domain != nil || len(latest.Endpoints) > 0:
		status = models.DirectoryPartial
		note = "RDAP or ASN records were retrieved, but not every answering endpoint has a numbering-authority identity."
	default:
		status = models.DirectoryUnavailable
		note = "RDAP and ASN lookups did not return a usable numbering-authority identity."
	}
	if latest.Domain != nil {
		if latest.Domain.Registrar != "" {
			note += " Domain RDAP registrar is " + latest.Domain.Registrar + "."
		} else if latest.Domain.LDHName != "" {
			note += " Domain RDAP record was retrieved for " + latest.Domain.LDHName + "."
		}
	}
	return coverage, status, strings.TrimSpace(note)
}

func analyzeNSRDAPAgreement(snapshots []models.MeasurementSnapshot, directoryNote string) (agreement, note string) {
	note = directoryNote
	var topologyNS []string
	var rdapNS []string
	for _, snapshot := range snapshots {
		if len(topologyNS) == 0 {
			topologyNS = snapshotTopology(snapshot).NSHosts
		}
		if len(rdapNS) == 0 {
			if directory := snapshotDirectory(snapshot); directory != nil && directory.Domain != nil {
				rdapNS = directory.Domain.Nameservers
			}
		}
		if len(topologyNS) > 0 && len(rdapNS) > 0 {
			break
		}
	}
	if len(topologyNS) == 0 || len(rdapNS) == 0 {
		return "", note
	}
	overlap := 0
	rdapSet := make(map[string]struct{}, len(rdapNS))
	for _, name := range rdapNS {
		rdapSet[normalizeHost(name)] = struct{}{}
	}
	for _, name := range topologyNS {
		if _, ok := rdapSet[normalizeHost(name)]; ok {
			overlap++
		}
	}
	switch {
	case overlap > 0 && overlap == len(topologyNS):
		agreement = models.DirectoryAgreementAgreed
		note = strings.TrimSpace(note + " Live nameservers match the RDAP registration nameservers.")
	case overlap > 0:
		agreement = models.DirectoryAgreementSingle
		note = strings.TrimSpace(note + " Live nameservers overlap RDAP nameservers but are not identical.")
	default:
		agreement = models.DirectoryAgreementConflict
		note = strings.TrimSpace(note + " Live nameservers do not match the RDAP registration nameservers, so DNS control-plane identity is not proven from registration alone.")
	}
	return agreement, note
}

func analyzeDNSSEC(snapshots []models.MeasurementSnapshot) (validated bool, note string) {
	if len(snapshots) == 0 {
		return false, ""
	}
	authenticated := 0
	checked := 0
	for _, snapshot := range snapshots {
		topology := snapshotTopology(snapshot)
		if topology.ResolverQuorum == 0 && len(topology.Resolvers) == 0 {
			continue
		}
		checked++
		if topology.DNSSECValidated > 0 && topology.DNSSECValidated == topology.ResolverQuorum {
			authenticated++
		} else {
			hits := 0
			for _, resolver := range topology.Resolvers {
				if resolver.DNSSEC {
					hits++
				}
			}
			if hits > 0 && hits == len(topology.Resolvers) {
				authenticated++
			}
		}
	}
	if checked == 0 {
		return false, "DNSSEC authenticity was not retained on resolver answers."
	}
	if authenticated == 0 {
		return false, "Public resolvers did not set the DNSSEC Authentic Data bit, so NS/CNAME/HTTPS names are not DNSSEC-proven."
	}
	return true, "Public resolvers authenticated DNSSEC on NS/CNAME/HTTPS answers in " + itoa(authenticated) + " retained round(s)."
}

func analyzeCAACorroboration(snapshots []models.MeasurementSnapshot, context diagnosisContext) (status, note string) {
	records := latestCAA(snapshots)
	if len(records) == 0 {
		return models.CAAAbsent, "No CAA issue/issuewild records were retained."
	}
	issuer := latestIssuer(context)
	return models.MatchCAA(records, issuer)
}

func analyzeTimingCorroboration(snapshots []models.MeasurementSnapshot, context diagnosisContext) string {
	parts := make([]string, 0, 2)
	if lead := sctLeadTime(snapshots, context); lead != "" {
		parts = append(parts, lead)
	}
	if ari := ariTiming(context); ari != "" {
		parts = append(parts, ari)
	}
	return strings.Join(parts, " ")
}

func sctLeadTime(snapshots []models.MeasurementSnapshot, context diagnosisContext) string {
	var earliest *models.SCTObservation
	for _, snapshot := range snapshots {
		for _, observation := range snapshotSCTs(snapshot) {
			if observation.Timestamp == nil {
				continue
			}
			if earliest == nil || observation.Timestamp.Before(*earliest.Timestamp) {
				copy := observation
				earliest = &copy
			}
		}
	}
	if earliest == nil || earliest.Timestamp == nil {
		return ""
	}
	cert := latestCertificate(context)
	if cert == nil || cert.NotBefore.IsZero() {
		return ""
	}
	delta := earliest.Timestamp.Sub(cert.NotBefore.UTC())
	hours := int(delta.Hours())
	switch {
	case hours <= -24:
		return "The earliest handshake SCT predates NotBefore by " + itoa(-hours/24) + " day(s), consistent with a preissued leaf later put into service."
	case hours >= 24:
		return "The earliest handshake SCT is " + itoa(hours/24) + " day(s) after NotBefore."
	default:
		return "The earliest handshake SCT is within a day of NotBefore."
	}
}

func ariTiming(context diagnosisContext) string {
	if context.state == nil || context.state.ARIWindowStart == nil {
		return ""
	}
	cert := latestCertificate(context)
	if cert == nil || cert.NotAfter.IsZero() {
		return ""
	}
	windowStart := context.state.ARIWindowStart.UTC()
	notAfter := cert.NotAfter.UTC()
	if windowStart.IsZero() || !windowStart.Before(notAfter) {
		return ""
	}
	days := int(notAfter.Sub(windowStart).Hours() / 24)
	if context.state.ARIEmergency {
		return "ARI marks an emergency window starting " + itoa(days) + " day(s) before NotAfter."
	}
	return "ARI suggestedWindow starts " + itoa(days) + " day(s) before NotAfter."
}

func latestCAA(snapshots []models.MeasurementSnapshot) []models.CAARecord {
	for _, snapshot := range snapshots {
		raw := strings.TrimSpace(snapshot.CAAJSON)
		if raw == "" || raw == "null" || raw == "[]" {
			continue
		}
		var records []models.CAARecord
		if json.Unmarshal([]byte(raw), &records) != nil || len(records) == 0 {
			continue
		}
		return records
	}
	return nil
}

func latestIssuer(context diagnosisContext) string {
	if cert := latestCertificate(context); cert != nil {
		return strings.TrimSpace(cert.Issuer + " " + cert.IssuerCN)
	}
	return ""
}

func latestCertificate(context diagnosisContext) *models.Certificate {
	if context.state != nil && context.state.CurrentFingerprint != "" {
		if cert, ok := context.certificates[context.state.CurrentFingerprint]; ok {
			copy := cert
			return &copy
		}
	}
	for _, snapshot := range context.snapshots {
		if snapshot.CertificateFingerprint == "" {
			continue
		}
		if cert, ok := context.certificates[snapshot.CertificateFingerprint]; ok {
			copy := cert
			return &copy
		}
	}
	return nil
}

func normalizeHost(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func nsCoverage(snapshots []models.MeasurementSnapshot) float64 {
	if len(snapshots) == 0 {
		return 0
	}
	withNS := 0
	for _, snapshot := range snapshots {
		topology := snapshotTopology(snapshot)
		if len(topology.NSHosts) > 0 {
			withNS++
			continue
		}
		if directory := snapshotDirectory(snapshot); directory != nil && directory.Domain != nil && len(directory.Domain.Nameservers) > 0 {
			withNS++
		}
	}
	return round2(float64(withNS) / float64(len(snapshots)))
}

func snapshotSCTs(snapshot models.MeasurementSnapshot) []models.SCTObservation {
	raw := strings.TrimSpace(snapshot.SCTJSON)
	if raw == "" || raw == "null" || raw == "[]" {
		return nil
	}
	var observations []models.SCTObservation
	if json.Unmarshal([]byte(raw), &observations) != nil {
		return nil
	}
	return observations
}

func snapshotDirectory(snapshot models.MeasurementSnapshot) *models.DirectoryObservation {
	raw := strings.TrimSpace(snapshot.DirectoryJSON)
	if raw == "" || raw == "null" {
		return nil
	}
	var observation models.DirectoryObservation
	if json.Unmarshal([]byte(raw), &observation) != nil {
		return nil
	}
	if observation.Domain == nil && len(observation.Endpoints) == 0 {
		return nil
	}
	return &observation
}

func snapshotTopology(snapshot models.MeasurementSnapshot) models.TopologySnapshot {
	raw := strings.TrimSpace(snapshot.TopologyJSON)
	if raw == "" || raw == "null" {
		return models.TopologySnapshot{}
	}
	var topology models.TopologySnapshot
	if json.Unmarshal([]byte(raw), &topology) != nil {
		return models.TopologySnapshot{}
	}
	return topology
}

func latestDirectory(snapshots []models.MeasurementSnapshot) *models.DirectoryObservation {
	for _, snapshot := range snapshots {
		if observation := snapshotDirectory(snapshot); observation != nil {
			return observation
		}
	}
	return nil
}

func directoryEndpointMap(directory *models.DirectoryObservation) map[string]models.IPDirectoryRecord {
	out := make(map[string]models.IPDirectoryRecord)
	if directory == nil {
		return out
	}
	for _, endpoint := range directory.Endpoints {
		if endpoint.IPAddress != "" {
			out[endpoint.IPAddress] = endpoint
		}
	}
	return out
}

func issuanceKey(observation models.CTObservation) string {
	if sha := strings.ToLower(strings.TrimSpace(observation.SHA256)); sha != "" {
		return "sha256:" + sha
	}
	serial := normalizeEvidenceSerial(observation.SerialNumber)
	if serial == "" {
		return ""
	}
	issuer := strings.ToLower(strings.TrimSpace(observation.IssuerName))
	if issuer == "" {
		return "serial:" + serial
	}
	return "serial:" + serial + "|" + issuer
}

func normalizeEvidenceSerial(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, ":", "")
	value = strings.TrimPrefix(value, "0x")
	return strings.TrimLeft(value, "0")
}
