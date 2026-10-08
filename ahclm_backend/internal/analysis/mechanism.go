package analysis

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"ahclm/internal/models"
)

// Mechanism identifiers name observable certificate behaviors. They are not
// controllers, releases, or operators. M7 is scored from a public regression
// that the share's six-column matrix does not include.
const (
	MechanismWrongName       = "M1_wrong_name_selection"
	MechanismPoolResidue     = "M2_address_pool_residue"
	MechanismSameKey         = "M3_same_key_reissue"
	MechanismPreissued       = "M4_preissued_stock"
	MechanismOnDemand        = "M5_on_demand_reissue"
	MechanismCertificatePool = "M6_certificate_pool"
	MechanismRolloutRace     = "M7_rollout_race"
)

const (
	weightStrong     = 2
	weightAgainst    = -1
	weightContradict = -2
)

// mechanismOrder is the stable presentation order. Scoring does not depend on it.
var mechanismOrder = []string{
	MechanismWrongName,
	MechanismPoolResidue,
	MechanismSameKey,
	MechanismPreissued,
	MechanismOnDemand,
	MechanismCertificatePool,
	MechanismRolloutRace,
}

var mechanismNames = map[string]string{
	MechanismWrongName:       "错误名称选择",
	MechanismPoolResidue:     "地址池残留",
	MechanismSameKey:         "同钥重签",
	MechanismPreissued:       "预签发库存",
	MechanismOnDemand:        "现发重签",
	MechanismCertificatePool: "证书池",
	MechanismRolloutRace:     "发布回退",
}

// evidenceMatrix lists only the non-zero compatibilities. An evidence row is
// applied when that feature was observed. An unobserved feature contributes
// nothing and is reported as missing rather than as a neutral zero.
var evidenceOrder = []string{
	"sni_name_mismatch",
	"empty_sni_same_leaf",
	"spki_same",
	"spki_different",
	"notbefore_old",
	"notbefore_fresh",
	"oscillation",
	"forward_no_return",
	"older_leaf_returns",
	"stale_leaf_on_current_dns",
}

// evidenceMatrix records only a prediction or a falsifier. A blank cell is
// not weak support. Weights stay numeric so one strong observation can still
// outrank a single opposing observation.
var evidenceMatrix = map[string]map[string]int{
	"sni_name_mismatch":         {MechanismWrongName: weightStrong},
	"empty_sni_same_leaf":       {MechanismWrongName: weightStrong},
	"spki_same":                 {MechanismSameKey: weightStrong},
	"spki_different":            {MechanismSameKey: weightContradict},
	"notbefore_old":             {MechanismPreissued: weightStrong, MechanismOnDemand: weightContradict},
	"notbefore_fresh":           {MechanismOnDemand: weightStrong, MechanismPreissued: weightContradict},
	"oscillation":               {MechanismCertificatePool: weightStrong, MechanismOnDemand: weightAgainst},
	"forward_no_return":         {MechanismOnDemand: weightStrong, MechanismCertificatePool: weightAgainst},
	"older_leaf_returns":        {MechanismRolloutRace: weightStrong, MechanismOnDemand: weightAgainst},
	"stale_leaf_on_current_dns": {MechanismPoolResidue: weightStrong},
}

var requiredEvidence = map[string]string{
	MechanismWrongName:       "sni_name_mismatch",
	MechanismPoolResidue:     "stale_leaf_on_current_dns",
	MechanismSameKey:         "spki_same",
	MechanismPreissued:       "notbefore_old",
	MechanismOnDemand:        "notbefore_fresh",
	MechanismCertificatePool: "oscillation",
	MechanismRolloutRace:     "older_leaf_returns",
}

var falsifyingEvidence = map[string][]string{
	MechanismSameKey:         {"spki_different"},
	MechanismPreissued:       {"notbefore_fresh"},
	MechanismOnDemand:        {"notbefore_old", "oscillation", "older_leaf_returns"},
	MechanismCertificatePool: {"forward_no_return"},
}

var evidenceLabels = map[string]string{
	"sni_name_mismatch":         "带正确 SNI 仍返回不含该域名的叶证书",
	"empty_sni_same_leaf":       "空 SNI 与带域名 SNI 返回同一张不含该域名的叶",
	"same_ip_multiple_leaves":   "同一地址在一轮中返回多张叶证书",
	"spki_same":                 "叶证书变了，公钥没变",
	"spki_different":            "叶证书变了，公钥也变了",
	"notbefore_old":             "新观察到的叶在首次看到时已经签发较久",
	"notbefore_fresh":           "新观察到的叶接近首次看到时才签发",
	"forward_no_return":         "同一地址单向换成新叶，没有回到旧叶",
	"oscillation":               "同一地址回到先前的叶，且这些叶覆盖查询名",
	"older_leaf_returns":        "较新的叶出现后，又回到更早签发的叶",
	"stale_leaf_on_current_dns": "旧叶仍出现在当前 DNS 地址上",
}

// MechanismScore is one candidate after the observed rows have been summed.
// Score is a compatibility sum, not a probability. Verdict is supported only
// when the mechanism's required evidence was observed and none of its
// falsifiers were.
type MechanismScore struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Score   int    `json:"score"`
	Ranked  bool   `json:"ranked"`
	Verdict string `json:"verdict"`
}

// MatrixEffect is one non-blank cell. Effect is "support" or "exclude".
type MatrixEffect struct {
	Mechanism string `json:"mechanism"`
	Effect    string `json:"effect"`
	Weight    int    `json:"weight"`
}

// MatrixRow is one evidence signature. Observed marks a row that this
// domain's public record actually matched.
type MatrixRow struct {
	ID       string         `json:"id"`
	Label    string         `json:"label"`
	Observed bool           `json:"observed"`
	Effects  []MatrixEffect `json:"effects"`
}

// MechanismColumn keeps the matrix columns in definition order.
type MechanismColumn struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// EvidenceHit is one observed feature and the mechanisms it moved.
type EvidenceHit struct {
	ID      string         `json:"id"`
	Summary string         `json:"summary"`
	Weights map[string]int `json:"weights"`
}

// MechanismReport ranks mechanisms that public observations can support. It
// never names an internal trigger.
type MechanismReport struct {
	Domain          string            `json:"domain"`
	Status          string            `json:"status"`
	MostSupported   string            `json:"most_supported,omitempty"`
	Limitation      string            `json:"limitation"`
	Columns         []MechanismColumn `json:"columns"`
	Matrix          []MatrixRow       `json:"matrix"`
	Scores          []MechanismScore  `json:"scores"`
	Evidence        []EvidenceHit     `json:"evidence,omitempty"`
	Counterexamples []string          `json:"counterexamples,omitempty"`
	Missing         []string          `json:"missing,omitempty"`
}

// InferMechanisms scores the retained public record. Certificates supply
// NotBefore, lifetime, SPKI, and SAN sets. Observations supply the time order.
// Probes supply SNI and same-address comparisons. Nothing here contacts a network.
func InferMechanisms(domain string, certs []models.Certificate, observations []models.CertObservation, probes []models.EndpointProbe) MechanismReport {
	byFingerprint := map[string]models.Certificate{}
	for _, cert := range certs {
		if cert.Fingerprint != "" {
			byFingerprint[cert.Fingerprint] = cert
		}
	}
	features := map[string]struct{}{}
	var counters []string
	observeProbes(probes, features)
	observeChanges(domain, observations, byFingerprint, features, &counters)
	return rankMechanisms(domain, features, counters)
}

func observeProbes(probes []models.EndpointProbe, features map[string]struct{}) {
	for _, probe := range probes {
		if !probe.Success || probe.Fingerprint == "" {
			continue
		}
		if probe.RequestedSNI != "" && !probe.CoversRequestedName {
			features["sni_name_mismatch"] = struct{}{}
		}
		analysis := probe.SelectionAnalysis
		if analysis == nil {
			continue
		}
		if !analysis.CertificateChanged && analysis.SelectedFingerprint != "" && !analysis.SelectedCoversRequestedName {
			features["empty_sni_same_leaf"] = struct{}{}
		}
	}
}

func observeChanges(domain string, observations []models.CertObservation, certs map[string]models.Certificate, features map[string]struct{}, counters *[]string) {
	ordered := append([]models.CertObservation(nil), observations...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].ObservedAt.Equal(ordered[j].ObservedAt) {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].ObservedAt.Before(ordered[j].ObservedAt)
	})
	byAddress := map[string][]step{}
	sanChanged, sanUnchanged := 0, 0
	for _, observation := range ordered {
		if observation.ObservationType == models.ObsStaleAfterChange {
			features["stale_leaf_on_current_dns"] = struct{}{}
		}
		previous := strings.TrimSpace(observation.PreviousFingerprint)
		current := strings.TrimSpace(observation.Fingerprint)
		if previous != "" && current != "" && previous != current {
			previousSPKI := firstNonEmpty(observation.PreviousSPKIFingerprint, certs[previous].SPKIFingerprint)
			currentSPKI := firstNonEmpty(observation.SPKIFingerprint, certs[current].SPKIFingerprint)
			if previousSPKI != "" && currentSPKI != "" {
				if previousSPKI == currentSPKI {
					features["spki_same"] = struct{}{}
				} else {
					features["spki_different"] = struct{}{}
				}
			}
			if sansDiffer(certs[previous], certs[current]) {
				sanChanged++
			} else if certs[previous].SANs != "" || certs[current].SANs != "" {
				sanUnchanged++
			}
			classifyIssuanceAge(observation.ObservedAt, certs[current], features)
		}
		if probeText := strings.TrimSpace(observation.EndpointProbes); probeText != "" {
			var probes []models.EndpointProbe
			if json.Unmarshal([]byte(probeText), &probes) == nil {
				observeProbes(probes, features)
			}
		}
		address := firstNonEmpty(observation.IPAddress, observation.PreviousIPAddress)
		if address != "" && current != "" {
			series := byAddress[address]
			if len(series) == 0 && previous != "" {
				series = append(series, step{at: observation.ObservedAt, fingerprint: previous, notBefore: certs[previous].NotBefore})
			}
			if len(series) == 0 || series[len(series)-1].fingerprint != current {
				series = append(series, step{at: observation.ObservedAt, fingerprint: current, notBefore: certs[current].NotBefore})
			}
			byAddress[address] = series
		}
	}
	if sanChanged > 0 && sanUnchanged > 0 {
		*counters = append(*counters, "有的替换改了 SAN 集合，有的没有，因此附加名称再生不能解释每一次替换。")
	}
	if _, old := features["notbefore_old"]; old {
		if _, fresh := features["notbefore_fresh"]; fresh {
			delete(features, "notbefore_old")
			delete(features, "notbefore_fresh")
			*counters = append(*counters, "签发年龄不一致：有的新叶已经较旧，有的接近首次观测才签发，因此不用 NotBefore 给预签发或现发打分。")
		}
	}
	for _, steps := range byAddress {
		classifyAddressSequence(domain, steps, certs, features)
	}
}

func classifyIssuanceAge(observed time.Time, cert models.Certificate, features map[string]struct{}) {
	if observed.IsZero() || cert.NotBefore.IsZero() || observed.Before(cert.NotBefore) {
		return
	}
	age := observed.Sub(cert.NotBefore)
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	if lifetime <= 0 && cert.ValidityDays > 0 {
		lifetime = time.Duration(cert.ValidityDays) * 24 * time.Hour
	}
	ratio := 0.0
	if lifetime > 0 {
		ratio = float64(age) / float64(lifetime)
	}
	if age <= 48*time.Hour || (lifetime > 0 && ratio <= 0.05) {
		features["notbefore_fresh"] = struct{}{}
		return
	}
	if age >= 14*24*time.Hour || ratio >= 0.30 {
		features["notbefore_old"] = struct{}{}
	}
}

func classifyAddressSequence(domain string, steps []step, certs map[string]models.Certificate, features map[string]struct{}) {
	if len(steps) < 2 {
		return
	}
	seen := map[string]time.Time{}
	returned := false
	olderReturned := false
	var newest time.Time
	for _, item := range steps {
		if _, ok := seen[item.fingerprint]; ok && !item.notBefore.IsZero() && !newest.IsZero() && item.notBefore.Before(newest) {
			olderReturned = true
			returned = true
		} else if _, ok := seen[item.fingerprint]; ok {
			returned = true
		}
		seen[item.fingerprint] = item.notBefore
		if !item.notBefore.IsZero() && (newest.IsZero() || item.notBefore.After(newest)) {
			newest = item.notBefore
		}
	}
	distinct := len(seen)
	namesCover := true
	for fingerprint := range seen {
		if !leafCoversDomain(domain, fingerprint, certs) {
			namesCover = false
			break
		}
	}
	if olderReturned {
		features["older_leaf_returns"] = struct{}{}
	}
	if returned && namesCover {
		features["oscillation"] = struct{}{}
	}
	if !returned && distinct >= 3 {
		features["forward_no_return"] = struct{}{}
	}
}

type step struct {
	at          time.Time
	fingerprint string
	notBefore   time.Time
}

func rankMechanisms(domain string, features map[string]struct{}, counters []string) MechanismReport {
	report := MechanismReport{
		Domain: domain,
		Limitation: "高亮行是这条域名实际观测到的证据。加号表示支持，减号表示排除，空格不加分。这张表不指出控制器、发布或操作者。",
	}
	report.Columns, report.Matrix = mechanismMatrix(features)
	totals := map[string]int{}
	for _, id := range mechanismOrder {
		totals[id] = 0
	}
	ids := make([]string, 0, len(features))
	for id := range features {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		weights := evidenceMatrix[id]
		if weights == nil {
			continue
		}
		copied := map[string]int{}
		for mechanism, weight := range weights {
			totals[mechanism] += weight
			copied[mechanism] = weight
		}
		report.Evidence = append(report.Evidence, EvidenceHit{ID: id, Summary: evidenceLabels[id], Weights: copied})
	}
	for _, id := range mechanismOrder {
		_, required := features[requiredEvidence[id]]
		falsified := evidenceFalsifies(id, features)
		verdict := "underdetermined"
		if falsified {
			verdict = "rejected"
		} else if required {
			verdict = "possible"
		}
		report.Scores = append(report.Scores, MechanismScore{
			ID: id, Name: mechanismNames[id], Score: totals[id], Verdict: verdict,
		})
	}
	sort.SliceStable(report.Scores, func(i, j int) bool {
		if report.Scores[i].Score == report.Scores[j].Score {
			return report.Scores[i].ID < report.Scores[j].ID
		}
		return report.Scores[i].Score > report.Scores[j].Score
	})
	report.Counterexamples = counters
	report.Missing = missingFeatures(features)
	eligible := make([]int, 0, len(report.Scores))
	for index := range report.Scores {
		if report.Scores[index].Verdict == "possible" && report.Scores[index].Score > 0 {
			eligible = append(eligible, index)
		}
	}
	if len(eligible) == 0 {
		report.Status = "insufficient"
		return report
	}
	leader := eligible[0]
	secondScore := 0
	if len(eligible) > 1 {
		secondScore = report.Scores[eligible[1]].Score
	}
	if report.Scores[leader].Score >= 2 && report.Scores[leader].Score-secondScore >= 2 {
		report.Status = "supported"
		report.MostSupported = report.Scores[leader].ID
		report.Scores[leader].Ranked = true
		report.Scores[leader].Verdict = "supported"
		return report
	}
	report.Status = "ambiguous"
	for _, index := range eligible {
		if report.Scores[leader].Score-report.Scores[index].Score < 2 {
			report.Scores[index].Ranked = true
		}
	}
	return report
}

func evidenceFalsifies(mechanism string, features map[string]struct{}) bool {
	for _, evidence := range falsifyingEvidence[mechanism] {
		if _, ok := features[evidence]; ok {
			return true
		}
	}
	return false
}

func mechanismMatrix(features map[string]struct{}) ([]MechanismColumn, []MatrixRow) {
	columns := make([]MechanismColumn, 0, len(mechanismOrder))
	for _, id := range mechanismOrder {
		columns = append(columns, MechanismColumn{ID: id, Name: mechanismNames[id]})
	}
	rows := make([]MatrixRow, 0, len(evidenceOrder))
	for _, evidence := range evidenceOrder {
		_, observed := features[evidence]
		row := MatrixRow{ID: evidence, Label: evidenceLabels[evidence], Observed: observed, Effects: []MatrixEffect{}}
		for _, mechanism := range mechanismOrder {
			weight, ok := evidenceMatrix[evidence][mechanism]
			if !ok || weight == 0 {
				continue
			}
			effect := "support"
			if weight < 0 {
				effect = "exclude"
			}
			row.Effects = append(row.Effects, MatrixEffect{Mechanism: mechanism, Effect: effect, Weight: weight})
		}
		rows = append(rows, row)
	}
	return columns, rows
}

func leafCoversDomain(domain, fingerprint string, certs map[string]models.Certificate) bool {
	cert, ok := certs[fingerprint]
	if !ok {
		return false
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(cert.CommonName), domain) {
		return true
	}
	for name := range sanSet(cert.SANs) {
		if name == domain {
			return true
		}
		if strings.HasPrefix(name, "*.") && strings.HasSuffix(domain, "."+name[2:]) {
			return true
		}
	}
	return false
}

func missingFeatures(features map[string]struct{}) []string {
	var missing []string
	if _, ok := features["sni_name_mismatch"]; ok {
		if _, have := features["empty_sni_same_leaf"]; !have {
			missing = append(missing, "还缺这个不匹配地址上的空 SNI 对照，才能排除 SNI 处理差异。")
		}
		missing = append(missing, "仍缺地址池成员、域名绑定和边缘发布记录，才能区分错误绑定和本不该服务该名称的地址。")
	}
	if _, ok := features["spki_different"]; ok {
		if _, have := features["spki_same"]; !have {
			missing = append(missing, "已看到的替换没有复用公钥。同钥重签只对同时带有新旧 SPKI 的替换被排除。")
		}
	}
	if _, old := features["notbefore_old"]; old {
		if _, fresh := features["notbefore_fresh"]; !fresh {
			missing = append(missing, "NotBefore 年龄支持预签发库存。它不是 CA 的签发时间戳。")
		}
	}
	if len(features) > 0 {
		missing = append(missing, "没有续签策略、CA 订单、部署和回滚记录，因此分数不能指出触发流程。")
	}
	return missing
}

func sansDiffer(previous, current models.Certificate) bool {
	left := sanSet(previous.SANs)
	right := sanSet(current.SANs)
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	if len(left) != len(right) {
		return true
	}
	for name := range left {
		if _, ok := right[name]; !ok {
			return true
		}
	}
	return false
}

func sanSet(raw string) map[string]struct{} {
	var names []string
	if json.Unmarshal([]byte(raw), &names) != nil {
		return nil
	}
	out := map[string]struct{}{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
