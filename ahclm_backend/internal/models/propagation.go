package models

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CDNPropagationStatus values describe the lifecycle of an active certificate
// propagation experiment. A completed experiment means every configured
// location served the target certificate for the required number of rounds.
const (
	CDNPropagationQueued   = "queued"
	CDNPropagationRunning  = "running"
	CDNPropagationComplete = "complete"
	CDNPropagationTimeout  = "timeout"
	CDNPropagationCanceled = "canceled"
	CDNPropagationFailed   = "failed"
)

// CDNPropagationCertificateLayer identifies which side of a CDN path is
// being measured. Global HTTPS probes observe the certificate served by the
// probe target; they do not infer the certificate used by a CDN when it
// connects back to the origin.
const (
	CDNPropagationLayerEdge         = "edge"
	CDNPropagationLayerOrigin       = "origin"
	CDNPropagationLayerOriginViaCDN = "origin_via_cdn"
)

// CDNPropagationConfig controls the optional background experiment worker.
// The worker is intentionally independent from the normal certificate scan
// cadence: propagation can be measured every few minutes without making all
// domains perform an expensive global probe.
type CDNPropagationConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	AutoStartOnChange bool          `mapstructure:"auto_start_on_change"`
	CDNOnly           bool          `mapstructure:"cdn_only"`
	WatchWindow       time.Duration `mapstructure:"watch_window"`
	PollInterval      time.Duration `mapstructure:"poll_interval"`
	MaxDuration       time.Duration `mapstructure:"max_duration"`
	StableRounds      int           `mapstructure:"stable_rounds"`
	Locations         []string      `mapstructure:"locations"`
	Timeout           time.Duration `mapstructure:"timeout"`
	MaxActive         int           `mapstructure:"max_active"`
}

// CDNPropagationExperiment is the durable control row for one replacement.
// SourceUpdatedAt is an operator supplied source-side timestamp when
// available. Automatically created experiments use the local monitor's first
// observation and identify that basis explicitly.
type CDNPropagationExperiment struct {
	ID                   uint       `json:"id" gorm:"primaryKey"`
	Domain               string     `json:"domain" gorm:"index;size:255"`
	Vendor               string     `json:"vendor,omitempty" gorm:"index;size:64"`
	CertificateLayer     string     `json:"certificate_layer" gorm:"index;size:16"`
	ProbeTarget          string     `json:"probe_target" gorm:"size:255"`
	ProbeHost            string     `json:"probe_host,omitempty" gorm:"size:255"`
	ProbePath            string     `json:"probe_path,omitempty" gorm:"size:1024"`
	ExpectedHTTPStatus   int        `json:"expected_http_status,omitempty"`
	WatchChanges         bool       `json:"watch_changes" gorm:"index"`
	WatchNotAfter        *time.Time `json:"watch_not_after,omitempty" gorm:"index"`
	Status               string     `json:"status" gorm:"index;size:32"`
	PreviousFingerprint  string     `json:"previous_fingerprint,omitempty" gorm:"size:64"`
	TargetFingerprint    string     `json:"target_fingerprint" gorm:"index;size:64"`
	SourceUpdatedAt      time.Time  `json:"source_updated_at" gorm:"index"`
	SourceTimeBasis      string     `json:"source_time_basis" gorm:"size:64"`
	StartedAt            time.Time  `json:"started_at"`
	LastAttemptedAt      *time.Time `json:"last_attempted_at,omitempty"`
	LastMeasuredAt       *time.Time `json:"last_measured_at,omitempty"`
	NextMeasureAt        time.Time  `json:"next_measure_at" gorm:"index"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
	CompletionReason     string     `json:"completion_reason,omitempty" gorm:"size:255"`
	PollIntervalSeconds  int64      `json:"poll_interval_seconds"`
	MaxDurationSeconds   int64      `json:"max_duration_seconds"`
	StableRoundsRequired int        `json:"stable_rounds_required"`
	StableRounds         int        `json:"stable_rounds"`
	ExpectedLocations    int        `json:"expected_locations"`
	ObservedLocations    int        `json:"observed_locations"`
	TargetLocations      int        `json:"target_locations"`
	Rounds               int        `json:"rounds"`
	LastError            string     `json:"last_error,omitempty" gorm:"type:text"`
	LocationsJSON        string     `json:"locations_json,omitempty" gorm:"type:text"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// CDNPropagationRound stores one Globalping measurement round. The per
// location rows below preserve the actual edge result used by the summary.
type CDNPropagationRound struct {
	MeasurementIDsJSON string    `json:"measurement_ids_json,omitempty" gorm:"type:text"`
	ID                 uint      `json:"id" gorm:"primaryKey"`
	ExperimentID       uint      `json:"experiment_id" gorm:"index"`
	RoundNumber        int       `json:"round_number"`
	ObservedAt         time.Time `json:"observed_at" gorm:"index"`
	MeasurementID      string    `json:"measurement_id,omitempty" gorm:"size:128"`
	Status             string    `json:"status" gorm:"size:32"`
	AnsweredCount      int       `json:"answered_count"`
	TargetCount        int       `json:"target_count"`
	PreviousCount      int       `json:"previous_count"`
	ExpectedCount      int       `json:"expected_count"`
	Complete           bool      `json:"complete"`
	Error              string    `json:"error,omitempty" gorm:"type:text"`
	CreatedAt          time.Time `json:"created_at"`
}

// CDNPropagationObservation is one location result from one round. Location
// identity is retained at the granularity supplied by Globalping, while the
// continent is used as the stable completion bucket when a city or probe ASN
// rotates between rounds.
type CDNPropagationObservation struct {
	MeasurementID         string    `json:"measurement_id,omitempty" gorm:"size:128"`
	RequestNonce          string    `json:"request_nonce,omitempty" gorm:"size:64"`
	OriginTLSResumed      string    `json:"origin_tls_resumed,omitempty" gorm:"size:16"`
	ID                    uint      `json:"id" gorm:"primaryKey"`
	ExperimentID          uint      `json:"experiment_id" gorm:"index"`
	RoundID               uint      `json:"round_id" gorm:"index"`
	ObservedAt            time.Time `json:"observed_at" gorm:"index"`
	LocationKey           string    `json:"location_key" gorm:"index;size:255"`
	Continent             string    `json:"continent,omitempty" gorm:"size:8"`
	Region                string    `json:"region,omitempty" gorm:"size:64"`
	Country               string    `json:"country,omitempty" gorm:"size:8"`
	City                  string    `json:"city,omitempty" gorm:"size:128"`
	ASN                   int       `json:"asn,omitempty"`
	Network               string    `json:"network,omitempty" gorm:"size:128"`
	ResolvedAddress       string    `json:"resolved_address,omitempty" gorm:"size:64"`
	Fingerprint           string    `json:"fingerprint,omitempty" gorm:"size:64"`
	Status                string    `json:"status,omitempty" gorm:"size:32"`
	TLSObserved           bool      `json:"tls_observed"`
	TLSAuthorized         bool      `json:"tls_authorized"`
	HTTPStatus            int       `json:"http_status,omitempty"`
	OriginFingerprint     string    `json:"origin_fingerprint,omitempty" gorm:"size:64"`
	OriginVerified        bool      `json:"origin_verified"`
	ProbeNonce            string    `json:"probe_nonce,omitempty" gorm:"size:64"`
	RequestSucceeded      bool      `json:"request_succeeded"`
	IsTarget              bool      `json:"is_target"`
	IsPrevious            bool      `json:"is_previous"`
	FingerprintChanged    bool      `json:"fingerprint_changed"`
	ChangeFromFingerprint string    `json:"change_from_fingerprint,omitempty" gorm:"size:64"`
	Error                 string    `json:"error,omitempty" gorm:"type:text"`
}

// CDNPropagationStartRequest is the API input for a new experiment.
type CDNPropagationStartRequest struct {
	Domain              string     `json:"domain"`
	Vendor              string     `json:"vendor,omitempty"`
	CertificateLayer    string     `json:"certificate_layer,omitempty"`
	ProbeTarget         string     `json:"probe_target,omitempty"`
	ProbeHost           string     `json:"probe_host,omitempty"`
	ProbePath           string     `json:"probe_path,omitempty"`
	ExpectedHTTPStatus  int        `json:"expected_http_status,omitempty"`
	WatchChanges        bool       `json:"watch_changes,omitempty"`
	WatchNotAfter       *time.Time `json:"watch_not_after,omitempty"`
	PreviousFingerprint string     `json:"previous_fingerprint,omitempty"`
	TargetFingerprint   string     `json:"target_fingerprint"`
	SourceUpdatedAt     *time.Time `json:"source_updated_at,omitempty"`
	SourceTimeBasis     string     `json:"source_time_basis,omitempty"`
	PollIntervalSeconds int        `json:"poll_interval_seconds,omitempty"`
	MaxDurationSeconds  int        `json:"max_duration_seconds,omitempty"`
	StableRounds        int        `json:"stable_rounds,omitempty"`
	Locations           []string   `json:"locations,omitempty"`
}

// CDNPropagationLocationSummary turns raw location rows into the values an
// operator needs to assess rollout latency and regional synchronization.
type CDNPropagationLocationSummary struct {
	LocationKey           string     `json:"location_key"`
	BaselineFingerprint   string     `json:"baseline_fingerprint,omitempty"`
	Continent             string     `json:"continent,omitempty"`
	Region                string     `json:"region,omitempty"`
	Country               string     `json:"country,omitempty"`
	City                  string     `json:"city,omitempty"`
	ASN                   int        `json:"asn,omitempty"`
	Network               string     `json:"network,omitempty"`
	FirstObservedAt       *time.Time `json:"first_observed_at,omitempty"`
	FirstTargetAt         *time.Time `json:"first_target_at,omitempty"`
	LastPreviousAt        *time.Time `json:"last_previous_at,omitempty"`
	LastObservedAt        *time.Time `json:"last_observed_at,omitempty"`
	LatestFingerprint     string     `json:"latest_fingerprint,omitempty"`
	LastTLSObserved       bool       `json:"last_tls_observed"`
	LastOriginFingerprint string     `json:"last_origin_fingerprint,omitempty"`
	LastOriginVerified    bool       `json:"last_origin_verified"`
	LastError             string     `json:"last_error,omitempty"`
	LastRequestSucceeded  bool       `json:"last_request_succeeded"`
	LastHTTPStatus        int        `json:"last_http_status,omitempty"`
	FirstRequestSuccessAt *time.Time `json:"first_request_success_at,omitempty"`
	TargetSeen            bool       `json:"target_seen"`
	PreviousSeen          bool       `json:"previous_seen"`
	AnsweredRounds        int        `json:"answered_rounds"`
	LatencyLowerSeconds   *float64   `json:"latency_lower_seconds,omitempty"`
	LatencySeconds        *float64   `json:"latency_seconds,omitempty"`
	State                 string     `json:"state"`
}

// CDNPropagationReport is the read model returned by the API. It contains
// enough information to reproduce the reported bounds without exposing every
// raw Globalping response.
type CDNPropagationReport struct {
	Experiment                   CDNPropagationExperiment        `json:"experiment"`
	Rounds                       []CDNPropagationRound           `json:"rounds"`
	Locations                    []CDNPropagationLocationSummary `json:"locations"`
	Changes                      []CDNPropagationChangeSummary   `json:"changes,omitempty"`
	FirstTargetAt                *time.Time                      `json:"first_target_at,omitempty"`
	AllRegionsTargetAt           *time.Time                      `json:"all_regions_target_at,omitempty"`
	CompletedAt                  *time.Time                      `json:"completed_at,omitempty"`
	SourceToFirstSeconds         *float64                        `json:"source_to_first_seconds,omitempty"`
	SourceToAllRegionsSeconds    *float64                        `json:"source_to_all_regions_seconds,omitempty"`
	SourceToCompleteSeconds      *float64                        `json:"source_to_complete_seconds,omitempty"`
	SynchronizationSpreadSeconds *float64                        `json:"synchronization_spread_seconds,omitempty"`
	SyncState                    string                          `json:"sync_state"`
	Interpretation               string                          `json:"interpretation"`
}

// CDNPropagationChangeSummary describes an unanticipated leaf change observed
// by a baseline watcher. FirstSeenAt and Regions are evidence bounds, not a
// claim about all CDN points of presence.
type CDNPropagationChangeSummary struct {
	PreviousFingerprint string    `json:"previous_fingerprint"`
	Fingerprint         string    `json:"fingerprint"`
	FirstSeenAt         time.Time `json:"first_seen_at"`
	LastSeenAt          time.Time `json:"last_seen_at"`
	Regions             []string  `json:"regions"`
	FirstSeenSpreadSecs float64   `json:"first_seen_spread_seconds"`
}

// NormalizePropagationLocations canonicalizes configured continents and
// removes duplicates while retaining deterministic ordering.
func NormalizePropagationLocations(locations []string) []string {
	seen := make(map[string]struct{}, len(locations))
	for _, location := range locations {
		value := strings.ToUpper(strings.TrimSpace(location))
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// PropagationLocationKey is stable when a probe moves between cities inside a
// continent. The full location is still stored separately for inspection.
func PropagationLocationKey(location GlobalProbeLocation) string {
	continent := strings.ToUpper(strings.TrimSpace(location.Continent))
	if continent != "" {
		return continent
	}
	parts := []string{location.Region, location.Country, location.City, location.Network}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.ToUpper(strings.Join(parts, "/"))
}

// ValidatePropagationRequest keeps malformed fingerprints and impossible
// timing values out of the persisted experiment table.
func (r CDNPropagationStartRequest) Validate() error {
	if strings.TrimSpace(r.Domain) == "" {
		return fmt.Errorf("domain is required")
	}
	layer := NormalizePropagationCertificateLayer(r.CertificateLayer)
	if !r.WatchChanges && strings.TrimSpace(r.TargetFingerprint) == "" {
		return fmt.Errorf("target_fingerprint is required")
	}
	if layer == "" {
		return fmt.Errorf("certificate_layer must be edge, origin, or origin_via_cdn")
	}
	if layer == CDNPropagationLayerOriginViaCDN {
		for _, name := range []string{r.ProbeTarget, r.ProbeHost} {
			name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
			if name != "" && (strings.ContainsAny(name, " \t\r\n/:\\?#") || net.ParseIP(name) != nil || !strings.Contains(name, ".")) {
				return fmt.Errorf("CDN probe target and host must be DNS hostnames")
			}
		}
		if r.WatchChanges {
			return fmt.Errorf("watch_changes is not supported for CDN origin request measurements")
		}
		path := strings.TrimSpace(r.ProbePath)
		if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n# ") {
			return fmt.Errorf("probe_path must be an absolute URL path without spaces or a fragment")
		}
		u, err := url.ParseRequestURI(path)
		if err != nil || u.IsAbs() || u.Host != "" || strings.HasPrefix(path, "//") {
			return fmt.Errorf("probe_path must be a valid local URL path")
		}
		if len(path) > 1024 {
			return fmt.Errorf("probe_path must not exceed 1024 characters")
		}
		if r.ExpectedHTTPStatus != 0 && (r.ExpectedHTTPStatus < 200 || r.ExpectedHTTPStatus > 399) {
			return fmt.Errorf("expected_http_status must be between 200 and 399")
		}
		if r.SourceUpdatedAt == nil || r.SourceUpdatedAt.IsZero() {
			return fmt.Errorf("source_updated_at is required for CDN origin request measurements")
		}
	}
	if layer == CDNPropagationLayerOrigin {
		target := strings.TrimSpace(r.ProbeTarget)
		ip := net.ParseIP(target)
		if ip == nil || !IsPublicIP(ip.String()) {
			return fmt.Errorf("probe_target must be a public IP address for origin measurements")
		}
		if strings.TrimSpace(r.ProbeHost) == "" {
			return fmt.Errorf("probe_host is required for origin measurements (TLS SNI and HTTP Host)")
		}
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.ProbeHost)), ".")
		if host == "" || strings.ContainsAny(host, " \t\r\n/:\\") || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
			return fmt.Errorf("probe_host must be a DNS hostname")
		}
	}
	if layer == CDNPropagationLayerOriginViaCDN {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.ProbeHost)), ".")
		if host != "" && (strings.ContainsAny(host, " \t\r\n/:\\") || net.ParseIP(host) != nil || !strings.Contains(host, ".")) {
			return fmt.Errorf("probe_host must be a DNS hostname")
		}
	}
	if strings.TrimSpace(r.TargetFingerprint) != "" && !validPropagationFingerprint(r.TargetFingerprint) {
		return fmt.Errorf("target_fingerprint must be a SHA-256 fingerprint")
	}
	if r.PreviousFingerprint != "" && !validPropagationFingerprint(r.PreviousFingerprint) {
		return fmt.Errorf("previous_fingerprint must be a SHA-256 fingerprint")
	}
	if r.PreviousFingerprint != "" && strings.EqualFold(
		strings.ReplaceAll(strings.TrimSpace(r.PreviousFingerprint), ":", ""),
		strings.ReplaceAll(strings.TrimSpace(r.TargetFingerprint), ":", ""),
	) {
		return fmt.Errorf("previous_fingerprint must differ from target_fingerprint")
	}
	if r.WatchChanges && strings.TrimSpace(r.PreviousFingerprint) != "" {
		return fmt.Errorf("previous_fingerprint is not used by a change watcher")
	}
	if r.PollIntervalSeconds < 0 || r.MaxDurationSeconds < 0 || r.StableRounds < 0 {
		return fmt.Errorf("propagation timing values must not be negative")
	}
	if r.PollIntervalSeconds > 0 && (r.PollIntervalSeconds < 30 || r.PollIntervalSeconds > 86400) {
		return fmt.Errorf("poll_interval_seconds must be between 30 and 86400")
	}
	if r.MaxDurationSeconds > 30*86400 {
		return fmt.Errorf("max_duration_seconds must not exceed 30 days")
	}
	if r.StableRounds > 100 {
		return fmt.Errorf("stable_rounds must not exceed 100")
	}
	for _, location := range NormalizePropagationLocations(r.Locations) {
		switch location {
		case "AF", "AS", "EU", "NA", "OC", "SA":
		default:
			return fmt.Errorf("unsupported propagation continent %q", location)
		}
	}
	return nil
}

// NormalizePropagationCertificateLayer keeps older rows and clients
// compatible: before the origin path was supported, every experiment was an
// edge observation of its public domain.
func NormalizePropagationCertificateLayer(layer string) string {
	switch strings.ToLower(strings.TrimSpace(layer)) {
	case "", CDNPropagationLayerEdge:
		return CDNPropagationLayerEdge
	case CDNPropagationLayerOrigin:
		return CDNPropagationLayerOrigin
	case CDNPropagationLayerOriginViaCDN:
		return CDNPropagationLayerOriginViaCDN
	default:
		return ""
	}
}

func validPropagationFingerprint(value string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), ":", "")
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
