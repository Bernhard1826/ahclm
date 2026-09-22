package models

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// TrancoTopLimit is the fixed production population size for the ranked
// Tranco source. Local lists may add domains on top of this population.
const TrancoTopLimit = 10000

// Observation types recorded in the cert_observations time-series.
const (
	ObsInitial           = "initial"            // first time we ever recorded a cert for this domain
	ObsChange            = "change"             // deployed certificate changed (new fingerprint)
	ObsMilestone         = "milestone"          // crossed a pre/post-expiry milestone (e.g. 7d before)
	ObsRevocationChange  = "revocation_change"  // revocation status transitioned
	ObsExpiry            = "expiry"             // certificate crossed its NotAfter
	ObsReappear          = "reappear"           // domain came back after being unreachable
	ObsUnreachable       = "unreachable"        // domain became unreachable
	ObsARIWindow         = "ari_window"         // CA's ARI suggestedWindow appeared or changed
	ObsARIEmergency      = "ari_emergency"      // ARI window pulled forward to "now" (mass-revocation signal)
	ObsSameKey           = "same_key"           // certificate changed while SPKI stayed the same
	ObsStaleAfterChange  = "stale_after_change" // same valid leaf remained after DNS/IP change (proxy)
	ObsResidual          = "residual"           // revoked predecessor observed after CA revocation
	ObsDeploymentFailure = "deployment_failure" // authorized/multi-endpoint deployment failure evidence
)

// DetectorVersion tags every observation with the detection-rule generation
// that produced it. Rows written before this field existed are backfilled to
// DetectorLegacy. Detection rules have been tightened over time, so a finding
// that aggregates legacy rows cannot claim the same confidence as one built
// from current-rule rows; the diagnosis layer reads this tag to say so.
const (
	DetectorLegacy  = "v1"
	DetectorCurrent = "v2"
)

// ChangeClass records what a "the certificate changed" observation actually
// proves. A fingerprint difference between two consecutive scans is only a
// replacement in time when both samples came from the same endpoint and the
// predecessor is no longer being served anywhere. Otherwise the difference is
// a property of *which server answered*, not of the deployment's history.
const (
	// ChangeClassReplacement: the same endpoint served a different leaf than it
	// did before, and the predecessor was not observed concurrently.
	ChangeClassReplacement = "replacement"
	// ChangeClassCoexisting: the same measurement round observed the predecessor
	// and the successor simultaneously on different endpoints. This is direct
	// proof that the two certificates are deployed concurrently, so the event is
	// not a replacement at all.
	ChangeClassCoexisting = "coexisting_leaf"
	// ChangeClassEndpointSampling: the leaf differs but the observation came
	// from a different address than the previous one, and no concurrent proof is
	// available. The difference may be temporal or spatial; it is undetermined.
	ChangeClassEndpointSampling = "endpoint_sampling"
	// ChangeClassUnknown: no endpoint identity was retained for the comparison.
	ChangeClassUnknown = "unknown"
)

// Domain deployment status.
const (
	StatusActive      = "active"
	StatusUnreachable = "unreachable"
	// StatusDormant is retained only for rows written by older binaries. New
	// scans never infer retirement or dormancy from certificate expiry.
	StatusDormant = "dormant"
)

// Revocation status values.
const (
	RevocationGood       = "good"
	RevocationRevoked    = "revoked"
	RevocationUnknown    = "unknown"
	RevocationNotChecked = "not_checked"
)

// Revocation check methods.
const (
	CheckedViaStapledOCSP = "stapled_ocsp"
	CheckedViaOCSP        = "ocsp"
	CheckedViaCRL         = "crl"
	CheckedViaNone        = "none"
)

// Scan job status values. The persisted job log is an audit trail for
// scheduled/manual scans; NextScanAt remains the scheduling source of truth.
const (
	ScanJobRunning   = "running"
	ScanJobSucceeded = "succeeded"
	ScanJobFailed    = "failed"
)

// Scan failure classes distinguish a target that cannot expose a certificate
// from a transient network problem. Failed scans remain counted, but only
// transient failures should consume retry attempts.
const (
	ScanFailureNetwork    = "network"
	ScanFailureDNS        = "dns"
	ScanFailureTLS        = "tls"
	ScanFailureNoEndpoint = "no_endpoint"
	ScanFailureCanceled   = "canceled"
	ScanFailureUnknown    = "unknown"
)

// ARI (ACME Renewal Information) fetch status.
const (
	ARIStatusOK          = "ok"          // suggestedWindow retrieved
	ARIStatusUnsupported = "unsupported" // issuer CA has no known ARI endpoint
	ARIStatusUnavailable = "unavailable" // ARI-capable CA but request could not be built/answered
	ARIStatusError       = "error"       // transient error querying ARI
	ARIStatusNotChecked  = "not_checked" // ARI checking disabled or not yet run
)

// Evidence status describes how far the staged monitoring pipeline progressed.
const (
	EvidenceStatusBaseline      = "baseline"
	EvidenceStatusPending       = "pending"
	EvidenceStatusComplete      = "complete"
	EvidenceStatusNotApplicable = "not_applicable"
	EvidenceStatusUnknown       = "unknown"
)

// ---------------------------------------------------------------------------
// Core entities (persisted)
// ---------------------------------------------------------------------------

// Certificate is one distinct physical certificate, de-duplicated globally by
// its SHA-256 fingerprint. Many domains may point at the same Certificate row
// (shared CDN / wildcard / SAN certificates), which is why the fingerprint is
// globally unique here and the domain lives in DomainCertificate instead.
type Certificate struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	Fingerprint     string    `json:"fingerprint" gorm:"uniqueIndex;size:64"`
	SPKIFingerprint string    `json:"spki_fingerprint,omitempty" gorm:"index;size:64"`
	SerialNumber    string    `json:"serial_number" gorm:"index;size:128"`
	Issuer          string    `json:"issuer"`
	IssuerCN        string    `json:"issuer_cn" gorm:"index;size:255"`
	Subject         string    `json:"subject"`
	CommonName      string    `json:"common_name" gorm:"index;size:255"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after" gorm:"index"`
	SignatureAlgo   string    `json:"signature_algorithm"`
	KeyAlgorithm    string    `json:"key_algorithm"`
	KeySize         int       `json:"key_size"`
	PublicKeyType   string    `json:"public_key_type"`
	IsCA            bool      `json:"is_ca"`
	SelfSigned      bool      `json:"self_signed"`
	SANs            string    `json:"sans" gorm:"type:text"`  // JSON array of subject alternative names
	ValidityDays    int       `json:"validity_days"`          // total lifetime NotAfter-NotBefore
	Chain           string    `json:"chain" gorm:"type:text"` // JSON array of chain entries (leaf→root)
	RawCert         string    `json:"-" gorm:"type:text"`     // base64 DER, not exposed in API
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// DomainCertificate holds the *current* deployment state for a domain plus all
// lifecycle & scheduling metadata. One small row per domain; NextScanAt is the
// heart of the adaptive scheduler.
type DomainCertificate struct {
	TLSFindings           string     `json:"tls_findings,omitempty" gorm:"type:text"`
	TLSCheckedAt          *time.Time `json:"tls_checked_at,omitempty"`
	ID                    uint       `json:"id" gorm:"primaryKey"`
	Domain                string     `json:"domain" gorm:"uniqueIndex;size:255"`
	TrancoRank            int        `json:"tranco_rank" gorm:"index"`
	LocalListMember       bool       `json:"local_list_member" gorm:"index;default:false"`
	CurrentCertificateID  uint       `json:"current_certificate_id" gorm:"index"`
	CurrentFingerprint    string     `json:"current_fingerprint" gorm:"index;size:64"`
	Status                string     `json:"status" gorm:"index"`            // active, unreachable; dormant is legacy only
	RevocationStatus      string     `json:"revocation_status" gorm:"index"` // good, revoked, unknown, not_checked
	RevocationCheckedVia  string     `json:"revocation_checked_via"`
	RevokedAt             *time.Time `json:"revoked_at,omitempty"`
	RevocationReason      string     `json:"revocation_reason,omitempty"`
	RevocationCheckedAt   *time.Time `json:"revocation_checked_at,omitempty"`
	RevocationNextCheckAt *time.Time `json:"revocation_next_check_at,omitempty" gorm:"index"`
	OCSPCheckedAt         *time.Time `json:"ocsp_checked_at,omitempty"`
	EvidenceStatus        string     `json:"evidence_status" gorm:"index"`
	EvidencePendingReason string     `json:"evidence_pending_reason,omitempty" gorm:"type:text"`
	EvidenceCheckedAt     *time.Time `json:"evidence_checked_at,omitempty"`
	FirstSeenAt           time.Time  `json:"first_seen_at"`
	LastScannedAt         time.Time  `json:"last_scanned_at" gorm:"index"`
	LastChangedAt         *time.Time `json:"last_changed_at,omitempty"`
	LastDaysUntilExpiry   int        `json:"last_days_until_expiry"`
	NextScanAt            time.Time  `json:"next_scan_at" gorm:"index"`
	Priority              int        `json:"priority" gorm:"index"`
	ScanCount             int        `json:"scan_count"`
	// ChangeCount is the number of same-IP leaf replacements, not the number of
	// times the domain-level current fingerprint differed. A new address, a
	// retired address, or two live addresses serving different leaves does not
	// increment this counter.
	ChangeCount               int        `json:"change_count"`
	ConsecutiveFailures       int        `json:"consecutive_failures"`
	LastError                 string     `json:"last_error,omitempty"`
	LastFailureClass          string     `json:"last_failure_class,omitempty"`
	ResolvedIPs               string     `json:"resolved_ips,omitempty" gorm:"type:text"`
	ConsensusIPs              string     `json:"consensus_ips,omitempty" gorm:"type:text"`
	TopologyCNAMEs            string     `json:"topology_cnames,omitempty" gorm:"type:text"`
	TopologyHash              string     `json:"topology_hash,omitempty" gorm:"index;size:64"`
	TopologyResolverQuorum    int        `json:"topology_resolver_quorum"`
	TopologyResolverAgreement float64    `json:"topology_resolver_agreement"`
	LastDNSObservedAt         *time.Time `json:"last_dns_observed_at,omitempty"`
	EndpointStates            string     `json:"endpoint_states,omitempty" gorm:"type:text"`
	EndpointDiversityStatus   string     `json:"endpoint_diversity_status,omitempty" gorm:"index;size:32"`
	EndpointDiversityRounds   int        `json:"endpoint_diversity_rounds"`
	// LastEndpointIP is the address whose handshake produced the currently
	// recorded certificate. Comparing it with the next scan's address is what
	// separates "this server now serves a different certificate" from "a
	// different server answered this time".
	LastEndpointIP      string     `json:"last_endpoint_ip,omitempty" gorm:"size:64"`
	LastEndpointProbeAt *time.Time `json:"last_endpoint_probe_at,omitempty"`

	LastDeepMeasurementAt    *time.Time `json:"last_deep_measurement_at,omitempty"`
	ResidualFingerprint      string     `json:"residual_fingerprint,omitempty" gorm:"index;size:64"`
	ResidualRevokedAt        *time.Time `json:"residual_revoked_at,omitempty"`
	ResidualFirstSeenAt      *time.Time `json:"residual_first_seen_at,omitempty"`
	ResidualLastSeenAt       *time.Time `json:"residual_last_seen_at,omitempty"`
	ResidualNextCheckAt      *time.Time `json:"residual_next_check_at,omitempty" gorm:"index"`
	ResidualObservationCount int        `json:"residual_observation_count"`

	// ARI (ACME Renewal Information) — the CA-side recommended renewal window.
	ARISupported      bool       `json:"ari_supported"`
	ARIStatus         string     `json:"ari_status,omitempty"`
	ARIWindowStart    *time.Time `json:"ari_window_start,omitempty"`
	ARIWindowEnd      *time.Time `json:"ari_window_end,omitempty"`
	ARIExplanationURL string     `json:"ari_explanation_url,omitempty"`
	ARICheckedAt      *time.Time `json:"ari_checked_at,omitempty"`
	ARIEmergency      bool       `json:"ari_emergency" gorm:"index"`
	ARINextPollAt     *time.Time `json:"ari_next_poll_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	CurrentCertificate *Certificate `json:"current_certificate,omitempty" gorm:"foreignKey:CurrentCertificateID"`
}

// CertObservation is the append-only time-series log. Under the hybrid storage
// strategy a row is written ONLY on a meaningful event (initial sighting,
// change, milestone crossing, revocation change, expiry) — never once per scan
// of an unchanged certificate. This is the dataset used for pattern analysis.
type CertObservation struct {
	ID                      uint       `json:"id" gorm:"primaryKey"`
	Domain                  string     `json:"domain" gorm:"index;size:255"`
	CertificateID           uint       `json:"certificate_id" gorm:"index"`
	Fingerprint             string     `json:"fingerprint" gorm:"index;size:64"`
	ObservedAt              time.Time  `json:"observed_at" gorm:"index"`
	ObservationType         string     `json:"observation_type" gorm:"index"`
	Milestone               string     `json:"milestone,omitempty" gorm:"index;size:32"`
	DaysUntilExpiry         int        `json:"days_until_expiry"`
	RevocationStatus        string     `json:"revocation_status,omitempty"`
	RevocationCheckedVia    string     `json:"revocation_checked_via,omitempty"`
	RevocationCheckedAt     *time.Time `json:"revocation_checked_at,omitempty"`
	RevokedAt               *time.Time `json:"revoked_at,omitempty"`
	RevocationReason        string     `json:"revocation_reason,omitempty"`
	EvidenceStatus          string     `json:"evidence_status"`
	EvidencePendingReason   string     `json:"evidence_pending_reason,omitempty" gorm:"type:text"`
	PreviousFingerprint     string     `json:"previous_fingerprint,omitempty" gorm:"size:64"`
	PreviousSPKIFingerprint string     `json:"previous_spki_fingerprint,omitempty" gorm:"size:64"`
	SPKIFingerprint         string     `json:"spki_fingerprint,omitempty" gorm:"size:64"`
	ResolvedIPs             string     `json:"resolved_ips,omitempty" gorm:"type:text"`
	PreviousResolvedIPs     string     `json:"previous_resolved_ips,omitempty" gorm:"type:text"`
	EndpointProbes          string     `json:"endpoint_probes,omitempty" gorm:"type:text"`
	DeepEvidence            string     `json:"deep_evidence,omitempty" gorm:"type:text"`
	ResidualDurationSeconds int64      `json:"residual_duration_seconds,omitempty"`
	TLSVersion              string     `json:"tls_version,omitempty"`
	CipherSuite             string     `json:"cipher_suite,omitempty"`
	IPAddress               string     `json:"ip_address,omitempty"`
	ScanDurationMs          int64      `json:"scan_duration_ms"`
	ARIWindowStart          *time.Time `json:"ari_window_start,omitempty"`
	ARIWindowEnd            *time.Time `json:"ari_window_end,omitempty"`
	// DetectorVersion is the detection-rule generation that produced this row.
	DetectorVersion string `json:"detector_version,omitempty" gorm:"index;size:8"`
	// ChangeClass is set on ObsChange rows and records whether the fingerprint
	// difference was proven to be a replacement in time, proven to be two
	// concurrently deployed leaves, or left undetermined by the sampling.
	ChangeClass string `json:"change_class,omitempty" gorm:"index;size:24"`
	// PreviousIPAddress is the endpoint that served the predecessor leaf. With
	// IPAddress it makes the same-endpoint comparison reproducible after the
	// fact instead of only at detection time.
	PreviousIPAddress string    `json:"previous_ip_address,omitempty" gorm:"size:64"`
	Notes             string    `json:"notes,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// DailyScanStat is one row per day with counters incremented in place, so we
// get daily throughput/change/revocation trends without a row-per-scan table.
type DailyScanStat struct {
	ID                  uint      `json:"id" gorm:"primaryKey"`
	Date                string    `json:"date" gorm:"uniqueIndex;size:10"` // YYYY-MM-DD
	TotalScans          int       `json:"total_scans"`
	SuccessfulScans     int       `json:"successful_scans"`
	FailedScans         int       `json:"failed_scans"`
	ChangesDetected     int       `json:"changes_detected"`
	RevocationsDetected int       `json:"revocations_detected"`
	NewCerts            int       `json:"new_certs"`
	MilestoneScans      int       `json:"milestone_scans"`
	TotalScanMs         int64     `json:"total_scan_ms"`
	AverageScanMs       float64   `json:"average_scan_ms" gorm:"-"` // computed
	UpdatedAt           time.Time `json:"updated_at"`
}

// TrancoList records metadata about each fetched ranking list.
type TrancoList struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	ListID    string    `json:"list_id" gorm:"index;size:64"`
	Source    string    `json:"source"` // configured downloaded zip source
	Date      string    `json:"date"`
	Count     int       `json:"count"`
	FetchedAt time.Time `json:"fetched_at"`
	CreatedAt time.Time `json:"created_at"`
}

// ScanJob is a persisted audit record for one scan attempt. For the Tranco
// Top-N population this gives enough traceability to answer "why did we scan this domain,
// when did it run, and what did it observe" without introducing a distributed
// queue prematurely.
type ScanJob struct {
	ID               uint       `json:"id" gorm:"primaryKey"`
	Domain           string     `json:"domain" gorm:"index;size:255"`
	Reason           string     `json:"reason" gorm:"index;size:64"`
	ScheduledAt      time.Time  `json:"scheduled_at" gorm:"index"`
	StartedAt        *time.Time `json:"started_at,omitempty" gorm:"index"`
	FinishedAt       *time.Time `json:"finished_at,omitempty" gorm:"index"`
	Status           string     `json:"status" gorm:"index;size:32"`
	Success          bool       `json:"success" gorm:"index"`
	Fingerprint      string     `json:"fingerprint,omitempty" gorm:"index;size:64"`
	RevocationStatus string     `json:"revocation_status,omitempty"`
	ARIStatus        string     `json:"ari_status,omitempty"`
	FailureClass     string     `json:"failure_class,omitempty"`
	Error            string     `json:"error,omitempty" gorm:"type:text"`
	ScanDurationMs   int64      `json:"scan_duration_ms"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// ARICacheEntry persists a CA's latest ARI renewalInfo response for one
// RFC 9773 certificate identifier. It survives process restarts and prevents
// repeated polling before the CA's Retry-After window has elapsed.
type ARICacheEntry struct {
	ID             uint       `json:"id" gorm:"primaryKey"`
	ARIIdentifier  string     `json:"ari_identifier" gorm:"uniqueIndex;size:512"`
	Source         string     `json:"source,omitempty"`
	Status         string     `json:"status" gorm:"index;size:32"`
	WindowStart    *time.Time `json:"window_start,omitempty"`
	WindowEnd      *time.Time `json:"window_end,omitempty"`
	ExplanationURL string     `json:"explanation_url,omitempty" gorm:"type:text"`
	RetryAfterSecs int        `json:"retry_after_secs"`
	FetchedAt      time.Time  `json:"fetched_at"`
	ExpiresAt      time.Time  `json:"expires_at" gorm:"index"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// CRLCacheEntry persists a verified CRL by distribution-point URL. RawDER is
// intentionally excluded from JSON responses; it is only an internal cache.
type CRLCacheEntry struct {
	ID         uint       `json:"id" gorm:"primaryKey"`
	URL        string     `json:"url" gorm:"uniqueIndex;type:text"`
	RawDER     []byte     `json:"-" gorm:"type:bytea"`
	ThisUpdate *time.Time `json:"this_update,omitempty"`
	NextUpdate *time.Time `json:"next_update,omitempty"`
	FetchedAt  time.Time  `json:"fetched_at"`
	ExpiresAt  time.Time  `json:"expires_at" gorm:"index"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// CertificateAlert is a user-configured alert rule (CRUD from the frontend).
type CertificateAlert struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Name         string    `json:"name"`
	IntervalDays int       `json:"interval_days"`
	IsEnabled    bool      `json:"is_enabled"`
	EmailEnabled bool      `json:"email_enabled"`
	WebhookURL   string    `json:"webhook_url,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ---------------------------------------------------------------------------
// In-memory / transport structs (not persisted directly)
// ---------------------------------------------------------------------------

// ScanResult is what the scanner returns for a single domain scan.
type ScanResult struct {
	TLSFindings           []TLSFinding        `json:"tls_findings,omitempty"`
	Domain                string              `json:"domain"`
	Success               bool                `json:"success"`
	Error                 string              `json:"error,omitempty"`
	FailureClass          string              `json:"failure_class,omitempty"`
	Cert                  *Certificate        `json:"certificate,omitempty"`
	Chain                 []*Certificate      `json:"chain,omitempty"`
	ConnectionInfo        *ConnectionInfo     `json:"connection_info,omitempty"`
	RevocationStatus      string              `json:"revocation_status"`
	RevocationCheckedVia  string              `json:"revocation_checked_via"`
	RevocationCheckedAt   *time.Time          `json:"revocation_checked_at,omitempty"`
	RevokedAt             *time.Time          `json:"revoked_at,omitempty"`
	RevocationReason      string              `json:"revocation_reason,omitempty"`
	EvidenceStatus        string              `json:"evidence_status"`
	EvidencePendingReason string              `json:"evidence_pending_reason,omitempty"`
	ARI                   *ARIInfo            `json:"ari,omitempty"`
	ScanDuration          time.Duration       `json:"scan_duration"`
	ScannedAt             time.Time           `json:"scanned_at"`
	RawChain              []*x509.Certificate `json:"-"`
	StapledOCSP           []byte              `json:"-"`
	ResolvedIPs           []string            `json:"resolved_ips,omitempty"`
	ResolvedIPsKnown      bool                `json:"resolved_ips_known"`
	EndpointProbes        []EndpointProbe     `json:"endpoint_probes,omitempty"`
	Topology              *TopologySnapshot   `json:"topology,omitempty"`
	DeepEvidence          *DeepEvidence       `json:"deep_evidence,omitempty"`
	MeasurementTrigger    string              `json:"measurement_trigger,omitempty"`
}

// ARIInfo is the CA-side ACME Renewal Information for the leaf certificate,
// obtained from the issuing CA's renewalInfo endpoint (RFC 9773).
type ARIInfo struct {
	Status         string     `json:"status"`           // ok, unsupported, unavailable, error
	Source         string     `json:"source,omitempty"` // CA name, e.g. "Let's Encrypt"
	WindowStart    *time.Time `json:"window_start,omitempty"`
	WindowEnd      *time.Time `json:"window_end,omitempty"`
	ExplanationURL string     `json:"explanation_url,omitempty"`
	RetryAfterSecs int        `json:"retry_after_secs,omitempty"`
	NextPollAt     *time.Time `json:"next_poll_at,omitempty"`
}

// ConnectionInfo holds TCP/TLS connection metadata.
type ConnectionInfo struct {
	Protocol           string           `json:"protocol"`
	TLSVersion         string           `json:"tls_version"`
	CipherSuite        string           `json:"cipher_suite"`
	NegotiatedProtocol string           `json:"negotiated_protocol,omitempty"`
	ALPN               string           `json:"alpn,omitempty"`
	ConnectionTime     int64            `json:"connection_time_ms"`
	IPAddress          string           `json:"ip_address,omitempty"`
	ResolvedIPs        []string         `json:"resolved_ips,omitempty"`
	SCTs               []SCTObservation `json:"scts,omitempty"`
}

// EndpointProbe is a candidate-only direct TLS check against one previously
// resolved address. It distinguishes an observed mixed rollout from a single
// vantage certificate change and does not imply complete global edge coverage.
type EndpointProbe struct {
	Findings        []TLSFinding `json:"findings,omitempty"`
	IPAddress       string       `json:"ip_address"`
	Success         bool         `json:"success"`
	Fingerprint     string       `json:"fingerprint,omitempty"`
	SPKIFingerprint string       `json:"spki_fingerprint,omitempty"`
	Error           string       `json:"error,omitempty"`
	TLSVersion      string       `json:"tls_version,omitempty"`
	CipherSuite     string       `json:"cipher_suite,omitempty"`
	IssuerCN        string       `json:"issuer_cn,omitempty"`
	CommonName      string       `json:"common_name,omitempty"`
	// KeyAlgorithm and KeySize separate an intentional RSA+ECDSA dual-certificate
	// deployment from a genuinely inconsistent one: the former serves different
	// keys for the same names on purpose.
	KeyAlgorithm string `json:"key_algorithm,omitempty"`
	KeySize      int    `json:"key_size,omitempty"`
	// SerialNumber and SANs are the leaf identity fields needed to compare two
	// certificates that share an issuer and validity window. SANsHash remains
	// the compact equality check; SANs is the human-readable name set.
	SerialNumber string   `json:"serial_number,omitempty"`
	SANs         []string `json:"sans,omitempty"`
	// SANsHash is a stable digest of the sorted SAN set. Endpoints whose
	// certificates cover exactly the same names are functionally interchangeable
	// even when the leaves differ.
	SANsHash  string     `json:"sans_hash,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
}

// EndpointState is the per-address longitudinal state used to tell a stable
// CDN fan-out from a rollout. FirstSeen/LastSeen are observation bounds; they
// do not imply that the address was continuously reachable between probes.
type EndpointState struct {
	IPAddress       string    `json:"ip_address"`
	Fingerprint     string    `json:"fingerprint,omitempty"`
	SPKIFingerprint string    `json:"spki_fingerprint,omitempty"`
	IssuerCN        string    `json:"issuer_cn,omitempty"`
	CommonName      string    `json:"common_name,omitempty"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	LastSuccess     bool      `json:"last_success"`
	Observations    int       `json:"observations"`
	Failures        int       `json:"failures"`
}

type TLSFinding struct {
	Code        string `json:"code"`
	Detail      string `json:"detail"`
	IPAddress   string `json:"ip_address"`
	Fingerprint string `json:"fingerprint"`
}

// DNSResolverObservation is one public-recursive-resolver view of a domain.
// Resolver identity and TTL are retained so a topology transition is a
// reproducible quorum event rather than a single changing answer.
type DNSResolverObservation struct {
	Resolver string   `json:"resolver"`
	A        []string `json:"a,omitempty"`
	AAAA     []string `json:"aaaa,omitempty"`
	CNAME    []string `json:"cname,omitempty"`
	HTTPS    []string `json:"https,omitempty"`
	NS       []string `json:"ns,omitempty"`
	TTL      int      `json:"ttl,omitempty"`
	DNSSEC   bool     `json:"dnssec,omitempty"`
	Success  bool     `json:"success"`
	Error    string   `json:"error,omitempty"`
}

type TopologySnapshot struct {
	Resolvers         []DNSResolverObservation `json:"resolvers,omitempty"`
	PublicIPs         []string                 `json:"public_ips,omitempty"`
	ConsensusIPs      []string                 `json:"consensus_ips,omitempty"`
	CNAMEChain        []string                 `json:"cname_chain,omitempty"`
	HTTPSTargets      []string                 `json:"https_targets,omitempty"`
	NSHosts           []string                 `json:"ns_hosts,omitempty"`
	ResolverQuorum    int                      `json:"resolver_quorum"`
	ResolverAgreement float64                  `json:"resolver_agreement"`
	DNSSECValidated   int                      `json:"dnssec_validated,omitempty"`
	TopologyHash      string                   `json:"topology_hash,omitempty"`
}

type CAARecord struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// CTObservation retains certificate-transparency timing and issuer clues
// needed to distinguish an automated renewal cadence from an ad-hoc change.
type CTObservation struct {
	ID             int64      `json:"id,omitempty"`
	IssuerName     string     `json:"issuer_name,omitempty"`
	SerialNumber   string     `json:"serial_number,omitempty"`
	SHA256         string     `json:"sha256,omitempty"`
	NotBefore      *time.Time `json:"not_before,omitempty"`
	NotAfter       *time.Time `json:"not_after,omitempty"`
	EntryTimestamp *time.Time `json:"entry_timestamp,omitempty"`
	Names          []string   `json:"names,omitempty"`
	Source         string     `json:"source,omitempty"`
}

// SCTObservation is a Signed Certificate Timestamp presented on the TLS
// handshake. It is a direct measurement that the served leaf was submitted to
// a CT log; it is not an independent issuance census the way crt.sh is.
type SCTObservation struct {
	Version      int        `json:"version,omitempty"`
	LogID        string     `json:"log_id,omitempty"`
	LogURL       string     `json:"log_url,omitempty"`
	Operator     string     `json:"operator,omitempty"`
	LogState     string     `json:"log_state,omitempty"`
	Qualified    bool       `json:"qualified,omitempty"`
	ChromeListed bool       `json:"chrome_listed,omitempty"`
	AppleListed  bool       `json:"apple_listed,omitempty"`
	TimestampMS  uint64     `json:"timestamp_ms,omitempty"`
	Timestamp    *time.Time `json:"timestamp,omitempty"`
	Extensions   []byte     `json:"-"`
	Inclusion    string     `json:"inclusion,omitempty"`
	LeafIndex    uint64     `json:"leaf_index,omitempty"`
	TreeSize     uint64     `json:"tree_size,omitempty"`
}

// RDAPNameRecord is the public registration record for the queried name.
type RDAPNameRecord struct {
	Handle        string     `json:"handle,omitempty"`
	LDHName       string     `json:"ldh_name,omitempty"`
	Status        []string   `json:"status,omitempty"`
	Registrar     string     `json:"registrar,omitempty"`
	RegistrarIANA string     `json:"registrar_iana,omitempty"`
	Registrant    string     `json:"registrant,omitempty"`
	Nameservers   []string   `json:"nameservers,omitempty"`
	RegisteredAt  *time.Time `json:"registered_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	Source        string     `json:"source,omitempty"`
}

// IPDirectoryRecord is the public numbering-authority and routing identity of
// one answering address. ASN/netname/org are independent of the TLS leaf.
type IPDirectoryRecord struct {
	IPAddress       string   `json:"ip_address"`
	ASN             int      `json:"asn,omitempty"`
	ASNName         string   `json:"asn_name,omitempty"`
	Prefix          string   `json:"prefix,omitempty"`
	Registry        string   `json:"registry,omitempty"`
	Country         string   `json:"country,omitempty"`
	NetName         string   `json:"net_name,omitempty"`
	OrgName         string   `json:"org_name,omitempty"`
	Handle          string   `json:"handle,omitempty"`
	CIDRs           []string `json:"cidrs,omitempty"`
	Source          string   `json:"source,omitempty"`
	Vendor          string   `json:"vendor,omitempty"`
	ASNSources      []string `json:"asn_sources,omitempty"`
	ConflictingASNs []int    `json:"conflicting_asns,omitempty"`
	SourceAgreement string   `json:"source_agreement,omitempty"`
}

// DirectoryObservation retains RDAP and ASN lookups collected in one deep
// round. It never replaces the certificate-to-endpoint assignment.
type DirectoryObservation struct {
	CollectedAt time.Time           `json:"collected_at"`
	Domain      *RDAPNameRecord     `json:"domain,omitempty"`
	Endpoints   []IPDirectoryRecord `json:"endpoints,omitempty"`
	Status      string              `json:"status,omitempty"`
}

type HTTPFingerprint struct {
	IPAddress       string   `json:"ip_address,omitempty"`
	StatusCode      int      `json:"status_code,omitempty"`
	Server          string   `json:"server,omitempty"`
	Via             string   `json:"via,omitempty"`
	Cache           string   `json:"cache,omitempty"`
	ProviderSignals []string `json:"provider_signals,omitempty"`
	Redirect        string   `json:"redirect,omitempty"`
}

type DeepEvidence struct {
	CollectedAt    time.Time             `json:"collected_at"`
	Topology       *TopologySnapshot     `json:"topology,omitempty"`
	CAA            []CAARecord           `json:"caa,omitempty"`
	CT             []CTObservation       `json:"ct,omitempty"`
	SCTs           []SCTObservation      `json:"scts,omitempty"`
	HTTP           *HTTPFingerprint      `json:"http,omitempty"`
	Directory      *DirectoryObservation `json:"directory,omitempty"`
	EndpointProbes []EndpointProbe       `json:"endpoint_probes,omitempty"`
	Errors         []string              `json:"errors,omitempty"`
	Status         string                `json:"status"`
}

// MeasurementSnapshot deliberately retains unchanged deep rounds. This makes
// stability, persistence and edge-specific transitions measurable over time.
type MeasurementSnapshot struct {
	ID                       uint      `json:"id" gorm:"primaryKey"`
	Domain                   string    `json:"domain" gorm:"index;size:255"`
	ObservedAt               time.Time `json:"observed_at" gorm:"index"`
	Trigger                  string    `json:"trigger" gorm:"index;size:64"`
	CertificateFingerprint   string    `json:"certificate_fingerprint,omitempty" gorm:"index;size:64"`
	SPKIFingerprint          string    `json:"spki_fingerprint,omitempty" gorm:"size:64"`
	TopologyHash             string    `json:"topology_hash,omitempty" gorm:"index;size:64"`
	ResolverQuorum           int       `json:"resolver_quorum"`
	ResolverAgreement        float64   `json:"resolver_agreement"`
	EndpointCount            int       `json:"endpoint_count"`
	SuccessfulEndpointCount  int       `json:"successful_endpoint_count"`
	FingerprintCount         int       `json:"fingerprint_count"`
	TopologyJSON             string    `json:"topology_json,omitempty" gorm:"type:text"`
	EndpointFingerprintsJSON string    `json:"endpoint_fingerprints_json,omitempty" gorm:"type:text"`
	CAAJSON                  string    `json:"caa_json,omitempty" gorm:"type:text"`
	CTJSON                   string    `json:"ct_json,omitempty" gorm:"type:text"`
	SCTJSON                  string    `json:"sct_json,omitempty" gorm:"type:text"`
	HTTPJSON                 string    `json:"http_json,omitempty" gorm:"type:text"`
	DirectoryJSON            string    `json:"directory_json,omitempty" gorm:"type:text"`
	ErrorsJSON               string    `json:"errors_json,omitempty" gorm:"type:text"`
	CreatedAt                time.Time `json:"created_at"`
}

// WebhookPayload is sent to configured webhooks / used for alert callbacks.
type WebhookPayload struct {
	Type        string       `json:"type"` // certificate_expiring, certificate_changed, certificate_revoked, certificate_expired
	Domain      string       `json:"domain"`
	Certificate *Certificate `json:"certificate,omitempty"`
	Message     string       `json:"message"`
	Milestone   string       `json:"milestone,omitempty"`
	Timestamp   time.Time    `json:"timestamp"`
}

// DomainView is a flattened, API-friendly view of a domain's status.
type DomainView struct {
	Domain                string     `json:"domain"`
	TrancoRank            int        `json:"tranco_rank"`
	LocalListMember       bool       `json:"local_list_member"`
	Status                string     `json:"status"`
	RevocationStatus      string     `json:"revocation_status"`
	CurrentFingerprint    string     `json:"current_fingerprint"`
	Issuer                string     `json:"issuer,omitempty"`
	NotAfter              *time.Time `json:"not_after,omitempty"`
	DaysUntilExpiry       int        `json:"days_until_expiry"`
	ExpirationStatus      string     `json:"expiration_status"`
	LastScannedAt         time.Time  `json:"last_scanned_at"`
	NextScanAt            time.Time  `json:"next_scan_at"`
	LastChangedAt         *time.Time `json:"last_changed_at,omitempty"`
	ChangeCount           int        `json:"change_count"`
	ScanCount             int        `json:"scan_count"`
	ARIStatus             string     `json:"ari_status,omitempty"`
	ARIWindowStart        *time.Time `json:"ari_window_start,omitempty"`
	ARIWindowEnd          *time.Time `json:"ari_window_end,omitempty"`
	ARIEmergency          bool       `json:"ari_emergency"`
	EvidenceStatus        string     `json:"evidence_status"`
	EvidencePendingReason string     `json:"evidence_pending_reason,omitempty"`
}

// ScheduleEntry describes an upcoming adaptive scan.
type ScheduleEntry struct {
	Domain             string    `json:"domain"`
	NextScanAt         time.Time `json:"next_scan_at"`
	InSeconds          int64     `json:"in_seconds"`
	Reason             string    `json:"reason"`
	DaysUntilExpiry    int       `json:"days_until_expiry"`
	Priority           int       `json:"priority"`
	CurrentFingerprint string    `json:"current_fingerprint"`
}

// Anomaly is a flagged irregularity found during analysis.
type Anomaly struct {
	Domain                    string          `json:"domain"`
	Type                      string          `json:"type"` // revoked, expired_served, expired_observed, early_renewal, frequent_change, same_key, stale_after_change, residual, deployment_failure, unreachable, expiring_soon, ari_emergency
	Severity                  string          `json:"severity"`
	Description               string          `json:"description"`
	Reason                    string          `json:"reason"`
	Evidence                  []string        `json:"evidence,omitempty"`
	CauseClassification       string          `json:"cause_classification"` // confirmed, inferred, unknown (mutually exclusive)
	ConfirmedReason           string          `json:"confirmed_reason"`
	InferredReason            string          `json:"inferred_reason"`
	ConfirmedEvidence         []string        `json:"confirmed_evidence"`
	InferredEvidence          []string        `json:"inferred_evidence"`
	EvidenceScope             string          `json:"evidence_scope"`
	EvidenceStatus            string          `json:"evidence_status"`
	EvidencePendingReason     string          `json:"evidence_pending_reason,omitempty"`
	Fingerprint               string          `json:"fingerprint,omitempty"`
	OccurrenceCount           int             `json:"occurrence_count"`
	MonitoringCount           int             `json:"monitoring_count"`
	SuccessfulMonitoringCount int             `json:"successful_monitoring_count"`
	FailedMonitoringCount     int             `json:"failed_monitoring_count"`
	FirstObservedAt           *time.Time      `json:"first_observed_at,omitempty"`
	LastObservedAt            *time.Time      `json:"last_observed_at,omitempty"`
	DetectedAt                time.Time       `json:"detected_at"`
	Diagnosis                 *CauseDiagnosis `json:"diagnosis,omitempty"`
	// FindingClass is how the diagnosis treats this row in the issue register:
	// a real incident, an expected deployment property, or not enough evidence.
	FindingClass string `json:"finding_class,omitempty"`
}

// CauseHypothesis is a ranked mechanism explanation. Scores are comparative
// support from retained measurements, not a claim that private operator intent
// was directly observed.
type CauseHypothesis struct {
	Code           string   `json:"code"`
	Label          string   `json:"label"`
	Score          float64  `json:"score"`
	Confidence     string   `json:"confidence"`
	Rationale      string   `json:"rationale"`
	Evidence       []string `json:"evidence,omitempty"`
	Contradictions []string `json:"contradictions,omitempty"`
}

type CauseDiagnosis struct {
	PrimaryCode          string            `json:"primary_code"`
	PrimaryLabel         string            `json:"primary_label"`
	Confidence           string            `json:"confidence"`
	Summary              string            `json:"summary"`
	EvidenceCompleteness float64           `json:"evidence_completeness"`
	Hypotheses           []CauseHypothesis `json:"hypotheses"`
	MeasurementPlan      []string          `json:"measurement_plan,omitempty"`
	MeasuredRounds       int               `json:"measured_rounds"`
	TransitionRounds     int               `json:"transition_rounds"`
	// ChurnShape is populated for certificate-churn findings. It separates
	// replacement in time from concurrent multi-certificate deployment, which
	// the raw change counter cannot do.
	ChurnShape *ChurnShape `json:"churn_shape,omitempty"`
	// Divergence is populated for multi-endpoint certificate findings. It
	// separates an intentional multi-CDN or dual-certificate arrangement from a
	// genuinely inconsistent deployment.
	Divergence *EndpointDivergence `json:"endpoint_divergence,omitempty"`
	// Provenance reports how much of the underlying evidence was produced by the
	// current detection rules rather than by a superseded generation.
	Provenance *EvidenceProvenance `json:"provenance,omitempty"`
	// Corroboration reports which independent evidence channels were actually
	// available. Confidence is capped by this, not by the volume of samples.
	Corroboration *EvidenceCorroboration `json:"corroboration,omitempty"`
	// BenignExplanation is set when the discriminating evidence shows the
	// finding is an expected property of the deployment rather than a defect.
	BenignExplanation string `json:"benign_explanation,omitempty"`
	// EvidenceCase is the auditable round-by-round record behind a causal
	// interpretation. It is intentionally separate from the ranked hypotheses:
	// a score can rank explanations, while this case records what was observed,
	// what is missing, and what would falsify the reading.
	EvidenceCase *EvidenceCase `json:"evidence_case,omitempty"`
	// Investigation is the operator-facing case file: the measured problem, the
	// evidence that supports it, and the inferred cause. It is derived from the
	// same measurements as the ranked hypotheses, but is written so a reader can
	// see problem, evidence and cause without decoding scoring internals.
	Investigation *Investigation `json:"investigation,omitempty"`
	// CauseStatus is established when same-endpoint replacement plus issuance
	// remaining-life name the process; inferred when those fields are present
	// but endpoint identity is missing; unestablished when neither holds.
	CauseStatus string `json:"cause_status,omitempty"`
}

// Finding classes for the issue register.
const (
	FindingIncident     = "incident"
	FindingExpected     = "expected"
	FindingInsufficient = "insufficient"
)

// Investigation is the operator-facing case file for one finding. For the
// three issue-register types that still need a proof (certificate diversity,
// frequent change, stale after topology change) Proof is the numbered
// measurement chain and Inference is the reversible operational reading.
type Investigation struct {
	FindingClass    string                  `json:"finding_class"`
	Problem         string                  `json:"problem"`
	WhyProblem      string                  `json:"why_this_is_a_problem,omitempty"`
	Cause           string                  `json:"cause"`
	CauseLabel      string                  `json:"cause_label"`
	CauseCode       string                  `json:"cause_code,omitempty"`
	CauseStatus     string                  `json:"cause_status,omitempty"` // established, inferred, or unestablished
	Confidence      string                  `json:"confidence"`
	WhyThisCause    []string                `json:"why_this_cause,omitempty"`
	RuledOut        []InvestigationRuledOut `json:"ruled_out,omitempty"`
	Facts           []string                `json:"facts,omitempty"`
	MissingEvidence []string                `json:"missing_evidence,omitempty"`
	Reversal        []string                `json:"reversal_conditions,omitempty"`
	// ProofKind is proven when every retained step is a direct measurement,
	// inferred when the operational reading still needs a missing comparison,
	// and mixed when some steps are proven and the mechanism is inferred.
	ProofKind      string                   `json:"proof_kind,omitempty"`
	Proof          []InvestigationProofStep `json:"proof,omitempty"`
	Inference      []InvestigationProofStep `json:"inference,omitempty"`
	ProviderGroups []ProviderExhibit        `json:"provider_groups,omitempty"`
	ChangeSequence []ChangeExhibit          `json:"change_sequence,omitempty"`
	Certificates   []CertificateExhibit     `json:"certificates,omitempty"`
	CDN            *CDNEvidence             `json:"cdn,omitempty"`
}

// InvestigationProofStep is one numbered claim in the operator-facing proof.
// Claim is a single assertion; Evidence is the retained measurements that
// prove or support it, listed immediately after. Kind is proven for a direct
// measurement and inferred for a best-supported reading that a later round
// can still overturn. Basis is how the measurements were taken, not the proof.
type InvestigationProofStep struct {
	Kind     string   `json:"kind"` // proven or inferred
	Label    string   `json:"label"`
	Claim    string   `json:"claim"`
	Evidence []string `json:"evidence,omitempty"`
	Basis    string   `json:"basis,omitempty"`
}

type InvestigationRuledOut struct {
	Label  string `json:"label"`
	Reason string `json:"reason"`
}

// ProviderExhibit is one provider-network allocation from the latest endpoint
// survey, with every answering address and the certificate it served.
type ProviderExhibit struct {
	Group     string            `json:"group"`
	Vendor    string            `json:"vendor,omitempty"`
	Conflict  bool              `json:"conflict"`
	LeafCount int               `json:"leaf_count"`
	Endpoints []EndpointExhibit `json:"endpoints"`
}

type EndpointExhibit struct {
	IPAddress       string `json:"ip_address"`
	ActiveDNS       bool   `json:"active_dns"`
	Success         bool   `json:"success"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	SPKIFingerprint string `json:"spki_fingerprint,omitempty"`
	IssuerCN        string `json:"issuer_cn,omitempty"`
	KeyAlgorithm    string `json:"key_algorithm,omitempty"`
	Error           string `json:"error,omitempty"`
}

// ChangeExhibit is one counted certificate-difference event, with the endpoint
// comparison that decides whether it was a replacement in time or sampling.
type ChangeExhibit struct {
	ObservedAt              time.Time `json:"observed_at"`
	PreviousFingerprint     string    `json:"previous_fingerprint,omitempty"`
	Fingerprint             string    `json:"fingerprint,omitempty"`
	PreviousIP              string    `json:"previous_ip,omitempty"`
	IPAddress               string    `json:"ip_address,omitempty"`
	Relation                string    `json:"endpoint_relation"`
	Coexisting              bool      `json:"coexisting"`
	ChangeClass             string    `json:"change_class,omitempty"`
	DaysUntilExpiry         int       `json:"days_until_expiry,omitempty"`
	PreviousSPKIFingerprint string    `json:"previous_spki_fingerprint,omitempty"`
	SPKIFingerprint         string    `json:"spki_fingerprint,omitempty"`
}

type CertificateExhibit struct {
	Fingerprint     string     `json:"fingerprint"`
	SPKIFingerprint string     `json:"spki_fingerprint,omitempty"`
	SerialNumber    string     `json:"serial_number,omitempty"`
	IssuerCN        string     `json:"issuer_cn,omitempty"`
	CommonName      string     `json:"common_name,omitempty"`
	SANs            []string   `json:"sans,omitempty"`
	KeyAlgorithm    string     `json:"key_algorithm,omitempty"`
	ValidityDays    int        `json:"validity_days,omitempty"`
	NotBefore       *time.Time `json:"not_before,omitempty"`
	NotAfter        *time.Time `json:"not_after,omitempty"`
}

// EvidenceCase is a bounded, source-grounded evidence chain for one domain and
// finding type. It contains only retained measurements and never implies full
// global edge coverage.
type EvidenceCase struct {
	Domain             string          `json:"domain"`
	AnomalyType        string          `json:"anomaly_type"`
	Status             string          `json:"status"`
	GeneratedAt        time.Time       `json:"generated_at"`
	ConfidenceCeiling  string          `json:"confidence_ceiling"`
	Rounds             []EvidenceRound `json:"rounds"`
	SupportingEvidence []string        `json:"supporting_evidence"`
	Contradictions     []string        `json:"contradictions"`
	MissingEvidence    []string        `json:"missing_evidence"`
	ReversalConditions []string        `json:"reversal_conditions"`
}

// EvidenceRound preserves the DNS view and endpoint results for one active
// measurement. ActiveDNS is false when an address was probed only as a
// historical/retired candidate and was not in that round's consensus answer.
type EvidenceRound struct {
	ObservedAt        time.Time          `json:"observed_at"`
	Trigger           string             `json:"trigger,omitempty"`
	ResolverQuorum    int                `json:"resolver_quorum"`
	ResolverAgreement float64            `json:"resolver_agreement"`
	EndpointCoverage  float64            `json:"endpoint_coverage"`
	ConsensusIPs      []string           `json:"consensus_ips,omitempty"`
	TopologyChanged   bool               `json:"topology_changed"`
	Endpoints         []EvidenceEndpoint `json:"endpoints"`
}

type EvidenceEndpoint struct {
	IPAddress       string `json:"ip_address"`
	ProviderGroup   string `json:"provider_group,omitempty"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	SPKIFingerprint string `json:"spki_fingerprint,omitempty"`
	IssuerCN        string `json:"issuer_cn,omitempty"`
	KeyAlgorithm    string `json:"key_algorithm,omitempty"`
	SANsHash        string `json:"sans_hash,omitempty"`
	Success         bool   `json:"success"`
	ActiveDNS       bool   `json:"active_dns"`
	Error           string `json:"error,omitempty"`
}

// ChurnShape describes the *shape* of a certificate-change sequence.
//
// A renewal sequence is monotone: once a leaf is replaced it never comes back.
// A load-balanced pool of concurrently deployed certificates produces the
// opposite signature — the same leaves recur, often alternating — because each
// scan samples whichever server answered, not a new point in time. Counting
// "changes" without this test conflates the two, and every downstream signal
// derived from consecutive pairs (same-key fraction, cadence, issuer churn)
// inherits the error.
type ChurnShape struct {
	ChangeEvents   int `json:"change_events"`
	DistinctLeaves int `json:"distinct_leaves"`
	DistinctSPKIs  int `json:"distinct_spkis"`
	// RevisitEvents counts changes that landed on a leaf already seen earlier in
	// the sequence. Renewal cannot revisit a retired certificate.
	RevisitEvents int     `json:"revisit_events"`
	RevisitRatio  float64 `json:"revisit_ratio"`
	// AlternationEvents counts A->B->A patterns, the signature of two endpoints
	// being sampled in turn.
	AlternationEvents int `json:"alternation_events"`
	// CoexistenceProofs counts change rows whose own endpoint survey observed the
	// predecessor and the successor in the same round. This is direct evidence,
	// not an inference.
	CoexistenceProofs int `json:"coexistence_proofs"`
	// SameEndpointChanges counts changes where the address that served the new
	// leaf is the address that served the previous one. Only these can establish
	// replacement in time.
	SameEndpointChanges    int `json:"same_endpoint_changes"`
	CrossEndpointChanges   int `json:"cross_endpoint_changes"`
	UnknownEndpointChanges int `json:"unknown_endpoint_changes"`
	// EffectiveReplacements is a lower bound on real replacements: visiting N
	// distinct leaves requires at least N-1 of them.
	EffectiveReplacements int     `json:"effective_replacements"`
	MeanIntervalHours     float64 `json:"mean_interval_hours"`
	CadenceRegularity     float64 `json:"cadence_regularity"`
	MedianValidityDays    int     `json:"median_validity_days"`
	ObservedSpanDays      float64 `json:"observed_span_days"`
	// ReplacementsPerValidityPeriod normalizes churn by certificate lifetime. A
	// 90-day certificate replaced every 60 days is not frequent change.
	ReplacementsPerValidityPeriod float64 `json:"replacements_per_validity_period"`
	// Remaining life and issuance dates are what separate a pre-issued rolling
	// pipeline from issuing a new certificate at replacement time. A different
	// public key is the default output of new issuance, not a cause.
	MedianRemainingDays   int     `json:"median_remaining_days"`
	RemainingSpreadDays   float64 `json:"remaining_spread_days"`
	MedianIssuanceAgeDays int     `json:"median_issuance_age_days"`
	DistinctIssuanceDays  int     `json:"distinct_issuance_days"`
	IssuanceCadenceDays   float64 `json:"issuance_cadence_days"`
	SameIssuerFraction    float64 `json:"same_issuer_fraction"`
	SameNameFraction      float64 `json:"same_name_fraction"`
	IssuanceMonotone      bool    `json:"issuance_monotone"`
	// RecoveredEndpointChanges counts comparisons whose serving address was
	// filled in from a retained round snapshot rather than from the change row.
	RecoveredEndpointChanges int `json:"recovered_endpoint_changes,omitempty"`
	// Interpretation is the discriminating verdict.
	Interpretation string `json:"interpretation"`
}

// Churn interpretations.
const (
	ChurnTemporalReplacement = "temporal_replacement"
	ChurnSpatialMultiplexing = "spatial_multiplexing"
	ChurnMixed               = "mixed"
	ChurnUndetermined        = "undetermined"
)

// EndpointDivergence describes the *structure* of certificate diversity across
// the sampled endpoints of one domain.
//
// Mixed certificates are the normal steady state of a multi-CDN or dual
// certificate deployment. What separates that from a real inconsistency is not
// the presence of diversity but its structure: whether each certificate maps
// cleanly onto its own provider/network partition, whether every endpoint's
// certificate is functionally valid for the name, and whether the split is
// stable or is a replacement that failed to propagate.
type EndpointDivergence struct {
	EndpointsProbed   int `json:"endpoints_probed"`
	EndpointsAnswered int `json:"endpoints_answered"`
	DistinctLeaves    int `json:"distinct_leaves"`
	DistinctIssuers   int `json:"distinct_issuers"`
	DistinctKeyAlgos  int `json:"distinct_key_algorithms"`
	DistinctSANSets   int `json:"distinct_san_sets"`
	// NetworkGroups counts the distinct network partitions (IPv4 /16, IPv6 /32)
	// that answered. Different partitions are usually different providers.
	NetworkGroups int `json:"network_groups"`
	// CleanPartition is true when no single network partition served two
	// different leaves. A clean partition means each provider is internally
	// consistent and the diversity is a between-provider property.
	CleanPartition bool `json:"clean_partition"`
	// IntraGroupConflicts counts partitions that served more than one leaf.
	// Those cannot be explained by multi-CDN: it is one operator's own fleet
	// disagreeing with itself.
	IntraGroupConflicts int `json:"intra_group_conflicts"`
	// DualCertificateSplit is true when the leaves differ only by public-key
	// algorithm while covering the same names from the same issuer, which is a
	// deliberate RSA+ECDSA arrangement.
	DualCertificateSplit bool `json:"dual_certificate_split"`
	// FunctionallyEquivalent is true when every answering endpoint served a
	// certificate that is currently valid and covers the queried name.
	FunctionallyEquivalent bool `json:"functionally_equivalent"`
	// DefectiveEndpoints lists endpoints whose certificate is expired, not yet
	// valid, name-mismatched or fails local chain validation.
	DefectiveEndpoints []string `json:"defective_endpoints,omitempty"`
	// PredecessorEndpoints lists endpoints still serving the leaf that was
	// replaced elsewhere.
	PredecessorEndpoints []string `json:"predecessor_endpoints,omitempty"`
	// ResidueHours is how long the predecessor has remained after the
	// replacement was first observed.
	ResidueHours float64 `json:"residue_hours"`
	// StableRounds counts consecutive earlier rounds with the same
	// partition-to-certificate assignment, compared by network partition rather
	// than by exact address so that CDN address rotation does not reset it.
	StableRounds int `json:"stable_rounds"`
	// Strong-rollout gates are deliberately explicit. A non-zero predecessor
	// count alone is not enough: it may be a retired IP or a legitimate second
	// CDN. StrongEvidence is true only after all gates pass.
	ConsecutivePredecessorRounds int      `json:"consecutive_predecessor_rounds"`
	PredecessorSpanHours         float64  `json:"predecessor_span_hours"`
	ResolverConsistentRounds     int      `json:"resolver_consistent_rounds"`
	ActiveEndpointCoverage       float64  `json:"active_endpoint_coverage"`
	ActivePredecessorEndpoints   []string `json:"active_predecessor_endpoints,omitempty"`
	RetiredPredecessorEndpoints  []string `json:"retired_predecessor_endpoints,omitempty"`
	StrongEvidence               bool     `json:"strong_evidence"`
	MissingEvidence              []string `json:"missing_evidence,omitempty"`
	ReversalConditions           []string `json:"reversal_conditions,omitempty"`
	// CDN is the vendor reading from DNS control-plane records and published
	// CDN prefixes. Completeness decides whether the multi-CDN verdict may use
	// named vendors or must stay on the /16 and /32 partition.
	CDN *CDNEvidence `json:"cdn,omitempty"`
	// Verdict is the discriminating result.
	Verdict string `json:"verdict"`
}

// Endpoint divergence verdicts.
const (
	DivergenceIntentionalMultiCDN = "intentional_multi_cdn"
	DivergenceDualCertificate     = "intentional_dual_certificate"
	DivergenceStuckRollout        = "stuck_partial_rollout"
	DivergencePropagating         = "rollout_in_progress"
	DivergenceIntraFleet          = "intra_fleet_inconsistency"
	DivergenceDefectiveEndpoint   = "defective_endpoint_certificate"
	DivergenceUndetermined        = "insufficient_endpoint_coverage"
)

// EvidenceProvenance separates rows produced by the current detection rules
// from rows produced by a superseded generation.
type EvidenceProvenance struct {
	TotalEvents   int     `json:"total_events"`
	CurrentEvents int     `json:"current_rule_events"`
	LegacyEvents  int     `json:"legacy_rule_events"`
	CurrentShare  float64 `json:"current_rule_share"`
	// LegacyDominated is true when most of the supporting rows predate the
	// current rules and therefore cannot carry the current rules' guarantees.
	LegacyDominated bool `json:"legacy_dominated"`
}

// EvidenceCorroboration reports which independent channels were available.
// Confidence is a function of these, not of how many samples were taken.
type EvidenceCorroboration struct {
	CTCoverage float64 `json:"ct_coverage"`
	CTEntries  int     `json:"ct_entries"`
	// CTIssuanceEvents counts distinct certificates that Certificate
	// Transparency records as issued for this name inside the observation
	// window. It is the independent upper bound on how many replacements can
	// have happened.
	CTIssuanceEvents int `json:"ct_issuance_events"`
	// CTStatus is corroborated, contradicted or unavailable.
	CTStatus           string  `json:"ct_status"`
	CTNote             string  `json:"ct_note,omitempty"`
	SCTPresented       bool    `json:"sct_presented"`
	SCTCount           int     `json:"sct_count"`
	SCTLogCount        int     `json:"sct_log_count"`
	SCTQualifiedLogs   int     `json:"sct_qualified_logs"`
	SCTAppleLogs       int     `json:"sct_apple_logs"`
	SCTInclusionProofs int     `json:"sct_inclusion_proofs"`
	SCTNote            string  `json:"sct_note,omitempty"`
	CAACoverage        float64 `json:"caa_coverage"`
	CAAStatus          string  `json:"caa_status,omitempty"`
	CAANote            string  `json:"caa_note,omitempty"`
	HTTPCoverage       float64 `json:"http_coverage"`
	EndpointCoverage   float64 `json:"endpoint_coverage"`
	ResolverAgreement  float64 `json:"resolver_agreement"`
	DirectoryCoverage  float64 `json:"directory_coverage"`
	DirectoryStatus    string  `json:"directory_status,omitempty"`
	DirectoryNote      string  `json:"directory_note,omitempty"`
	NSCoverage         float64 `json:"ns_coverage"`
	NSRDAPAgreement    string  `json:"ns_rdap_agreement,omitempty"`
	DNSSECValidated    bool    `json:"dnssec_validated,omitempty"`
	DNSSECNote         string  `json:"dnssec_note,omitempty"`
	TimingNote         string  `json:"timing_note,omitempty"`
	// ConfidenceCeiling is the highest confidence the available corroboration
	// can support, regardless of how strongly a hypothesis scores.
	ConfidenceCeiling string `json:"confidence_ceiling"`
}

// CT corroboration states.
const (
	CTCorroborated = "corroborated"
	CTContradicted = "contradicted"
	CTUnavailable  = "unavailable"
)

// Directory corroboration states.
const (
	DirectoryIdentified  = "identified"
	DirectoryPartial     = "partial"
	DirectoryUnavailable = "unavailable"
)

const (
	SCTInclusionProven    = "proven"
	SCTInclusionMissing   = "missing"
	SCTInclusionUnchecked = "unchecked"
	SCTInclusionError     = "error"
)

const (
	CAAAuthorized   = "authorized"
	CAAUnauthorized = "unauthorized"
	CAAAbsent       = "absent"
	CAAUnknown      = "unknown"
)

// ScanQueue represents the current scanning queue state.
type ScanQueue struct {
	Pending   int `json:"pending"`
	Running   int `json:"running"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

// LabelCount is a labelled aggregate bucket for distribution charts.
type LabelCount struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
	Order int    `json:"order"`
}

// CadencePoint is one domain plotted as (days-to-expiry, hours-to-next-scan),
// used to visualise how scanning densifies near expiry.
type CadencePoint struct {
	Domain          string  `json:"domain"`
	DaysUntilExpiry float64 `json:"days_until_expiry"`
	NextScanHours   float64 `json:"next_scan_hours"`
}

// Patterns bundles population-level regularities for the analysis view.
type Patterns struct {
	TotalDeployed   int64          `json:"total_deployed"`
	Issuers         []LabelCount   `json:"issuers"`
	KeyTypes        []LabelCount   `json:"key_types"`
	ValidityBuckets []LabelCount   `json:"validity_buckets"`
	RenewalLeadTime []LabelCount   `json:"renewal_lead_time"`
	ARIWindows      []LabelCount   `json:"ari_windows"`
	Cadence         []CadencePoint `json:"cadence"`
}

// SystemStats holds system-wide statistics.
type SystemStats struct {
	TotalCertificates int64     `json:"total_certificates"`
	TotalDomains      int64     `json:"total_domains"`
	ActiveDomains     int64     `json:"active_domains"`
	TodayScans        int       `json:"today_scans"`
	QueueDepth        int       `json:"queue_depth"`
	DueNow            int64     `json:"due_now"`
	ExpiringCerts7d   int64     `json:"expiring_certs_7d"`
	ExpiringCerts30d  int64     `json:"expiring_certs_30d"`
	ExpiredCerts      int64     `json:"expired_certs"`
	RevokedCerts      int64     `json:"revoked_certs"`
	ChangedToday      int       `json:"changed_today"`
	Observations      int64     `json:"observations"`
	AverageScanTimeMs float64   `json:"average_scan_time_ms"`
	DatabaseSize      string    `json:"database_size"`
	Uptime            string    `json:"uptime"`
	StartTime         time.Time `json:"start_time"`
}

// HealthCheck represents system health status.
type HealthCheck struct {
	Status     string    `json:"status"`
	Database   string    `json:"database"`
	Scanner    string    `json:"scanner"`
	Scheduler  string    `json:"scheduler"`
	Tranco     string    `json:"tranco"`
	LastScanAt time.Time `json:"last_scan_at"`
	Errors     []string  `json:"errors,omitempty"`
}

// ---------------------------------------------------------------------------
// API response wrappers
// ---------------------------------------------------------------------------

type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

type Pagination struct {
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

type PaginatedResponse struct {
	Success    bool        `json:"success"`
	Data       interface{} `json:"data"`
	Pagination Pagination  `json:"pagination"`
}

// CertificateFilter holds filter options for certificate/domain queries.
type CertificateFilter struct {
	Domain       string
	Issuer       string
	Status       string
	Revocation   string
	ExpiringDays int
	Expired      bool
	Page         int
	PerPage      int
	SortBy       string
	SortOrder    string
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Database   DatabaseConfig   `mapstructure:"database"`
	Scanner    ScannerConfig    `mapstructure:"scanner"`
	Scheduler  SchedulerConfig  `mapstructure:"scheduler"`
	Tranco     TrancoConfig     `mapstructure:"tranco"`
	LocalLists LocalListsConfig `mapstructure:"local_lists"`
	Alerts     AlertsConfig     `mapstructure:"alerts"`
}

type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	CORS            bool          `mapstructure:"cors"`
	CORSOrigins     []string      `mapstructure:"cors_origins"`
	CORSMaxAge      time.Duration `mapstructure:"cors_max_age"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

type DatabaseConfig struct {
	Host               string        `mapstructure:"host"`
	Port               int           `mapstructure:"port"`
	User               string        `mapstructure:"user"`
	Password           string        `mapstructure:"password"`
	Database           string        `mapstructure:"database"`
	SSLMode            string        `mapstructure:"sslmode"`
	MaxOpenConnections int           `mapstructure:"max_open_connections"`
	MaxIdleConnections int           `mapstructure:"max_idle_connections"`
	ConnMaxLifetime    time.Duration `mapstructure:"conn_max_lifetime"`
}

type ScannerConfig struct {
	TLSPort                   int                 `mapstructure:"tls_port"`
	Timeout                   time.Duration       `mapstructure:"timeout"`
	Retries                   int                 `mapstructure:"retries"`
	RetryBackoffUnit          time.Duration       `mapstructure:"retry_backoff_unit"`
	Workers                   int                 `mapstructure:"workers"`
	RateLimit                 int                 `mapstructure:"rate_limit"`
	UserAgent                 string              `mapstructure:"user_agent"`
	HTTPIdleConnTimeout       time.Duration       `mapstructure:"http_idle_conn_timeout"`
	HTTPExpectContinueTimeout time.Duration       `mapstructure:"http_expect_continue_timeout"`
	CheckRevocation           bool                `mapstructure:"check_revocation"`
	CheckCRL                  bool                `mapstructure:"check_crl"`
	RevocationTimeout         time.Duration       `mapstructure:"revocation_timeout"`
	CRLCacheTTL               time.Duration       `mapstructure:"crl_cache_ttl"`
	CheckARI                  bool                `mapstructure:"check_ari"`
	ARITimeout                time.Duration       `mapstructure:"ari_timeout"`
	ARICacheDefaultTTL        time.Duration       `mapstructure:"ari_cache_default_ttl"`
	ARICacheMinimumTTL        time.Duration       `mapstructure:"ari_cache_minimum_ttl"`
	ARIProviders              []ARIProviderConfig `mapstructure:"ari_providers"`
	DNSResolvers              []string            `mapstructure:"dns_resolvers"`
	MaxEndpointSamples        int                 `mapstructure:"max_endpoint_samples"`
	EndpointProbeConcurrency  int                 `mapstructure:"endpoint_probe_concurrency"`
	CheckCAA                  bool                `mapstructure:"check_caa"`
	CheckCT                   bool                `mapstructure:"check_ct"`
	CTTimeout                 time.Duration       `mapstructure:"ct_timeout"`
	CTEndpoint                string              `mapstructure:"ct_endpoint"`
	CheckHTTPFingerprint      bool                `mapstructure:"check_http_fingerprint"`
	CheckRDAP                 bool                `mapstructure:"check_rdap"`
	RDAPTimeout               time.Duration       `mapstructure:"rdap_timeout"`
	RDAPEndpoint              string              `mapstructure:"rdap_endpoint"`
	CheckASN                  bool                `mapstructure:"check_asn"`
	CheckRIPEstat             bool                `mapstructure:"check_ripestat"`
	RIPEstatEndpoint          string              `mapstructure:"ripestat_endpoint"`
	CheckOfficialPrefixes     bool                `mapstructure:"check_official_prefixes"`
	CloudflareIPv4URL         string              `mapstructure:"cloudflare_ipv4_url"`
	CloudflareIPv6URL         string              `mapstructure:"cloudflare_ipv6_url"`
	FastlyPublicIPURL         string              `mapstructure:"fastly_public_ip_url"`
	CloudfrontIPURL           string              `mapstructure:"cloudfront_ip_url"`
	CheckChromeLogList        bool                `mapstructure:"check_chrome_log_list"`
	ChromeLogListURL          string              `mapstructure:"chrome_log_list_url"`
	CheckAppleLogList         bool                `mapstructure:"check_apple_log_list"`
	AppleLogListURL           string              `mapstructure:"apple_log_list_url"`
	AWSIPRangesURL            string              `mapstructure:"aws_ip_ranges_url"`
	BunnyEdgeListURL          string              `mapstructure:"bunny_edge_list_url"`
	CheckSCTInclusion         bool                `mapstructure:"check_sct_inclusion"`
	CheckCertSpotter          bool                `mapstructure:"check_certspotter"`
	CertSpotterEndpoint       string              `mapstructure:"certspotter_endpoint"`
}

// ARIProviderConfig identifies a CA's ACME directory using configured issuer
// metadata. Providers are configuration, never an embedded CA allowlist.
type ARIProviderConfig struct {
	Name                       string   `mapstructure:"name"`
	DirectoryURL               string   `mapstructure:"directory_url"`
	IssuerCommonNamePatterns   []string `mapstructure:"issuer_common_name_patterns"`
	IssuerOrganizationContains []string `mapstructure:"issuer_organization_contains"`
}

type SchedulerConfig struct {
	Enabled                bool          `mapstructure:"enabled"`
	TickInterval           time.Duration `mapstructure:"tick_interval"`
	Milestones             []int         `mapstructure:"milestones"`               // days before expiry
	PostExpiryChecks       []int         `mapstructure:"post_expiry_checks"`       // days after expiry
	BaselineInterval       time.Duration `mapstructure:"baseline_interval"`        // far-from-expiry cadence
	NearExpiryInterval     time.Duration `mapstructure:"near_expiry_interval"`     // <1 day out cadence
	MinGap                 time.Duration `mapstructure:"min_gap"`                  // never scan more often than this
	ARIPollInterval        time.Duration `mapstructure:"ari_poll_interval"`        // fallback poll cadence when ARI Retry-After is absent
	RevocationPollInterval time.Duration `mapstructure:"revocation_poll_interval"` // low-frequency deep revocation sweep
	MaxDailyScans          int           `mapstructure:"max_daily_scans"`
	ScanTimeout            time.Duration `mapstructure:"scan_timeout"`
	FailureBackoffUnit     time.Duration `mapstructure:"failure_backoff_unit"`
	FailureBackoffMax      time.Duration `mapstructure:"failure_backoff_max"`
	NearExpiryWindow       time.Duration `mapstructure:"near_expiry_window"`
	ARIChangeThreshold     time.Duration `mapstructure:"ari_change_threshold"`
	ARIPollDueTolerance    time.Duration `mapstructure:"ari_poll_due_tolerance"`
}

type TrancoConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	SourceURL        string        `mapstructure:"source_url"`
	MaxDomains       int           `mapstructure:"max_domains"` // must equal TrancoTopLimit
	FetchOnStart     bool          `mapstructure:"fetch_on_start"`
	RefreshInterval  time.Duration `mapstructure:"refresh_interval"`
	RequestTimeout   time.Duration `mapstructure:"request_timeout"`
	CacheTTL         time.Duration `mapstructure:"cache_ttl"`
	MaxResponseBytes int           `mapstructure:"max_response_bytes"`
	UserAgent        string        `mapstructure:"user_agent"`
}

// LocalListsConfig describes additional domain populations loaded from files.
// All configured sources are combined as a set; a successful refresh replaces
// the previous local-list membership atomically while preserving Tranco ranks.
type LocalListsConfig struct {
	Enabled         bool                    `mapstructure:"enabled"`
	FetchOnStart    bool                    `mapstructure:"fetch_on_start"`
	RefreshInterval time.Duration           `mapstructure:"refresh_interval"`
	Sources         []LocalListSourceConfig `mapstructure:"sources"`
}

type LocalListSourceConfig struct {
	Name       string `mapstructure:"name"`
	Path       string `mapstructure:"path"`
	Format     string `mapstructure:"format"`
	MaxDomains int    `mapstructure:"max_domains"`
}

type AlertsConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	EmailFrom      string `mapstructure:"email_from"`
	EmailTo        string `mapstructure:"email_to"`
	SMTPHost       string `mapstructure:"smtp_host"`
	SMTPPort       int    `mapstructure:"smtp_port"`
	EmailUser      string `mapstructure:"email_user"`
	EmailPassword  string `mapstructure:"email_password"`
	WebhookEnabled bool   `mapstructure:"webhook_enabled"`
	WebhookURL     string `mapstructure:"webhook_url"`
}

// Validate rejects incomplete configuration. It deliberately does not fill in
// operational values: all endpoints, ports, rates and schedules must be
// declared by the deployment configuration.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Server.Host) == "" {
		return fmt.Errorf("server.host is required")
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	if c.Server.ReadTimeout <= 0 || c.Server.WriteTimeout <= 0 || c.Server.IdleTimeout <= 0 || c.Server.ShutdownTimeout <= 0 {
		return fmt.Errorf("server read_timeout, write_timeout, idle_timeout, and shutdown_timeout must be positive")
	}
	if c.Server.CORS {
		if len(c.Server.CORSOrigins) == 0 || c.Server.CORSMaxAge <= 0 {
			return fmt.Errorf("server.cors_origins and server.cors_max_age are required when CORS is enabled")
		}
		for _, origin := range c.Server.CORSOrigins {
			parsed, err := url.Parse(strings.TrimSpace(origin))
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return fmt.Errorf("invalid CORS origin %q", origin)
			}
		}
	}

	if strings.TrimSpace(c.Database.Host) == "" || strings.TrimSpace(c.Database.User) == "" || strings.TrimSpace(c.Database.Password) == "" || strings.TrimSpace(c.Database.Database) == "" || strings.TrimSpace(c.Database.SSLMode) == "" {
		return fmt.Errorf("database host, user, password, database, and sslmode are required")
	}
	if c.Database.Port < 1 || c.Database.Port > 65535 {
		return fmt.Errorf("invalid database port: %d", c.Database.Port)
	}
	if c.Database.MaxOpenConnections < 1 || c.Database.MaxIdleConnections < 0 || c.Database.MaxIdleConnections > c.Database.MaxOpenConnections || c.Database.ConnMaxLifetime <= 0 {
		return fmt.Errorf("database pool configuration is invalid")
	}

	if c.Scanner.TLSPort < 1 || c.Scanner.TLSPort > 65535 || c.Scanner.Timeout <= 0 || c.Scanner.Retries < 0 || c.Scanner.RetryBackoffUnit <= 0 || c.Scanner.Workers < 1 || c.Scanner.RateLimit < 1 || strings.TrimSpace(c.Scanner.UserAgent) == "" || c.Scanner.HTTPIdleConnTimeout <= 0 || c.Scanner.HTTPExpectContinueTimeout <= 0 {
		return fmt.Errorf("scanner TLS, timeout, retry, worker, rate-limit, user-agent, and HTTP timeout configuration is required")
	}
	if c.Scanner.CheckCRL && !c.Scanner.CheckRevocation {
		return fmt.Errorf("scanner.check_crl requires scanner.check_revocation")
	}
	if c.Scanner.CheckRevocation && c.Scanner.RevocationTimeout <= 0 {
		return fmt.Errorf("scanner.revocation_timeout is required when revocation checking is enabled")
	}
	if c.Scanner.CheckCRL && c.Scanner.CRLCacheTTL <= 0 {
		return fmt.Errorf("scanner.crl_cache_ttl is required when CRL checking is enabled")
	}
	if c.Scanner.CheckARI {
		if c.Scanner.ARITimeout <= 0 || c.Scanner.ARICacheDefaultTTL <= 0 || c.Scanner.ARICacheMinimumTTL <= 0 || c.Scanner.ARICacheMinimumTTL > c.Scanner.ARICacheDefaultTTL {
			return fmt.Errorf("scanner ARI timeouts and cache TTLs are invalid")
		}
		if len(c.Scanner.ARIProviders) == 0 {
			return fmt.Errorf("scanner.ari_providers is required when ARI checking is enabled")
		}
		for _, provider := range c.Scanner.ARIProviders {
			if strings.TrimSpace(provider.Name) == "" || strings.TrimSpace(provider.DirectoryURL) == "" || (len(provider.IssuerCommonNamePatterns) == 0 && len(provider.IssuerOrganizationContains) == 0) {
				return fmt.Errorf("each ARI provider requires name, directory_url, and at least one issuer matcher")
			}
			parsed, err := url.Parse(strings.TrimSpace(provider.DirectoryURL))
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
				return fmt.Errorf("ARI provider %q has invalid directory_url", provider.Name)
			}
		}
	}
	if c.Scanner.MaxEndpointSamples < 0 || c.Scanner.EndpointProbeConcurrency < 0 {
		return fmt.Errorf("scanner endpoint sampling values must not be negative")
	}
	if c.Scanner.CheckCT && c.Scanner.CTTimeout <= 0 {
		return fmt.Errorf("scanner.ct_timeout is required when CT checking is enabled")
	}
	if c.Scanner.CTEndpoint != "" {
		parsed, err := url.Parse(strings.TrimSpace(c.Scanner.CTEndpoint))
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("scanner.ct_endpoint must be an absolute HTTPS URL")
		}
	}
	if c.Scanner.CheckRDAP && c.Scanner.RDAPTimeout <= 0 {
		return fmt.Errorf("scanner.rdap_timeout is required when RDAP checking is enabled")
	}
	if c.Scanner.RDAPEndpoint != "" {
		parsed, err := url.Parse(strings.TrimSpace(c.Scanner.RDAPEndpoint))
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("scanner.rdap_endpoint must be an absolute HTTPS URL")
		}
	}
	for _, item := range []struct {
		name  string
		value string
	}{
		{"ripestat_endpoint", c.Scanner.RIPEstatEndpoint},
		{"cloudflare_ipv4_url", c.Scanner.CloudflareIPv4URL},
		{"cloudflare_ipv6_url", c.Scanner.CloudflareIPv6URL},
		{"fastly_public_ip_url", c.Scanner.FastlyPublicIPURL},
		{"cloudfront_ip_url", c.Scanner.CloudfrontIPURL},
		{"chrome_log_list_url", c.Scanner.ChromeLogListURL},
		{"apple_log_list_url", c.Scanner.AppleLogListURL},
		{"aws_ip_ranges_url", c.Scanner.AWSIPRangesURL},
		{"bunny_edge_list_url", c.Scanner.BunnyEdgeListURL},
		{"certspotter_endpoint", c.Scanner.CertSpotterEndpoint},
	} {
		if strings.TrimSpace(item.value) == "" {
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(item.value))
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("scanner.%s must be an absolute HTTPS URL", item.name)
		}
	}
	for _, resolver := range c.Scanner.DNSResolvers {
		parsed, err := url.Parse(strings.TrimSpace(resolver))
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("scanner.dns_resolvers contains invalid HTTPS URL %q", resolver)
		}
	}

	if c.Scheduler.TickInterval <= 0 || len(c.Scheduler.Milestones) == 0 || len(c.Scheduler.PostExpiryChecks) == 0 || c.Scheduler.BaselineInterval <= 0 || c.Scheduler.NearExpiryInterval <= 0 || c.Scheduler.NearExpiryWindow <= 0 || c.Scheduler.MinGap <= 0 || c.Scheduler.ARIPollInterval <= 0 || c.Scheduler.RevocationPollInterval <= 0 || c.Scheduler.MaxDailyScans < 1 || c.Scheduler.ScanTimeout <= 0 || c.Scheduler.FailureBackoffUnit <= 0 || c.Scheduler.FailureBackoffMax < c.Scheduler.FailureBackoffUnit || c.Scheduler.ARIChangeThreshold <= 0 || c.Scheduler.ARIPollDueTolerance <= 0 {
		return fmt.Errorf("scheduler configuration is incomplete or invalid")
	}
	if c.Scheduler.ARIPollInterval <= 0 {
		return fmt.Errorf("scheduler.ari_poll_interval must be positive")
	}
	if c.Scheduler.ARIPollInterval < c.Scheduler.MinGap {
		return fmt.Errorf("scheduler.ari_poll_interval must not be shorter than scheduler.min_gap")
	}
	if c.Scheduler.RevocationPollInterval < c.Scheduler.MinGap {
		return fmt.Errorf("scheduler.revocation_poll_interval must not be shorter than scheduler.min_gap")
	}
	for _, days := range append(append([]int{}, c.Scheduler.Milestones...), c.Scheduler.PostExpiryChecks...) {
		if days < 0 {
			return fmt.Errorf("scheduler milestone values must not be negative")
		}
	}

	if c.Tranco.Enabled {
		if strings.TrimSpace(c.Tranco.SourceURL) == "" || c.Tranco.MaxDomains != TrancoTopLimit || c.Tranco.RefreshInterval <= 0 || c.Tranco.RequestTimeout <= 0 || c.Tranco.CacheTTL <= 0 || c.Tranco.MaxResponseBytes < 1 || strings.TrimSpace(c.Tranco.UserAgent) == "" {
			return fmt.Errorf("tranco configuration is incomplete")
		}
		parsed, err := url.Parse(strings.TrimSpace(c.Tranco.SourceURL))
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("tranco.source_url must be an absolute HTTPS URL")
		}
	}
	if c.LocalLists.Enabled {
		if len(c.LocalLists.Sources) == 0 || c.LocalLists.RefreshInterval <= 0 {
			return fmt.Errorf("local_lists configuration is incomplete")
		}
		seenNames := make(map[string]struct{}, len(c.LocalLists.Sources))
		for i, source := range c.LocalLists.Sources {
			name := strings.TrimSpace(source.Name)
			if name == "" {
				return fmt.Errorf("local_lists.sources[%d].name is required", i)
			}
			if _, exists := seenNames[strings.ToLower(name)]; exists {
				return fmt.Errorf("local_lists source name %q is duplicated", name)
			}
			seenNames[strings.ToLower(name)] = struct{}{}
			if strings.TrimSpace(source.Path) == "" {
				return fmt.Errorf("local_lists source %q path is required", name)
			}
			format := strings.ToLower(strings.TrimSpace(source.Format))
			if format != "" && format != "auto" && format != "lines" && format != "jsonl" {
				return fmt.Errorf("local_lists source %q has unsupported format %q", name, source.Format)
			}
			if source.MaxDomains < 0 {
				return fmt.Errorf("local_lists source %q max_domains must not be negative", name)
			}
		}
	}
	return nil
}

// DSN builds the PostgreSQL connection string for the given database name.
func (d *DatabaseConfig) DSN(dbname string) string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, dbname, d.SSLMode)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// FromX509Cert converts an x509.Certificate to our Certificate entity. The
// result is domain-independent (the domain lives in DomainCertificate).
func FromX509Cert(c *x509.Certificate, seenAt time.Time) *Certificate {
	sans := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	sansJSON, _ := json.Marshal(sans)

	keyAlg, pubKeyType, keySize := PublicKeyProfile(c)

	return &Certificate{
		Fingerprint:     Fingerprint(c),
		SPKIFingerprint: SPKIFingerprint(c),
		SerialNumber:    c.SerialNumber.Text(16),
		Issuer:          c.Issuer.String(),
		IssuerCN:        c.Issuer.CommonName,
		Subject:         c.Subject.String(),
		CommonName:      c.Subject.CommonName,
		NotBefore:       c.NotBefore,
		NotAfter:        c.NotAfter,
		SignatureAlgo:   c.SignatureAlgorithm.String(),
		KeyAlgorithm:    keyAlg,
		KeySize:         keySize,
		PublicKeyType:   pubKeyType,
		IsCA:            c.IsCA,
		SelfSigned:      c.Subject.String() == c.Issuer.String(),
		SANs:            string(sansJSON),
		ValidityDays:    int(c.NotAfter.Sub(c.NotBefore).Hours() / 24),
		RawCert:         base64.StdEncoding.EncodeToString(c.Raw),
		FirstSeenAt:     seenAt,
		LastSeenAt:      seenAt,
	}
}

// Fingerprint returns the SHA-256 fingerprint (hex) of a certificate.
func Fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}

// PublicKeyProfile reports the public-key algorithm, type and size. The
// endpoint survey needs the same derivation as the stored certificate so an
// RSA plus ECDSA pair can be recognized from probe data alone.
func PublicKeyProfile(c *x509.Certificate) (algorithm, keyType string, size int) {
	if c == nil || c.PublicKey == nil {
		return "Unknown", "Unknown", 0
	}
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", "Ed25519", 256
	default:
		name := c.PublicKeyAlgorithm.String()
		return name, name, 0
	}
}

// PublicKeySize is the key size alone, for callers that already know the
// algorithm.
func PublicKeySize(c *x509.Certificate) int {
	_, _, size := PublicKeyProfile(c)
	return size
}

// SANSetHash digests the sorted, case-normalized DNS name set. Endpoints whose
// certificates hash to the same value cover exactly the same names and are
// therefore interchangeable for the queried host, whatever else differs.
func SANSetHash(names []string) string {
	if len(names) == 0 {
		return ""
	}
	normalized := make([]string, 0, len(names))
	for _, name := range names {
		trimmed := strings.ToLower(strings.TrimSpace(name))
		if trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	if len(normalized) == 0 {
		return ""
	}
	sort.Strings(normalized)
	h := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
	return hex.EncodeToString(h[:])
}

// ProviderGroup maps an address to the allocation that usually belongs to one
// operator or CDN: an IPv4 /16 or an IPv6 /32.
//
// Comparing endpoint surveys by exact address is why a permanently stable CDN
// arrangement never looked stable: edge addresses rotate on every query, so the
// map keys changed every round and the stability test could never accumulate.
// The provider allocation is stable exactly where the individual address is not.
func ProviderGroup(address string) string {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return "unparsed:" + strings.TrimSpace(address)
	}
	if v4 := ip.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(16, 32)), Mask: net.CIDRMask(16, 32)}).String()
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(32, 128)), Mask: net.CIDRMask(32, 128)}).String()
}

// ProviderAssignmentSignature reduces an address-to-certificate map to
// "which provider network served which certificates", discarding the individual
// addresses that a CDN rotates.
func ProviderAssignmentSignature(assignment map[string]string) string {
	byGroup := make(map[string]map[string]struct{})
	for address, fingerprint := range assignment {
		if fingerprint == "" {
			continue
		}
		group := ProviderGroup(address)
		if byGroup[group] == nil {
			byGroup[group] = make(map[string]struct{})
		}
		byGroup[group][fingerprint] = struct{}{}
	}
	parts := make([]string, 0, len(byGroup))
	for group, fingerprints := range byGroup {
		values := make([]string, 0, len(fingerprints))
		for fingerprint := range fingerprints {
			values = append(values, fingerprint)
		}
		sort.Strings(values)
		parts = append(parts, group+"=>"+strings.Join(values, ","))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// SPKIFingerprint identifies the public key independently of the certificate
// wrapper. It lets lifecycle analysis distinguish a same-key reissue from an
// observed key rotation without claiming to know the operator's intent.
func SPKIFingerprint(c *x509.Certificate) string {
	if c == nil || c.PublicKey == nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// SPKIFingerprintFromRaw is used when an older database row has a raw DER
// certificate but predates the persisted SPKI fingerprint column.
func SPKIFingerprintFromRaw(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return ""
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	return SPKIFingerprint(cert)
}

// ChainEntry is a compact description of one certificate in a chain.
type ChainEntry struct {
	CommonName string    `json:"common_name"`
	IssuerCN   string    `json:"issuer_cn"`
	NotAfter   time.Time `json:"not_after"`
	IsCA       bool      `json:"is_ca"`
}

// BuildChainJSON serializes the presented chain (leaf→root) compactly for storage.
func BuildChainJSON(chain []*x509.Certificate) string {
	entries := make([]ChainEntry, 0, len(chain))
	for _, c := range chain {
		cn := c.Subject.CommonName
		if cn == "" {
			cn = c.Subject.String()
		}
		entries = append(entries, ChainEntry{
			CommonName: cn,
			IssuerCN:   c.Issuer.CommonName,
			NotAfter:   c.NotAfter,
			IsCA:       c.IsCA,
		})
	}
	b, _ := json.Marshal(entries)
	return string(b)
}

// ParseSANs parses the JSON SANs string back to a slice.
func ParseSANs(sansJSON string) []string {
	var sans []string
	if sansJSON != "" {
		_ = json.Unmarshal([]byte(sansJSON), &sans)
	}
	return sans
}

// DaysUntil returns whole days from now until t (negative if past). It floors,
// so any instant past t yields a negative value (a cert that expired an hour
// ago is -1 day, never 0).
func DaysUntil(t, now time.Time) int {
	return int(math.Floor(t.Sub(now).Hours() / 24))
}

// ExpirationStatus returns a status string for a certificate given "now".
func ExpirationStatus(notAfter, now time.Time) string {
	days := DaysUntil(notAfter, now)
	switch {
	case days < 0:
		return "expired"
	case days == 0:
		return "expires_today"
	case days <= 3:
		return "critical"
	case days <= 7:
		return "warning"
	case days <= 30:
		return "attention"
	default:
		return "valid"
	}
}

// MilestoneLabel builds a stable milestone key, e.g. "7d_before_expiry".
func MilestoneLabel(days int, beforeExpiry bool) string {
	if beforeExpiry {
		return fmt.Sprintf("%dd_before_expiry", days)
	}
	return fmt.Sprintf("%dd_after_expiry", days)
}

// ARIWindowFraction returns where the ARI suggestedWindow start falls within the
// certificate's lifetime (NotBefore=0.0, NotAfter=1.0). Normal ACME behaviour
// places it around 2/3 (the start of the final third of the lifetime).
func ARIWindowFraction(notBefore, notAfter, windowStart time.Time) float64 {
	life := notAfter.Sub(notBefore).Seconds()
	if life <= 0 {
		return 0
	}
	return windowStart.Sub(notBefore).Seconds() / life
}

// ARIIsEmergency reports whether the CA has pulled the renewal window forward to
// "now" markedly earlier than the usual last-third schedule — the signature of
// an emergency mass-revocation event. It is emergency when the CA recommends
// renewing immediately (window already open) yet the window start sits well
// before the normal ~2/3 point of the lifetime. A window that has simply arrived
// at its normal late position is NOT an emergency.
func ARIIsEmergency(now, notBefore, notAfter, windowStart time.Time) bool {
	if windowStart.After(now) {
		return false // window not open yet — nothing urgent
	}
	return ARIWindowFraction(notBefore, notAfter, windowStart) < 0.5
}

// GetDomain extracts a bare hostname from a URL or returns the input cleaned.
func GetDomain(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "www.")
	if idx := strings.Index(input, "/"); idx > 0 {
		input = input[:idx]
	}
	return input
}

// IsPrivateIP reports whether the host is a private / loopback IP.
func IsPrivateIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// IsPublicIP reports whether an address is suitable for public DNS/topology
// evidence. Besides private/link-local addresses, exclude documentation,
// benchmark, shared-address and other reserved ranges that can be used by a
// transparent proxy or test harness.
func IsPublicIP(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil || !ip.IsGlobalUnicast() || IsPrivateIP(ip.String()) {
		return false
	}
	for _, cidr := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"2001:db8::/32", "2001:10::/28",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return false
		}
	}
	return true
}

// GetTLSVersionName converts a tls.Version value to a string.
func GetTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionSSL30: //nolint:staticcheck
		return "SSL 3.0"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}

// GetCipherSuiteName returns a readable cipher suite name.
func GetCipherSuiteName(id uint16) string {
	if name := tls.CipherSuiteName(id); name != "" {
		return name
	}
	return fmt.Sprintf("0x%04X", id)
}
