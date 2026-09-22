// ---- Core entities (mirror backend models) ----

export interface Certificate {
  id: number;
  fingerprint: string;
  spki_fingerprint?: string;
  serial_number: string;
  issuer: string;
  issuer_cn: string;
  subject: string;
  common_name: string;
  not_before: string;
  not_after: string;
  signature_algorithm: string;
  key_algorithm: string;
  key_size: number;
  public_key_type: string;
  is_ca: boolean;
  self_signed: boolean;
  sans: string;
  validity_days: number;
  chain?: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface ChainEntry {
  common_name: string;
  issuer_cn: string;
  not_after: string;
  is_ca: boolean;
}

export interface DomainCertificate {
  id: number;
  domain: string;
  tranco_rank: number;
  local_list_member?: boolean;
  current_certificate_id: number;
  current_fingerprint: string;
  status: string;
  revocation_status: string;
  revocation_checked_via: string;
  revoked_at?: string;
  revocation_reason?: string;
  ocsp_checked_at?: string;
  first_seen_at: string;
  last_scanned_at: string;
  last_changed_at?: string;
  last_days_until_expiry: number;
  next_scan_at: string;
  priority: number;
  scan_count: number;
  change_count: number;
  consecutive_failures: number;
  last_error?: string;
  last_failure_class?: string;
  resolved_ips?: string;
  consensus_ips?: string;
  topology_cnames?: string;
  topology_hash?: string;
  topology_resolver_quorum?: number;
  topology_resolver_agreement?: number;
  previous_resolved_ips?: string;
  last_dns_observed_at?: string;
  endpoint_states?: string;
  endpoint_diversity_status?: string;
  endpoint_diversity_rounds?: number;
  last_endpoint_probe_at?: string;
  last_deep_measurement_at?: string;
  residual_fingerprint?: string;
  residual_revoked_at?: string;
  residual_first_seen_at?: string;
  residual_last_seen_at?: string;
  residual_next_check_at?: string;
  residual_observation_count?: number;
  ari_supported?: boolean;
  ari_status?: string;
  ari_window_start?: string;
  ari_window_end?: string;
  ari_explanation_url?: string;
  ari_checked_at?: string;
  ari_emergency?: boolean;
  ari_next_poll_at?: string;
  evidence_status?: string;
  evidence_pending_reason?: string;
  current_certificate?: Certificate;
}

export interface DomainView {
  domain: string;
  tranco_rank: number;
  local_list_member?: boolean;
  status: string;
  revocation_status: string;
  current_fingerprint: string;
  issuer?: string;
  not_after?: string;
  days_until_expiry: number;
  expiration_status: string;
  last_scanned_at: string;
  next_scan_at: string;
  last_changed_at?: string;
  change_count: number;
  scan_count: number;
  ari_status?: string;
  ari_window_start?: string;
  ari_window_end?: string;
  ari_emergency?: boolean;
  evidence_status?: string;
  evidence_pending_reason?: string;
}

export interface CertObservation {
  id: number;
  domain: string;
  certificate_id: number;
  fingerprint: string;
  observed_at: string;
  observation_type: string;
  milestone?: string;
  days_until_expiry: number;
  revocation_status?: string;
  previous_fingerprint?: string;
  previous_spki_fingerprint?: string;
  spki_fingerprint?: string;
  resolved_ips?: string;
  previous_resolved_ips?: string;
  endpoint_probes?: string;
  deep_evidence?: string;
  residual_duration_seconds?: number;
  tls_version?: string;
  cipher_suite?: string;
  scan_duration_ms: number;
  ari_window_start?: string;
  ari_window_end?: string;
  notes?: string;
  evidence_status?: string;
  evidence_pending_reason?: string;
}

export interface MeasurementSnapshot {
  id: number;
  domain: string;
  observed_at: string;
  trigger: string;
  certificate_fingerprint?: string;
  spki_fingerprint?: string;
  topology_hash?: string;
  resolver_quorum: number;
  resolver_agreement: number;
  endpoint_count: number;
  successful_endpoint_count: number;
  fingerprint_count: number;
  topology_json?: string;
  endpoint_fingerprints_json?: string;
  caa_json?: string;
  ct_json?: string;
  http_json?: string;
  errors_json?: string;
}

export interface ScheduleEntry {
  domain: string;
  next_scan_at: string;
  in_seconds: number;
  reason: string;
  days_until_expiry: number;
  priority: number;
  current_fingerprint: string;
}

export interface Anomaly {
  domain: string;
  type: string;
  severity: string;
  description: string;
  reason: string;
  evidence?: string[];
  cause_classification: 'confirmed' | 'inferred' | 'unknown' | string;
  confirmed_reason: string;
  inferred_reason: string;
  confirmed_evidence: string[];
  inferred_evidence: string[];
  evidence_scope?: string;
  evidence_status?: string;
  evidence_pending_reason?: string;
  fingerprint?: string;
  occurrence_count: number;
  monitoring_count: number;
  successful_monitoring_count: number;
  failed_monitoring_count: number;
  first_observed_at?: string;
  last_observed_at?: string;
  detected_at: string;
  diagnosis?: CauseDiagnosis;
  finding_class?: 'incident' | 'expected' | 'insufficient' | string;
}

export interface CauseHypothesis {
  code: string;
  label: string;
  score: number;
  confidence: string;
  rationale: string;
  evidence?: string[];
  contradictions?: string[];
}

export interface ChurnShape {
  change_events: number;
  distinct_leaves: number;
  distinct_spkis: number;
  revisit_events: number;
  revisit_ratio: number;
  alternation_events: number;
  coexistence_proofs: number;
  same_endpoint_changes: number;
  cross_endpoint_changes: number;
  unknown_endpoint_changes: number;
  effective_replacements: number;
  mean_interval_hours: number;
  cadence_regularity: number;
  median_validity_days: number;
  observed_span_days: number;
  replacements_per_validity_period: number;
  median_remaining_days?: number;
  remaining_spread_days?: number;
  median_issuance_age_days?: number;
  distinct_issuance_days?: number;
  issuance_cadence_days?: number;
  same_issuer_fraction?: number;
  same_name_fraction?: number;
  issuance_monotone?: boolean;
  recovered_endpoint_changes?: number;
  interpretation: string;
}
export interface EndpointDivergence {
  endpoints_probed: number;
  endpoints_answered: number;
  distinct_leaves: number;
  distinct_issuers: number;
  distinct_key_algorithms: number;
  distinct_san_sets: number;
  network_groups: number;
  clean_partition: boolean;
  intra_group_conflicts: number;
  dual_certificate_split: boolean;
  functionally_equivalent: boolean;
  defective_endpoints?: string[];
  predecessor_endpoints?: string[];
  residue_hours: number;
  stable_rounds: number;
  consecutive_predecessor_rounds: number;
  predecessor_span_hours: number;
  resolver_consistent_rounds: number;
  active_endpoint_coverage: number;
  active_predecessor_endpoints?: string[];
  retired_predecessor_endpoints?: string[];
  strong_evidence: boolean;
  missing_evidence?: string[];
  reversal_conditions?: string[];
  cdn?: CDNEvidence | null;
  verdict: string;
}

export interface CDNEvidence {
  completeness: string;
  method?: string;
  hostname_vendors?: string[];
  cname_vendors?: string[];
  https_vendors?: string[];
  http_vendors?: string[];
  endpoint_vendors?: Record<string, string>;
  distinct_vendors: number;
  identified_endpoints: number;
  unidentified_endpoints?: string[];
  vendor_conflicts: number;
  clean_vendor_split: boolean;
  sources?: string[];
  note?: string;
}
export interface EvidenceEndpoint {
  ip_address: string;
  provider_group?: string;
  fingerprint?: string;
  spki_fingerprint?: string;
  issuer_cn?: string;
  key_algorithm?: string;
  sans_hash?: string;
  success: boolean;
  active_dns: boolean;
  error?: string;
}
export interface EvidenceRound {
  observed_at: string;
  trigger?: string;
  resolver_quorum: number;
  resolver_agreement: number;
  endpoint_coverage: number;
  consensus_ips?: string[];
  topology_changed: boolean;
  endpoints: EvidenceEndpoint[];
}
export interface EvidenceCase {
  domain: string;
  anomaly_type: string;
  status: string;
  generated_at: string;
  confidence_ceiling: string;
  rounds: EvidenceRound[];
  supporting_evidence: string[];
  contradictions: string[];
  missing_evidence: string[];
  reversal_conditions: string[];
}
export interface EvidenceProvenance {
  total_events: number;
  current_rule_events: number;
  legacy_rule_events: number;
  current_rule_share: number;
  legacy_dominated: boolean;
}
export interface EvidenceCorroboration {
  ct_coverage: number;
  ct_entries: number;
  ct_issuance_events: number;
  ct_status: string;
  ct_note?: string;
  sct_presented?: boolean;
  sct_count?: number;
  sct_log_count?: number;
  sct_qualified_logs?: number;
  sct_apple_logs?: number;
  sct_inclusion_proofs?: number;
  sct_note?: string;
  caa_coverage: number;
  caa_status?: string;
  caa_note?: string;
  http_coverage: number;
  endpoint_coverage: number;
  resolver_agreement: number;
  directory_coverage?: number;
  directory_status?: string;
  directory_note?: string;
  ns_coverage?: number;
  ns_rdap_agreement?: string;
  dnssec_validated?: boolean;
  dnssec_note?: string;
  timing_note?: string;
  confidence_ceiling: string;
}
export interface CauseDiagnosis {
  primary_code: string;
  primary_label: string;
  confidence: string;
  summary: string;
  evidence_completeness: number;
  hypotheses?: CauseHypothesis[] | null;
  measurement_plan?: string[];
  measured_rounds: number;
  transition_rounds: number;
  churn_shape?: ChurnShape | null;
  endpoint_divergence?: EndpointDivergence | null;
  provenance?: EvidenceProvenance | null;
  corroboration?: EvidenceCorroboration | null;
  benign_explanation?: string;
  evidence_case?: EvidenceCase | null;
  investigation?: Investigation | null;
  cause_status?: string;
}

export interface InvestigationRuledOut {
  label: string;
  reason: string;
}

export interface InvestigationProofStep {
  kind: 'proven' | 'inferred' | string;
  label: string;
  claim: string;
  evidence?: string[];
  basis?: string;
}

export interface EndpointExhibit {
  ip_address: string;
  active_dns: boolean;
  success: boolean;
  fingerprint?: string;
  spki_fingerprint?: string;
  issuer_cn?: string;
  key_algorithm?: string;
  error?: string;
}

export interface ProviderExhibit {
  group: string;
  vendor?: string;
  conflict: boolean;
  leaf_count: number;
  endpoints: EndpointExhibit[];
}

export interface ChangeExhibit {
  observed_at: string;
  previous_fingerprint?: string;
  fingerprint?: string;
  previous_ip?: string;
  ip_address?: string;
  endpoint_relation: string;
  coexisting: boolean;
  change_class?: string;
  days_until_expiry?: number;
  previous_spki_fingerprint?: string;
  spki_fingerprint?: string;
}

export interface CertificateExhibit {
  fingerprint: string;
  spki_fingerprint?: string;
  serial_number?: string;
  issuer_cn?: string;
  common_name?: string;
  sans?: string[];
  key_algorithm?: string;
  validity_days?: number;
  not_before?: string;
  not_after?: string;
}

export interface Investigation {
  finding_class: 'incident' | 'expected' | 'insufficient' | string;
  problem: string;
  why_this_is_a_problem?: string;
  cause: string;
  cause_label: string;
  cause_code?: string;
  cause_status?: string;
  confidence: string;
  why_this_cause?: string[];
  ruled_out?: InvestigationRuledOut[];
  facts?: string[];
  missing_evidence?: string[];
  reversal_conditions?: string[];
  proof_kind?: 'proven' | 'mixed' | 'inferred' | 'unestablished' | string;
  proof?: InvestigationProofStep[];
  inference?: InvestigationProofStep[];
  provider_groups?: ProviderExhibit[];
  change_sequence?: ChangeExhibit[];
  certificates?: CertificateExhibit[];
  cdn?: CDNEvidence | null;
}


export interface EndpointProbe {
  ip_address: string;
  success: boolean;
  fingerprint?: string;
  spki_fingerprint?: string;
  issuer_cn?: string;
  common_name?: string;
  error?: string;
}

export interface LabelCount {
  label: string;
  count: number;
  order: number;
}

export interface CadencePoint {
  domain: string;
  days_until_expiry: number;
  next_scan_hours: number;
}

export interface Patterns {
  total_deployed: number;
  issuers: LabelCount[];
  key_types: LabelCount[];
  validity_buckets: LabelCount[];
  renewal_lead_time: LabelCount[];
  ari_windows: LabelCount[];
  cadence: CadencePoint[];
}

export interface ConnectionInfo {
  protocol: string;
  tls_version: string;
  cipher_suite: string;
  negotiated_protocol?: string;
  alpn?: string;
  connection_time_ms: number;
  ip_address?: string;
}

export interface ScanResult {
  domain: string;
  success: boolean;
  error?: string;
  certificate?: Certificate;
  chain?: Certificate[];
  connection_info?: ConnectionInfo;
  revocation_status: string;
  revocation_checked_via: string;
  evidence_status: string;
  evidence_pending_reason?: string;
  revoked_at?: string;
  revocation_reason?: string;
  failure_class?: string;
  scan_duration: number;
  scanned_at: string;
  resolved_ips?: string[];
  endpoint_probes?: EndpointProbe[];
  topology?: unknown;
  deep_evidence?: unknown;
  measurement_trigger?: string;
}

export interface CertificateAlert {
  id: number;
  name: string;
  interval_days: number;
  is_enabled: boolean;
  email_enabled: boolean;
  webhook_url?: string;
  created_at: string;
  updated_at: string;
}

export interface ScanQueue {
  pending: number;
  running: number;
  completed: number;
  failed: number;
}

export interface ScanJob {
  id: number;
  domain: string;
  reason: string;
  scheduled_at: string;
  started_at?: string;
  finished_at?: string;
  status: string;
  success: boolean;
  fingerprint?: string;
  revocation_status?: string;
  ari_status?: string;
  failure_class?: string;
  error?: string;
  scan_duration_ms: number;
}

export interface SystemStats {
  total_certificates: number;
  total_domains: number;
  active_domains: number;
  today_scans: number;
  queue_depth: number;
  due_now: number;
  expiring_certs_7d: number;
  expiring_certs_30d: number;
  expired_certs: number;
  revoked_certs: number;
  changed_today: number;
  observations: number;
  average_scan_time_ms: number;
  database_size: string;
  uptime: string;
  start_time: string;
}

export interface HealthCheck {
  status: string;
  database: string;
  scanner: string;
  scheduler: string;
  tranco: string;
  last_scan_at: string;
  errors?: string[];
}

export interface DailyStat {
  id: number;
  date: string;
  total_scans: number;
  successful_scans: number;
  failed_scans: number;
  changes_detected: number;
  revocations_detected: number;
  new_certs: number;
  milestone_scans: number;
  total_scan_ms: number;
  average_scan_ms: number;
}

export interface TrancoList {
  id: number;
  list_id: string;
  source: string;
  date: string;
  count: number;
  fetched_at: string;
}

export interface SchedulerStatus {
  enabled: boolean;
  paused?: boolean;
  queue_status?: ScanQueue;
  pending?: number;
  milestones?: number[];
}

export interface RuntimeConfig {
  server: { host: string; port: number; cors: boolean; cors_origins: string[] };
  database: { host: string; port: number; database: string; sslmode: string; max_open_connections: number; max_idle_connections: number; conn_max_lifetime: string };
  scanner: { tls_port: number; timeout: string; workers: number; rate_limit: number; check_revocation: boolean; check_crl: boolean; check_ari: boolean; dns_resolvers?: string[]; max_endpoint_samples?: number; endpoint_probe_concurrency?: number; check_caa?: boolean; check_ct?: boolean; ct_endpoint?: string; check_http_fingerprint?: boolean; check_rdap?: boolean; rdap_endpoint?: string; check_asn?: boolean; check_ripestat?: boolean; check_official_prefixes?: boolean; check_chrome_log_list?: boolean; check_apple_log_list?: boolean; check_sct_inclusion?: boolean; check_certspotter?: boolean; official_cdn_prefixes?: number; chrome_ct_logs?: number; apple_ct_logs?: number };
  scheduler: { enabled: boolean; milestones: number[]; post_expiry_checks: number[]; baseline_interval: string; near_expiry_interval: string; min_gap: string; ari_poll_interval: string; revocation_poll_interval: string; max_daily_scans: number };
  tranco: { enabled: boolean; source_url: string; max_domains: number; refresh_interval: string; fetch_on_start: boolean };
  local_lists: { enabled: boolean; refresh_interval: string; fetch_on_start: boolean; sources: { name: string; path: string; format: string; max_domains: number }[] };
}

// ---- API envelopes ----

export interface APIResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}

export interface Pagination {
  page: number;
  per_page: number;
  total: number;
  total_pages: number;
}

export interface PaginatedResponse<T> {
  success: boolean;
  data: T[];
  pagination: Pagination;
}

export interface DomainFilter {
  domain?: string;
  status?: string;
  revocation?: string;
  page?: number;
  per_page?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}
