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
  endpoint_probes_json?: string;
  caa_json?: string;
  ct_json?: string;
  http_json?: string;
  errors_json?: string;
}

export interface CDNPropagationConfig {
  enabled: boolean;
  auto_start_on_change: boolean;
  cdn_only: boolean;
  watch_window_seconds: number;
  poll_interval_seconds: number;
  max_duration_seconds: number;
  stable_rounds: number;
  locations: string[];
  certificate_layers?: string[];
  provider: string;
  origin_probe_target_required?: boolean;
  origin_probe_target_type?: string;
  origin_probe_host_role?: string;
  probe_path_cache_busting?: boolean;
  requires_monitored_domain: boolean;
}

export interface CDNPropagationExperiment {
  created_at: string;
  id: number;
  domain: string;
  vendor?: string;
  certificate_layer: 'edge' | 'origin' | 'origin_via_cdn' | string;
  probe_target: string;
  probe_host?: string;
  probe_path?: string;
  expected_http_status?: number;
  watch_changes: boolean;
  status: 'queued' | 'running' | 'complete' | 'timeout' | 'canceled' | 'failed' | string;
  previous_fingerprint?: string;
  target_fingerprint: string;
  source_updated_at: string;
  source_time_basis: string;
  started_at: string;
  last_attempted_at?: string;
  last_measured_at?: string;
  next_measure_at: string;
  completed_at?: string;
  completion_reason?: string;
  poll_interval_seconds: number;
  max_duration_seconds: number;
  stable_rounds_required: number;
  stable_rounds: number;
  expected_locations: number;
  observed_locations: number;
  target_locations: number;
  rounds: number;
  last_error?: string;
  locations_json?: string;
}

export interface CDNPropagationRound {
  id: number;
  experiment_id: number;
  round_number: number;
  observed_at: string;
  measurement_id?: string;
  status: string;
  answered_count: number;
  target_count: number;
  previous_count: number;
  expected_count: number;
  complete: boolean;
  error?: string;
}

export interface CDNPropagationLocation {
  location_key: string;
  baseline_fingerprint?: string;
  continent?: string;
  region?: string;
  country?: string;
  city?: string;
  asn?: number;
  network?: string;
  first_observed_at?: string;
  first_target_at?: string;
  last_previous_at?: string;
  last_observed_at?: string;
  latest_fingerprint?: string;
  last_tls_observed: boolean;
  last_origin_fingerprint?: string;
  last_origin_verified: boolean;
  last_error?: string;
  last_request_succeeded: boolean;
  last_http_status?: number;
  first_request_success_at?: string;
  target_seen: boolean;
  previous_seen: boolean;
  answered_rounds: number;
  latency_lower_seconds?: number;
  latency_seconds?: number;
  state: string;
}

export interface CDNPropagationReport {
  experiment: CDNPropagationExperiment;
  rounds: CDNPropagationRound[];
  locations: CDNPropagationLocation[];
  changes?: Array<{
    previous_fingerprint: string;
    fingerprint: string;
    first_seen_at: string;
    last_seen_at: string;
    regions: string[];
    first_seen_spread_seconds: number;
  }>;
  first_target_at?: string;
  all_regions_target_at?: string;
  completed_at?: string;
  source_to_first_seconds?: number;
  source_to_all_regions_seconds?: number;
  source_to_complete_seconds?: number;
  synchronization_spread_seconds?: number;
  sync_state: string;
  interpretation: string;
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
  evidence_class?: 'deterministic' | 'speculative' | string;
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
  proven_successors?: number;
  undated_endpoint_changes?: number;
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
  stable_address_rounds?: number;
  stable_address_span_hours?: number;
  independent_lineages?: boolean;
  address_pools?: number;
  pooled_endpoints?: string[];
  unobservable_endpoints?: string[];
  predecessor_issued_at?: string;
  successor_issued_at?: string;
  address_returns?: number;
  consecutive_predecessor_rounds: number;
  predecessor_span_hours: number;
  resolver_consistent_rounds: number;
  active_endpoint_coverage: number;
  active_predecessor_endpoints?: string[];
  retired_predecessor_endpoints?: string[];
  strong_evidence: boolean;
  reference_completed?: number;
  reference_finished_within?: number;
  reference_share?: number;
  alert_share?: number;
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
  requested_sni?: string;
  fingerprint?: string;
  default_fingerprint?: string;
  spki_fingerprint?: string;
  issuer_cn?: string;
  key_algorithm?: string;
  sans_hash?: string;
  selection_interpretation?: string;
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
  internal_evidence?: InternalEvidenceSummary | null;
}

export interface InternalEvidenceSummary {
  status: 'absent' | 'partial' | 'complete' | string;
  determination: string;
  root_cause_code?: string;
  root_cause_label?: string;
  conclusion?: string;
  confidence: string;
  event_count: number;
  correlated_events: number;
  source_systems?: string[];
  event_types?: string[];
  evidence?: string[];
  missing?: string[];
  next_required_events?: string[];
  last_event_at?: string;
}

export interface PublicKeyDeploymentEvent {
  at: string;
  kind: string;
  fingerprint?: string;
  spki?: string;
  previous?: string;
  ip_address?: string;
  region?: string;
  source: string;
  lower_bound?: boolean;
  evidence_id?: number;
  detail?: string;
}

export interface PublicKeyCycleMetrics {
  issuance_to_first_public_basis?: 'exact_issuance' | 'not_before';
  first_issued_at?: string;
  first_issued_exact_at?: string;
  first_deployed_at?: string;
  first_retired_at?: string;
  first_public_observed_at?: string;
  last_change_at?: string;
  issuance_to_first_public_seconds?: number;
  deployment_to_first_public_seconds?: number;
  first_public_to_stable_seconds?: number;
  successor_to_previous_retirement_seconds?: number;
  observed_span_seconds?: number;
  address_count: number;
  address_coverage: number;
  stable_round_count: number;
}

export interface PublicKeyDeploymentCycle {
  domain: string;
  generated_at: string;
  status: 'complete' | 'partial' | 'external_only' | string;
  determination: string;
  current_fingerprint?: string;
  current_spki?: string;
  certificate_count: number;
  public_key_count: number;
  same_key_replacements: number;
  events: PublicKeyDeploymentEvent[];
  metrics: PublicKeyCycleMetrics;
  missing_evidence?: string[];
  internal_evidence?: InternalEvidenceSummary | null;
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
  requested_sni?: string;
  fingerprint?: string;
  default_fingerprint?: string;
  spki_fingerprint?: string;
  issuer_cn?: string;
  key_algorithm?: string;
  selection_interpretation?: string;
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
  previous_issuer_cn?: string;
  issuer_cn?: string;
  previous_common_name?: string;
  common_name?: string;
  previous_key_algorithm?: string;
  key_algorithm?: string;
  sans_added?: string[];
  sans_removed?: string[];
  issuer_changed?: boolean;
  common_name_changed?: boolean;
  key_algorithm_changed?: boolean;
  public_key_changed?: boolean;
}

export interface CertificateExhibit {
  fingerprint: string;
  spki_fingerprint?: string;
  serial_number?: string;
  issuer?: string;
  issuer_cn?: string;
  subject?: string;
  common_name?: string;
  sans?: string[];
  signature_algorithm?: string;
  key_algorithm?: string;
  key_size?: number;
  public_key_type?: string;
  is_ca?: boolean;
  self_signed?: boolean;
  validity_days?: number;
  not_before?: string;
  not_after?: string;
  chain?: ChainEntry[];
  pem?: string;
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
  related_names?: RelatedNameProbe[];
  certificates?: CertificateExhibit[];
  cdn?: CDNEvidence | null;
  internal_evidence?: InternalEvidenceSummary | null;
  impact?: FindingImpact | null;
}

export interface ImpactEffect {
  kind: 'proven' | 'inferred' | string;
  code: string;
  label: string;
  claim: string;
  audience?: string;
  evidence?: string[];
}

export interface FindingImpact {
  summary: string;
  severity_ceiling: string;
  effects?: ImpactEffect[];
  not_established?: string[];
}


export interface EndpointProbe {
  ip_address: string;
  requested_sni?: string;
  success: boolean;
  fingerprint?: string;
  spki_fingerprint?: string;
  issuer_cn?: string;
  common_name?: string;
  key_algorithm?: string;
  key_size?: number;
  serial_number?: string;
  sans?: string[];
  sans_hash?: string;
  chain_fingerprints?: string[];
  covers_requested_name?: boolean;
  not_before?: string;
  not_after?: string;
  tls_version?: string;
  cipher_suite?: string;
  handshakes?: number;
  other_fingerprints?: string[];
  earliest_sct?: string;
  error?: string;
  selection_probes?: EndpointSelectionProbe[];
  selection_analysis?: EndpointSelectionAnalysis;
}

export interface EndpointSelectionProbe {
  variant: string;
  requested_sni?: string;
  success: boolean;
  fingerprint?: string;
  spki_fingerprint?: string;
  issuer_cn?: string;
  common_name?: string;
  key_algorithm?: string;
  key_size?: number;
  serial_number?: string;
  sans?: string[];
  chain_fingerprints?: string[];
  not_before?: string;
  not_after?: string;
  tls_version?: string;
  cipher_suite?: string;
  negotiated_protocol?: string;
  covers_requested_name?: boolean;
  error?: string;
}

export interface EndpointSelectionAnalysis {
  requested_sni?: string;
  selected_fingerprint?: string;
  default_fingerprint?: string;
  certificate_changed: boolean;
  chain_changed?: boolean;
  san_set_changed?: boolean;
  selected_covers_requested_name: boolean;
  default_covers_requested_name: boolean;
  interpretation: string;
  evidence?: string[];
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
  requested_sni?: string;
  http_host?: string;
  tls_version: string;
  cipher_suite: string;
  negotiated_protocol?: string;
  alpn?: string;
  connection_time_ms: number;
  ip_address?: string;
}

export interface HTTPFingerprint {
  ip_address?: string;
  requested_sni?: string;
  host_header?: string;
  tls_fingerprint?: string;
  tls_version?: string;
  negotiated_protocol?: string;
  status_code?: number;
  server?: string;
  via?: string;
  cache?: string;
  provider_signals?: string[];
  redirect?: string;
}

export interface MechanismScore {
  id: string;
  name: string;
  score: number;
  ranked: boolean;
  verdict?: string;
}

export interface MechanismColumn {
  id: string;
  name: string;
}

export interface MechanismMatrixEffect {
  mechanism: string;
  effect: 'support' | 'exclude' | string;
  weight: number;
}

export interface MechanismMatrixRow {
  id: string;
  label: string;
  observed: boolean;
  effects: MechanismMatrixEffect[];
}

export interface MechanismEvidence {
  id: string;
  summary: string;
  weights: Record<string, number>;
}

export interface MechanismReport {
  domain: string;
  status: 'supported' | 'ambiguous' | 'insufficient' | string;
  most_supported?: string;
  limitation: string;
  columns?: MechanismColumn[];
  matrix?: MechanismMatrixRow[];
  scores: MechanismScore[];
  evidence?: MechanismEvidence[];
  counterexamples?: string[];
  missing?: string[];
}

export interface DeepDiagnosisReport {
  domain: string;
  experiment: 'sni_selection' | 'repeat_handshake' | 'http_route' | string;
  started_at: string;
  question: string;
  limitation: string;
  probes?: EndpointProbe[];
  http?: HTTPFingerprint;
  observations?: string[];
}

export interface RelatedNameProbe {
  name: string;
  first_observed_at?: string;
  last_observed_at?: string;
  added_count: number;
  removed_count: number;
  branch_like_label?: boolean;
  probed_at: string;
  dns_status: 'active' | 'no_public_address' | 'inconclusive' | string;
  resolver_quorum?: number;
  resolved_ips?: string[];
  cname_chain?: string[];
  tls_answered: boolean;
  fingerprint?: string;
  issuer_cn?: string;
  common_name?: string;
  sans?: string[];
  covers_own_name?: boolean;
  covers_root_name?: boolean;
  shares_root_ip?: boolean;
  shares_root_cname?: boolean;
  shares_root_leaf?: boolean;
  http?: HTTPFingerprint;
  error?: string;
}

export interface DeepEvidence {
  collected_at: string;
  topology?: unknown;
  caa?: unknown[];
  ct?: unknown[];
  scts?: unknown[];
  http?: HTTPFingerprint;
  directory?: unknown;
  endpoint_probes?: EndpointProbe[];
  related_names?: RelatedNameProbe[];
  errors?: string[];
  status: string;
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
  deep_evidence?: DeepEvidence;
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
  scanner: { tls_port: number; timeout: string; workers: number; rate_limit: number; check_revocation: boolean; check_crl: boolean; check_ari: boolean; dns_resolvers?: string[]; max_endpoint_samples?: number; endpoint_probe_concurrency?: number; related_name_probe_limit?: number; related_name_probe_timeout?: string; check_caa?: boolean; check_ct?: boolean; ct_endpoint?: string; check_http_fingerprint?: boolean; check_rdap?: boolean; rdap_endpoint?: string; check_asn?: boolean; check_ripestat?: boolean; check_official_prefixes?: boolean; check_chrome_log_list?: boolean; check_apple_log_list?: boolean; check_sct_inclusion?: boolean; check_certspotter?: boolean; official_cdn_prefixes?: number; chrome_ct_logs?: number; apple_ct_logs?: number };
  scheduler: { enabled: boolean; milestones: number[]; post_expiry_checks: number[]; baseline_interval: string; near_expiry_interval: string; min_gap: string; ari_poll_interval: string; revocation_poll_interval: string; max_daily_scans: number };
  propagation?: { enabled: boolean; auto_start_on_change: boolean; cdn_only: boolean; poll_interval: string; max_duration: string; stable_rounds: number; locations: string[]; timeout: string; max_active: number };
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
