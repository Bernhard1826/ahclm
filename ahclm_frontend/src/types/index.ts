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
  previous_resolved_ips?: string;
  last_dns_observed_at?: string;
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
  scanner: { tls_port: number; timeout: string; workers: number; rate_limit: number; check_revocation: boolean; check_crl: boolean; check_ari: boolean };
  scheduler: { enabled: boolean; milestones: number[]; post_expiry_checks: number[]; baseline_interval: string; near_expiry_interval: string; min_gap: string; ari_poll_interval: string; revocation_poll_interval: string; max_daily_scans: number };
  tranco: { enabled: boolean; source_url: string; max_domains: number; refresh_interval: string; fetch_on_start: boolean };
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
