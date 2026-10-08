import axios, { AxiosError } from 'axios';
import type {
  APIResponse,
  PaginatedResponse,
  Anomaly,
  CertObservation,
  Certificate,
  CertificateAlert,
  DailyStat,
  DomainCertificate,
  DomainFilter,
  DomainView,
  HealthCheck,
  Patterns,
  ScanQueue,
  ScanJob,
  ScanResult,
  ScheduleEntry,
  SchedulerStatus,
  SystemStats,
  TrancoList,
  RuntimeConfig,
  CauseDiagnosis,
  PublicKeyDeploymentCycle,
  DeepDiagnosisReport,
  MechanismReport,
  MeasurementSnapshot,
  CDNPropagationConfig,
  CDNPropagationExperiment,
  CDNPropagationReport,
} from '@/types';

const apiURL = String(import.meta.env.VITE_API_URL || '/api').trim();

const api = axios.create({
  baseURL: apiURL,
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.response.use(
  (r) => r,
  (error: AxiosError<APIResponse<unknown>>) => {
    if (error.response?.data?.error) throw new Error(error.response.data.error);
    if (error.code === 'ECONNABORTED') throw new Error('请求超时，请稍后重试。');
    if (!error.response) throw new Error('无法连接后端，请检查服务状态。');
    throw new Error(`请求失败（HTTP ${error.response.status}）。`);
  }
);

function qs(params?: Record<string, unknown>): string {
  const p = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') p.append(k, String(v));
    });
  }
  return p.toString();
}

// Health & stats
export const getHealth = () => api.get<APIResponse<HealthCheck>>('/health').then((r) => r.data);
export const getSystemStats = () => api.get<APIResponse<SystemStats>>('/stats').then((r) => r.data);
export const getRuntimeConfig = () => api.get<APIResponse<RuntimeConfig>>('/config').then((r) => r.data);

// Domains (lifecycle state)
export const getDomains = (filter?: DomainFilter) =>
  api.get<PaginatedResponse<DomainView>>(`/domains?${qs(filter as Record<string, unknown>)}`).then((r) => r.data);

export const getDomain = (domain: string) =>
  api
    .get<APIResponse<{ domain: DomainCertificate; view: DomainView; current_certificate?: Certificate }>>(
      `/domains/${encodeURIComponent(domain)}`
    )
    .then((r) => r.data);

export const getDomainObservations = (domain: string, limit = 200) =>
  api
    .get<APIResponse<{ domain: string; count: number; observations: CertObservation[] }>>(
      `/domains/${encodeURIComponent(domain)}/observations?limit=${limit}`
    )
    .then((r) => r.data);

export const getDomainMeasurements = (domain: string, limit = 120) =>
  api
    .get<APIResponse<{ domain: string; count: number; measurements: MeasurementSnapshot[] }>>(
      `/domains/${encodeURIComponent(domain)}/measurements?limit=${limit}`
    )
    .then((r) => r.data);

// Certificates inventory
export const getCertificates = (filter?: DomainFilter) =>
  api.get<PaginatedResponse<Certificate>>(`/certificates?${qs(filter as Record<string, unknown>)}`).then((r) => r.data);

export const getExpiringCertificates = (days = 7) =>
  api
    .get<APIResponse<{ days: number; count: number; domains: DomainView[] }>>(`/certificates/expiring?days=${days}`)
    .then((r) => r.data);

export const getExpiredCertificates = () =>
  api.get<APIResponse<{ count: number; domains: DomainView[] }>>('/certificates/expired').then((r) => r.data);

// Revocation & analysis
export const getRevocations = () =>
  api.get<APIResponse<{ count: number; domains: DomainView[] }>>('/revocations').then((r) => r.data);

export const getAnomalies = (
  limit = 100,
  page = 1,
  summary = false,
  options?: { compact?: boolean; type?: string; domain?: string },
) =>
  api
    .get<APIResponse<{ count: number; page?: number; per_page?: number; total_pages?: number; anomalies: Anomaly[] }>>(
      `/analysis/anomalies?${qs({
        per_page: limit,
        page,
        summary: summary ? 1 : undefined,
        compact: options?.compact ? 1 : undefined,
        type: options?.type,
        domain: options?.domain,
      })}`,
      { timeout: 300000 },
    )
    .then((r) => r.data);

export const getDiagnosis = (domain: string, type?: string) =>
  api
    .get<APIResponse<{ domain: string; type?: string; diagnosis: CauseDiagnosis }>>(`/analysis/diagnosis?${qs({ domain, type })}`)
    .then((r) => r.data);

export const getPatterns = () =>
  api.get<APIResponse<Patterns>>('/analysis/patterns').then((r) => r.data);

export const getMechanismInference = (domain: string) =>
  api
    .get<APIResponse<{ domain: string; mechanism_inference: MechanismReport }>>(`/analysis/mechanism-inference?${qs({ domain })}`)
    .then((r) => r.data);

export const getKeyCycle = (domain: string) =>
  api
    .get<APIResponse<{ domain: string; key_cycle: PublicKeyDeploymentCycle }>>(`/analysis/key-cycle?${qs({ domain })}`)
    .then((r) => r.data);

export const runDeepDiagnosis = (request: { domain: string; experiment: string; addresses?: string[] }) =>
  api.post<APIResponse<DeepDiagnosisReport>>('/analysis/deep-probes', request, { timeout: 330000 }).then((r) => r.data);

// Scanning
export const scanDomain = (domain: string) =>
  api.post<APIResponse<ScanResult>>('/scan', { domain }).then((r) => r.data);

export const scanBatch = (domains: string[], workers: number) =>
  api
    .post<APIResponse<{ total: number; succeeded: number; results: ScanResult[]; errors: string[] }>>('/scan/batch', {
      domains,
      workers,
    })
    .then((r) => r.data);

export const getScanStatus = () => api.get<APIResponse<ScanQueue>>('/scan/status').then((r) => r.data);
export const getScanJobs = (limit = 20) =>
  api.get<APIResponse<{ count: number; jobs: ScanJob[] }>>(`/scan/jobs?limit=${limit}`).then((r) => r.data);

export const getCDNPropagationConfig = () =>
  api.get<APIResponse<CDNPropagationConfig>>('/cdn-propagation/config').then((r) => r.data);
export const getCDNPropagationExperiments = (domain?: string) =>
  api.get<APIResponse<{ count: number; experiments: CDNPropagationExperiment[] }>>(`/cdn-propagation?${qs({ domain })}`).then((r) => r.data);
export const getCDNPropagationReport = (id: number) =>
  api.get<APIResponse<CDNPropagationReport>>(`/cdn-propagation/experiments/${id}`).then((r) => r.data);
export const startCDNPropagation = (request: {
  domain: string;
  vendor?: string;
  certificate_layer?: 'edge' | 'origin' | 'origin_via_cdn';
  probe_target?: string;
  probe_host?: string;
  probe_path?: string;
  expected_http_status?: number;
  watch_changes?: boolean;
  previous_fingerprint?: string;
  target_fingerprint?: string;
  source_updated_at?: string;
  source_time_basis?: string;
  poll_interval_seconds?: number;
  max_duration_seconds?: number;
  stable_rounds?: number;
  locations?: string[];
}) => api.post<APIResponse<CDNPropagationReport>>('/cdn-propagation', request).then((r) => r.data);
export const cancelCDNPropagation = (id: number) =>
  api.post<APIResponse<{ status: string }>>(`/cdn-propagation/experiments/${id}/cancel`).then((r) => r.data);

// Scheduler
export const getSchedulerStatus = () =>
  api.get<APIResponse<SchedulerStatus>>('/scheduler/status').then((r) => r.data);
export const pauseScheduler = () => api.post<APIResponse<{ status: string }>>('/scheduler/pause').then((r) => r.data);
export const resumeScheduler = () => api.post<APIResponse<{ status: string }>>('/scheduler/resume').then((r) => r.data);
export const triggerTranco = () =>
  api.post<APIResponse<{ status: string; domains: number }>>('/scheduler/tranco').then((r) => r.data);

export const getUpcomingSchedule = (limit = 100) =>
  api
    .get<APIResponse<{ count: number; schedule: ScheduleEntry[] }>>(`/schedule/upcoming?limit=${limit}`)
    .then((r) => r.data);

// Alerts
export const getAlerts = () => api.get<APIResponse<CertificateAlert[]>>('/alerts').then((r) => r.data);
export const createAlert = (a: Omit<CertificateAlert, 'id' | 'created_at' | 'updated_at'>) =>
  api.post<APIResponse<CertificateAlert>>('/alerts', a).then((r) => r.data);
export const updateAlert = (id: number, a: CertificateAlert) =>
  api.put<APIResponse<CertificateAlert>>(`/alerts/${id}`, a).then((r) => r.data);
export const deleteAlert = (id: number) =>
  api.delete<APIResponse<{ deleted: boolean }>>(`/alerts/${id}`).then((r) => r.data);

// Tranco & statistics
export const getTrancoLatest = () => api.get<APIResponse<TrancoList>>('/tranco/latest').then((r) => r.data);
export const getDailyStatistics = (start?: string, end?: string) =>
  api.get<APIResponse<DailyStat[]>>(`/statistics/daily?${qs({ start, end })}`).then((r) => r.data);

export default api;
