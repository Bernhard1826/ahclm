import { statusLabel, reasonLabel } from '@/lib/labels';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowLeft,
  ShieldCheck,
  ShieldOff,
  RefreshCw,
  Flag,
  CalendarX,
  Plug,
  Plus,
  Clock,
  Link2,
  CalendarClock,
  AlertTriangle,
  Network,
  Timer,
  GitBranch,
  ExternalLink,
} from 'lucide-react';
import { getDomain, getDomainObservations, getDomainMeasurements, getDiagnosis } from '@/api';
import type { Anomaly, CertObservation, ChainEntry, CauseDiagnosis, MeasurementSnapshot } from '@/types';
import { fmtDate, fmtDateTime, fmtDays, timeUntil } from '@/lib/format';
import CauseInvestigation from '@/components/CauseInvestigation';
import DeepDiagnosisPanel from '@/components/DeepDiagnosisPanel';

const obsMeta: Record<string, { icon: typeof Flag; color: string; label: string }> = {
  initial: { icon: Plus, color: 'text-blue-400 bg-blue-500/15', label: "首次观测" },
  change: { icon: RefreshCw, color: 'text-emerald-400 bg-emerald-500/15', label: "证书已变更" },
  milestone: { icon: Flag, color: 'text-violet-400 bg-violet-500/15', label: "到期里程碑" },
  revocation_change: { icon: ShieldOff, color: 'text-red-400 bg-red-500/15', label: "吊销状态变更" },
  expiry: { icon: CalendarX, color: 'text-orange-400 bg-orange-500/15', label: "已过期" },
  reappear: { icon: ShieldCheck, color: 'text-green-400 bg-green-500/15', label: "恢复可访问" },
  unreachable: { icon: Plug, color: 'text-yellow-400 bg-yellow-500/15', label: "无法访问" },
  ari_window: { icon: CalendarClock, color: 'text-cyan-400 bg-cyan-500/15', label: "ARI 续签窗口" },
  ari_emergency: { icon: AlertTriangle, color: 'text-red-400 bg-red-500/15', label: "ARI 紧急窗口：建议立即续签" },
  same_key: { icon: RefreshCw, color: 'text-cyan-400 bg-cyan-500/15', label: "同钥替换" },
  stale_after_change: { icon: Network, color: 'text-amber-400 bg-amber-500/15', label: "拓扑变更后的旧证书残留" },
  residual: { icon: Timer, color: 'text-red-400 bg-red-500/15', label: "已吊销证书残留" },
  deployment_failure: { icon: GitBranch, color: 'text-orange-400 bg-orange-500/15', label: "观测到部分部署" },
};

const ariStatusText: Record<string, string> = {
  unsupported: "签发 CA 未提供 ARI 接口。",
  unavailable: "CA 支持 ARI，但尚未提供该证书的续签窗口。",
  error: "上次扫描未能访问 ARI 接口。",
  not_checked: "尚未检查 ARI。",
};

function findingTypeFromDiagnosis(diagnosis: CauseDiagnosis): string {
  if (diagnosis.churn_shape) {
    switch (diagnosis.primary_code) {
      case 'same_key_reissue':
      case 'concurrent_same_key':
      case 'same_key_unestablished':
        return 'same_key';
      case 'early_renewal_replacement':
      case 'early_renewal_unestablished':
        return 'early_renewal';
      default:
        return 'frequent_change';
    }
  }
  if (diagnosis.endpoint_divergence) {
    return diagnosis.investigation?.cause_code === 'dns_cutover_before_tls_deployment' ? 'stale_after_change' : 'deployment_failure';
  }
  switch (diagnosis.primary_code) {
    case 'expired_leaf_still_served':
      return 'expired_served';
    case 'expired_leaf_historically_observed':
      return 'expired_observed';
    case 'current_leaf_inside_expiry_window':
      return 'expiring_soon';
    case 'current_leaf_revoked':
      return 'revoked';
    case 'revoked_leaf_still_observable':
      return 'residual';
    case 'tls_measurement_failed':
      return 'unreachable';
    case 'ari_window_pulled_to_present':
      return 'ari_emergency';
    case 'expired_leaf_at_sampled_endpoint':
      return 'expired_endpoint';
    case 'name_mismatch_at_sampled_endpoint':
      return 'hostname_mismatch';
    case 'not_yet_valid_leaf_at_sampled_endpoint':
      return 'not_yet_valid';
    case 'local_chain_invalid_at_sampled_endpoint':
      return 'local_chain_validation_failed';
    case 'endpoint_probe_incomplete':
      return 'endpoint_probe_inconclusive';
    default:
      return diagnosis.investigation?.cause_code || 'deployment_failure';
  }
}

function TimelineItem({ o, last }: { o: CertObservation; last: boolean }) {
  const meta = obsMeta[o.observation_type] ?? obsMeta.initial;
  const Icon = meta.icon;
  return (
    <div className="flex gap-4">
      <div className="flex flex-col items-center">
        <div className={`p-2 rounded-full ${meta.color}`}>
          <Icon className="h-4 w-4" />
        </div>
        {!last && <div className="w-px flex-1 bg-slate-700 my-1" />}
      </div>
      <div className="pb-6 flex-1 min-w-0 break-words">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium">{meta.label}</span>
          {o.milestone && <span className="status-badge info">{reasonLabel(o.milestone)}</span>}
          {o.observation_type === 'revocation_change' && o.revocation_status && (
            <span className={`status-badge ${o.revocation_status}`}>{statusLabel(o.revocation_status)}</span>
          )}
        </div>
        <p className="text-xs text-slate-500 mt-1">{fmtDateTime(o.observed_at)} • {fmtDays(o.days_until_expiry)}</p>
        {o.previous_fingerprint && (
          <p className="text-xs text-slate-500 mt-1 font-mono">
            {o.previous_fingerprint.slice(0, 16)}… → {o.fingerprint.slice(0, 16)}…
          </p>
        )}
        {(o.tls_version || o.cipher_suite) && (
          <p className="text-xs text-slate-600 mt-1">{o.tls_version} • {o.cipher_suite}</p>
        )}
        {(o.spki_fingerprint || o.previous_spki_fingerprint) && (
          <p className="text-xs text-cyan-500/80 mt-1 font-mono">
            SPKI {o.previous_spki_fingerprint ? `${o.previous_spki_fingerprint.slice(0, 16)}… → ` : ''}{o.spki_fingerprint?.slice(0, 16) ?? '—'}…
          </p>
        )}
        {o.residual_duration_seconds !== undefined && (
          <p className="text-xs text-red-400/80 mt-1">直接观测的残留下界： {(o.residual_duration_seconds / 3600).toFixed(1)} 小时</p>
        )}
        {(o.previous_resolved_ips || o.resolved_ips) && (
          <p className="text-xs text-amber-500/80 mt-1 break-all">
            DNS/IP 证据： {o.previous_resolved_ips ? `${o.previous_resolved_ips} → ` : ''}{o.resolved_ips ?? '—'}
          </p>
        )}
        {o.endpoint_probes && (
          <p className="text-xs text-orange-400/80 mt-1 break-all">端点探测证据： {o.endpoint_probes}</p>
        )}
        {o.ari_window_start && (
          <p className="text-xs text-cyan-500/80 mt-1">
            窗口 {fmtDate(o.ari_window_start)} → {o.ari_window_end ? fmtDate(o.ari_window_end) : '—'}
          </p>
        )}
        {o.notes && <p className="text-xs text-slate-500 mt-1">{o.notes}</p>}
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-2 border-b border-slate-700/50 last:border-0">
      <span className="text-slate-400 text-sm">{label}</span>
      <span className="text-sm text-right break-all">{value}</span>
    </div>
  );
}

export default function DomainDetail() {
  const { domain = '' } = useParams();

  const { data: detail, isLoading } = useQuery({
    queryKey: ['domain', domain],
    queryFn: async () => (await getDomain(domain)).data,
  });
  const { data: obs } = useQuery({
    queryKey: ['observations', domain],
    queryFn: async () => (await getDomainObservations(domain)).data,
  });
  const { data: diagnosisData } = useQuery({
    queryKey: ['diagnosis', domain],
    queryFn: async () => (await getDiagnosis(domain)).data,
    enabled: Boolean(domain),
  });
  const { data: measurementsData } = useQuery({
    queryKey: ['measurements', domain],
    queryFn: async () => (await getDomainMeasurements(domain)).data,
    enabled: Boolean(domain),
  });


  if (isLoading) {
    return <div className="flex justify-center py-16"><div className="spinner" /></div>;
  }
  if (!detail) {
    return (
      <div className="card text-center py-12">
        <p className="text-slate-400">未找到该域名。</p>
        <Link to="/domains" className="text-primary-400 hover:underline mt-2 inline-block">返回域名列表</Link>
      </div>
    );
  }

  const dc = detail.domain;
  const cert = detail.current_certificate;
  const view = detail.view;
  const observations = obs?.observations ?? [];
  const diagnosis: CauseDiagnosis | undefined = diagnosisData?.diagnosis;
  const measurements: MeasurementSnapshot[] = measurementsData?.measurements ?? [];

  const sans: string[] = cert?.sans ? (() => { try { return JSON.parse(cert.sans); } catch { return []; } })() : [];
  const chain: ChainEntry[] = cert?.chain ? (() => { try { return JSON.parse(cert.chain); } catch { return []; } })() : [];

  const chainRole = (i: number, c: ChainEntry) =>
    i === 0 ? '叶证书' : c.is_ca && c.common_name === c.issuer_cn ? '根证书' : c.is_ca ? '中间证书' : '—';

  const ariFraction = (() => {
    if (!cert || !dc.ari_window_start) return null;
    const nb = new Date(cert.not_before).getTime();
    const na = new Date(cert.not_after).getTime();
    const ws = new Date(dc.ari_window_start).getTime();
    if (!(na > nb)) return null;
    return (ws - nb) / (na - nb);
  })();

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <Link to="/domains" className="btn btn-secondary p-2" aria-label="返回域名列表"><ArrowLeft className="h-4 w-4" /></Link>
        <div>
          <h1 className="text-2xl font-bold text-white">{dc.domain}</h1>
          <p className="text-slate-400 text-sm">
            Tranco 排名 {dc.tranco_rank || '—'} • {dc.scan_count} 次扫描 · {dc.change_count} 次变更
          </p>
        </div>
        <div className="ml-auto flex gap-2">
          <span className={`status-badge ${dc.status}`}>{statusLabel(dc.status)}</span>
          <span className={`status-badge ${dc.revocation_status}`}>{statusLabel(dc.revocation_status)}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Current certificate */}
        <div className="card lg:col-span-2">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary-500" /> 当前证书
          </h2>
          {cert ? (
            <div>
              <Row label="通用名称（CN）" value={cert.common_name} />
              <Row label="签发者" value={cert.issuer_cn} />
              <Row label="序列号" value={<span className="font-mono text-xs">{cert.serial_number}</span>} />
              <Row label="指纹（SHA-256）" value={<span className="font-mono text-xs">{cert.fingerprint}</span>} />
              <Row label="SPKI 指纹" value={<span className="font-mono text-xs">{cert.spki_fingerprint || '—'}</span>} />
              <Row label="公钥" value={`${cert.key_algorithm} ${cert.key_size} 位`} />
              <Row label="签名算法" value={cert.signature_algorithm} />
              <Row label="有效期起始" value={fmtDateTime(cert.not_before)} />
              <Row label="有效期截止" value={
                <span className={`status-badge ${view.expiration_status}`}>
                  {fmtDateTime(cert.not_after)} ({fmtDays(view.days_until_expiry)})
                </span>
              } />
              <Row label="有效期长度" value={`${cert.validity_days} 天`} />
              <Row label="主体备用名称（SAN）" value={sans.length ? sans.join(', ') : '—'} />
            </div>
          ) : (
            <p className="text-slate-500 text-sm">尚未采集到证书。</p>
          )}
        </div>

        {/* Revocation + schedule */}
        <div className="space-y-4 min-w-0">
          <div className="card">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              {dc.revocation_status === 'revoked'
                ? <ShieldOff className="h-5 w-5 text-red-500" />
                : <ShieldCheck className="h-5 w-5 text-green-500" />}
              吊销状态
            </h2>
            <Row label="状态" value={<span className={`status-badge ${dc.revocation_status}`}>{statusLabel(dc.revocation_status)}</span>} />
            <Row label="检查方式" value={dc.revocation_checked_via ? statusLabel(dc.revocation_checked_via) : '—'} />
            <Row label="证据状态" value={statusLabel(dc.evidence_status)} />
            {dc.evidence_pending_reason && <Row label="证据说明" value={dc.evidence_pending_reason} />}
            {dc.revoked_at && <Row label="吊销时间" value={fmtDateTime(dc.revoked_at)} />}
            {dc.revocation_reason && <Row label="原因" value={statusLabel(dc.revocation_reason)} />}
            {dc.ocsp_checked_at && <Row label="最近 OCSP 检查" value={fmtDateTime(dc.ocsp_checked_at)} />}
          </div>

          <div className="card">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Network className="h-5 w-5 text-amber-400" /> 生命周期证据
            </h2>
            <Row label="解析到的公网 IP" value={dc.resolved_ips || "未采集"} />
            <Row label="解析器共识" value={dc.consensus_ips || "尚未确定"} />
            <Row label="解析器一致度" value={dc.topology_resolver_agreement !== undefined ? `${Math.round(dc.topology_resolver_agreement * 100)}%（${dc.topology_resolver_quorum ?? 0} 个解析器）` : '—'} />
            <Row label="端点多样性" value={dc.endpoint_diversity_status ? statusLabel(dc.endpoint_diversity_status) : "尚未测量"} />
            {dc.endpoint_diversity_rounds ? <Row label="多样性轮次" value={dc.endpoint_diversity_rounds} /> : null}
            <Row label="最近 DNS 快照" value={dc.last_dns_observed_at ? fmtDateTime(dc.last_dns_observed_at) : '—'} />
            {dc.residual_fingerprint ? (
              <>
                <Row label="残留追踪" value={<span className="status-badge critical">进行中</span>} />
                <Row label="吊销时间锚点" value={dc.residual_revoked_at ? fmtDateTime(dc.residual_revoked_at) : '—'} />
                <Row label="后续观测次数" value={dc.residual_observation_count ?? 0} />
                <p className="text-xs text-slate-500 mt-2">残留时间表示该观测端点的直接时间下界，其范围限于该端点。</p>
              </>
            ) : (
              <Row label="残留追踪" value="No open revocation-follow-up incident" />
            )}
          </div>

          {diagnosis?.investigation && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><Network className="h-5 w-5 text-cyan-400" /> 问题、证据链与推断</h2>
              <CauseInvestigation
                rounds={diagnosis.endpoint_divergence || (diagnosis.investigation.provider_groups?.length ?? 0) > 0
                  ? (diagnosis.evidence_case?.rounds ?? [])
                  : []}
                anomaly={{
                  domain,
                  type: findingTypeFromDiagnosis(diagnosis),
                  severity: diagnosis.benign_explanation ? 'info' : 'warning',
                  description: diagnosis.investigation.problem,
                  reason: diagnosis.investigation.cause,
                  cause_classification: 'inferred',
                  confirmed_reason: '',
                  inferred_reason: diagnosis.investigation.cause,
                  confirmed_evidence: [],
                  inferred_evidence: [],
                  occurrence_count: 1,
                  monitoring_count: diagnosis.measured_rounds,
                  successful_monitoring_count: 0,
                  failed_monitoring_count: 0,
                  detected_at: '',
                  finding_class: diagnosis.investigation.finding_class,
                  diagnosis,
                } as Anomaly}
                investigation={diagnosis.investigation}
              />
            </div>
          )}

          <div className="card">
            <DeepDiagnosisPanel domain={domain} snapshots={measurements} />
          </div>

          {measurements.length > 0 && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><RefreshCw className="h-5 w-5 text-emerald-400" /> 测量记录</h2>
              <p className="text-xs text-slate-500 mb-3">每行是一个保留的观测轮次；未发生变化的轮次可作为因果推断的对照。</p>
              <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr className="text-slate-500 text-left"><th className="pb-2 pr-3">时间</th><th className="pb-2 pr-3">触发原因</th><th className="pb-2 pr-3">解析器</th><th className="pb-2 pr-3">端点</th><th className="pb-2">叶证书种类数</th></tr></thead><tbody>{measurements.slice(0, 12).map((measurement) => <tr key={measurement.id} className="border-t border-slate-700/50"><td className="py-2 pr-3 whitespace-nowrap">{fmtDateTime(measurement.observed_at)}</td><td className="py-2 pr-3 text-cyan-400">{reasonLabel(measurement.trigger)}</td><td className="py-2 pr-3">{Math.round(measurement.resolver_agreement * 100)}% / {measurement.resolver_quorum}</td><td className="py-2 pr-3">{measurement.successful_endpoint_count}/{measurement.endpoint_count}</td><td className="py-2">{measurement.fingerprint_count}</td></tr>)}</tbody></table></div>
            </div>
          )}

          <div className="card">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Clock className="h-5 w-5 text-primary-500" /> 自适应调度
            </h2>
            <Row label="下次扫描" value={`${timeUntil(dc.next_scan_at)} (${fmtDateTime(dc.next_scan_at)})`} />
            <Row label="优先级" value={dc.priority} />
            <Row label="最近扫描" value={fmtDateTime(dc.last_scanned_at)} />
            {dc.last_changed_at && <Row label="最近变更" value={fmtDateTime(dc.last_changed_at)} />}
            {dc.consecutive_failures > 0 && <Row label="失败次数" value={dc.consecutive_failures} />}
          </div>

          <div className="card">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <CalendarClock className="h-5 w-5 text-primary-500" /> ARI · CA 建议续签
            </h2>
            {dc.ari_status === 'ok' ? (
              <div>
                {dc.ari_emergency && (
                  <div className="mb-3 flex items-center gap-2 rounded bg-red-500/15 text-red-400 px-3 py-2 text-sm">
                    <AlertTriangle className="h-4 w-4 shrink-0" />
                    紧急：CA 已将续签窗口提前至当前。
                  </div>
                )}
                <Row label="窗口起始" value={dc.ari_window_start ? fmtDateTime(dc.ari_window_start) : '—'} />
                <Row label="窗口结束" value={dc.ari_window_end ? fmtDateTime(dc.ari_window_end) : '—'} />
                {ariFraction !== null && (
                  <Row label="在有效期中的位置" value={
                    <span className={ariFraction < 0.5 ? 'text-red-400' : ''}>
                      {(ariFraction * 100).toFixed(0)}%
                      {ariFraction < 0.5 ? "（提前 / 紧急）" : ariFraction >= 0.6 && ariFraction < 0.75 ? "（常规：最后三分之一）" : ''}
                    </span>
                  } />
                )}
                {dc.ari_checked_at && <Row label="最近检查" value={fmtDateTime(dc.ari_checked_at)} />}
                {dc.ari_next_poll_at && <Row label="下次轮询" value={timeUntil(dc.ari_next_poll_at)} />}
                {dc.ari_explanation_url && (
                  <a href={dc.ari_explanation_url} target="_blank" rel="noreferrer"
                    className="mt-3 inline-flex items-center gap-1 text-primary-400 hover:underline text-sm">
                    <ExternalLink className="h-3.5 w-3.5" /> CA 说明
                  </a>
                )}
              </div>
            ) : (
              <p className="text-slate-500 text-sm">
                {ariStatusText[dc.ari_status ?? 'not_checked'] ?? "尚未检查 ARI。"}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Certificate chain */}
      {chain.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Link2 className="h-5 w-5 text-primary-500" /> 证书链（{chain.length}）
          </h2>
          <div className="space-y-2">
            {chain.map((c, i) => (
              <div key={i} className="flex items-center gap-3 p-3 rounded bg-slate-700/30"
                style={{ marginLeft: `${i * 16}px` }}>
                <span className="text-xs text-slate-500 w-20 shrink-0">{chainRole(i, c)}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm truncate">{c.common_name}</p>
                  <p className="text-xs text-slate-500 truncate">签发者： {c.issuer_cn || '—'} · 到期于 {fmtDate(c.not_after)}</p>
                </div>
                {c.is_ca && <span className="status-badge info">CA</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Lifecycle timeline */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">生命周期时间线（{observations.length}）</h2>
        {observations.length ? (
          <div>
            {observations.map((o, i) => (
              <TimelineItem key={o.id} o={o} last={i === observations.length - 1} />
            ))}
          </div>
        ) : (
          <p className="text-slate-500 text-sm">
            暂无生命周期事件；证书变更、跨越里程碑、吊销及过期时会记录事件。
          </p>
        )}
      </div>
    </div>
  );
}
