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
import type { CertObservation, ChainEntry, CauseDiagnosis, MeasurementSnapshot } from '@/types';
import { fmtDate, fmtDateTime, fmtDays, timeUntil } from '@/lib/format';

const obsMeta: Record<string, { icon: typeof Flag; color: string; label: string }> = {
  initial: { icon: Plus, color: 'text-blue-400 bg-blue-500/15', label: 'Initial sighting' },
  change: { icon: RefreshCw, color: 'text-emerald-400 bg-emerald-500/15', label: 'Certificate changed' },
  milestone: { icon: Flag, color: 'text-violet-400 bg-violet-500/15', label: 'Expiry milestone' },
  revocation_change: { icon: ShieldOff, color: 'text-red-400 bg-red-500/15', label: 'Revocation change' },
  expiry: { icon: CalendarX, color: 'text-orange-400 bg-orange-500/15', label: 'Expired' },
  reappear: { icon: ShieldCheck, color: 'text-green-400 bg-green-500/15', label: 'Reachable again' },
  unreachable: { icon: Plug, color: 'text-yellow-400 bg-yellow-500/15', label: 'Unreachable' },
  ari_window: { icon: CalendarClock, color: 'text-cyan-400 bg-cyan-500/15', label: 'ARI renewal window' },
  ari_emergency: { icon: AlertTriangle, color: 'text-red-400 bg-red-500/15', label: 'ARI emergency — renew now' },
  same_key: { icon: RefreshCw, color: 'text-cyan-400 bg-cyan-500/15', label: 'Same-key replacement' },
  stale_after_change: { icon: Network, color: 'text-amber-400 bg-amber-500/15', label: 'Stale after topology change' },
  residual: { icon: Timer, color: 'text-red-400 bg-red-500/15', label: 'Residual revoked certificate' },
  deployment_failure: { icon: GitBranch, color: 'text-orange-400 bg-orange-500/15', label: 'Partial deployment observed' },
};

const ariStatusText: Record<string, string> = {
  unsupported: 'Issuer CA does not expose an ARI endpoint.',
  unavailable: 'ARI-capable CA, but no window is available for this certificate yet.',
  error: 'Could not reach the ARI endpoint on the last scan.',
  not_checked: 'ARI has not been checked yet.',
};

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
      <div className="pb-6 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium">{meta.label}</span>
          {o.milestone && <span className="status-badge info">{o.milestone.replace(/_/g, ' ')}</span>}
          {o.observation_type === 'revocation_change' && o.revocation_status && (
            <span className={`status-badge ${o.revocation_status}`}>{o.revocation_status}</span>
          )}
        </div>
        <p className="text-xs text-slate-500 mt-1">{fmtDateTime(o.observed_at)} • {fmtDays(o.days_until_expiry)} to expiry</p>
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
          <p className="text-xs text-red-400/80 mt-1">Direct residual lower bound: {(o.residual_duration_seconds / 3600).toFixed(1)} hours</p>
        )}
        {(o.previous_resolved_ips || o.resolved_ips) && (
          <p className="text-xs text-amber-500/80 mt-1 break-all">
            DNS/IP evidence: {o.previous_resolved_ips ? `${o.previous_resolved_ips} → ` : ''}{o.resolved_ips ?? '—'}
          </p>
        )}
        {o.endpoint_probes && (
          <p className="text-xs text-orange-400/80 mt-1 break-all">Endpoint probe evidence: {o.endpoint_probes}</p>
        )}
        {o.ari_window_start && (
          <p className="text-xs text-cyan-500/80 mt-1">
            window {fmtDate(o.ari_window_start)} → {o.ari_window_end ? fmtDate(o.ari_window_end) : '—'}
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
        <p className="text-slate-400">Domain not found.</p>
        <Link to="/domains" className="text-primary-400 hover:underline mt-2 inline-block">Back to domains</Link>
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
    i === 0 ? 'leaf' : c.is_ca && c.common_name === c.issuer_cn ? 'root' : c.is_ca ? 'intermediate' : '—';

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
      <div className="flex items-center gap-3">
        <Link to="/domains" className="btn btn-secondary p-2"><ArrowLeft className="h-4 w-4" /></Link>
        <div>
          <h1 className="text-2xl font-bold text-white">{dc.domain}</h1>
          <p className="text-slate-400 text-sm">
            Tranco rank {dc.tranco_rank || '—'} • {dc.scan_count} scans • {dc.change_count} changes
          </p>
        </div>
        <div className="ml-auto flex gap-2">
          <span className={`status-badge ${dc.status}`}>{dc.status}</span>
          <span className={`status-badge ${dc.revocation_status}`}>{dc.revocation_status}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Current certificate */}
        <div className="card lg:col-span-2">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary-500" /> Current Certificate
          </h2>
          {cert ? (
            <div>
              <Row label="Common Name" value={cert.common_name} />
              <Row label="Issuer" value={cert.issuer_cn} />
              <Row label="Serial" value={<span className="font-mono text-xs">{cert.serial_number}</span>} />
              <Row label="Fingerprint (SHA-256)" value={<span className="font-mono text-xs">{cert.fingerprint}</span>} />
              <Row label="SPKI fingerprint" value={<span className="font-mono text-xs">{cert.spki_fingerprint || '—'}</span>} />
              <Row label="Key" value={`${cert.key_algorithm} ${cert.key_size}-bit`} />
              <Row label="Signature" value={cert.signature_algorithm} />
              <Row label="Valid from" value={fmtDateTime(cert.not_before)} />
              <Row label="Valid until" value={
                <span className={`status-badge ${view.expiration_status}`}>
                  {fmtDateTime(cert.not_after)} ({fmtDays(view.days_until_expiry)})
                </span>
              } />
              <Row label="Lifetime" value={`${cert.validity_days} days`} />
              <Row label="SANs" value={sans.length ? sans.join(', ') : '—'} />
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No certificate captured yet.</p>
          )}
        </div>

        {/* Revocation + schedule */}
        <div className="space-y-4">
          <div className="card">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              {dc.revocation_status === 'revoked'
                ? <ShieldOff className="h-5 w-5 text-red-500" />
                : <ShieldCheck className="h-5 w-5 text-green-500" />}
              Revocation
            </h2>
            <Row label="Status" value={<span className={`status-badge ${dc.revocation_status}`}>{dc.revocation_status}</span>} />
            <Row label="Checked via" value={dc.revocation_checked_via || '—'} />
            <Row label="Evidence status" value={dc.evidence_status || 'unknown'} />
            {dc.evidence_pending_reason && <Row label="Evidence note" value={dc.evidence_pending_reason} />}
            {dc.revoked_at && <Row label="Revoked at" value={fmtDateTime(dc.revoked_at)} />}
            {dc.revocation_reason && <Row label="Reason" value={dc.revocation_reason} />}
            {dc.ocsp_checked_at && <Row label="Last OCSP" value={fmtDateTime(dc.ocsp_checked_at)} />}
          </div>

          <div className="card">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Network className="h-5 w-5 text-amber-400" /> Lifecycle evidence
            </h2>
            <Row label="Resolved public IPs" value={dc.resolved_ips || 'Not captured'} />
            <Row label="Resolver consensus" value={dc.consensus_ips || 'Not established'} />
            <Row label="Resolver agreement" value={dc.topology_resolver_agreement !== undefined ? `${Math.round(dc.topology_resolver_agreement * 100)}% (${dc.topology_resolver_quorum ?? 0} resolvers)` : '—'} />
            <Row label="Endpoint diversity" value={dc.endpoint_diversity_status || 'Not measured'} />
            <Row label="Last DNS snapshot" value={dc.last_dns_observed_at ? fmtDateTime(dc.last_dns_observed_at) : '—'} />
            {dc.residual_fingerprint ? (
              <>
                <Row label="Residual tracking" value={<span className="status-badge critical">open</span>} />
                <Row label="Revocation anchor" value={dc.residual_revoked_at ? fmtDateTime(dc.residual_revoked_at) : '—'} />
                <Row label="Follow-up observations" value={dc.residual_observation_count ?? 0} />
                <p className="text-xs text-slate-500 mt-2">Residual timing is a direct lower bound at this observed endpoint. It is not a global edge count.</p>
              </>
            ) : (
              <Row label="Residual tracking" value="No open revocation-follow-up incident" />
            )}
          </div>

          {diagnosis && (
            <div className="card">
              {(() => {
                const hypotheses = Array.isArray(diagnosis.hypotheses) ? diagnosis.hypotheses : [];
                return (
                  <>
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><Network className="h-5 w-5 text-cyan-400" /> Deep cause assessment</h2>
              <p className="text-sm text-slate-200">{diagnosis.summary}</p>
              <p className="text-xs text-slate-500 mt-2">{diagnosis.measured_rounds} measurement rounds · {diagnosis.transition_rounds} transitions · {Math.round(diagnosis.evidence_completeness * 100)}% evidence completeness</p>
              <div className="mt-3 space-y-2">
                {hypotheses.slice(0, 3).map((hypothesis) => <div key={hypothesis.code} className="text-xs"><div className="flex justify-between text-slate-400"><span>{hypothesis.label}</span><span>{Math.round(hypothesis.score * 100)}%</span></div><div className="h-1 bg-slate-700 mt-1"><div className="h-1 bg-cyan-500" style={{ width: `${Math.round(hypothesis.score * 100)}%` }} /></div></div>)}
              </div>
                  </>
                );
              })()}
            </div>
          )}

          {measurements.length > 0 && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><RefreshCw className="h-5 w-5 text-emerald-400" /> Measurement ledger</h2>
              <p className="text-xs text-slate-500 mb-3">Each row is a retained observation round; unchanged rounds are controls for causal inference.</p>
              <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr className="text-slate-500 text-left"><th className="pb-2 pr-3">Time</th><th className="pb-2 pr-3">Trigger</th><th className="pb-2 pr-3">Resolvers</th><th className="pb-2 pr-3">Endpoints</th><th className="pb-2">Leaf diversity</th></tr></thead><tbody>{measurements.slice(0, 12).map((measurement) => <tr key={measurement.id} className="border-t border-slate-700/50"><td className="py-2 pr-3 whitespace-nowrap">{fmtDateTime(measurement.observed_at)}</td><td className="py-2 pr-3 text-cyan-400">{measurement.trigger}</td><td className="py-2 pr-3">{Math.round(measurement.resolver_agreement * 100)}% / {measurement.resolver_quorum}</td><td className="py-2 pr-3">{measurement.successful_endpoint_count}/{measurement.endpoint_count}</td><td className="py-2">{measurement.fingerprint_count}</td></tr>)}</tbody></table></div>
            </div>
          )}

          <div className="card">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Clock className="h-5 w-5 text-primary-500" /> Adaptive Schedule
            </h2>
            <Row label="Next scan" value={`${timeUntil(dc.next_scan_at)} (${fmtDateTime(dc.next_scan_at)})`} />
            <Row label="Priority" value={dc.priority} />
            <Row label="Last scanned" value={fmtDateTime(dc.last_scanned_at)} />
            {dc.last_changed_at && <Row label="Last changed" value={fmtDateTime(dc.last_changed_at)} />}
            {dc.consecutive_failures > 0 && <Row label="Failures" value={dc.consecutive_failures} />}
          </div>

          <div className="card">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <CalendarClock className="h-5 w-5 text-primary-500" /> ARI · CA-recommended renewal
            </h2>
            {dc.ari_status === 'ok' ? (
              <div>
                {dc.ari_emergency && (
                  <div className="mb-3 flex items-center gap-2 rounded bg-red-500/15 text-red-400 px-3 py-2 text-sm">
                    <AlertTriangle className="h-4 w-4 shrink-0" />
                    Emergency: the CA moved the renewal window to now.
                  </div>
                )}
                <Row label="Window start" value={dc.ari_window_start ? fmtDateTime(dc.ari_window_start) : '—'} />
                <Row label="Window end" value={dc.ari_window_end ? fmtDateTime(dc.ari_window_end) : '—'} />
                {ariFraction !== null && (
                  <Row label="Position in lifetime" value={
                    <span className={ariFraction < 0.5 ? 'text-red-400' : ''}>
                      {(ariFraction * 100).toFixed(0)}%
                      {ariFraction < 0.5 ? ' (early / urgent)' : ariFraction >= 0.6 && ariFraction < 0.75 ? ' (normal last-⅓)' : ''}
                    </span>
                  } />
                )}
                {dc.ari_checked_at && <Row label="Last checked" value={fmtDateTime(dc.ari_checked_at)} />}
                {dc.ari_next_poll_at && <Row label="Next poll" value={timeUntil(dc.ari_next_poll_at)} />}
                {dc.ari_explanation_url && (
                  <a href={dc.ari_explanation_url} target="_blank" rel="noreferrer"
                    className="mt-3 inline-flex items-center gap-1 text-primary-400 hover:underline text-sm">
                    <ExternalLink className="h-3.5 w-3.5" /> CA explanation
                  </a>
                )}
              </div>
            ) : (
              <p className="text-slate-500 text-sm">
                {ariStatusText[dc.ari_status ?? 'not_checked'] ?? 'ARI has not been checked yet.'}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Certificate chain */}
      {chain.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Link2 className="h-5 w-5 text-primary-500" /> Certificate Chain ({chain.length})
          </h2>
          <div className="space-y-2">
            {chain.map((c, i) => (
              <div key={i} className="flex items-center gap-3 p-3 rounded bg-slate-700/30"
                style={{ marginLeft: `${i * 16}px` }}>
                <span className="text-xs text-slate-500 w-20 shrink-0">{chainRole(i, c)}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm truncate">{c.common_name}</p>
                  <p className="text-xs text-slate-500 truncate">issued by {c.issuer_cn || '—'} • expires {fmtDate(c.not_after)}</p>
                </div>
                {c.is_ca && <span className="status-badge info">CA</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Lifecycle timeline */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Lifecycle Timeline ({observations.length})</h2>
        {observations.length ? (
          <div>
            {observations.map((o, i) => (
              <TimelineItem key={o.id} o={o} last={i === observations.length - 1} />
            ))}
          </div>
        ) : (
          <p className="text-slate-500 text-sm">
            No lifecycle events yet — events are recorded on changes, milestone crossings, revocation and expiry.
          </p>
        )}
      </div>
    </div>
  );
}
