import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { AlertTriangle, ShieldOff, CalendarX, RefreshCw, Repeat, CalendarClock, KeyRound, Network, Timer, GitBranch } from 'lucide-react';
import { getAnomalies } from '@/api';
import type { Anomaly } from '@/types';
import { fmtDateTime } from '@/lib/format';
import AnomalyCause from '@/components/AnomalyCause';

const typeMeta: Record<string, { icon: typeof AlertTriangle; label: string }> = {
  revoked: { icon: ShieldOff, label: 'Revoked certificate' },
  expired_served: { icon: CalendarX, label: 'Serving expired certificate' },
  expired_observed: { icon: CalendarX, label: 'Expired certificate observed (dormant)' },
  early_renewal: { icon: RefreshCw, label: 'Early renewal' },
  frequent_change: { icon: Repeat, label: 'Frequent changes' },
  unreachable: { icon: AlertTriangle, label: 'Repeatedly unreachable' },
  expiring_soon: { icon: CalendarClock, label: 'Expiring within 7 days' },
  ari_emergency: { icon: CalendarClock, label: 'ARI emergency (CA urges immediate renewal)' },
  same_key: { icon: KeyRound, label: 'Same-key certificate replacement' },
  stale_after_change: { icon: Network, label: 'Stale certificate after topology change' },
  residual: { icon: Timer, label: 'Revoked certificate residual service' },
  deployment_failure: { icon: GitBranch, label: 'Observed partial deployment' },
};

function severityBadge(s: string): string {
  return s === 'critical' ? 'critical' : s === 'warning' ? 'warning' : 'info';
}

export default function Anomalies() {
  const { data, isLoading } = useQuery({
    queryKey: ['anomalies'],
    queryFn: async () => (await getAnomalies(1000)).data,
    refetchInterval: 60000,
  });

  const anomalies: Anomaly[] = data?.anomalies ?? [];
  const grouped = anomalies.reduce<Record<string, Anomaly[]>>((acc, a) => {
    (acc[a.type] ??= []).push(a);
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Anomalies & Patterns</h1>
        <p className="text-slate-400 mt-1">Irregularities detected across the certificate lifecycle dataset</p>
      </div>

      {isLoading && <div className="flex justify-center py-16"><div className="spinner" /></div>}

      {!isLoading && anomalies.length === 0 && (
        <div className="card text-center py-12 text-slate-500">
          No anomalies detected yet. Accumulate more scan data to surface patterns.
        </div>
      )}

      {Object.entries(grouped).map(([type, items]) => {
        const meta = typeMeta[type] ?? { icon: AlertTriangle, label: type };
        const Icon = meta.icon;
        return (
          <div key={type} className="card">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Icon className="h-5 w-5 text-primary-500" /> {meta.label}
              <span className="text-sm text-slate-500">({items.length})</span>
            </h2>
            <div className="space-y-2">
              {items.map((a, i) => (
                <div key={`${a.domain}-${i}`} className="p-4 rounded bg-slate-700/30 space-y-2">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                    <Link to={`/domains/${encodeURIComponent(a.domain)}`} className="text-primary-400 hover:underline">
                      {a.domain}
                    </Link>
                    <p className="text-xs text-slate-500 mt-0.5">{a.description}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <span className={`status-badge ${severityBadge(a.severity)}`}>{a.severity}</span>
                      <p className="text-xs text-slate-600 mt-1">{fmtDateTime(a.detected_at)}</p>
                    </div>
                  </div>
                  <AnomalyCause anomaly={a} />
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                    <div className="bg-slate-800/60 rounded p-2"><span className="block text-slate-500">Finding observations</span><strong className="text-slate-200">{a.occurrence_count ?? 1}</strong></div>
                    <div className="bg-slate-800/60 rounded p-2"><span className="block text-slate-500">Monitoring rounds</span><strong className="text-slate-200">{a.monitoring_count ?? 0}</strong></div>
                    <div className="bg-slate-800/60 rounded p-2"><span className="block text-slate-500">Successful</span><strong className="text-slate-200">{a.successful_monitoring_count ?? 0}</strong></div>
                    <div className="bg-slate-800/60 rounded p-2"><span className="block text-slate-500">Failed</span><strong className="text-slate-200">{a.failed_monitoring_count ?? 0}</strong></div>
                  </div>
                  <div className="text-xs text-slate-600 flex flex-wrap gap-x-4 gap-y-1">
                    <span>First: {a.first_observed_at ? fmtDateTime(a.first_observed_at) : '—'}</span>
                    <span>Last: {a.last_observed_at ? fmtDateTime(a.last_observed_at) : '—'}</span>
                    {a.evidence_scope && <span>Scope: {a.evidence_scope}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
