import { useQuery } from '@tanstack/react-query';
import { BarChart3, Building2, KeyRound, CalendarRange, RefreshCw, Activity, CalendarClock } from 'lucide-react';
import {
  BarChart,
  Bar,
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { getPatterns } from '@/api';
import type { LabelCount } from '@/types';

const tip = {
  contentStyle: { background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0' },
  labelStyle: { color: '#94a3b8' },
  cursor: { fill: 'rgba(148,163,184,0.08)' },
};
const PALETTE = ['#3b82f6', '#10b981', '#a855f7', '#f59e0b', '#ef4444', '#06b6d4', '#ec4899', '#84cc16'];

function Panel({ icon: Icon, title, subtitle, children }: {
  icon: typeof BarChart3; title: string; subtitle?: string; children: React.ReactNode;
}) {
  return (
    <div className="card">
      <h2 className="text-lg font-semibold mb-1 flex items-center gap-2">
        <Icon className="h-5 w-5 text-primary-500" /> {title}
      </h2>
      {subtitle && <p className="text-xs text-slate-500 mb-3">{subtitle}</p>}
      {children}
    </div>
  );
}

function VBar({ data, color }: { data: LabelCount[]; color: string }) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 8, left: -16 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis dataKey="label" stroke="#64748b" fontSize={11} interval={0} angle={-15} textAnchor="end" height={50} />
        <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
        <Tooltip {...tip} />
        <Bar dataKey="count" fill={color} radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

function HBar({ data }: { data: LabelCount[] }) {
  return (
    <ResponsiveContainer width="100%" height={Math.max(240, data.length * 30)}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
        <XAxis type="number" stroke="#64748b" fontSize={12} allowDecimals={false} />
        <YAxis type="category" dataKey="label" stroke="#64748b" fontSize={11} width={150} />
        <Tooltip {...tip} />
        <Bar dataKey="count" radius={[0, 4, 4, 0]}>
          {data.map((_, i) => <Cell key={i} fill={PALETTE[i % PALETTE.length]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export default function Analytics() {
  const { data, isLoading } = useQuery({
    queryKey: ['patterns'],
    queryFn: async () => (await getPatterns()).data,
    refetchInterval: 60000,
  });

  if (isLoading && !data) {
    return <div className="flex justify-center py-16"><div className="spinner" /></div>;
  }

  const p = data;
  const cadence = (p?.cadence ?? []).filter((c) => c.days_until_expiry >= -14 && c.days_until_expiry <= 120);
  const renewalTotal = (p?.renewal_lead_time ?? []).reduce((s, x) => s + x.count, 0);
  const ariTotal = (p?.ari_windows ?? []).reduce((s, x) => s + x.count, 0);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Patterns &amp; Regularities</h1>
        <p className="text-slate-400 mt-1">
          Statistical regularities across {p?.total_deployed ?? '—'} currently deployed certificates
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel icon={Building2} title="Certificate Authority (issuer) distribution"
          subtitle="Which CAs the monitored population relies on">
          {p?.issuers?.length ? <HBar data={p.issuers} /> : <Empty />}
        </Panel>

        <Panel icon={KeyRound} title="Key type distribution" subtitle="Public-key algorithm and size">
          {p?.key_types?.length ? <VBar data={p.key_types} color="#10b981" /> : <Empty />}
        </Panel>

        <Panel icon={CalendarRange} title="Certificate lifetime distribution"
          subtitle="Total validity period (NotAfter − NotBefore)">
          {p?.validity_buckets?.length ? <VBar data={p.validity_buckets} color="#a855f7" /> : <Empty />}
        </Panel>

        <Panel icon={RefreshCw} title="Renewal lead time"
          subtitle="How long before expiry sites replace their certificate — the core renewal regularity">
          {renewalTotal > 0 ? (
            <VBar data={p!.renewal_lead_time} color="#f59e0b" />
          ) : (
            <div className="h-[240px] flex flex-col items-center justify-center text-center text-sm text-slate-500">
              <RefreshCw className="h-8 w-8 mb-2 opacity-40" />
              No certificate changes observed yet.<br />
              This regularity emerges as scanning accumulates over time.
            </div>
          )}
        </Panel>

        <Panel icon={CalendarClock} title="ARI recommended-renewal window position"
          subtitle="Where the CA-recommended (ARI) renewal window starts within the certificate lifetime — normal ACME places it in the last ⅓ (~0.67); <0.5 signals an early/emergency window">
          {ariTotal > 0 ? (
            <VBar data={p!.ari_windows} color="#06b6d4" />
          ) : (
            <div className="h-[240px] flex flex-col items-center justify-center text-center text-sm text-slate-500">
              <CalendarClock className="h-8 w-8 mb-2 opacity-40" />
              No ARI windows recorded yet.<br />
              Emerges as ARI-capable CAs (Let&apos;s Encrypt, Google) are scanned.
            </div>
          )}
        </Panel>
      </div>

      {/* Adaptive cadence scatter */}
      <Panel icon={Activity} title="Adaptive scan cadence vs. time-to-expiry"
        subtitle="Each point is a domain: as a certificate nears expiry (left), its next scan is scheduled sooner (lower) — the strategy densifies near critical time nodes">
        <ResponsiveContainer width="100%" height={320}>
          <ScatterChart margin={{ top: 12, right: 16, bottom: 24, left: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis type="number" dataKey="days_until_expiry" name="Days to expiry" stroke="#64748b" fontSize={12}
              label={{ value: 'Days until expiry →', position: 'insideBottom', offset: -12, fill: '#64748b', fontSize: 12 }} />
            <YAxis type="number" dataKey="next_scan_hours" name="Hours to next scan" stroke="#64748b" fontSize={12}
              label={{ value: 'Hours to next scan', angle: -90, position: 'insideLeft', fill: '#64748b', fontSize: 12 }} />
            <ZAxis range={[50, 50]} />
            <Tooltip {...tip} formatter={(v) => (typeof v === 'number' ? String(Math.round(v)) : String(v))} />
            <Scatter data={cadence} fill="#3b82f6" fillOpacity={0.6} />
          </ScatterChart>
        </ResponsiveContainer>
        <p className="text-xs text-slate-600 mt-2">
          Showing {cadence.length} domains within −14…120 days of expiry. Points hug the axes: near-expiry domains
          (small x) cluster at small y (imminent rescans); far-from-expiry domains sit near the 168 h baseline.
        </p>
      </Panel>
    </div>
  );
}

function Empty() {
  return <div className="h-[240px] flex items-center justify-center text-sm text-slate-500">No data yet.</div>;
}
