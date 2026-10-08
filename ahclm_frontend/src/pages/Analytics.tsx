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
import { bucketLabel } from '@/lib/labels';

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
      <BarChart data={data.map((item) => ({ ...item, label: bucketLabel(item.label) }))} margin={{ top: 8, right: 8, bottom: 8, left: -16 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis dataKey="label" stroke="#64748b" fontSize={11} interval={0} angle={-15} textAnchor="end" height={50} />
        <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
        <Tooltip {...tip} />
        <Bar dataKey="count" name="数量" fill={color} radius={[4, 4, 0, 0]} />
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
        <Bar dataKey="count" name="数量" radius={[0, 4, 4, 0]}>
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
        <h1 className="text-2xl font-bold text-white">模式与规律</h1>
        <p className="text-slate-400 mt-1">
          当前已部署的 {p?.total_deployed ?? '—'} 张证书的统计规律
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel icon={Building2} title="证书颁发机构（CA）分布"
          subtitle="监测域名所使用的证书颁发机构">
          {p?.issuers?.length ? <HBar data={p.issuers} /> : <Empty />}
        </Panel>

        <Panel icon={KeyRound} title="公钥类型分布" subtitle="公钥算法与位数">
          {p?.key_types?.length ? <VBar data={p.key_types} color="#10b981" /> : <Empty />}
        </Panel>

        <Panel icon={CalendarRange} title="证书有效期分布"
          subtitle="总有效期（NotAfter − NotBefore）">
          {p?.validity_buckets?.length ? <VBar data={p.validity_buckets} color="#a855f7" /> : <Empty />}
        </Panel>

        <Panel icon={RefreshCw} title="续签提前量"
          subtitle="站点在到期前多久替换证书，用于分析续签规律">
          {renewalTotal > 0 ? (
            <VBar data={p!.renewal_lead_time} color="#f59e0b" />
          ) : (
            <div className="h-[240px] flex flex-col items-center justify-center text-center text-sm text-slate-500">
              <RefreshCw className="h-8 w-8 mb-2 opacity-40" />
              尚未观测到证书变更。<br />
              规律将随扫描记录的积累逐渐显现。
            </div>
          )}
        </Panel>

        <Panel icon={CalendarClock} title="ARI 建议续签窗口的位置"
          subtitle="CA 建议的 ARI 续签窗口在有效期中的起始位置：常规 ACME 通常位于最后三分之一（约 0.67），小于 0.5 表示提前或紧急窗口">
          {ariTotal > 0 ? (
            <VBar data={p!.ari_windows} color="#06b6d4" />
          ) : (
            <div className="h-[240px] flex flex-col items-center justify-center text-center text-sm text-slate-500">
              <CalendarClock className="h-8 w-8 mb-2 opacity-40" />
              尚未记录 ARI 窗口。<br />
              扫描支持 ARI 的 CA（如 Let’s Encrypt、Google）证书后会逐步积累数据。
            </div>
          )}
        </Panel>
      </div>

      {/* Adaptive cadence scatter */}
      <Panel icon={Activity} title="自适应扫描间隔与距到期时间"
        subtitle="每个点代表一个域名：证书越接近到期（越靠左），下次扫描越早（越靠下），体现关键时间节点附近的加密扫描策略">
        <ResponsiveContainer width="100%" height={320}>
          <ScatterChart margin={{ top: 12, right: 16, bottom: 24, left: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis type="number" dataKey="days_until_expiry" name="距到期天数" stroke="#64748b" fontSize={12}
              label={{ value: "距到期天数 →", position: 'insideBottom', offset: -12, fill: '#64748b', fontSize: 12 }} />
            <YAxis type="number" dataKey="next_scan_hours" name="距下次扫描小时数" stroke="#64748b" fontSize={12}
              label={{ value: "距下次扫描小时数", angle: -90, position: 'insideLeft', fill: '#64748b', fontSize: 12 }} />
            <ZAxis range={[50, 50]} />
            <Tooltip {...tip} formatter={(v) => (typeof v === 'number' ? String(Math.round(v)) : String(v))} />
            <Scatter data={cadence} fill="#3b82f6" fillOpacity={0.6} />
          </ScatterChart>
        </ResponsiveContainer>
        <p className="text-xs text-slate-600 mt-2">
          显示 {cadence.length} 个距到期 −14 至 120 天的域名。临近到期的域名集中在左下方（即将复扫），远离到期的域名接近 168 小时基线。
        </p>
      </Panel>
    </div>
  );
}

function Empty() {
  return <div className="h-[240px] flex items-center justify-center text-sm text-slate-500">暂无数据。</div>;
}
