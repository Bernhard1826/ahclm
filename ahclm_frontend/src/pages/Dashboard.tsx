import { statusLabel, severityLabel, reasonLabel } from '@/lib/labels';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Shield,
  Globe,
  AlertTriangle,
  Clock,
  ShieldOff,
  Database,
  Activity,
  GitCommitHorizontal,
} from 'lucide-react';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import {
  getSystemStats,
  getHealth,
  getDailyStatistics,
  getRevocations,
  getAnomalies,
  getUpcomingSchedule,
} from '@/api';
import { fmtDate, timeUntil } from '@/lib/format';

function StatCard({ icon: Icon, label, value, subtext, color }: {
  icon: typeof Shield;
  label: string;
  value: string | number;
  subtext?: string;
  color: string;
}) {
  return (
    <div className="card">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-slate-400">{label}</p>
          <p className="text-3xl font-bold mt-1">{value}</p>
          {subtext && <p className="text-xs text-slate-500 mt-1">{subtext}</p>}
        </div>
        <div className={`p-3 rounded-lg ${color}`}>
          <Icon className="h-6 w-6" />
        </div>
      </div>
    </div>
  );
}

function shown(value: number | string | null | undefined): number | string {
  return value ?? '—';
}

const chartTip = {
  contentStyle: { background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0' },
  labelStyle: { color: '#94a3b8' },
};

export default function Dashboard() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['systemStats'],
    queryFn: async () => (await getSystemStats()).data,
    refetchInterval: 30000,
  });
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: async () => (await getHealth()).data,
    refetchInterval: 60000,
  });
  const { data: daily } = useQuery({
    queryKey: ['dailyStats'],
    queryFn: async () => (await getDailyStatistics()).data ?? [],
    refetchInterval: 60000,
  });
  const { data: revocations } = useQuery({
    queryKey: ['revocations'],
    queryFn: async () => (await getRevocations()).data,
    refetchInterval: 60000,
  });
  const { data: schedule } = useQuery({
    queryKey: ['upcoming', 8],
    queryFn: async () => (await getUpcomingSchedule(8)).data,
    refetchInterval: 30000,
  });
  const { data: anomalyData } = useQuery({
    queryKey: ['anomalies', 'dashboard'],
    queryFn: async () => (await getAnomalies(8, 1, true)).data,
    refetchInterval: 60000,
  });
  const anomalies = anomalyData?.anomalies ?? [];

  if (isLoading && !stats) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="spinner" />
      </div>
    );
  }

  const chartData = (daily ?? []).map((d) => ({
    date: d.date.slice(5),
    scans: d.total_scans,
    changes: d.changes_detected,
    revocations: d.revocations_detected,
    milestones: d.milestone_scans,
  }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">总览</h1>
          <p className="text-slate-400 mt-1">自适应 HTTPS 证书生命周期总览</p>
        </div>
        <div className="flex items-center gap-3 text-sm">
          <span className="text-slate-400">运行时长 {stats?.uptime ?? '—'}</span>
          <span className={`status-badge ${health?.status === 'healthy' ? 'good' : 'warning'}`}>
            {statusLabel(health?.status)}
          </span>
        </div>
      </div>

      {/* System status */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Activity className="h-5 w-5 text-primary-500" /> 系统状态
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            ["数据库", health?.database === 'connected'],
            ["扫描器", health?.scanner === 'ready'],
            ["调度器", health?.scheduler === 'running'],
            ['Tranco', health?.tranco === 'ready'],
          ].map(([label, ok]) => (
            <div key={label as string} className="flex items-center gap-3">
              <div className={`w-3 h-3 rounded-full ${ok ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm">{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Stat grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Globe} label="监测域名" value={shown(stats?.total_domains)}
          subtext={`${shown(stats?.active_domains)} 个活跃`} color="bg-primary-500/20 text-primary-400" />
        <StatCard icon={Shield} label="不同证书" value={shown(stats?.total_certificates)}
          subtext={`${shown(stats?.observations)} 次生命周期事件`} color="bg-blue-500/20 text-blue-400" />
        <StatCard icon={ShieldOff} label="已吊销" value={shown(stats?.revoked_certs)}
          subtext="仍部署的已吊销证书" color="bg-red-500/20 text-red-400" />
        <StatCard icon={AlertTriangle} label="7 天内到期" value={shown(stats?.expiring_certs_7d)}
          subtext={`${shown(stats?.expiring_certs_30d)} 张在 30 天内到期`} color="bg-yellow-500/20 text-yellow-400" />
        <StatCard icon={Clock} label="已过期且仍在提供" value={shown(stats?.expired_certs)}
          subtext="需要关注" color="bg-orange-500/20 text-orange-400" />
        <StatCard icon={GitCommitHorizontal} label="今日变更" value={shown(stats?.changed_today)}
          subtext={`${shown(stats?.today_scans)} 次今日扫描`} color="bg-emerald-500/20 text-emerald-400" />
        <StatCard icon={Activity} label="待扫描" value={shown(stats?.due_now)}
          subtext="已加入扫描队列" color="bg-violet-500/20 text-violet-400" />
        <StatCard icon={Database} label="数据库" value={shown(stats?.database_size)}
          subtext={stats?.average_scan_time_ms != null ? `平均扫描 ${Math.round(stats.average_scan_time_ms)} 毫秒` : '—'} color="bg-slate-500/20 text-slate-400" />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">每日扫描量</h2>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="date" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} />
              <Tooltip {...chartTip} />
              <Line type="monotone" dataKey="scans" stroke="#3b82f6" strokeWidth={2} dot={false} name="扫描次数" />
              <Line type="monotone" dataKey="milestones" stroke="#a855f7" strokeWidth={2} dot={false} name="里程碑扫描" />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">检测到的变更与吊销</h2>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="date" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} />
              <Tooltip {...chartTip} />
              <Bar dataKey="changes" fill="#10b981" name="证书变更" />
              <Bar dataKey="revocations" fill="#ef4444" name="吊销" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Current collector findings */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-yellow-500" /> 当前问题
          </h2>
          <Link to="/anomalies" className="text-primary-400 text-sm hover:underline">查看全部</Link>
        </div>
        {anomalies.length > 0 ? (
          <div className="space-y-2">
            {anomalies.slice(0, 6).map((a) => (
              <div key={`${a.domain}-${a.type}`} className="p-3 rounded bg-slate-700/30">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <Link to={`/domains/${encodeURIComponent(a.domain)}`} className="text-primary-400 hover:underline text-sm">
                      {a.domain}
                    </Link>
                    <p className="text-xs text-slate-300 mt-0.5"><span className="font-semibold uppercase tracking-wide text-slate-500">观测现象： </span>{a.description}</p>
                  </div>
                  <span className={`status-badge ${a.severity}`}>{severityLabel(a.severity)}</span>
                </div>
                <p className="text-xs text-slate-400 mt-2"><span className="font-semibold uppercase tracking-wide text-slate-500">证据： </span>{(a.confirmed_evidence?.length ? a.confirmed_evidence : a.evidence ?? []).slice(0, 2).join(' · ') || "未保留证据记录。"}</p>
                <p className="text-xs text-slate-500 mt-1">观测 {a.occurrence_count ?? 1} 次</p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-slate-500">当前没有具备证据支持的活动问题。</p>
        )}
      </div>

      {/* Revocations + upcoming schedule */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <ShieldOff className="h-5 w-5 text-red-500" /> 已吊销证书
            </h2>
            <Link to="/anomalies" className="text-primary-400 text-sm hover:underline">查看分析</Link>
          </div>
          {revocations && revocations.count > 0 ? (
            <div className="space-y-2">
              {revocations.domains.slice(0, 6).map((d) => (
                <Link key={d.domain} to={`/domains/${encodeURIComponent(d.domain)}`}
                  className="flex items-center justify-between p-2 rounded bg-red-500/10 hover:bg-red-500/20">
                  <span className="text-sm">{d.domain}</span>
                  <span className="status-badge revoked">已吊销</span>
                </Link>
              ))}
            </div>
          ) : revocations ? (
            <p className="text-sm text-slate-500">未检测到已吊销证书。</p>
          ) : (
            <p className="text-sm text-slate-500">吊销数据暂不可用。</p>
          )}
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Clock className="h-5 w-5 text-primary-500" /> 接下来的自适应扫描
            </h2>
            <Link to="/schedule" className="text-primary-400 text-sm hover:underline">完整调度</Link>
          </div>
          <div className="space-y-2">
            {(schedule?.schedule ?? []).slice(0, 6).map((e) => (
              <div key={e.domain} className="flex items-center justify-between text-sm">
                <Link to={`/domains/${encodeURIComponent(e.domain)}`} className="text-primary-400 hover:underline truncate max-w-[160px]">
                  {e.domain}
                </Link>
                <span className="text-slate-400">{reasonLabel(e.reason)}</span>
                <span className="text-slate-500">{timeUntil(e.next_scan_at)}</span>
              </div>
            ))}
            {schedule ? (!schedule.schedule.length && <p className="text-sm text-slate-500">暂无已安排的扫描。</p>) : (
              <p className="text-sm text-slate-500">调度数据暂不可用。</p>
            )}
          </div>
        </div>
      </div>

      <p className="text-xs text-slate-600 text-center">
        Tranco 列表监测数据 · 图表起始日期： {fmtDate(daily?.[0]?.date)} 起
      </p>
    </div>
  );
}
