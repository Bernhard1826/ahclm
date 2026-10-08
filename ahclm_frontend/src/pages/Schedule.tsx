import { reasonLabel } from '@/lib/labels';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { CalendarClock } from 'lucide-react';
import { getUpcomingSchedule, getSchedulerStatus } from '@/api';
import { fmtDateTime, fmtDays, timeUntil } from '@/lib/format';

function priorityBadge(p: number): string {
  if (p >= 95) return 'critical';
  if (p >= 80) return 'warning';
  if (p >= 50) return 'attention';
  return 'unknown';
}

export default function Schedule() {
  const { data, isLoading } = useQuery({
    queryKey: ['schedule', 100],
    queryFn: async () => (await getUpcomingSchedule(100)).data,
    refetchInterval: 20000,
  });
  const { data: sched } = useQuery({
    queryKey: ['schedulerStatus'],
    queryFn: async () => (await getSchedulerStatus()).data,
  });

  const entries = data?.schedule ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">自适应扫描调度</h1>
        <p className="text-slate-400 mt-1">
          证书接近到期里程碑时，会对相应域名进行复扫
          {sched?.milestones ? `（到期前 ${sched.milestones.join('、')} 天）` : ''}。
        </p>
      </div>

      <div className="card flex flex-wrap gap-6 items-center">
        <div>
          <p className="text-sm text-slate-400">调度器</p>
          <p className="text-xl font-bold">
            <span className={`status-badge ${sched?.paused ? 'warning' : 'good'}`}>
              {sched?.enabled ? (sched?.paused ? '已暂停' : '运行中') : '已禁用'}
            </span>
          </p>
        </div>
        <div><p className="text-sm text-slate-400">待扫描</p><p className="text-xl font-bold">{sched?.queue_status?.pending ?? '—'}</p></div>
        <div><p className="text-sm text-slate-400">运行中</p><p className="text-xl font-bold">{sched?.queue_status?.running ?? '—'}</p></div>
        <div><p className="text-sm text-slate-400">今日已完成</p><p className="text-xl font-bold">{sched?.queue_status?.completed ?? '—'}</p></div>
      </div>

      <div className="card p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>下次扫描</th>
                <th>距现在</th>
                <th>域名</th>
                <th>原因</th>
                <th>距到期</th>
                <th>优先级</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && <tr><td colSpan={6} className="text-center py-8"><div className="spinner mx-auto" /></td></tr>}
              {!isLoading && entries.length === 0 && (
                <tr><td colSpan={6} className="text-center py-8 text-slate-500">暂无扫描计划。</td></tr>
              )}
              {entries.map((e) => (
                <tr key={e.domain}>
                  <td className="text-slate-400 text-xs whitespace-nowrap">{fmtDateTime(e.next_scan_at)}</td>
                  <td className="text-slate-500 text-xs whitespace-nowrap">{timeUntil(e.next_scan_at)}</td>
                  <td>
                    <Link to={`/domains/${encodeURIComponent(e.domain)}`} className="text-primary-400 hover:underline flex items-center gap-2">
                      <CalendarClock className="h-4 w-4 opacity-60" />{e.domain}
                    </Link>
                  </td>
                  <td className="text-slate-300">{reasonLabel(e.reason)}</td>
                  <td>{e.current_fingerprint ? fmtDays(e.days_until_expiry) : '—'}</td>
                  <td><span className={`status-badge ${priorityBadge(e.priority)}`}>{e.priority}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
