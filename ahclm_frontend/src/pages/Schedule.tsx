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
        <h1 className="text-2xl font-bold text-white">Adaptive Scan Schedule</h1>
        <p className="text-slate-400 mt-1">
          Each domain is rescanned as its certificate approaches expiry milestones
          {sched?.milestones ? ` (${sched.milestones.join(', ')} days before expiry)` : ''}.
        </p>
      </div>

      <div className="card flex flex-wrap gap-6 items-center">
        <div>
          <p className="text-sm text-slate-400">Scheduler</p>
          <p className="text-xl font-bold">
            <span className={`status-badge ${sched?.paused ? 'warning' : 'good'}`}>
              {sched?.enabled ? (sched?.paused ? 'paused' : 'running') : 'disabled'}
            </span>
          </p>
        </div>
        <div><p className="text-sm text-slate-400">Due now</p><p className="text-xl font-bold">{sched?.queue_status?.pending ?? '—'}</p></div>
        <div><p className="text-sm text-slate-400">Running</p><p className="text-xl font-bold">{sched?.queue_status?.running ?? '—'}</p></div>
        <div><p className="text-sm text-slate-400">Completed today</p><p className="text-xl font-bold">{sched?.queue_status?.completed ?? '—'}</p></div>
      </div>

      <div className="card p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Next scan</th>
                <th>When</th>
                <th>Domain</th>
                <th>Reason</th>
                <th>Expires in</th>
                <th>Priority</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && <tr><td colSpan={6} className="text-center py-8"><div className="spinner mx-auto" /></td></tr>}
              {!isLoading && entries.length === 0 && (
                <tr><td colSpan={6} className="text-center py-8 text-slate-500">No scans scheduled yet.</td></tr>
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
                  <td className="text-slate-300">{e.reason}</td>
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
