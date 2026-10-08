import { statusLabel } from '@/lib/labels';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Globe, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { getDomains } from '@/api';
import type { DomainFilter } from '@/types';
import { fmtDays, timeAgo, timeUntil } from '@/lib/format';

export default function Domains() {
  const [filter, setFilter] = useState<DomainFilter>({
    page: 1,
    per_page: 25,
    sort_by: 'tranco_rank',
    sort_order: 'asc',
  });
  const [search, setSearch] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['domains', filter],
    queryFn: () => getDomains(filter),
    refetchInterval: 30000,
  });

  const rows = data?.data ?? [];
  const pg = data?.pagination;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">域名</h1>
          <p className="text-slate-400 mt-1">监测域名及其当前证书状态</p>
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              className="input pl-9"
              placeholder="搜索域名…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && setFilter((f) => ({ ...f, domain: search, page: 1 }))}
            />
          </div>
          <select className="input w-auto" value={filter.status ?? ''}
            onChange={(e) => setFilter((f) => ({ ...f, status: e.target.value, page: 1 }))}>
            <option value="">全部状态</option>
            <option value="active">活跃</option>
            <option value="unreachable">无法访问</option>
            <option value="dormant">休眠</option>
          </select>
          <select className="input w-auto" value={filter.revocation ?? ''}
            onChange={(e) => setFilter((f) => ({ ...f, revocation: e.target.value, page: 1 }))}>
            <option value="">全部吊销状态</option>
            <option value="good">正常</option>
            <option value="revoked">已吊销</option>
            <option value="unknown">未知</option>
          </select>
          <select className="input w-auto" value={`${filter.sort_by}:${filter.sort_order}`}
            onChange={(e) => {
              const [sb, so] = e.target.value.split(':');
              setFilter((f) => ({ ...f, sort_by: sb, sort_order: so as 'asc' | 'desc', page: 1 }));
            }}>
            <option value="tranco_rank:asc">排名 ↑</option>
            <option value="next_scan_at:asc">下次扫描 ↑</option>
            <option value="last_scanned_at:desc">最近扫描 ↓</option>
            <option value="change_count:desc">变更最多</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>#</th>
                <th>域名</th>
                <th>状态</th>
                <th>吊销状态</th>
                <th>签发者</th>
                <th>到期时间</th>
                <th>变更次数</th>
                <th>最近扫描</th>
                <th>下次扫描</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={9} className="text-center py-8"><div className="spinner mx-auto" /></td></tr>
              )}
              {!isLoading && rows.length === 0 && (
                <tr><td colSpan={9} className="text-center py-8 text-slate-500">
                  暂无域名，请获取 Tranco 列表或执行扫描。
                </td></tr>
              )}
              {rows.map((d) => (
                <tr key={d.domain}>
                  <td className="text-slate-500">{d.tranco_rank || '—'}</td>
                  <td>
                    <Link to={`/domains/${encodeURIComponent(d.domain)}`} className="text-primary-400 hover:underline flex items-center gap-2">
                      <Globe className="h-4 w-4 opacity-60" />{d.domain}
                      {d.ari_emergency && (
                        <span className="status-badge critical" title="CA 已将 ARI 续签窗口提前至当前">ARI!</span>
                      )}
                    </Link>
                  </td>
                  <td><span className={`status-badge ${d.status}`}>{statusLabel(d.status)}</span></td>
                  <td><span className={`status-badge ${d.revocation_status}`}>{statusLabel(d.revocation_status)}</span></td>
                  <td className="text-slate-400 truncate max-w-[160px]">{d.issuer || '—'}</td>
                  <td>
                    {d.not_after ? (
                      <span className={`status-badge ${d.expiration_status}`}>{fmtDays(d.days_until_expiry)}</span>
                    ) : '—'}
                  </td>
                  <td className="text-slate-300">{d.change_count}</td>
                  <td className="text-slate-500 text-xs">{timeAgo(d.last_scanned_at)}</td>
                  <td className="text-slate-500 text-xs">{timeUntil(d.next_scan_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {pg && pg.total > 0 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-slate-400">
            {(pg.page - 1) * pg.per_page + 1}–{Math.min(pg.page * pg.per_page, pg.total)} / 共 {pg.total}
          </span>
          <div className="flex gap-2">
            <button aria-label="上一页" className="btn btn-secondary" disabled={pg.page <= 1}
              onClick={() => setFilter((f) => ({ ...f, page: (f.page ?? 1) - 1 }))}>
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span className="px-3 py-2">{pg.page} / {pg.total_pages}</span>
            <button aria-label="下一页" className="btn btn-secondary" disabled={pg.page >= pg.total_pages}
              onClick={() => setFilter((f) => ({ ...f, page: (f.page ?? 1) + 1 }))}>
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
