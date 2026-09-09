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
          <h1 className="text-2xl font-bold text-white">Domains</h1>
          <p className="text-slate-400 mt-1">Monitored domains and their current certificate state</p>
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              className="input pl-9"
              placeholder="Search domain..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && setFilter((f) => ({ ...f, domain: search, page: 1 }))}
            />
          </div>
          <select className="input w-auto" value={filter.status ?? ''}
            onChange={(e) => setFilter((f) => ({ ...f, status: e.target.value, page: 1 }))}>
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="unreachable">Unreachable</option>
            <option value="dormant">Dormant</option>
          </select>
          <select className="input w-auto" value={filter.revocation ?? ''}
            onChange={(e) => setFilter((f) => ({ ...f, revocation: e.target.value, page: 1 }))}>
            <option value="">Any revocation</option>
            <option value="good">Good</option>
            <option value="revoked">Revoked</option>
            <option value="unknown">Unknown</option>
          </select>
          <select className="input w-auto" value={`${filter.sort_by}:${filter.sort_order}`}
            onChange={(e) => {
              const [sb, so] = e.target.value.split(':');
              setFilter((f) => ({ ...f, sort_by: sb, sort_order: so as 'asc' | 'desc', page: 1 }));
            }}>
            <option value="tranco_rank:asc">Rank ↑</option>
            <option value="next_scan_at:asc">Next scan ↑</option>
            <option value="last_scanned_at:desc">Last scanned ↓</option>
            <option value="change_count:desc">Most changes</option>
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
                <th>Domain</th>
                <th>Status</th>
                <th>Revocation</th>
                <th>Issuer</th>
                <th>Expires</th>
                <th>Changes</th>
                <th>Last scan</th>
                <th>Next scan</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={9} className="text-center py-8"><div className="spinner mx-auto" /></td></tr>
              )}
              {!isLoading && rows.length === 0 && (
                <tr><td colSpan={9} className="text-center py-8 text-slate-500">
                  No domains yet. Fetch the Tranco list or run a scan.
                </td></tr>
              )}
              {rows.map((d) => (
                <tr key={d.domain}>
                  <td className="text-slate-500">{d.tranco_rank || '—'}</td>
                  <td>
                    <Link to={`/domains/${encodeURIComponent(d.domain)}`} className="text-primary-400 hover:underline flex items-center gap-2">
                      <Globe className="h-4 w-4 opacity-60" />{d.domain}
                      {d.ari_emergency && (
                        <span className="status-badge critical" title="CA moved the ARI renewal window to now">ARI!</span>
                      )}
                    </Link>
                  </td>
                  <td><span className={`status-badge ${d.status}`}>{d.status}</span></td>
                  <td><span className={`status-badge ${d.revocation_status}`}>{d.revocation_status}</span></td>
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
            {(pg.page - 1) * pg.per_page + 1}–{Math.min(pg.page * pg.per_page, pg.total)} of {pg.total}
          </span>
          <div className="flex gap-2">
            <button className="btn btn-secondary" disabled={pg.page <= 1}
              onClick={() => setFilter((f) => ({ ...f, page: (f.page ?? 1) - 1 }))}>
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span className="px-3 py-2">{pg.page} / {pg.total_pages}</span>
            <button className="btn btn-secondary" disabled={pg.page >= pg.total_pages}
              onClick={() => setFilter((f) => ({ ...f, page: (f.page ?? 1) + 1 }))}>
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
