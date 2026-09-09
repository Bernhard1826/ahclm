import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ListOrdered, RefreshCw, Loader2, CheckCircle } from 'lucide-react';
import { getTrancoLatest, getSystemStats, triggerTranco } from '@/api';
import { fmtDateTime } from '@/lib/format';

export default function Tranco() {
  const qc = useQueryClient();

  const { data: latest, isLoading } = useQuery({
    queryKey: ['trancoLatest'],
    queryFn: async () => (await getTrancoLatest()).data,
    retry: false,
  });
  const { data: stats } = useQuery({
    queryKey: ['systemStats'],
    queryFn: async () => (await getSystemStats()).data,
  });

  const fetchMutation = useMutation({
    mutationFn: () => triggerTranco(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['trancoLatest'] });
      qc.invalidateQueries({ queryKey: ['systemStats'] });
      qc.invalidateQueries({ queryKey: ['domains'] });
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Tranco List</h1>
          <p className="text-slate-400 mt-1">Popular-domain ranking used as the scanning population</p>
        </div>
        <button className="btn btn-primary" onClick={() => fetchMutation.mutate()} disabled={fetchMutation.isPending}>
          {fetchMutation.isPending ? <><Loader2 className="h-4 w-4 mr-2 inline animate-spin" />Fetching…</> : <><RefreshCw className="h-4 w-4 mr-2 inline" />Fetch &amp; Register</>}
        </button>
      </div>

      {fetchMutation.isSuccess && (
        <div className="card bg-green-500/10 border-green-500/30 flex items-center gap-3">
          <CheckCircle className="h-6 w-6 text-green-500" />
          <p className="text-green-400">{fetchMutation.data?.data?.domains ?? '—'} domains registered for adaptive scanning.</p>
        </div>
      )}

      <div className="card bg-primary-500/10 border-primary-500/30">
        <div className="flex items-start gap-4">
          <ListOrdered className="h-8 w-8 text-primary-500 flex-shrink-0" />
          <div>
            <h2 className="text-lg font-semibold">About the Tranco list</h2>
            <p className="text-slate-300 mt-2 text-sm">
              Tranco (tranco-list.eu) is a research-oriented ranking that aggregates Cisco Umbrella, Majestic,
              Farsight and Cloudflare Radar into a reproducible top-1M list. AHCLM downloads the real zipped CSV
              and registers the top-N domains (configurable) as the scanning population.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Latest Fetched List</h2>
          {isLoading ? (
            <div className="flex justify-center py-6"><div className="spinner" /></div>
          ) : latest ? (
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-slate-400">List ID</span><span>{latest.list_id}</span></div>
              <div className="flex justify-between"><span className="text-slate-400">Source</span>
                <span className={`status-badge ${latest.source === 'zip' ? 'good' : 'warning'}`}>{latest.source}</span></div>
              <div className="flex justify-between"><span className="text-slate-400">Domains registered</span><span>{latest.count.toLocaleString()}</span></div>
              <div className="flex justify-between"><span className="text-slate-400">Fetched</span><span>{fmtDateTime(latest.fetched_at)}</span></div>
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No list fetched yet. Click “Fetch &amp; Register”.</p>
          )}
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Current Population</h2>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-slate-400">Monitored domains</span><span>{stats?.total_domains ?? '—'}</span></div>
            <div className="flex justify-between"><span className="text-slate-400">Active</span><span>{stats?.active_domains ?? '—'}</span></div>
            <div className="flex justify-between"><span className="text-slate-400">Distinct certificates</span><span>{stats?.total_certificates ?? '—'}</span></div>
            <div className="flex justify-between"><span className="text-slate-400">Lifecycle events</span><span>{stats?.observations ?? '—'}</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}
