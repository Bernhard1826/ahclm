import { statusLabel } from '@/lib/labels';
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
          <h1 className="text-2xl font-bold text-white">Tranco 列表</h1>
          <p className="text-slate-400 mt-1">用作扫描样本的热门域名排名</p>
        </div>
        <button className="btn btn-primary" onClick={() => fetchMutation.mutate()} disabled={fetchMutation.isPending}>
          {fetchMutation.isPending ? <><Loader2 className="h-4 w-4 mr-2 inline animate-spin" />正在获取…</> : <><RefreshCw className="h-4 w-4 mr-2 inline" />获取并登记</>}
        </button>
      </div>

      {fetchMutation.isSuccess && (
        <div className="card bg-green-500/10 border-green-500/30 flex items-center gap-3">
          <CheckCircle className="h-6 w-6 text-green-500" />
          <p className="text-green-400">{fetchMutation.data?.data?.domains ?? '—'} 个域名已登记到自适应扫描。</p>
        </div>
      )}

      <div className="card bg-primary-500/10 border-primary-500/30">
        <div className="flex items-start gap-4">
          <ListOrdered className="h-8 w-8 text-primary-500 flex-shrink-0" />
          <div>
            <h2 className="text-lg font-semibold">关于 Tranco 列表</h2>
            <p className="text-slate-300 mt-2 text-sm">
              Tranco（tranco-list.eu）是面向研究的排名，汇总 Cisco Umbrella、Majestic、Farsight 和 Cloudflare Radar 数据，提供可复现的百万域名列表。AHCLM 下载压缩 CSV 文件，并将排名前 N 的域名登记为扫描样本（数量可配置）。
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">最近获取的列表</h2>
          {isLoading ? (
            <div className="flex justify-center py-6"><div className="spinner" /></div>
          ) : latest ? (
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-slate-400">列表编号</span><span>{latest.list_id}</span></div>
              <div className="flex justify-between"><span className="text-slate-400">来源</span>
                <span className={`status-badge ${latest.source === 'zip' ? 'good' : 'warning'}`}>{statusLabel(latest.source)}</span></div>
              <div className="flex justify-between"><span className="text-slate-400">已登记域名数</span><span>{latest.count.toLocaleString('zh-CN')}</span></div>
              <div className="flex justify-between"><span className="text-slate-400">获取时间</span><span>{fmtDateTime(latest.fetched_at)}</span></div>
            </div>
          ) : (
            <p className="text-slate-500 text-sm">尚未获取列表，请点击“获取并登记”。</p>
          )}
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-4">当前监测样本</h2>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-slate-400">监测域名</span><span>{stats?.total_domains ?? '—'}</span></div>
            <div className="flex justify-between"><span className="text-slate-400">活跃</span><span>{stats?.active_domains ?? '—'}</span></div>
            <div className="flex justify-between"><span className="text-slate-400">不同证书</span><span>{stats?.total_certificates ?? '—'}</span></div>
            <div className="flex justify-between"><span className="text-slate-400">生命周期事件</span><span>{stats?.observations ?? '—'}</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}
