import { statusLabel, reasonLabel } from '@/lib/labels';
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Scan, Play, Pause, Clock, CheckCircle, XCircle, Loader2, ListOrdered } from 'lucide-react';
import {
  scanDomain,
  scanBatch,
  getScanStatus,
  getScanJobs,
  getSchedulerStatus,
  getRuntimeConfig,
  pauseScheduler,
  resumeScheduler,
  triggerTranco,
} from '@/api';
import type { ScanResult } from '@/types';

function ms(ns?: number) {
  return ns ? Math.round(ns / 1e6) : '—';
}

export default function Scanning() {
  const qc = useQueryClient();
  const [domain, setDomain] = useState('');
  const [batchDomains, setBatchDomains] = useState('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [batchResults, setBatchResults] = useState<ScanResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  const { data: scanStatus } = useQuery({
    queryKey: ['scanStatus'],
    queryFn: async () => (await getScanStatus()).data,
    refetchInterval: 5000,
  });
  const { data: sched } = useQuery({
    queryKey: ['schedulerStatus'],
    queryFn: async () => (await getSchedulerStatus()).data,
    refetchInterval: 10000,
  });
  const { data: runtimeConfig } = useQuery({
    queryKey: ['runtimeConfig'],
    queryFn: async () => (await getRuntimeConfig()).data,
  });
  const { data: recentJobs } = useQuery({
    queryKey: ['scanJobs'],
    queryFn: async () => (await getScanJobs(10)).data,
    refetchInterval: 5000,
  });

  const scanMutation = useMutation({
    mutationFn: (d: string) => scanDomain(d),
    onSuccess: (res) => {
      if (res.success && res.data) { setScanResult(res.data); setError(null); }
      else setError(res.error || "扫描失败");
      qc.invalidateQueries({ queryKey: ['scanStatus'] });
      qc.invalidateQueries({ queryKey: ['scanJobs'] });
    },
    onError: (e: Error) => setError(e.message),
  });

  const batchMutation = useMutation({
    mutationFn: (domains: string[]) => {
      const workers = runtimeConfig?.scanner.workers;
      if (!workers) return Promise.reject(new Error("扫描器配置暂不可用"));
      return scanBatch(domains, workers);
    },
    onSuccess: (res) => {
      if (res.success && res.data) setBatchResults(res.data.results || []);
      qc.invalidateQueries({ queryKey: ['scanStatus'] });
      qc.invalidateQueries({ queryKey: ['scanJobs'] });
    },
  });

  const pauseMutation = useMutation({ mutationFn: () => pauseScheduler(), onSuccess: () => qc.invalidateQueries({ queryKey: ['schedulerStatus'] }) });
  const resumeMutation = useMutation({ mutationFn: () => resumeScheduler(), onSuccess: () => qc.invalidateQueries({ queryKey: ['schedulerStatus'] }) });
  const trancoMutation = useMutation({ mutationFn: () => triggerTranco(), onSuccess: () => qc.invalidateQueries({ queryKey: ['scanStatus'] }) });

  const paused = sched?.paused ?? false;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">扫描</h1>
        <p className="text-slate-400 mt-1">手动扫描证书并控制自适应调度器</p>
      </div>

      {/* Queue + controls */}
      <div className="card">
        <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Clock className="h-5 w-5 text-primary-500" /> 扫描队列
          </h2>
          <div className="flex gap-2">
            <button
              onClick={() => (paused ? resumeMutation.mutate() : pauseMutation.mutate())}
              className="btn btn-secondary text-sm"
              disabled={pauseMutation.isPending || resumeMutation.isPending}
            >
              {paused ? <Play className="h-4 w-4 mr-1 inline" /> : <Pause className="h-4 w-4 mr-1 inline" />}
              {paused ? "恢复调度器" : "暂停调度器"}
            </button>
            <button onClick={() => trancoMutation.mutate()} className="btn btn-primary text-sm" disabled={trancoMutation.isPending}>
              {trancoMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 inline animate-spin" /> : <ListOrdered className="h-4 w-4 mr-1 inline" />}
              获取 Tranco 列表
            </button>
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
          {[["待处理", scanStatus?.pending, 'text-primary-400'], ["运行中", scanStatus?.running, 'text-blue-400'],
            ["已完成", scanStatus?.completed, 'text-green-400'], ["失败", scanStatus?.failed, 'text-red-400']].map(
            ([label, val, color]) => (
              <div key={label as string} className="p-4 bg-slate-700/50 rounded-lg">
                <p className={`text-2xl font-bold ${color}`}>{(val as number | undefined) ?? '—'}</p>
                <p className="text-xs text-slate-400">{label}</p>
              </div>
            )
          )}
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <ListOrdered className="h-5 w-5 text-primary-500" /> 最近扫描任务
          </h2>
          <span className="text-xs text-slate-500">已保存的审计记录</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-sm">
            <thead className="text-slate-400 border-b border-slate-700">
              <tr>
                <th className="text-left py-2 pr-3">域名</th>
                <th className="text-left py-2 pr-3">原因</th>
                <th className="text-left py-2 pr-3">状态</th>
                <th className="text-left py-2 pr-3">开始时间</th>
                <th className="text-left py-2">证书</th>
              </tr>
            </thead>
            <tbody>
              {(recentJobs?.jobs ?? []).map((job) => (
                <tr key={job.id} className="border-b border-slate-800">
                  <td className="py-2 pr-3 text-slate-200">{job.domain}</td>
                  <td className="py-2 pr-3 text-slate-400">{reasonLabel(job.reason)}</td>
                  <td className="py-2 pr-3">
                    <span className={`status-badge ${job.success ? 'good' : job.status === 'failed' ? 'revoked' : 'unknown'}`}>
                      {statusLabel(job.status)}
                    </span>
                  </td>
                  <td className="py-2 pr-3 text-xs text-slate-500">
                    {new Date(job.started_at ?? job.scheduled_at).toLocaleString('zh-CN')}
                  </td>
                  <td className="py-2 text-xs text-slate-500 font-mono">
                    {job.fingerprint
                      ? `${job.fingerprint.slice(0, 12)}…`
                      : job.error
                        ? `${job.failure_class ? `[${job.failure_class}] ` : ''}${job.error}`
                        : '—'}
                  </td>
                </tr>
              ))}
              {(recentJobs?.jobs ?? []).length === 0 && (
                <tr><td colSpan={5} className="py-6 text-center text-slate-500">尚无扫描任务记录。</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Single scan */}
        <div className="card">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><Scan className="h-5 w-5 text-primary-500" /> 单域名扫描</h2>
          <div className="space-y-4">
            <input className="input" value={domain} onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && domain.trim() && scanMutation.mutate(domain.trim())}
              placeholder="输入已授权的域名" />
            <button className="btn btn-primary w-full" disabled={scanMutation.isPending || !domain.trim()}
              onClick={() => { setScanResult(null); setError(null); scanMutation.mutate(domain.trim()); }}>
              {scanMutation.isPending ? <><Loader2 className="h-4 w-4 mr-2 inline animate-spin" />正在扫描…</> : <><Scan className="h-4 w-4 mr-2 inline" />立即扫描</>}
            </button>

            {error && (
              <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-2 text-red-400">
                <XCircle className="h-5 w-5" /><p>{error}</p>
              </div>
            )}

            {scanResult?.success && scanResult.certificate && (
              <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/30 space-y-2 text-sm">
                <div className="flex items-center gap-2 text-green-400 mb-1"><CheckCircle className="h-5 w-5" /><span className="font-medium">扫描成功</span></div>
                <div className="flex justify-between"><span className="text-slate-400">签发者</span><span className="truncate max-w-[220px]">{scanResult.certificate.issuer_cn}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">到期时间</span><span>{new Date(scanResult.certificate.not_after).toLocaleDateString('zh-CN')}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">吊销状态</span><span className={`status-badge ${scanResult.revocation_status}`}>{statusLabel(scanResult.revocation_status)}{scanResult.revocation_checked_via && scanResult.revocation_checked_via !== 'none' ? ` (${scanResult.revocation_checked_via})` : ''}</span></div>
                <div className="flex justify-between gap-3"><span className="text-slate-400">证据状态</span><span className="status-badge unknown">{statusLabel(scanResult.evidence_status)}</span></div>
                {scanResult.evidence_pending_reason && <div className="text-xs text-amber-300">{scanResult.evidence_pending_reason}</div>}
                <div className="flex justify-between"><span className="text-slate-400">TLS</span><span>{scanResult.connection_info?.tls_version} • {scanResult.connection_info?.cipher_suite}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">耗时</span><span>{ms(scanResult.scan_duration)}{scanResult.scan_duration ? ' 毫秒' : ''}</span></div>
              </div>
            )}
            {scanResult && !scanResult.success && (
              <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-2 text-red-400">
                <XCircle className="h-5 w-5" /><span>扫描失败： {scanResult.error}</span>
              </div>
            )}
          </div>
        </div>

        {/* Batch */}
        <div className="card">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><Scan className="h-5 w-5 text-primary-500" /> 批量扫描</h2>
          <div className="space-y-4">
            <textarea className="input h-40 resize-none" value={batchDomains} onChange={(e) => setBatchDomains(e.target.value)}
              placeholder="粘贴已授权的域名，每行一个" />
            <button className="btn btn-primary w-full" disabled={batchMutation.isPending || !batchDomains.trim() || !runtimeConfig?.scanner.workers}
              onClick={() => { setBatchResults([]); batchMutation.mutate(batchDomains.split('\n').map((d) => d.trim()).filter(Boolean)); }}>
              {batchMutation.isPending ? <><Loader2 className="h-4 w-4 mr-2 inline animate-spin" />正在扫描…</> : <><Scan className="h-4 w-4 mr-2 inline" />开始批量扫描</>}
            </button>
            {batchResults.length > 0 && (
              <div className="max-h-80 overflow-y-auto space-y-2">
                {batchResults.map((r, i) => (
                  <div key={i} className={`flex items-center gap-2 p-2 rounded ${r.success ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
                    {r.success ? <CheckCircle className="h-4 w-4 text-green-400" /> : <XCircle className="h-4 w-4 text-red-400" />}
                    <span className="text-sm flex-1">{r.domain}</span>
                    {r.success ? <span className={`status-badge ${r.revocation_status}`}>{statusLabel(r.revocation_status)}</span>
                      : <span className="text-xs text-red-400 truncate max-w-[150px]">{r.error}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
