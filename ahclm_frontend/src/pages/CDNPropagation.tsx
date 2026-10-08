import { statusLabel, regionLabel } from '@/lib/labels';
import { explanationText } from '@/lib/explanations';
import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Activity, Check, Circle, Clock3, Loader2, Play, Radar, RefreshCw, X } from 'lucide-react';
import {
  cancelCDNPropagation,
  getCDNPropagationConfig,
  getCDNPropagationExperiments,
  getCDNPropagationReport,
  startCDNPropagation,
} from '@/api';
import type { CDNPropagationReport } from '@/types';

const continents = [
  ['AF', "非洲"], ['AS', "亚洲"], ['EU', "欧洲"],
  ['NA', "北美洲"], ['OC', "大洋洲"], ['SA', "南美洲"],
];

function timestamp(value?: string) {
  return value ? new Date(value).toLocaleString('zh-CN') : '-';
}

function duration(seconds?: number): string {
  if (seconds === undefined || !Number.isFinite(seconds)) return '-';
  if (seconds < 0) return `-${duration(-seconds)}`;
  if (seconds < 60) return `${seconds.toFixed(0)} 秒`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} 分钟`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} 小时`;
  return `${(seconds / 86400).toFixed(1)} 天`;
}

function lagBound(lower?: number, upper?: number): string {
  if (lower === undefined) return duration(upper);
  if (upper === undefined) return `${duration(lower)}+`;
  return `${duration(lower)} 至 ${duration(upper)}`;
}

function shortFingerprint(value?: string) {
  if (!value) return '-';
  return `${value.slice(0, 12)}...${value.slice(-8)}`;
}

function statusClass(status: string) {
  if (status === 'complete' || status === 'target' || status === 'synchronized' || status === 'origin_verified' || status === 'request_ok') return 'text-emerald-400';
  if (status === 'running' || status === 'watching' || status === 'changed' || status === 'in_progress' || status === 'mixed' || status === 'regional_lag') return 'text-amber-300';
  if (status === 'timeout' || status === 'failed' || status === 'incomplete' || status === 'provider_error' || status === 'provider_skipped') return 'text-red-400';
  if (status === 'canceled') return 'text-slate-400';
  return 'text-slate-400';
}

export default function CDNPropagation() {
  const qc = useQueryClient();
  const [selectedID, setSelectedID] = useState<number | null>(null);
  const [domain, setDomain] = useState('');
  const [vendor, setVendor] = useState('');
  const [certificateLayer, setCertificateLayer] = useState<'edge' | 'origin' | 'origin_via_cdn'>('edge');
  const [probeTarget, setProbeTarget] = useState('');
  const [probeHost, setProbeHost] = useState('');
  const [probePath, setProbePath] = useState('/.well-known/ahclm-origin');
  const [expectedHTTPStatus, setExpectedHTTPStatus] = useState(200);
  const [pollSeconds, setPollSeconds] = useState(30);
  const [watchChanges, setWatchChanges] = useState(true);
  const [previousFingerprint, setPreviousFingerprint] = useState('');
  const [targetFingerprint, setTargetFingerprint] = useState('');
  const [sourceUpdatedAt, setSourceUpdatedAt] = useState('');
  const [locations, setLocations] = useState<string[]>([]);
  const [formError, setFormError] = useState('');

  const configQuery = useQuery({ queryKey: ['cdnPropagationConfig'], queryFn: async () => (await getCDNPropagationConfig()).data });
  const listQuery = useQuery({
    queryKey: ['cdnPropagationExperiments'],
    queryFn: async () => (await getCDNPropagationExperiments()).data,
    refetchInterval: 15000,
  });
  const reportQuery = useQuery({
    queryKey: ['cdnPropagationReport', selectedID],
    queryFn: async () => (await getCDNPropagationReport(selectedID!)).data,
    enabled: selectedID !== null,
    refetchInterval: (query) => ['running', 'queued'].includes(query.state.data?.experiment.status ?? '') ? 15000 : false,
  });

  useEffect(() => {
    if (locations.length === 0 && configQuery.data?.locations?.length) setLocations(configQuery.data.locations);
  }, [configQuery.data, locations.length]);

  const startMutation = useMutation({
    mutationFn: () => startCDNPropagation({
      domain: domain.trim(),
      vendor: vendor.trim() || undefined,
      certificate_layer: certificateLayer,
      probe_target: certificateLayer === 'origin' ? probeTarget.trim() : domain.trim(),
      probe_host: certificateLayer === 'origin' ? probeHost.trim() : domain.trim(),
      probe_path: certificateLayer === 'origin_via_cdn' ? probePath.trim() : undefined,
      expected_http_status: certificateLayer === 'origin_via_cdn' ? expectedHTTPStatus : undefined,
      watch_changes: watchChanges,
      previous_fingerprint: watchChanges ? undefined : previousFingerprint.trim() || undefined,
      target_fingerprint: watchChanges ? undefined : targetFingerprint.trim().replace(/:/g, ''),
      source_updated_at: (certificateLayer === 'origin_via_cdn' || !watchChanges) && sourceUpdatedAt ? new Date(sourceUpdatedAt).toISOString() : undefined,
      source_time_basis: (certificateLayer === 'origin_via_cdn' || !watchChanges) && sourceUpdatedAt ? 'operator_input' : undefined,
      locations,
      poll_interval_seconds: certificateLayer === 'origin_via_cdn' ? pollSeconds : undefined,
      max_duration_seconds: certificateLayer === 'origin_via_cdn' ? 3600 : undefined,
    }),
    onSuccess: (response) => {
      const report = response.data as CDNPropagationReport | undefined;
      if (report) setSelectedID(report.experiment.id);
      setFormError('');
      qc.invalidateQueries({ queryKey: ['cdnPropagationExperiments'] });
      qc.invalidateQueries({ queryKey: ['cdnPropagationReport'] });
    },
    onError: (error: Error) => setFormError(error.message),
  });

  const cancelMutation = useMutation({
    mutationFn: (id: number) => cancelCDNPropagation(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cdnPropagationExperiments'] });
      qc.invalidateQueries({ queryKey: ['cdnPropagationReport', selectedID] });
    },
  });

  const report = reportQuery.data as CDNPropagationReport | undefined;
  const experiments = listQuery.data?.experiments ?? [];
  const selected = report?.experiment;
  const isSelectedOriginViaCDN = selected?.certificate_layer === 'origin_via_cdn';
  const latencyOrigin = selected?.watch_changes ? "监测启动" : ['operator_input', 'origin_reload'].includes(selected?.source_time_basis ?? '') ? "源证书更新" : "监测观测";
  const validFingerprint = /^(?:[a-fA-F0-9]{64}|(?:[a-fA-F0-9]{2}:){31}[a-fA-F0-9]{2})$/.test(targetFingerprint.trim());
  const isOriginViaCDN = certificateLayer === 'origin_via_cdn';
  const validOrigin = certificateLayer === 'edge' || (certificateLayer === 'origin' ? probeTarget.trim() && probeHost.trim() : probePath.trim().startsWith('/') && sourceUpdatedAt && expectedHTTPStatus >= 200 && expectedHTTPStatus <= 399 && pollSeconds >= 30 && pollSeconds <= 86400);
  const canStart = Boolean(domain.trim() && validOrigin && (watchChanges || validFingerprint) && locations.length > 0 && !startMutation.isPending);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Radar className="h-6 w-6 text-cyan-400" /> CDN 传播</h1>
        </div>
        <button
          type="button"
          className="btn btn-secondary text-sm"
          onClick={() => { qc.invalidateQueries({ queryKey: ['cdnPropagationExperiments'] }); if (selectedID) qc.invalidateQueries({ queryKey: ['cdnPropagationReport', selectedID] }); }}
          title="刷新测量记录"
        ><RefreshCw className="h-4 w-4 mr-2 inline" />刷新</button>
      </div>

      {configQuery.isError && <div role="alert" className="border-l-2 border-amber-400 pl-3 text-sm text-amber-300">无法访问当前后端的传播测量接口。</div>}
      {listQuery.isError && <div role="alert" className="border-l-2 border-red-400 pl-3 text-sm text-red-300">无法加载实验： {(listQuery.error as Error).message}</div>}

      <section className="card">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-700 pb-3 mb-4">
          <h2 className="font-semibold flex items-center gap-2"><Play className="h-4 w-4 text-cyan-400" /> 启动测量</h2>
          <span className="text-xs text-slate-400">{configQuery.data?.provider ?? 'Globalping'} / {configQuery.data?.poll_interval_seconds ? `每 ${duration(configQuery.data.poll_interval_seconds)}` : "按配置轮询"}</span>
        </div>
        <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); setFormError(''); startMutation.mutate(); }}>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
            <label className="text-sm text-slate-300">域名
              <input className="input mt-1" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="www.example.com" autoComplete="url" />
            </label>
            <label className="text-sm text-slate-300">CDN 服务商
              <input className="input mt-1" value={vendor} onChange={(event) => setVendor(event.target.value)} placeholder="可选" />
            </label>
            <label className="text-sm text-slate-300">证书层级
              <select className="input mt-1" value={certificateLayer} onChange={(event) => { const layer = event.target.value as 'edge' | 'origin' | 'origin_via_cdn'; setCertificateLayer(layer); if (layer === 'origin_via_cdn') setWatchChanges(false); }}>
                <option value="edge">CDN 边缘证书</option><option value="origin">源站证书（直连）</option><option value="origin_via_cdn">CDN 回源请求</option>
              </select>
            </label>
            {!isOriginViaCDN && <label className="inline-flex items-center gap-2 text-sm text-slate-300 self-end pb-2">
              <input type="checkbox" className="accent-cyan-500" checked={watchChanges} onChange={(event) => setWatchChanges(event.target.checked)} />监测尚未知晓的证书变更
            </label>}
          </div>
          {certificateLayer === 'origin' && <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-sm text-slate-300">源站公网 IP
              <input className="input mt-1 font-mono" value={probeTarget} onChange={(event) => setProbeTarget(event.target.value)} placeholder="203.0.113.10" />
            </label>
            <label className="text-sm text-slate-300">源站主机名（TLS SNI 与 HTTP Host）
              <input className="input mt-1" value={probeHost} onChange={(event) => setProbeHost(event.target.value)} placeholder="origin.example.com" />
            </label>
          </div>}
          {isOriginViaCDN && <>
            <div className="grid grid-cols-1 md:grid-cols-[minmax(260px,1fr)_180px] gap-3">
              <label className="text-sm text-slate-300">源站证书核验路径
                <input className="input mt-1 font-mono" value={probePath} onChange={(event) => setProbePath(event.target.value)} placeholder="/healthz" />
              </label>
              <label className="text-sm text-slate-300">期望 HTTP 状态码
                <input className="input mt-1" type="number" min={200} max={399} value={expectedHTTPStatus} onChange={(event) => setExpectedHTTPStatus(Number(event.target.value))} />
              </label>
            </div>
            <label className="block text-sm text-slate-300">探测间隔（秒，至少 30；最长运行 1 小时）<input className="input mt-1 max-w-40 block" type="number" min={30} max={86400} value={pollSeconds} onChange={(event) => setPollSeconds(Number(event.target.value))} /></label>
            <p className="text-xs text-slate-400">请部署项目提供的源站探测端点，并在 CDN 禁用该路径的缓存、启用严格回源 TLS 验证。系统核验随机标记和连接证书指纹；HTTP 成功本身不算换证成功。</p>
          </>}
          {!watchChanges && <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-sm text-slate-300">前任证书 SHA-256
              <input className="input mt-1 font-mono text-xs" value={previousFingerprint} onChange={(event) => setPreviousFingerprint(event.target.value)} placeholder="可选；64 位十六进制字符" />
            </label>
            <label className="text-sm text-slate-300">{isOriginViaCDN ? "目标源站证书 SHA-256" : "目标证书 SHA-256"}
              <input className="input mt-1 font-mono text-xs" value={targetFingerprint} onChange={(event) => setTargetFingerprint(event.target.value)} placeholder="64 位十六进制字符" />
            </label>
          </div>}
          <div className="grid grid-cols-1 md:grid-cols-[minmax(260px,1fr)_2fr_auto] gap-4 items-end">
            {(!watchChanges || isOriginViaCDN) && <label className="text-sm text-slate-300">源证书更新时间
              <input className="input mt-1" type="datetime-local" step="0.001" value={sourceUpdatedAt} onChange={(event) => setSourceUpdatedAt(event.target.value)} />
            </label>}
            <fieldset>
              <legend className="text-sm text-slate-300 mb-2">探测地区</legend>
              <div className="flex flex-wrap gap-x-4 gap-y-2">
                {continents.map(([code, name]) => (
                  <label key={code} className="inline-flex items-center gap-2 text-sm text-slate-300">
                    <input type="checkbox" className="accent-cyan-500" checked={locations.includes(code)} onChange={(event) => setLocations((current) => event.target.checked ? [...new Set([...current, code])].sort() : current.filter((item) => item !== code))} />
                    {name}
                  </label>
                ))}
              </div>
            </fieldset>
            <button type="submit" className="btn btn-primary min-w-40" disabled={!canStart}>
              {startMutation.isPending ? <><Loader2 className="h-4 w-4 mr-2 inline animate-spin" />正在启动</> : <><Play className="h-4 w-4 mr-2 inline" />启动</>}
            </button>
          </div>
          {formError && <p role="alert" className="text-sm text-red-400">{formError}</p>}
          {!configQuery.data?.enabled && <p className="text-xs text-amber-300">自动实验已禁用，仍可手动启动测量。</p>}
        </form>
      </section>

      <section className="card p-0 overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
          <h2 className="font-semibold">实验</h2>
          <span className="text-xs text-slate-400">{experiments.length} 条记录</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[760px]">
            <thead className="text-slate-400 border-b border-slate-700">
              <tr><th className="text-left p-3">域名</th><th className="text-left p-3">状态</th><th className="text-left p-3">地区</th><th className="text-left p-3">尝试次数</th><th className="text-left p-3">最近测量</th><th className="text-left p-3">源时间依据</th><th className="text-left p-3">开始时间</th><th className="p-3" /></tr>
            </thead>
            <tbody>
              {experiments.map((item) => (
                <tr key={item.id} className={`border-b border-slate-800 cursor-pointer hover:bg-slate-800/60 ${selectedID === item.id ? 'bg-slate-800/70' : ''}`} onClick={() => setSelectedID(item.id)}>
                  <td className="p-3 text-slate-100">{item.domain}{item.vendor ? <span className="text-slate-500 ml-2">{item.vendor}</span> : null}<span className="text-slate-500 ml-2">{statusLabel(item.certificate_layer || 'edge')}</span></td>
                  <td className={`p-3 capitalize ${statusClass(item.status)}`}>
                    {item.status === 'running' && item.last_error ? "等待探测服务" : statusLabel(item.status)}
                    {item.last_error && <span className="block max-w-[280px] truncate text-xs font-normal text-red-300" title={item.last_error}>{item.last_error}</span>}
                  </td>
                  <td className="p-3 text-slate-300">{item.target_locations}/{item.expected_locations}</td>
                  <td className="p-3 text-slate-300">{item.rounds} <span className="text-slate-500">（{item.stable_rounds}/{item.stable_rounds_required} 轮稳定）</span></td>
                  <td className="p-3 text-slate-400">{timestamp(item.last_measured_at)}</td>
                  <td className="p-3 text-slate-400">{statusLabel(item.source_time_basis)}</td>
                  <td className="p-3 text-slate-400">{timestamp(item.started_at)}</td>
                  <td className="p-3 text-right">{(item.status === 'running' || item.status === 'queued') && <button type="button" title="取消实验" className="p-1 text-slate-400 hover:text-red-400" onClick={(event) => { event.stopPropagation(); cancelMutation.mutate(item.id); }}><X className="h-4 w-4" /></button>}</td>
                </tr>
              ))}
              {experiments.length === 0 && <tr><td colSpan={8} className="p-8 text-center text-slate-500">暂无传播实验。</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      {reportQuery.isLoading && <div className="card text-slate-400 flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" />正在加载报告</div>}
      {reportQuery.isError && <div role="alert" className="card text-red-400">{(reportQuery.error as Error).message}</div>}
      {report && selected && (
        <section className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-700 pb-3">
            <div>
              <h2 className="text-lg font-semibold text-white">{selected.domain}</h2>
              <p className="text-xs text-slate-400">{isSelectedOriginViaCDN ? `经 CDN GET ${selected.probe_path} / 期望 HTTP ${selected.expected_http_status}` : selected.certificate_layer === 'origin' ? `源站 ${selected.probe_target} / SNI ${selected.probe_host}` : "CDN 边缘"} / {selected.watch_changes ? "基线监测" : isSelectedOriginViaCDN ? "源证书更新时间" : `目标证书 ${shortFingerprint(selected.target_fingerprint)}`} / {timestamp(selected.source_updated_at)} ({statusLabel(selected.source_time_basis)})</p>
            </div>
            <div className={`flex items-center gap-2 text-sm font-medium ${statusClass(report.sync_state)}`}>
              {report.sync_state === 'synchronized' ? <Check className="h-4 w-4" /> : report.sync_state === 'in_progress' ? <Circle className="h-3 w-3 fill-current" /> : <Activity className="h-4 w-4" />}
              {statusLabel(report.sync_state)}
            </div>
          </div>
          <p className="text-sm text-slate-300">{explanationText(report.interpretation)}</p>
          <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-400">
            <span>创建时间： {timestamp(selected.created_at)}</span>
            <span>开始探测： {selected.status === 'queued' ? '等待名额' : timestamp(selected.started_at)}</span>
            <span>最近尝试： {timestamp(selected.last_attempted_at)}</span>
            <span>最近成功测量： {timestamp(selected.last_measured_at)}</span>
            {selected.last_error && <span className="max-w-full text-red-300" title={selected.last_error}>服务商状态： {selected.last_error}</span>}
          </div>
          {selected.watch_changes && <div className="overflow-x-auto border-y border-slate-700">
            <table className="w-full text-sm min-w-[760px]"><thead className="text-slate-400 border-b border-slate-700"><tr><th className="text-left py-2 pr-3">旧叶证书</th><th className="text-left py-2 pr-3">新叶证书</th><th className="text-left py-2 pr-3">首次观测</th><th className="text-left py-2 pr-3">地区</th><th className="text-left py-2">观测传播范围</th></tr></thead><tbody>
              {(report.changes ?? []).map((change, index) => <tr key={`${change.previous_fingerprint}-${change.fingerprint}-${index}`} className="border-b border-slate-800"><td className="py-2 pr-3 font-mono text-xs">{shortFingerprint(change.previous_fingerprint)}</td><td className="py-2 pr-3 font-mono text-xs">{shortFingerprint(change.fingerprint)}</td><td className="py-2 pr-3">{timestamp(change.first_seen_at)}</td><td className="py-2 pr-3">{change.regions.map(regionLabel).join('、')}</td><td className="py-2">{duration(change.first_seen_spread_seconds)}</td></tr>)}
              {(report.changes ?? []).length === 0 && <tr><td colSpan={5} className="py-3 text-center text-slate-500">尚未观测到叶证书变更；首个成功轮次用于建立各地区基线。</td></tr>}
            </tbody></table>
          </div>}
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
            {[
              [`${latencyOrigin}至首个${isSelectedOriginViaCDN ? '核验成功' : ''}地区`, duration(report.source_to_first_seconds)],
              [`${latencyOrigin}至所有${isSelectedOriginViaCDN ? '核验成功' : ''}地区`, duration(report.source_to_all_regions_seconds)],
              [`${latencyOrigin}至稳定确认`, duration(report.source_to_complete_seconds)],
              [isSelectedOriginViaCDN ? "地区首次核验时间差" : "地区首次观测时间差", duration(report.synchronization_spread_seconds)],
              [isSelectedOriginViaCDN ? "当前核验成功地区" : "当前目标覆盖率", `${selected.target_locations}/${selected.expected_locations}`],
            ].map(([label, value]) => <div key={label} className="border-l-2 border-cyan-500 pl-3 py-1"><p className="text-xs text-slate-400">{label}</p><p className="mt-1 text-lg font-semibold text-white">{value}</p></div>)}
          </div>

          <div className="overflow-x-auto border-y border-slate-700">
            <table className="w-full text-sm min-w-[920px]">
              <thead className="text-slate-400 border-b border-slate-700"><tr><th className="text-left py-2 pr-3">地区</th><th className="text-left py-2 pr-3">最新状态</th><th className="text-left py-2 pr-3">{isSelectedOriginViaCDN ? "首次核验新证书" : "首次看到目标证书"}</th><th className="text-left py-2 pr-3">{isSelectedOriginViaCDN ? "最近 HTTP 状态" : "末次看到前任证书"}</th><th className="text-left py-2 pr-3">观测延迟界限</th><th className="text-left py-2 pr-3">{isSelectedOriginViaCDN ? "源站连接证书指纹" : "最新指纹"}</th><th className="text-right py-2">响应轮次</th></tr></thead>
              <tbody>
                {report.locations.map((item) => (
                  <tr key={item.location_key} className="border-b border-slate-800">
                    <td className="py-2 pr-3 text-slate-100">{regionLabel(item.continent || item.location_key)}<span className="ml-2 text-xs text-slate-500">{[item.city, item.country, item.network].filter(Boolean).join(' / ')}</span></td>
                    <td className={`py-2 pr-3 capitalize ${statusClass(item.state)}`}>{statusLabel(item.state)}{item.last_error && <span className="block text-xs text-slate-400 max-w-64" title={item.last_error}>{explanationText(item.last_error)}</span>}</td>
                    <td className="py-2 pr-3 text-slate-300">{timestamp(item.first_target_at)}</td>
                    <td className="py-2 pr-3 text-slate-300">{isSelectedOriginViaCDN ? item.last_http_status || '-' : timestamp(item.last_previous_at)}</td>
                    <td className="py-2 pr-3 text-slate-300">{lagBound(item.latency_lower_seconds, item.latency_seconds)}</td>
                    <td className="py-2 pr-3 font-mono text-xs text-slate-400" title={isSelectedOriginViaCDN ? item.last_origin_fingerprint : item.latest_fingerprint}>{shortFingerprint(isSelectedOriginViaCDN ? item.last_origin_fingerprint ?? '' : item.latest_fingerprint)}</td>
                    <td className="py-2 text-right text-slate-300">{item.answered_rounds}</td>
                  </tr>
                ))}
                {report.locations.length === 0 && <tr><td colSpan={7} className="py-6 text-center text-slate-500">等待首轮地区测量。</td></tr>}
              </tbody>
            </table>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-2 flex items-center gap-2"><Clock3 className="h-4 w-4 text-cyan-400" /> 最近轮次</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm min-w-[640px]">
                <thead className="text-slate-500 border-b border-slate-800"><tr><th className="text-left py-2 pr-3">尝试时间</th><th className="text-left py-2 pr-3">观测</th><th className="text-left py-2 pr-3">结果</th><th className="text-right py-2 pr-3">{isSelectedOriginViaCDN ? "成功地区" : "目标证书地区"}</th><th className="text-right py-2 pr-3">{isSelectedOriginViaCDN ? "未核验地区" : "前任证书地区"}</th><th className="text-right py-2">已响应</th></tr></thead>
                <tbody>
                  {[...report.rounds].reverse().slice(0, 12).map((round) => <tr key={round.id} className="border-b border-slate-800"><td className="py-2 pr-3 text-slate-300">#{round.round_number}</td><td className="py-2 pr-3 text-slate-400">{timestamp(round.observed_at)}</td><td title={round.error} className={`py-2 pr-3 ${round.complete ? 'text-emerald-400' : statusClass(round.status)}`}>{statusLabel(round.status)}{round.error && <span className="block max-w-[520px] truncate text-xs font-normal text-red-300">{round.error}</span>}</td><td className="py-2 pr-3 text-right text-slate-300">{round.target_count}/{round.expected_count}</td><td className="py-2 pr-3 text-right text-slate-300">{isSelectedOriginViaCDN ? round.expected_count - round.target_count : round.previous_count}</td><td className="py-2 text-right text-slate-300">{round.answered_count}</td></tr>)}
                  {report.rounds.length === 0 && <tr><td colSpan={6} className="py-5 text-center text-slate-500">尚未采集轮次。</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
