import { useQuery } from '@tanstack/react-query';
import { Database, Scan, CalendarClock, ShieldCheck, Info } from 'lucide-react';
import { getSystemStats, getSchedulerStatus, getRuntimeConfig } from '@/api';

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between py-2 border-b border-slate-700/50 last:border-0">
      <span className="text-slate-400 text-sm">{label}</span>
      <span className="text-sm text-right">{value}</span>
    </div>
  );
}

export default function Settings() {
  const { data: stats } = useQuery({ queryKey: ['systemStats'], queryFn: async () => (await getSystemStats()).data });
  const { data: sched } = useQuery({ queryKey: ['schedulerStatus'], queryFn: async () => (await getSchedulerStatus()).data });
  const { data: config } = useQuery({ queryKey: ['runtimeConfig'], queryFn: async () => (await getRuntimeConfig()).data });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">设置</h1>
        <p className="text-slate-400 mt-1">当前生效的系统配置（通过 config.yaml 或环境变量设置）</p>
      </div>

      <div className="card bg-primary-500/10 border-primary-500/30 flex items-start gap-3">
        <Info className="h-5 w-5 text-primary-400 flex-shrink-0 mt-0.5" />
        <p className="text-sm text-slate-300">
          此处配置只读。修改 <code className="text-primary-300">ahclm_backend/config.yaml</code> （或 <code className="text-primary-300">AHCLM_*</code> 环境变量），然后重启后端使配置生效。
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><Database className="h-5 w-5 text-primary-500" /> 数据库</h2>
          <Field label="引擎" value="PostgreSQL" />
          <Field label="数据库" value={config?.database.database ?? '—'} />
          <Field label="主机与端口" value={config ? `${config.database.host} : ${config.database.port}` : '—'} />
          <Field label="大小" value={stats?.database_size ?? '—'} />
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><ShieldCheck className="h-5 w-5 text-primary-500" /> 吊销状态</h2>
          <Field label="OCSP（装订与主动查询）" value={config ? <span className={`status-badge ${config.scanner.check_revocation ? 'good' : 'warning'}`}>{config.scanner.check_revocation ? '已启用' : '已禁用'}</span> : '—'} />
          <Field label="CRL 回退检查" value={config ? <span className={`status-badge ${config.scanner.check_crl ? 'good' : 'warning'}`}>{config.scanner.check_crl ? '已启用' : '已禁用'}</span> : '—'} />
          <Field label="证书透明度（CT）" value={config ? <span className={`status-badge ${config.scanner.check_ct ? 'good' : 'warning'}`}>{config.scanner.check_ct ? '已启用' : '已禁用'}</span> : '—'} />
          <Field label="RDAP" value={config ? <span className={`status-badge ${config.scanner.check_rdap ? 'good' : 'warning'}`}>{config.scanner.check_rdap ? '已启用' : '已禁用'}</span> : '—'} />
          <Field label="ASN 目录" value={config ? <span className={`status-badge ${config.scanner.check_asn ? 'good' : 'warning'}`}>{config.scanner.check_asn ? '已启用' : '已禁用'}</span> : '—'} />
          <Field label="RIPEstat 路由" value={config ? <span className={`status-badge ${config.scanner.check_ripestat ? 'good' : 'warning'}`}>{config.scanner.check_ripestat ? '已启用' : '已禁用'}</span> : '—'} />
          <Field label="CDN 官方地址前缀" value={config ? <span className={`status-badge ${config.scanner.check_official_prefixes ? 'good' : 'warning'}`}>{config.scanner.check_official_prefixes ? `${config.scanner.official_cdn_prefixes ?? 0} 条已加载` : '已禁用'}</span> : '—'} />
          <Field label="Chrome CT 日志列表" value={config ? <span className={`status-badge ${config.scanner.check_chrome_log_list ? 'good' : 'warning'}`}>{config.scanner.check_chrome_log_list ? `${config.scanner.chrome_ct_logs ?? 0} 个日志` : '已禁用'}</span> : '—'} />
          <Field label="Apple CT 日志列表" value={config ? <span className={`status-badge ${config.scanner.check_apple_log_list ? 'good' : 'warning'}`}>{config.scanner.check_apple_log_list ? `${config.scanner.apple_ct_logs ?? 0} 个日志` : '已禁用'}</span> : '—'} />
          <Field label="SCT 包含性证明" value={config ? <span className={`status-badge ${config.scanner.check_sct_inclusion ? 'good' : 'warning'}`}>{config.scanner.check_sct_inclusion ? '已启用' : '已禁用'}</span> : '—'} />
          <Field label="CertSpotter CT 索引" value={config ? <span className={`status-badge ${config.scanner.check_certspotter ? 'good' : 'warning'}`}>{config.scanner.check_certspotter ? '已启用' : '已禁用'}</span> : '—'} />
          <Field label="说明" value={<span className="text-xs text-slate-500">Let’s Encrypt 需要 CRL 检查</span>} />
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><CalendarClock className="h-5 w-5 text-primary-500" /> 自适应调度器</h2>
          <Field label="状态" value={<span className={`status-badge ${sched?.paused ? 'warning' : 'good'}`}>{sched?.enabled ? (sched?.paused ? '已暂停' : '运行中') : '已禁用'}</span>} />
          <Field label="里程碑（到期前天数）" value={config?.scheduler.milestones?.join(', ') ?? '—'} />
          <Field label="到期后检查" value={config?.scheduler.post_expiry_checks?.join(', ') ?? '—'} />
          <Field label="基线扫描间隔" value={config?.scheduler.baseline_interval ?? '—'} />
          <Field label="临近到期间隔" value={config?.scheduler.near_expiry_interval ?? '—'} />
          <Field label="吊销证据检查间隔" value={config?.scheduler.revocation_poll_interval ?? '—'} />
          <Field label="待扫描" value={sched?.queue_status?.pending ?? '—'} />
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><Scan className="h-5 w-5 text-primary-500" /> 扫描器与监测样本</h2>
          <Field label="TLS 端口" value={config?.scanner.tls_port ?? '—'} />
          <Field label="扫描并发数" value={config?.scanner.workers ?? '—'} />
          <Field label="监测域名" value={stats?.total_domains ?? '—'} />
          <Field label="不同证书" value={stats?.total_certificates ?? '—'} />
          <Field label="生命周期观测数" value={stats?.observations ?? '—'} />
          <Field label="平均扫描耗时" value={stats ? `${Math.round(stats.average_scan_time_ms)} 毫秒` : '—'} />
          <Field label="今日扫描数" value={stats?.today_scans ?? '—'} />
        </div>
      </div>
    </div>
  );
}
