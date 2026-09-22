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
        <h1 className="text-2xl font-bold text-white">Configuration</h1>
        <p className="text-slate-400 mt-1">Effective system configuration (set via config.yaml / environment)</p>
      </div>

      <div className="card bg-primary-500/10 border-primary-500/30 flex items-start gap-3">
        <Info className="h-5 w-5 text-primary-400 flex-shrink-0 mt-0.5" />
        <p className="text-sm text-slate-300">
          Settings are read-only here. Edit <code className="text-primary-300">ahclm_backend/config.yaml</code> (or
          the <code className="text-primary-300">AHCLM_*</code> environment variables) and restart the backend to change them.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><Database className="h-5 w-5 text-primary-500" /> Database</h2>
          <Field label="Engine" value="PostgreSQL" />
          <Field label="Database" value={config?.database.database ?? '—'} />
          <Field label="Host : Port" value={config ? `${config.database.host} : ${config.database.port}` : '—'} />
          <Field label="Size" value={stats?.database_size ?? '—'} />
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><ShieldCheck className="h-5 w-5 text-primary-500" /> Revocation</h2>
          <Field label="OCSP (stapled + active)" value={config ? <span className={`status-badge ${config.scanner.check_revocation ? 'good' : 'warning'}`}>{config.scanner.check_revocation ? 'enabled' : 'disabled'}</span> : '—'} />
          <Field label="CRL fallback" value={config ? <span className={`status-badge ${config.scanner.check_crl ? 'good' : 'warning'}`}>{config.scanner.check_crl ? 'enabled' : 'disabled'}</span> : '—'} />
          <Field label="Certificate Transparency" value={config ? <span className={`status-badge ${config.scanner.check_ct ? 'good' : 'warning'}`}>{config.scanner.check_ct ? 'enabled' : 'disabled'}</span> : '—'} />
          <Field label="RDAP" value={config ? <span className={`status-badge ${config.scanner.check_rdap ? 'good' : 'warning'}`}>{config.scanner.check_rdap ? 'enabled' : 'disabled'}</span> : '—'} />
          <Field label="ASN directory" value={config ? <span className={`status-badge ${config.scanner.check_asn ? 'good' : 'warning'}`}>{config.scanner.check_asn ? 'enabled' : 'disabled'}</span> : '—'} />
          <Field label="RIPEstat routing" value={config ? <span className={`status-badge ${config.scanner.check_ripestat ? 'good' : 'warning'}`}>{config.scanner.check_ripestat ? 'enabled' : 'disabled'}</span> : '—'} />
          <Field label="Official CDN prefixes" value={config ? <span className={`status-badge ${config.scanner.check_official_prefixes ? 'good' : 'warning'}`}>{config.scanner.check_official_prefixes ? `${config.scanner.official_cdn_prefixes ?? 0} loaded` : 'disabled'}</span> : '—'} />
          <Field label="Chrome CT log list" value={config ? <span className={`status-badge ${config.scanner.check_chrome_log_list ? 'good' : 'warning'}`}>{config.scanner.check_chrome_log_list ? `${config.scanner.chrome_ct_logs ?? 0} logs` : 'disabled'}</span> : '—'} />
          <Field label="Apple CT log list" value={config ? <span className={`status-badge ${config.scanner.check_apple_log_list ? 'good' : 'warning'}`}>{config.scanner.check_apple_log_list ? `${config.scanner.apple_ct_logs ?? 0} logs` : 'disabled'}</span> : '—'} />
          <Field label="SCT inclusion proofs" value={config ? <span className={`status-badge ${config.scanner.check_sct_inclusion ? 'good' : 'warning'}`}>{config.scanner.check_sct_inclusion ? 'enabled' : 'disabled'}</span> : '—'} />
          <Field label="CertSpotter CT index" value={config ? <span className={`status-badge ${config.scanner.check_certspotter ? 'good' : 'warning'}`}>{config.scanner.check_certspotter ? 'enabled' : 'disabled'}</span> : '—'} />
          <Field label="Note" value={<span className="text-xs text-slate-500">CRL required for Let’s Encrypt</span>} />
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><CalendarClock className="h-5 w-5 text-primary-500" /> Adaptive Scheduler</h2>
          <Field label="Status" value={<span className={`status-badge ${sched?.paused ? 'warning' : 'good'}`}>{sched?.enabled ? (sched?.paused ? 'paused' : 'running') : 'disabled'}</span>} />
          <Field label="Milestones (days before expiry)" value={config?.scheduler.milestones?.join(', ') ?? '—'} />
          <Field label="Post-expiry checks" value={config?.scheduler.post_expiry_checks?.join(', ') ?? '—'} />
          <Field label="Baseline cadence" value={config?.scheduler.baseline_interval ?? '—'} />
          <Field label="Near-expiry cadence" value={config?.scheduler.near_expiry_interval ?? '—'} />
          <Field label="Revocation evidence cadence" value={config?.scheduler.revocation_poll_interval ?? '—'} />
          <Field label="Due now" value={sched?.queue_status?.pending ?? '—'} />
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><Scan className="h-5 w-5 text-primary-500" /> Scanner &amp; Population</h2>
          <Field label="TLS port" value={config?.scanner.tls_port ?? '—'} />
          <Field label="Scanner workers" value={config?.scanner.workers ?? '—'} />
          <Field label="Monitored domains" value={stats?.total_domains ?? '—'} />
          <Field label="Distinct certificates" value={stats?.total_certificates ?? '—'} />
          <Field label="Lifecycle observations" value={stats?.observations ?? '—'} />
          <Field label="Avg scan time" value={stats ? `${Math.round(stats.average_scan_time_ms)} ms` : '—'} />
          <Field label="Today’s scans" value={stats?.today_scans ?? '—'} />
        </div>
      </div>
    </div>
  );
}
