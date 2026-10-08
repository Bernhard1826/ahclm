import { useEffect, useMemo, useState } from 'react';
import { FlaskConical, Play, RotateCcw } from 'lucide-react';
import { useMutation } from '@tanstack/react-query';
import { runDeepDiagnosis } from '@/api';
import type { DeepDiagnosisReport, MeasurementSnapshot } from '@/types';
import { shortFp } from '@/lib/format';
import { explanationText } from '@/lib/explanations';

type Experiment = 'sni_selection' | 'repeat_handshake' | 'http_route';

const EXPERIMENTS: Array<{ value: Experiment; label: string }> = [
  { value: 'sni_selection', label: "带 SNI 与空 SNI 对照" },
  { value: 'repeat_handshake', label: "重复握手" },
  { value: 'http_route', label: "HTTP 路由" },
];

function addressesFromSnapshots(snapshots: MeasurementSnapshot[]): string[] {
  const addresses = new Set<string>();
  for (const snapshot of snapshots.slice(0, 3)) {
    if (!snapshot.endpoint_probes_json) continue;
    try {
      const probes = JSON.parse(snapshot.endpoint_probes_json) as Array<{ ip_address?: string }>;
      for (const probe of probes) {
        if (probe.ip_address) addresses.add(probe.ip_address);
      }
    } catch {
      // A malformed retained probe record should not block a targeted run.
    }
  }
  return [...addresses].slice(0, 12);
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : "实验未能完成。";
}

export default function DeepDiagnosisPanel({ domain, snapshots }: { domain: string; snapshots: MeasurementSnapshot[] }) {
  const suggestedAddresses = useMemo(() => addressesFromSnapshots(snapshots), [snapshots]);
  const [experiment, setExperiment] = useState<Experiment>('sni_selection');
  const [addressText, setAddressText] = useState('');
  const [addressTouched, setAddressTouched] = useState(false);
  const [report, setReport] = useState<DeepDiagnosisReport | null>(null);
  const mutation = useMutation({
    mutationFn: async () => {
      const response = await runDeepDiagnosis({
        domain,
        experiment,
        addresses: addressText.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean),
      });
      if (!response.data) throw new Error("实验未返回报告。");
      return response.data;
    },
    onSuccess: (data) => setReport(data),
  });

  useEffect(() => {
    if (!addressTouched && !addressText && suggestedAddresses.length > 0) setAddressText(suggestedAddresses.join(', '));
  }, [addressText, addressTouched, suggestedAddresses]);

  const reset = () => {
    setReport(null);
    mutation.reset();
    setAddressTouched(false);
    setAddressText(suggestedAddresses.join(', '));
  };

  return (
    <section className="deep-diagnosis" aria-label="深入诊断实验">
      <div className="cause-inv-kicker">
        <h3><FlaskConical className="deep-diagnosis-icon" size={16} /> 针对性实验</h3>
        <span className="cause-inv-class insufficient">外部证据</span>
      </div>
      <div className="deep-diagnosis-controls">
        <label>
          <span>实验</span>
          <select className="input" value={experiment} onChange={(event) => setExperiment(event.target.value as Experiment)} disabled={mutation.isPending}>
            {EXPERIMENTS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
        </label>
        <label className="deep-diagnosis-addresses">
          <span>地址</span>
          <input className="input" value={addressText} onChange={(event) => { setAddressTouched(true); setAddressText(event.target.value); }} placeholder="23.185.0.2, 23.185.0.4" disabled={mutation.isPending} />
        </label>
        <div className="deep-diagnosis-actions">
          <button type="button" className="btn btn-primary" onClick={() => mutation.mutate()} disabled={mutation.isPending}>
            <Play size={14} /> {mutation.isPending ? "正在运行…" : "运行实验"}
          </button>
          {(report || mutation.error) && (
            <button type="button" className="btn btn-secondary deep-diagnosis-reset" onClick={reset} title="清除实验结果" aria-label="清除实验结果">
              <RotateCcw size={14} />
            </button>
          )}
        </div>
      </div>
      {mutation.error && <p className="deep-diagnosis-error">{errorText(mutation.error)}</p>}
      {report && (
        <div className="deep-diagnosis-report">
          <p className="deep-diagnosis-question">{explanationText(report.question)}</p>
          {report.observations && report.observations.length > 0 && (
            <ul className="deep-diagnosis-observations">{report.observations.map((observation) => <li key={observation}>{observation}</li>)}</ul>
          )}
          {report.probes && report.probes.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs deep-diagnosis-table">
                <thead><tr><th>IP</th><th>叶证书</th><th>SPKI</th><th>证书选择</th><th>其他叶证书</th></tr></thead>
                <tbody>{report.probes.map((probe) => (
                  <tr key={probe.ip_address}>
                    <td className="font-mono">{probe.ip_address}</td>
                    <td className="font-mono">{shortFp(probe.fingerprint)}</td>
                    <td className="font-mono">{shortFp(probe.spki_fingerprint)}</td>
                    <td>{probe.selection_analysis?.interpretation || (probe.covers_requested_name === false ? "名称不匹配" : probe.success ? '已选择' : probe.error || '失败')}</td>
                    <td>{probe.other_fingerprints?.length ? probe.other_fingerprints.map((fingerprint) => shortFp(fingerprint)).join(', ') : '—'}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
          {report.http && (
            <p className="deep-diagnosis-http">HTTP {report.http.status_code ?? '—'} · {report.http.ip_address || "解析地址"} · 叶证书 {shortFp(report.http.tls_fingerprint)}</p>
          )}
          <p className="deep-diagnosis-limitation">{explanationText(report.limitation)}</p>
        </div>
      )}
    </section>
  );
}
