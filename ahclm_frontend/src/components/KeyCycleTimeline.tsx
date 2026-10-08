import { statusLabel } from '@/lib/labels';
import type { PublicKeyDeploymentCycle, PublicKeyDeploymentEvent } from '@/types';
import { fmtDateTime, shortFp } from '@/lib/format';

const KIND_LABEL: Record<string, string> = {
  not_before_lower_bound: 'NotBefore 下界',
  leaf_first_stored: '叶证书首次入库',
  leaf_first_observed: '叶证书首次观测',
  key_generated: '密钥生成',
  certificate_issued: '证书签发',
  deployed: '已部署',
  rolled_back: '已回滚',
  key_retired: '密钥退役',
  public_transition: '公开观测到切换',
};

const STATUS_LABEL: Record<string, string> = {
  complete: '有控制面时间',
  partial: '控制面记录不完整',
  external_only: '仅有公开时间下界',
};

function duration(seconds?: number): string {
  if (seconds === undefined || seconds === null || Number.isNaN(seconds)) return '—';
  if (seconds < 120) return `${Math.round(seconds)} 秒`;
  const hours = seconds / 3600;
  if (hours < 48) return `${hours.toFixed(1)} 小时`;
  return `${(hours / 24).toFixed(1)} 天`;
}

function coverage(value?: number): string {
  if (value === undefined || value === null || Number.isNaN(value)) return '—';
  return `${Math.round(value * 100)}%`;
}

function eventLabel(event: PublicKeyDeploymentEvent): string {
  return KIND_LABEL[event.kind] || event.kind.replace(/_/g, ' ');
}

export default function KeyCycleTimeline({ cycle }: { cycle: PublicKeyDeploymentCycle }) {
  const status = cycle.status === 'complete' ? 'proven' : cycle.status === 'partial' ? 'mixed' : 'insufficient';
  const events = cycle.events ?? [];
  return (
    <section className="key-cycle" aria-label="公钥部署周期">
      <div className="cause-inv-kicker">
        <h3>公钥部署周期</h3>
        <span className={'cause-inv-class ' + status}>
          {STATUS_LABEL[cycle.status] || '仅有公开时间下界'}
        </span>
      </div>
      <p className="key-cycle-note">
        {cycle.certificate_count} 张叶证书，{cycle.public_key_count} 个公钥
        {cycle.same_key_replacements > 0 ? `，${cycle.same_key_replacements} 次同钥替换` : ''}。
        NotBefore 是证书有效期起点；首次观测只能说明证书在该时刻已被提供。精确部署时间需要成功且关联的控制面事件。
      </p>
      <dl className="key-cycle-metrics">
        <div><dt>有效期起点</dt><dd>{fmtDateTime(cycle.metrics?.first_issued_at)}</dd></div>
        <div><dt>精确签发</dt><dd>{fmtDateTime(cycle.metrics?.first_issued_exact_at)}</dd></div>
        <div><dt>首次精确部署</dt><dd>{fmtDateTime(cycle.metrics?.first_deployed_at)}</dd></div>
        <div><dt>首次精确退役</dt><dd>{fmtDateTime(cycle.metrics?.first_retired_at)}</dd></div>
        <div><dt>首次公开观测</dt><dd>{fmtDateTime(cycle.metrics?.first_public_observed_at)}</dd></div>
        <div><dt>{cycle.metrics?.issuance_to_first_public_basis === 'exact_issuance' ? '签发到首次观测' : '有效期起点到首次观测'}</dt><dd>{duration(cycle.metrics?.issuance_to_first_public_seconds)}</dd></div>
        <div><dt>部署到首次观测</dt><dd>{duration(cycle.metrics?.deployment_to_first_public_seconds)}</dd></div>
        <div><dt>首次观测到稳定</dt><dd>{duration(cycle.metrics?.first_public_to_stable_seconds)}</dd></div>
        <div><dt>后任与前任末次观测间隔</dt><dd>{duration(cycle.metrics?.successor_to_previous_retirement_seconds)}</dd></div>
        <div><dt>观测跨度</dt><dd>{duration(cycle.metrics?.observed_span_seconds)}</dd></div>
        <div><dt>地址数</dt><dd>{cycle.metrics?.address_count ?? 0}</dd></div>
        <div><dt>端点证据覆盖</dt><dd>{coverage(cycle.metrics?.address_coverage)}</dd></div>
        <div><dt>稳定轮次</dt><dd>{cycle.metrics?.stable_round_count ?? 0}</dd></div>
      </dl>
      {cycle.internal_evidence && (
        <div className="key-cycle-evidence">
          <div className="key-cycle-evidence-head">
            <span>内部控制面证据</span>
            <b className={statusLabel(cycle.internal_evidence.status)}>{statusLabel(cycle.internal_evidence.status)}</b>
          </div>
          <p>{cycle.internal_evidence.conclusion || statusLabel(cycle.internal_evidence.determination)}</p>
          <small>{cycle.internal_evidence.correlated_events}/{cycle.internal_evidence.event_count} 条事件带有因果关联</small>
          {cycle.internal_evidence.evidence && cycle.internal_evidence.evidence.length > 0 && (
            <ul>{cycle.internal_evidence.evidence.slice(0, 4).map((line) => <li key={line}>{line}</li>)}</ul>
          )}
        </div>
      )}
      {events.length > 0 ? (
        <ol className="key-cycle-events">
          {events.map((event, index) => (
            <li key={(event.at || '') + '-' + event.kind + '-' + index} className={event.lower_bound ? 'bound' : 'exact'}>
              <time>{fmtDateTime(event.at)}</time>
              <div>
                <b>{eventLabel(event)}</b>
                {event.lower_bound && <span className="key-cycle-bound">时间下界</span>}
                {event.fingerprint && <code>{shortFp(event.fingerprint)}</code>}
                {event.ip_address && <span>{event.ip_address}</span>}
                {event.detail && <small>{event.detail}</small>}
                <small>{statusLabel(event.source)}{event.evidence_id ? ` · 证据 #${event.evidence_id}` : ''}</small>
              </div>
            </li>
          ))}
        </ol>
      ) : (
        <p className="anomaly-console-muted">这个域名没有保留证书时间。</p>
      )}
      {(cycle.missing_evidence?.length ?? 0) > 0 && (
        <div className="key-cycle-missing">
          <span>要得到精确部署时间，还缺这些记录</span>
          <ul>{cycle.missing_evidence!.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
      )}
    </section>
  );
}
