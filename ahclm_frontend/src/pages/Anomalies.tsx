import { severityLabel } from '@/lib/labels';
import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  CalendarClock,
  CalendarX,
  CheckCircle2,
  ChevronRight,
  GitBranch,
  KeyRound,
  Network,
  RefreshCw,
  Repeat,
  ScanLine,
  Search,
  ShieldOff,
  XCircle,
} from 'lucide-react';
import { getAnomalies, getKeyCycle, getMechanismInference } from '@/api';
import type { Anomaly } from '@/types';
import KeyCycleTimeline from '@/components/KeyCycleTimeline';
import MechanismInference from '@/components/MechanismInference';
import { fmtDateTime } from '@/lib/format';

const typeMeta: Record<string, { icon: typeof AlertTriangle; label: string; short: string }> = {
  revoked: { icon: ShieldOff, label: '证书已吊销', short: '已吊销' },
  expired_served: { icon: CalendarX, label: '仍在提供过期证书', short: '过期仍在服务' },
  expired_observed: { icon: CalendarX, label: '观测到过期证书（休眠）', short: '过期已观测' },
  early_renewal: { icon: RefreshCw, label: '提前替换', short: '提前替换' },
  frequent_change: { icon: Repeat, label: '频繁变更', short: '频繁变更' },
  unreachable: { icon: AlertTriangle, label: '反复不可达', short: '不可达' },
  measurement_failed: { icon: Network, label: '测量失败，确认待定', short: '待确认' },
  expiring_soon: { icon: CalendarClock, label: '7 天内到期', short: '即将到期' },
  ari_emergency: { icon: CalendarClock, label: 'ARI 紧急窗口', short: 'ARI 紧急' },
  same_key: { icon: KeyRound, label: '同钥换证', short: '同钥' },
  stale_after_change: { icon: Network, label: '拓扑变化后旧证仍在', short: '旧证残留' },
  deployment_failure: { icon: GitBranch, label: '端点证书不一致', short: '证书混用' },
  hostname_mismatch: { icon: ShieldOff, label: '证书主机名不匹配', short: '名称不匹配' },
  endpoint_probe_inconclusive: { icon: Network, label: '额外端点检查不完整', short: '探测不完整' },
  not_yet_valid: { icon: CalendarClock, label: '证书尚未生效', short: '尚未生效' },
  expired_endpoint: { icon: CalendarX, label: '抽到的端点证书已过期', short: '端点过期' },
  local_chain_validation_failed: { icon: ShieldOff, label: '本地信任链校验失败', short: '链校验失败' },
};

const severityRank: Record<string, number> = { critical: 0, warning: 1, info: 2 };
const INITIAL_VISIBLE_FINDINGS = 80;

interface IssueGroup {
  type: string;
  label: string;
  icon: typeof AlertTriangle;
  findings: Anomaly[];
  domains: number;
  severity: string;
  observations: number;
  deterministic: number;
  speculative: number;
  lastObservedAt?: string;
}

type EvidenceClassFilter = 'all' | 'deterministic' | 'speculative';

function severityTone(severity: string): string {
  return severity === 'critical' ? 'critical' : severity === 'warning' ? 'warning' : 'info';
}

function typeLabel(type: string): string {
  return typeMeta[type]?.short ?? type.replace(/_/g, ' ');
}

function issueLabel(type: string): string {
  return typeMeta[type]?.label ?? type.replace(/_/g, ' ');
}

function registerType(type: string): string {
  return type === 'residual' ? 'revoked' : type;
}

function isSuppressedDomain(domain: string): boolean {
  const name = domain.trim().toLowerCase().replace(/\.$/, '');
  return name === 'pool.ntp.org'
    || name.endsWith('.pool.ntp.org')
    || name.endsWith('.telemetry.microsoft.com')
    || name === 'telemetry.microsoft.com'
    || name.endsWith('.events.data.microsoft.com')
    || name === 'events.data.microsoft.com'
    || name === 'watson.events.data.microsoft.com'
    || name === 'fbcdn.net'
    || name === 'tiktokv.com'
    || name === 'google.cn';
}

function isIssueRegisterFinding(anomaly: Anomaly): boolean {
  return !isSuppressedDomain(anomaly.domain) && Boolean(anomaly.evidence_class);
}

function buildIssueGroups(items: Anomaly[]): IssueGroup[] {
  const byType = new Map<string, Anomaly[]>();
  for (const item of items) {
    const type = registerType(item.type);
    const current = byType.get(type) ?? [];
    const existing = type === 'revoked' ? current.findIndex((finding) => finding.domain === item.domain) : -1;
    if (existing >= 0) {
      current[existing] = { ...current[existing], ...item, type };
    } else {
      current.push({ ...item, type });
    }
    byType.set(type, current);
  }

  return Array.from(byType, ([type, findings]) => {
    const ordered = findings.sort((a, b) => (
      (severityRank[a.severity] ?? 3) - (severityRank[b.severity] ?? 3)
      || (b.occurrence_count ?? 0) - (a.occurrence_count ?? 0)
      || a.domain.localeCompare(b.domain)
    ));
    const dates = ordered
      .map((finding) => finding.last_observed_at || finding.detected_at)
      .filter((date): date is string => Boolean(date))
      .sort()
      .reverse();
    return {
      type,
      label: issueLabel(type),
      icon: typeMeta[type]?.icon ?? AlertTriangle,
      findings: ordered,
      domains: new Set(ordered.map((finding) => finding.domain)).size,
      severity: ordered[0]?.severity ?? 'info',
      observations: ordered.reduce((total, finding) => total + (finding.occurrence_count ?? 1), 0),
      deterministic: ordered.filter((finding) => finding.evidence_class === 'deterministic').length,
      speculative: ordered.filter((finding) => finding.evidence_class === 'speculative').length,
      lastObservedAt: dates[0],
    };
  }).sort((a, b) => (
    (severityRank[a.severity] ?? 3) - (severityRank[b.severity] ?? 3)
    || b.domains - a.domains
    || b.observations - a.observations
    || a.label.localeCompare(b.label)
  ));
}

async function loadAllAnomalies() {
  const pageSize = 500;
  const firstResponse = await getAnomalies(pageSize, 1, true, { compact: true });
  const first = firstResponse.data ?? { count: 0, anomalies: [], total_pages: 1 };
  const totalPages = first.total_pages ?? 1;
  if (totalPages <= 1) return first;

  const pages = Array.from({ length: totalPages - 1 }, (_, offset) => offset + 2);
  const responses = await Promise.all(pages.map((page) => getAnomalies(pageSize, page, true, { compact: true })));
  const anomalies = [
    ...first.anomalies,
    ...responses.flatMap((response) => response.data?.anomalies ?? []),
  ];
  return { ...first, anomalies };
}

export default function Anomalies() {
  const [selectedIssueType, setSelectedIssueType] = useState<string | null>(null);
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [selectedFindingType, setSelectedFindingType] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [evidenceClassFilter, setEvidenceClassFilter] = useState<EvidenceClassFilter>('all');
  const [search, setSearch] = useState('');
  const [visibleLimit, setVisibleLimit] = useState(INITIAL_VISIBLE_FINDINGS);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['anomalies'],
    queryFn: loadAllAnomalies,
    staleTime: 30000,
    refetchOnWindowFocus: false,
    refetchInterval: 300000,
  });

  const anomalies = useMemo(
    () => (data?.anomalies ?? []).filter(isIssueRegisterFinding),
    [data?.anomalies],
  );
  const issueGroups = useMemo(() => buildIssueGroups(anomalies), [anomalies]);
  const filteredIssues = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return issueGroups
      .map((issue) => {
        const findings = issue.findings.filter((finding) => (
          (severityFilter === 'all' || finding.severity === severityFilter)
          && (!needle || [issue.type, issue.label, finding.domain, finding.description]
            .some((value) => value?.toLowerCase().includes(needle)))
        ));
        if (!findings.length) return null;
        return {
          ...issue,
          findings,
          domains: new Set(findings.map((finding) => finding.domain)).size,
          severity: findings[0]?.severity ?? issue.severity,
          observations: findings.reduce((total, finding) => total + (finding.occurrence_count ?? 1), 0),
          deterministic: findings.filter((finding) => finding.evidence_class === 'deterministic').length,
          speculative: findings.filter((finding) => finding.evidence_class === 'speculative').length,
          lastObservedAt: findings
            .map((finding) => finding.last_observed_at || finding.detected_at)
            .filter((date): date is string => Boolean(date))
            .sort()
            .reverse()[0],
        };
      })
      .filter((issue): issue is NonNullable<typeof issue> => Boolean(issue));
  }, [issueGroups, search, severityFilter]);

  const selectedIssue = filteredIssues.find((issue) => issue.type === selectedIssueType) ?? filteredIssues[0];
  const affectedFindings = selectedIssue?.findings.filter((finding) => (
    evidenceClassFilter === 'all' || finding.evidence_class === evidenceClassFilter
  )) ?? [];
  const visibleFindings = affectedFindings.slice(0, visibleLimit);
  const selected = affectedFindings.find((finding) => finding.domain === selectedDomain && finding.type === selectedFindingType)
    ?? affectedFindings.find((finding) => finding.domain === selectedDomain)
    ?? affectedFindings[0];
  const selectedDomainFindings = selected
    ? filteredIssues.flatMap((issue) => issue.findings.filter((finding) => (
      finding.domain === selected.domain
      && (evidenceClassFilter === 'all' || finding.evidence_class === evidenceClassFilter)
    )))
    : [];

  const counts = useMemo(() => anomalies.reduce<Record<string, number>>((acc, anomaly) => {
    acc[anomaly.severity] = (acc[anomaly.severity] ?? 0) + 1;
    return acc;
  }, {}), [anomalies]);
  const selectedIssueEvidenceCounts = useMemo(() => (
    selectedIssue?.findings.reduce<Record<string, number>>((acc, finding) => {
      if (finding.evidence_class) acc[finding.evidence_class] = (acc[finding.evidence_class] ?? 0) + 1;
      return acc;
    }, {}) ?? {}
  ), [selectedIssue]);
  const affectedDomainCount = useMemo(() => new Set(anomalies.map((anomaly) => anomaly.domain)).size, [anomalies]);
  const filteredDomainCount = useMemo(
    () => new Set(filteredIssues.flatMap((issue) => issue.findings.map((finding) => finding.domain))).size,
    [filteredIssues],
  );

  const updateSearch = (value: string) => {
    setSearch(value);
    setVisibleLimit(INITIAL_VISIBLE_FINDINGS);
  };

  const updateSeverity = (value: string) => {
    setSeverityFilter(value);
    setVisibleLimit(INITIAL_VISIBLE_FINDINGS);
  };

  const updateEvidenceClass = (value: EvidenceClassFilter) => {
    setEvidenceClassFilter(value);
    setVisibleLimit(INITIAL_VISIBLE_FINDINGS);
  };

  const selectIssue = (issue: IssueGroup) => {
    const first = issue.findings[0];
    setSelectedIssueType(issue.type);
    setSelectedDomain(first?.domain ?? null);
    setSelectedFindingType(first?.type ?? null);
    setVisibleLimit(INITIAL_VISIBLE_FINDINGS);
  };

  const selectFinding = (finding: Anomaly) => {
    const targetIssue = filteredIssues.find((issue) => issue.type === registerType(finding.type));
    if (targetIssue) setSelectedIssueType(targetIssue.type);
    setSelectedDomain(finding.domain);
    setSelectedFindingType(finding.type);
  };

  return (
    <div className="anomaly-console-page">
      <header className="anomaly-console-header">
        <div className="anomaly-console-header-copy">
          <p className="anomaly-console-kicker">问题登记</p>
          <h1>异常</h1>
          <p>已观测到的证书状况和保留下来的证据。</p>
        </div>
        <div className="anomaly-console-status">
          <span className="anomaly-console-live" />
          <span>每 5 分钟更新</span>
          <button type="button" className="anomaly-console-refresh" onClick={() => refetch()} disabled={isLoading} aria-label="刷新结果" title="刷新结果">
            <RefreshCw size={15} className={isLoading ? 'spin' : ''} />
          </button>
        </div>
      </header>

      <section className="anomaly-console-metrics" aria-label="问题摘要">
        <Metric label="问题类型" value={issueGroups.length} detail="当前测量分类" tone="primary" />
        <Metric label="受影响域名" value={affectedDomainCount} detail="有记录的域名" tone="slate" />
        <Metric label="观测记录" value={anomalies.reduce((total, item) => total + (item.occurrence_count ?? 1), 0)} detail="保留的监测观测" tone="slate" />
        <Metric label="严重问题" value={counts.critical ?? 0} detail="需要立即查看" tone="critical" />
      </section>

      <div className="anomaly-console-controls">
        <label className="anomaly-console-search">
          <Search size={16} aria-hidden="true" />
          <input value={search} onChange={(event) => updateSearch(event.target.value)} placeholder="搜索问题或受影响域名" aria-label="搜索测量问题" />
          {search && <button type="button" onClick={() => updateSearch('')} aria-label="清除搜索" title="清除搜索"><XCircle size={15} /></button>}
        </label>
        <div className="anomaly-console-filters" role="group" aria-label="严重程度筛选">
          {[['all', '全部'], ['critical', '严重'], ['warning', '警告'], ['info', '提示']].map(([value, label]) => (
            <button key={value} type="button" className={severityFilter === value ? 'active' : ''} aria-pressed={severityFilter === value} onClick={() => updateSeverity(value)}>{label}</button>
          ))}
        </div>
        <span className="anomaly-console-result-count">{filteredIssues.length} 类问题 · {filteredDomainCount} 个域名</span>
      </div>

      {isLoading && <div className="anomaly-console-state"><span className="spinner" /> 正在加载测量问题…</div>}
      {isError && (
        <div className="anomaly-console-state error"><XCircle size={20} /><span>测量问题加载失败。</span><button type="button" onClick={() => refetch()}>重试</button></div>
      )}
      {!isLoading && !isError && anomalies.length === 0 && (
        <div className="anomaly-console-state success"><CheckCircle2 size={20} /><span>当前没有记录中的测量问题。</span></div>
      )}
      {!isLoading && !isError && anomalies.length > 0 && filteredIssues.length === 0 && (
        <div className="anomaly-console-state">
          <ScanLine size={20} />
          <span>没有问题符合这个搜索或严重程度。</span>
          <button type="button" onClick={() => { updateSearch(''); updateSeverity('all'); updateEvidenceClass('all'); }}>清除筛选</button>
        </div>
      )}

      {!isLoading && !isError && filteredIssues.length > 0 && selectedIssue && (
        <div className="anomaly-issue-workspace">
          <nav className="anomaly-problem-strip" aria-label="测量问题类型">
            <div className="anomaly-problem-strip-head">
              <div>
                <span className="anomaly-console-kicker">问题索引</span>
                <h2>测量问题</h2>
              </div>
          <span>{filteredIssues.length} 类</span>
            </div>
            <div className="anomaly-problem-strip-list" role="tablist" aria-label="选择一个测量问题">
              {filteredIssues.map((issue) => {
                const IssueIcon = issue.icon;
                const selectedType = selectedIssue.type === issue.type;
                return (
                  <button
                    type="button"
                    key={issue.type}
                    role="tab"
                    aria-selected={selectedType}
                    className={'anomaly-problem-chip ' + severityTone(issue.severity) + (selectedType ? ' selected' : '')}
                    onClick={() => selectIssue(issue)}
                    title={`${issue.label} · ${issue.domains} 个域名 · ${issue.observations} 次观测 · ${issue.deterministic} 条确定 · ${issue.speculative} 条推测`}
                  >
                    <span className={'anomaly-problem-chip-icon ' + severityTone(issue.severity)}><IssueIcon size={15} /></span>
                    <span className="anomaly-problem-chip-copy">
                      <span className="anomaly-problem-chip-name">{issue.label}</span>
                      <span className="anomaly-problem-chip-meta">{issue.domains} 个域名 · {issue.observations} 次观测 · {issue.deterministic} 确定 · {issue.speculative} 推测</span>
                    </span>
                  </button>
                );
              })}
            </div>
          </nav>

          <div className="anomaly-issue-body">
            <aside className="anomaly-issue-affected" aria-label="受影响域名">
              <div className="anomaly-issue-index-head">
                <div>
                  <span className="anomaly-console-kicker">受影响域名</span>
                  <h2>有这个问题的主机</h2>
                </div>
                <span>{affectedFindings.length}</span>
              </div>
              <p className="anomaly-issue-affected-focus">{selectedIssue.label}</p>
              <div className="anomaly-issue-evidence-filters">
                <span>证据强度</span>
                <div role="group" aria-label="证据强度筛选">
                  {([
                    ['all', '全部'],
                    ['deterministic', '确定'],
                    ['speculative', '推测'],
                  ] as [EvidenceClassFilter, string][]).map(([value, label]) => (
                    <button
                      key={value}
                      type="button"
                      className={evidenceClassFilter === value ? 'active' : ''}
                      aria-pressed={evidenceClassFilter === value}
                      onClick={() => updateEvidenceClass(value)}
                    >
                      <span>{label}</span>
                      {value !== 'all' && <small>{selectedIssueEvidenceCounts[value] ?? 0}</small>}
                    </button>
                  ))}
                </div>
              </div>
              <div className="anomaly-issue-affected-list">
                {visibleFindings.map((finding) => {
                  const active = selected.domain === finding.domain && selected.type === finding.type;
                  return (
                    <button
                      type="button"
                      key={`${finding.domain}-${finding.type}`}
                      className={'anomaly-affected-item' + (active ? ' selected' : '')}
                      onClick={() => selectFinding(finding)}
                      title={finding.description}
                    >
                      <span className={'anomaly-console-domain-marker ' + severityTone(finding.severity)} />
                      <span className="anomaly-affected-main">
                        <span className="anomaly-affected-domain">{finding.domain}</span>
                        <span className="anomaly-affected-meta">{finding.occurrence_count ?? 1} 次 · {fmtDateTime(finding.last_observed_at || finding.detected_at)}</span>
                      </span>
                      <span className={'anomaly-evidence-class ' + (finding.evidence_class === 'deterministic' ? 'deterministic' : 'speculative')}>
                        {finding.evidence_class === 'deterministic' ? '确定' : '推测'}
                      </span>
                    </button>
                  );
                })}
                {!visibleFindings.length && <p className="anomaly-affected-empty">没有域名符合当前筛选。</p>}
              </div>
              {affectedFindings.length > visibleLimit && (
                <button type="button" className="anomaly-console-more" onClick={() => setVisibleLimit((limit) => limit + INITIAL_VISIBLE_FINDINGS)}>
                  再显示 {Math.min(INITIAL_VISIBLE_FINDINGS, affectedFindings.length - visibleLimit)} 条 <ChevronRight size={14} />
                </button>
              )}
            </aside>

            {selected ? (
            <section className="anomaly-console-inspector" aria-label="选中的测量结果">
              <div className="anomaly-console-inspector-head">
                <div>
                  <span className="anomaly-console-kicker">选中问题</span>
                  <h2>{issueLabel(selected.type)}</h2>
                  <p className="anomaly-selected-domain">{selected.domain}</p>
                </div>
                <div className="anomaly-console-inspector-actions">
                  <span className={'anomaly-console-severity ' + severityTone(selected.severity)}><span />{severityLabel(selected.severity)}</span>
                  <span className={'anomaly-evidence-class ' + (selected.evidence_class === 'deterministic' ? 'deterministic' : 'speculative')}>
                    {selected.evidence_class === 'deterministic' ? '确定' : '推测'}
                  </span>
                  <Link to={`/domains/${encodeURIComponent(selected.domain)}`}>打开域名 <ChevronRight size={14} /></Link>
                </div>
              </div>

              {selectedDomainFindings.length > 1 && (
                <div className="anomaly-console-finding-nav" aria-label="这个域名的其他问题">
                  {selectedDomainFindings.map((finding) => (
                    <button key={finding.type} type="button" className={finding.type === selected.type ? 'active' : ''} onClick={() => selectFinding(finding)}>
                      {typeLabel(finding.type)} <span>{finding.occurrence_count ?? 1}</span>
                    </button>
                  ))}
                </div>
              )}

              <div className={'anomaly-console-observation compact ' + severityTone(selected.severity)}>
                <div>
                  <span className="anomaly-console-kicker">观测状况</span>
                  <h3>{selected.description}</h3>
                </div>
                <div className="anomaly-console-observation-facts">
                  <Fact label="首次记录" value={fmtDateTime(selected.first_observed_at || selected.detected_at)} />
                  <Fact label="最近记录" value={fmtDateTime(selected.last_observed_at || selected.detected_at)} />
                  <Fact label="观测次数" value={String(selected.occurrence_count ?? 1)} />
                  <Fact label="监测轮次" value={String(selected.monitoring_count ?? 0)} />
                </div>
              </div>

              <FindingEvidence anomaly={selected} />
              <FindingAnalysis domain={selected.domain} />
            </section>
            ) : (
              <section className="anomaly-console-inspector" aria-label="选中的测量结果">
                <div className="anomaly-console-inspector-head">
                  <div>
                    <span className="anomaly-console-kicker">选中问题</span>
                    <h2>{selectedIssue.label}</h2>
                    <p className="anomaly-selected-domain">没有符合当前证据强度的结果</p>
                  </div>
                </div>
                <div className="anomaly-console-state">
                  这个问题下没有符合当前筛选的记录。
                </div>
              </section>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, detail, tone }: { label: string; value: number; detail: string; tone: string }) {
  return <div className={'anomaly-console-metric ' + tone}><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>;
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}

function FindingAnalysis({ domain }: { domain: string }) {
  const cycle = useQuery({
    queryKey: ['key-cycle', domain],
    queryFn: async () => (await getKeyCycle(domain)).data,
    enabled: Boolean(domain),
  });
  const mechanism = useQuery({
    queryKey: ['mechanism-inference', domain],
    queryFn: async () => (await getMechanismInference(domain)).data,
    enabled: Boolean(domain),
  });
  const keyCycle = cycle.data?.key_cycle;
  const report = mechanism.data?.mechanism_inference;
  return (
    <div className="anomaly-analysis">
      {(cycle.isLoading || mechanism.isLoading) && <p className="anomaly-analysis-status">正在加载公钥周期和机制评分…</p>}
      {(cycle.isError || mechanism.isError) && (
        <p className="anomaly-analysis-status" role="alert">
          {cycle.isError ? '公钥周期加载失败。' : ''}{mechanism.isError ? '机制评分加载失败。' : ''}
          <button type="button" onClick={() => { if (cycle.isError) void cycle.refetch(); if (mechanism.isError) void mechanism.refetch(); }}>重试加载</button>
        </p>
      )}
      {keyCycle && <KeyCycleTimeline cycle={keyCycle} />}
      {report && <MechanismInference report={report} />}
    </div>
  );
}

function FindingEvidence({ anomaly }: { anomaly: Anomaly }) {
  const evidence = useQuery({
    queryKey: ['anomaly-evidence', anomaly.domain, anomaly.type],
    queryFn: async () => {
      const result = await getAnomalies(1, 1, true, { domain: anomaly.domain, type: anomaly.type });
      return result.data?.anomalies?.[0] ?? anomaly;
    },
    enabled: Boolean(anomaly.domain && anomaly.type),
    staleTime: 300000,
  });

  if (evidence.isLoading) {
    return <div className="anomaly-console-state">正在加载此条记录的完整证据…</div>;
  }

  if (evidence.isError) {
    return (
      <>
        <EvidencePanel anomaly={anomaly} />
        <p className="anomaly-analysis-status" role="alert">
          完整证据加载失败。<button type="button" onClick={() => void evidence.refetch()}>重试</button>
        </p>
      </>
    );
  }

  return <EvidencePanel anomaly={evidence.data ?? anomaly} />;
}

function EvidencePanel({ anomaly }: { anomaly: Anomaly }) {
  const observed = Array.from(new Set([
    ...(anomaly.confirmed_evidence ?? []),
    ...(anomaly.evidence ?? []),
  ].map((item) => item.trim()).filter(Boolean).flatMap(expandEndpointProbeEvidence)));
  const evidenceFacts = [
    ['观测记录', String(anomaly.occurrence_count ?? 1)],
    ...(anomaly.monitoring_count > 0 ? [['监测轮次', String(anomaly.monitoring_count)] as [string, string]] : []),
    ...(anomaly.successful_monitoring_count > 0 ? [['成功轮次', String(anomaly.successful_monitoring_count)] as [string, string]] : []),
    ...(anomaly.failed_monitoring_count > 0 ? [['失败轮次', String(anomaly.failed_monitoring_count)] as [string, string]] : []),
  ];

  return (
    <div className="anomaly-console-ledger anomaly-observation-ledger">
      <section className="anomaly-console-ledger-panel measured">
        <div className="anomaly-console-section-head">
          <div><span className="anomaly-console-step">01</span><h3>观测状况</h3></div>
        </div>
        <p className="anomaly-console-observed-text">{anomaly.description}</p>
        <div className="anomaly-evidence-facts">
          {evidenceFacts.map(([label, value]) => <Fact key={label} label={label} value={value} />)}
        </div>
        {anomaly.fingerprint && <p className="anomaly-evidence-fingerprint">证书指纹：<code>{anomaly.fingerprint}</code></p>}
      </section>
      <section className="anomaly-console-ledger-panel interpretation">
        <div className="anomaly-console-section-head">
          <div><span className="anomaly-console-step">02</span><h3>证据</h3></div>
          <span className="anomaly-console-evidence-count">{observed.length} 条记录</span>
        </div>
        {observed.length > 0 ? (
          <ul className="anomaly-console-evidence-list prose">
            {observed.map((item, index) => <EvidenceItem key={`${item}-${index}`} value={item} />)}
          </ul>
        ) : (
          <p className="anomaly-console-muted">此次观测未保留证据记录。</p>
        )}
        {anomaly.evidence_pending_reason && <p className="anomaly-console-evidence-note">证据说明： {anomaly.evidence_pending_reason}</p>}
        {anomaly.evidence_class === 'speculative' && !anomaly.evidence_pending_reason && (
          <p className="anomaly-console-evidence-note">证据仍在积累，该发现暂列为候选。</p>
        )}
      </section>
    </div>
  );
}

function expandEndpointProbeEvidence(value: string): string[] {
  const marker = 'endpoint_probes=';
  const markerIndex = value.indexOf(marker);
  if (markerIndex < 0) return [value];

  const jsonStart = markerIndex + marker.length;
  const jsonEnd = value.lastIndexOf(']') + 1;
  if (jsonEnd <= jsonStart) return [value];

  let probes: Array<Record<string, unknown>>;
  try {
    const parsed = JSON.parse(value.slice(jsonStart, jsonEnd));
    if (!Array.isArray(parsed)) return [value];
    probes = parsed.filter((probe): probe is Record<string, unknown> => Boolean(probe && typeof probe === 'object'));
  } catch {
    return [value];
  }

  const prefix = value.slice(0, markerIndex).trim();
  const summaries = probes.map((probe, index) => {
    const ip = typeof probe.ip_address === 'string' ? probe.ip_address : `probe-${index + 1}`;
    const fingerprint = typeof probe.fingerprint === 'string' ? probe.fingerprint : 'none';
    const commonName = typeof probe.common_name === 'string' ? probe.common_name : 'none';
    const sans = Array.isArray(probe.sans) ? probe.sans.filter((name): name is string => typeof name === 'string').join(',') : 'none';
    const notAfter = typeof probe.not_after === 'string' ? probe.not_after : 'unknown';
    const covered = typeof probe.covers_requested_name === 'boolean' ? String(probe.covers_requested_name) : 'unknown';
    const error = typeof probe.error === 'string' ? ` error=${probe.error}` : '';
    return `endpoint_probe ip=${ip} fingerprint=${fingerprint} common_name=${commonName} sans=${sans} not_after=${notAfter} covers_requested_name=${covered}${error}`;
  });

  // Keep the original JSON as a collapsed record so every displayed summary
  // remains reproducible against the backend evidence payload.
  return [
    `${prefix ? `${prefix} ` : ''}endpoint_probe_count=${probes.length}`,
    ...summaries,
    value,
  ];
}

function EvidenceItem({ value }: { value: string }) {
  if (value.startsWith('endpoint_probe ') || value.startsWith('endpoint_probe_count=')) {
    return <li className="anomaly-evidence-probe"><code>{value}</code></li>;
  }
  if (value.length <= 260) return <li>{value}</li>;
  return (
    <li className="anomaly-evidence-long">
      <details>
        <summary>{value.slice(0, 240)}...</summary>
        <pre>{value}</pre>
      </details>
    </li>
  );
}
