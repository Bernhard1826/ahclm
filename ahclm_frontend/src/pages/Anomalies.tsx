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
  Timer,
  XCircle,
} from 'lucide-react';
import { getAnomalies, getAnomalyCost } from '@/api';
import type { Anomaly, CauseDiagnosis } from '@/types';
import { fmtDateTime } from '@/lib/format';
import CostBreakdown from '@/components/CostBreakdown';

const typeMeta: Record<string, { icon: typeof AlertTriangle; label: string; short: string }> = {
  revoked: { icon: ShieldOff, label: 'Revoked certificate', short: 'Revoked' },
  expired_served: { icon: CalendarX, label: 'Serving expired certificate', short: 'Expired served' },
  expired_observed: { icon: CalendarX, label: 'Expired certificate observed (dormant)', short: 'Expired observed' },
  early_renewal: { icon: RefreshCw, label: 'Early renewal', short: 'Early renewal' },
  frequent_change: { icon: Repeat, label: 'Frequent changes', short: 'Frequent changes' },
  unreachable: { icon: AlertTriangle, label: 'Repeatedly unreachable', short: 'Unreachable' },
  measurement_failed: { icon: Network, label: 'Measurement failed; confirmation pending', short: 'Pending confirmation' },
  expiring_soon: { icon: CalendarClock, label: 'Expiring within 7 days', short: 'Expiring soon' },
  ari_emergency: { icon: CalendarClock, label: 'ARI emergency', short: 'ARI emergency' },
  same_key: { icon: KeyRound, label: 'Same-key certificate replacement', short: 'Same key' },
  stale_after_change: { icon: Network, label: 'Stale certificate after topology change', short: 'Stale after change' },
  residual: { icon: Timer, label: 'Revoked certificate residual service', short: 'Residual service' },
  deployment_failure: { icon: GitBranch, label: 'Certificate diversity across endpoints', short: 'Mixed certificates' },
  hostname_mismatch: { icon: ShieldOff, label: 'Certificate hostname mismatch', short: 'Name mismatch' },
  endpoint_probe_inconclusive: { icon: Network, label: 'Additional endpoint check incomplete', short: 'Incomplete probe' },
  not_yet_valid: { icon: CalendarClock, label: 'Certificate not yet valid', short: 'Not yet valid' },
  expired_endpoint: { icon: CalendarX, label: 'Expired certificate at sampled endpoint', short: 'Expired endpoint' },
  local_chain_validation_failed: { icon: ShieldOff, label: 'Local trust-chain validation failed', short: 'Chain validation' },
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
  lastObservedAt?: string;
}

interface CauseDetails {
  classification: string;
  reason: string;
  evidence: string[];
  evidenceStatus: string;
  pendingReason?: string;
  diagnosis?: CauseDiagnosis;
}

function severityTone(severity: string): string {
  return severity === 'critical' ? 'critical' : severity === 'warning' ? 'warning' : 'info';
}

function typeLabel(type: string): string {
  return typeMeta[type]?.short ?? type.replace(/_/g, ' ');
}

function issueLabel(type: string): string {
  return typeMeta[type]?.label ?? type.replace(/_/g, ' ');
}

function buildIssueGroups(items: Anomaly[]): IssueGroup[] {
  const byType = new Map<string, Anomaly[]>();
  for (const item of items) {
    const current = byType.get(item.type) ?? [];
    current.push(item);
    byType.set(item.type, current);
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
      lastObservedAt: dates[0],
    };
  }).sort((a, b) => (
    (severityRank[a.severity] ?? 3) - (severityRank[b.severity] ?? 3)
    || b.domains - a.domains
    || b.observations - a.observations
    || a.label.localeCompare(b.label)
  ));
}

function causeDetails(anomaly: Anomaly): CauseDetails {
  const confirmedReason = anomaly.confirmed_reason || '';
  const inferredReason = anomaly.inferred_reason || '';
  const confirmedEvidence = Array.isArray(anomaly.confirmed_evidence) ? anomaly.confirmed_evidence : [];
  const inferredEvidence = Array.isArray(anomaly.inferred_evidence) ? anomaly.inferred_evidence : [];
  const hasConfirmed = Boolean(confirmedReason || confirmedEvidence.length);
  const hasInferred = Boolean(inferredReason || inferredEvidence.length);
  const classification = hasConfirmed
    ? 'confirmed'
    : hasInferred
      ? 'inferred'
      : (anomaly.cause_classification === 'confirmed' || anomaly.cause_classification === 'inferred' ? anomaly.cause_classification : 'unknown');
  const inferred = classification === 'inferred';
  return {
    classification,
    reason: inferred ? (inferredReason || anomaly.reason || '') : (confirmedReason || anomaly.reason || ''),
    evidence: inferred
      ? (inferredEvidence.length ? inferredEvidence : (anomaly.evidence ?? []))
      : (confirmedEvidence.length ? confirmedEvidence : (anomaly.evidence ?? [])),
    evidenceStatus: anomaly.evidence_status || 'unknown',
    pendingReason: anomaly.evidence_pending_reason,
    diagnosis: anomaly.diagnosis,
  };
}

export default function Anomalies() {
  const [selectedIssueType, setSelectedIssueType] = useState<string | null>(null);
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [selectedFindingType, setSelectedFindingType] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [visibleLimit, setVisibleLimit] = useState(INITIAL_VISIBLE_FINDINGS);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['anomalies'],
    queryFn: async () => (await getAnomalies(1000)).data,
    refetchInterval: 60000,
  });

  const anomalies: Anomaly[] = data?.anomalies ?? [];
  const issueGroups = useMemo(() => buildIssueGroups(anomalies), [anomalies]);
  const domainFindings = useMemo(() => {
    const byDomain = new Map<string, Anomaly[]>();
    for (const anomaly of anomalies) {
      const current = byDomain.get(anomaly.domain) ?? [];
      current.push(anomaly);
      byDomain.set(anomaly.domain, current);
    }
    return byDomain;
  }, [anomalies]);
  const filteredIssues = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return issueGroups
      .map((issue) => {
        const findings = issue.findings.filter((finding) => severityFilter === 'all' || finding.severity === severityFilter);
        if (!findings.length) return null;
        const searchValues = [
          issue.type,
          issue.label,
          ...findings.flatMap((finding) => [finding.domain, finding.description, finding.reason]),
        ];
        if (needle && !searchValues.some((value) => value?.toLowerCase().includes(needle))) return null;
        return {
          ...issue,
          findings,
          domains: new Set(findings.map((finding) => finding.domain)).size,
          severity: findings[0]?.severity ?? issue.severity,
          observations: findings.reduce((total, finding) => total + (finding.occurrence_count ?? 1), 0),
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
  const affectedFindings = selectedIssue?.findings ?? [];
  const selected = affectedFindings.find((finding) => finding.domain === selectedDomain && finding.type === selectedFindingType)
    ?? affectedFindings.find((finding) => finding.domain === selectedDomain)
    ?? affectedFindings[0];
  const selectedDomainFindings = selected ? (domainFindings.get(selected.domain) ?? []) : [];
  const visibleFindings = affectedFindings.slice(0, visibleLimit);
  const cause = selected ? causeDetails(selected) : null;

  const { data: costData, isLoading: costLoading, isError: costError } = useQuery({
    queryKey: ['anomaly-cost', selected?.domain],
    queryFn: async () => (await getAnomalyCost(selected!.domain)).data,
    enabled: Boolean(selected),
    staleTime: 60000,
  });

  const counts = useMemo(() => anomalies.reduce<Record<string, number>>((acc, anomaly) => {
    acc[anomaly.severity] = (acc[anomaly.severity] ?? 0) + 1;
    return acc;
  }, {}), [anomalies]);
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

  const selectIssue = (issue: IssueGroup) => {
    const first = issue.findings[0];
    setSelectedIssueType(issue.type);
    setSelectedDomain(first?.domain ?? null);
    setSelectedFindingType(first?.type ?? null);
  };

  const selectFinding = (finding: Anomaly) => {
    const targetIssue = filteredIssues.find((issue) => issue.type === finding.type);
    if (targetIssue) setSelectedIssueType(targetIssue.type);
    setSelectedDomain(finding.domain);
    setSelectedFindingType(finding.type);
  };

  return (
    <div className="anomaly-console-page">
      <header className="anomaly-console-header">
        <div className="anomaly-console-header-copy">
          <p className="anomaly-console-kicker">ISSUE REGISTER</p>
          <h1>Anomalies</h1>
          <p>Start with the measured problem. Compare its reach, then inspect an affected certificate, its evidence, and response cost.</p>
        </div>
        <div className="anomaly-console-status">
          <span className="anomaly-console-live" />
          <span>Evidence index live</span>
          <button type="button" className="anomaly-console-refresh" onClick={() => refetch()} disabled={isLoading} aria-label="Refresh findings" title="Refresh findings">
            <RefreshCw size={15} className={isLoading ? 'spin' : ''} />
          </button>
        </div>
      </header>

      <section className="anomaly-console-metrics" aria-label="Problem summary">
        <Metric label="Problem types" value={issueGroups.length} detail="measured issues" tone="primary" />
        <Metric label="Affected domains" value={affectedDomainCount} detail="certificates needing review" tone="slate" />
        <Metric label="Measured findings" value={anomalies.length} detail="retained observations" tone="slate" />
        <Metric label="Critical findings" value={counts.critical ?? 0} detail="requires immediate review" tone="critical" />
      </section>

      <div className="anomaly-console-controls">
        <label className="anomaly-console-search">
          <Search size={16} aria-hidden="true" />
          <input value={search} onChange={(event) => updateSearch(event.target.value)} placeholder="Search a problem or affected domain" aria-label="Search measured problems" />
          {search && <button type="button" onClick={() => updateSearch('')} aria-label="Clear search" title="Clear search"><XCircle size={15} /></button>}
        </label>
        <div className="anomaly-console-filters" role="group" aria-label="Severity filter">
          {[['all', 'All'], ['critical', 'Critical'], ['warning', 'Warning'], ['info', 'Info']].map(([value, label]) => (
            <button key={value} type="button" className={severityFilter === value ? 'active' : ''} onClick={() => updateSeverity(value)}>{label}</button>
          ))}
        </div>
        <span className="anomaly-console-result-count">{filteredIssues.length} problem type{filteredIssues.length === 1 ? '' : 's'} · {filteredDomainCount} domain{filteredDomainCount === 1 ? '' : 's'}</span>
      </div>

      {isLoading && <div className="anomaly-console-state"><span className="spinner" /> Loading measured problems...</div>}
      {isError && (
        <div className="anomaly-console-state error"><XCircle size={20} /><span>Measured problems could not be loaded.</span><button type="button" onClick={() => refetch()}>Try again</button></div>
      )}
      {!isLoading && !isError && anomalies.length === 0 && (
        <div className="anomaly-console-state success"><CheckCircle2 size={20} /><span>No active measurement problems are currently recorded.</span></div>
      )}
      {!isLoading && !isError && anomalies.length > 0 && filteredIssues.length === 0 && (
        <div className="anomaly-console-state"><ScanLine size={20} /><span>No problems match this search or severity filter.</span><button type="button" onClick={() => { updateSearch(''); updateSeverity('all'); }}>Clear filters</button></div>
      )}

      {!isLoading && !isError && filteredIssues.length > 0 && selectedIssue && selected && cause && (
        <div className="anomaly-issue-workspace">
          <aside className="anomaly-issue-index" aria-label="Measured problem types">
            <div className="anomaly-issue-index-head">
              <div><span className="anomaly-console-kicker">PROBLEM INDEX</span><h2>Measured problems</h2></div>
              <span>{filteredIssues.length}</span>
            </div>
            <div className="anomaly-issue-index-list">
              {filteredIssues.map((issue) => {
                const IssueIcon = issue.icon;
                return (
                  <button type="button" key={issue.type} className={'anomaly-issue-item ' + (selectedIssue.type === issue.type ? 'selected' : '')} onClick={() => selectIssue(issue)}>
                    <span className={'anomaly-issue-icon ' + severityTone(issue.severity)}><IssueIcon size={16} /></span>
                    <span className="anomaly-issue-main">
                      <span className="anomaly-issue-name">{issue.label}</span>
                      <span className="anomaly-issue-meta">{issue.domains} domain{issue.domains === 1 ? '' : 's'} · {issue.observations} observations</span>
                      <span className="anomaly-issue-last">last {fmtDateTime(issue.lastObservedAt)}</span>
                    </span>
                    <ChevronRight size={15} className="anomaly-issue-arrow" />
                  </button>
                );
              })}
            </div>
          </aside>

          <aside className="anomaly-issue-affected" aria-label="Affected domains for selected problem">
            <div className="anomaly-issue-index-head">
              <div><span className="anomaly-console-kicker">AFFECTED SET</span><h2>{selectedIssue.label}</h2></div>
              <span>{Math.min(visibleLimit, affectedFindings.length)} / {affectedFindings.length}</span>
            </div>
            <div className="anomaly-issue-affected-list">
              {visibleFindings.map((finding) => (
                <button type="button" key={finding.domain + '-' + finding.type + '-' + (finding.fingerprint ?? '')} className={'anomaly-affected-item ' + (selected.domain === finding.domain ? 'selected' : '')} onClick={() => selectFinding(finding)}>
                  <span className={'anomaly-console-domain-marker ' + severityTone(finding.severity)} />
                  <span className="anomaly-affected-main">
                    <span className="anomaly-affected-domain">{finding.domain}</span>
                    <span className="anomaly-affected-meta">{finding.occurrence_count ?? 1} observations · last {fmtDateTime(finding.last_observed_at || finding.detected_at)}</span>
                    <span className="anomaly-affected-description">{finding.description}</span>
                  </span>
                  <ChevronRight size={15} className="anomaly-issue-arrow" />
                </button>
              ))}
            </div>
            {visibleLimit < affectedFindings.length && (
              <button type="button" className="anomaly-console-load-more" onClick={() => setVisibleLimit((limit) => limit + INITIAL_VISIBLE_FINDINGS)}>
                Show {Math.min(INITIAL_VISIBLE_FINDINGS, affectedFindings.length - visibleLimit)} more affected domains <ChevronRight size={14} />
              </button>
            )}
          </aside>

          <section className="anomaly-console-inspector" aria-label="Selected measured finding">
            <div className="anomaly-console-inspector-head">
              <div>
                <p className="anomaly-console-kicker">SELECTED FINDING</p>
                <h2>{selectedIssue.label}</h2>
                <p className="anomaly-selected-domain">{selected.domain}</p>
              </div>
              <div className="anomaly-console-inspector-actions">
                <span className={'anomaly-console-severity ' + severityTone(selected.severity)}><span />{selected.severity}</span>
                <Link to={'/domains/' + encodeURIComponent(selected.domain)} title="Open domain detail">Open domain <ChevronRight size={14} /></Link>
              </div>
            </div>

            {selectedDomainFindings.length > 1 && (
              <div className="anomaly-console-finding-nav" role="tablist" aria-label="Findings for selected domain">
                {selectedDomainFindings.map((finding) => {
                  const MetaIcon = typeMeta[finding.type]?.icon ?? AlertTriangle;
                  return (
                    <button key={finding.type} type="button" role="tab" aria-selected={selected.type === finding.type} className={selected.type === finding.type ? 'active' : ''} onClick={() => selectFinding(finding)}>
                      <MetaIcon size={14} />{typeLabel(finding.type)}
                    </button>
                  );
                })}
              </div>
            )}

            <div className={'anomaly-console-observation ' + severityTone(selected.severity)}>
              <div><span className="anomaly-console-kicker">OBSERVED CONDITION</span><h3>{selected.description}</h3></div>
              <div className="anomaly-console-observation-facts"><Fact label="Detected" value={fmtDateTime(selected.detected_at)} /><Fact label="Observed" value={(selected.occurrence_count ?? 1) + ' times'} /><Fact label="Rounds" value={String(selected.monitoring_count ?? 0)} /></div>
            </div>

            <div className="anomaly-console-ledger">
              <section className="anomaly-console-ledger-panel measured">
                <div className="anomaly-console-section-head"><div><span className="anomaly-console-step">01</span><h3>Directly measured</h3></div><span className={'anomaly-console-evidence-state ' + cause.evidenceStatus}>{cause.evidenceStatus.replace(/_/g, ' ')}</span></div>
                <p className="anomaly-console-section-intro">Facts retained from AHCLM active measurement for this problem.</p>
                {cause.evidence.length > 0 ? <ul className="anomaly-console-evidence-list">{cause.evidence.map((item, index) => <li key={item + '-' + index}>{item}</li>)}</ul> : <p className="anomaly-console-muted">No evidence details were retained.</p>}
                {cause.pendingReason && <p className="anomaly-console-pending">Pending: {cause.pendingReason}</p>}
              </section>
              <section className="anomaly-console-ledger-panel interpretation">
                <div className="anomaly-console-section-head"><div><span className="anomaly-console-step">02</span><h3>Cause assessment</h3></div><span className={'anomaly-console-certainty ' + cause.classification}>{cause.classification}</span></div>
                <p className="anomaly-console-section-intro">Ranked mechanism assessment from longitudinal measurements. It does not claim private operator intent.</p>
                {cause.diagnosis ? (
                  <div className="diagnosis-panel">
                    {(() => {
                      const hypotheses = Array.isArray(cause.diagnosis.hypotheses) ? cause.diagnosis.hypotheses : [];
                      return (
                        <>
                    <div className="diagnosis-primary"><span>{cause.diagnosis.primary_label}</span><strong>{cause.diagnosis.confidence}</strong></div>
                    <p className="anomaly-console-cause-text">{cause.diagnosis.summary}</p>
                    <div className="diagnosis-meta">{cause.diagnosis.measured_rounds} measurement rounds · {cause.diagnosis.transition_rounds} transitions · {Math.round(cause.diagnosis.evidence_completeness * 100)}% evidence completeness</div>
                    <div className="diagnosis-hypotheses">
                      {hypotheses.slice(0, 3).map((hypothesis) => (
                        <div className="diagnosis-hypothesis" key={hypothesis.code}>
                          <div><span>{hypothesis.label}</span><b>{Math.round(hypothesis.score * 100)}%</b></div>
                          <div className="diagnosis-meter"><i style={{ width: `${Math.round(hypothesis.score * 100)}%` }} /></div>
                          <small>{hypothesis.rationale}</small>
                        </div>
                      ))}
                    </div>
                    {cause.diagnosis.measurement_plan?.length ? <div className="diagnosis-plan"><span>Next evidence</span>{cause.diagnosis.measurement_plan.map((step) => <p key={step}>{step}</p>)}</div> : null}
                        </>
                      );
                    })()}
                  </div>
                ) : <p className="anomaly-console-cause-text">{cause.reason || 'No cause detail recorded.'}</p>}
              </section>
            </div>

            <section className="anomaly-console-history">
              <div className="anomaly-console-section-head"><div><span className="anomaly-console-step">03</span><h3>Measurement history</h3></div><span className="anomaly-console-history-scope">{selected.evidence_scope || 'Counts use retained monitoring operations.'}</span></div>
              <div className="anomaly-console-history-grid"><HistoryFact label="Successful rounds" value={selected.successful_monitoring_count ?? 0} tone="good" /><HistoryFact label="Failed rounds" value={selected.failed_monitoring_count ?? 0} tone="bad" /><HistoryFact label="First observed" value={fmtDateTime(selected.first_observed_at)} /><HistoryFact label="Last observed" value={fmtDateTime(selected.last_observed_at)} /></div>
            </section>

            <section className="anomaly-console-cost">
              <div className="anomaly-console-section-head"><div><span className="anomaly-console-step">04</span><h3>Response cost</h3></div>{costLoading && <span className="anomaly-console-cost-loading"><span className="spinner" /> Calculating</span>}</div>
              {costError && <div className="anomaly-console-cost-message error">Cost evidence could not be loaded for this domain.</div>}
              {!costLoading && !costError && costData?.cost && <CostBreakdown cost={costData.cost} />}
              {!costLoading && !costError && !costData?.cost && <div className="anomaly-console-cost-message">No current-certificate cost case is open. The finding may be historical or no longer active.</div>}
            </section>
          </section>
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

function HistoryFact({ label, value, tone = '' }: { label: string; value: string | number; tone?: string }) {
  return <div><span className={tone}>{label}</span><strong>{value}</strong></div>;
}
