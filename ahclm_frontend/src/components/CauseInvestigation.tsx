import { statusLabel } from '@/lib/labels';
import { CheckCircle2, GitBranch, Repeat, ShieldAlert, ShieldQuestion } from 'lucide-react';
import type {
  Anomaly,
  CDNEvidence,
  CertificateExhibit,
  ChangeExhibit,
  EvidenceEndpoint,
  EvidenceRound,
  FindingImpact,
  Investigation,
  InvestigationProofStep,
  ProviderExhibit,
  RelatedNameProbe,
} from '@/types';
import CertificateRecord from '@/components/CertificateRecord';
import { causeKindOf } from '@/lib/causeKind';
import { fmtDateTime, shortFp } from '@/lib/format';

const LEAF_TONES = 5;

function findingTone(value?: string): 'incident' | 'expected' | 'insufficient' {
  if (value === 'expected') return 'expected';
  if (value === 'insufficient') return 'insufficient';
  return 'incident';
}

function certLookup(certificates: CertificateExhibit[] | undefined): Map<string, CertificateExhibit> {
  const map = new Map<string, CertificateExhibit>();
  for (const certificate of certificates ?? []) {
    if (certificate.fingerprint) map.set(certificate.fingerprint, certificate);
  }
  return map;
}

function leafTone(fingerprint?: string, tones?: Map<string, number>): number | undefined {
  if (!fingerprint || !tones) return undefined;
  return tones.get(fingerprint);
}

function leafClass(tone?: number): string {
  return tone === undefined ? 'leaf-none' : `leaf-${tone % LEAF_TONES}`;
}

function CertChip({
  fingerprint,
  certificates,
  tones,
}: {
  fingerprint?: string;
  certificates: Map<string, CertificateExhibit>;
  tones?: Map<string, number>;
}) {
  const cert = fingerprint ? certificates.get(fingerprint) : undefined;
  const tone = leafTone(fingerprint, tones);
  return (
    <span className={'cause-inv-cert ' + leafClass(tone)} title={fingerprint || "未采集"}>
      <span className="cause-inv-swatch" aria-hidden="true" />
      <span>
        <code>{shortFp(fingerprint)}</code>
        {(cert?.issuer_cn || cert?.key_algorithm) && (
          <small>{[cert?.issuer_cn, cert?.key_algorithm].filter(Boolean).join(' · ')}</small>
        )}
      </span>
    </span>
  );
}

function relationLabel(change: ChangeExhibit): string {
  if (change.coexisting || change.change_class === 'coexisting_leaf') return "同轮次出现两张证书";
  if (change.endpoint_relation === 'same_endpoint') return "同一端点";
  if (change.endpoint_relation === 'different_endpoint') return "不同端点";
  return "未保留端点";
}

function transitionDelta(change: ChangeExhibit): string | undefined {
  const parts: string[] = [];
  if (change.sans_added?.length) parts.push(`SAN +${change.sans_added.join(', ')}`);
  if (change.sans_removed?.length) parts.push(`SAN −${change.sans_removed.join(', ')}`);
  if (change.issuer_changed) parts.push(`签发者 ${change.previous_issuer_cn || '?'} → ${change.issuer_cn || '?'}`);
  if (change.common_name_changed) parts.push(`CN ${change.previous_common_name || '?'} → ${change.common_name || '?'}`);
  if (change.key_algorithm_changed) parts.push(`公钥 ${change.previous_key_algorithm || '?'} → ${change.key_algorithm || '?'}`);
  if (change.public_key_changed) parts.push("公钥已变更");
  return parts.length ? parts.join(' · ') : undefined;
}

function formatSANs(values?: string[]): string {
  if (!values?.length) return "未采集";
  if (values.length <= 3) return values.join(', ');
  return `${values.slice(0, 3).join(', ')} +${values.length - 3}`;
}

function selectionLabel(value?: string): string | undefined {
  switch (value) {
    case 'sni_selects_name_matching_certificate': return "SNI 选择了名称匹配的叶证书";
    case 'sni_selects_alternate_name_matching_certificate': return "SNI 选择了另一张名称匹配的叶证书";
    case 'same_name_matching_certificate_with_or_without_sni': return "有无 SNI 均返回同一张匹配证书";
    case 'same_default_certificate_name_mismatch': return "返回同一张默认证书；名称不匹配";
    case 'sni_selects_certificate_not_matching_name': return "SNI 选择的叶证书不匹配名称";
    case 'no_sni_control_failed': return "空 SNI 对照失败";
    case 'primary_sni_probe_failed': return "SNI 探测失败";
    default: return value;
  }
}

function uniqueLines(values: string[] | undefined, limit = 6): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values ?? []) {
    const text = value.trim();
    if (!text || seen.has(text) || isNarrativeEvidence(text)) continue;
    seen.add(text);
    out.push(text);
    if (out.length >= limit) break;
  }
  return out;
}

function isNarrativeEvidence(value: string): boolean {
  const lower = value.toLowerCase();
  return [
    'this is a problem',
    'this is not counted',
    'this is a suspected',
    'cannot reappear',
    'cannot explain',
    'falsif',
    'not observed on the control plane',
    'that operational sequence',
    'strong-evidence',
    'propagation window',
    'no endpoint divergence',
    'no churn shape',
    'missing comparison',
    'later round',
    'best-supported',
  ].some((marker) => lower.includes(marker));
}

function endpointExhibit(endpoint: EvidenceEndpoint) {
  return {
    ip_address: endpoint.ip_address,
    active_dns: endpoint.active_dns,
    success: endpoint.success,
    requested_sni: endpoint.requested_sni,
    fingerprint: endpoint.fingerprint,
    default_fingerprint: endpoint.default_fingerprint,
    spki_fingerprint: endpoint.spki_fingerprint,
    issuer_cn: endpoint.issuer_cn,
    key_algorithm: endpoint.key_algorithm,
    selection_interpretation: endpoint.selection_interpretation,
    error: endpoint.error,
  };
}

function exhibitsFromRounds(rounds: EvidenceRound[]): { groups: ProviderExhibit[]; certificates: CertificateExhibit[] } {
  const source = rounds.find((round) => round.endpoints.length > 0);
  if (!source) return { groups: [], certificates: [] };

  const grouped = new Map<string, ReturnType<typeof endpointExhibit>[]>();
  for (const endpoint of source.endpoints) {
    const group = endpoint.provider_group || '—';
    const list = grouped.get(group) ?? [];
    list.push(endpointExhibit(endpoint));
    grouped.set(group, list);
  }
  const groups: ProviderExhibit[] = [...grouped.entries()].map(([group, endpoints]) => {
    const leaves = new Set(endpoints.map((endpoint) => endpoint.fingerprint).filter(Boolean));
    return { group, conflict: leaves.size > 1, leaf_count: leaves.size, endpoints };
  });

  const certificates = new Map<string, CertificateExhibit>();
  for (const round of rounds) {
    for (const endpoint of round.endpoints) {
      mergeCertificate(certificates, endpoint);
    }
  }
  return { groups, certificates: [...certificates.values()] };
}

function mergeCertificate(map: Map<string, CertificateExhibit>, source: Partial<CertificateExhibit> & { fingerprint?: string }) {
  if (!source.fingerprint) return;
  const current = map.get(source.fingerprint) ?? { fingerprint: source.fingerprint };
  map.set(source.fingerprint, {
    fingerprint: current.fingerprint,
    spki_fingerprint: current.spki_fingerprint || source.spki_fingerprint,
    serial_number: current.serial_number || source.serial_number,
    issuer_cn: current.issuer_cn || source.issuer_cn,
    common_name: current.common_name || source.common_name,
    sans: current.sans?.length ? current.sans : source.sans,
    key_algorithm: current.key_algorithm || source.key_algorithm,
    validity_days: current.validity_days || source.validity_days,
    not_before: current.not_before || source.not_before,
    not_after: current.not_after || source.not_after,
  });
}

function enrichCertificates(
  certificates: CertificateExhibit[],
  groups: ProviderExhibit[],
  rounds: EvidenceRound[],
): CertificateExhibit[] {
  const map = new Map<string, CertificateExhibit>();
  for (const certificate of certificates) mergeCertificate(map, certificate);
  for (const group of groups) {
    for (const endpoint of group.endpoints) mergeCertificate(map, endpoint);
  }
  for (const round of rounds) {
    for (const endpoint of round.endpoints) mergeCertificate(map, endpoint);
  }
  return [...map.values()];
}

function leafTonesFor(fingerprints: string[]): Map<string, number> {
  const unique = [...new Set(fingerprints.filter(Boolean))].sort();
  return new Map(unique.map((fingerprint, index) => [fingerprint, index % LEAF_TONES]));
}

function numberedSteps(visible: Record<string, boolean>): Record<string, string> {
  const order = ['problem', 'impact', 'proof', 'inference', 'evidence', 'cause'];
  const labels: Record<string, string> = {};
  let index = 1;
  for (const key of order) {
    if (!visible[key]) continue;
    labels[key] = String(index).padStart(2, '0');
    index += 1;
  }
  return labels;
}

function becauseLabel(kind: 'proven' | 'inferred'): string {
  return kind === 'inferred' ? "当前依据：" : '依据：';
}

function impactCeilingLabel(value?: string): string {
  switch (value) {
    case 'client_rejection': return "客户端可能拒绝连接";
    case 'split_view': return "视图不一致";
    case 'pending_expiry': return "即将到期";
    case 'extra_issuance': return "额外签发";
    case 'key_continuity': return "公钥不变";
    case 'measurement_only': return "仅限当前测量点";
    case 'none': return "未发现问题";
    default: return (value ? statusLabel(value) : '影响');
  }
}

function audienceLabel(value?: string): string {
  switch (value) {
    case 'clients': return '客户端';
    case 'operators': return '运营者';
    case 'relying_parties': return "依赖方";
    default: return value || '';
  }
}

function causeKindMeta(kind: 'proven' | 'inferred'): { stamp: string; heading: string; badge: string; note: string } {
  if (kind === 'inferred') {
    return {
      stamp: 'inferred',
      heading: "推测原因",
      badge: 'speculative',
      note: "该原因是对下方测量的推断，后续轮次可证实或推翻它。",
    };
  }
  return {
    stamp: 'established',
    heading: "确定原因",
    badge: 'deterministic',
    note: "该原因由下方已保留的测量证据确定。",
  };
}

function ClaimBody({
  label,
  claim,
  evidence,
  kind,
  stamp,
}: {
  label?: string;
  claim: string;
  evidence?: string[];
  kind: 'proven' | 'inferred';
  stamp?: string;
}) {
  const items = uniqueLines(evidence, 12);
  return (
    <div className={'cause-inv-claim-body ' + kind}>
      {(label || stamp) && (
        <p className="cause-inv-claim-label">
          {stamp && <span className={'cause-inv-kind-stamp ' + kind}>{statusLabel(stamp)}</span>}
          {label}
        </p>
      )}
      <p className="cause-inv-claim-text">{claim}</p>
      {items.length > 0 && (
        <>
          <p className="cause-inv-because">{becauseLabel(kind)}</p>
          <ul className="cause-inv-claim-evidence">
            {items.map((item, index) => (
              <li key={item + '-' + index}>{item}</li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

function ImpactSection({ impact, step }: { impact: FindingImpact; step: string }) {
  const effects = (impact.effects ?? []).filter((effect) => effect.claim || effect.label);
  const forbidden = uniqueLines(impact.not_established, 6);
  return (
    <section className="cause-inv-impact" aria-label="测得的影响">
      <div className="cause-inv-kicker">
        <span className="anomaly-console-step">{step}</span>
        <h3>影响</h3>
        <span className={'cause-inv-class ' + (impact.severity_ceiling === 'none' ? 'expected' : impact.severity_ceiling === 'measurement_only' ? 'insufficient' : 'incident')}>
          {impactCeilingLabel(impact.severity_ceiling)}
        </span>
      </div>
      {impact.summary && <p className="cause-inv-impact-summary">{impact.summary}</p>}
      {effects.length > 0 && (
        <ul className="cause-inv-impact-effects">
          {effects.map((effect, index) => (
            <li key={(effect.code || effect.label) + '-' + index} className={'cause-inv-impact-effect ' + (effect.kind === 'inferred' ? 'inferred' : 'proven')}>
              <p className="cause-inv-claim-label">
                <span className={'cause-inv-kind-stamp ' + (effect.kind === 'inferred' ? 'inferred' : 'proven')}>
                  {effect.kind === 'inferred' ? 'inferred' : 'established'}
                </span>
                {effect.label}
                {effect.audience ? <small> · {audienceLabel(effect.audience)}</small> : null}
              </p>
              <p className="cause-inv-claim-text">{effect.claim}</p>
              {uniqueLines(effect.evidence, 6).length > 0 && (
                <ul className="cause-inv-claim-evidence">
                  {uniqueLines(effect.evidence, 6).map((line) => <li key={line}>{line}</li>)}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}
      {forbidden.length > 0 && (
        <div className="cause-inv-impact-limits">
          <span>当前测量尚未确定</span>
          <ul>{forbidden.map((line) => <li key={line}>{line}</li>)}</ul>
        </div>
      )}
    </section>
  );
}

function ClaimChain({ steps, kind }: { steps: InvestigationProofStep[]; kind: 'proven' | 'inferred' }) {
  const visible = steps.filter((step) => uniqueLines(step.evidence, 12).length > 0);
  return (
    <ol className={'cause-inv-chain ' + kind}>
      {visible.map((step, index) => (
        <li key={(step.label || step.claim) + '-' + index} className="cause-inv-claim">
          <span className="cause-inv-claim-index" aria-hidden="true">{String(index + 1).padStart(2, '0')}</span>
          <ClaimBody label={step.label} claim={step.claim} evidence={step.evidence} kind={kind} />
        </li>
      ))}
    </ol>
  );
}

function measuredFrom(steps: InvestigationProofStep[]): string[] {
  const out: string[] = [];
  for (const step of steps) {
    for (const item of uniqueLines(step.evidence, 12)) {
      if (!out.includes(item)) out.push(item);
    }
  }
  return out.slice(0, 12);
}

function causeArgument(
  investigation: Investigation,
  proofSteps: InvestigationProofStep[],
  inferenceSteps: InvestigationProofStep[],
): { label?: string; claim: string; evidence: string[]; kind: 'proven' | 'inferred' } | null {
  const provenConclusion = [...proofSteps].reverse().find((step) => step.label === "结论");
  const inferredReading = [...inferenceSteps].reverse().find((step) => uniqueLines(step.evidence, 12).length > 0);
  const inferredCause = causeKindOf(investigation) === 'inferred';
  if (inferredReading && inferredCause) {
    const evidence = uniqueLines(inferredReading.evidence, 12);
    if (evidence.length === 0) return null;
    return {
      label: investigation.cause_label || inferredReading.label,
      claim: inferredReading.claim || investigation.cause,
      evidence,
      kind: 'inferred',
    };
  }
  if (provenConclusion) {
    return {
      label: investigation.cause_label || provenConclusion.label,
      claim: provenConclusion.claim || investigation.cause,
      evidence: uniqueLines(provenConclusion.evidence, 12).length ? uniqueLines(provenConclusion.evidence, 12) : measuredFrom(proofSteps),
      kind: 'proven',
    };
  }
  const claim = investigation.cause || investigation.cause_label;
  if (!claim) return null;
  return {
    label: investigation.cause && investigation.cause_label ? investigation.cause_label : undefined,
    claim,
    evidence: measuredFrom([...proofSteps, ...inferenceSteps]),
    kind: inferredCause ? 'inferred' : 'proven',
  };
}

export default function CauseInvestigation({
  anomaly,
  investigation,
  rounds = [],
  roundsLoading = false,
}: {
  anomaly: Anomaly;
  investigation: Investigation;
  rounds?: EvidenceRound[];
  roundsLoading?: boolean;
}) {
  const tone = findingTone(investigation.finding_class || anomaly.finding_class);
  const churnFinding = anomaly.type === 'frequent_change' || anomaly.type === 'early_renewal' || anomaly.type === 'same_key';
  const diversityFinding = anomaly.type === 'deployment_failure' || anomaly.type === 'stale_after_change';
  const tlsFinding = anomaly.type === 'expired_endpoint'
    || anomaly.type === 'hostname_mismatch'
    || anomaly.type === 'not_yet_valid'
    || anomaly.type === 'local_chain_validation_failed'
    || anomaly.type === 'endpoint_probe_inconclusive';
  const assignmentFinding = diversityFinding || tlsFinding;
  const proofSteps = investigation.proof ?? [];
  const provenEvidence = new Set(proofSteps.flatMap((step) => uniqueLines(step.evidence, 24)));
  const inferenceSteps = (diversityFinding
    ? (investigation.inference ?? []).map((step) => {
      const leftover = uniqueLines(step.evidence, 12).filter((line) => !provenEvidence.has(line));
      if (leftover.length > 0) return { ...step, evidence: leftover };
      if (step.basis && !provenEvidence.has(step.basis)) return { ...step, evidence: [step.basis] };
      return { ...step, evidence: [] };
    }).filter((step) => uniqueLines(step.evidence, 12).length > 0)
    : (investigation.inference ?? []));
  const facts = uniqueLines(investigation.facts, 8);
  const ruledOut = (investigation.ruled_out ?? []).slice(0, 3);
  const reversals = uniqueLines(investigation.reversal_conditions, 4);
  const internalEvidence = investigation.internal_evidence;
  const derived = exhibitsFromRounds(assignmentFinding ? rounds : []);
  const groups = assignmentFinding
    ? (investigation.provider_groups?.length ? investigation.provider_groups : derived.groups)
    : [];
  const changes = (churnFinding || anomaly.type === 'stale_after_change')
    ? (investigation.change_sequence ?? [])
    : [];
  const relatedNames = (churnFinding || anomaly.type === 'stale_after_change')
    ? (investigation.related_names ?? [])
    : [];
  const certs = enrichCertificates(
    investigation.certificates?.length ? investigation.certificates : (assignmentFinding ? derived.certificates : []),
    groups,
    assignmentFinding ? rounds : [],
  );
  const certificates = certLookup(certs);
  const tones = leafTonesFor([
    ...certs.map((certificate) => certificate.fingerprint),
    ...groups.flatMap((group) => group.endpoints.map((endpoint) => endpoint.fingerprint || '')),
    ...rounds.flatMap((round) => round.endpoints.map((endpoint) => endpoint.fingerprint || '')),
  ]);
  const HeadlineIcon = tone === 'expected' ? CheckCircle2 : tone === 'insufficient' ? ShieldQuestion : ShieldAlert;
  const showAssignment = assignmentFinding;
  const showEndpointTable = assignmentFinding;
  const showRounds = assignmentFinding && rounds.length > 0;
  const showProblem = Boolean(investigation.problem || investigation.why_this_is_a_problem);
  const impact = investigation.impact;
  const showImpact = Boolean(impact && (impact.summary || (impact.effects && impact.effects.length)));
  const measuredProof = proofSteps.filter((step) => step.label !== "结论" && uniqueLines(step.evidence, 12).length > 0);
  const measuredInference = inferenceSteps.filter((step) => uniqueLines(step.evidence, 12).length > 0);
  const showProof = measuredProof.length > 0;
  const showInference = measuredInference.length > 0;
  const showData = (showAssignment && groups.length > 0) || certs.length > 0 || changes.length > 0 || relatedNames.length > 0 || showRounds || roundsLoading;
  const showEvidence = !showProof && (facts.length > 0 || showData);
  const showSource = showProof && (showData || roundsLoading);
  const cause = causeArgument(investigation, proofSteps, inferenceSteps);
  const showCause = Boolean(cause || ruledOut.length);
  const step = numberedSteps({
    problem: showProblem,
    impact: showImpact,
    proof: showProof,
    inference: showInference,
    evidence: showEvidence,
    cause: showCause,
  });
  const sourceRecord = (
    <>
      {roundsLoading && rounds.length === 0 && groups.length === 0 && certs.length === 0 && changes.length === 0 ? (
        <div className="anomaly-console-evidence-loading"><span className="spinner" /> 正在加载测量记录…</div>
      ) : showData ? (
        <>
          {showAssignment && (
            <CertificateDiversityMap groups={groups} rounds={rounds} certificates={certs} tones={tones} cdn={investigation.cdn} />
          )}
          {showEndpointTable && (
            <CollectedEndpointTable groups={groups} rounds={rounds} certificates={certificates} tones={tones} />
          )}
          {changes.length > 0 && <ChangeStrip changes={changes} certificates={certificates} tones={tones} />}
          {relatedNames.length > 0 && <RelatedNameStrip probes={relatedNames} />}
          {certs.length > 0 && <CertificateTable certificates={certs} tones={tones} />}
          {showRounds && <MeasurementRounds rounds={rounds} certificates={certificates} tones={tones} />}
        </>
      ) : (
        <p className="anomaly-console-muted">该发现未保留端点、证书或轮次记录。</p>
      )}
    </>
  );

  return (
    <div className={'cause-inv ' + tone + (showProof ? ' has-proof' : '')}>
      {showProblem && (
        <section className="cause-inv-problem" aria-label="测得的问题">
          <div className="cause-inv-kicker">
            <span className="anomaly-console-step">{step.problem}</span>
            <h3>问题</h3>
            <span className={'cause-inv-class ' + tone}>{tone === 'expected' ? "预期特征" : tone === 'insufficient' ? "证据不足" : "测得的问题"}</span>
          </div>
          <div className="cause-inv-problem-copy">
            <HeadlineIcon size={18} />
            <div className="cause-inv-claim-body">
              {investigation.problem && <p className="cause-inv-claim-text">{investigation.problem}</p>}
              {investigation.why_this_is_a_problem && (
                <>
                  <p className="cause-inv-because">依据：</p>
                  <ul className="cause-inv-claim-evidence">
                    <li>{investigation.why_this_is_a_problem}</li>
                  </ul>
                </>
              )}
            </div>
          </div>
        </section>
      )}

      {showImpact && impact && (
        <ImpactSection impact={impact} step={step.impact} />
      )}

      {showProof && (
        <section className="cause-inv-proof-section" aria-label="已证实的步骤">
          <div className="cause-inv-kicker">
            <span className="anomaly-console-step">{step.proof}</span>
            <h3>证据链</h3>
            <span className="cause-inv-class proven">逐项结论及其证据</span>
          </div>
          <ClaimChain steps={measuredProof} kind="proven" />
        </section>
      )}

      {showInference && (
        <section className="cause-inv-inference-section" aria-label="推断步骤">
          <div className="cause-inv-kicker">
            <span className="anomaly-console-step">{step.inference}</span>
            <h3>推断</h3>
            <span className="cause-inv-class insufficient">逐项推断及其测量依据</span>
          </div>
          <ClaimChain steps={measuredInference} kind="inferred" />
          {reversals.length > 0 && (
            <div className="cause-inv-limits">
              <div>
                <span>证伪条件</span>
                <ul>{reversals.map((item) => <li key={item}>{item}</li>)}</ul>
              </div>
            </div>
          )}
        </section>
      )}

      {showEvidence && (
        <section className="cause-inv-evidence" aria-label="已保留的证据">
          <div className="cause-inv-kicker">
            <span className="anomaly-console-step">{step.evidence}</span>
            <h3>证据</h3>
          </div>
          <div className={'cause-inv-split' + (showData || roundsLoading ? '' : ' text-only')}>
            <div className="cause-inv-summary">
              <span>描述</span>
              {facts.length > 0 ? (
                <ul className="cause-inv-facts">
                  {facts.map((fact, index) => <li key={fact + '-' + index}>{fact}</li>)}
                </ul>
              ) : (
                <p className="anomaly-console-muted">未保留文字摘要；右侧展示已采集的测量记录。</p>
              )}
            </div>
            <div className="cause-inv-data">
              <span>测量记录</span>
              {sourceRecord}
            </div>
          </div>
        </section>
      )}

      {showCause && (
        <section className={'cause-inv-cause' + (cause?.kind === 'inferred' ? ' inferred' : ' established')} aria-label={cause ? causeKindMeta(cause.kind).heading : "原因"}>
          <div className="cause-inv-kicker">
            <span className="anomaly-console-step">{step.cause}</span>
            <h3>{cause ? causeKindMeta(cause.kind).heading : "原因"}</h3>
            {cause && (
              <span className={'cause-inv-class ' + (cause.kind === 'inferred' ? 'insufficient' : 'proven')}>
                {statusLabel(causeKindMeta(cause.kind).badge)}
              </span>
            )}
          </div>
          {cause && <p className="cause-inv-kind-note">{causeKindMeta(cause.kind).note}</p>}
          {cause && (
            <ClaimBody
              label={cause.label}
              claim={cause.claim}
              evidence={cause.evidence}
              kind={cause.kind}
              stamp={causeKindMeta(cause.kind).stamp}
            />
          )}
          {ruledOut.length > 0 && (
            <div className="cause-inv-ruled">
              <span>已排除的解释</span>
              {ruledOut.map((item) => (
                <div key={item.label} className="cause-inv-claim-body">
                  <p className="cause-inv-claim-text">{item.label}</p>
                  {item.reason && (
                    <>
                      <p className="cause-inv-because">依据：</p>
                      <ul className="cause-inv-claim-evidence">
                        <li>{item.reason}</li>
                      </ul>
                    </>
                  )}
                </div>
              ))}
            </div>
          )}
          {internalEvidence && (
            <div className="cause-inv-internal-evidence">
              <span>控制面证据</span>
              <strong>{statusLabel(internalEvidence.status)} · {internalEvidence.correlated_events}/{internalEvidence.event_count} 条关联事件</strong>
              <p>{internalEvidence.conclusion || internalEvidence.determination}</p>
              {internalEvidence.missing && internalEvidence.missing.length > 0 && (
                <ul>{internalEvidence.missing.slice(0, 4).map((item) => <li key={item}>{item}</li>)}</ul>
              )}
            </div>
          )}
        </section>
      )}

      {showSource && (
        <details className="cause-inv-source">
          <summary>
            <span>源记录</span>
            <small>证据链引用的端点、证书与轮次表</small>
          </summary>
          <div className="cause-inv-source-body">{sourceRecord}</div>
        </details>
      )}
    </div>
  );
}

type EndpointRow = {
  ip: string;
  network: string;
  conflict: boolean;
  active: boolean;
  success: boolean;
  fingerprint?: string;
  issuer?: string;
  key?: string;
  selection?: string;
  error?: string;
};

function endpointRows(groups: ProviderExhibit[], rounds: EvidenceRound[]): EndpointRow[] {
  const rows: EndpointRow[] = [];
  for (const group of groups) {
    for (const endpoint of group.endpoints) {
      rows.push({
        ip: endpoint.ip_address,
        network: group.group,
        conflict: group.conflict,
        active: endpoint.active_dns,
        success: endpoint.success,
        fingerprint: endpoint.fingerprint,
        issuer: endpoint.issuer_cn,
        key: endpoint.key_algorithm,
        selection: selectionLabel(endpoint.selection_interpretation),
        error: endpoint.error,
      });
    }
  }
  if (rows.length === 0 && rounds[0]) {
    for (const endpoint of rounds[0].endpoints) {
      rows.push({
        ip: endpoint.ip_address,
        network: endpoint.provider_group || '—',
        conflict: false,
        active: endpoint.active_dns,
        success: endpoint.success,
        fingerprint: endpoint.fingerprint,
        issuer: endpoint.issuer_cn,
        key: endpoint.key_algorithm,
        selection: selectionLabel(endpoint.selection_interpretation),
        error: endpoint.error,
      });
    }
  }
  return rows;
}

function CertificateDiversityMap({
  groups,
  rounds,
  certificates,
  tones,
  cdn,
}: {
  groups: ProviderExhibit[];
  rounds: EvidenceRound[];
  certificates: CertificateExhibit[];
  tones: Map<string, number>;
  cdn?: CDNEvidence | null;
}) {
  const rows = endpointRows(groups, rounds);
  if (rows.length === 0 && certificates.length < 2) return null;
  const lookup = certLookup(certificates);
  const leaves = [...new Set(rows.map((row) => row.fingerprint).filter((value): value is string => Boolean(value)))];
  const networks = [...new Map(rows.map((row) => [row.network, row.conflict])).entries()];
  const mixed = leaves.length > 1;
  const conflictCount = networks.filter(([, conflict]) => conflict).length;
  const servedBy = (fingerprint: string) => rows.filter((row) => row.fingerprint === fingerprint);
  const compareRows = mixed ? certificateDiffs(certificates, leaves) : [];
  const vendorMethod = cdn?.method === 'vendor';
  const vendorLabel = (network: string) => groups.find((group) => group.group === network)?.vendor;

  return (
    <div className={'cause-inv-diversity' + (mixed ? ' mixed' : '')}>
      <div className="cause-inv-exhibit-head">
        <GitBranch size={14} />
        <span>证书分配</span>
        <small>
          {leaves.length || certificates.length} 种 叶证书
          {mixed ? ` · ${conflictCount > 0 ? `${conflictCount} 个网络内部不一致` : vendorMethod ? "按已识别 CDN 分析" : "按网络分区分析"}` : ''}
        </small>
      </div>
      <p className="cause-inv-diversity-lead">
        {mixed
          ? "同色端点返回同一张叶证书；不同颜色表示同次测量中的不同证书。"
          : "所有响应端点均返回同一张叶证书。"}
      </p>
      {cdn && (
        <p className={'cause-inv-cdn-method ' + (vendorMethod ? 'vendor' : 'network')}>
          {vendorMethod
            ? `所有响应端点均已识别 CDN 服务商，共涉及 ${cdn.distinct_vendors} 家 CDN。`
            : "CDN 识别不完整，使用 IPv4 /16 和 IPv6 /32 网络分区分析。"}
          {cdn.note ? ` ${cdn.note}` : ''}
        </p>
      )}
      <div className="cause-inv-leaf-grid">
        {(certificates.length ? certificates : leaves.map((fingerprint) => lookup.get(fingerprint) ?? { fingerprint })).map((certificate) => {
          const hosts = servedBy(certificate.fingerprint);
          const tone = leafTone(certificate.fingerprint, tones);
          return (
            <article key={certificate.fingerprint} className={'cause-inv-leaf-card ' + leafClass(tone)}>
              <header>
                <span className="cause-inv-swatch" aria-hidden="true" />
                <strong>叶证书 {tone === undefined ? '?' : String.fromCharCode(65 + (tone % LEAF_TONES))}</strong>
                <small>{hosts.length} 端点</small>
              </header>
              <CertificateRecord
                certificate={certificate}
                heading={`叶证书 ${tone === undefined ? '?' : String.fromCharCode(65 + (tone % LEAF_TONES))}`}
              />
            </article>
          );
        })}
      </div>
      {networks.length > 0 && (
        <div className="cause-inv-network-map">
          {networks.map(([network, conflict]) => (
            <section key={network} className={conflict ? 'conflict' : ''}>
              <header>
                <code>{network}{vendorLabel(network) ? ` · ${vendorLabel(network)}` : ''}</code>
                <b>{conflict ? "内部不一致" : "同一张叶证书"}</b>
              </header>
              <ul>
                {rows.filter((row) => row.network === network).map((row) => (
                  <li key={row.ip} className={leafClass(leafTone(row.fingerprint, tones))}>
                    <span className="cause-inv-swatch" aria-hidden="true" />
                    <div>
                      <code>{row.ip}</code>
                      <small>{row.active ? "当前 DNS 地址" : "不在当前 DNS 中"} · {row.success ? "TLS 已响应" : row.error || '失败'}</small>
                    </div>
                    <CertChip fingerprint={row.fingerprint} certificates={lookup} tones={tones} />
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}
      {compareRows.length > 0 && (
        <div className="cause-inv-diff">
          <div className="cause-inv-exhibit-head">
            <span>证书之间的差异</span>
            <small>{compareRows.filter((row) => row.disagrees).length} 字段 存在差异</small>
          </div>
          <div className="cause-inv-diff-legend">
            {leaves.map((fingerprint) => (
              <CertChip key={fingerprint} fingerprint={fingerprint} certificates={lookup} tones={tones} />
            ))}
          </div>
          <div className="cause-inv-diff-grid" style={{ gridTemplateColumns: `minmax(92px, 0.7fr) repeat(${leaves.length}, minmax(0, 1fr))` }}>
            <span>字段</span>
            {leaves.map((fingerprint) => (
              <span key={fingerprint} className={leafClass(leafTone(fingerprint, tones))}>叶证书 {String.fromCharCode(65 + ((leafTone(fingerprint, tones) ?? 0) % LEAF_TONES))}</span>
            ))}
            {compareRows.map((row) => (
              <div key={row.field} className={'cause-inv-diff-row ' + (row.disagrees ? 'disagrees' : 'agrees')}>
                <strong>{row.field}</strong>
                {row.values.map((value, index) => (
                  <p key={leaves[index]} className={leafClass(leafTone(leaves[index], tones))}>
                    <span className="cause-inv-diff-leaf">叶证书 {String.fromCharCode(65 + ((leafTone(leaves[index], tones) ?? 0) % LEAF_TONES))}</span>
                    {value}
                  </p>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function certificateDiffs(certificates: CertificateExhibit[], leaves: string[]) {
  const lookup = certLookup(certificates);
  const fields: { field: string; read: (certificate?: CertificateExhibit) => string }[] = [
    { field: "指纹", read: (certificate) => shortFp(certificate?.fingerprint, 20) },
    { field: "序列号", read: (certificate) => certificate?.serial_number || "未采集" },
    { field: "签发者", read: (certificate) => certificate?.issuer || certificate?.issuer_cn || "未采集" },
    { field: "主体", read: (certificate) => certificate?.subject || certificate?.common_name || "未采集" },
    { field: 'SAN', read: (certificate) => formatSANs(certificate?.sans) },
    { field: "公钥", read: (certificate) => certificate?.key_algorithm ? `${certificate.key_algorithm}${certificate.key_size ? ` ${certificate.key_size}` : ''}` : "未采集" },
    { field: "签名算法", read: (certificate) => certificate?.signature_algorithm || "未采集" },
    { field: 'SPKI', read: (certificate) => shortFp(certificate?.spki_fingerprint, 16) },
    {
      field: "有效期",
      read: (certificate) => {
        if (certificate?.not_before || certificate?.not_after) {
          return `${fmtDateTime(certificate?.not_before)} → ${fmtDateTime(certificate?.not_after)}`;
        }
        return certificate?.validity_days ? `${certificate.validity_days} 天` : "未采集";
      },
    },
  ];
  return fields.map((item) => {
    const values = leaves.map((fingerprint) => item.read(lookup.get(fingerprint)));
    const captured = values.filter((value) => value !== "未采集");
    return {
      field: item.field,
      values,
      disagrees: captured.length > 0 && new Set(values).size > 1,
    };
  });
}

function CollectedEndpointTable({
  groups,
  rounds,
  certificates,
  tones,
}: {
  groups: ProviderExhibit[];
  rounds: EvidenceRound[];
  certificates: Map<string, CertificateExhibit>;
  tones: Map<string, number>;
}) {
  const rows = endpointRows(groups, rounds);
  if (rows.length === 0) return null;
  return (
    <div className="cause-inv-table-wrap">
      <div className="cause-inv-exhibit-head">
        <GitBranch size={14} />
        <span>已采样端点</span>
        <small>{rows.length} 地址</small>
      </div>
      <table className="cause-inv-data-table">
        <thead>
          <tr>
            <th>DNS</th>
            <th>IP</th>
            <th>网络</th>
            <th>证书</th>
            <th>结果</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.ip} className={leafClass(leafTone(row.fingerprint, tones))}>
              <td><span className={'anomaly-console-dns-state ' + (row.active ? 'active' : 'retired')}>{row.active ? '当前 DNS 地址' : "不在当前 DNS 中"}</span></td>
              <td><code>{row.ip}</code></td>
              <td>
                <code>{row.network}</code>
                {row.conflict && <small>内部不一致</small>}
              </td>
              <td><CertChip fingerprint={row.fingerprint} certificates={certificates} tones={tones} /></td>
              <td>{row.success ? (row.selection || "TLS 已响应") : row.error || '失败'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CertificateTable({ certificates, tones }: { certificates: CertificateExhibit[]; tones: Map<string, number> }) {
  const ordered = [...certificates].sort((left, right) => {
    const leftIssued = left.not_before ? Date.parse(left.not_before) : 0;
    const rightIssued = right.not_before ? Date.parse(right.not_before) : 0;
    return leftIssued - rightIssued;
  });
  return (
    <div className="cause-inv-table-wrap">
      <div className="cause-inv-exhibit-head">
        <span>序列中的证书</span>
        <small>{ordered.length} 张叶证书 · 按有效期起始时间升序 · 剩余有效期见上方序列</small>
      </div>
      <table className="cause-inv-data-table">
        <thead>
          <tr>
            <th>叶证书</th>
            <th>指纹</th>
            <th>序列号</th>
            <th>签发者</th>
            <th>SAN</th>
            <th>有效期起始</th>
            <th>到期时间</th>
            <th>有效期长度</th>
          </tr>
        </thead>
        <tbody>
          {ordered.map((certificate) => (
            <tr key={certificate.fingerprint} className={leafClass(leafTone(certificate.fingerprint, tones))}>
              <td><span className={'cause-inv-swatch ' + leafClass(leafTone(certificate.fingerprint, tones))} aria-hidden="true" /></td>
              <td><code title={certificate.fingerprint}>{shortFp(certificate.fingerprint, 20)}</code></td>
              <td><code title={certificate.serial_number}>{certificate.serial_number || '—'}</code></td>
              <td>{certificate.issuer_cn || '—'}</td>
              <td title={(certificate.sans ?? []).join(', ')}>{formatSANs(certificate.sans)}</td>
              <td>{certificate.not_before ? fmtDateTime(certificate.not_before) : '—'}</td>
              <td>{certificate.not_after ? fmtDateTime(certificate.not_after) : '—'}</td>
              <td>{certificate.validity_days ? `${certificate.validity_days} 天` : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function roundSignature(round: EvidenceRound): string {
  return [...round.endpoints]
    .map((endpoint) => [endpoint.ip_address, endpoint.fingerprint || '', endpoint.active_dns ? '1' : '0'].join(':'))
    .sort()
    .join('|');
}

function collapseIdenticalRounds(rounds: EvidenceRound[]): { round: EvidenceRound; count: number; firstAt: string; lastAt: string }[] {
  const groups: { round: EvidenceRound; count: number; firstAt: string; lastAt: string }[] = [];
  for (const round of rounds) {
    const previous = groups[groups.length - 1];
    if (previous && roundSignature(previous.round) === roundSignature(round)) {
      previous.count += 1;
      previous.lastAt = round.observed_at || previous.lastAt;
      continue;
    }
    groups.push({ round, count: 1, firstAt: round.observed_at, lastAt: round.observed_at });
  }
  return groups;
}

function MeasurementRounds({
  rounds,
  certificates,
  tones,
}: {
  rounds: EvidenceRound[];
  certificates: Map<string, CertificateExhibit>;
  tones: Map<string, number>;
}) {
  const collapsed = collapseIdenticalRounds(rounds);
  return (
    <div className="cause-inv-rounds">
      <div className="cause-inv-exhibit-head">
        <span>端点测量</span>
        <small>{rounds.length} 轮次 · {collapsed.length} 种不同分配</small>
      </div>
      {collapsed.map((item, index) => (
        <article key={(item.round.observed_at || '') + '-' + index} className="cause-inv-round">
          <header>
            <strong>{item.count === 1 ? "1 轮" : `${item.count} 轮相同观测`}</strong>
            <time>{item.count === 1 ? fmtDateTime(item.firstAt) : `${fmtDateTime(item.firstAt)} → ${fmtDateTime(item.lastAt)}`}</time>
          </header>
          {item.round.endpoints.length > 0 && (
            <table className="cause-inv-data-table">
              <thead>
                <tr>
                  <th>DNS</th>
                  <th>端点</th>
                  <th>网络</th>
                  <th>证书</th>
                  <th>结果</th>
                </tr>
              </thead>
              <tbody>
                {item.round.endpoints.map((endpoint) => (
                  <tr key={endpoint.ip_address} className={leafClass(leafTone(endpoint.fingerprint, tones))}>
                    <td><span className={'anomaly-console-dns-state ' + (endpoint.active_dns ? 'active' : 'retired')}>{endpoint.active_dns ? '当前 DNS 地址' : "不在当前 DNS 中"}</span></td>
                    <td><code>{endpoint.ip_address}</code></td>
                    <td><code>{endpoint.provider_group || '—'}</code></td>
                    <td><CertChip fingerprint={endpoint.fingerprint} certificates={certificates} tones={tones} /></td>
                    <td>{endpoint.success ? "TLS 已响应" : endpoint.error || '失败'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </article>
      ))}
    </div>
  );
}

function ChangeStrip({
  changes,
  certificates,
  tones,
}: {
  changes: ChangeExhibit[];
  certificates: Map<string, CertificateExhibit>;
  tones: Map<string, number>;
}) {
  return (
    <div className="cause-inv-changes">
      <div className="cause-inv-exhibit-head">
        <Repeat size={14} />
        <span>替换序列</span>
        <small>按时间升序 · 同地址表示时间上的替换 · 显示新叶证书的剩余有效期和有效期起始日期</small>
      </div>
      <ol>
        {changes.map((change, index) => (
          <li key={(change.observed_at || '') + '-' + index} className={change.coexisting ? 'coexist' : change.endpoint_relation}>
            <time>{fmtDateTime(change.observed_at)}</time>
            <div className="cause-inv-change-pair">
              <CertChip fingerprint={change.previous_fingerprint} certificates={certificates} tones={tones} />
              <span aria-hidden="true">→</span>
              <CertChip fingerprint={change.fingerprint} certificates={certificates} tones={tones} />
            </div>
            <p>
              <b>{relationLabel(change)}</b>
              {(change.previous_ip || change.ip_address) && (
                <span> {change.previous_ip || '未知'} → {change.ip_address || '未知'}</span>
              )}
              {(change.days_until_expiry ?? 0) > 0 && <span> · {change.days_until_expiry} 天（新叶证书剩余有效期）</span>}
              {certificates.get(change.fingerprint || '')?.not_before && (
                <span> · 有效期起始 {fmtDateTime(certificates.get(change.fingerprint || '')?.not_before)}</span>
              )}
            </p>
            {transitionDelta(change) && <small>{transitionDelta(change)}</small>}
          </li>
        ))}
      </ol>
    </div>
  );
}

function RelatedNameStrip({ probes }: { probes: RelatedNameProbe[] }) {
  return (
    <div className="cause-inv-related-names">
      <div className="cause-inv-exhibit-head">
        <GitBranch size={14} />
        <span>变更 SAN 名称的主动测量</span>
        <small>当前公开 DNS、SNI/TLS 与直接端点探测；证据范围限于公开测量</small>
      </div>
      <div className="cause-inv-related-grid">
        {probes.map((probe) => {
          const relationship = [
            probe.shares_root_ip ? "与主域名使用相同公网 IP" : '',
            probe.shares_root_cname ? "与主域名使用相同 CNAME 路径" : '',
            probe.shares_root_leaf ? "与主域名使用相同叶证书" : '',
          ].filter(Boolean);
          const history = `SAN +${probe.added_count} / −${probe.removed_count}`;
          return (
            <article key={probe.name} className={'cause-inv-related ' + probe.dns_status}>
              <header>
                <code>{probe.name}</code>
                <span>{statusLabel(probe.dns_status)}</span>
              </header>
              <p>{history}{probe.branch_like_label ? " · 临时名称模式" : ''}</p>
              {probe.resolver_quorum ? <p>解析器数量： {probe.resolver_quorum}</p> : null}
              {probe.resolved_ips?.length ? <p>IP: {probe.resolved_ips.join(', ')}</p> : null}
              {probe.cname_chain?.length ? <p>CNAME: {probe.cname_chain.join(' → ')}</p> : null}
              {probe.tls_answered && <p>TLS：已响应 · 覆盖自身域名： {probe.covers_own_name ? '是' : '否'}{probe.covers_root_name ? " · 同时覆盖主域名" : ''}</p>}
              {relationship.length > 0 && <p>与主域名的关系： {relationship.join(' · ')}</p>}
              {probe.http && <p>HTTP: {probe.http.status_code || '已响应'}{probe.http.redirect ? ` · 重定向至 ${probe.http.redirect}` : ''}</p>}
              {probe.error && <p className="cause-inv-related-error">{probe.error}</p>}
            </article>
          );
        })}
      </div>
    </div>
  );
}
