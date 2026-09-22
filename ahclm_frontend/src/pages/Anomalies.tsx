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
import { getAnomalies, getAnomalyEvidence } from '@/api';
import type { Anomaly, CauseDiagnosis, EvidenceCase, Investigation, InvestigationProofStep } from '@/types';
import { causeKindBadge, causeKindLabel, causeKindNote, causeKindOf, type CauseKind } from '@/lib/causeKind';
import { fmtDateTime } from '@/lib/format';
import CauseInvestigation from '@/components/CauseInvestigation';

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
  deployment_failure: { icon: GitBranch, label: 'Certificate diversity across endpoints', short: 'Mixed certificates' },
  hostname_mismatch: { icon: ShieldOff, label: 'Certificate hostname mismatch', short: 'Name mismatch' },
  endpoint_probe_inconclusive: { icon: Network, label: 'Additional endpoint check incomplete', short: 'Incomplete probe' },
  not_yet_valid: { icon: CalendarClock, label: 'Certificate not yet valid', short: 'Not yet valid' },
  expired_endpoint: { icon: CalendarX, label: 'Expired certificate at sampled endpoint', short: 'Expired endpoint' },
  local_chain_validation_failed: { icon: ShieldOff, label: 'Local trust-chain validation failed', short: 'Chain validation' },
};

const severityRank: Record<string, number> = { critical: 0, warning: 1, info: 2 };
const INITIAL_VISIBLE_FINDINGS = 80;

type CauseFilter = 'all' | CauseKind;
const causeRank: Record<CauseKind, number> = { deterministic: 0, inferred: 1 };

interface IssueGroup {
  type: string;
  label: string;
  icon: typeof AlertTriangle;
  findings: Anomaly[];
  domains: number;
  severity: string;
  observations: number;
  lastObservedAt?: string;
  established: number;
  inferred: number;
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

function registerType(type: string): string {
  return type === 'residual' ? 'revoked' : type;
}

function preferRevokedFinding(current: Anomaly, incoming: Anomaly): Anomaly {
  if (current.type === 'revoked' && incoming.type === 'residual') return current;
  if (current.type === 'residual' && incoming.type === 'revoked') return { ...incoming, type: 'revoked' };
  return { ...incoming, type: registerType(incoming.type) };
}

function buildIssueGroups(items: Anomaly[]): IssueGroup[] {
  const byType = new Map<string, Anomaly[]>();
  for (const item of items) {
    const type = registerType(item.type);
    const current = byType.get(type) ?? [];
    if (type === 'revoked') {
      const idx = current.findIndex((existing) => existing.domain === item.domain);
      if (idx >= 0) {
        current[idx] = preferRevokedFinding(current[idx], item);
        byType.set(type, current);
        continue;
      }
    }
    current.push({ ...item, type });
    byType.set(type, current);
  }

  return Array.from(byType, ([type, findings]) => {
    const ordered = findings.sort((a, b) => (
      causeRank[causeKindOf(a)] - causeRank[causeKindOf(b)]
      || (severityRank[a.severity] ?? 3) - (severityRank[b.severity] ?? 3)
      || (b.occurrence_count ?? 0) - (a.occurrence_count ?? 0)
      || a.domain.localeCompare(b.domain)
    ));
    const dates = ordered
      .map((finding) => finding.last_observed_at || finding.detected_at)
      .filter((date): date is string => Boolean(date))
      .sort()
      .reverse();
    const established = ordered.filter((finding) => causeKindOf(finding) === 'deterministic').length;
    return {
      type,
      label: issueLabel(type),
      icon: typeMeta[type]?.icon ?? AlertTriangle,
      findings: ordered,
      domains: new Set(ordered.map((finding) => finding.domain)).size,
      severity: ordered[0]?.severity ?? 'info',
      observations: ordered.reduce((total, finding) => total + (finding.occurrence_count ?? 1), 0),
      lastObservedAt: dates[0],
      established,
      inferred: ordered.length - established,
    };
  }).sort((a, b) => (
    (severityRank[a.severity] ?? 3) - (severityRank[b.severity] ?? 3)
    || b.domains - a.domains
    || b.observations - a.observations
    || a.label.localeCompare(b.label)
  ));
}

function isIssueRegisterFinding(anomaly: Anomaly): boolean {
  if (anomaly.finding_class === 'expected'
    || Boolean(anomaly.diagnosis?.benign_explanation)
    || anomaly.diagnosis?.investigation?.finding_class === 'expected') {
    return false;
  }
  const code = anomaly.diagnosis?.primary_code ?? '';
  const divergence = anomaly.diagnosis?.endpoint_divergence;
  const sameEndpoint = anomaly.diagnosis?.churn_shape?.same_endpoint_changes ?? 0;
  switch (anomaly.type) {
    case 'deployment_failure':
      return (divergence?.distinct_leaves ?? 0) >= 2
        && !['intentional_multi_cdn', 'intentional_dual_certificate'].includes(code);
    case 'stale_after_change':
      if (['intentional_multi_cdn', 'intentional_dual_certificate'].includes(code)) {
        return false;
      }
      return Boolean(divergence?.active_predecessor_endpoints?.length);
    case 'frequent_change':
      if ([
        'concurrent_multi_certificate_pool',
        'short_lived_certificate_automation',
        'insufficient_longitudinal_evidence',
        'endpoint_attribution_unavailable',
      ].includes(code)) {
        return false;
      }
      return sameEndpoint > 0;
    case 'same_key':
      if (code === 'same_key_unestablished') {
        return false;
      }
      return (anomaly.diagnosis?.churn_shape?.change_events ?? anomaly.occurrence_count ?? 0) > 0;
    case 'early_renewal':
      if ([
        'concurrent_multi_certificate_pool',
        'short_lived_certificate_automation',
        'early_renewal_unestablished',
      ].includes(code)) {
        return false;
      }
      return code === 'early_renewal_replacement'
        && sameEndpoint > 0
        && (anomaly.diagnosis?.churn_shape?.median_remaining_days ?? 0) > 30;
    default:
      return true;
  }
}

const churnFindingTypes = new Set(['frequent_change', 'early_renewal', 'same_key']);
const diversityFindingTypes = new Set(['deployment_failure', 'stale_after_change']);
const tlsValidationFindingTypes = new Set([
  'expired_endpoint',
  'hostname_mismatch',
  'not_yet_valid',
  'local_chain_validation_failed',
  'endpoint_probe_inconclusive',
]);

function usesEndpointAssignment(type?: string): boolean {
  return Boolean(type && (diversityFindingTypes.has(type) || tlsValidationFindingTypes.has(type)));
}

function usesChangeSequence(type?: string): boolean {
  return Boolean(type && (churnFindingTypes.has(type) || type === 'stale_after_change'));
}

function investigationOf(anomaly: Anomaly, evidence?: { investigation?: Investigation | null; diagnosis?: CauseDiagnosis; evidence_case?: EvidenceCase } | null): Investigation | null {
  const diagnosis = evidence?.diagnosis || anomaly.diagnosis;
  const existing = evidence?.investigation
    || diagnosis?.investigation
    || null;
  if (existing?.problem) {
    if (!usesEndpointAssignment(anomaly.type)) {
      return {
        ...existing,
        provider_groups: existing.provider_groups ?? [],
        change_sequence: usesChangeSequence(anomaly.type) ? existing.change_sequence : [],
      };
    }
    if ((existing.provider_groups?.length || 0) > 0 || (existing.certificates?.length || 0) > 0) return existing;
    const fallback = investigationFromDiagnosis(anomaly, diagnosis, evidence?.evidence_case || diagnosis?.evidence_case);
    return {
      ...existing,
      provider_groups: existing.provider_groups?.length ? existing.provider_groups : fallback?.provider_groups,
      certificates: existing.certificates?.length ? existing.certificates : fallback?.certificates,
      change_sequence: existing.change_sequence?.length ? existing.change_sequence : fallback?.change_sequence,
      proof_kind: existing.proof_kind || fallback?.proof_kind,
      proof: existing.proof?.length ? existing.proof : fallback?.proof,
      inference: existing.inference?.length ? existing.inference : fallback?.inference,
    };
  }
  return investigationFromDiagnosis(anomaly, diagnosis, evidence?.evidence_case || diagnosis?.evidence_case);
}

function exhibitsFromEvidenceCase(evidenceCase?: EvidenceCase | null): Pick<Investigation, 'provider_groups' | 'certificates'> {
  const round = evidenceCase?.rounds?.find((item) => item.endpoints.length > 0);
  if (!round) return {};
  const groups = new Map<string, NonNullable<Investigation['provider_groups']>[number]>();
  for (const endpoint of round.endpoints) {
    const group = endpoint.provider_group || '—';
    const current = groups.get(group) ?? { group, conflict: false, leaf_count: 0, endpoints: [] };
    current.endpoints.push({
      ip_address: endpoint.ip_address,
      active_dns: endpoint.active_dns,
      success: endpoint.success,
      fingerprint: endpoint.fingerprint,
      spki_fingerprint: endpoint.spki_fingerprint,
      issuer_cn: endpoint.issuer_cn,
      key_algorithm: endpoint.key_algorithm,
      error: endpoint.error,
    });
    groups.set(group, current);
  }
  const providerGroups = [...groups.values()].map((group) => {
    const leaves = new Set(group.endpoints.map((endpoint) => endpoint.fingerprint).filter(Boolean));
    return { ...group, leaf_count: leaves.size, conflict: leaves.size > 1 };
  });
  const certificates = new Map<string, NonNullable<Investigation['certificates']>[number]>();
  for (const item of evidenceCase?.rounds ?? []) {
    for (const endpoint of item.endpoints) {
      if (!endpoint.fingerprint || certificates.has(endpoint.fingerprint)) continue;
      certificates.set(endpoint.fingerprint, {
        fingerprint: endpoint.fingerprint,
        spki_fingerprint: endpoint.spki_fingerprint,
        issuer_cn: endpoint.issuer_cn,
        key_algorithm: endpoint.key_algorithm,
      });
    }
  }
  return { provider_groups: providerGroups, certificates: [...certificates.values()] };
}

function investigationFromDiagnosis(anomaly: Anomaly, diagnosis?: CauseDiagnosis | null, evidenceCase?: EvidenceCase | null): Investigation | null {
  if (!diagnosis) return null;
  const divergence = diagnosis.endpoint_divergence;
  const facts: string[] = [];
  if (usesEndpointAssignment(anomaly.type) && divergence && divergence.endpoints_answered >= 2) {
    facts.push(`${divergence.endpoints_answered} sampled endpoint(s) served ${divergence.distinct_leaves} distinct certificate(s).`);
    facts.push(
      divergence.intra_group_conflicts > 0
        ? `Addresses fall into ${divergence.network_groups} provider network(s); ${divergence.intra_group_conflicts} of those networks served more than one certificate. This is not a multi-CDN split.`
        : `Addresses fall into ${divergence.network_groups} provider network(s); each network served one certificate.`,
    );
    if (divergence.stable_rounds > 0) {
      facts.push(`The same provider-to-certificate assignment held in ${divergence.stable_rounds} earlier round(s).`);
    }
    const cleanMultiProvider = (divergence.network_groups ?? 0) >= 2 && (divergence.intra_group_conflicts ?? 0) === 0;
    if (!cleanMultiProvider && (divergence.active_predecessor_endpoints?.length || 0) > 0) {
      facts.push(`Active DNS still serves the replaced certificate on ${divergence.active_predecessor_endpoints?.join(', ')} for ${divergence.consecutive_predecessor_rounds} consecutive round(s) spanning ${divergence.predecessor_span_hours.toFixed(1)} hours.`);
    }
    if (!cleanMultiProvider && divergence.residue_hours > 0 && (divergence.predecessor_endpoints?.length || 0) > 0) {
      facts.push(`The replaced certificate has remained reachable for ${divergence.residue_hours.toFixed(1)} hours (propagation is expected to finish within 24 hours).`);
    }
    if (!cleanMultiProvider && divergence.strong_evidence) {
      facts.push('The stuck-rollout gates all passed: the predecessor is still on an active DNS address across enough independent rounds.');
    }
  }
  const churn = diagnosis.churn_shape;
  if (churn && churnFindingTypes.has(anomaly.type)) {
    facts.push(`${churn.change_events} counted difference(s) across ${churn.distinct_leaves} distinct leaf certificate(s).`);
    facts.push(`Endpoint comparison: ${churn.same_endpoint_changes} same address, ${churn.cross_endpoint_changes} different address, ${churn.unknown_endpoint_changes} unrecorded.`);
    if ((churn.median_remaining_days ?? 0) > 0) {
      facts.push(`At replacement, the served certificate had ${churn.median_remaining_days} day(s) left (spread ${churn.remaining_spread_days ?? 0} day(s)).`);
    }
    if ((churn.median_issuance_age_days ?? 0) > 0) {
      facts.push(`Those certificates had already been issued for ${churn.median_issuance_age_days} day(s) when they were served.`);
    }
    if ((churn.distinct_issuance_days ?? 0) > 0) {
      facts.push(`Issuance dates cover ${churn.distinct_issuance_days} distinct day(s).`);
    }
  }
  const primary = diagnosis.hypotheses?.[0];
  const ruledOut = (diagnosis.hypotheses ?? [])
    .slice(1)
    .filter((item) => item.score >= 0.08 && item.code !== 'replacement_mechanism_unestablished' && item.code !== 'endpoint_attribution_unavailable')
    .slice(0, 3)
    .map((item) => ({
      label: item.label,
      reason: (item.contradictions ?? []).join(' ') || 'Lower support from the retained measurements than the primary reading.',
    }));
  const problem = diagnosis.investigation?.problem
    || (usesEndpointAssignment(anomaly.type) && divergence
      ? `${divergence.endpoints_answered} sampled endpoint(s) served ${divergence.distinct_leaves} distinct certificate(s) across ${divergence.network_groups} provider network(s).`
      : anomaly.description);
  const whyProblem = diagnosis.investigation?.why_this_is_a_problem
    || (usesEndpointAssignment(anomaly.type) ? whyDiversityIsAProblem(diagnosis.primary_code, divergence) : undefined);
  const exhibits = exhibitsFromEvidenceCase(evidenceCase || diagnosis.evidence_case);
  return {
    finding_class: anomaly.finding_class || (diagnosis.benign_explanation ? 'expected' : diagnosis.primary_code?.includes('undetermined') ? 'insufficient' : 'incident'),
    problem,
    why_this_is_a_problem: whyProblem,
    cause: diagnosis.benign_explanation || diagnosis.summary || anomaly.reason,
    cause_label: diagnosis.investigation?.cause_label || diagnosis.primary_label,
    cause_code: diagnosis.primary_code,
    cause_status: diagnosis.investigation?.cause_status || diagnosis.cause_status,
    confidence: diagnosis.confidence,
    why_this_cause: diagnosis.investigation?.why_this_cause?.length
      ? diagnosis.investigation.why_this_cause
      : (primary?.rationale ? [primary.rationale] : undefined),
    ruled_out: ruledOut,
    facts: facts.length ? facts : (diagnosis.investigation?.facts ?? diagnosis.evidence_case?.supporting_evidence ?? []),
    missing_evidence: diagnosis.measurement_plan || (usesEndpointAssignment(anomaly.type) ? diagnosis.endpoint_divergence?.missing_evidence : undefined),
    reversal_conditions: usesEndpointAssignment(anomaly.type) ? diagnosis.endpoint_divergence?.reversal_conditions : undefined,
    provider_groups: usesEndpointAssignment(anomaly.type)
      ? (diagnosis.investigation?.provider_groups?.length ? diagnosis.investigation.provider_groups : exhibits.provider_groups)
      : (diagnosis.investigation?.provider_groups ?? []),
    certificates: diagnosis.investigation?.certificates?.length ? diagnosis.investigation.certificates : (usesEndpointAssignment(anomaly.type) ? exhibits.certificates : []),
    change_sequence: usesChangeSequence(anomaly.type) ? diagnosis.investigation?.change_sequence : [],
    cdn: usesEndpointAssignment(anomaly.type) ? (diagnosis.investigation?.cdn || diagnosis.endpoint_divergence?.cdn) : undefined,
    ...proofFromDiagnosis(anomaly, diagnosis),
  };
}

function proofStep(kind: 'proven' | 'inferred', label: string, claim: string, evidence: string[], basis?: string): InvestigationProofStep {
  const narrative = [
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
  ];
  return {
    kind,
    label,
    claim,
    evidence: evidence.filter((item) => {
      const text = item.trim();
      if (!text) return false;
      const lower = text.toLowerCase();
      return !narrative.some((marker) => lower.includes(marker));
    }),
    basis,
  };
}

function proofFromDiagnosis(anomaly: Anomaly, diagnosis: CauseDiagnosis): Pick<Investigation, 'proof_kind' | 'proof' | 'inference'> {
  const existing = diagnosis.investigation;
  if ((existing?.proof?.length || 0) > 0 || (existing?.inference?.length || 0) > 0) {
    return {
      proof_kind: existing?.proof_kind,
      proof: existing?.proof,
      inference: existing?.inference,
    };
  }
  const proven: InvestigationProofStep[] = [];
  const inferred: InvestigationProofStep[] = [];
  const divergence = diagnosis.endpoint_divergence;
  const churn = diagnosis.churn_shape;
  if (anomaly.type === 'deployment_failure' || anomaly.type === 'stale_after_change') {
    if (!divergence) {
      inferred.push(proofStep('inferred', 'Coverage', 'Live certificate diversity cannot be read from this sample.', ['Answering endpoints retained: 0. Distinct leaves retained: 0.']));
    } else {
      proven.push(proofStep(
        'proven',
        anomaly.type === 'stale_after_change' && divergence.distinct_leaves >= 2 ? 'Post-change mix' : 'Observed mix',
        'The current measurement round served more than one leaf certificate.',
        [`${divergence.endpoints_answered} answering endpoint(s) produced ${divergence.distinct_leaves} distinct leaf fingerprint(s).`],
        'Direct TLS probes in one measurement round, keyed by endpoint address and leaf fingerprint.',
      ));
      if (divergence.intra_group_conflicts > 0) {
        proven.push(proofStep('proven', 'Same-network disagreement', 'The mix is inside one provider network, so a between-provider split cannot explain it.', [`${divergence.intra_group_conflicts} of ${divergence.network_groups} provider network(s) served more than one leaf.`], 'IPv4 /16 and IPv6 /32 partition of the answering addresses.'));
      } else if (divergence.network_groups >= 2) {
        proven.push(proofStep('proven', 'Between-provider split', 'Each provider network served one certificate consistently.', [`${divergence.network_groups} provider network(s); 0 intra-network conflicts.`], 'The same partition used for multi-CDN.'));
      }
      if ((divergence.active_predecessor_endpoints?.length || 0) > 0) {
        proven.push(proofStep('proven', 'Active predecessor', 'Active DNS still serves the predecessor certificate.', [`Predecessor still on ${divergence.active_predecessor_endpoints?.join(', ')}.`, `${divergence.consecutive_predecessor_rounds} consecutive DNS-active round(s) spanning ${divergence.predecessor_span_hours.toFixed(1)} hours.`], 'The predecessor fingerprint is still on an address in the current resolver consensus.'));
      }
      if (diagnosis.primary_code === 'stuck_partial_rollout' && divergence.strong_evidence) {
        proven.push(proofStep('proven', 'Conclusion', 'The replacement did not reach every active endpoint.', [
          ...(divergence.active_predecessor_endpoints ?? []).map((ip) => `Active-DNS predecessor address: ${ip}.`),
          `Consecutive DNS-active predecessor rounds: ${divergence.consecutive_predecessor_rounds}.`,
          `Predecessor span: ${divergence.predecessor_span_hours.toFixed(1)} hours.`,
          `Residue since replacement first observed: ${divergence.residue_hours.toFixed(1)} hours.`,
        ]));
      } else if (diagnosis.primary_code === 'intra_fleet_inconsistency' || diagnosis.primary_code === 'defective_endpoint_certificate') {
        proven.push(proofStep('proven', 'Conclusion', diagnosis.investigation?.cause || diagnosis.summary, [
          `Intra-network conflicts: ${divergence.intra_group_conflicts}.`,
          `Defective endpoints: ${(divergence.defective_endpoints ?? []).join(', ') || 0}.`,
        ], 'Direct assignment measurements.'));
      } else if (diagnosis.primary_code === 'rollout_in_progress' || diagnosis.primary_code === 'insufficient_endpoint_coverage' || (diagnosis.primary_code === 'stuck_partial_rollout' && !divergence.strong_evidence)) {
        inferred.push(proofStep('inferred', 'Not yet settled', `Predecessor and successor are both still reachable after ${divergence.residue_hours.toFixed(1)} hours.`, [
          `Answering endpoints: ${divergence.endpoints_answered}. Distinct leaves: ${divergence.distinct_leaves}.`,
          `Consecutive DNS-active predecessor rounds: ${divergence.consecutive_predecessor_rounds}.`,
          `Residue since replacement first observed: ${divergence.residue_hours.toFixed(1)} hours.`,
        ]));
      }
    }
  } else if (anomaly.type === 'same_key') {
    const changes = diagnosis.investigation?.change_sequence ?? [];
    const certs = new Map((diagnosis.investigation?.certificates ?? []).map((item) => [item.fingerprint, item]));
    const pairLines = changes.flatMap((change) => {
      const previousSPKI = change.previous_spki_fingerprint || certs.get(change.previous_fingerprint ?? '')?.spki_fingerprint;
      const currentSPKI = change.spki_fingerprint || certs.get(change.fingerprint ?? '')?.spki_fingerprint;
      if (!previousSPKI || !currentSPKI || previousSPKI !== currentSPKI) return [];
      const address = change.endpoint_relation === 'same_endpoint' && change.ip_address
        ? `same address ${change.ip_address}`
        : change.ip_address
          ? `serving address ${change.ip_address}`
          : 'serving address not retained';
      const remaining = change.days_until_expiry ? `; successor remaining life ${change.days_until_expiry} day(s)` : '';
      return [`${change.observed_at} leaf ${(change.previous_fingerprint ?? '').slice(0, 12)} → ${(change.fingerprint ?? '').slice(0, 12)}; SPKI ${currentSPKI.slice(0, 12)}; ${address}${remaining}.`];
    });
    const pairCount = churn?.change_events ?? pairLines.length;
    const evidence = pairLines.length ? pairLines : [
      `Same-key pairs: ${pairCount}.`,
      `Distinct leaves: ${churn?.distinct_leaves ?? 0}.`,
      `Distinct SPKI(s): ${churn?.distinct_spkis ?? 0}.`,
    ];
    if (pairCount > 0) {
      proven.push(proofStep('proven', 'Leaf changed', 'A later scan served a different leaf certificate than the previous scan.', evidence, 'Leaf fingerprints compared between consecutive successful scans.'));
      proven.push(proofStep('proven', 'SPKI unchanged', 'Those two leaves share one SPKI fingerprint, so the public key did not rotate.', evidence, 'SPKI fingerprints taken from the retained certificates or the replacement row.'));
      if ((churn?.same_endpoint_changes ?? 0) > 0) {
        proven.push(proofStep('proven', 'Same address', 'The new leaf was served from the same address as the previous leaf.', [
          ...evidence,
          `Same-address comparisons: ${churn?.same_endpoint_changes}.`,
        ], 'Replacement in time is only proven when consecutive scans share the serving address.'));
      } else if ((churn?.cross_endpoint_changes ?? 0) > 0) {
        proven.push(proofStep('proven', 'Different addresses', 'The new leaf was served from a different address than the previous leaf.', [
          ...evidence,
          `Different-address comparisons: ${churn?.cross_endpoint_changes}.`,
        ], 'Consecutive scans recorded both serving addresses, and they differ.'));
      } else {
        proven.push(proofStep('proven', 'Serving address', 'The serving address was not retained on those pairs, so replacement in time is not proven.', [
          ...evidence,
          `Pairs with no serving address: ${churn?.unknown_endpoint_changes ?? pairCount}.`,
        ]));
      }
      if (diagnosis.cause_status === 'established') {
        proven.push(proofStep('proven', 'Conclusion', 'The successor leaf was served with the predecessor public key.', evidence));
        if ((churn?.median_remaining_days ?? 0) > 0 || (churn?.median_issuance_age_days ?? 0) >= 0) {
          inferred.push(proofStep('inferred', 'Key reused on a new leaf', `The successor still had ${churn?.median_remaining_days ?? 0} day(s) remaining and issuance age ${churn?.median_issuance_age_days ?? 0} day(s) when it was served, so a new leaf was issued or deployed without rotating the public key.`, [
            ...evidence,
            `Median successor remaining life: ${churn?.median_remaining_days ?? 0} day(s).`,
            `Median successor issuance age: ${churn?.median_issuance_age_days ?? 0} day(s).`,
          ], 'Remaining life is NotAfter minus observation time; issuance age is observation time minus NotBefore.'));
        }
      } else {
        inferred.push(proofStep('inferred', 'Shared SPKI without a serving address', `Leaf fingerprints differ while SPKI fingerprints match on ${pairCount} pair(s).`, evidence));
      }
    }
  } else if (anomaly.type === 'early_renewal') {
    const remaining = churn?.median_remaining_days ?? 0;
    const validity = churn?.median_validity_days ?? 0;
    const evidence = [
      `Predecessor remaining life at replacement: ${remaining} day(s).`,
      `Predecessor lifetime: ${validity} day(s).`,
      `Same-address comparisons: ${churn?.same_endpoint_changes ?? 0}.`,
      `Different-address comparisons: ${churn?.cross_endpoint_changes ?? 0}.`,
      `Pairs with no serving address: ${churn?.unknown_endpoint_changes ?? 0}.`,
    ];
    if (diagnosis.primary_code === 'early_renewal_replacement' && (churn?.same_endpoint_changes ?? 0) > 0 && remaining > 30) {
      proven.push(proofStep('proven', 'Predecessor remaining life', `The predecessor still had more than 30 days remaining when it was replaced (${remaining} day(s)).`, evidence, 'Predecessor remaining life is predecessor NotAfter minus the observation time of the replacement.'));
      proven.push(proofStep('proven', 'Same address', 'The new leaf was served from the same address as the previous leaf.', evidence, 'Replacement in time is only proven when consecutive scans share the serving address.'));
      proven.push(proofStep('proven', 'Conclusion', 'This is an early replacement: a still-valid predecessor was retired more than 30 days before its NotAfter on the same address.', evidence));
      inferred.push(proofStep('inferred', 'New leaf at replacement time', `The successor's issuance age at observation was ${churn?.median_issuance_age_days ?? 0} day(s), so a new leaf was served while the predecessor still had ${remaining} day(s) remaining.`, [
        ...evidence,
        `Successor issuance age: ${churn?.median_issuance_age_days ?? 0} day(s).`,
      ], 'Issuance age is observation time minus successor NotBefore.'));
    } else if (diagnosis.primary_code === 'concurrent_multi_certificate_pool') {
      proven.push(proofStep('proven', 'Different addresses', 'The two leaves were observed on different addresses or in the same round.', evidence));
    } else if (diagnosis.primary_code === 'short_lived_certificate_automation') {
      proven.push(proofStep('proven', 'Short predecessor lifetime', `The predecessor lifetime is ${validity} day(s), which is not a long-lived certificate being retired early.`, evidence));
    } else {
      inferred.push(proofStep('inferred', 'Not established', 'No retained same-address replacement has a predecessor remaining life greater than 30 days.', evidence));
    }
  } else if (anomaly.type === 'frequent_change' && churn) {
    proven.push(proofStep('proven', 'Counted differences', 'Monitoring recorded repeated leaf-fingerprint differences.', [`${churn.change_events} counted difference(s) across ${churn.distinct_leaves} distinct leaf certificate(s).`], 'Each change row is a fingerprint difference between consecutive successful scans.'));
    proven.push(proofStep('proven', 'Endpoint comparison', churn.same_endpoint_changes > 0 ? 'Replacement in time is proven on the same address.' : 'The counted differences were not shown to be replacements on the same address.', [`${churn.same_endpoint_changes} same-address comparison(s).`, `${churn.cross_endpoint_changes} different-address.`, `${churn.unknown_endpoint_changes} unrecorded.`], 'Replacement in time is only proven when the address that served the new leaf is the address that served the previous one.'));
    if (churn.same_endpoint_changes > 0 && diagnosis.cause_status === 'established') {
      proven.push(proofStep('proven', 'Conclusion', diagnosis.summary, [`${churn.same_endpoint_changes} same-endpoint comparison(s).`, `Remaining life ${churn.median_remaining_days ?? 0} day(s); issuance age ${churn.median_issuance_age_days ?? 0} day(s).`]));
    } else {
      inferred.push(proofStep('inferred', diagnosis.primary_label || 'Process unnamed', `Replacement-time leaves still have ${churn.median_remaining_days ?? 0} of ${churn.median_validity_days} day(s) left and issuance age ${churn.median_issuance_age_days ?? 0}.`, [
        `Counted fingerprint differences: ${churn.change_events}.`,
        `Same-address comparisons: ${churn.same_endpoint_changes}.`,
        `Change rows with no serving address: ${churn.unknown_endpoint_changes}.`,
        `Median remaining life: ${churn.median_remaining_days ?? 0} day(s).`,
        `Median issuance age: ${churn.median_issuance_age_days ?? 0} day(s).`,
      ], 'Cause status is inferred until same-endpoint replacement is retained.'));
    }
  }
  const proofKind = proven.length && !inferred.length ? 'proven' : proven.length && inferred.length ? 'mixed' : inferred.length ? 'inferred' : undefined;
  return { proof_kind: proofKind, proof: proven.length ? proven : undefined, inference: inferred.length ? inferred : undefined };
}

function whyDiversityIsAProblem(code?: string, divergence?: CauseDiagnosis['endpoint_divergence'] | null): string {
  switch (code) {
    case 'stuck_partial_rollout':
      return 'This is a problem because an active DNS endpoint is still serving the replaced certificate after the 24-hour propagation window.';
    case 'intra_fleet_inconsistency':
      if (divergence?.cdn?.method === 'vendor' && (divergence.cdn.distinct_vendors ?? 1) <= 1) {
        return 'This is a problem because addresses attributed to the same named CDN served more than one certificate. Multi-CDN does not explain disagreement inside one operator.';
      }
      return `This is a problem because ${divergence?.intra_group_conflicts ?? 1} provider network(s) served more than one certificate. Multi-CDN does not explain disagreement inside one operator's own address space.`;
    case 'rollout_in_progress':
      return 'This is a problem only if the mixed assignment persists. The current evidence shows a replacement that has not yet settled.';
    case 'intentional_multi_cdn':
      if (divergence?.cdn?.method === 'vendor' && (divergence.cdn.distinct_vendors ?? 0) >= 2) {
        return 'This is not counted as a problem: each named CDN served one certificate consistently.';
      }
      return 'This is not counted as a problem: each provider network served one certificate consistently. Endpoint vendors were not complete, so the reading uses the IPv4 /16 and IPv6 /32 partition.';
    case 'intentional_dual_certificate':
      return 'This is not counted as a problem: the leaves differ only by public-key algorithm.';
    case 'defective_endpoint_certificate':
      if ((divergence?.network_groups ?? 0) >= 2 && (divergence?.intra_group_conflicts ?? 0) === 0) {
        return 'This is not counted as a mixed-certificate deployment problem: each provider network served one certificate. A certificate that is not valid for the name is a separate TLS finding.';
      }
      return 'This is a problem because at least one endpoint served a certificate that is not currently valid for the queried name.';
    default:
      if ((divergence?.network_groups ?? 0) >= 2 && (divergence?.intra_group_conflicts ?? 0) === 0) {
        return 'This is not counted as a problem: each provider network served one certificate consistently.';
      }
      return 'Mixed certificates were measured; the retained sample is used to tell a deliberate split from an inconsistent deployment.';
  }
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
  const [causeFilter, setCauseFilter] = useState<CauseFilter>('all');
  const [search, setSearch] = useState('');
  const [visibleLimit, setVisibleLimit] = useState(INITIAL_VISIBLE_FINDINGS);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['anomalies'],
    queryFn: async () => {
      const pageSize = 500;
      const firstResponse = await getAnomalies(pageSize);
      const first = firstResponse.data ?? { count: 0, anomalies: [], total_pages: 1 };
      const totalPages = first.total_pages ?? 1;
      if (totalPages <= 1) return first;
      const rest = await Promise.all(Array.from({ length: totalPages - 1 }, (_, offset) => getAnomalies(pageSize, offset + 2)));
      return { ...first, anomalies: [first.anomalies, ...rest.map((response) => response.data?.anomalies ?? [])].flat() };
    },
    refetchInterval: 60000,
  });

  const anomalies: Anomaly[] = useMemo(
    () => (data?.anomalies ?? []).filter(isIssueRegisterFinding),
    [data?.anomalies],
  );
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
        const established = findings.filter((finding) => causeKindOf(finding) === 'deterministic').length;
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
          established,
          inferred: findings.length - established,
        };
      })
      .filter((issue): issue is NonNullable<typeof issue> => Boolean(issue));
  }, [issueGroups, search, severityFilter]);

  const selectedIssue = filteredIssues.find((issue) => issue.type === selectedIssueType) ?? filteredIssues[0];
  const affectedFindings = selectedIssue?.findings ?? [];
  const findingsByCause = useMemo(() => ({
    deterministic: affectedFindings.filter((finding) => causeKindOf(finding) === 'deterministic'),
    inferred: affectedFindings.filter((finding) => causeKindOf(finding) === 'inferred'),
  }), [affectedFindings]);
  const causeCounts = {
    deterministic: findingsByCause.deterministic.length,
    inferred: findingsByCause.inferred.length,
  };
  const causeFilteredFindings = causeFilter === 'all'
    ? affectedFindings
    : findingsByCause[causeFilter];
  const visibleCauseGroups = useMemo(() => {
    const kinds: CauseKind[] = causeFilter === 'all' ? ['deterministic', 'inferred'] : [causeFilter];
    return kinds.map((kind) => ({
      kind,
      findings: findingsByCause[kind].slice(0, visibleLimit),
      total: findingsByCause[kind].length,
    }));
  }, [causeFilter, findingsByCause, visibleLimit]);
  const visibleCauseCount = visibleCauseGroups.reduce((total, group) => total + group.findings.length, 0);
  const remainingCauseCount = visibleCauseGroups.reduce((total, group) => total + Math.max(0, group.total - visibleLimit), 0);
  const selected = causeFilteredFindings.find((finding) => finding.domain === selectedDomain && finding.type === selectedFindingType)
    ?? causeFilteredFindings.find((finding) => finding.domain === selectedDomain)
    ?? causeFilteredFindings[0]
    ?? affectedFindings[0];
  const selectedDomainFindings = selected
    ? (domainFindings.get(selected.domain) ?? [])
    : [];
  const cause = selected ? causeDetails(selected) : null;

  const { data: evidenceData, isLoading: evidenceLoading, isError: evidenceError } = useQuery({
    queryKey: ['anomaly-evidence', selected?.domain, selected?.type],
    queryFn: async () => (await getAnomalyEvidence(selected!.domain, selected!.type)).data,
    enabled: Boolean(selected),
    staleTime: 60000,
  });

  const evidenceCase: EvidenceCase | null = evidenceData?.evidence_case ?? cause?.diagnosis?.evidence_case ?? null;
  const investigation = selected ? investigationOf(selected, evidenceData) : null;

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

  const updateCauseFilter = (value: CauseFilter) => {
    setCauseFilter(value);
    setVisibleLimit(INITIAL_VISIBLE_FINDINGS);
  };

  const selectIssue = (issue: IssueGroup) => {
    const first = issue.findings[0];
    setSelectedIssueType(issue.type);
    setSelectedDomain(first?.domain ?? null);
    setSelectedFindingType(first?.type ?? null);
    setCauseFilter('all');
    setVisibleLimit(INITIAL_VISIBLE_FINDINGS);
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
          <p>Problems and suspected problems only.</p>
        </div>
        <div className="anomaly-console-status">
          <span className="anomaly-console-live" />
          <span>Live</span>
          <button type="button" className="anomaly-console-refresh" onClick={() => refetch()} disabled={isLoading} aria-label="Refresh findings" title="Refresh findings">
            <RefreshCw size={15} className={isLoading ? 'spin' : ''} />
          </button>
        </div>
      </header>

      <section className="anomaly-console-metrics" aria-label="Problem summary">
        <Metric label="Problem types" value={issueGroups.length} detail="open incidents and suspected cases" tone="primary" />
        <Metric label="Affected domains" value={affectedDomainCount} detail="certificates needing review" tone="slate" />
        <Metric label="Suspected findings" value={anomalies.filter((item) => item.finding_class === 'insufficient').length} detail="not enough evidence to close" tone="slate" />
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
        <div className="anomaly-console-state">
          <ScanLine size={20} />
          <span>No problems match this search or severity filter.</span>
          <button type="button" onClick={() => { updateSearch(''); updateSeverity('all'); updateCauseFilter('all'); }}>Clear filters</button>
        </div>
      )}

      {!isLoading && !isError && filteredIssues.length > 0 && selectedIssue && selected && cause && (
        <div className="anomaly-issue-workspace">
          {/* Full-width problem strip keeps every issue label readable. Domains stay
              in a compact rail; evidence/cause still owns the main viewport. */}
          <nav className="anomaly-problem-strip" aria-label="Measured problem types">
            <div className="anomaly-problem-strip-head">
              <div>
                <span className="anomaly-console-kicker">PROBLEM INDEX</span>
                <h2>Measured problems</h2>
              </div>
              <span>{filteredIssues.length} type{filteredIssues.length === 1 ? '' : 's'}</span>
            </div>
            <div className="anomaly-problem-strip-list" role="tablist" aria-label="Select a measured problem">
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
                    title={`${issue.label} · ${issue.domains} domains · ${issue.established} established · ${issue.inferred} inferred`}
                  >
                    <span className={'anomaly-problem-chip-icon ' + severityTone(issue.severity)}><IssueIcon size={15} /></span>
                    <span className="anomaly-problem-chip-copy">
                      <span className="anomaly-problem-chip-name">{issue.label}</span>
                      <span className="anomaly-problem-chip-meta">{issue.domains} domain{issue.domains === 1 ? '' : 's'} · {issue.observations} obs.</span>
                      <span className="anomaly-problem-chip-causes">
                        <span className="deterministic">{issue.established} established</span>
                        <span className="inferred">{issue.inferred} inferred</span>
                      </span>
                    </span>
                  </button>
                );
              })}
            </div>
          </nav>

          <div className="anomaly-issue-body">
            <aside className="anomaly-issue-affected" aria-label="Affected domains for selected problem">
              <div className="anomaly-issue-index-head">
                <div>
                  <span className="anomaly-console-kicker">AFFECTED DOMAINS</span>
                  <h2>Hosts with this problem</h2>
                </div>
                <span>{visibleCauseCount} / {causeFilteredFindings.length}</span>
              </div>
              <p className="anomaly-issue-affected-focus" title={selectedIssue.label}>{selectedIssue.label}</p>
              <div className="anomaly-issue-cause-filters" role="group" aria-label="Cause kind filter">
                {([
                  ['all', `All ${affectedFindings.length}`],
                  ['deterministic', `Established ${causeCounts.deterministic}`],
                  ['inferred', `Inferred ${causeCounts.inferred}`],
                ] as Array<[CauseFilter, string]>).map(([value, label]) => (
                  <button
                    key={value}
                    type="button"
                    className={causeFilter === value ? 'active ' + value : value}
                    onClick={() => updateCauseFilter(value)}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <div className="anomaly-issue-affected-list">
                {visibleCauseGroups.map((group) => (
                  <section key={group.kind} className={'anomaly-affected-group ' + group.kind} aria-label={causeKindLabel(group.kind)}>
                    <header className="anomaly-affected-group-head">
                      <span>{causeKindLabel(group.kind)}</span>
                      <span>{group.total}</span>
                    </header>
                    {group.findings.length === 0 ? (
                      <p className="anomaly-affected-empty">
                        {group.kind === 'deterministic'
                          ? 'No host in this problem has an established cause.'
                          : 'No host in this problem has an inferred cause.'}
                      </p>
                    ) : group.findings.map((finding) => (
                      <button
                        type="button"
                        key={finding.domain + '-' + finding.type + '-' + (finding.fingerprint ?? '')}
                        className={'anomaly-affected-item ' + group.kind + (selected.domain === finding.domain ? ' selected' : '')}
                        onClick={() => selectFinding(finding)}
                        title={finding.description || finding.domain}
                      >
                        <span className={'anomaly-console-domain-marker ' + severityTone(finding.severity)} />
                        <span className="anomaly-affected-main">
                          <span className="anomaly-affected-domain">{finding.domain}</span>
                          <span className="anomaly-affected-meta">
                            {finding.occurrence_count ?? 1} obs. · {fmtDateTime(finding.last_observed_at || finding.detected_at)}
                          </span>
                        </span>
                        <span className={'anomaly-affected-cause ' + group.kind}>
                          {group.kind === 'deterministic' ? 'established' : 'inferred'}
                        </span>
                      </button>
                    ))}
                  </section>
                ))}
              </div>
              {remainingCauseCount > 0 && (
                <button type="button" className="anomaly-console-load-more" onClick={() => setVisibleLimit((limit) => limit + INITIAL_VISIBLE_FINDINGS)}>
                  Show {Math.min(INITIAL_VISIBLE_FINDINGS * (causeFilter === 'all' ? 2 : 1), remainingCauseCount)} more <ChevronRight size={14} />
                </button>
              )}
            </aside>

            <section className="anomaly-console-inspector" aria-label="Selected measured finding">
              <div className="anomaly-console-inspector-head">
                <div>
                  <p className="anomaly-console-kicker">SELECTED FINDING</p>
                  <h2>{selectedIssue.label}</h2>
                  <p className="anomaly-selected-domain">{selected.domain}</p>
                  {investigation && (
                    <p className="anomaly-console-proof-kind">
                      {causeKindNote(causeKindOf(investigation))}
                    </p>
                  )}
                </div>
                <div className="anomaly-console-inspector-actions">
                  {investigation && (
                    <span className={'cause-inv-class ' + (causeKindOf(investigation) === 'deterministic' ? 'proven' : 'insufficient')}>
                      {causeKindBadge(causeKindOf(investigation))}
                    </span>
                  )}
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

            <div className={'anomaly-console-observation compact ' + severityTone(selected.severity)}>
              <div className="anomaly-console-observation-facts">
                <Fact label="First recorded" value={fmtDateTime(selected.detected_at)} />
                <Fact label="Last recorded" value={fmtDateTime(selected.last_observed_at || selected.detected_at)} />
                <Fact label="Recurrences" value={String(selected.occurrence_count ?? 1)} />
              </div>
            </div>

            {investigation ? (
              <>
                <CauseInvestigation
                  anomaly={selected}
                  investigation={investigation}
                  rounds={usesEndpointAssignment(selected.type) ? (evidenceCase?.rounds ?? []) : []}
                  roundsLoading={usesEndpointAssignment(selected.type) && evidenceLoading}
                />
                {evidenceError && !evidenceCase?.rounds?.length && (
                  <p className="anomaly-console-pending">Collected round data could not be loaded for this finding.</p>
                )}
              </>
            ) : evidenceLoading ? (
              <div className="anomaly-console-evidence-loading"><span className="spinner" /> Reconstructing problem, evidence and cause...</div>
            ) : (
              <div className="anomaly-console-ledger">
                <section className="anomaly-console-ledger-panel measured">
                  <div className="anomaly-console-section-head"><div><span className="anomaly-console-step">01</span><h3>Problem</h3></div></div>
                  <p className="anomaly-console-cause-text">{selected.description}</p>
                  {cause.pendingReason && <p className="anomaly-console-pending">Pending: {cause.pendingReason}</p>}
                </section>
                <section className="anomaly-console-ledger-panel interpretation">
                  <div className="anomaly-console-section-head"><div><span className="anomaly-console-step">02</span><h3>Cause</h3></div><span className={'anomaly-console-certainty ' + cause.classification}>{cause.classification}</span></div>
                  <p className="anomaly-console-cause-text">{cause.diagnosis?.summary || cause.reason || 'No cause recorded.'}</p>
                </section>
              </div>
            )}
            </section>
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


