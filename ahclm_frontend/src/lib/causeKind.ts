import type { Anomaly, Investigation } from '@/types';

export type CauseKind = 'deterministic' | 'inferred';

function fieldsOf(source: Anomaly | Investigation | { cause_status?: string; proof_kind?: string }): {
  causeStatus: string;
  proofKind: string;
} {
  if ('type' in source && 'domain' in source) {
    const investigation = source.diagnosis?.investigation;
    return {
      causeStatus: investigation?.cause_status || source.diagnosis?.cause_status || '',
      proofKind: investigation?.proof_kind || '',
    };
  }
  return {
    causeStatus: source.cause_status || '',
    proofKind: 'proof_kind' in source ? (source.proof_kind || '') : '',
  };
}

export function causeKindOf(
  source: Anomaly | Investigation | { cause_status?: string; proof_kind?: string } | null | undefined,
): CauseKind {
  if (!source) return 'inferred';
  const { causeStatus, proofKind } = fieldsOf(source);
  // Operational cause is inferred unless the retained measurements already
  // establish it. Mixed proof with an established cause stays deterministic:
  // proven steps are the condition; any inference is a reading of that condition.
  if (
    causeStatus === 'inferred'
    || causeStatus === 'unestablished'
    || proofKind === 'inferred'
    || proofKind === 'unestablished'
    || (proofKind === 'mixed' && causeStatus !== 'established')
  ) {
    return 'inferred';
  }
  if (causeStatus === 'established' || proofKind === 'proven') {
    return 'deterministic';
  }
  return 'inferred';
}

export function causeKindLabel(kind: CauseKind): string {
  return kind === 'deterministic' ? "确定原因" : "推测原因";
}

export function causeKindBadge(kind: CauseKind): string {
  return kind === 'deterministic' ? "确定原因" : "推测原因";
}

export function causeKindNote(kind: CauseKind): string {
  return kind === 'deterministic'
    ? "原因已确定。下方逐项列出结论及证明该结论的测量证据。"
    : "原因仍属推测。已证实步骤引用测量证据，内部操作原因由这些证据推断。";
}
