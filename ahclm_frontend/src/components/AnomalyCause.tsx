import type { Anomaly } from '@/types';

interface AnomalyCauseProps {
  anomaly: Anomaly;
  compact?: boolean;
}

function values(value: string[] | undefined): string[] {
  return Array.isArray(value) ? value : [];
}

export default function AnomalyCause({ anomaly, compact = false }: AnomalyCauseProps) {
  const rawClassification = anomaly.cause_classification || 'unknown';
  const evidenceStatus = anomaly.evidence_status || 'unknown';
  const evidenceStatusLabel = evidenceStatus.replace(/_/g, ' ');
  const confirmedReason = anomaly.confirmed_reason || '';
  const inferredReason = anomaly.inferred_reason || '';
  const confirmedEvidence = values(anomaly.confirmed_evidence);
  const inferredEvidence = values(anomaly.inferred_evidence);
  const hasConfirmed = Boolean(confirmedReason || confirmedEvidence.length);
  const hasInferred = Boolean(inferredReason || inferredEvidence.length);
  const classification = hasConfirmed
    ? 'confirmed'
    : hasInferred
      ? 'inferred'
      : (rawClassification === 'confirmed' || rawClassification === 'inferred' ? rawClassification : 'unknown');
  const isInferred = classification === 'inferred';
  const displayConfirmedReason = classification === 'confirmed' ? (confirmedReason || anomaly.reason || '') : '';
  const displayInferredReason = classification === 'inferred' ? (inferredReason || anomaly.reason || '') : '';
  const displayConfirmedEvidence = classification === 'confirmed'
    ? (confirmedEvidence.length ? confirmedEvidence : values(anomaly.evidence))
    : [];
  const displayInferredEvidence = classification === 'inferred'
    ? (inferredEvidence.length ? inferredEvidence : values(anomaly.evidence))
    : [];

  const evidenceBlock = (label: string, reason: string, evidence: string[], tone: 'confirmed' | 'inferred') => (
    <section className={`cause-block cause-${tone}`}>
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-300">{label}</h4>
        <span className="text-[10px] uppercase tracking-wide text-slate-500">{tone}</span>
      </div>
      <p className="mt-1 text-xs leading-relaxed text-slate-300">{reason || 'No cause recorded.'}</p>
      <div className="mt-2">
        <p className="text-[10px] uppercase tracking-wide text-slate-500">{tone === 'confirmed' ? 'Confirmed evidence' : 'Inferred evidence'}</p>
        {evidence.length > 0 ? (
          <ul className="mt-1 space-y-1 text-[11px] text-slate-400">
            {evidence.map((item, index) => <li key={`${item}-${index}`} className="break-words font-mono">{item}</li>)}
          </ul>
        ) : (
          <p className="mt-1 text-[11px] italic text-slate-600">No {tone} evidence recorded.</p>
        )}
      </div>
    </section>
  );

  return (
    <div className={compact ? 'mt-2 space-y-2' : 'mt-3 space-y-2'}>
      <div className="flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-wide text-slate-500">
        <span>Cause certainty</span>
        <span className="rounded border border-slate-600 px-1.5 py-0.5 text-slate-300">{classification}</span>
        <span>Evidence status</span>
        <span className="rounded border border-slate-600 px-1.5 py-0.5 text-slate-300">{evidenceStatusLabel}</span>
      </div>
      {evidenceStatus === 'pending' && anomaly.evidence_pending_reason ? (
        <p className="text-[11px] italic text-amber-300">Evidence pending: {anomaly.evidence_pending_reason}</p>
      ) : null}
      {isInferred
        ? evidenceBlock('Inferred cause', displayInferredReason, displayInferredEvidence, 'inferred')
        : classification === 'confirmed'
          ? evidenceBlock('Confirmed cause', displayConfirmedReason, displayConfirmedEvidence, 'confirmed')
          : evidenceBlock('Cause detail', anomaly.reason || 'No cause recorded.', values(anomaly.evidence), 'confirmed')}
    </div>
  );
}
