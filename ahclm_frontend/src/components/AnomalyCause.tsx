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
  const reason = isInferred ? (inferredReason || anomaly.reason || '') : (confirmedReason || anomaly.reason || '');
  const evidence = isInferred
    ? (inferredEvidence.length ? inferredEvidence : values(anomaly.evidence))
    : (confirmedEvidence.length ? confirmedEvidence : values(anomaly.evidence));

  return (
    <div className={`cause-analysis ${compact ? 'compact' : ''}`}>
      <div className="cause-analysis-head">
        <span className="cause-analysis-label">Cause analysis</span>
        <span className={`certainty-pill ${classification}`}>{classification}</span>
        <span className={`evidence-state ${evidenceStatus}`}>{evidenceStatus.replace(/_/g, ' ')}</span>
      </div>
      {evidenceStatus === 'pending' && anomaly.evidence_pending_reason && (
        <p className="cause-pending">Evidence pending: {anomaly.evidence_pending_reason}</p>
      )}
      <div className={`cause-summary ${isInferred ? 'inferred' : classification === 'confirmed' ? 'confirmed' : 'unknown'}`}>
        <span className="cause-summary-label">{isInferred ? 'Inferred cause' : classification === 'confirmed' ? 'Confirmed cause' : 'Cause detail'}</span>
        <p>{anomaly.diagnosis?.summary || reason || 'No cause recorded.'}</p>
      </div>
      {anomaly.diagnosis && (
        <div className="cause-diagnosis-mini">
          <span>{anomaly.diagnosis.primary_label} · {anomaly.diagnosis.confidence}</span>
          <small>{anomaly.diagnosis.measured_rounds} rounds · {Math.round(anomaly.diagnosis.evidence_completeness * 100)}% evidence completeness</small>
        </div>
      )}
      <div className="cause-evidence">
        <span className="cause-summary-label">{isInferred ? 'Inferred evidence' : 'Confirmed evidence'}</span>
        {evidence.length > 0 ? (
          <ul>
            {evidence.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
          </ul>
        ) : (
          <p className="cause-no-evidence">No evidence recorded.</p>
        )}
      </div>
    </div>
  );
}
