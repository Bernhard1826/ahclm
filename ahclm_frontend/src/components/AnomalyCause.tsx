import type { Anomaly } from '@/types';

interface AnomalyCauseProps {
  anomaly: Anomaly;
  compact?: boolean;
}

function values(value: string[] | undefined): string[] {
  return Array.isArray(value) ? value : [];
}

function churnCauseFacts(anomaly: Anomaly): string[] {
  const churn = anomaly.diagnosis?.churn_shape;
  if (!churn) return [];
  const facts: string[] = [];
  if ((churn.median_remaining_days ?? 0) > 0) {
    facts.push(`at replacement, ${churn.median_remaining_days} day(s) remained (spread ${churn.remaining_spread_days ?? 0})`);
  }
  if ((churn.median_issuance_age_days ?? 0) > 0) {
    facts.push(`served certificates were already ${churn.median_issuance_age_days} day(s) old, across ${churn.distinct_issuance_days ?? 0} issuance day(s)`);
  } else if ((churn.distinct_issuance_days ?? 0) > 0) {
    facts.push(`issuance dates cover ${churn.distinct_issuance_days} distinct day(s)`);
  }
  if (churn.same_endpoint_changes > 0 || churn.cross_endpoint_changes > 0 || churn.unknown_endpoint_changes > 0) {
    facts.push(`endpoint comparison: ${churn.same_endpoint_changes} same · ${churn.cross_endpoint_changes} different · ${churn.unknown_endpoint_changes} unrecorded`);
  }
  return facts;
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
  const investigation = anomaly.diagnosis?.investigation;
  const benignExplanation = anomaly.diagnosis?.benign_explanation;
  const measuredFacts = churnCauseFacts(anomaly);
  const causeBody = investigation
    ? (investigation.why_this_cause?.find((line) => line && !line.startsWith('This is an inference')) || investigation.why_this_cause?.[0] || investigation.cause || benignExplanation || '')
    : '';
  if (investigation) {
    return (
      <div className={`cause-analysis ${compact ? 'compact' : ''}`}>
        <div className="cause-analysis-head">
          <span className="cause-analysis-label">{investigation.finding_class === 'expected' ? 'Expected property' : 'Cause'}</span>
          <span className={`certainty-pill ${investigation.finding_class === 'expected' ? 'info' : classification}`}>{investigation.finding_class || classification}</span>
        </div>
        <p className="cause-summary-label">{investigation.cause_label}</p>
        {investigation.cause_status === 'inferred' && (
          <p className="cause-status-note">Inferred from issuance remaining-life; same-endpoint replacement is not established.</p>
        )}
        {causeBody && <p className={investigation.finding_class === 'expected' ? 'cause-benign' : 'cause-compact-body'}>{causeBody}</p>}
        {measuredFacts.length > 0 && (
          <ul className="cause-measured-facts">
            {measuredFacts.map((fact) => <li key={fact}>{fact}</li>)}
          </ul>
        )}
      </div>
    );
  }
  if (benignExplanation) {
    return (
      <div className={`cause-analysis ${compact ? 'compact' : ''}`}>
        <div className="cause-analysis-head">
          <span className="cause-analysis-label">Expected deployment property</span>
          <span className="certainty-pill info">expected</span>
        </div>
        <p className="cause-benign"><strong>No incident opened.</strong> {benignExplanation}</p>
      </div>
    );
  }
  // The discriminating analyses are what separate a real problem from an
  // expected property of the deployment, so they are shown next to the claim
  // rather than hidden behind the hypothesis list.
  const churn = anomaly.diagnosis?.churn_shape || null;
  const divergence = anomaly.diagnosis?.endpoint_divergence || null;
  const corroboration = anomaly.diagnosis?.corroboration || null;
  const provenance = anomaly.diagnosis?.provenance || null;

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
      {anomaly.diagnosis?.benign_explanation && (
        <p className="cause-benign">
          <strong>Expected deployment property.</strong> {anomaly.diagnosis.benign_explanation}
        </p>
      )}
      {anomaly.diagnosis && (
        <div className="cause-diagnosis-mini">
          <span>{anomaly.diagnosis.primary_label} · {anomaly.diagnosis.confidence}</span>
          <small>{anomaly.diagnosis.measured_rounds} rounds · {Math.round(anomaly.diagnosis.evidence_completeness * 100)}% evidence completeness</small>
        </div>
      )}
      {churn && (
        <div className="cause-discriminator">
          <span className="cause-summary-label">Change-sequence shape · {churn.interpretation.replace(/_/g, ' ')}</span>
          <ul>
            <li>{churn.change_events} counted change(s) across {churn.distinct_leaves} distinct certificate(s)</li>
            <li>{churn.revisit_events} returned to a certificate seen earlier — a replaced certificate cannot come back</li>
            <li>At most {churn.effective_replacements} replacement(s) can explain the observed set</li>
            {churn.coexistence_proofs > 0 && (
              <li>{churn.coexistence_proofs} round(s) saw two of these certificates at the same time</li>
            )}
            <li>
              endpoint comparison: {churn.same_endpoint_changes} same · {churn.cross_endpoint_changes} different · {churn.unknown_endpoint_changes} unrecorded
            </li>
            {churn.median_validity_days > 0 && (
              <li>{churn.replacements_per_validity_period} replacement(s) per {churn.median_validity_days}-day certificate lifetime</li>
            )}
            {(churn.median_remaining_days ?? 0) > 0 && (
              <li>at replacement, {churn.median_remaining_days} day(s) remained (spread {churn.remaining_spread_days ?? 0})</li>
            )}
            {(churn.median_issuance_age_days ?? 0) > 0 && (
              <li>served certificates were already {churn.median_issuance_age_days} day(s) old, across {churn.distinct_issuance_days ?? 0} issuance day(s)</li>
            )}
          </ul>
        </div>
      )}
      {divergence && divergence.endpoints_answered >= 2 && (
        <div className="cause-discriminator">
          <span className="cause-summary-label">Endpoint structure · {divergence.verdict.replace(/_/g, ' ')}</span>
          <ul>
            <li>{divergence.endpoints_answered} endpoint(s) answered with {divergence.distinct_leaves} distinct certificate(s)</li>
            <li>
              spread over {divergence.network_groups} provider network(s);{' '}
              {divergence.intra_group_conflicts > 0
                ? `${divergence.intra_group_conflicts} network(s) disagreed internally, which no multi-provider arrangement explains`
                : 'each network served its own certificate consistently'}
            </li>
            {divergence.cdn && (
              <li>
                {divergence.cdn.method === 'vendor'
                  ? `multi-CDN uses named vendors (${divergence.cdn.distinct_vendors} CDN${divergence.cdn.distinct_vendors === 1 ? '' : 's'} identified)`
                  : 'multi-CDN uses the IPv4 /16 and IPv6 /32 partition because CDN identification is incomplete'}
              </li>
            )}
            <li>assignment held for {divergence.stable_rounds} earlier round(s), compared by network allocation rather than by address</li>
            {divergence.dual_certificate_split && <li>same issuer and names under {divergence.distinct_key_algorithms} key algorithms — a deliberate pair</li>}
            {divergence.defective_endpoints && divergence.defective_endpoints.length > 0 && (
              <li>{divergence.defective_endpoints.length} endpoint(s) served a certificate not valid for the name: {divergence.defective_endpoints.join(', ')}</li>
            )}
            {divergence.predecessor_endpoints && divergence.predecessor_endpoints.length > 0 && (
              <li>{divergence.predecessor_endpoints.length} endpoint(s) still on the replaced certificate after {Math.round(divergence.residue_hours)}h</li>
            )}
          </ul>
        </div>
      )}
      {corroboration && (
        <p className="cause-corroboration">
          Confidence ceiling <strong>{corroboration.confidence_ceiling}</strong> — certificate transparency {corroboration.ct_status.replace(/_/g, ' ')}
          {corroboration.ct_issuance_events > 0 ? ` (${corroboration.ct_issuance_events} logged issuance(s))` : ''}
          {corroboration.sct_presented ? `, handshake SCT (${corroboration.sct_log_count || 0} log${(corroboration.sct_log_count || 0) === 1 ? '' : 's'}${corroboration.sct_qualified_logs ? `, ${corroboration.sct_qualified_logs} Chrome-listed` : ''}${corroboration.sct_apple_logs ? `, ${corroboration.sct_apple_logs} Apple-listed` : ''}${corroboration.sct_inclusion_proofs ? `, ${corroboration.sct_inclusion_proofs} inclusion-proven` : ''})` : ', handshake SCT not presented'}
          {corroboration.directory_status ? `, numbering authority ${corroboration.directory_status.replace(/_/g, ' ')}` : ''}
          {corroboration.caa_status ? `, CAA ${corroboration.caa_status.replace(/_/g, ' ')}` : ''}
          {corroboration.dnssec_validated ? ', DNSSEC authenticated' : ''}
          {`, endpoint coverage ${Math.round(corroboration.endpoint_coverage * 100)}%.`}
          {corroboration.ct_note ? ` ${corroboration.ct_note}` : ''}
          {corroboration.sct_note ? ` ${corroboration.sct_note}` : ''}
          {corroboration.directory_note ? ` ${corroboration.directory_note}` : ''}
          {corroboration.caa_note ? ` ${corroboration.caa_note}` : ''}
          {corroboration.dnssec_note ? ` ${corroboration.dnssec_note}` : ''}
          {corroboration.timing_note ? ` ${corroboration.timing_note}` : ''}
        </p>
      )}
      {provenance && provenance.legacy_dominated && (
        <p className="cause-provenance">
          {provenance.legacy_rule_events} of {provenance.total_events} supporting observation(s) were recorded by a superseded detection rule and do not carry the current rule's guarantees.
        </p>
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
