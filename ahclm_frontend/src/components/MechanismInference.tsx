import type { MechanismReport } from '@/types';

const STATUS_LABEL: Record<string, string> = {
  supported: '最符合',
  ambiguous: '未能分开',
  insufficient: '证据不足',
};

const VERDICT_LABEL: Record<string, string> = {
  supported: '最符合',
  possible: '可能',
  rejected: '排除',
  underdetermined: '不能判定',
};

function cellMark(effect?: string): string {
  if (effect === 'support') return '+';
  if (effect === 'exclude') return '−';
  return '';
}

export default function MechanismInference({ report }: { report: MechanismReport }) {
  const scores = report.scores ?? [];
  const columns = report.columns ?? [];
  const matrix = report.matrix ?? [];
  const label = STATUS_LABEL[report.status] || report.status;
  return (
    <section className="mechanism" aria-label="机制推断">
      <div className="cause-inv-kicker">
        <h3>机制推断</h3>
        <span className={'cause-inv-class ' + (report.status === 'supported' ? 'mixed' : 'insufficient')}>{label}</span>
      </div>
      <p className="mechanism-note">{report.limitation}</p>
      {report.most_supported && <p className="mechanism-lead">最符合：{scores.find((item) => item.id === report.most_supported)?.name || report.most_supported}</p>}
      {scores.length > 0 && (
        <ol className="mechanism-scores">
          {scores.map((item) => (
            <li key={item.id} className={item.score < 0 ? 'against' : item.score === 0 ? 'neutral' : ''}>
              <b>{item.score > 0 ? `+${item.score}` : item.score}</b>
              <span>{item.name}</span>
              {item.verdict && <small>{VERDICT_LABEL[item.verdict] || item.verdict}</small>}
            </li>
          ))}
        </ol>
      )}
      {matrix.length > 0 && columns.length > 0 && (
        <div className="mechanism-matrix-wrap">
          <table className="mechanism-matrix">
            <caption>证据兼容性</caption>
            <thead>
              <tr>
                <th>证据</th>
                {columns.map((column) => <th key={column.id}>{column.name}</th>)}
              </tr>
            </thead>
            <tbody>
              {matrix.map((row) => (
                <tr key={row.id} className={row.observed ? 'observed' : ''}>
                  <th>{row.label}</th>
                  {columns.map((column) => {
                    const effect = row.effects?.find((item) => item.mechanism === column.id);
                    return <td key={column.id} className={effect?.effect || ''}>{cellMark(effect?.effect)}</td>;
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {report.counterexamples && report.counterexamples.length > 0 && (
        <div className="mechanism-counter">
          <span>反例</span>
          <ul>{report.counterexamples.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
      )}
      {report.missing && report.missing.length > 0 && (
        <ul className="mechanism-missing">{report.missing.slice(0, 3).map((item) => <li key={item}>{item}</li>)}</ul>
      )}
    </section>
  );
}
