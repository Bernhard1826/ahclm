import { useState } from 'react';
import type { CertificateExhibit, ChainEntry } from '@/types';
import { fmtDateTime, shortFp } from '@/lib/format';

function formatSANs(values?: string[]): string {
  if (!values?.length) return "未采集";
  return values.join(', ');
}

function keyLabel(certificate: CertificateExhibit): string {
  const bits = certificate.key_size ? ` ${certificate.key_size}` : '';
  if (certificate.key_algorithm) return `${certificate.key_algorithm}${bits}`.trim();
  if (certificate.public_key_type) return `${certificate.public_key_type}${bits}`.trim();
  return "未采集";
}

function chainRole(index: number, entry: ChainEntry, total: number): string {
  if (index === 0 && !entry.is_ca) return '叶证书';
  if (index === total - 1 || (entry.is_ca && entry.common_name === entry.issuer_cn)) return '根证书';
  if (entry.is_ca) return '中间证书';
  return '证书';
}

function copyText(value: string) {
  if (!value || !navigator.clipboard) return;
  void navigator.clipboard.writeText(value);
}

export default function CertificateRecord({
  certificate,
  compact = false,
  toneClass,
  heading,
}: {
  certificate: CertificateExhibit;
  compact?: boolean;
  toneClass?: string;
  heading?: string;
}) {
  const [openPEM, setOpenPEM] = useState(false);
  const chain = certificate.chain ?? [];
  const captured = Boolean(
    certificate.serial_number
    || certificate.subject
    || certificate.issuer
    || certificate.issuer_cn
    || certificate.common_name
    || (certificate.sans && certificate.sans.length)
    || certificate.pem,
  );

  return (
    <article className={'cert-record' + (compact ? ' compact' : '') + (toneClass ? ' ' + toneClass : '')}>
      <header className="cert-record-head">
        <div>
          <p className="cert-record-kicker">{heading || "证书"}</p>
          <h3>{certificate.common_name || certificate.subject || "叶证书"}</h3>
        </div>
        <code title={certificate.fingerprint}>{shortFp(certificate.fingerprint, compact ? 16 : 24)}</code>
      </header>
      {!captured ? (
        <p className="cert-record-missing">已保留叶证书指纹，但未采集解析后的证书字段。</p>
      ) : (
        <dl className="cert-record-grid">
          <div><dt>主体</dt><dd title={certificate.subject}>{certificate.subject || certificate.common_name || "未采集"}</dd></div>
          <div><dt>签发者</dt><dd title={certificate.issuer}>{certificate.issuer || certificate.issuer_cn || "未采集"}</dd></div>
          <div><dt>序列号</dt><dd><code>{certificate.serial_number || "未采集"}</code></dd></div>
          <div><dt>指纹</dt><dd><code>{certificate.fingerprint}</code></dd></div>
          <div><dt>SPKI</dt><dd><code>{certificate.spki_fingerprint || "未采集"}</code></dd></div>
          <div><dt>公钥</dt><dd>{keyLabel(certificate)}</dd></div>
          <div><dt>签名算法</dt><dd>{certificate.signature_algorithm || "未采集"}</dd></div>
          <div>
            <dt>有效期</dt>
            <dd>
              {certificate.not_before || certificate.not_after
                ? `${fmtDateTime(certificate.not_before)} → ${fmtDateTime(certificate.not_after)}`
                : "未采集"}
              {certificate.validity_days ? `（${certificate.validity_days} 天）` : ''}
            </dd>
          </div>
          <div className="wide"><dt>主体备用名称（SAN）</dt><dd>{formatSANs(certificate.sans)}</dd></div>
          {(certificate.is_ca || certificate.self_signed) && (
            <div>
              <dt>标记</dt>
              <dd>{[certificate.is_ca ? 'CA' : '', certificate.self_signed ? "自签名" : ''].filter(Boolean).join(' · ')}</dd>
            </div>
          )}
        </dl>
      )}
      {chain.length > 0 && (
        <ol className="cert-record-chain">
          {chain.map((entry, index) => (
            <li key={`${entry.common_name}-${index}`}>
              <span>{chainRole(index, entry, chain.length)}</span>
              <strong>{entry.common_name || "未命名"}</strong>
              <small>签发者： {entry.issuer_cn || '未知'}{entry.not_after ? ` · 截止 ${fmtDateTime(entry.not_after)}` : ''}</small>
            </li>
          ))}
        </ol>
      )}
      {certificate.pem && !compact && (
        <div className="cert-record-pem">
          <button type="button" onClick={() => setOpenPEM((open) => !open)}>
            {openPEM ? "收起 PEM" : "展开 PEM"}
          </button>
          <button type="button" onClick={() => copyText(certificate.pem || '')}>复制 PEM</button>
          {openPEM && <pre>{certificate.pem}</pre>}
        </div>
      )}
    </article>
  );
}

export function certificateHeadline(certificate?: CertificateExhibit): string {
  if (!certificate) return '';
  const name = certificate.common_name || certificate.subject || shortFp(certificate.fingerprint, 12);
  const issuer = certificate.issuer_cn ? ` · ${certificate.issuer_cn}` : '';
  return `${name}${issuer}`;
}
