import { formatDistanceToNow, format } from 'date-fns';
import { zhCN } from 'date-fns/locale';

function parse(iso?: string): Date | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d.getTime()) || d.getFullYear() < 2000) return null;
  return d;
}

export function timeAgo(iso?: string): string {
  const d = parse(iso);
  return d ? formatDistanceToNow(d, { addSuffix: true, locale: zhCN }) : '—';
}

export function timeUntil(iso?: string): string {
  const d = parse(iso);
  if (!d) return '—';
  return formatDistanceToNow(d, { addSuffix: true, locale: zhCN });
}

export function fmtDateTime(iso?: string): string {
  const d = parse(iso);
  return d ? format(d, 'yyyy-MM-dd HH:mm') : '—';
}

export function fmtDate(iso?: string): string {
  const d = parse(iso);
  return d ? format(d, 'yyyy-MM-dd') : '—';
}

export function fmtDays(days: number): string {
  if (days < 0) return `已过期 ${Math.abs(days)} 天`;
  if (days === 0) return '今天到期';
  return `${days} 天`;
}

export function shortFp(value?: string, length = 12): string {
  const fingerprint = (value || '').trim();
  if (!fingerprint) return '未采集';
  return fingerprint.length <= length ? fingerprint : `${fingerprint.slice(0, length)}…`;
}
