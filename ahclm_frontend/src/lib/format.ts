import { formatDistanceToNow, format } from 'date-fns';

function parse(iso?: string): Date | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d.getTime()) || d.getFullYear() < 2000) return null;
  return d;
}

export function timeAgo(iso?: string): string {
  const d = parse(iso);
  return d ? formatDistanceToNow(d, { addSuffix: true }) : '—';
}

export function timeUntil(iso?: string): string {
  const d = parse(iso);
  if (!d) return '—';
  return formatDistanceToNow(d, { addSuffix: true });
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
  if (days < 0) return `expired ${Math.abs(days)}d ago`;
  if (days === 0) return 'today';
  return `${days}d`;
}
