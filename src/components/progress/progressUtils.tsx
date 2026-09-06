// progressUtils -- ProgressView extracted constants, types and helper functions

import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import WarningIcon from '@mui/icons-material/Warning';
import BugReportIcon from '@mui/icons-material/BugReport';
import SecurityIcon from '@mui/icons-material/Security';
import type { ScanStatus, ScanEvent } from '../../shared/types';

export const STATUS_COLOR: Record<ScanStatus, 'default' | 'info' | 'success' | 'warning' | 'error'> = {
  pending: 'default', running: 'info', paused: 'warning', completed: 'success', stopped: 'warning', error: 'error',
};

// 事件类型 -> 图标 + 颜色
// [P1-FIX] 修正事件样式表：删除不存在于 EventType 的幽灵 key（detection_not_found），
// 补齐 extraction_progress / scan_stopped / scan_paused / scan_resumed（此前静默走灰色默认，
// 暂停/停止在时间线上无视觉区分）。
export const EVENT_STYLE: Record<string, { icon: ReactNode; color: string }> = {
  scan_started: { icon: <InfoIcon fontSize="small" />, color: '#1565c0' },
  scan_phase: { icon: <InfoIcon fontSize="small" />, color: '#1565c0' },
  http_request: { icon: <InfoIcon fontSize="small" />, color: '#475569' },
  point_discovered: { icon: <BugReportIcon fontSize="small" />, color: '#7c3aed' },
  point_testing: { icon: <SecurityIcon fontSize="small" />, color: '#ed6c02' },
  detection_found: { icon: <CheckCircleIcon fontSize="small" />, color: '#2e7d32' },
  extraction_progress: { icon: <BugReportIcon fontSize="small" />, color: '#7c3aed' },
  point_skipped: { icon: <WarningIcon fontSize="small" />, color: '#f59e0b' },
  scan_completed: { icon: <CheckCircleIcon fontSize="small" />, color: '#2e7d32' },
  scan_stopped: { icon: <WarningIcon fontSize="small" />, color: '#f59e0b' },
  scan_paused: { icon: <WarningIcon fontSize="small" />, color: '#f59e0b' },
  scan_resumed: { icon: <InfoIcon fontSize="small" />, color: '#1565c0' },
  scan_error: { icon: <ErrorIcon fontSize="small" />, color: '#d32f2f' },
  waf_detected: { icon: <WarningIcon fontSize="small" />, color: '#dc2626' },
  sqlmap_log: { icon: <InfoIcon fontSize="small" />, color: '#374151' },
  sqlmap_vuln: { icon: <CheckCircleIcon fontSize="small" />, color: '#2e7d32' },
};

export function getEventStyle(type: string) {
  return EVENT_STYLE[type] || { icon: <InfoIcon fontSize="small" />, color: '#757575' };
}

// sqlmap 日志颜色
export const LOG_COLOR: Record<string, string> = {
  success: '#2e7d32', error: '#d32f2f', info: '#1565c0',
  warn: '#ed6c02', debug: '#9e9e9e', output: '#374151',
};

type TFunc = ReturnType<typeof useTranslation>['t'];

export function renderSecondary(e: ScanEvent, t: TFunc) {
  if (e.type === 'http_request') {
    const p = e.payload as { method?: string; url?: string; status?: number; ms?: number };
    return (
      <span style={{ color: '#475569', fontFamily: '"JetBrains Mono", monospace', fontSize: 12 }}>
        {p.method} {p.url} → {p.status}{p.ms != null ? ` (${p.ms}ms)` : ''}
      </span>
    );
  }
  if (e.type === 'sqlmap_log') {
    const p = e.payload as { level?: string; text?: string };
    const color = LOG_COLOR[p.level ?? 'output'] || '#374151';
    return (
      <span style={{ color, fontFamily: 'monospace', fontSize: 12, whiteSpace: 'pre-wrap' }}>
        {p.text}
      </span>
    );
  }
  if (e.type === 'sqlmap_vuln') {
    const v = e.payload as { param?: string; technique?: string };
    return <span>{t('progress.vulnFoundPrefix')}<b>{v.param}</b>{t('progress.vulnFoundSep')}<b>{v.technique}</b></span>;
  }
  if (e.type === 'waf_detected') {
    const p = e.payload as { vendors?: { vendor: string }[] };
    const vendors = p.vendors?.map((v) => v.vendor).join(t('progress.vendorSep')) || t('progress.unknown');
    return <span>{t('progress.wafDetected', { vendors })}</span>;
  }
  if (e.type === 'point_discovered') {
    const p = e.payload as { points?: unknown[] };
    return <span>{t('progress.pointsDiscovered', { count: p.points?.length || 0 })}</span>;
  }
  return typeof e.payload === 'object' ? JSON.stringify(e.payload) : String(e.payload);
}

export function formatEvents(events: ScanEvent[]): string {
  return events
    .map((e) => {
      const payload = typeof e.payload === 'object' && e.payload !== null
        ? JSON.stringify(e.payload) : String(e.payload ?? '');
      return `[${e.type}] ${e.ts} ${payload}`;
    })
    .join('\n');
}

// 阶段耗时分析
export interface StageTiming {
  label: string;
  seconds: number;
  color: string;
}

export function secondsBetween(a: string, b: string): number {
  const ta = new Date(a).getTime();
  const tb = new Date(b).getTime();
  if (Number.isNaN(ta) || Number.isNaN(tb)) return 0;
  return Math.max(0, (tb - ta) / 1000);
}

export function computeStageTimings(events: ScanEvent[]): StageTiming[] {
  if (events.length < 2) return [];
  const stages: StageTiming[] = [];
  const firstPt = events.find((e) => e.type === 'point_testing');
  const lastDf = [...events].reverse().find((e) => e.type === 'detection_found');
  if (firstPt && lastDf) {
    const d = secondsBetween(firstPt.ts, lastDf.ts);
    if (d > 0) stages.push({ label: 'progress.stageDetect', seconds: d, color: '#ed6c02' });
  }
  const firstEp = events.find((e) => e.type === 'extraction_progress');
  const lastEp = [...events].reverse().find((e) => e.type === 'extraction_progress');
  if (firstEp && lastEp) {
    const d = secondsBetween(firstEp.ts, lastEp.ts);
    if (d > 0) stages.push({ label: 'progress.stageExtract', seconds: d, color: '#7c3aed' });
  }
  const total = secondsBetween(events[0].ts, events[events.length - 1].ts);
  if (total > 0) stages.push({ label: 'progress.stageTotal', seconds: total, color: '#1565c0' });
  return stages;
}

// 事件类型计数徽章
export interface BadgeItem {
  label: string;
  count: number;
  color: string;
}

export function computeBadges(events: ScanEvent[]): BadgeItem[] {
  const countOf = (type: string) => events.filter((e) => e.type === type).length;
  const badges: BadgeItem[] = [
    { label: 'progress.badgeDiscovered', count: countOf('point_discovered'), color: EVENT_STYLE.point_discovered.color },
    { label: 'progress.badgeTested', count: countOf('point_testing'), color: EVENT_STYLE.point_testing.color },
    { label: 'progress.badgeHits', count: countOf('detection_found') + countOf('sqlmap_vuln'), color: EVENT_STYLE.detection_found.color },
    { label: 'progress.badgeErrors', count: countOf('scan_error'), color: EVENT_STYLE.scan_error.color },
  ];
  return badges.filter((b) => b.count > 0);
}

export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(text); return; }
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  document.execCommand('copy'); document.body.removeChild(ta);
}
