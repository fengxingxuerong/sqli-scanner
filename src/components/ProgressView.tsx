// ProgressView -- 可视化进度面板：进度条 + 事件时间线 + 实时统计
// 拆分为 6 个子组件 + progressUtils 工具模块（⑱：原 439 行 -> 主组件仅状态管理 + 渲染编排）

import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box, Typography, LinearProgress, Chip, Stack, Divider,
} from '@mui/material';
import { useScanStore } from '../store/scanStore';
import { tauriBridge } from '../shared/tauriBridge';
import { STATUS_COLOR } from './progress/progressUtils';
import {
  computeStageTimings, computeBadges, formatEvents, copyText,
} from './progress/progressUtils';
import PhaseAlert from './progress/PhaseAlert';
import StageTimingBar from './progress/StageTimingBar';
import EventBadges from './progress/EventBadges';
import StatCardGroup from './progress/StatCardGroup';
import LogActions from './progress/LogActions';
import EventTimeline from './progress/EventTimeline';
import type { ScanStatus } from '../shared/types';

export default function ProgressView() {
  const { t } = useTranslation();
  const status = useScanStore((s) => s.status) as ScanStatus;
  const events = useScanStore((s) => s.events);
  const scanId = useScanStore((s) => s.scanId);
  // H2：进度聚合改为消费 store 增量维护值（不再从 events 滑窗重算，
  // 长扫描中早期 point_discovered 被截断后进度条不会归零/回退）
  const progressTotal = useScanStore((s) => s.progressTotal);
  // [P1-FIX] 订阅增量数字而非 processedPointIds 对象（对象每事件新引用触发整组件重渲染）
  const processedCount = useScanStore((s) => s.processedCount);
  const [downloadError, setDownloadError] = useState('');
  const running = status === 'running';
  const total = progressTotal;
  const processed = processedCount;
  const pct = total > 0 ? Math.round((processed / total) * 100) : null;
  const progressValue = pct == null ? undefined : Math.min(100, pct);

  // 阶段耗时统计条
  const stageTimings = useMemo(() => computeStageTimings(events), [events]);
  const maxStage = stageTimings.length > 0 ? Math.max(...stageTimings.map((s) => s.seconds)) : 0;

  // 事件类型计数徽章
  const badges = useMemo(() => computeBadges(events), [events]);

  // 实时速率指示器：每 5 秒重算一次（events / 已用秒数）
  const [rateTick, setRateTick] = useState(0);
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => setRateTick((n) => n + 1), 5000);
    return () => clearInterval(id);
  }, [running]);
  const reqRate = useMemo(() => {
    if (events.length < 1) return null;
    const start = new Date(events[0].ts).getTime();
    if (Number.isNaN(start)) return null;
    const end = running ? Date.now() : new Date(events[events.length - 1].ts).getTime();
    if (Number.isNaN(end)) return null;
    const secs = (end - start) / 1000;
    if (secs <= 0) return null;
    return events.length / secs;
  }, [events, running, rateTick]); // eslint-disable-line react-hooks/exhaustive-deps -- rateTick 仅作定时刷新信号

  // 统计信息
  const vulnFound = useMemo(() => events.filter(e => e.type === 'detection_found').length, [events]);
  const wafDetected = useMemo(() => events.filter(e => e.type === 'waf_detected').length, [events]);
  const pointsTested = useMemo(() => events.filter(e => e.type === 'point_testing').length, [events]);
  // 当前阶段提示：从最新 scan_phase 事件取 message
  const currentPhase = useMemo(() => {
    if (!running) return null;
    const phases = events.filter(e => e.type === 'scan_phase');
    if (phases.length === 0) {
      // 无 scan_phase 事件时从其他事件推断
      if (events.some(e => e.type === 'extraction_progress')) return t('progress.phaseExtracting');
      if (pointsTested > 0) return t('progress.phaseDetecting', { count: pointsTested });
      if (events.length > 0) return t('progress.phaseInitializing');
      return t('progress.phaseStarting');
    }
    const last = phases[phases.length - 1];
    return (last.payload as { message?: string })?.message || t('progress.phaseScanning');
  }, [events, running, pointsTested, t]);
  const elapsed = useMemo(() => {
    if (events.length < 2) return '';
    const first = new Date(events[0].ts).getTime();
    const last = new Date(events[events.length - 1].ts).getTime();
    if (Number.isNaN(first) || Number.isNaN(last)) return '';
    const diff = Math.max(0, last - first);
    if (diff < 1000) return '< 1s';
    if (diff < 60000) return `${Math.round(diff / 1000)}s`;
    const min = Math.floor(diff / 60000);
    const sec = Math.round((diff % 60000) / 1000);
    return `${min}m ${sec}s`;
  }, [events]);

  const handleCopyLogs = async () => {
    if (!events.length) return;
    try { await copyText(formatEvents(events)); } catch { /* silent */ }
  };

  const handleDownloadLogs = () => {
    if (!events.length) return;
    setDownloadError('');
    const name = `scan_logs_${scanId || 'unknown'}.log`;
    tauriBridge.saveFile(name, formatEvents(events), 'text/plain; charset=utf-8')
      .catch((err) => setDownloadError(t('progress.downloadFailed', { detail: err?.message || t('progress.unknownError') })));
  };

  // 最近 50 条事件（倒序，最新的在前）
  const recentEvents = useMemo(() => {
    const reversed = [...events].reverse();
    return reversed.slice(0, 50);
  }, [events]);

  return (
    <Box className="space-y-3">
      {/* 当前阶段提示 */}
      <PhaseAlert running={running} currentPhase={currentPhase} pct={pct} />

      {/* 进度条 + 统计 */}
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="subtitle1" fontWeight={600}>{t('scan.progress')}</Typography>
        <Chip label={t(`status.${status}`)} color={STATUS_COLOR[status]} size="small" />
      </Stack>
      <LinearProgress
        variant={!running ? 'determinate' : pct == null ? 'indeterminate' : 'determinate'}
        value={!running ? 100 : pct == null ? undefined : progressValue}
        sx={{ height: 8, borderRadius: 4 }}
      />
      {running && pct != null && (
        <Typography variant="caption" color="text.secondary">
          {t('scan.pointsProcessed', { processed, total, pct: progressValue })}
        </Typography>
      )}

      {/* 阶段耗时统计条 + 事件类型计数徽章 */}
      {(stageTimings.length > 0 || badges.length > 0) && (
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          spacing={1.5}
          alignItems="stretch"
          useFlexGap
          sx={{ mt: 0.5 }}
        >
          <StageTimingBar stageTimings={stageTimings} maxStage={maxStage} />
          <EventBadges badges={badges} reqRate={reqRate} />
        </Stack>
      )}

      {/* 统计卡片 */}
      <StatCardGroup
        total={total}
        pointsTested={pointsTested}
        vulnFound={vulnFound}
        wafDetected={wafDetected}
        elapsed={elapsed}
        running={running}
      />

      {/* 操作按钮 */}
      <LogActions
        eventsLength={events.length}
        onCopyLogs={handleCopyLogs}
        onDownloadLogs={handleDownloadLogs}
        downloadError={downloadError}
      />

      <Divider />

      {/* 事件时间线 */}
      <EventTimeline events={events} recentEvents={recentEvents} />
    </Box>
  );
}
