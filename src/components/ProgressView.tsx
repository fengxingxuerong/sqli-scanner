import { Box, Typography, LinearProgress, List, ListItem, ListItemText, Chip, Grid, Paper, Button } from '@mui/material';
import { useScanStore } from '../store/scanStore';
import { useScan } from '../hooks/useScan';
import type { ScanStatus, ScanEvent } from '../shared/types';

// 毫秒时长格式化为可读字符串（s / m s / h m）
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '0s';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return `${m}m ${rs}s`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return `${h}h ${rm}m`;
}

// 由事件时间戳与当前阶段百分比线性外推耗时 / 预计剩余（估算，非精确）
export function estimateRemaining(
  events: ScanEvent[],
  percent: number,
): { elapsedMs: number; remainingMs: number | null } {
  if (events.length < 2) return { elapsedMs: 0, remainingMs: null };
  const first = Date.parse(events[0].ts);
  const last = Date.parse(events[events.length - 1].ts);
  if (!Number.isFinite(first) || !Number.isFinite(last)) return { elapsedMs: 0, remainingMs: null };
  const elapsedMs = last - first;
  if (elapsedMs <= 0) return { elapsedMs: 0, remainingMs: null };
  if (percent <= 0 || percent >= 100) return { elapsedMs, remainingMs: null };
  const remainingMs = (elapsedMs / percent) * (100 - percent);
  return { elapsedMs, remainingMs };
}

const STATUS_LABEL: Record<ScanStatus, string> = {
  pending: '待开始',
  running: '扫描中',
  completed: '已完成',
  stopped: '已停止',
  error: '出错',
};

// SSE 实时连接状态 → 指示文案与颜色（绿=已连接 / 蓝=连接中 / 琥珀=重连中 / 灰=未连接）
const SSE_STATUS: Record<'idle' | 'connecting' | 'open' | 'reconnecting', { label: string; color: string }> = {
  idle: { label: '未连接', color: '#9e9e9e' },
  connecting: { label: '连接中…', color: '#1565c0' },
  open: { label: '实时已连接', color: '#2e7d32' },
  reconnecting: { label: '重连中…', color: '#ed6c02' },
};

const STATUS_COLOR: Record<ScanStatus, 'default' | 'info' | 'success' | 'warning' | 'error'> = {
  pending: 'default',
  running: 'info',
  completed: 'success',
  stopped: 'warning',
  error: 'error',
};

// sqlmap 输出级别 → 颜色
const LOG_COLOR: Record<string, string> = {
  success: '#2e7d32',
  error: '#d32f2f',
  info: '#1565c0',
  warn: '#ed6c02',
  debug: '#9e9e9e',
  output: '#374151',
};

// 按事件类型渲染 secondary 内容（sqlmap 输出做着色/高亮）
function renderSecondary(e: ScanEvent) {
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
    return (
      <span>
        发现注入点：参数 <b>{v.param}</b> · 技术 <b>{v.technique}</b>
      </span>
    );
  }
  return typeof e.payload === 'object' ? JSON.stringify(e.payload) : String(e.payload);
}

// 从 status + 事件推导扫描阶段与百分比（纯函数，便于测试与复用）
export interface ProgressInfo {
  percent: number;
  stage: string;
}
export function deriveProgress(status: ScanStatus, events: ScanEvent[]): ProgressInfo {
  if (status === 'pending') return { percent: 0, stage: '待开始' };
  if (status === 'completed') return { percent: 100, stage: '已完成' };
  if (status === 'stopped') return { percent: 100, stage: '已停止' };
  if (status === 'error') return { percent: 100, stage: '出错' };
  // running：按事件先后顺序判断当前所处阶段
  const hasDiscovered = events.some((e) => e.type === 'point_discovered');
  const hasSecondOrder = events.some((e) => e.type === 'second_order_discovery');
  const hasFound = events.some((e) => e.type === 'detection_found' || e.type === 'sqlmap_vuln');
  if (hasFound) return { percent: 80, stage: '确认漏洞' };
  if (hasSecondOrder) return { percent: 60, stage: '二阶发现' };
  if (hasDiscovered) return { percent: 35, stage: '探测注入点' };
  if (events.length > 0) return { percent: 20, stage: '主动探测' };
  return { percent: 5, stage: '初始化' };
}

// 实时进度区：阶段进度条 + 指标面板 + 事件流
export default function ProgressView() {
  const { status, events, discoveredPoints, confirmedVulnPointIds, secondOrderDiscovery, scanConcurrency, sseStatus, engine, scanId, targetUrl } =
    useScanStore();
  const { stopScan } = useScan();
  const running = status === 'running';
  const info = deriveProgress(status, events);
  // 耗时 / 预计剩余：基于事件时间戳线性外推（估算）
  const { elapsedMs, remainingMs } = estimateRemaining(events, info.percent);

  // 实时指标（从 store 派生，不解析事件 payload，稳定可靠）
  const secondConfirmed = secondOrderDiscovery?.confirmed.length ?? 0;
  const secondCandidates = secondOrderDiscovery?.candidates.length ?? 0;
  const metrics: { label: string; value: string | number; tone: 'info' | 'error' | 'warning' | false }[] = [
    { label: '注入点', value: discoveredPoints.length, tone: 'info' },
    { label: '已确认漏洞', value: confirmedVulnPointIds.length, tone: 'error' },
    { label: '二阶确认', value: `${secondConfirmed}/${secondCandidates}`, tone: 'warning' },
    { label: '事件总数', value: events.length, tone: false },
    { label: '已耗时', value: elapsedMs > 0 ? formatDuration(elapsedMs) : '—', tone: false },
    { label: '并发度', value: scanConcurrency ?? '—', tone: false },
  ];

  return (
    <Box className="space-y-3">
      {/* 扫描任务卡：当前任务概览 + 醒目停止控制（复用 store 字段与 useScan.stopScan） */}
      <Paper variant="outlined" className="p-3">
        <Box className="flex items-center justify-between mb-2">
          <Typography variant="subtitle2" fontWeight={700}>扫描任务</Typography>
          <Chip size="small" label={STATUS_LABEL[status]} color={STATUS_COLOR[status]} />
        </Box>
        <Typography variant="body2" sx={{ wordBreak: 'break-all' }} className="mb-1">
          <b>目标地址：</b>
          {targetUrl || '—'}
        </Typography>
        <Box className="flex flex-wrap gap-x-4 gap-y-1">
          <Typography variant="caption" color="text.secondary">
            引擎：{engine === 'sqlmap' ? 'sqlmap 高级' : '自带引擎'}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            并发：{scanConcurrency ?? '—'}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            用时：{elapsedMs > 0 ? formatDuration(elapsedMs) : '—'}
          </Typography>
        </Box>
        <Box className="mt-2">
          <Button
            variant="contained"
            color="error"
            size="small"
            disabled={status !== 'running' || !scanId}
            onClick={() => scanId && stopScan(scanId)}
          >
            停止扫描
          </Button>
        </Box>
      </Paper>

      <Box className="flex items-center justify-between">
        <Typography variant="subtitle1" fontWeight={600}>
          实时进度
        </Typography>
        <Box className="flex items-center gap-2">
          {/* SSE 实时连接状态指示：让用户直观看到进度是否在实时推送 */}
          <Box className="flex items-center gap-1" title="实时事件流连接状态">
            <Box
              component="span"
              className="inline-block rounded-full"
              sx={{ width: 8, height: 8, bgcolor: SSE_STATUS[sseStatus].color }}
            />
            <Typography variant="caption" color="text.secondary">
              {SSE_STATUS[sseStatus].label}
            </Typography>
          </Box>
          <Chip label={STATUS_LABEL[status]} color={STATUS_COLOR[status]} size="small" />
        </Box>
      </Box>

      {/* 阶段进度条：从 status + 事件推导 determinate 百分比，替代纯不确定条 */}
      <Box className="flex items-center gap-2 mb-1">
        <Typography variant="body2" color="text.secondary">阶段</Typography>
        <Chip size="small" label={info.stage} color={running ? 'info' : 'default'} />
        <Typography variant="body2" color="text.secondary">{info.percent}%</Typography>
      </Box>
      <LinearProgress
        variant="determinate"
        value={info.percent}
        color={status === 'error' ? 'error' : status === 'completed' ? 'success' : 'primary'}
      />

      {/* 预计剩余时间（仅扫描中显示；基于事件时间戳线性外推，标注「估算」避免误读为精确值） */}
      {running && (
        <Box className="flex items-center gap-2 mt-1 mb-1">
          <Typography variant="body2" color="text.secondary">预计剩余</Typography>
          <Chip
            size="small"
            color="warning"
            label={remainingMs != null ? `约 ${formatDuration(remainingMs)}（估算）` : '估算中…'}
          />
        </Box>
      )}

      {/* 实时指标面板 */}
      <Grid container spacing={1} className="mt-1">
        {metrics.map((m) => (
          <Grid item xs={6} sm={4} md={2} key={m.label}>
            <Box className="rounded border border-gray-200 p-2 text-center">
              <Typography variant="h6" fontWeight={700} color={m.tone || undefined} className="leading-none">
                {m.value}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {m.label}
              </Typography>
            </Box>
          </Grid>
        ))}
      </Grid>

      <List dense className="max-h-72 overflow-auto rounded border border-gray-200 mt-1">
        {events.length === 0 && (
          <ListItem>
            <ListItemText primary="暂无事件，开始扫描后这里会实时显示进度" />
          </ListItem>
        )}
        {events.map((e, i) => (
          <ListItem key={i} divider>
            <ListItemText
              primary={
                <span className="font-mono text-xs text-gray-400">
                  [{e.type}] {e.ts}
                </span>
              }
              secondary={renderSecondary(e)}
            />
          </ListItem>
        ))}
      </List>
    </Box>
  );
}
