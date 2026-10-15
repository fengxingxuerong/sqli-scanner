// EventTimeline —— 扫描事件直播控制台
// [D80 2026-10-14] 从"最近 50 条倒序列表"改为终端式直播：
//   · 全量事件按时间序渲染（倒序 50 条会藏掉过程，用户要求"扫描过程全部可见"）；
//   · 自动跟随最新（用户上翻即暂停跟随，提供「跳到最新」）；
//   · 终端配色（.terminal-block + 等宽字体 + 事件类型着色），运行中有呼吸指示灯。
// 组件名/路径保持不变（ProgressView 及其测试的引用面不变）。

import { useEffect, useRef, useState } from 'react';
import { Box, Typography, Button, Stack } from '@mui/material';
import { useTranslation } from 'react-i18next';
import VerticalAlignBottomIcon from '@mui/icons-material/VerticalAlignBottom';
import type { ScanEvent } from '../../shared/types';
import { getEventStyle, renderSecondary } from './progressUtils';

export interface EventTimelineProps {
  events: ScanEvent[];
  /** 扫描进行中：显示呼吸指示灯与跟随态 */
  running?: boolean;
}

export default function EventTimeline({ events, running = false }: EventTimelineProps) {
  const { t } = useTranslation();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoFollow, setAutoFollow] = useState(true);

  // 自动跟随：事件数变化且仍处于跟随态时贴底
  useEffect(() => {
    if (!autoFollow) return;
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events.length, autoFollow]);

  // 用户上翻 => 暂停跟随；回到底部 => 恢复
  const handleScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    setAutoFollow(atBottom);
  };

  const jumpToLatest = () => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
    setAutoFollow(true);
  };

  return (
    <>
      <Stack direction="row" alignItems="center" spacing={1} className="mb-1">
        {running && (
          <Box
            aria-label="live"
            className="pulse-dot"
            sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#22c55e', flexShrink: 0 }}
          />
        )}
        <Typography variant="subtitle2" fontWeight={600}>
          {t('scan.events')}
        </Typography>
        <Typography variant="caption" color="text.secondary" className="mono">
          {events.length}
        </Typography>
        {!autoFollow && (
          <Button size="small" startIcon={<VerticalAlignBottomIcon />} onClick={jumpToLatest} sx={{ ml: 'auto' }}>
            {t('scan.jumpToLatest')}
          </Button>
        )}
      </Stack>
      <Box
        ref={scrollRef}
        onScroll={handleScroll}
        className="terminal-block mono"
        data-testid="event-console"
        sx={{
          maxHeight: 420,
          overflowY: 'auto',
          py: 1,
          '& .evt-row': { py: 0.25 },
          '& .evt-row:hover': { bgcolor: 'rgba(0, 212, 255, 0.04)' },
        }}
      >
        {events.length === 0 && (
          <Typography variant="caption" color="text.secondary" className="mono">
            {t('scan.noEvents')}
          </Typography>
        )}
        {events.map((e) => {
          const style = getEventStyle(e.type);
          const stableKey = typeof e.seq === 'number' ? e.seq : `${e.ts}-${e.type}-${e.scanId ?? ''}`;
          return (
            <Box key={stableKey} className="evt-row" sx={{ display: 'flex', gap: 1.5, alignItems: 'baseline' }}>
              <Typography component="span" variant="caption" sx={{ color: 'text.disabled', flexShrink: 0 }}>
                {e.ts}
              </Typography>
              <Typography component="span" variant="caption" sx={{ color: style.color, fontWeight: 700, flexShrink: 0, minWidth: 132 }}>
                {e.type}
              </Typography>
              <Typography component="span" variant="caption" sx={{ color: 'text.secondary', minWidth: 0 }}>
                {renderSecondary(e, t)}
              </Typography>
            </Box>
          );
        })}
      </Box>
    </>
  );
}
