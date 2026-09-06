// EventTimeline -- scrollable list of recent scan events

import { Box, Typography, List, ListItem, ListItemText } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { ScanEvent } from '../../shared/types';
import { getEventStyle, renderSecondary } from './progressUtils';

export interface EventTimelineProps {
  events: ScanEvent[];
  recentEvents: ScanEvent[];
}

export default function EventTimeline({ events, recentEvents }: EventTimelineProps) {
  const { t } = useTranslation();
  return (
    <>
      <Typography variant="subtitle2" fontWeight={600} className="mb-1">{t('scan.events')}</Typography>
      <List dense className="max-h-72 overflow-auto rounded border border-gray-200">
        {events.length === 0 && (
          <ListItem>
            <ListItemText primary={t('scan.noEvents')} />
          </ListItem>
        )}
        {recentEvents.map((e) => {
          const style = getEventStyle(e.type);
          // [P1-FIX] 稳定 key：倒序列表用 key={i} 时新事件到达整体位移、50 行 DOM 全量重建。
          // 优先用服务端单调 seq（SSE id 行），无 seq（mock/旧事件）退化为 ts+type。
          const stableKey = typeof e.seq === 'number' ? e.seq : `${e.ts}-${e.type}-${e.scanId ?? ''}`;
          return (
            <ListItem key={stableKey} divider sx={{ py: 0.5 }}>
              <Box sx={{ mr: 1.5, mt: 0.3, color: style.color, display: 'flex', alignItems: 'center' }}>
                {style.icon}
              </Box>
              <ListItemText
                primary={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography variant="caption" sx={{ color: style.color, fontWeight: 600, fontFamily: 'monospace' }}>
                      {e.type}
                    </Typography>
                    <Typography variant="caption" color="text.disabled">
                      {e.ts}
                    </Typography>
                  </Box>
                }
                secondary={renderSecondary(e, t)}
              />
            </ListItem>
          );
        })}
      </List>
    </>
  );
}
