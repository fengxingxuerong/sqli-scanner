// StageTimingBar -- stage timing horizontal bars

import { Box, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { StageTiming } from './progressUtils';

export interface StageTimingBarProps {
  stageTimings: StageTiming[];
  maxStage: number;
}

export default function StageTimingBar({ stageTimings, maxStage }: StageTimingBarProps) {
  const { t } = useTranslation();
  if (stageTimings.length === 0) return null;
  return (
    <Box sx={{ flex: 1, minWidth: 200 }}>
      <Typography variant="caption" color="text.secondary">
        {t('progress.stageTiming')}
      </Typography>
      <Box sx={{ mt: 0.5 }}>
        {stageTimings.map((s) => (
          <Box key={s.label} sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.3 }}>
            <Typography
              variant="caption"
              sx={{ width: 56, color: s.color, fontWeight: 700, flexShrink: 0 }}
            >
              {t(s.label)}
            </Typography>
            <Box
              sx={{
                flex: 1,
                height: 10,
                bgcolor: 'rgba(0,0,0,0.06)',
                borderRadius: 5,
                overflow: 'hidden',
              }}
            >
              <Box
                sx={{
                  width: `${maxStage > 0 ? Math.max(2, (s.seconds / maxStage) * 100) : 0}%`,
                  height: '100%',
                  bgcolor: s.color,
                  borderRadius: 5,
                  transition: 'width 0.3s ease',
                }}
              />
            </Box>
            <Typography
              variant="caption"
              sx={{ width: 52, textAlign: 'right', fontFamily: 'monospace', flexShrink: 0 }}
            >
              {s.seconds.toFixed(1)}s
            </Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
}
