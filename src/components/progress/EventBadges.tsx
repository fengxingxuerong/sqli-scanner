// EventBadges -- event type count badges + request rate

import { Box, Stack, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { BadgeItem } from './progressUtils';

export interface EventBadgesProps {
  badges: BadgeItem[];
  reqRate: number | null;
}

export default function EventBadges({ badges, reqRate }: EventBadgesProps) {
  const { t } = useTranslation();
  if (badges.length === 0 && reqRate == null) return null;
  return (
    <Box sx={{ flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
      <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
        {badges.map((b) => (
          <Box
            key={b.label}
            sx={{
              px: 0.8,
              py: 0.15,
              borderRadius: 1,
              bgcolor: `${b.color}22`,
              color: b.color,
              fontSize: 11,
              fontWeight: 700,
              whiteSpace: 'nowrap',
              lineHeight: 1.4,
            }}
          >
            {t(b.label, { count: b.count })}
          </Box>
        ))}
      </Stack>
      {reqRate != null && (
        <Typography variant="caption" sx={{ color: '#9e9e9e', fontFamily: 'monospace', textAlign: 'right' }}>
          {t('progress.reqRate', { rate: reqRate.toFixed(1) })}
        </Typography>
      )}
    </Box>
  );
}
