// StatCardGroup -- summary stat cards (points / tested / vulns / waf / elapsed)

import { Paper, Typography, Stack } from '@mui/material';
import { useTranslation } from 'react-i18next';

export interface StatCardGroupProps {
  total: number;
  pointsTested: number;
  vulnFound: number;
  wafDetected: number;
  elapsed: string;
  running: boolean;
}

export default function StatCardGroup({ total, pointsTested, vulnFound, wafDetected, elapsed, running }: StatCardGroupProps) {
  const { t } = useTranslation();
  return (
    <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
      <Paper variant="outlined" sx={{ px: 1.5, py: 0.8, borderRadius: 2 }}>
        <Typography variant="caption" color="text.secondary">{t('progress.points')}</Typography>
        <Typography variant="body2" fontWeight={700}>{total || '-'}</Typography>
      </Paper>
      <Paper variant="outlined" sx={{ px: 1.5, py: 0.8, borderRadius: 2 }}>
        <Typography variant="caption" color="text.secondary">{t('progress.tested')}</Typography>
        <Typography variant="body2" fontWeight={700}>{pointsTested || '-'}</Typography>
      </Paper>
      <Paper variant="outlined" sx={{ px: 1.5, py: 0.8, borderRadius: 2 }}>
        <Typography variant="caption" color="text.secondary">{t('progress.vulns')}</Typography>
        <Typography variant="body2" fontWeight={700} color={vulnFound > 0 ? 'error.main' : 'inherit'}>
          {vulnFound > 0 ? `${vulnFound} !` : (vulnFound === 0 && !running ? t('progress.safe') : '-')}
        </Typography>
      </Paper>
      {wafDetected > 0 && (
        <Paper variant="outlined" sx={{ px: 1.5, py: 0.8, borderRadius: 2, borderColor: 'warning.main' }}>
          <Typography variant="caption" color="text.secondary">{t('progress.waf')}</Typography>
          <Typography variant="body2" fontWeight={700} color="warning.main">{t('progress.detected')}</Typography>
        </Paper>
      )}
      {elapsed && (
        <Paper variant="outlined" sx={{ px: 1.5, py: 0.8, borderRadius: 2 }}>
          <Typography variant="caption" color="text.secondary">{t('progress.elapsed')}</Typography>
          <Typography variant="body2" fontWeight={700}>{elapsed}</Typography>
        </Paper>
      )}
    </Stack>
  );
}
