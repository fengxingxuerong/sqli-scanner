// PhaseAlert -- current phase indicator alert

import { Alert, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';

export interface PhaseAlertProps {
  running: boolean;
  currentPhase: string | null;
  pct: number | null;
}

export default function PhaseAlert({ running, currentPhase, pct }: PhaseAlertProps) {
  const { t } = useTranslation();
  return (
    <>
      {running && currentPhase && (
        <Alert severity="info" variant="outlined" sx={{ py: 0.5, '& .MuiAlert-message': { fontSize: 14 } }}>
          {currentPhase}
        </Alert>
      )}
      {running && pct == null && currentPhase && (
        <Typography variant="caption" color="text.secondary">
          {t('progress.phasePreparing')}
        </Typography>
      )}
    </>
  );
}
