// LogActions -- copy / download log buttons + event count + error alert

import { Box, Button, Typography, Alert } from '@mui/material';
import { useTranslation } from 'react-i18next';

export interface LogActionsProps {
  eventsLength: number;
  onCopyLogs: () => void;
  onDownloadLogs: () => void;
  downloadError: string;
}

export default function LogActions({ eventsLength, onCopyLogs, onDownloadLogs, downloadError }: LogActionsProps) {
  const { t } = useTranslation();
  return (
    <>
      <Box className="flex items-center gap-2">
        <Button size="small" variant="outlined" disabled={!eventsLength} onClick={onCopyLogs}>
          {t('scan.copyLogs')}
        </Button>
        <Button size="small" variant="outlined" disabled={!eventsLength} onClick={onDownloadLogs}>
          {t('scan.downloadLogs')}
        </Button>
        <Typography variant="caption" color="text.secondary">{t('scan.eventsCount', { count: eventsLength })}</Typography>
      </Box>
      {downloadError && <Alert severity="error" variant="outlined">{downloadError}</Alert>}
    </>
  );
}
