import { Box, Typography, Paper } from '@mui/material';
import { useTranslation } from 'react-i18next';

// 只读 Payload 展示组件
export default function PayloadViewer({ payloads }: { payloads: string[] }) {
  const { t } = useTranslation();
  if (!payloads || payloads.length === 0) {
    return <Typography variant="body2" color="text.secondary">{t('common.noPayload')}</Typography>;
  }
  return (
    <Box className="space-y-2">
      <Typography variant="subtitle2" fontWeight={600}>
        {t('common.payloadReadonly')}
      </Typography>
      {payloads.map((p, i) => (
        <Paper key={i} variant="outlined" className="p-2 bg-gray-50">
          <pre className="payload text-xs">{p}</pre>
        </Paper>
      ))}
    </Box>
  );
}
