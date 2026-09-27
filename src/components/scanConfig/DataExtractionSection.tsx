// 数据提取分段（enableExtract）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Alert, FormControlLabel } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function DataExtractionSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.dataExtraction')}</Typography>
      <FormControlLabel
        control={<Switch checked={config.enableExtract} onChange={handleToggle('enableExtract')} />}
        label={t('scanConfig.enableExtract')}
      />
      {config.enableExtract && (
        <Alert severity="warning" variant="outlined" className="mt-2">
          {t('scanConfig.extractWarning')}
        </Alert>
      )}
    </Box>
  );
}
