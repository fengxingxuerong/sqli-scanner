// 注入点范围分段（testPath / testHeaders）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Stack, FormControlLabel } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function InjectionScopeSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.injectionScope')}</Typography>
      {/* [2026-09-23] 这两键此前「引擎已消费 / REST 白名单已收 / UI 无入口」：
          能力在，用户拿不到。默认关（与 TargetParser 默认一致）。 */}
      <Stack spacing={2}>
        <FormControlLabel
          control={<Switch checked={config.testPath ?? false} onChange={handleToggle('testPath')} />}
          label={t('scanConfig.testPathLabel')}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.testPathHint')}
        </Typography>
        <FormControlLabel
          control={<Switch checked={config.testHeaders ?? false} onChange={handleToggle('testHeaders')} />}
          label={t('scanConfig.testHeadersLabel')}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.testHeadersHint')}
        </Typography>
      </Stack>
    </Box>
  );
}
