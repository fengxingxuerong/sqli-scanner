// 授权范围与传输安全分段（scope / insecureTls / validationSkip，仅内置引擎）
// —— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Stack, Alert, FormControlLabel } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function ScopeSecuritySection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle, handleScopeChange } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.scopeSecurity')}</Typography>
      {/* ── 授权范围与传输安全（[P0-SEC] scope 硬约束 + insecureTls；仅内置引擎透传）── */}
      <Stack spacing={2}>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.scopeLabel')}</Typography>
          <textarea
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            style={{ minHeight: 56, resize: 'vertical' }}
            placeholder={t('scanConfig.scopePlaceholder')}
            aria-label={t('scanConfig.scopeLabel')}
            value={(config.scope ?? []).join('\n')}
            onChange={(e) => handleScopeChange(e.target.value)}
          />
          <Typography variant="caption" color="text.disabled">
            {t('scanConfig.scopeHint')}
          </Typography>
        </Box>
        <FormControlLabel
          control={<Switch checked={config.insecureTls ?? false} onChange={handleToggle('insecureTls')} />}
          label={t('scanConfig.insecureTlsLabel')}
        />
        {config.insecureTls && (
          <Alert severity="warning" variant="outlined">
            {t('scanConfig.insecureTlsWarning')}
          </Alert>
        )}
        <FormControlLabel
          control={<Switch checked={config.validationSkip !== false} onChange={handleToggle('validationSkip')} />}
          label={t('scanConfig.validationSkipLabel')}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.validationSkipHint')}
        </Typography>
      </Stack>
    </Box>
  );
}
