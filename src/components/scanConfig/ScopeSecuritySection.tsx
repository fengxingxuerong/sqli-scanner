// 授权范围与传输安全分段（scope / insecureTls / clientCert / validationSkip，仅内置引擎）
// —— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Stack, Alert, FormControlLabel } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function ScopeSecuritySection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle, handleScopeChange, handleText } = createScanConfigActions(config, onChange);

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
        {/* ── [2026-10-01] mTLS 客户端证书（对标 sqlmap --cert）───────────────────
            与 insecureTls 同段但语义正交：insecureTls 管「我信不信目标证书」，
            clientCert 管「目标信不信我」。目标要求双向认证时没有证书连第一跳都被拒，
            检测阶段之前就已出局 —— 属能力缺失而非便利开关，故给入口。 */}
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.clientCertLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.clientCertPlaceholder')}
            aria-label={t('scanConfig.clientCertLabel')}
            value={config.clientCert ?? ''}
            onChange={handleText('clientCert')}
          />
          <Typography variant="caption" color="text.disabled">
            {t('scanConfig.clientCertHint')}
          </Typography>
        </Box>
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
