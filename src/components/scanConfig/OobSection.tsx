// 带外通道（OOB）分段（仅内置引擎）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Stack, Alert, FormControlLabel } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function OobSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { patchNested } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.oobTitle')}</Typography>
      {/* ── 带外通道（OOB）[2026-09-23 UI-REACH] ─────────────
          enabled 是**总开关**：techniques 里勾了 oob 还不够，接收端必须在此开启才会启动。
          这条通道在「无回显 + WAF 拦 sleep/报错/union」的场景里是唯一可达的一条
          （e2e/oob-real-lab 真 PG 16.2 实测），此前 UI 完全拿不到。 */}
      <FormControlLabel
        control={<Switch checked={config.oob?.enabled ?? false} onChange={(e) => patchNested('oob', 'enabled', e.target.checked)} />}
        label={t('scanConfig.oobEnable')}
      />
      <Typography variant="caption" color="text.disabled" className="block mt-1">
        {t('scanConfig.oobHint')}
      </Typography>
      {config.oob?.enabled && (
        <>
          <Alert severity="info" variant="outlined" className="my-2">
            {t('scanConfig.oobWarning')}
          </Alert>
          <Stack spacing={2}>
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.oobCallbackBase')}</Typography>
              <input
                className="mt-1 w-full px-3 py-2 border rounded text-sm"
                aria-label={t('scanConfig.oobCallbackBase')}
                placeholder="127.0.0.1:8899"
                value={config.oob?.callbackBase ?? ''}
                onChange={(e) => patchNested('oob', 'callbackBase', e.target.value.trim() || undefined)}
              />
              <Typography variant="caption" color="text.disabled">{t('scanConfig.oobCallbackBaseHint')}</Typography>
            </Box>
            <FormControlLabel
              control={<Switch size="small" checked={config.oob?.dnsOob ?? false} onChange={(e) => patchNested('oob', 'dnsOob', e.target.checked)} />}
              label={t('scanConfig.oobDnsEnable')}
            />
            {config.oob?.dnsOob && (
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.oobDnsDomain')}</Typography>
                <input
                  className="mt-1 w-full px-3 py-2 border rounded text-sm"
                  aria-label={t('scanConfig.oobDnsDomain')}
                  placeholder="oob.example.com"
                  value={config.oob?.dnsDomain ?? ''}
                  onChange={(e) => patchNested('oob', 'dnsDomain', e.target.value.trim() || undefined)}
                />
                <Typography variant="caption" color="text.disabled">{t('scanConfig.oobDnsHint')}</Typography>
              </Box>
            )}
          </Stack>
        </>
      )}
    </Box>
  );
}
