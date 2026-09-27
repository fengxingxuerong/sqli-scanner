// 授权与安全护栏分段（productionMode / confirmDestructive）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Alert, FormControlLabel } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function SafetyGuardSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.safetyGuardTitle')}</Typography>
      {/* ── 授权与安全护栏 [2026-09-23 UI-REACH] ─────────────────────────────
          引擎默认就把目标当生产系统（defaults.js: productionMode=true），高危池
          （写文件 / RCE / 永久改配置 / DoS）必须 confirmDestructive===true 才投放。
          这两键此前没有 UI 入口，后果不是「没有护栏」而是**能力被默认值锁死**：
          界面用户无论怎么调 level/risk 都拿不到高危载荷，报告却只写「未检出」。
          与 OOB / 二阶同一形态 —— 默认关 + 无入口 = 永远测不到。 */}
      <FormControlLabel
        control={<Switch checked={config.productionMode ?? true} onChange={handleToggle('productionMode')} />}
        label={t('scanConfig.productionModeLabel')}
      />
      <Typography variant="caption" color="text.disabled" className="block mt-1">
        {t('scanConfig.productionModeHint')}
      </Typography>
      {config.productionMode === false && (
        <Alert severity="warning" variant="outlined" className="my-2">
          {t('scanConfig.productionModeOffWarning')}
        </Alert>
      )}
      <FormControlLabel
        sx={{ display: 'flex', mt: 2 }}
        control={<Switch checked={config.confirmDestructive ?? false} onChange={handleToggle('confirmDestructive')} />}
        label={t('scanConfig.confirmDestructiveLabel')}
      />
      <Typography variant="caption" color="text.disabled" className="block mt-1">
        {t('scanConfig.confirmDestructiveHint')}
      </Typography>
      {config.confirmDestructive === true && (
        <Alert severity="error" variant="outlined" className="mt-2">
          {t('scanConfig.confirmDestructiveWarning')}
        </Alert>
      )}
    </Box>
  );
}
