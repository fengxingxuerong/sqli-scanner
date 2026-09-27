// 会话持久化分段（sessionDefault / sessionFile）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Stack, FormControlLabel } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function SessionSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle, handleText } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.sessionPersistence')}</Typography>
      <Stack spacing={2}>
        <FormControlLabel
          control={<Switch checked={config.sessionDefault ?? false} onChange={handleToggle('sessionDefault')} />}
          label={t('scanConfig.enableResume')}
        />
        {/* [2026-09-23 UI-REACH] sessionFile：显式指定会话文件名（登记在案却无控件的假暴露键）。
            后端 isSafeSessionPath 只收「工作目录下的文件名」或系统临时目录内路径，
            绝对路径与 .. 逃逸一律拒绝 —— 提示里要写清，否则用户填绝对路径会拿到 400。 */}
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.sessionFileLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            aria-label={t('scanConfig.sessionFileLabel')}
            placeholder="sqli-session.json"
            value={config.sessionFile ?? ''}
            onChange={handleText('sessionFile')}
          />
          <Typography variant="caption" color="text.disabled">{t('scanConfig.sessionFileHint')}</Typography>
        </Box>
      </Stack>
    </Box>
  );
}
