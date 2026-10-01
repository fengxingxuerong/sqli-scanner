// 高级注入面分段（noCast / hex / flushSession / unionFrom / unionCols / paramDel / dumpWhere）
// —— 2026-10-01 UI-REACH §1.3：CLI 能用、引擎真读、REST 白名单已收的 7 键接进内置引擎面板。
// 此前这批键只有 SqlmapOptions（/sqlmap/start 桥接模式）有控件，内置引擎用户拿不到。
// 关闭态语义：布尔关 = 发 false（引擎 `=== true` 严格判定，false 即关）；
// 字符串留空 = 整个省键（与 handleText 既有口径一致，引擎走 falsy 兜底）。
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Stack, FormControlLabel, TextField } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function AdvancedInjectionSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle, handleText } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.advancedInjection')}</Typography>
      <Stack spacing={2}>
        {/* ── 三个严格布尔位（引擎 `config.x === true` 判定，false 也如实发送）── */}
        <FormControlLabel
          control={<Switch checked={config.noCast ?? false} onChange={handleToggle('noCast')} />}
          label={t('scanConfig.noCastLabel')}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.noCastHint')}
        </Typography>
        <FormControlLabel
          control={<Switch checked={config.hex ?? false} onChange={handleToggle('hex')} />}
          label={t('scanConfig.hexLabel')}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.hexHint')}
        </Typography>
        <FormControlLabel
          control={<Switch checked={config.flushSession ?? false} onChange={handleToggle('flushSession')} />}
          label={t('scanConfig.flushSessionLabel')}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.flushSessionHint')}
        </Typography>
        {/* ── 四个字符串旋钮（留空 = 关闭态，请求体省键）── */}
        <TextField
          size="small"
          label={t('scanConfig.unionFromLabel')}
          value={config.unionFrom ?? ''}
          onChange={handleText('unionFrom')}
          inputProps={{ 'aria-label': t('scanConfig.unionFromLabel') }}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.unionFromHint')}
        </Typography>
        <TextField
          size="small"
          label={t('scanConfig.unionColsLabel')}
          value={config.unionCols ?? ''}
          onChange={handleText('unionCols')}
          inputProps={{ 'aria-label': t('scanConfig.unionColsLabel') }}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.unionColsHint')}
        </Typography>
        <TextField
          size="small"
          label={t('scanConfig.paramDelLabel')}
          value={config.paramDel ?? ''}
          onChange={handleText('paramDel')}
          inputProps={{ 'aria-label': t('scanConfig.paramDelLabel') }}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.paramDelHint')}
        </Typography>
        <TextField
          size="small"
          label={t('scanConfig.dumpWhereLabel')}
          value={config.dumpWhere ?? ''}
          onChange={handleText('dumpWhere')}
          inputProps={{ 'aria-label': t('scanConfig.dumpWhereLabel') }}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.dumpWhereHint')}
        </Typography>
      </Stack>
    </Box>
  );
}
