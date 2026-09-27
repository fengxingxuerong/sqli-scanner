// 枚举与拖库分段（extractScope）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Select, MenuItem, FormControl, InputLabel, Stack, Alert, FormControlLabel } from '@mui/material';
import type { ExtractScopeMode } from '../../shared/types';
import { EXTRACT_SCOPE_OPTIONS } from '../../shared/constants';
import type { ExtractScopeField } from '../../shared/constants';
import { parseScopeList } from '../../shared/scanConfig';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

/** 枚举动作的输入项（顺序 = UI 展示顺序）。哪些项与当前动作相关由 EXTRACT_SCOPE_OPTIONS.needs 决定。 */
const SCOPE_FIELDS: { key: ExtractScopeField; label: string }[] = [
  { key: 'dbs', label: 'scanConfig.extractScopeDbs' },
  { key: 'tables', label: 'scanConfig.extractScopeTables' },
  { key: 'cols', label: 'scanConfig.extractScopeCols' },
  { key: 'keyword', label: 'scanConfig.extractScopeKeyword' },
];

/** 该动作会用到哪些输入项 —— 用不到的置灰禁用，避免「填了但选了不看它的动作」这种白填。 */
function scopeFieldsFor(mode: ExtractScopeMode): ExtractScopeField[] {
  return EXTRACT_SCOPE_OPTIONS.find((o) => o.value === mode)?.needs ?? [];
}

export default function EnumerationSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { setScopeField } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.enumeration')}</Typography>
      {/* ── 枚举与拖库 [2026-09-23 E2] ──
          这条链此前断在两处：引擎能跑（engine/extractScope.js）、CLI 能用
          （bin/cli/config.js:314），但 REST 白名单没收该键（传了静默丢弃）、UI 无入口
          → Web / 桌面 / API 三端实际拿不到枚举与拖库能力。 */}
      <Stack spacing={2}>
        <FormControl size="small" fullWidth>
          <InputLabel>{t('scanConfig.extractScopeLabel')}</InputLabel>
          <Select
            value={config.extractScope?.mode ?? ''}
            label={t('scanConfig.extractScopeLabel')}
            onChange={(e) => {
              const v = e.target.value as ExtractScopeMode | '';
              // 留空 = 不启用：整键发 undefined（与其它开关「关闭态干净」口径一致）
              onChange({ extractScope: v === '' ? undefined : { ...(config.extractScope ?? {}), mode: v } });
            }}
          >
            <MenuItem value="">{t('scanConfig.extractScopeNone')}</MenuItem>
            {EXTRACT_SCOPE_OPTIONS.map((o) => (
              <MenuItem key={o.value} value={o.value}>{t(`scanConfig.extractScopes.${o.value}`)}</MenuItem>
            ))}
          </Select>
        </FormControl>

        {config.extractScope && (
          <>
            <Typography variant="caption" color="text.disabled">
              {t('scanConfig.extractScopeHint')}
            </Typography>
            {SCOPE_FIELDS.map((f) => {
              const need = scopeFieldsFor(config.extractScope!.mode).includes(f.key);
              return (
                <Box key={f.key} sx={{ opacity: need ? 1 : 0.45 }}>
                  <Typography variant="caption" color="text.secondary">{t(f.label)}</Typography>
                  <input
                    className="mt-1 w-full px-3 py-2 border rounded text-sm"
                    aria-label={t(f.label)}
                    disabled={!need}
                    value={(f.key === 'keyword'
                      ? (config.extractScope!.keyword ?? '')
                      : ((config.extractScope![f.key as 'dbs' | 'tables' | 'cols'] ?? []) as string[]).join(', '))}
                    onChange={(e) => {
                      const raw = e.target.value;
                      if (f.key === 'keyword') {
                        setScopeField('keyword', raw.trim() || undefined);
                      } else {
                        const list = parseScopeList(raw);
                        setScopeField(f.key, list.length ? list : undefined);
                      }
                    }}
                  />
                </Box>
              );
            })}
            <FormControlLabel
              control={
                <Switch
                  checked={config.extractScope.excludeSysdbs !== false}
                  onChange={(e) => setScopeField('excludeSysdbs', e.target.checked)}
                />
              }
              label={t('scanConfig.extractScopeExcludeSys')}
            />
            <Alert severity="warning" variant="outlined">
              {t('scanConfig.extractWarning')}
            </Alert>
          </>
        )}
      </Stack>
    </Box>
  );
}
