// 二阶注入分段（仅内置引擎）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import {
  Box, Typography, Switch, Select, MenuItem, FormControl, InputLabel, Stack, Alert, FormControlLabel,
} from '@mui/material';
import { parseScopeList } from '../../shared/scanConfig';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function SecondOrderSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { patchNested } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.secondOrderTitle')}</Typography>
      {/* ── 二阶注入 [2026-09-23 UI-REACH] ─────────────
          开启即代表将对目标发起**真实写请求**，故警示与写确认位（allowWrites）
          都必须在界面上给出来：生产护栏（productionMode）一开，非幂等请求没有
          allowWrites 一律不放行 —— 只给 enabled 不给 allowWrites，
          用户会得到「开了二阶却永远未检出」这种最难查的假阴性。 */}
      <FormControlLabel
        control={<Switch checked={config.secondOrder?.enabled ?? false} onChange={(e) => patchNested('secondOrder', 'enabled', e.target.checked)} />}
        label={t('scanConfig.secondOrderEnable')}
      />
      <Typography variant="caption" color="text.disabled" className="block mt-1">
        {t('scanConfig.secondOrderHint')}
      </Typography>
      {config.secondOrder?.enabled && (
        <>
          <Alert severity="warning" variant="outlined" className="my-2">
            {t('scanConfig.secondOrderWarning')}
          </Alert>
          <Stack spacing={2}>
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.secondOrderTriggerUrls')}</Typography>
              <textarea
                className="mt-1 w-full px-3 py-2 border rounded text-sm"
                rows={2}
                aria-label={t('scanConfig.secondOrderTriggerUrls')}
                placeholder="https://target.example.com/profile"
                value={(config.secondOrder?.triggerUrls ?? []).join('\n')}
                onChange={(e) => {
                  const list = parseScopeList(e.target.value);
                  patchNested('secondOrder', 'triggerUrls', list.length ? list : undefined);
                }}
              />
              <Typography variant="caption" color="text.disabled">{t('scanConfig.secondOrderTriggerUrlsHint')}</Typography>
            </Box>
            <FormControlLabel
              control={<Switch size="small" checked={config.secondOrder?.allowWrites ?? false} onChange={(e) => patchNested('secondOrder', 'allowWrites', e.target.checked)} />}
              label={t('scanConfig.secondOrderAllowWrites')}
            />
            <Typography variant="caption" color="text.disabled">
              {t('scanConfig.secondOrderAllowWritesHint')}
            </Typography>
            <FormControlLabel
              control={<Switch size="small" checked={config.secondOrder?.negativeControl ?? true} onChange={(e) => patchNested('secondOrder', 'negativeControl', e.target.checked)} />}
              label={t('scanConfig.secondOrderNegativeControl')}
            />
            <FormControlLabel
              control={<Switch size="small" checked={config.secondOrder?.oobTrigger ?? false} onChange={(e) => patchNested('secondOrder', 'oobTrigger', e.target.checked)} />}
              label={t('scanConfig.secondOrderOobTrigger')}
            />
            <Typography variant="caption" color="text.disabled">
              {t('scanConfig.secondOrderOobTriggerHint')}
            </Typography>
            {/* [2026-09-23 UI-REACH] 读写分离：读取阶段的请求发往独立 URL。
                引擎一直在读这三个字段，但此前 CLI/REST/UI 三条路径都到不了它们。
                secondUrl 与触发页同级风险（会带会话 Cookie 发请求），后端对其
                单独做 SSRF + 授权范围校验，不通过则回退触发页。 */}
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.secondOrderSecondUrl')}</Typography>
              <input
                className="mt-1 w-full px-3 py-2 border rounded text-sm"
                aria-label={t('scanConfig.secondOrderSecondUrl')}
                placeholder={t('scanConfig.secondOrderSecondUrlPlaceholder')}
                value={config.secondOrder?.secondUrl ?? ''}
                onChange={(e) => patchNested('secondOrder', 'secondUrl', e.target.value.trim() || undefined)}
              />
              <Typography variant="caption" color="text.disabled">
                {t('scanConfig.secondOrderSecondUrlHint')}
              </Typography>
            </Box>
            <FormControl size="small" fullWidth>
              <InputLabel>{t('scanConfig.secondOrderSecondMethod')}</InputLabel>
              <Select
                value={config.secondOrder?.secondMethod ?? 'GET'}
                label={t('scanConfig.secondOrderSecondMethod')}
                onChange={(e) => patchNested('secondOrder', 'secondMethod', e.target.value)}
              >
                {['GET', 'POST', 'HEAD'].map((m2) => (
                  <MenuItem key={m2} value={m2}>{m2}</MenuItem>
                ))}
              </Select>
              <Typography variant="caption" color="text.disabled">
                {t('scanConfig.secondOrderSecondMethodHint')}
              </Typography>
            </FormControl>
          </Stack>
        </>
      )}
    </Box>
  );
}
