// payload 与响应判定调优分段（仅内置引擎）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import {
  Box, Typography, Switch, Select, MenuItem, FormControl, InputLabel, Stack, Alert,
  Divider, FormControlLabel,
} from '@mui/material';
import { BUILTIN_DBMS_OPTIONS } from '../../shared/constants';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function PayloadTuningSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle, handleText, setMatchCode } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.payloadTuning')}</Typography>
      {/* ── payload 与响应判定调优（[P0-FIX 2026-09-09] 后端已支持、UI 补接的开关）──
          这些键以前在面板上根本不存在（或只写 store 不进 startScan），后果分两种：
          · 预筛/静态跳过的预算控制勾不到 → 对大目标多发几倍无用请求；
          · matchString/notString 无入口 → 强动态页面的布尔盲注只能靠相似度比对，误报/漏报无法人工锺定。 */}
      <Stack spacing={2}>
        <FormControlLabel
          control={<Switch checked={config.prefilter !== false} onChange={handleToggle('prefilter')} />}
          label={t('scanConfig.prefilterLabel')}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.prefilterHint')}
        </Typography>
        <FormControlLabel
          control={<Switch checked={config.prefilterSinglePoint ?? false} onChange={handleToggle('prefilterSinglePoint')} />}
          label={t('scanConfig.prefilterSingleLabel')}
        />
        <FormControlLabel
          control={<Switch checked={config.skipStatic ?? false} onChange={handleToggle('skipStatic')} />}
          label={t('scanConfig.skipStaticLabel')}
        />

        <Divider />

        <FormControlLabel
          control={<Switch checked={config.useRegistry ?? false} onChange={handleToggle('useRegistry')} />}
          label={t('scanConfig.useRegistryLabel')}
        />
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.testFilterLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.testFilterPlaceholder')}
            aria-label={t('scanConfig.testFilterLabel')}
            value={config.testFilter ?? ''}
            onChange={handleText('testFilter')}
          />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.testSkipLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.testSkipPlaceholder')}
            aria-label={t('scanConfig.testSkipLabel')}
            value={config.testSkip ?? ''}
            onChange={handleText('testSkip')}
          />
        </Box>
        {!config.useRegistry && (
          <Alert severity="info" variant="outlined">
            {t('scanConfig.useRegistryGate')}
          </Alert>
        )}

        <Divider />

        <FormControl size="small" fullWidth>
          <InputLabel>{t('scanConfig.dbmsLabel')}</InputLabel>
          <Select
            value={config.dbms ?? ''}
            label={t('scanConfig.dbmsLabel')}
            onChange={(e) => onChange({ dbms: e.target.value || null })}
          >
            <MenuItem value="">{t('scanConfig.dbmsAuto')}</MenuItem>
            {BUILTIN_DBMS_OPTIONS.map((o) => (
              <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
            ))}
          </Select>
          <Typography variant="caption" color="text.disabled">
            {t('scanConfig.dbmsHint')}
          </Typography>
        </FormControl>

        <Divider />

        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.matchStringLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.matchStringPlaceholder')}
            aria-label={t('scanConfig.matchStringLabel')}
            value={config.matchString ?? ''}
            onChange={handleText('matchString')}
          />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.notStringLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.notStringPlaceholder')}
            aria-label={t('scanConfig.notStringLabel')}
            value={config.notString ?? ''}
            onChange={handleText('notString')}
          />
        </Box>
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.anchorHint')}
        </Typography>

        {/* [2026-09-26 UI-REACH] 判定锚点族的其余成员（对标 --titles / --code / --regexp）。
            引擎 Detector._matchByTitle/_matchByCode/_matchByRegexp 一直在消费、
            REST 白名单也收，唯独前端没有控件 —— 强动态页面上「真假响应只差状态码」
            或「只差一个正则片段」时，用户拿不到任何手段告诉引擎判据是什么，
            于是判不出来就落「未检出」。这是能力缺失，不是便利开关。 */}
        <Divider />
        <FormControlLabel
          control={<Switch checked={config.matchTitle ?? false} onChange={handleToggle('matchTitle')} />}
          label={t('scanConfig.matchTitleLabel')}
        />
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.matchCodeLabel')}</Typography>
          <Stack direction="row" spacing={1} className="mt-1">
            <input
              className="w-full px-3 py-2 border rounded text-sm"
              type="number"
              min={100}
              max={599}
              placeholder={t('scanConfig.matchCodeTruePlaceholder')}
              aria-label={t('scanConfig.matchCodeTruePlaceholder')}
              value={config.matchCode?.true ?? ''}
              onChange={(e) => setMatchCode('true', e.target.value)}
            />
            <input
              className="w-full px-3 py-2 border rounded text-sm"
              type="number"
              min={100}
              max={599}
              placeholder={t('scanConfig.matchCodeFalsePlaceholder')}
              aria-label={t('scanConfig.matchCodeFalsePlaceholder')}
              value={config.matchCode?.false ?? ''}
              onChange={(e) => setMatchCode('false', e.target.value)}
            />
          </Stack>
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.matchRegexpLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.matchRegexpPlaceholder')}
            aria-label={t('scanConfig.matchRegexpLabel')}
            value={config.matchRegexp ?? ''}
            onChange={handleText('matchRegexp')}
          />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.trueRegexpLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.trueRegexpPlaceholder')}
            aria-label={t('scanConfig.trueRegexpLabel')}
            value={config.trueRegexp ?? ''}
            onChange={handleText('trueRegexp')}
          />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.falseRegexpLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.falseRegexpPlaceholder')}
            aria-label={t('scanConfig.falseRegexpLabel')}
            value={config.falseRegexp ?? ''}
            onChange={handleText('falseRegexp')}
          />
        </Box>
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.anchorFamilyHint')}
        </Typography>
      </Stack>
    </Box>
  );
}
