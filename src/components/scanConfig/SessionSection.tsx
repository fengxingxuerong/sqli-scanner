// 会话持久化分段（sessionDefault / sessionFile）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
// [2026-09-29 UI-REACH] 新增 CSRF 会话层与会话保活两组控件（能力缺失类 8 键中的 6 个：
// 默认关/空 ⇒ CSRF 目标的 POST 注入面全灭 / 长扫描被踢会话 ⇒ 假阴性，详见 types.ts 注释）
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

        {/* [2026-09-29 UI-REACH] CSRF 会话层。子字段（token 名/方法/刷新频率）只在 csrfUrl
            填了之后才有意义 —— 未填时置灰，避免「配了一堆孤儿参数」的错觉。
            后端口径：csrfMethod 只认 GET/POST；csrfRefreshFreq 取 1-10000；
            csrfUrl 非 http(s) 或越出授权范围（scope）会被静默丢弃（logger.warn）。 */}
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.csrfUrlLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder="http://target/login"
            aria-label={t('scanConfig.csrfUrlLabel')}
            value={config.csrfUrl ?? ''}
            onChange={handleText('csrfUrl')}
          />
          <Typography variant="caption" color="text.disabled">{t('scanConfig.csrfHint')}</Typography>
        </Box>
        <Box className={`grid grid-cols-3 gap-2 ${config.csrfUrl ? '' : 'opacity-60'}`}>
          <Box>
            <Typography variant="caption" color="text.secondary">{t('scanConfig.csrfTokenNameLabel')}</Typography>
            <input
              className="mt-1 w-full px-3 py-2 border rounded text-sm"
              placeholder="csrf_token"
              aria-label={t('scanConfig.csrfTokenNameLabel')}
              disabled={!config.csrfUrl}
              value={config.csrfTokenName ?? ''}
              onChange={handleText('csrfTokenName')}
            />
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">{t('scanConfig.csrfMethodLabel')}</Typography>
            <select
              className="mt-1 w-full px-3 py-2 border rounded text-sm"
              aria-label={t('scanConfig.csrfMethodLabel')}
              disabled={!config.csrfUrl}
              value={config.csrfMethod ?? 'GET'}
              onChange={(e) => onChange({ csrfMethod: e.target.value })}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">{t('scanConfig.csrfFreqLabel')}</Typography>
            <input
              className="mt-1 w-full px-3 py-2 border rounded text-sm"
              type="number"
              min={1}
              placeholder="50"
              aria-label={t('scanConfig.csrfFreqLabel')}
              disabled={!config.csrfUrl}
              value={config.csrfRefreshFreq ?? ''}
              onChange={(e) => {
                const n = Number(e.target.value);
                onChange({ csrfRefreshFreq: Number.isFinite(n) && n >= 1 ? Math.floor(n) : undefined });
              }}
            />
          </Box>
        </Box>

        {/* [2026-09-29 UI-REACH] 会话保活（对标 --safe-url/--safe-freq）。safeFreq 依赖
            safeUrl（后端只在 safeUrl 合法时才读 safeFreq），故未填 safeUrl 时置灰。 */}
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.safeUrlLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder="http://target/health"
            aria-label={t('scanConfig.safeUrlLabel')}
            value={config.safeUrl ?? ''}
            onChange={handleText('safeUrl')}
          />
          <Typography variant="caption" color="text.disabled">{t('scanConfig.safeUrlHint')}</Typography>
        </Box>
        <Box className={config.safeUrl ? '' : 'opacity-60'}>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.safeFreqLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            type="number"
            min={1}
            placeholder="100"
            aria-label={t('scanConfig.safeFreqLabel')}
            disabled={!config.safeUrl}
            value={config.safeFreq ?? ''}
            onChange={(e) => {
              const n = Number(e.target.value);
              onChange({ safeFreq: Number.isFinite(n) && n >= 1 ? Math.floor(n) : undefined });
            }}
          />
          <Typography variant="caption" color="text.disabled">{t('scanConfig.safeFreqHint')}</Typography>
        </Box>
      </Stack>
    </Box>
  );
}
