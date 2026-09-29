// 请求控制分段（timeout / concurrency / retry / ratePerSec / delay / maxReq / timeThresholdMs / prefix / suffix）
// —— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Slider, Stack, FormControlLabel, Switch } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function RequestControlSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleNumber, handleText, handleToggle } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.requestControl')}</Typography>
      <Stack spacing={3}>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.timeout')}: {config.timeoutMs}</Typography>
          <Slider value={config.timeoutMs} min={1000} max={60000} step={1000} aria-label={t('scanConfig.timeout')} onChange={handleNumber('timeoutMs')} size="small" />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.concurrency')}: {config.concurrency}</Typography>
          <Slider value={config.concurrency} min={1} max={10} step={1} aria-label={t('scanConfig.concurrency')} marks onChange={handleNumber('concurrency')} size="small" />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.retry')}: {config.retry}</Typography>
          <Slider value={config.retry} min={0} max={5} step={1} aria-label={t('scanConfig.retry')} marks onChange={handleNumber('retry')} size="small" />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.ratePerSec')}: {config.ratePerSec}</Typography>
          <Slider value={config.ratePerSec} min={1} max={100} step={1} aria-label={t('scanConfig.ratePerSec')} onChange={handleNumber('ratePerSec')} size="small" />
        </Box>
        {/* [2026-09-23 UI-REACH] delay / maxReq（对标 sqlmap --delay / --max-requests）。
            delay 与上面的 ratePerSec 是**两套机制**：一个是固定间隔、一个是令牌桶平均速率 ——
            文案必须说清，否则使用者会以为是重复项。maxReq 是总请求上限（0=不限），
            靶场与大目标上的安全阀。上限 60 秒与引擎侧 MAX_DELAY_SEC 一致。 */}
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.delayLabel')}: {config.delay ?? 0} {t('scanConfig.seconds')}</Typography>
          <Slider
            value={config.delay ?? 0}
            min={0} max={60} step={1}
            aria-label={t('scanConfig.delayLabel')}
            onChange={handleNumber('delay')}
            size="small"
          />
          <Typography variant="caption" color="text.disabled">{t('scanConfig.delayHint')}</Typography>
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.maxReqLabel')}</Typography>
          <input
            type="number"
            min={0}
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            aria-label={t('scanConfig.maxReqLabel')}
            placeholder="0"
            value={config.maxReq ?? 0}
            onChange={(e) => {
              const n = Number(e.target.value);
              onChange({ maxReq: Number.isFinite(n) && n > 0 ? n : 0 });
            }}
          />
          <Typography variant="caption" color="text.disabled">{t('scanConfig.maxReqHint')}</Typography>
        </Box>
        {/* [2026-09-23 UI-REACH] timeThresholdMs：登记在 SCAN_CONFIG_KEYS 但面板从未渲染
            （契约测试当时把「登记」当「有入口」，故这条断链一直假绿）。
            它是时间盲注的真/假判据阈值 —— 目标链路慢（跨地域/CDN）时 1500ms 会误判，
            快的时候又过于宽松，属于必须能调的判定参数。 */}
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.timeThreshold')}: {config.timeThresholdMs} ms</Typography>
          <Slider
            value={config.timeThresholdMs}
            min={100} max={60000} step={100}
            aria-label={t('scanConfig.timeThreshold')}
            onChange={handleNumber('timeThresholdMs')}
            size="small"
          />
          <Typography variant="caption" color="text.disabled">
            {t('scanConfig.timeThresholdHint')}
          </Typography>
        </Box>
        {/* [2026-09-23 UI-REACH] prefix / suffix：payload 闭合控制（对标 sqlmap --prefix/--suffix）。
            同样登记在案却无控件的假暴露键。手工确认过注入点上下文、而引擎自动闭合探测
            失败时，这是唯一的补救手段（后端 clamp 上限 200 字符）。 */}
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.payloadClosure')}</Typography>
          <Box className="grid grid-cols-2 gap-2 mt-1">
            <input
              className="px-3 py-2 border rounded text-sm"
              aria-label={t('scanConfig.prefixLabel')}
              placeholder={t('scanConfig.prefixPlaceholder')}
              maxLength={200}
              value={config.prefix ?? ''}
              onChange={handleText('prefix')}
            />
            <input
              className="px-3 py-2 border rounded text-sm"
              aria-label={t('scanConfig.suffixLabel')}
              placeholder={t('scanConfig.suffixPlaceholder')}
              maxLength={200}
              value={config.suffix ?? ''}
              onChange={handleText('suffix')}
            />
          </Box>
          <Typography variant="caption" color="text.disabled">
            {t('scanConfig.payloadClosureHint')}
          </Typography>
        </Box>
        {/* [2026-09-29 UI-REACH] hpp（对标 sqlmap --hpp，引擎默认关）：注入参数 query+body
            双份提交。被 WAF 拦死的目标上这是备用代码路径/绕过形态 —— 关着 = 少一条能
            打穿的路径（登记表分类治理时定为「能力缺失类」，守卫⑧跟踪的那批键之一）。 */}
        <FormControlLabel
          control={<Switch checked={config.hpp ?? false} onChange={handleToggle('hpp')} />}
          label={t('scanConfig.hppLabel')}
        />
        <Typography variant="caption" color="text.disabled">
          {t('scanConfig.hppHint')}
        </Typography>
      </Stack>
    </Box>
  );
}
