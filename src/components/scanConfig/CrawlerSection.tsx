// 爬虫分段（crawlDepth / crawlForms，仅内置引擎）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Slider, FormControlLabel } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function CrawlerSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle, handleNumber } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.crawler')}</Typography>
      <FormControlLabel
        control={<Switch checked={(config.crawlDepth ?? 0) > 0} onChange={(e) => onChange({ crawlDepth: e.target.checked ? 2 : 0 })} />}
        label={t('scanConfig.enableCrawler')}
      />
      {(config.crawlDepth ?? 0) > 0 && (
        <Box className="mt-2">
          <Typography variant="caption" color="text.secondary">{t('scanConfig.crawlDepth')}: {config.crawlDepth}</Typography>
          <Slider value={config.crawlDepth ?? 2} min={1} max={3} step={1} aria-label={t('scanConfig.crawlDepth')} marks onChange={handleNumber('crawlDepth')} size="small" />
        </Box>
      )}
      {/* [2026-09-26 UI-REACH] crawlForms（对标 --forms）：引擎 TargetParser._crawlForms
          一直在读，但前端此前无控件 → 默认 false 意味着**页面表单一个都不测**，
          而报告只会写「未检出」（少测一整类注入面，不是便利性差异）。
          关着爬虫时该开关无意义 → 置灰，避免「填了也不生效」的假暴露。 */}
      <Box className="mt-2">
        <FormControlLabel
          control={
            <Switch
              checked={config.crawlForms ?? false}
              disabled={(config.crawlDepth ?? 0) <= 0}
              onChange={handleToggle('crawlForms')}
            />
          }
          label={t('scanConfig.crawlFormsLabel')}
        />
        <Typography variant="caption" color="text.disabled" className="block">
          {t('scanConfig.crawlFormsHint')}
        </Typography>
      </Box>
      {/* [2026-10-02 实战 P1-4] crawlBrowser（headless 浏览器爬取）：SPA 目标的 XHR 接口
          发现。不依赖爬虫开关（depth=0 也渲染入口页），故不置灰；需 playwright +
          系统浏览器（msedge/chrome），引擎不可用时自动降级 HTTP 爬虫。 */}
      <Box className="mt-2">
        <FormControlLabel
          control={
            <Switch checked={config.crawlBrowser ?? false} onChange={handleToggle('crawlBrowser')} />
          }
          label={t('scanConfig.crawlBrowserLabel')}
        />
        <Typography variant="caption" color="text.disabled" className="block">
          {t('scanConfig.crawlBrowserHint')}
        </Typography>
      </Box>
      {/* [2026-10-02 竞品吸收] paramMine（对标 Arjun 参数发现）：挖掘不依赖爬虫（直接探目标
          URL），故不置灰。会向目标发送额外探测请求（预算硬顶），因此默认关。 */}
      <Box className="mt-2">
        <FormControlLabel
          control={
            <Switch checked={config.paramMine ?? false} onChange={handleToggle('paramMine')} />
          }
          label={t('scanConfig.paramMineLabel')}
        />
        <Typography variant="caption" color="text.disabled" className="block">
          {t('scanConfig.paramMineHint')}
        </Typography>
      </Box>
    </Box>
  );
}
