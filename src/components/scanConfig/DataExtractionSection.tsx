// 数据提取分段（enableExtract）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Alert, FormControlLabel, Divider } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function DataExtractionSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle, handleIntInput } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.dataExtraction')}</Typography>
      <FormControlLabel
        control={<Switch checked={config.enableExtract} onChange={handleToggle('enableExtract')} />}
        label={t('scanConfig.enableExtract')}
      />
      {config.enableExtract && (
        <Alert severity="warning" variant="outlined" className="mt-2">
          {t('scanConfig.extractWarning')}
        </Alert>
      )}
      {/* [2026-10-03 UI-REACH] 拖库/提取治理 8 键（此前 CLI/REST 可设、面板无入口）。
          全部是「覆盖型」旋钮：留空 = 引擎内部兜底（defaults），请求体省键零行为变化。
          只在 enableExtract=true 时渲染 —— 提取没开时这些旋钮没有消费方，摆出来只会
          让人误以为「填了就会拖库」。 */}
      {config.enableExtract && (
        <Box className="mt-3">
          <Divider className="mb-2" />
          <Typography variant="caption" color="text.secondary">{t('scanConfig.dumpTuning')}</Typography>
          <Box className="grid grid-cols-2 gap-2 mt-1">
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.dumpRowLimitLabel')}</Typography>
              <input
                type="number" min={1} max={1000}
                className="w-full px-3 py-2 border rounded text-sm"
                aria-label={t('scanConfig.dumpRowLimitLabel')}
                placeholder="100"
                value={config.dumpRowLimit ?? ''}
                onChange={handleIntInput('dumpRowLimit')}
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.dumpMaxRowsLabel')}</Typography>
              <input
                type="number" min={1} max={50000}
                className="w-full px-3 py-2 border rounded text-sm"
                aria-label={t('scanConfig.dumpMaxRowsLabel')}
                placeholder="50000"
                value={config.dumpMaxRows ?? ''}
                onChange={handleIntInput('dumpMaxRows')}
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.dumpStartLabel')}</Typography>
              <input
                type="number" min={0} max={1000000}
                className="w-full px-3 py-2 border rounded text-sm"
                aria-label={t('scanConfig.dumpStartLabel')}
                placeholder="0"
                value={config.dumpStart ?? ''}
                onChange={handleIntInput('dumpStart')}
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.dumpStopLabel')}</Typography>
              <input
                type="number" min={0} max={1000000}
                className="w-full px-3 py-2 border rounded text-sm"
                aria-label={t('scanConfig.dumpStopLabel')}
                placeholder={t('scanConfig.dumpStopPh')}
                value={config.dumpStop ?? ''}
                onChange={handleIntInput('dumpStop')}
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.extractConcurrencyLabel')}</Typography>
              <input
                type="number" min={1} max={16}
                className="w-full px-3 py-2 border rounded text-sm"
                aria-label={t('scanConfig.extractConcurrencyLabel')}
                placeholder="4"
                value={config.extractConcurrency ?? ''}
                onChange={handleIntInput('extractConcurrency')}
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.dumpConcurrencyLabel')}</Typography>
              <input
                type="number" min={1} max={16}
                className="w-full px-3 py-2 border rounded text-sm"
                aria-label={t('scanConfig.dumpConcurrencyLabel')}
                placeholder="4"
                value={config.dumpConcurrency ?? ''}
                onChange={handleIntInput('dumpConcurrency')}
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.dumpDatabaseConcurrencyLabel')}</Typography>
              <input
                type="number" min={1} max={16}
                className="w-full px-3 py-2 border rounded text-sm"
                aria-label={t('scanConfig.dumpDatabaseConcurrencyLabel')}
                placeholder="2"
                value={config.dumpDatabaseConcurrency ?? ''}
                onChange={handleIntInput('dumpDatabaseConcurrency')}
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.maxColumnsGuessLabel')}</Typography>
              <input
                type="number" min={1} max={100}
                className="w-full px-3 py-2 border rounded text-sm"
                aria-label={t('scanConfig.maxColumnsGuessLabel')}
                placeholder="30"
                value={config.maxColumnsGuess ?? ''}
                onChange={handleIntInput('maxColumnsGuess')}
              />
            </Box>
          </Box>
          <Typography variant="caption" color="text.disabled">
            {t('scanConfig.dumpTuningHint')}
          </Typography>
        </Box>
      )}
    </Box>
  );
}
