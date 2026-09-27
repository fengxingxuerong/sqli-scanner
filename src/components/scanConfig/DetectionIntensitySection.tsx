// 检测强度分段（level / risk / techniques）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Slider, Select, MenuItem, FormControl, InputLabel, Stack, Chip } from '@mui/material';
import type { TechniqueType } from '../../shared/types';
import { TECHNIQUES } from '../../shared/constants';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

export default function DetectionIntensitySection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleNumber } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.detectionIntensity')}</Typography>
      <Stack spacing={3}>
        <Box>
          <Typography variant="caption" color="text.secondary" gutterBottom>
            {t('scanConfig.levelLabel')} (Level): {config.level ?? 1}
          </Typography>
          <Slider
            value={config.level ?? 1}
            min={1} max={5} step={1}
            aria-label={t('scanConfig.levelLabel')}
            marks={[
              { value: 1, label: '1' },
              { value: 2, label: '2' },
              { value: 3, label: '3' },
              { value: 4, label: '4' },
              { value: 5, label: '5' },
            ]}
            onChange={handleNumber('level')}
            size="small"
          />
          <Typography variant="caption" color="text.disabled">
            {t('scanConfig.levelHint')}
          </Typography>
        </Box>

        <Box>
          <Typography variant="caption" color="text.secondary" gutterBottom>
            {t('scanConfig.riskLabel')} (Risk): {config.risk ?? 2}
          </Typography>
          <Slider
            value={config.risk ?? 2}
            min={1} max={3} step={1}
            aria-label={t('scanConfig.riskLabel')}
            marks={[
              { value: 1, label: t('scanConfig.riskLow') },
              { value: 2, label: t('scanConfig.riskMid') },
              { value: 3, label: t('scanConfig.riskHigh') },
            ]}
            onChange={handleNumber('risk')}
            size="small"
          />
          <Typography variant="caption" color="text.disabled">
            {t('scanConfig.riskHint')}
          </Typography>
        </Box>

        <FormControl size="small" fullWidth>
          <InputLabel>{t('scanConfig.techniques')}</InputLabel>
          <Select
            multiple
            value={config.techniques ?? TECHNIQUES}
            label={t('scanConfig.techniques')}
            onChange={(e) => onChange({ techniques: e.target.value as TechniqueType[] })}
            renderValue={(selected) => (
              <Box className="flex gap-1 flex-wrap">
                {(selected as string[]).map((tech) => (
                  <Chip key={tech} label={t(`technique.${tech}`)} size="small" />
                ))}
              </Box>
            )}
          >
            {TECHNIQUES.map((tech) => (
              <MenuItem key={tech} value={tech}>
                {t(`technique.${tech}`)}
              </MenuItem>
            ))}
          </Select>
          <Typography variant="caption" color="text.disabled">
            {t('scanConfig.techniquesHint')}
          </Typography>
        </FormControl>
      </Stack>
    </Box>
  );
}
