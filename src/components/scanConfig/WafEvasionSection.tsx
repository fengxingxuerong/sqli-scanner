// WAF 绕过分段（WafTamperPanel 薄封装，仅内置引擎）—— 2026-09-27 自 ScanConfigPanel 拆出
import { useTranslation } from 'react-i18next';
import { Box, Typography } from '@mui/material';
import WafTamperPanel from '../WafTamperPanel';
import type { WafSectionProps } from './sectionProps';

export default function WafEvasionSection({ config, onChange, wafSuggestion }: WafSectionProps) {
  const { t } = useTranslation();

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.wafEvasion')}</Typography>
      <WafTamperPanel
        value={config.wafEvasion?.tamper ?? { enabled: false, plugins: [], intensity: 'medium' }}
        onChange={(t2) => onChange({ wafEvasion: { ...config.wafEvasion, tamper: t2 } })}
        suggestion={wafSuggestion}
      />
    </Box>
  );
}
