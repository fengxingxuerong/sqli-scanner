// WAF 绕过分段（WafTamperPanel 薄封装，仅内置引擎）—— 2026-09-27 自 ScanConfigPanel 拆出
import { useTranslation } from 'react-i18next';
import { Box } from '@mui/material';
import WafTamperPanel from '../WafTamperPanel';
import type { WafSectionProps } from './sectionProps';
import SectionTitle from './SectionTitle';

export default function WafEvasionSection({ config, onChange, wafSuggestion }: WafSectionProps) {
  const { t } = useTranslation();

  return (
    <Box>
      <SectionTitle hintKey="wafEvasion">{t('scanConfig.wafEvasion')}</SectionTitle>
      <WafTamperPanel
        value={config.wafEvasion?.tamper ?? { enabled: false, plugins: [], intensity: 'medium' }}
        onChange={(t2) => onChange({ wafEvasion: { ...config.wafEvasion, tamper: t2 } })}
        suggestion={wafSuggestion}
      />
    </Box>
  );
}
