// ReportVerdictHint —— 报告判读速览（D85 小白引导体系）
// 常驻报告摘要区上方：标题旁的「?」点开是「未检出 ≠ 没洞」等判读要点
// （完整三张判读表在帮助中心「结果判读」Tab，此处只做入口级提醒）。

import { useTranslation } from 'react-i18next';
import { Stack, Typography } from '@mui/material';
import InfoHint from './InfoHint';

export default function ReportVerdictHint() {
  const { t } = useTranslation();
  return (
    <Stack direction="row" alignItems="center" className="mb-2">
      <Typography variant="subtitle2" color="text.secondary">{t('report.title')}</Typography>
      <InfoHint rich title={t('help.tabVerdict')} text={t('help.verdictCaveat')} />
    </Stack>
  );
}
