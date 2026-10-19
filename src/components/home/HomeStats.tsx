// ============================================================================
// HomeStats —— 首页统计卡组（D107 桌面端 UI 全面优化）
//
// 四个数回答四个问题：扫过多少次 / 一共挖出多少洞 / 其中多少是高危 / 覆盖多少目标。
// 每张卡附一句「怎么算的」——统计口径不写出来的话，用户看到数字只会猜。
// ============================================================================
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Grid } from '@mui/material';
import HistoryIcon from '@mui/icons-material/History';
import BugReportIcon from '@mui/icons-material/BugReport';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import TravelExploreIcon from '@mui/icons-material/TravelExplore';
import CyberStat from '../cyber/CyberStat';
import type { CyberStatTone } from '../cyber/CyberStat';
import type { HistoryRecord } from '../../shared/types';

interface StatDef {
  label: string;
  hint: string;
  icon: ReactNode;
  tone: CyberStatTone;
}

export default function HomeStats({ history }: { history: HistoryRecord[] }) {
  const { t } = useTranslation();

  const totalScans = history.length;
  const totalVulns = history.reduce((acc, h) => acc + (h.report?.vulns?.length ?? 0), 0);
  const highRiskScans = history.filter((h) => {
    const r = h.report?.riskLevel ?? h.riskLevel;
    return r === 'Critical' || r === 'High';
  }).length;
  const targetCount = new Set(history.map((h) => h.report?.target?.baseUrl ?? h.target)).size;

  const defs: StatDef[] = [
    {
      label: t('home.stats.totalScans'),
      hint: t('home.stats.totalScansHint'),
      icon: <HistoryIcon />,
      tone: 'cyan',
    },
    {
      label: t('home.stats.vulnsFound'),
      hint: t('home.stats.vulnsFoundHint'),
      icon: <BugReportIcon />,
      tone: 'danger',
    },
    {
      label: t('home.stats.highRisk'),
      hint: t('home.stats.highRiskHint'),
      icon: <WarningAmberIcon />,
      tone: 'warn',
    },
    {
      label: t('home.stats.targets'),
      hint: t('home.stats.targetsHint'),
      icon: <TravelExploreIcon />,
      tone: 'success',
    },
  ];
  const values = [totalScans, totalVulns, highRiskScans, targetCount];

  return (
    <Grid container spacing={2} className="mb-4">
      {defs.map((d, i) => (
        <Grid item xs={12} sm={6} md={3} key={d.label}>
          <CyberStat value={values[i]} label={d.label} hint={d.hint} icon={d.icon} tone={d.tone} />
        </Grid>
      ))}
    </Grid>
  );
}
