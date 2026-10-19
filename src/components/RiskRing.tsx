// 报告摘要的风险等级环形图 + 图例。
// [D109] 从 ReportSummarySection.tsx 拆出：该函数曾 226 行 / 32 复杂度，
// 超过存量基线（214 / 31）。

import { useTranslation } from 'react-i18next';
import { Box, Stack, Typography } from '@mui/material';

export interface RiskRingSegment {
  key: string;
  color: string;
  count: number;
  len: number;
  offset: number;
}

interface RiskRingProps {
  ringSegments: RiskRingSegment[];
  ringRadius: number;
  ringCirc: number;
  totalVulns: number;
  riskRing: Array<{ key: string; color: string; count: number }>;
}

const RISK_LABEL_KEY: Record<string, string> = {
  Critical: 'critical',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
};

export default function RiskRing({
  ringSegments, ringRadius, ringCirc, totalVulns, riskRing,
}: RiskRingProps) {
  const { t } = useTranslation();
  return (
    <Box className="text-center">
      <svg width="150" height="150" viewBox="0 0 150 150" role="img" aria-label={t('report.charts.riskDistribution')}>
        {/* 背景环 —— [D107] 原为硬编码 #efefef，暗色模式下是一圈刺眼白线 */}
        <circle cx="75" cy="75" r={ringRadius} fill="none" stroke="var(--cy-line)" strokeWidth="16" />
        {/* 四段风险环 */}
        {ringSegments.map((seg) =>
          seg.count > 0 ? (
            <circle
              key={seg.key}
              cx="75"
              cy="75"
              r={ringRadius}
              fill="none"
              stroke={seg.color}
              strokeWidth="16"
              strokeDasharray={`${seg.len} ${ringCirc - seg.len}`}
              strokeDashoffset={-seg.offset}
              transform="rotate(-90 75 75)"
            />
          ) : null,
        )}
        {/* 中心：总漏洞数 —— [D107] 原为硬编码 #212121/#757575，
            暗色下数字近乎不可读 */}
        <text x="75" y="72" textAnchor="middle" fontSize="26" fontWeight="700" fill="var(--cy-text)">
          {totalVulns}
        </text>
        <text x="75" y="92" textAnchor="middle" fontSize="11" fill="var(--cy-text-dim)">
          {t('report.charts.total')}
        </text>
      </svg>
      {/* 图例 */}
      <Stack direction="row" spacing={1.5} justifyContent="center" className="mt-1" flexWrap="wrap">
        {riskRing.map((seg) => (
          <Box key={seg.key} className="flex items-center" sx={{ gap: 0.5 }}>
            <Box sx={{ width: 10, height: 10, borderRadius: '2px', backgroundColor: seg.color, flexShrink: 0 }} />
            <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1 }}>
              {t(`risk.${RISK_LABEL_KEY[seg.key] || 'low'}`)} · {seg.count}
            </Typography>
          </Box>
        ))}
      </Stack>
    </Box>
  );
}
