// ReportSummarySection —— 报告头部摘要区（风险等级卡片 + 风险统计卡片 + 可视化图表）
// [P0-FIX] 从 ReportPage.tsx 拆分：ReportPage 仅保留编排/标签页，此组件负责纯展示逻辑
// （图表计算 + 渲染），使主页面文件瘦身、职责清晰。

import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box, Typography, Card, CardContent, Grid, Stack, Chip, Alert, Button,
} from '@mui/material';
import type { ReportModel, SqlmapVulnEntry, Vulnerability } from '../shared/types';

// 风险等级 → 颜色（与 ReportPage 原 RISK_COLORS 一致，导出供 ReportPage 复用防漂移）
// 注：为保证漏洞列表卡片与摘要卡片的 WCAG 对比度一致，采用 ReportPage 原值（AA 达标）。
export const RISK_COLORS: Record<string, string> = {
  Critical: '#d32f2f',
  High: '#bf360c', // WCAG AA 5.60:1
  Medium: '#9e6b00',
  Low: '#2e7d32',
};

// 检测技术 → 颜色（与 ReportPage 原 TECHNIQUE_COLORS 一致，导出供复用）
export const TECHNIQUE_COLORS: Record<string, string> = {
  union: '#7c3aed',
  error: '#d32f2f',
  boolean: '#1565c0',
  time: '#ed6c02',
  stacked: '#2e7d32',
  oob: '#6a1b9a',
  inline: '#00838f',
  second_order: '#ad1457',
  nosql: '#00695c',
};

interface Props {
  report: ReportModel;
  isSqlmap: boolean;
  effectiveVulnCount: number;
  chartCollapsed: boolean;
  onToggleCharts: () => void;
}

export default function ReportSummarySection({
  report,
  isSqlmap,
  effectiveVulnCount,
  chartCollapsed,
  onToggleCharts,
}: Props) {
  const { t, i18n } = useTranslation();
  const vulns: Vulnerability[] = useMemo(() => report.vulns || [], [report.vulns]);
  const sqlmapVulns: SqlmapVulnEntry[] = (report.sqlmap?.vulns || []).filter((v) => !!v && !!v.raw);
  const riskLevel = report.riskLevel || 'Low';
  const riskColor = RISK_COLORS[riskLevel] || '#388e3c';

  // 可视化数据：技术分布 + 风险等级环形图（useMemo 避免每次渲染重复计算）
  const { techniqueEntries, maxTechCount, riskRing, ringSegments, totalVulns, ringCirc, ringRadius, riskCounts } = useMemo(() => {
    const techniqueCounts = vulns.reduce<Record<string, number>>((acc, v) => {
      const tk = v.technique || 'unknown';
      acc[tk] = (acc[tk] || 0) + 1;
      return acc;
    }, {});
    const techniqueEntries = Object.entries(techniqueCounts).sort((a, b) => b[1] - a[1]);
    const maxTechCount = techniqueEntries.length ? techniqueEntries[0][1] : 0;
    const riskRing = [
      { key: 'Critical', color: RISK_COLORS.Critical },
      { key: 'High', color: RISK_COLORS.High },
      { key: 'Medium', color: RISK_COLORS.Medium },
      { key: 'Low', color: RISK_COLORS.Low },
    ].map((seg) => ({ ...seg, count: vulns.filter((v) => v.riskLevel === seg.key).length }));
    const totalVulns = vulns.length;
    const ringRadius = 60;
    const ringCirc = 2 * Math.PI * ringRadius;
    const ringSegments = riskRing.reduce<Array<typeof riskRing[number] & { len: number; offset: number }>>(
      (arr, seg) => {
        const len = totalVulns > 0 ? (seg.count / totalVulns) * ringCirc : 0;
        const offset = arr.length ? arr[arr.length - 1].offset + arr[arr.length - 1].len : 0;
        return [...arr, { ...seg, len, offset }];
      },
      [],
    );
    const riskCounts = {
      critical: vulns.filter(v => v.riskLevel === 'Critical').length,
      high: vulns.filter(v => v.riskLevel === 'High').length,
      medium: vulns.filter(v => v.riskLevel === 'Medium').length,
      low: vulns.filter(v => v.riskLevel === 'Low').length,
    };
    return { techniqueEntries, maxTechCount, riskRing, ringSegments, totalVulns, ringCirc, ringRadius, riskCounts };
  }, [vulns]);
  const fmt = (iso: string | undefined) =>
    iso ? new Date(iso).toLocaleString(i18n.language.startsWith('zh') ? 'zh-CN' : 'en-US') : '';

  return (
    <>
      {/* 风险等级卡片 */}
      <Card className="mb-4" sx={{ borderLeft: `6px solid ${riskColor}` }}>
        <CardContent>
          <Grid container spacing={3} alignItems="center">
            <Grid item xs={12} md={3} className="text-center">
              <Typography variant="h3" fontWeight={700} sx={{ color: riskColor }}>
                {riskLevel}
              </Typography>
              <Typography variant="caption" color="text.secondary">{t('report.riskLevel')}</Typography>
            </Grid>
            <Grid item xs={12} md={9}>
              <Stack spacing={1}>
                <Typography variant="h6" fontWeight={600}>
                  {report.target?.baseUrl || t('report.unknownTarget')}
                </Typography>
                <Stack direction="row" spacing={2} flexWrap="wrap">
                  <Chip
                    label={isSqlmap
                      ? t('report.vulnCountSqlmap', { count: effectiveVulnCount })
                      : t('report.vulnCount', { count: effectiveVulnCount })}
                    color={effectiveVulnCount > 0 ? 'error' : 'success'}
                    size="small"
                  />
                  <Chip label={report.dbms || t('report.unknownDbms')} variant="outlined" size="small" />
                  <Chip label={t('report.injectionPointCount', { count: report.points?.length || 0 })} variant="outlined" size="small" />
                  <Chip label={fmt(report.startedAt)} variant="outlined" size="small" />
                </Stack>
              </Stack>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* 统计卡片 */}
      <Grid container spacing={2} className="mb-4">
        <Grid item xs={6} md={3}>
          <Card variant="outlined">
            <CardContent className="text-center">
              <Typography variant="h4" fontWeight={700} color="error">{isSqlmap ? sqlmapVulns.length : riskCounts.critical}</Typography>
              <Typography variant="caption" color="text.secondary">{isSqlmap ? t('report.stat.hit') : t('risk.critical')}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} md={3}>
          <Card variant="outlined">
            <CardContent className="text-center">
              <Typography variant="h4" fontWeight={700} color="warning.main">{isSqlmap ? 0 : riskCounts.high}</Typography>
              <Typography variant="caption" color="text.secondary">{t('risk.high')}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} md={3}>
          <Card variant="outlined">
            <CardContent className="text-center">
              <Typography variant="h4" fontWeight={700} color="warning.light">{isSqlmap ? 0 : riskCounts.medium}</Typography>
              <Typography variant="caption" color="text.secondary">{t('risk.medium')}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} md={3}>
          <Card variant="outlined">
            <CardContent className="text-center">
              <Typography variant="h4" fontWeight={700} color="success.main">{isSqlmap ? 0 : riskCounts.low}</Typography>
              <Typography variant="caption" color="text.secondary">{t('risk.low')}</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* 可视化图表：技术分布条形图 + 风险等级环形图 */}
      {vulns.length === 0 ? (
        <Alert severity="info" variant="outlined" className="mb-4">
          {t('report.charts.noData')}
        </Alert>
      ) : (
        <Card variant="outlined" className="mb-4">
          <CardContent>
            <Grid container spacing={3}>
              {/* 漏洞技术分布条形图（可折叠） */}
              <Grid item xs={12} md={7}>
                <Stack direction="row" justifyContent="space-between" alignItems="center" className="mb-2">
                  <Typography variant="subtitle2" fontWeight={600}>{t('report.charts.techniqueDistribution')}</Typography>
                  <Button size="small" onClick={onToggleCharts}>
                    {chartCollapsed ? t('report.charts.expand') : t('report.charts.collapse')}
                  </Button>
                </Stack>
                {!chartCollapsed && (
                  <Stack spacing={1.5}>
                    {techniqueEntries.map(([tech, count]) => (
                      <Box key={tech} className="flex items-center" sx={{ gap: 1.5 }}>
                        <Typography
                          variant="caption"
                          sx={{ width: 130, flexShrink: 0, textAlign: 'right', color: 'text.secondary', lineHeight: '18px' }}
                        >
                          {t(`technique.${tech}`, { defaultValue: tech })}
                        </Typography>
                        <Box
                          sx={{ flex: 1, height: 18, borderRadius: 1, backgroundColor: '#f0f0f0', overflow: 'hidden' }}
                        >
                          <Box
                            sx={{
                              width: `${maxTechCount > 0 ? (count / maxTechCount) * 100 : 0}%`,
                              height: '100%',
                              backgroundColor: TECHNIQUE_COLORS[tech] || '#888',
                              transition: 'width 0.4s ease',
                            }}
                          />
                        </Box>
                        <Typography variant="caption" sx={{ width: 36, flexShrink: 0, textAlign: 'right', fontWeight: 600 }}>
                          {count}
                        </Typography>
                      </Box>
                    ))}
                  </Stack>
                )}
              </Grid>

              {/* 风险等级环形图 */}
              <Grid item xs={12} md={5}>
                <Typography variant="subtitle2" fontWeight={600} align="center" className="mb-1">
                  {t('report.charts.riskDistribution')}
                </Typography>
                <Box className="text-center">
                  <svg width="150" height="150" viewBox="0 0 150 150" role="img" aria-label={t('report.charts.riskDistribution')}>
                    {/* 背景环 */}
                    <circle cx="75" cy="75" r={ringRadius} fill="none" stroke="#efefef" strokeWidth="16" />
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
                    {/* 中心：总漏洞数 */}
                    <text x="75" y="72" textAnchor="middle" fontSize="26" fontWeight="700" fill="#212121">
                      {totalVulns}
                    </text>
                    <text x="75" y="92" textAnchor="middle" fontSize="11" fill="#757575">
                      {t('report.charts.total')}
                    </text>
                  </svg>
                  {/* 图例 */}
                  <Stack direction="row" spacing={1.5} justifyContent="center" className="mt-1" flexWrap="wrap">
                    {riskRing.map((seg) => (
                      <Box key={seg.key} className="flex items-center" sx={{ gap: 0.5 }}>
                        <Box sx={{ width: 10, height: 10, borderRadius: '2px', backgroundColor: seg.color, flexShrink: 0 }} />
                        <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1 }}>
                          {t(`risk.${seg.key === 'Critical' ? 'critical' : seg.key === 'High' ? 'high' : seg.key === 'Medium' ? 'medium' : 'low'}`)} · {seg.count}
                        </Typography>
                      </Box>
                    ))}
                  </Stack>
                </Box>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}
    </>
  );
}
