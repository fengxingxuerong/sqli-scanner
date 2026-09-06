// 可视化报告页：风险仪表盘风格
// 大号风险等级卡片 + 漏洞列表 + 提取数据 + 一键操作
// P1-U1 增强：sqlmap 模式（report.engine==='sqlmap'）时，漏洞列表改用 report.sqlmap.vulns 渲染，
// 并新增「sqlmap 日志」Tab 回放原始输出——修复 sqlmap 命中即显示「未发现漏洞」的语义缺陷。

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box, Container, Paper, Button, Stack, Typography, Chip,
  Alert, Card, CardContent, Divider, LinearProgress, Tab, Tabs
} from '@mui/material';
import { ArrowBack, Refresh, PlayArrow } from '@mui/icons-material';
import { useScan } from '../hooks/useScan';
import { useScanStore } from '../store/scanStore';
import i18n from '../i18n';
import ReportExport from '../components/ReportExport';
import VulnDetail from '../components/VulnDetail';
import DbTree from '../components/DbTree';
import ReportSummarySection, { RISK_COLORS, TECHNIQUE_COLORS } from '../components/ReportSummarySection';
import type { Vulnerability, SqlmapVulnEntry } from '../shared/types';

// sqlmap 日志级别 → 颜色（与 ProgressView 同源，避免重复定义漂移）
const SQLMAP_LOG_COLOR: Record<string, string> = {
  error: '#d32f2f',
  success: '#43a047',
  info: '#1565c0',
  debug: '#9e9e9e',
  warn: '#f57c00',
  output: '#374151',
};

// [P1-FIX] 日期格式化兜底：缺失/非法时间戳渲染 '-'（原实现直接 new Date(undefined) → "Invalid Date"）
function fmtDate(iso?: string | null): string {
  if (!iso) return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '-';
  return d.toLocaleString(i18n.language.startsWith('zh') ? 'zh-CN' : 'en-US');
}

// sqlmap 命中行 → 漏洞卡片（param / technique / raw 原文）
function SqlmapVulnCard({ v }: { v: SqlmapVulnEntry }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <Card
      variant="outlined"
      className="cursor-pointer"
      sx={{ borderLeft: '4px solid #d32f2f' }}
      onClick={() => setOpen(!open)}
      aria-expanded={open}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          setOpen(!open);
        }
      }}
    >
      <CardContent className="py-3">
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography variant="subtitle2" fontWeight={600}>
              {v.param ? t('report.sqlmapVuln.param', { param: v.param }) : t('report.sqlmapVuln.unknownParam')}
            </Typography>
            <Typography variant="caption" color="text.secondary">{t('report.sqlmapVuln.confirmedInjection')}</Typography>
          </Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <Chip label={v.technique} size="small" sx={{ backgroundColor: '#1565c0', color: '#fff' }} />
            <Chip label={t('risk.critical')} size="small" sx={{ backgroundColor: '#d32f2f', color: '#fff' }} />
          </Stack>
        </Stack>
        {open && (
          <Box className="mt-3 pt-3 border-t border-gray-200">
            <Typography variant="caption" color="text.secondary">{t('report.sqlmapVuln.rawHitLine')}</Typography>
            <Box
              component="pre"
              className="mt-1 p-2 rounded overflow-x-auto"
              sx={{ backgroundColor: '#f5f5f5', fontSize: '0.75rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
            >
              {v.raw}
            </Box>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

// TECHNIQUE_COLORS 已由 ReportSummarySection 导出（单一事实源），此处不再重复定义（防漂移）。

function TabPanel({ children, value, index }: { children: React.ReactNode; value: number; index: number }) {
  return value === index ? (
    <Box
      className="py-4"
      role="tabpanel"
      id={`report-tabpanel-${index}`}
      aria-labelledby={`report-tab-${index}`}
    >
      {children}
    </Box>
  ) : null;
}

export default function ReportPage() {
  const { t } = useTranslation();
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { getReport, startScan } = useScan();
  const report = useScanStore((s) => s.report);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [tab, setTab] = useState(0);
  const [resumeError, setResumeError] = useState('');
  const [chartCollapsed, setChartCollapsed] = useState(false);

  useEffect(() => {
    if (!id) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError('');
    getReport(id)
      .then(() => { if (!cancelled) setLoading(false); })
      .catch((e) => { if (!cancelled) { setError(e.message || t('report.loadError')); setLoading(false); } });
    return () => { cancelled = true; };
  }, [id, getReport, t]);

  if (loading) {
    return (
      <Container maxWidth="md" className="py-6">
        <Box className="text-center py-10">
          <LinearProgress className="mb-4" />
          <Typography color="text.secondary">{t('report.loading')}</Typography>
        </Box>
      </Container>
    );
  }

  if (error) {
    return (
      <Container maxWidth="md" className="py-6">
        <Alert severity="error" className="mb-4">{error}</Alert>
        <Button startIcon={<ArrowBack />} onClick={() => navigate('/')}>{t('report.backToHome')}</Button>
      </Container>
    );
  }

  if (!report) {
    return (
      <Container maxWidth="md" className="py-6">
        <Alert severity="warning">{t('report.notFound')}</Alert>
        <Button startIcon={<ArrowBack />} onClick={() => navigate('/')} className="mt-4">{t('report.backToHome')}</Button>
      </Container>
    );
  }

  const vulns = report.vulns || [];
  const data = report.data;
  // sqlmap 模式：漏洞来自 sqlmap.vulns（内置引擎报告无此字段）
  const isSqlmap = report.engine === 'sqlmap';
  const sqlmapVulns: SqlmapVulnEntry[] = (report.sqlmap?.vulns || []).filter((v) => !!v && !!v.raw);
  const sqlmapLogs = report.sqlmap?.logs || [];
  // [P1-FIX] sqlmap 日志无界渲染：超大日志（数千行）全量挂 DOM 会冻结页面，仅渲染最近 500 行
  const VISIBLE_LOG_TAIL = 500;
  const visibleSqlmapLogs = sqlmapLogs.length > VISIBLE_LOG_TAIL
    ? sqlmapLogs.slice(-VISIBLE_LOG_TAIL)
    : sqlmapLogs;
  const effectiveVulnCount = isSqlmap ? sqlmapVulns.length : vulns.length;

  // 续跑（P1-U5 补充）：复用 HistoryPage 判定——仅 builtin + 有会话配置时可续跑
  const resumeCfg = report.target?.config;
  const canResumeHere =
    !isSqlmap && !!resumeCfg && !!(resumeCfg.sessionFile || resumeCfg.sessionDefault);
  const handleResumeHere = async () => {
    if (!report.target) return;
    try {
      await startScan({
        engine: 'builtin',
        url: report.target.baseUrl,
        method: report.target.method,
        bodyParams: report.target.bodyParams,
        cookieParams: report.target.cookieParams,
        headerParams: report.target.headerParams,
        config: {
          ...resumeCfg,
          sessionFile:
            resumeCfg.sessionFile || (resumeCfg.sessionDefault ? 'sqli-session-latest.json' : undefined),
          sessionDefault: resumeCfg.sessionDefault,
        },
      });
      navigate('/scan');
    } catch (e: unknown) {
      setResumeError(e instanceof Error ? e.message : t('history.resumeFailed'));
    }
  };

  // 可视化数据计算已下沉至 ReportSummarySection（单一事实源，本页仅透传折叠态）

  return (
    <Container maxWidth="lg" className="py-6">
      {/* 鎿嶄綔鏍?*/}
      <Stack direction="row" spacing={2} className="mb-4" alignItems="center">
        <Button startIcon={<ArrowBack />} onClick={() => navigate('/')} size="small">{t('report.back')}</Button>
        <Button
          startIcon={<Refresh />}
          onClick={() => { if (id) getReport(id, { force: true }); }}
          size="small"
        >
          {t('report.refresh')}
        </Button>
        {canResumeHere && (
          <Button
            startIcon={<PlayArrow />}
            onClick={handleResumeHere}
            size="small"
            color="primary"
            variant="outlined"
          >
            {t('history.resume')}
          </Button>
        )}
        {resumeError && (
          <Typography variant="caption" color="error">{resumeError}</Typography>
        )}
        <Box className="ml-auto">
          <ReportExport />
        </Box>
      </Stack>

      {/* 报告摘要区：风险卡片 + 统计卡片 + 可视化图表（独立组件，本页仅透传折叠态） */}
      <ReportSummarySection
        report={report}
        isSqlmap={isSqlmap}
        effectiveVulnCount={effectiveVulnCount}
        chartCollapsed={chartCollapsed}
        onToggleCharts={() => setChartCollapsed((c) => !c)}
      />


      {/* 标签页 */}
      <Paper variant="outlined" className="mb-4">
        <Tabs value={tab} onChange={(_, v) => setTab(v)} aria-label={t('report.title')}>
          <Tab label={t('report.vulnListTab', { count: effectiveVulnCount })} id="report-tab-0" aria-controls="report-tabpanel-0" />
          <Tab label={t('report.extractedDataTab', { count: data?.databases?.length || 0 })} id="report-tab-1" aria-controls="report-tabpanel-1" />
          <Tab label={t('report.summary')} id="report-tab-2" aria-controls="report-tabpanel-2" />
          {isSqlmap && <Tab label={t('report.sqlmapLogsTab', { count: sqlmapLogs.length })} id="report-tab-3" aria-controls="report-tabpanel-3" />}
        </Tabs>

        {/* 漏洞列表：sqlmap 模式从 sqlmap.vulns 渲染，内置引擎走 vulns */}
        <TabPanel value={tab} index={0}>
          {isSqlmap ? (
            sqlmapVulns.length === 0 ? (
              <Alert severity="success" variant="outlined">{t('report.sqlmapNoInjection')}</Alert>
            ) : (
              <Stack spacing={2}>
                {sqlmapVulns.map((v, i) => <SqlmapVulnCard key={i} v={v} />)}
              </Stack>
            )
          ) : vulns.length === 0 ? (
            <Alert severity="success" variant="outlined">{t('report.noVulns')}</Alert>
          ) : (
            <Stack spacing={2}>
              {vulns.map((vuln) => (
                <Card
                  key={vuln.id}
                  variant="outlined"
                  className="cursor-pointer"
                  sx={{ borderLeft: `4px solid ${RISK_COLORS[vuln.riskLevel] || '#888'}` }}
                  onClick={() => setSelectedVuln(selectedVuln?.id === vuln.id ? null : vuln)}
                  aria-expanded={selectedVuln?.id === vuln.id}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setSelectedVuln(selectedVuln?.id === vuln.id ? null : vuln);
                    }
                  }}
                >
                  <CardContent className="py-3">
                    <Stack direction="row" justifyContent="space-between" alignItems="center">
                      <Box>
                        <Typography variant="subtitle2" fontWeight={600}>
                          {vuln.pointId}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {vuln.description || t('report.techniqueInjection', { technique: vuln.technique })}
                        </Typography>
                      </Box>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Chip
                          label={vuln.technique}
                          size="small"
                          sx={{ backgroundColor: TECHNIQUE_COLORS[vuln.technique] || '#888', color: '#fff' }}
                        />
                        <Chip
                          label={vuln.riskLevel}
                          size="small"
                          sx={{ backgroundColor: RISK_COLORS[vuln.riskLevel] || '#888', color: '#fff' }}
                        />
                        {vuln.dbms && <Chip label={vuln.dbms} size="small" variant="outlined" />}
                      </Stack>
                    </Stack>
                    {selectedVuln?.id === vuln.id && (
                      <Box className="mt-3 pt-3 border-t border-gray-200">
                        <VulnDetail vuln={vuln} />
                      </Box>
                    )}
                  </CardContent>
                </Card>
              ))}
            </Stack>
          )}
        </TabPanel>

        {/* 提取数据 */}
        <TabPanel value={tab} index={1}>
          {data && data.databases && data.databases.length > 0 ? (
            <DbTree data={data} />
          ) : (
            <Alert severity="info" variant="outlined">
              {t('report.noExtractedData')}
            </Alert>
          )}
        </TabPanel>

        {/* 检测摘要 */}
        <TabPanel value={tab} index={2}>
          <Stack spacing={2}>
            <Box>
              <Typography variant="subtitle2" fontWeight={600}>{t('report.scanTarget')}</Typography>
              <Typography variant="body2" color="text.secondary">
                {report.target?.baseUrl || '-'}
              </Typography>
            </Box>
            <Divider />
            <Box>
              <Typography variant="subtitle2" fontWeight={600}>{t('report.scanDbms')}</Typography>
              <Typography variant="body2" color="text.secondary">
                {report.dbms || t('report.dbmsUnidentified')}
              </Typography>
            </Box>
            <Divider />
            <Box>
              <Typography variant="subtitle2" fontWeight={600}>{t('report.injectionPointCountLabel')}</Typography>
              <Typography variant="body2" color="text.secondary">
                {t('report.itemCount', { count: report.points?.length || 0 })}
              </Typography>
            </Box>
            <Divider />
            <Box>
              <Typography variant="subtitle2" fontWeight={600}>{t('report.scanTime')}</Typography>
              <Typography variant="body2" color="text.secondary">
                {fmtDate(report.startedAt)}
                {report.finishedAt ? ` → ${fmtDate(report.finishedAt)}` : ''}
              </Typography>
            </Box>
            {report.summary?.wafDetected && report.summary.wafDetected.length > 0 && (
              <>
                <Divider />
                <Box>
                  <Typography variant="subtitle2" fontWeight={600}>{t('report.wafDetection')}</Typography>
                  <Stack direction="row" spacing={1} className="mt-1">
                    {report.summary.wafDetected.map((w, i) => (
                      <Chip key={i} label={`${w.vendor} (${Math.round(w.confidence * 100)}%)`} size="small" color="warning" variant="outlined" />
                    ))}
                  </Stack>
                </Box>
              </>
            )}
          </Stack>
        </TabPanel>

        {/* sqlmap 日志 Tab（仅 sqlmap 模式渲染） */}
        {isSqlmap && (
          <TabPanel value={tab} index={3}>
            {sqlmapLogs.length === 0 ? (
              <Alert severity="info" variant="outlined">{t('report.noSqlmapLogs')}</Alert>
            ) : (
              <>
                {sqlmapLogs.length > VISIBLE_LOG_TAIL && (
                  <Alert severity="info" variant="outlined" className="mb-2" sx={{ py: 0.5 }}>
                    {t('report.logTruncated', { total: sqlmapLogs.length, shown: VISIBLE_LOG_TAIL })}
                  </Alert>
                )}
                <Box
                  component="pre"
                  className="p-3 rounded overflow-x-auto"
                  sx={{ backgroundColor: '#1e1e1e', color: '#e0e0e0', fontSize: '0.72rem', lineHeight: 1.5, maxHeight: 480, overflowY: 'auto' }}
                >
                  {visibleSqlmapLogs.map((l, i) => (
                    <Box key={i} component="span" sx={{ display: 'block', color: SQLMAP_LOG_COLOR[l.level] || '#e0e0e0' }}>
                      [{typeof l.ts === 'string' ? l.ts.slice(11, 19) : ''}] {l.text}
                    </Box>
                  ))}
                </Box>
              </>
            )}
          </TabPanel>
        )}
      </Paper>
    </Container>
  );
}
