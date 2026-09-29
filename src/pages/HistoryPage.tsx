// 历史页 — 清新卡片式设计，统一新视觉风格
//
// [2026-09-29] 数据源改造：由「只读浏览器 localStorage」改为「服务端清单为主 + 本地兜底」。
//   此前服务端早就有 `GET /api/scans`（台账 + 在途合并），但本页没接 ⇒ 换机器/换浏览器/
//   清缓存/引擎重启，历史就空了 —— 而同一批扫描在 CLI 那边一直看得到。
//   降级纪律：服务端拿不到时**退回本地列表并如实提示**，不允许出现"比改造前更差"的白屏。

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box, Container, Typography, Card, CardContent, Chip, Button,
  IconButton, Alert, Stack, Grid
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import ReplayIcon from '@mui/icons-material/Replay';
import HistoryIcon from '@mui/icons-material/History';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import { useTranslation } from 'react-i18next';
import { useScanStore } from '../store/scanStore';
import { useScan } from '../hooks/useScan';
import { useServerHistory } from '../hooks/useServerHistory';
import { mergeHistory, type MergedHistoryRow } from '../shared/historyMerge';
import { buildResumeConfig } from '../shared/scanConfig';
import i18n from '../i18n';
import type { HistoryRecord, RiskLevel } from '../shared/types';

const RISK_COLORS: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
  Critical: 'error',
  High: 'warning',
  Medium: 'info',
  Low: 'success',
};

function formatTime(iso: string | null): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const locale = i18n.language.startsWith('zh') ? 'zh-CN' : 'en-US';
  return d.toLocaleString(locale, {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}

/** 来源标记：让用户知道这条是「跨机器可见」还是「只在这台浏览器里」 */
const SOURCE_LABEL: Record<MergedHistoryRow['source'], { key: string; color: 'info' | 'success' | 'default' }> = {
  ledger: { key: 'history.sourceServer', color: 'info' },
  live: { key: 'history.sourceLive', color: 'success' },
  local: { key: 'history.sourceLocal', color: 'default' },
};

export default function HistoryPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const history = useScanStore((s) => s.history);
  const removeHistory = useScanStore((s) => s.removeHistory);
  const { startScan } = useScan();
  const server = useServerHistory();
  const [resumeError, setResumeError] = useState('');

  // 服务端清单 ∪ 本地历史（去重规则见 historyMerge.ts）
  const rows = mergeHistory(server.rows, history);

  // 续跑要读 report.target.config，服务端清单里没有报告全文 —— 只有本地快照齐才行
  const canResume = (h?: HistoryRecord) => {
    const cfg = h?.report?.target?.config;
    if (!cfg) return false;
    if (h?.report?.engine === 'sqlmap') return false;
    return !!(cfg.sessionFile || cfg.sessionDefault);
  };

  const handleResume = async (row: MergedHistoryRow) => {
    setResumeError('');
    if (!row.local?.report?.target) return;
    const cfg = row.local.report.target.config;
    try {
      await startScan({
        engine: row.local.report.engine || 'builtin',
        url: row.local.report.target.baseUrl,
        method: row.local.report.target.method,
        bodyParams: row.local.report.target.bodyParams,
        cookieParams: row.local.report.target.cookieParams,
        headerParams: row.local.report.target.headerParams,
        // [P0-FIX 2026-09-09] 续跑配置走 buildResumeConfig：结构化透传 + 类型归一。
        // 以前这里手拄字段表（`sessionFile`/`sessionDefault` 逐键列），而 scope / delay / reqRate
        // 这类「前端未建模但已保存」的键全靠人记——历史上正是这么把「授权范围」丢在续跑路上的。
        config: buildResumeConfig(cfg),
      });
      navigate('/scan');
    } catch (e: unknown) {
      setResumeError(e instanceof Error ? e.message : t('history.resumeFailed'));
    }
  };

  const handleDelete = (e: React.MouseEvent, scanId: string) => {
    e.stopPropagation();
    removeHistory(scanId);
  };

  const goto = (scanId: string) => navigate(`/report/${scanId}`);

  return (
    <Container maxWidth="md" className="py-6">
      {/* 页面标题 */}
      <Box className="mb-6">
        <Typography variant="h4" fontWeight={700} gutterBottom>
          {t('history.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('history.subtitle', { count: rows.length })}
        </Typography>
      </Box>

      {resumeError && (
        <Alert severity="error" className="mb-4" onClose={() => setResumeError('')}>
          {resumeError}
        </Alert>
      )}

      {/* 服务端拿不到清单：不是错误，是降级 —— 必须说清楚"现在显示的是什么" */}
      {server.error && (
        <Alert severity="warning" className="mb-4">
          {t('history.serverUnavailable', { message: server.error })}
        </Alert>
      )}

      {rows.length === 0 ? (
        <Box className="p-10 text-center" sx={{ border: 1, borderColor: 'divider', borderRadius: 2 }}>
          <HistoryIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 2 }} />
          <Typography color="text.secondary" gutterBottom>
            {t('history.empty')}
          </Typography>
          <Button variant="contained" onClick={() => navigate('/scan')} className="mt-2">
            {t('history.firstScan')}
          </Button>
        </Box>
      ) : (
        <Stack spacing={2}>
          {rows.map((row) => {
            const risk: RiskLevel | null = row.riskLevel;
            const targetUrl = row.target || t('history.unknownTarget');
            const isSqlmap = row.local?.report?.engine === 'sqlmap';
            const meta = SOURCE_LABEL[row.source];

            return (
              <Card
                key={row.scanId}
                variant="outlined"
                className="cursor-pointer"
                sx={{
                  transition: 'box-shadow 0.2s ease, transform 0.15s ease',
                  '&:hover': { boxShadow: 3, transform: 'translateY(-1px)' },
                }}
                onClick={() => goto(row.scanId)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    goto(row.scanId);
                  }
                }}
              >
                <CardContent className="py-3">
                  <Grid container alignItems="center" spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" fontWeight={600} noWrap>
                        {targetUrl}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {row.scanId.slice(0, 8)} · {formatTime(row.finishedAt)}
                      </Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                        {risk ? (
                          <Chip
                            label={t('history.risk', { level: t(`risk.${risk.toLowerCase()}`) })}
                            size="small"
                            color={RISK_COLORS[risk]}
                            variant="outlined"
                          />
                        ) : (
                          // 老台账没有 highestRisk 字段 ⇒ 显示"未知"而不是猜一个出来
                          <Chip label={t('history.riskUnknown')} size="small" variant="outlined" />
                        )}
                        <Chip label={t(meta.key)} size="small" color={meta.color} variant="outlined" />
                        {isSqlmap && <Chip label="sqlmap" size="small" color="secondary" variant="outlined" />}
                      </Stack>
                      <Typography variant="caption" color="text.secondary" className="mt-1">
                        {row.vulns > 0 ? t('history.vulns', { count: row.vulns }) : t('history.noVulns')}
                      </Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Stack direction="row" spacing={1} justifyContent="flex-end">
                        {canResume(row.local) && (
                          <Button
                            size="small"
                            variant="outlined"
                            startIcon={<ReplayIcon />}
                            aria-label={t('history.resume')}
                            onClick={(e) => { e.stopPropagation(); handleResume(row); }}
                          >
                            {t('history.resume')}
                          </Button>
                        )}
                        <Button
                          size="small"
                          endIcon={<ArrowForwardIcon />}
                          onClick={(e) => { e.stopPropagation(); goto(row.scanId); }}
                        >
                          {t('history.view')}
                        </Button>
                        {/* 只有本地条目删得掉：服务端没有 DELETE 端点，给按钮点了没反应等于骗人 */}
                        {row.local && (
                          <IconButton
                            size="small"
                            color="default"
                            aria-label={t('history.delete')}
                            onClick={(e) => handleDelete(e, row.scanId)}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        )}
                      </Stack>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            );
          })}
        </Stack>
      )}
    </Container>
  );
}
