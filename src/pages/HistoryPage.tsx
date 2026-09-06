// 历史页 — 清新卡片式设计，统一新视觉风格

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

export default function HistoryPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const history = useScanStore((s) => s.history);
  const removeHistory = useScanStore((s) => s.removeHistory);
  const { startScan } = useScan();
  const [resumeError, setResumeError] = useState('');

  const canResume = (h: HistoryRecord) => {
    const cfg = h.report?.target?.config;
    if (!cfg) return false;
    if (h.report?.engine === 'sqlmap') return false;
    return !!(cfg.sessionFile || cfg.sessionDefault);
  };

  const handleResume = async (h: HistoryRecord) => {
    setResumeError('');
    if (!h.report?.target) return;
    const cfg = h.report.target.config;
    try {
      await startScan({
        engine: h.report.engine || 'builtin',
        url: h.report.target.baseUrl,
        method: h.report.target.method,
        bodyParams: h.report.target.bodyParams,
        cookieParams: h.report.target.cookieParams,
        headerParams: h.report.target.headerParams,
        config: {
          ...cfg,
          sessionFile: cfg.sessionFile || (cfg.sessionDefault ? 'sqli-session-latest.json' : undefined),
          sessionDefault: cfg.sessionDefault,
        },
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

  return (
    <Container maxWidth="md" className="py-6">
      {/* 页面标题 */}
      <Box className="mb-6">
        <Typography variant="h4" fontWeight={700} gutterBottom>
          {t('history.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('history.subtitle', { count: history.length })}
        </Typography>
      </Box>

      {resumeError && (
        <Alert severity="error" className="mb-4" onClose={() => setResumeError('')}>
          {resumeError}
        </Alert>
      )}

      {history.length === 0 ? (
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
          {history.map((h) => {
            const risk: RiskLevel = h.report?.riskLevel ?? h.riskLevel ?? 'Low';
            const targetUrl = h.report?.target?.baseUrl ?? h.target ?? t('history.unknownTarget');
            const vulnCount = h.report?.vulns?.length ?? 0;
            const isSqlmap = h.report?.engine === 'sqlmap';

            return (
              <Card
                key={h.scanId}
                variant="outlined"
                className="cursor-pointer"
                sx={{
                  transition: 'box-shadow 0.2s ease, transform 0.15s ease',
                  '&:hover': { boxShadow: 3, transform: 'translateY(-1px)' },
                }}
                onClick={() => navigate(`/report/${h.scanId}`)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    navigate(`/report/${h.scanId}`);
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
                        {h.scanId.slice(0, 8)} · {formatTime(h.finishedAt)}
                      </Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Stack direction="row" spacing={1}>
                        <Chip
                          label={t('history.risk', { level: t(`risk.${risk.toLowerCase()}`) })}
                          size="small"
                          color={RISK_COLORS[risk]}
                          variant="outlined"
                        />
                        {isSqlmap && <Chip label="sqlmap" size="small" color="secondary" variant="outlined" />}
                      </Stack>
                      <Typography variant="caption" color="text.secondary" className="mt-1">
                        {vulnCount > 0 ? t('history.vulns', { count: vulnCount }) : t('history.noVulns')}
                      </Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Stack direction="row" spacing={1} justifyContent="flex-end">
                        {canResume(h) && (
                          <Button
                            size="small"
                            variant="outlined"
                            startIcon={<ReplayIcon />}
                            aria-label={t('history.resume')}
                            onClick={(e) => { e.stopPropagation(); handleResume(h); }}
                          >
                            {t('history.resume')}
                          </Button>
                        )}
                        <Button
                          size="small"
                          endIcon={<ArrowForwardIcon />}
                          onClick={(e) => { e.stopPropagation(); navigate(`/report/${h.scanId}`); }}
                        >
                          {t('history.view')}
                        </Button>
                        <IconButton
                          size="small"
                          color="default"
                          aria-label={t('history.delete')}
                          onClick={(e) => handleDelete(e, h.scanId)}
                        >
                          <DeleteIcon fontSize="small" />
                        </IconButton>
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