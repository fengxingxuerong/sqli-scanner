// 首页：现代 SaaS 仪表盘风格的简洁仪表盘。
// 设计要点：
//  - 大而醒目的「开始扫描」CTA（渐变 Hero + 白色主按钮，导航到 /scan）
//  - 快速统计（总扫描 / 发现漏洞 / 高危风险 / 已检测目标）
//  - 最近 5 次扫描历史（点击回溯报告，跳转 /report/:scanId）
//  - 轻量入场动画（fadeInUp，交错延迟），无复杂选项
// 说明：store 暴露的是 history 状态字段（useScanStore((s) => s.history)），
//      与 HistoryPage 使用方式一致，返回 HistoryRecord[]。

import { keyframes } from '@emotion/react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  Divider,
  Grid,
  Paper,
  Stack,
  Typography,
} from '@mui/material';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import BugReportIcon from '@mui/icons-material/BugReport';
import HistoryIcon from '@mui/icons-material/History';
import SecurityIcon from '@mui/icons-material/Security';
import TravelExploreIcon from '@mui/icons-material/TravelExplore';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { useTranslation } from 'react-i18next';
import { useScanStore } from '../store/scanStore';
import i18n from '../i18n';
import type { RiskLevel } from '../shared/types';

// 入场动画：自下而上淡入（避免生硬出现）
const fadeInUp = keyframes`
  from { opacity: 0; transform: translateY(18px); }
  to   { opacity: 1; transform: translateY(0); }
`;

// 风险等级 → Chip 颜色映射
const RISK_CHIP_COLOR: Record<RiskLevel, 'error' | 'warning' | 'info' | 'success'> = {
  Critical: 'error',
  High: 'warning',
  Medium: 'info',
  Low: 'success',
};

// 时间格式化（容错非法/空值）
function formatTime(iso: string | null): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const locale = i18n.language.startsWith('zh') ? 'zh-CN' : 'en-US';
  return d.toLocaleString(locale, {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// 首页默认导出组件
export default function HomePage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const history = useScanStore((s) => s.history);

  const recent = history.slice(0, 5); // 最近 5 次
  const totalScans = history.length;
  const totalVulns = history.reduce((acc, h) => acc + (h.report?.vulns?.length ?? 0), 0);
  const highRiskScans = history.filter((h) => {
    const r = h.report?.riskLevel ?? h.riskLevel;
    return r === 'Critical' || r === 'High';
  }).length;
  const targetCount = new Set(history.map((h) => h.report?.target?.baseUrl ?? h.target)).size;

  const stats = [
    { label: t('home.stats.totalScans'), value: totalScans, icon: <HistoryIcon />, color: '#6366f1' },
    { label: t('home.stats.vulnsFound'), value: totalVulns, icon: <BugReportIcon />, color: '#ef4444' },
    { label: t('home.stats.highRisk'), value: highRiskScans, icon: <WarningAmberIcon />, color: '#f59e0b' },
    { label: t('home.stats.targets'), value: targetCount, icon: <TravelExploreIcon />, color: '#10b981' },
  ];

  const goScan = () => navigate('/scan');

  return (
    <Container maxWidth="lg" className="py-6">
      {/* 点阵背景 */}
      <div className="dot-grid" />

      {/* ── Hero：赛博玻璃风 ── */}
      <Box
        className="glass"
        sx={{
          borderRadius: 4,
          p: { xs: 4, md: 8 },
          position: 'relative',
          overflow: 'hidden',
          animation: `${fadeInUp} 0.55s ease-out both`,
          boxShadow: '0 0 60px rgba(0, 212, 255, 0.06)',
          '&::before': {
            content: '""', position: 'absolute', top: 0, left: 0, right: 0, height: '2px',
            background: 'linear-gradient(90deg, transparent 10%, #00d4ff 40%, #8b5cf6 60%, transparent 90%)',
            boxShadow: '0 0 8px rgba(0, 212, 255, 0.3)',
          },
        }}
      >
        <Stack spacing={1.5} alignItems="flex-start" sx={{ position: 'relative', zIndex: 1 }}>
          <Chip
            icon={<SecurityIcon />}
            label={t('app.title')}
            size="small"
            sx={{
              color: '#00d4ff',
              borderColor: 'rgba(0, 212, 255, 0.3)',
              bgcolor: 'rgba(0, 212, 255, 0.08)',
              '& .MuiChip-icon': { color: '#00d4ff' },
              fontFamily: '"JetBrains Mono", monospace',
            }}
            variant="outlined"
          />
          <Typography
            component="h1"
            fontWeight={800}
            sx={{
              fontSize: { xs: 28, md: 44 },
              letterSpacing: '-0.03em',
              lineHeight: 1.1,
              background: 'linear-gradient(135deg, #00d4ff 0%, #8b5cf6 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
            }}
          >
            {t('home.hero')}
          </Typography>
          <Typography variant="body1" sx={{ color: 'rgba(148, 163, 184, 0.9)', maxWidth: 560 }}>
            {t('app.tagline')}
          </Typography>
          <Button
            variant="contained"
            size="large"
            endIcon={<ArrowForwardIcon />}
            onClick={goScan}
            sx={{
              mt: 2,
              px: { xs: 4, md: 5 },
              py: 1.4,
              borderRadius: 2,
              fontSize: '1rem',
              fontWeight: 700,
              color: '#0a0e16',
              background: 'linear-gradient(135deg, #00d4ff 0%, #8b5cf6 100%)',
              boxShadow: '0 0 24px rgba(0, 212, 255, 0.3)',
              transition: 'transform 0.2s, box-shadow 0.2s',
              '&:hover': {
                transform: 'translateY(-2px)',
                background: 'linear-gradient(135deg, #33dfff 0%, #a78bfa 100%)',
                boxShadow: '0 0 32px rgba(0, 212, 255, 0.5)',
              },
            }}
          >
            {t('home.startScan')}
          </Button>
        </Stack>

        {/* 右下角装饰：盾牌光晕 */}
        <Box sx={{
          position: 'absolute', right: { xs: -40, md: 20 }, bottom: -20,
          opacity: 0.06, fontSize: { xs: 120, md: 200 }, pointerEvents: 'none',
        }}>
          <SecurityIcon sx={{ fontSize: 'inherit', color: '#00d4ff' }} />
        </Box>
      </Box>

      {/* ── 快速统计 ── */}
      <Grid container spacing={3} sx={{ mt: 1 }}>
        {stats.map((s, i) => (
          <Grid item xs={12} sm={6} md={3} key={s.label}>
            <Card
              sx={{
                animation: `${fadeInUp} 0.5s ease-out both`,
                animationDelay: `${0.08 * (i + 1)}s`,
                p: 0,
              }}
            >
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={1.5}>
                  <Box
                    sx={{
                      width: 44, height: 44, borderRadius: 2,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      color: '#0a0e16', flexShrink: 0,
                      background: `linear-gradient(135deg, ${s.color}40 0%, ${s.color}80 100%)`,
                      boxShadow: `0 0 12px ${s.color}40`,
                    }}
                  >
                    {s.icon}
                  </Box>
                  <Box>
                    <Typography variant="h4" fontWeight={800} lineHeight={1}>
                      {s.value}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {s.label}
                    </Typography>
                  </Box>
                </Stack>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* ── 最近扫描（5 条）── */}
      <Paper
        variant="outlined"
        sx={{ mt: 4, borderRadius: 3, animation: `${fadeInUp} 0.55s ease-out 0.45s both` }}
      >
        <Stack
          direction="row"
          alignItems="center"
          justifyContent="space-between"
          sx={{ px: 3, py: 2 }}
        >
          <Typography variant="h6" fontWeight={700}>
            {t('home.recentScans')}
          </Typography>
          {history.length > 0 && (
            <Button size="small" endIcon={<ArrowForwardIcon />} onClick={() => navigate('/history')}>
              {t('home.viewAll')}
            </Button>
          )}
        </Stack>
        <Divider />
        {recent.length === 0 ? (
          <Box sx={{ p: 5, textAlign: 'center' }}>
            <HistoryIcon sx={{ fontSize: 44, color: 'text.disabled', mb: 1 }} />
            <Typography color="text.secondary" gutterBottom>
              {t('home.empty')}
            </Typography>
            {/* 三步引导卡片 */}
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} justifyContent="center" className="mt-4">
              {[
                { step: '1', title: t('home.guide.step1'), desc: t('home.guide.step1Desc') },
                { step: '2', title: t('home.guide.step2'), desc: t('home.guide.step2Desc') },
                { step: '3', title: t('home.guide.step3'), desc: t('home.guide.step3Desc') },
              ].map((item) => (
                <Card key={item.step} variant="outlined" sx={{ minWidth: 160, borderRadius: 2, flex: 1 }}>
                  <CardContent sx={{ textAlign: 'center', py: 2.5 }}>
                    <Box sx={{
                      width: 36, height: 36, borderRadius: '50%',
                      bgcolor: 'primary.main', color: '#fff',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontWeight: 700, mx: 'auto', mb: 1.5, fontSize: '1rem',
                    }}>
                      {item.step}
                    </Box>
                    <Typography variant="subtitle2" fontWeight={600} gutterBottom>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </CardContent>
                </Card>
              ))}
            </Stack>
          </Box>
        ) : (
          <Box>
            {recent.map((h, idx) => {
              const risk: RiskLevel = h.report?.riskLevel ?? h.riskLevel ?? 'Low';
              const targetUrl = h.report?.target?.baseUrl ?? h.target ?? t('home.unknownTarget');
              return (
                <Box key={h.scanId}>
                  {idx > 0 && <Divider />}
                  <Box
                    onClick={() => navigate(`/report/${h.scanId}`)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        navigate(`/report/${h.scanId}`);
                      }
                    }}
                    sx={{
                      px: 3,
                      py: 2,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 2,
                      transition: 'background-color 0.15s ease',
                      '&:hover': { bgcolor: 'action.hover' },
                    }}
                  >
                    <Box sx={{ minWidth: 0, flex: 1 }}>
                      <Typography variant="body1" noWrap fontWeight={600}>
                        {targetUrl}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {h.scanId} {formatTime(h.finishedAt)}
                      </Typography>
                    </Box>
                    <Stack direction="row" spacing={1} alignItems="center" flexShrink={0}>
                      {h.report?.engine === 'sqlmap' && (
                        <Chip label="sqlmap" size="small" color="secondary" variant="outlined" />
                      )}
                      <Chip
                        label={t('history.risk', { level: t(`risk.${risk.toLowerCase()}`) })}
                        size="small"
                        color={RISK_CHIP_COLOR[risk]}
                        variant="outlined"
                      />
                    </Stack>
                  </Box>
                </Box>
              );
            })}
          </Box>
        )}
      </Paper>
    </Container>
  );
}
