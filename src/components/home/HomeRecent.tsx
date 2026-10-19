// ============================================================================
// HomeRecent —— 首页「最近扫描」列表（D107 桌面端 UI 全面优化）
//
// 有记录时是快捷回溯入口（点整行进报告），无记录时是空态引导。
// 列表项补「查看报告」按钮与风险色条：整行可点这件事不写出来没人知道。
// ============================================================================
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Box, Button, Chip, Divider, Stack, Typography } from '@mui/material';
import HistoryIcon from '@mui/icons-material/History';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CyberPanel from '../cyber/CyberPanel';
import i18n from '../../i18n';
import type { HistoryRecord, RiskLevel } from '../../shared/types';

/** 风险等级 → Chip 语义色（与 HistoryPage 保持同一映射口径） */
const RISK_CHIP_COLOR: Record<RiskLevel, 'error' | 'warning' | 'info' | 'success'> = {
  Critical: 'error',
  High: 'warning',
  Medium: 'info',
  Low: 'success',
};

/** 风险等级 → 条目左侧色条取色 */
const RISK_BAR: Record<RiskLevel, string> = {
  Critical: 'var(--cy-magenta)',
  High: 'var(--cy-amber)',
  Medium: 'var(--cy-cyan)',
  Low: 'var(--cy-lime)',
};

function formatTime(iso: string | null): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const locale = i18n.language.startsWith('zh') ? 'zh-CN' : 'en-US';
  return d.toLocaleString(locale, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

interface HomeRecentProps {
  /** 已裁剪好的最近记录（调用方决定条数上限） */
  rows: HistoryRecord[];
  /** 是否存在历史记录（决定空态渲染） */
  hasHistory: boolean;
}

export default function HomeRecent({ rows, hasHistory }: HomeRecentProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const goto = (scanId: string) => navigate(`/report/${scanId}`);

  return (
    <CyberPanel
      title={t('home.recentScans')}
      desc={t('home.recentScansDesc')}
      icon={<HistoryIcon />}
      dense
      actions={
        hasHistory ? (
          <Button size="small" endIcon={<ArrowForwardIcon />} onClick={() => navigate('/history')}>
            {t('home.viewAll')}
          </Button>
        ) : undefined
      }
    >
      {!hasHistory ? (
        <Box sx={{ p: 3, textAlign: 'center' }}>
          <HistoryIcon sx={{ fontSize: 40, color: 'text.disabled', mb: 1 }} />
          <Typography color="text.secondary">{t('home.empty')}</Typography>
        </Box>
      ) : (
        <Box>
          {rows.map((h, idx) => {
            const risk: RiskLevel = h.report?.riskLevel ?? h.riskLevel ?? 'Low';
            const targetUrl = h.report?.target?.baseUrl ?? h.target ?? t('home.unknownTarget');
            return (
              <Box key={h.scanId}>
                {idx > 0 && <Divider sx={{ borderColor: 'var(--cy-line)' }} />}
                <Box
                  onClick={() => goto(h.scanId)}
                  role="button"
                  tabIndex={0}
                  aria-label={`${t('home.viewAll')} ${targetUrl}`}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      goto(h.scanId);
                    }
                  }}
                  sx={{
                    px: 1.5,
                    py: 1.5,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 2,
                    flexWrap: 'wrap',
                    borderLeft: `2px solid ${RISK_BAR[risk]}`,
                    pl: 1.5,
                    transition: 'background-color 0.15s ease, transform 0.15s ease',
                    '&:hover': {
                      bgcolor: 'action.hover',
                      transform: 'translateX(2px)',
                    },
                  }}
                >
                  <Box sx={{ minWidth: 0, flex: 1 }}>
                    <Typography variant="body1" noWrap fontWeight={600}>
                      {targetUrl}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" className="mono">
                      {h.scanId} · {formatTime(h.finishedAt)}
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
                    <Button size="small" endIcon={<ArrowForwardIcon />} onClick={(e) => { e.stopPropagation(); goto(h.scanId); }}>
                      {t('history.view')}
                    </Button>
                  </Stack>
                </Box>
              </Box>
            );
          })}
        </Box>
      )}
    </CyberPanel>
  );
}
