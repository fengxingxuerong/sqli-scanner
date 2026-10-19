// 历史记录单行卡片。
// [D109] 从 HistoryPage.tsx 拆出：HistoryPage 曾 170 行 / 29 复杂度，
// 超过存量基线（161 / 28）。数据合并与续跑/删除动作仍由父页负责。

import type { MouseEvent } from 'react';
import {
  Card, CardContent, Chip, IconButton, Button, Grid, Stack, Typography,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import ReplayIcon from '@mui/icons-material/Replay';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import { useTranslation } from 'react-i18next';
import type { MergedHistoryRow } from '../shared/historyMerge';
import i18n from '../i18n';
import type { HistoryRecord, RiskLevel } from '../shared/types';

const RISK_COLORS: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
  Critical: 'error',
  High: 'warning',
  Medium: 'info',
  Low: 'success',
};

/** [D107] 风险等级 → 卡片左侧色条取色（与首页最近记录同一套语义色） */
const RISK_BAR: Record<string, string> = {
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

interface HistoryRowCardProps {
  row: MergedHistoryRow;
  canResume: (h?: HistoryRecord) => boolean;
  onResume: (row: MergedHistoryRow) => void;
  onDelete: (e: MouseEvent, scanId: string) => void;
  onGoto: (scanId: string) => void;
}

export default function HistoryRowCard({
  row, canResume, onResume, onDelete, onGoto,
}: HistoryRowCardProps) {
  const { t } = useTranslation();
  const risk: RiskLevel | null = row.riskLevel;
  const targetUrl = row.target || t('history.unknownTarget');
  const isSqlmap = row.local?.report?.engine === 'sqlmap';
  const meta = SOURCE_LABEL[row.source];

  return (
    <Card
      variant="outlined"
      className="cursor-pointer cyber-panel"
      sx={{
        borderRadius: 1.5,
        borderLeft: risk ? `3px solid ${RISK_BAR[risk]}` : undefined,
        transition: 'box-shadow 0.2s ease, transform 0.15s ease, border-color 0.15s ease',
        '&:hover': { boxShadow: 3, transform: 'translateY(-1px)', borderColor: 'var(--cy-line-strong)' },
      }}
      onClick={() => onGoto(row.scanId)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onGoto(row.scanId);
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
                  onClick={(e) => { e.stopPropagation(); onResume(row); }}
                >
                  {t('history.resume')}
                </Button>
              )}
              <Button
                size="small"
                endIcon={<ArrowForwardIcon />}
                onClick={(e) => { e.stopPropagation(); onGoto(row.scanId); }}
              >
                {t('history.view')}
              </Button>
              {/* 只有本地条目删得掉：服务端没有 DELETE 端点，给按钮点了没反应等于骗人 */}
              {row.local && (
                <IconButton
                  size="small"
                  color="default"
                  aria-label={t('history.delete')}
                  onClick={(e) => onDelete(e, row.scanId)}
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
}
