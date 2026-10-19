// 历史页 — 清新卡片式设计，统一新视觉风格
//
// [2026-09-29] 数据源改造：由「只读浏览器 localStorage」改为「服务端清单为主 + 本地兜底」。
//   此前服务端早就有 `GET /api/scans`（台账 + 在途合并），但本页没接 ⇒ 换机器/换浏览器/
//   清缓存/引擎重启，历史就空了 —— 而同一批扫描在 CLI 那边一直看得到。
//   降级纪律：服务端拿不到时**退回本地列表并如实提示**，不允许出现"比改造前更差"的白屏。

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Container, Button, Alert, Stack } from '@mui/material';
import HistoryIcon from '@mui/icons-material/History';
import TravelExploreIcon from '@mui/icons-material/TravelExplore';
import { useTranslation } from 'react-i18next';
import { useScanStore } from '../store/scanStore';
import { useScan } from '../hooks/useScan';
import { useServerHistory } from '../hooks/useServerHistory';
import { mergeHistory, type MergedHistoryRow } from '../shared/historyMerge';
import HistoryEmpty from '../components/HistoryEmpty';
import HistoryRowCard from '../components/HistoryRowCard';
import PageHeader from '../components/cyber/PageHeader';
import { buildResumeConfig } from '../shared/scanConfig';
import type { HistoryRecord } from '../shared/types';

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
      {/* 页面标题 —— [D107] 统一 PageHeader：图标 + 标题 + 一句话用途 + 右侧 CTA */}
      <PageHeader
        icon={<HistoryIcon />}
        title={t('history.title')}
        desc={t('history.subtitle', { count: rows.length })}
        actions={
          <Button
            size="small"
            variant="contained"
            startIcon={<TravelExploreIcon />}
            onClick={() => navigate('/scan')}
          >
            {t('history.firstScan')}
          </Button>
        }
      />

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
        <HistoryEmpty />
      ) : (
        <Stack spacing={2}>
          {rows.map((row) => (
            <HistoryRowCard
              key={row.scanId}
              row={row}
              canResume={canResume}
              onResume={handleResume}
              onDelete={handleDelete}
              onGoto={goto}
            />
          ))}
        </Stack>
      )}
    </Container>
  );
}
