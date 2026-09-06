// 变更点：
//  P1-6：导出失败不再仅 console.error —— 新增 exportError 状态渲染错误 Alert，
//        整份报告导出与拖库数据导出共用提示位，让用户感知失败原因。
//  P1-4（顺带）：store 订阅改为按需选择器（scanId / report 各自订阅），
//        避免本组件随 SSE 事件（events 数组变化）无谓重渲染。
//  [P0-FIX] 移除误导性 3×3 AI 模型选择器：后端 generateAiReport 始终使用固定 3 角色流水线
//  (analyst→writer→reviewer)，忽略请求中的 keyIndex/modelIndex。改为简单按钮+流水线说明。

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Box, Typography, Alert, CircularProgress, Paper } from '@mui/material';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';
import { useScan } from '../hooks/useScan';
import { useScanStore } from '../store/scanStore';
import { tauriBridge } from '../shared/tauriBridge';
import { hasDumpData, dumpToCsv, dumpToJson } from '../shared/dumpExport';
import { apiClient } from '../shared/apiClient';

// 报告导出：JSON / HTML / CSV / Markdown（整份报告）
export type ExportFormat = 'json' | 'html' | 'csv' | 'markdown' | 'db-json';

export default function ReportExport() {
  const { t } = useTranslation();
  const { exportReport } = useScan();
  // P1-4：按需选择器订阅
  const scanId = useScanStore((s) => s.scanId);
  const report = useScanStore((s) => s.report);
  // P1-6：导出失败提示
  const [exportError, setExportError] = useState('');
  // AI 报告生成状态
  const [aiLoading, setAiLoading] = useState(false);
  const [aiContent, setAiContent] = useState('');
  const [aiModel, setAiModel] = useState('');
  const [aiError, setAiError] = useState('');

  const handleExport = (format: ExportFormat) => {
    if (!scanId) return;
    setExportError('');
    exportReport(scanId, format).catch((err) => {
      const detail = err instanceof Error ? err.message : t('common.unknownError');
      console.error(t('reportExport.exportReportFailed', { detail }), err);
      // P1-6：失败给出用户可见提示（原来仅 console.error）
      setExportError(t('reportExport.exportReportFailed', { detail }));
    });
  };

  // P2-S7：拖库数据单独导出（CSV/JSON）。纯客户端生成，不依赖后端会话存活
  // （历史回溯快照也可导出）。仅在存在拖库数据时可用。
  const dumpData = report?.data ?? null;
  const canExportDump = hasDumpData(dumpData);

  const handleDumpExport = (format: 'csv' | 'json') => {
    if (!dumpData || !canExportDump) return;
    setExportError('');
    const content = format === 'csv' ? dumpToCsv(dumpData) : dumpToJson(dumpData);
    const mime =
      format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json; charset=utf-8';
    const ext = format === 'csv' ? 'dump.csv' : 'dump.json';
    tauriBridge.saveFile(`dump_${report!.scanId}.${ext}`, content, mime).catch((err) => {
      const detail = err instanceof Error ? err.message : t('common.unknownError');
      console.error(t('reportExport.exportDumpFailed', { detail }), err);
      // P1-6：失败给出用户可见提示（原来仅 console.error）
      setExportError(t('reportExport.exportDumpFailed', { detail }));
    });
  };

  const handleAiReport = async () => {
    if (!scanId) return;
    setAiLoading(true);
    setAiError('');
    setAiContent('');
    try {
      // [P0-FIX] 不再传 keyIndex/modelIndex（后端忽略），走固定 3 角色流水线
      const result = await apiClient.report.ai(scanId);
      if (result.success) {
        setAiContent(result.content);
        setAiModel(result.model);
      } else {
        setAiError(t('reportExport.aiFailed'));
      }
    } catch (e: unknown) {
      setAiError(e instanceof Error ? e.message : t('common.unknownError'));
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <Box className="space-y-2">
      <Typography variant="subtitle2" fontWeight={600}>
        {t('reportExport.title')}
      </Typography>
      <Box className="flex gap-2 flex-wrap">
        <Button variant="contained" size="small" disabled={!scanId} onClick={() => handleExport('json')}>
          JSON
        </Button>
        <Button variant="outlined" size="small" disabled={!scanId} onClick={() => handleExport('html')}>
          HTML
        </Button>
        <Button variant="outlined" size="small" disabled={!scanId} onClick={() => handleExport('csv')}>
          CSV
        </Button>
        <Button variant="outlined" size="small" disabled={!scanId} onClick={() => handleExport('markdown')}>
          Markdown
        </Button>
      </Box>

      <Typography variant="subtitle2" fontWeight={600} sx={{ mt: 1 }}>
        {t('reportExport.dumpTitle')}
      </Typography>
      <Box className="flex gap-2 flex-wrap">
        <Button
          variant="outlined"
          size="small"
          disabled={!canExportDump}
          onClick={() => handleDumpExport('csv')}
        >
          {t('reportExport.dumpCsv')}
        </Button>
        <Button
          variant="outlined"
          size="small"
          disabled={!canExportDump}
          onClick={() => handleDumpExport('json')}
        >
          {t('reportExport.dumpJson')}
        </Button>
        {/* 后端 db-json（完整拖库快照，含分页续拉数据；客户端版无需后端会话但结构近似） */}
        <Button
          variant="outlined"
          size="small"
          disabled={!scanId}
          onClick={() => handleExport('db-json' as ExportFormat)}
        >
          {t('reportExport.dumpDbJson')}
        </Button>
      </Box>
      {!canExportDump && (
        <Typography variant="caption" color="text.secondary">
          {t('reportExport.noDumpData')}
        </Typography>
      )}

      {/* P1-6：导出失败提示（整份报告与拖库数据共用） */}
      {exportError && (
        <Alert severity="error" variant="outlined">
          {exportError}
        </Alert>
      )}

      {/* AI 漏洞报告生成 */}
      <Typography variant="subtitle2" fontWeight={600} sx={{ mt: 2 }}>
        {t('reportExport.aiTitle')}
      </Typography>
      <Box className="flex gap-2 items-center flex-wrap">
        {/* [P0-FIX] 移除误导性 3×3 选择器：后端为固定 3 角色流水线（analyst→writer→reviewer），
            无用户可选 key/model 组合；保留说明文案并直接生成。 */}
        <Button
          variant="contained"
          size="small"
          disabled={!scanId || aiLoading}
          onClick={handleAiReport}
          startIcon={aiLoading ? <CircularProgress size={16} /> : <AutoAwesomeIcon />}
        >
          {aiLoading ? t('reportExport.aiGenerating') : t('reportExport.aiAnalyze')}
        </Button>
      </Box>
      {aiError && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1 }}>
          {aiError}
        </Alert>
      )}
      {aiContent && (
        <Paper variant="outlined" sx={{ p: 2, mt: 1, maxHeight: 400, overflow: 'auto' }}>
          <Typography variant="caption" color="text.secondary">
            {t('reportExport.aiModelLabel', { model: aiModel })}
          </Typography>
          <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', mt: 1 }}>
            {aiContent}
          </Typography>
        </Paper>
      )}
    </Box>
  );
}