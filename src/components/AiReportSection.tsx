// AI 报告区块（[D275] 从 ReportExport 抽出）：
//   ① 主组件 ReportExport 已贴复杂度基线，AI 提示/状态继续内联会让行数棘轮失效；
//   ② 这里只负责「生成 + 如实展示」：partial / ⚠️ 未审阅 / cached 必须显式提示，
//      不能只把正文渲染出来让读者以为这是完整报告。
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Box, Typography, Alert, CircularProgress, Paper } from '@mui/material';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';
import { apiClient } from '../shared/apiClient';

/**
 * 报告正文与来源标注（含 cached / 审阅状态）。
 * @param {{model:string,content:string,reviewNote:string,cached:boolean}} props 展示事实
 * @returns {JSX.Element} 正文卡片
 */
function AiReportResult({ model, content, reviewNote, cached }: {
  model: string;
  content: string;
  reviewNote: string;
  cached: boolean;
}) {
  const { t } = useTranslation();
  return (
    <Paper variant="outlined" sx={{ p: 2, mt: 1, maxHeight: 400, overflow: 'auto' }}>
      <Typography variant="caption" color="text.secondary">
        {t('reportExport.aiModelLabel', { model })}
        {cached ? ` · ${t('reportExport.aiCached')}` : ''}
      </Typography>
      {reviewNote && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
          {reviewNote}
        </Typography>
      )}
      <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', mt: 1 }}>
        {content}
      </Typography>
    </Paper>
  );
}

/**
 * AI 漏洞报告生成与展示。
 * @param {{scanId: string|null}} props 当前扫描 id（null 时按钮禁用）
 * @returns {JSX.Element} AI 报告区块
 */
export default function AiReportSection({ scanId }: { scanId: string | null }) {
  const { t } = useTranslation();
  const [aiLoading, setAiLoading] = useState(false);
  const [aiContent, setAiContent] = useState('');
  const [aiModel, setAiModel] = useState('');
  const [aiReviewNote, setAiReviewNote] = useState('');
  const [aiPartial, setAiPartial] = useState(false);
  const [aiCached, setAiCached] = useState(false);
  const [aiError, setAiError] = useState('');

  const handleAiReport = async () => {
    if (!scanId) return;
    setAiLoading(true);
    setAiError('');
    setAiContent('');
    setAiReviewNote('');
    setAiPartial(false);
    setAiCached(false);
    try {
      // [P0-FIX] 不再传 keyIndex/modelIndex（后端忽略），走固定 3 角色流水线
      const result = await apiClient.report.ai(scanId);
      if (result.success) {
        setAiContent(result.content);
        setAiModel(result.model);
        setAiReviewNote(result.reviewNote || '');
        // [D275] 半成品/未审阅必须在 UI 显式提示，不能只把 reviewNote 藏起来
        setAiPartial(Boolean(result.stepwise?.partial) || /⚠️/.test(result.reviewNote || ''));
        setAiCached(Boolean(result.cached));
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
    <>
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
      {aiPartial && (
        <Alert severity="warning" variant="outlined" sx={{ mt: 1 }}>
          {t('reportExport.aiPartialWarning')}
        </Alert>
      )}
      {aiContent && (
        <AiReportResult
          model={aiModel}
          content={aiContent}
          reviewNote={aiReviewNote}
          cached={aiCached}
        />
      )}
    </>
  );
}
