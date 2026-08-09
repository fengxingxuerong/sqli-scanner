import { useState, type RefObject } from 'react';
import { Button, Box, Typography } from '@mui/material';
import { useScan } from '../hooks/useScan';
import { useScanStore } from '../store/scanStore';
import { reportToMarkdown, reportToCsv, downloadText, downloadPdf } from '../shared/reportExport';

// 报告导出：JSON / HTML（走后端 /export 端点）+ Markdown / CSV / PDF（纯前端生成）
// PDF 需要报告内容根的 DOM ref（由 ReportPage 传入，指向不含工具栏/导出区的报告主体）。
// 另提供「复制 Markdown / CSV」剪贴板快捷按钮：渗透测试常需把结果直接贴工单/聊天，比下载更顺手。
export default function ReportExport({ contentRef }: { contentRef?: RefObject<HTMLElement> }) {
  const { exportReport } = useScan();
  const { scanId, report } = useScanStore();
  const [pdfBusy, setPdfBusy] = useState(false);
  const [copied, setCopied] = useState<null | 'md' | 'csv'>(null);

  const handleExport = (format: 'json' | 'html') => {
    if (!scanId) return;
    // Web 版直接打开下载链接；Tauri 版也走同一链接（由桥接可改为落盘）
    exportReport(scanId, format);
  };

  // 纯前端生成：基于 store 中已加载的完整报告快照，不依赖后端
  const handleMarkdown = () => {
    if (!report) return;
    downloadText(`report-${report.scanId}.md`, reportToMarkdown(report), 'text/markdown;charset=utf-8');
  };
  const handleCsv = () => {
    if (!report) return;
    downloadText(`report-${report.scanId}.csv`, reportToCsv(report), 'text/csv;charset=utf-8');
  };

  // 复制文本到剪贴板：优先 navigator.clipboard（安全上下文），降级到 textarea + execCommand（http/localhost 等非 HTTPS）
  const copyText = async (kind: 'md' | 'csv') => {
    if (!report) return;
    const text = kind === 'md' ? reportToMarkdown(report) : reportToCsv(report);
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      setCopied(kind);
      setTimeout(() => setCopied(null), 2000);
    } catch {
      // 复制失败不阻塞页面（如浏览器禁用剪贴板权限），仅不显示「已复制」
    }
  };

  // PDF：栅格化报告内容根 → 多页 jsPDF（DOM 栅格化天然支持中文与拓扑图）
  const handlePdf = async () => {
    const node = contentRef?.current;
    if (!node || !report) return;
    try {
      setPdfBusy(true);
      await downloadPdf(node, `report-${report.scanId}.pdf`);
    } catch (e) {
      // 栅格化失败（如浏览器不支持）不阻塞页面，仅控制台记录
      console.error('PDF 导出失败：', e);
    } finally {
      setPdfBusy(false);
    }
  };

  const hasContent = !!contentRef?.current;

  return (
    <Box className="space-y-2">
      <Typography variant="subtitle2" fontWeight={600}>
        导出报告
      </Typography>
      <Box className="flex gap-2 flex-wrap">
        <Button variant="contained" size="small" disabled={!scanId} onClick={() => handleExport('json')}>
          导出 JSON
        </Button>
        <Button variant="outlined" size="small" disabled={!scanId} onClick={() => handleExport('html')}>
          导出 HTML
        </Button>
        <Button variant="outlined" size="small" disabled={!report} onClick={handleMarkdown}>
          导出 Markdown
        </Button>
        <Button variant="outlined" size="small" disabled={!report} onClick={handleCsv}>
          导出 CSV
        </Button>
        <Button
          variant="contained"
          size="small"
          color="secondary"
          disabled={!report || !hasContent || pdfBusy}
          onClick={handlePdf}
        >
          {pdfBusy ? '生成中…' : '导出 PDF'}
        </Button>
      </Box>
      <Box className="flex gap-2 flex-wrap">
        <Button
          size="small"
          variant="text"
          disabled={!report}
          onClick={() => copyText('md')}
        >
          {copied === 'md' ? '已复制 ✓' : '复制 Markdown'}
        </Button>
        <Button
          size="small"
          variant="text"
          disabled={!report}
          onClick={() => copyText('csv')}
        >
          {copied === 'csv' ? '已复制 ✓' : '复制 CSV'}
        </Button>
      </Box>
    </Box>
  );
}
