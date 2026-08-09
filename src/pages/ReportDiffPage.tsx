import { useMemo, useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Typography,
  Box,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Button,
  Alert,
  TextField,
  InputAdornment,
  IconButton,
} from '@mui/material';
import { useScanStore } from '../store/scanStore';
import { diffReports, diffToMarkdown, diffToJson, diffToCsv, type PointDiffEntry, type VulnDiffEntry } from '../shared/reportDiff';
import { TECHNIQUE_LABEL, RISK_LABEL } from '../shared/constants';
import { downloadText, downloadPdf } from '../shared/reportExport';
import type { ReportModel } from '../shared/types';
import ClearIcon from '@mui/icons-material/Clear';
import { Highlight } from '../components/Highlight';

// 状态 → 颜色
const STATUS_COLOR: Record<string, 'success' | 'error' | 'warning'> = {
  added: 'success',
  removed: 'error',
  changed: 'warning',
};
const STATUS_LABEL: Record<string, string> = { added: '新增', removed: '消失', changed: '变化' };

function changeText(changes: { field: string; before: string; after: string }[] | undefined): string {
  if (!changes || !changes.length) return '';
  return changes.map((c) => `${c.field}: ${c.before} → ${c.after}`).join('；');
}

// 差异搜索匹配：覆盖 标识/位置/技术/风险/变化说明
function pointMatches(p: PointDiffEntry, q: string): boolean {
  const hay = `${p.param} ${p.location} ${changeText(p.changes)}`.toLowerCase();
  return hay.includes(q.toLowerCase());
}
function vulnMatches(v: VulnDiffEntry, q: string): boolean {
  const r = v.vulnA || v.vulnB;
  const hay = `${v.param} ${TECHNIQUE_LABEL[v.technique] ?? v.technique} ${
    r ? (RISK_LABEL[r.riskLevel] ?? r.riskLevel) : ''
  } ${changeText(v.changes)}`.toLowerCase();
  return hay.includes(q.toLowerCase());
}

export default function ReportDiffPage() {
  const navigate = useNavigate();
  const { history } = useScanStore();
  // 仅保留含完整报告快照的记录
  const records = useMemo(() => history.filter((h) => h.report), [history]);

  const [aId, setAId] = useState('');
  const [bId, setBId] = useState('');
  const [query, setQuery] = useState('');
  const searchRef = useRef<HTMLInputElement>(null);
  // 快捷键：按 / 聚焦差异搜索框
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      const typing = !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
      if (e.key === '/' && !typing) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
    // 该 effect 仅挂载一次：query 不进依赖，避免每次输入重建监听
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const reportA: ReportModel | undefined = records.find((r) => r.scanId === aId)?.report;
  const reportB: ReportModel | undefined = records.find((r) => r.scanId === bId)?.report;

  const diff = useMemo(
    () => (reportA && reportB ? diffReports(reportA, reportB) : null),
    [reportA, reportB],
  );

  // 差异搜索：同源过滤两张表（注入点差异 + 漏洞差异）
  const filteredPoints = useMemo(() => {
    if (!diff) return [];
    const q = query.trim().toLowerCase();
    return q ? diff.points.filter((p) => pointMatches(p, q)) : diff.points;
  }, [diff, query]);
  const filteredVulns = useMemo(() => {
    if (!diff) return [];
    const q = query.trim().toLowerCase();
    return q ? diff.vulns.filter((v) => vulnMatches(v, q)) : diff.vulns;
  }, [diff, query]);

  const contentRef = useRef<HTMLDivElement>(null);
  const [pdfBusy, setPdfBusy] = useState(false);
  const [copied, setCopied] = useState<null | 'md' | 'csv'>(null);

  const handlePdf = async () => {
    if (!diff || !contentRef.current) return;
    setPdfBusy(true);
    try {
      await downloadPdf(contentRef.current, `diff-${aId}-vs-${bId}.pdf`);
    } catch (e) {
      console.error('差异报告 PDF 导出失败', e);
    } finally {
      setPdfBusy(false);
    }
  };

  const copyText = async (kind: 'md' | 'csv') => {
    if (!diff) return;
    const text = kind === 'md' ? diffToMarkdown(diff) : diffToCsv(diff);
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
      /* 剪贴板不可用时静默忽略 */
    }
  };

  return (
    <Container maxWidth="lg" className="py-6">
      <Box className="flex items-center justify-between mb-4">
        <Typography variant="h5" fontWeight={700}>
          报告对比
        </Typography>
        <Button variant="text" onClick={() => navigate('/history')}>
          历史 →
        </Button>
      </Box>

      {records.length < 2 ? (
        <Alert severity="info">
          历史记录中至少需要 2 份含完整快照的报告才能对比。请先在「历史」中保留至少两次扫描结果。
        </Alert>
      ) : (
        <>
          <Paper variant="outlined" className="p-3 mb-3">
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth size="small">
                  <InputLabel id="diff-a-label">基准报告 (A)</InputLabel>
                  <Select
                    labelId="diff-a-label"
                    label="基准报告 (A)"
                    value={aId}
                    onChange={(e) => setAId(e.target.value)}
                  >
                    {records.map((r) => (
                      <MenuItem key={r.scanId} value={r.scanId}>
                        {r.scanId} · {r.report?.target.baseUrl}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth size="small">
                  <InputLabel id="diff-b-label">对比报告 (B)</InputLabel>
                  <Select
                    labelId="diff-b-label"
                    label="对比报告 (B)"
                    value={bId}
                    onChange={(e) => setBId(e.target.value)}
                  >
                    {records.map((r) => (
                      <MenuItem key={r.scanId} value={r.scanId}>
                        {r.scanId} · {r.report?.target.baseUrl}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </Paper>

          {!diff ? (
            <Typography color="text.secondary">请选择两份报告（A 与 B）以查看差异。</Typography>
          ) : (
            <>
              <Box className="rp-no-print mb-3">
                <TextField
                  size="small"
                  fullWidth
                  label="搜索差异（参数 / 位置 / 技术 / 风险 / 变化）"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Escape') setQuery('');
                  }}
                  inputRef={searchRef}
                  InputProps={{
                    endAdornment: query ? (
                      <InputAdornment position="end">
                        <IconButton
                          aria-label="清除差异搜索"
                          size="small"
                          edge="end"
                          onMouseDown={(e) => e.preventDefault()}
                          onClick={() => setQuery('')}
                        >
                          <ClearIcon fontSize="small" />
                        </IconButton>
                      </InputAdornment>
                    ) : undefined,
                  }}
                />
              </Box>
              {query.trim() ? (
                <Typography variant="caption" color="text.secondary" className="rp-no-print">
                  注入点差异 命中 {filteredPoints.length} / {diff.points.length} · 漏洞差异 命中 {filteredVulns.length} / {diff.vulns.length}
                </Typography>
              ) : null}
              {query.trim() && filteredPoints.length === 0 && filteredVulns.length === 0 && (
                <Typography color="text.secondary" className="rp-no-print">无匹配差异（请调整搜索词）</Typography>
              )}
              <div ref={contentRef}>
              <Paper variant="outlined" className="p-3 mb-3">
                <Typography variant="subtitle2" fontWeight={700} className="mb-2">
                  概览
                </Typography>
                <Box className="flex flex-wrap gap-1 mb-2">
                  <Chip size="small" label={`基准: ${diff.targetA}`} variant="outlined" />
                  <Chip size="small" label={`对比: ${diff.targetB}`} variant="outlined" />
                </Box>
                <Box className="flex flex-wrap gap-1">
                  <Chip size="small" color="success" label={`注入点新增 ${diff.summary.pointsAdded}`} />
                  <Chip size="small" color="error" label={`注入点消失 ${diff.summary.pointsRemoved}`} />
                  <Chip size="small" color="warning" label={`注入点变化 ${diff.summary.pointsChanged}`} />
                  <Chip size="small" color="success" label={`漏洞新增 ${diff.summary.vulnsAdded}`} />
                  <Chip size="small" color="error" label={`漏洞消失 ${diff.summary.vulnsRemoved}`} />
                  <Chip size="small" color="warning" label={`漏洞变化 ${diff.summary.vulnsChanged}`} />
                </Box>
                <Box className="flex flex-wrap gap-2 mt-2 rp-no-print">
                  <Button
                    size="small"
                    variant="outlined"
                    disabled={!diff}
                    onClick={() => downloadText(`diff-${aId}-vs-${bId}.md`, diffToMarkdown(diff!), 'text/markdown;charset=utf-8')}
                  >
                    导出差异 Markdown
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    disabled={!diff}
                    onClick={() => downloadText(`diff-${aId}-vs-${bId}.json`, diffToJson(diff!), 'application/json;charset=utf-8')}
                  >
                    导出差异 JSON
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    disabled={!diff}
                    onClick={() => downloadText(`diff-${aId}-vs-${bId}.csv`, diffToCsv(diff!), 'text/csv;charset=utf-8')}
                  >
                    导出差异 CSV
                  </Button>
                  <Button
                    size="small"
                    variant="contained"
                    color="secondary"
                    disabled={!diff || pdfBusy}
                    onClick={handlePdf}
                  >
                    {pdfBusy ? '生成 PDF…' : '导出差异 PDF'}
                  </Button>
                  <Button size="small" variant="text" disabled={!diff} onClick={() => copyText('md')}>
                    {copied === 'md' ? '已复制 ✓' : '复制 Markdown'}
                  </Button>
                  <Button size="small" variant="text" disabled={!diff} onClick={() => copyText('csv')}>
                    {copied === 'csv' ? '已复制 ✓' : '复制 CSV'}
                  </Button>
                </Box>
              </Paper>

              <Paper variant="outlined" className="p-3 mb-3">
                <Typography variant="subtitle2" fontWeight={700} className="mb-2">
                  注入点差异
                </Typography>
                <DiffTable
                  rows={filteredPoints}
                  emptyHint={query.trim() ? '无匹配的注入点差异' : undefined}
                  render={(d: PointDiffEntry) => (
                    <>
                      <TableCell><Highlight text={d.param} query={query} /></TableCell>
                      <TableCell><Highlight text={d.location} query={query} /></TableCell>
                      <TableCell><Highlight text={changeText(d.changes)} query={query} /></TableCell>
                    </>
                  )}
                />
              </Paper>

              <Paper variant="outlined" className="p-3 mb-3">
                <Typography variant="subtitle2" fontWeight={700} className="mb-2">
                  漏洞差异
                </Typography>
                <DiffTable
                  rows={filteredVulns}
                  emptyHint={query.trim() ? '无匹配的漏洞差异' : undefined}
                  render={(d: VulnDiffEntry) => (
                    <>
                      <TableCell><Highlight text={d.param} query={query} /></TableCell>
                      <TableCell><Highlight text={TECHNIQUE_LABEL[d.technique] ?? d.technique} query={query} /></TableCell>
                      <TableCell>
                        {d.vulnA || d.vulnB
                          ? <Highlight text={RISK_LABEL[(d.vulnA || d.vulnB)!.riskLevel] ?? (d.vulnA || d.vulnB)!.riskLevel} query={query} />
                          : ''}
                      </TableCell>
                      <TableCell><Highlight text={changeText(d.changes)} query={query} /></TableCell>
                    </>
                  )}
                />
              </Paper>
            </div>
            </>
          )}
        </>
      )}
    </Container>
  );
}

// 差异行底色：新增=绿 / 消失=红 / 变化=琥珀（行内高亮，便于一眼定位变动）
const ROW_TINT: Record<'added' | 'removed' | 'changed', string> = {
  added: '#e6f4ea',
  removed: '#fdecea',
  changed: '#fff4e5',
};

// 通用差异表：列出 状态 + 实体列（由 render 提供）+ 变化说明
function DiffTable<T extends { status: 'added' | 'removed' | 'changed' }>({
  rows,
  render,
  emptyHint,
}: {
  rows: T[];
  render: (row: T) => React.ReactNode;
  emptyHint?: string;
}) {
  if (rows.length === 0) {
    return <Typography variant="body2" color="text.secondary">{emptyHint ?? '无差异（两次扫描结果一致）。'}</Typography>;
  }
  return (
    <Table size="small">
      <TableHead>
        <TableRow>
          <TableCell>状态</TableCell>
          <TableCell>标识</TableCell>
          <TableCell>属性</TableCell>
          <TableCell>变化</TableCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {rows.map((row, i) => (
          <TableRow key={i} data-diff-status={row.status} sx={{ bgcolor: ROW_TINT[row.status] }}>
            <TableCell>
              <Chip size="small" color={STATUS_COLOR[row.status]} label={STATUS_LABEL[row.status]} />
            </TableCell>
            {render(row)}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
