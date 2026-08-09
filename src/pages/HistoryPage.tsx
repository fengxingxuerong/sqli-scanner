import { useEffect, useMemo, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Paper,
  Typography,
  List,
  ListItemButton,
  ListItemText,
  ListItemSecondaryAction,
  Chip,
  Button,
  IconButton,
  Divider,
  TextField,
  FormControl,
  InputAdornment,
  InputLabel,
  Select,
  MenuItem,
  Pagination,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import ClearIcon from '@mui/icons-material/Clear';
import { useScanStore } from '../store/scanStore';
import { RISK_LABEL, RISK_LEVELS } from '../shared/constants';
import type { RiskLevel } from '../shared/types';
import { Highlight } from '../components/Highlight';

// 单页展示条数（历史上限 100，分页避免长列表一次渲染）
const PAGE_SIZE = 10;

// 历史页：读取持久化历史（含完整报告快照），支持回溯与删除。
// 工具栏：scanId / 目标URL 文本搜索 + 风险等级筛选；列表分页。
export default function HistoryPage() {
  const navigate = useNavigate();
  const { history, setReport, removeHistory } = useScanStore();
  const [query, setQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<'All' | RiskLevel>('All');
  const searchRef = useRef<HTMLInputElement>(null);
  // 快捷键：按 / 聚焦搜索框
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
  }, []);
  const [page, setPage] = useState(0);

  useEffect(() => {
    // 历史为本地持久化，无需额外加载
  }, []);

  // 搜索/筛选变化 → 回到第一页，避免停留在越界页
  useEffect(() => {
    setPage(0);
  }, [query, riskFilter]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return history.filter((h) => {
      const targetUrl = h.report?.target?.baseUrl ?? h.target ?? '';
      const risk = h.report?.riskLevel ?? h.riskLevel ?? 'Low';
      const matchQ = !q || h.scanId.toLowerCase().includes(q) || targetUrl.toLowerCase().includes(q);
      const matchR = riskFilter === 'All' || risk === riskFilter;
      return matchQ && matchR;
    });
  }, [history, query, riskFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages - 1);
  const paged = filtered.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE);

  const renderList = (items: typeof history) => (
    <Paper variant="outlined">
      <List dense>
        {items.map((h, idx) => {
          const targetUrl = h.report?.target?.baseUrl ?? h.target ?? '(未知目标)';
          const risk = h.report?.riskLevel ?? h.riskLevel ?? 'Low';
          return (
            <Box key={h.scanId}>
              {idx > 0 && <Divider component="li" />}
              <ListItemButton
                onClick={() => {
                  if (h.report) setReport(h.report);
                  navigate(`/report/${h.scanId}`);
                }}
              >
                <ListItemText
                  primary={
                    <span className="font-mono text-sm">
                      <Highlight text={h.scanId} query={query} />
                    </span>
                  }
                  secondary={<Highlight text={targetUrl} query={query} />}
                />
                <Chip label={`风险 ${RISK_LABEL[risk] ?? risk}`} size="small" className="mr-2" />
                <ListItemSecondaryAction>
                  <IconButton
                    edge="end"
                    aria-label="删除"
                    onClick={() => removeHistory(h.scanId)}
                  >
                    <DeleteIcon />
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItemButton>
            </Box>
          );
        })}
      </List>
    </Paper>
  );

  return (
    <Container maxWidth="md" className="py-6">
      <Box className="flex items-center justify-between mb-4">
        <Typography variant="h5" fontWeight={700}>
          历史扫描
        </Typography>
        <Box className="flex gap-2">
          <Button variant="outlined" size="small" onClick={() => navigate('/diff')}>
            对比报告
          </Button>
          <Button variant="text" onClick={() => navigate('/scan')}>
            新建扫描 →
          </Button>
        </Box>
      </Box>

      {/* 工具栏：搜索 + 风险筛选 */}
      <Box className="flex flex-col sm:flex-row gap-2 mb-4">
        <TextField
          size="small"
          fullWidth
          label="搜索 scanId / 目标 URL"
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
                  aria-label="清除搜索"
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
        <Box className="flex items-center gap-1">
          <FormControl size="small" sx={{ minWidth: 140 }}>
            <InputLabel id="risk-filter-label">风险等级</InputLabel>
            <Select
              labelId="risk-filter-label"
              label="风险等级"
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value as 'All' | RiskLevel)}
            >
              <MenuItem value="All">全部</MenuItem>
              {RISK_LEVELS.map((lv) => (
                <MenuItem key={lv} value={lv}>
                  {RISK_LABEL[lv]}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          {riskFilter !== 'All' && (
            <IconButton
              aria-label="清除风险筛选"
              size="small"
              onClick={() => setRiskFilter('All')}
            >
              <ClearIcon fontSize="small" />
            </IconButton>
          )}
        </Box>
      </Box>

      {history.length === 0 ? (
        <Typography color="text.secondary">暂无历史记录</Typography>
      ) : filtered.length === 0 ? (
        <Typography color="text.secondary">无匹配记录（请调整搜索词或风险筛选）</Typography>
      ) : (
        <Box className="space-y-3">
          <Typography variant="caption" color="text.secondary">
            共 {filtered.length} 条匹配（每页 {PAGE_SIZE} 条，第 {safePage + 1}/{totalPages} 页）
          </Typography>
          {renderList(paged)}
          {totalPages > 1 && (
            <Box className="flex justify-center">
              <Pagination
                count={totalPages}
                page={safePage + 1}
                onChange={(_, p) => setPage(p - 1)}
                color="primary"
                showFirstButton
                showLastButton
              />
            </Box>
          )}
        </Box>
      )}
    </Container>
  );
}
