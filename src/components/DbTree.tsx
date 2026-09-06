import { useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { ReactNode, KeyboardEvent } from 'react';
import {
  Box,
  Typography,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  Paper,
  IconButton,
  Button,
  Alert,
  TablePagination,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import type { ExtractedData } from '../shared/types';
import { tableToCsv, tableToJson } from '../shared/dumpExport';
import { tauriBridge } from '../shared/tauriBridge';

// 递归树节点：数据库 → 表 → 列 / 数据
// actions（可选）：节点行尾操作区（如单表导出按钮），点击不触发节点折叠。
// defaultOpen（可选）：初始展开态，配合 key 变化可在搜索态自动展开。
function Node({
  label,
  children,
  actions,
  badge,
  defaultOpen,
}: {
  label: string;
  children: ReactNode;
  actions?: ReactNode;
  badge?: ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen ?? false);
  const { t } = useTranslation();

  const handleKeyDown = useCallback((e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setOpen((o) => !o);
      return;
    }
    if (e.key === 'ArrowRight' && !open) {
      e.preventDefault();
      setOpen(true);
      return;
    }
    if (e.key === 'ArrowLeft' && open) {
      e.preventDefault();
      setOpen(false);
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const tree = e.currentTarget.closest('[role="tree"]');
      if (!tree) return;
      const allItems = Array.from(tree.querySelectorAll('[role="treeitem"]'));
      const idx = allItems.indexOf(e.currentTarget);
      const next = e.key === 'ArrowDown' ? allItems[idx + 1] : allItems[idx - 1];
      if (next) (next as HTMLElement).focus();
    }
  }, [open]);

  return (
    <Box className="ml-1">
      <Box
        className="flex items-center gap-1 cursor-pointer select-none"
        onClick={() => setOpen((o) => !o)}
        onKeyDown={handleKeyDown}
        role="treeitem"
        tabIndex={0}
        aria-expanded={open}
      >
        <IconButton size="small" className="!p-0" aria-label={open ? t('common.collapse') : t('common.expand')}>
          {open ? <ExpandMoreIcon fontSize="small" /> : <ChevronRightIcon fontSize="small" />}
        </IconButton>
        <Typography variant="body2">{label}</Typography>
        {badge && <Box className="ml-1">{badge}</Box>}
        {actions && (
          <Box className="ml-1" onClick={(e) => e.stopPropagation()}>
            {actions}
          </Box>
        )}
      </Box>
      {open && <Box className="ml-4 border-l border-gray-200 pl-2" role="group">{children}</Box>}
    </Box>
  );
}

// 文件名安全化：表键形如 "db.table"，剔除 Windows 保留字符
function safeFileName(tableKey: string): string {
  return tableKey.replace(/[\\/:*?"<>|]/g, '_');
}

// 行数徽章（纯 CSS，无新依赖）：表节点标题旁的行数标记
function RowCountBadge({ label }: { label: string }) {
  return (
    <span
      style={{
        padding: '0 6px',
        fontSize: 11,
        lineHeight: '16px',
        borderRadius: 8,
        background: 'rgba(25, 118, 210, 0.12)',
        color: '#1976d2',
        fontWeight: 600,
        whiteSpace: 'nowrap',
      }}
    >
      {label}
    </span>
  );
}

// 数据表分页组件：每表独立分页状态（rows 切片显示，支持翻页/页大小调整），
// 替代原硬编码 rows.slice(0,20)——大表拖库数据可完整浏览。
function DataTable({ rows, cols }: { rows: Array<Record<string, unknown> | object>; cols: string[] }) {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  if (!rows || rows.length === 0) return null;
  const total = rows.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(page, pageCount - 1);
  const start = safePage * pageSize;
  const slice = rows.slice(start, start + pageSize);
  return (
    <Box>
      <Table size="small">
        <TableHead>
          <TableRow>
            {cols.map((c, i) => (
              <TableCell key={i}>{String(c).split(':')[0]}</TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {slice.map((r, ri) => (
            <TableRow key={start + ri}>
              {cols.map((c, ci) => (
                <TableCell key={ci}>
                  {String((r as Record<string, unknown>)[String(c).split(':')[0]] ?? '')}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <TablePagination
        component="div"
        count={total}
        page={safePage}
        onPageChange={(_, p) => setPage(p)}
        rowsPerPage={pageSize}
        onRowsPerPageChange={(e) => {
          setPageSize(parseInt(e.target.value, 10));
          setPage(0);
        }}
        rowsPerPageOptions={[10, 20, 50, 100]}
        labelRowsPerPage=""
        labelDisplayedRows={({ from, to, count }) => `${from}-${to} / ${count}`}
        sx={{ '& .MuiTablePagination-spacer': { display: 'none' } }}
      />
    </Box>
  );
}

// 库/表/列/数据 树形展示（递归，无第三方树组件依赖）
export default function DbTree({ data }: { data: ExtractedData | null }) {
  const { t } = useTranslation();
  const [exportError, setExportError] = useState('');
  const [query, setQuery] = useState('');

  // 快速搜索过滤：大小写不敏感匹配库名 / 表名
  const queryLower = query.trim().toLowerCase();
  const queryActive = queryLower !== '';

  // useMemo 必须在条件 return 之前调用（React Hooks 规则）
  const filtered = useMemo(() => {
    if (!data || data.databases.length === 0) return [];
    if (!queryActive) {
      return data.databases.map((db) => ({ db, tables: data.tables[db] || [] }));
    }
    return data.databases
      .filter((db) => {
        const tables = data.tables[db] || [];
        return db.toLowerCase().includes(queryLower) || tables.some((tbl) => tbl.toLowerCase().includes(queryLower));
      })
      .map((db) => ({
        db,
        tables: (data.tables[db] || []).filter(
          (tbl) => db.toLowerCase().includes(queryLower) || tbl.toLowerCase().includes(queryLower),
        ),
      }));
  }, [data, queryLower, queryActive]);

  // 空态优化：data 为空时给出更友好的提示（在 hooks 之后 return 不违反规则）
  if (!data || data.databases.length === 0) {
    return (
      <Box className="space-y-1" role="tree" aria-label={t('dbTree.treeLabel')}>
        <Typography variant="body2" color="text.secondary">
          {t('dbTree.noData')}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {t('dbTree.emptyHint')}
        </Typography>
      </Box>
    );
  }

  // 单表导出（S7/G15）：纯前端从当前 report.data 切片生成下载，不依赖后端会话存活。
  const handleTableExport = (format: 'csv' | 'json', tableKey: string) => {
    setExportError('');
    const content = format === 'csv' ? tableToCsv(data, tableKey) : tableToJson(data, tableKey);
    const mime =
      format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json; charset=utf-8';
    tauriBridge.saveFile(`table_${safeFileName(tableKey)}.${format}`, content, mime).catch((err) => {
      const detail = err instanceof Error ? err.message : t('common.unknownError');
      console.error(t('dbTree.exportTableFailed', { detail }), err);
      setExportError(t('dbTree.exportTableFailed', { detail }));
    });
  };

  return (
    <Box className="space-y-2" role="tree" aria-label={t('dbTree.treeLabel')}>
      <Typography variant="subtitle2" fontWeight={600}>
        {t('dbTree.treeLabel')}
      </Typography>
      {/* 快速搜索过滤 */}
      <input
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder={t('dbTree.searchPlaceholder')}
        aria-label={t('dbTree.searchPlaceholder')}
        className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:outline-none focus:border-blue-500"
      />
      {exportError && (
        <Alert severity="error" variant="outlined">
          {exportError}
        </Alert>
      )}
      {filtered.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          {t('dbTree.noMatch')}
        </Typography>
      )}
      {filtered.map(({ db, tables }) => {
        return (
          <Node
            key={`${db}-${queryActive}`}
            defaultOpen={queryActive}
            label={t('dbTree.database', { name: db })}
          >
            {tables.map((table) => {
              const key = `${db}.${table}`;
              const cols = data.columns[key] || [];
              const rows = data.rows[key] || [];
              return (
                <Node
                  key={`${table}-${queryActive}`}
                  defaultOpen={queryActive}
                  label={t('dbTree.table', { name: table })}
                  badge={
                    <RowCountBadge
                      label={t('dbTree.rowCountBadge', { count: rows.length })}
                    />
                  }
                  actions={
                    <Box className="flex items-center gap-0.5">
                      <Button
                        size="small"
                        variant="text"
                        className="!min-w-0 !px-1 !text-xs"
                        title={t('dbTree.exportCsvTitle', { table })}
                        onClick={() => handleTableExport('csv', key)}
                      >
                        {t('dbTree.exportCsv')}
                      </Button>
                      <Button
                        size="small"
                        variant="text"
                        className="!min-w-0 !px-1 !text-xs"
                        title={t('dbTree.exportJsonTitle', { table })}
                        onClick={() => handleTableExport('json', key)}
                      >
                        {t('dbTree.exportJson')}
                      </Button>
                      {/* 导出按钮增强：行数统计标签 */}
                      <Typography
                        component="span"
                        variant="caption"
                        color="text.secondary"
                        className="!ml-1"
                      >
                        {t('dbTree.exportRowCount', { count: rows.length })}
                      </Typography>
                    </Box>
                  }
                >
                  <Node label={t('dbTree.columns', { count: cols.length })}>
                    <Typography variant="caption">{cols.join(' , ') || 'unknown'}</Typography>
                    {/* 数据预览列：列名下方显示前 2 行（逗号分隔） */}
                    {rows.length > 0 && (
                      <Box className="mt-1">
                        <Typography variant="caption" color="text.secondary">
                          {t('dbTree.previewRowsLabel')}
                        </Typography>
                        {rows.slice(0, 2).map((r, ri) => (
                          <Typography key={ri} variant="caption" className="block">
                            {cols
                              .map((c) =>
                                String(
                                  (r as Record<string, unknown>)[String(c).split(':')[0]] ?? '',
                                ),
                              )
                              .join(', ')}
                          </Typography>
                        ))}
                      </Box>
                    )}
                  </Node>
                  <Node label={t('dbTree.dataPreview')}>
                    <Box className="p-2">
                      {rows.length > 0 ? (
                        <DataTable rows={rows} cols={cols} />
                      ) : (
                        <Typography variant="caption">{t('dbTree.noRows')}</Typography>
                      )}
                    </Box>
                  </Node>
                </Node>
              );
            })}
          </Node>
        );
      })}
      <Paper variant="outlined" className="p-2">
        <Typography variant="caption" color="text.secondary">
          {t('dbTree.summary', { count: data.databases.length })}
        </Typography>
      </Paper>
    </Box>
  );
}
