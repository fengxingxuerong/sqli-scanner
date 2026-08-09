import { useState } from 'react';
import type { ReactNode } from 'react';
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
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import type { ExtractedData } from '../shared/types';
import { DUMP_ROW_LIMIT } from '../shared/constants';
import { Highlight } from './Highlight';

// 单表预览最多展示行数（UI 侧截断，与后端拖库上限 DUMP_ROW_LIMIT 区分）
const PREVIEW_ROWS = 20;
// 节点开合状态：key 为组合路径（db / db|t:table / ...|cols / ...|data）
type OpenMap = Record<string, boolean>;

// 枚举所有可控节点 key（用于「展开全部 / 收起全部」）
function buildKeys(data: ExtractedData): string[] {
  const keys: string[] = [];
  data.databases.forEach((db) => {
    const dbKey = `db:${db}`;
    keys.push(dbKey);
    (data.tables[db] || []).forEach((table) => {
      const tKey = `${dbKey}|t:${table}`;
      keys.push(tKey, `${tKey}|cols`, `${tKey}|data`);
    });
  });
  return keys;
}

// 默认：仅展开数据库层级（表/列/数据预览默认收起，避免大结果撑爆页面）
function buildDefaultOpen(data: ExtractedData): OpenMap {
  const m: OpenMap = {};
  data.databases.forEach((db) => {
    m[`db:${db}`] = true;
  });
  return m;
}

// 搜索过滤：表是否命中（表名 / 任一列名 / 任一单元格值，忽略大小写）
function tableMatches(db: string, table: string, data: ExtractedData, q: string): boolean {
  if (table.toLowerCase().includes(q)) return true;
  const key = `${db}.${table}`;
  const cols = data.columns[key] || [];
  if (cols.some((c) => c.toLowerCase().includes(q))) return true;
  const rows = data.rows[key] || [];
  return rows.some((r) =>
    cols.some((c) =>
      String((r as Record<string, unknown>)[String(c).split(':')[0]] ?? '')
        .toLowerCase()
        .includes(q),
    ),
  );
}

// 搜索过滤：数据库是否命中（库名 / 任一表命中）
function dbMatches(db: string, data: ExtractedData, q: string): boolean {
  if (db.toLowerCase().includes(q)) return true;
  return (data.tables[db] || []).some((t) => tableMatches(db, t, data, q));
}

// 库/表/列/数据 树形展示（受控开合，无第三方树组件依赖）
// search 非空时按 库名/表名/列名/单元格值 递归过滤（命中即保留子树）
export default function DbTree({ data, search }: { data: ExtractedData | null; search?: string }) {
  const [openMap, setOpenMap] = useState<OpenMap>(() => (data ? buildDefaultOpen(data) : {}));

  if (!data) {
    return <Typography variant="body2" color="text.secondary">暂无提取数据</Typography>;
  }

  const q = (search || '').trim().toLowerCase();
  const dbs = q ? data.databases.filter((db) => dbMatches(db, data, q)) : data.databases;

  const toggle = (key: string) => setOpenMap((m) => ({ ...m, [key]: !m[key] }));
  const allKeys = buildKeys(data);
  const expandAll = () => setOpenMap(Object.fromEntries(allKeys.map((k) => [k, true])));
  const collapseAll = () => setOpenMap(Object.fromEntries(allKeys.map((k) => [k, false])));

  // 受控节点：开合由顶层 openMap 决定，节点自身不再持有局部 state
  const renderNode = (key: string, label: ReactNode, children: ReactNode) => {
    const open = !!openMap[key];
    return (
      <Box className="ml-1" key={key}>
        <Box
          className="flex items-center gap-1 cursor-pointer select-none"
          onClick={() => toggle(key)}
          role="button"
          aria-expanded={open}
        >
          <IconButton size="small" className="!p-0">
            {open ? <ExpandMoreIcon fontSize="small" /> : <ChevronRightIcon fontSize="small" />}
          </IconButton>
          <Typography variant="body2">{label}</Typography>
        </Box>
        {open && <Box className="ml-4 border-l border-gray-200 pl-2">{children}</Box>}
      </Box>
    );
  };

  return (
    <Box className="space-y-2">
      <Box className="flex items-center justify-between">
        <Typography variant="subtitle2" fontWeight={600}>
          拖库数据树
        </Typography>
        <Box className="flex gap-2">
          <Button size="small" variant="outlined" onClick={expandAll}>
            展开全部
          </Button>
          <Button size="small" variant="outlined" onClick={collapseAll}>
            收起全部
          </Button>
        </Box>
      </Box>

      {dbs.map((db) => {
        const dbKey = `db:${db}`;
        const tables = q
          ? (data.tables[db] || []).filter((t) => tableMatches(db, t, data, q))
          : (data.tables[db] || []);
        return renderNode(
          dbKey,
          <>
            🗄 数据库 <Highlight text={db} query={search} />
          </>,
          tables.map((table) => {
            const tKey = `${dbKey}|t:${table}`;
            const key = `${db}.${table}`;
            const cols = data.columns[key] || [];
            const rows = data.rows[key] || [];
            return renderNode(
              tKey,
              <>
                📄 表 <Highlight text={table} query={search} /> ({rows.length} 行)
              </>,
              <>
                {renderNode(
                  `${tKey}|cols`,
                  `列 (${cols.length})`,
                  <Typography variant="caption">
                    {cols.map((c, i) => (
                      <span key={i}>
                        {i > 0 ? ' , ' : ''}
                        <Highlight text={String(c).split(':')[0]} query={search} />
                      </span>
                    ))}
                    {cols.length === 0 ? 'unknown' : ''}
                  </Typography>,
                )}
                {renderNode(
                  `${tKey}|data`,
                  '数据预览',
                  <Box className="p-2 max-h-72 overflow-auto">
                    {rows.length > 0 ? (
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            {cols.map((c, i) => (
                              <TableCell key={i}>
                                <Highlight text={String(c).split(':')[0]} query={search} />
                              </TableCell>
                            ))}
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {rows.slice(0, PREVIEW_ROWS).map((r, ri) => (
                            <TableRow key={ri}>
                              {cols.map((c, ci) => (
                                <TableCell key={ci}>
                                  <Highlight
                                    text={String(
                                      (r as Record<string, unknown>)[String(c).split(':')[0]] ?? '',
                                    )}
                                    query={search}
                                  />
                                </TableCell>
                              ))}
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    ) : (
                      <Typography variant="caption">无数据</Typography>
                    )}
                  </Box>,
                )}
              </>,
            );
          }),
        );
      })}

      {q && dbs.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          无匹配的数据库 / 表 / 列 / 值
        </Typography>
      )}

      <Paper variant="outlined" className="p-2">
        <Typography variant="caption" color="text.secondary">
          共 {dbs.length} 个数据库 · 单表预览最多 {PREVIEW_ROWS} 行（后端拖库上限 {DUMP_ROW_LIMIT} 行）
        </Typography>
      </Paper>
    </Box>
  );
}
