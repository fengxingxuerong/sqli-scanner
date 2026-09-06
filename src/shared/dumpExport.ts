import type { ExtractedData } from './types';

// 拖库数据导出工具（P2-S7）：从报告 report.data 提取库/表/列/行，
// 支持 CSV（对标 sqlmap --dump 输出形态）与 JSON 两种格式，纯函数便于单测。

/** 判断是否存在拖库数据（databases/tables/rows 任一非空即视为有） */
export function hasDumpData(data: ExtractedData | null | undefined): boolean {
  if (!data) return false;
  return !!(
    (Array.isArray(data.databases) && data.databases.length > 0) ||
    (data.tables && Object.keys(data.tables).length > 0) ||
    (data.rows && Object.keys(data.rows).length > 0)
  );
}

// CSV 单元格转义：含逗号/引号/换行时加引号包裹，内部引号翻倍
function csvCell(v: unknown): string {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// 拖库数据 → CSV（对标 sqlmap --dump 形态：库清单 + 每表一区块「库.表 → 列头 → 行」）
export function dumpToCsv(data: ExtractedData): string {
  const lines: string[] = [];
  lines.push('# 拖库数据（sqlmap --dump 风格）');
  if (Array.isArray(data.databases) && data.databases.length > 0) {
    lines.push(`# 数据库: ${data.databases.join(', ')}`);
  }
  const rows = data.rows || {};
  for (const [tableKey, arr] of Object.entries(rows)) {
    if (!Array.isArray(arr) || arr.length === 0) continue;
    const cols = Object.keys(arr[0] ?? {});
    if (cols.length === 0) continue;
    lines.push('');
    lines.push(`## ${tableKey}`);
    lines.push(cols.join(','));
    for (const obj of arr) {
      lines.push(cols.map((c) => csvCell((obj as Record<string, unknown>)[c])).join(','));
    }
  }
  return '\uFEFF' + lines.join('\n');
}

// 拖库数据 → JSON（与后端 db-json 导出同构：databases/tables/columns/rows）
export function dumpToJson(data: ExtractedData): string {
  return JSON.stringify(data, null, 2);
}

// ── 单表导出（G15/S7 补充）：从已加载报告数据切片导出单个表，纯前端生成 ──
// 列定义形如 "id:INTEGER"，表头取冒号前的列名（与 DbTree 表格展示一致）。

/** 单表 → CSV：首行表头=列名，行数据按列名取值；转义复用 csvCell（逗号/引号/换行） */
export function tableToCsv(data: ExtractedData, tableKey: string): string {
  const cols = (data.columns && data.columns[tableKey]) || [];
  const rows = (data.rows && data.rows[tableKey]) || [];
  const names = cols.map((c) => String(c).split(':')[0]);
  const lines: string[] = [names.join(',')];
  for (const obj of rows) {
    const rec = (obj || {}) as Record<string, unknown>;
    lines.push(names.map((n) => csvCell(rec[n])).join(','));
  }
  return '\uFEFF' + lines.join('\n');
}

/** 单表 → JSON：{ database, table, columns, rows } 结构化切片 */
export function tableToJson(data: ExtractedData, tableKey: string): string {
  const dot = tableKey.indexOf('.');
  const database = dot > 0 ? tableKey.slice(0, dot) : '';
  const table = dot > 0 ? tableKey.slice(dot + 1) : tableKey;
  const cols = (data.columns && data.columns[tableKey]) || [];
  const rows = (data.rows && data.rows[tableKey]) || [];
  return JSON.stringify({ database, table, columns: cols, rows }, null, 2);
}
