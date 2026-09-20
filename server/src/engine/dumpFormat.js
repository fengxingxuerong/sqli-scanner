// =====================================================================
// dumpFormat.js —— 拖库结果的数据导出格式化（对标 sqlmap --dump-format）
//
// [大文件拆分 2026-09-20] 从 Extractor.js 抽出。原为 5 个实例方法
// （formatDumpData / _formatCsv / _escapeCsvCell / _formatSql / _formatHtml），
// 但它们**完全不依赖 this**、无 I/O、无状态 —— 纯粹是「表格数据 → 字符串」，
// 属于典型的错误归属（放在提取器里只因为「提取完顺手格式化」）。
//
// 抽离带来的实际收益（不只是行数）：
//   · 转义正确性可直接单测 —— CSV 转义与 HTML 实体编码是**注入面**
//     （拖出的数据可能含引号/换行/标签，单元格转义漏一处就能破坏导出文件结构，
//      HTML 报告里更可能变成 XSS）。此前只能通过完整的拖库链路间接验证。
//   · 格式扩展（如新增 xml/markdown）不必碰 Extractor。
//
// 职责边界：只负责把 rows+columns 渲染成字符串，**不负责取数、不碰网络**。
// =====================================================================
import { AppError, ErrorCode } from '../core/errors.js';

/**
 * CSV 单元格转义：含逗号/引号/换行/首尾空格的字段用双引号包裹，内部引号双写。
 *
 * 为什么首尾空格也要包裹：不包裹的话，`" a"` 往返一轮会变成 `"a"`，数据静默失真。
 * @param {any} v 单元格值（null/undefined 视为空串）
 * @returns {string} 可直接拼进 CSV 行的文本
 */
export function escapeCsvCell(v) {
  const s = v == null ? '' : String(v);
  if (/[",\n\r]/.test(s) || /^\s|\s$/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/**
 * CSV 格式化：表头 + 行数据，逗号分隔。
 * @param {object[]} rows 行数组
 * @param {string[]} columns 列名数组
 * @returns {string} 含表头在内的完整 CSV 文本（\n 分隔）
 */
export function formatCsv(rows, columns) {
  const lines = [columns.map(escapeCsvCell).join(',')];
  for (const row of rows) {
    lines.push(columns.map((c) => escapeCsvCell(row[c])).join(','));
  }
  return lines.join('\n');
}

/**
 * SQL INSERT 语句格式化：INSERT INTO table (cols) VALUES (vals);
 * 字符串值按 SQL 字面量转义（单引号双写），null/undefined 输出 NULL。
 * @param {object[]} rows 行数组
 * @param {string[]} columns 列名数组
 * @param {string} [table] 目标表名（原样拼入，不对标识符做方言转义 —— 与既有行为一致；
 *   允许缺省：调用方 formatDumpData 的 table 是可选参数，缺省时表中会渲染成 "undefined"，
 *   这是拆分前就有的既有行为，此处不"顺手修"，仅如实标注类型）
 * @returns {string} 每行一条 INSERT，\n 分隔
 */
export function formatSql(rows, columns, table) {
  const escapeSqlValue = (v) => {
    if (v == null) return 'NULL';
    return `'${String(v).replace(/'/g, "''")}'`;
  };
  const colList = columns.join(', ');
  return rows.map((row) =>
    `INSERT INTO ${table} (${colList}) VALUES (${columns.map((c) => escapeSqlValue(row[c])).join(', ')});`
  ).join('\n');
}

/**
 * HTML 表格格式化：<table><thead>…<tbody>…
 *
 * 所有值做 HTML 实体编码。**这是安全边界不是美化**：拖库内容来自目标数据库，
 * 完全不可信 —— 未编码时，一行含 `<script>` 的注释字段就能在查看报告时执行（存储型 XSS）。
 * @param {object[]} rows 行数组
 * @param {string[]} columns 列名数组
 * @returns {string} 完整 <table> 片段（不再包 <html>/<body>，由报告层决定外壳）
 */
export function formatHtml(rows, columns) {
  const esc = (s) => String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
  const thead = `<thead><tr>${columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead>`;
  const tbody = `<tbody>${rows.map((row) =>
    `<tr>${columns.map((c) => `<td>${esc(row[c])}</td>`).join('')}</tr>`
  ).join('')}</tbody>`;
  return `<table>${thead}${tbody}</table>`;
}

/**
 * 将提取的行数据格式化为指定格式（对标 sqlmap --dump-format）。
 *
 * 行为契约（与拆分前逐字一致）：
 *   · `json`（默认）→ **返回原始数组**（不是字符串），调用方可直接序列化；
 *   · 空数据仍返回**格式骨架**（CSV 返回表头行、SQL 返回空串、HTML 返回空表），
 *     而不是返回空数组 —— 报告层依赖这个骨架判断「确实拖到了 0 行」；
 *   · 未知 format → 抛 AppError(INVALID_PARAM)，不静默回落。
 *
 * @param {object[]} rows 行数组
 * @param {string[]} [columns] 列名数组（缺省时从首行推断）
 * @param {string} [table] 表名（仅 sql 格式使用）
 * @param {string} [format] 目标格式：'json'(默认) | 'csv' | 'sql' | 'html'
 *   —— 故意标 `{string}` 而非联合字面量类型：本函数对未知 format **运行时抛错**，
 *      是开放输入 + 显式校验，不是编译期枚举收窄。标成联合类型会让薄委托
 *      （形参为 string）产生 TS2345 双向不兼容。
 * @returns {any} json 返回数组，其余返回字符串
 */
export function formatDumpData(rows, columns, table, format = 'json') {
  if (!Array.isArray(rows) || rows.length === 0) {
    // 空数据仍返回格式骨架（CSV 返回表头行，SQL 返回空串，HTML 返回空表）
    if (format === 'csv') return (columns || []).map(escapeCsvCell).join(',');
    if (format === 'sql') return '';
    if (format === 'html') return formatHtml([], columns || []);
    return rows || [];
  }
  const cols = columns || Object.keys(rows[0]);
  switch (format) {
    case 'json':
      return rows;
    case 'csv':
      return formatCsv(rows, cols);
    case 'sql':
      return formatSql(rows, cols, table);
    case 'html':
      return formatHtml(rows, cols);
    default:
      throw new AppError(ErrorCode.INVALID_PARAM, `不支持的 dump 格式: ${format}`);
  }
}
