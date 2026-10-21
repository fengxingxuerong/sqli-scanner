// [D121 2026-10-21] GraphQL 查询串内联值位扫描。
//
// 为什么需要：GraphQL 请求 body 通常是 JSON `{query:"{ pastes(filter:\"x\") { id } }"}`。
// 既有 JSON 叶子通道会把整段 query 字符串替换成 payload（D114 DVGA 实测），生成的不是
// 合法 GraphQL，服务端在解析层就 400 —— 注入值从未进 resolver，与「没有注入」同形。
// 本模块只做一件事：在查询串里定位**双引号字符串字面量**，记录其字节区间与参数名，
// 供构造侧「保持骨架、只换值位」。不解析完整 GraphQL AST（避免引入依赖，也不需要）。
//
// 边界（诚实标注）：
//   · 只认标准双引号字符串；block string（"""…"""）整体跳过，不生成点；
//   · 只认内联字面量；`variables` 里的值由既有 JSON 叶子通道处理，不在这里重复；
//   · 非 JSON body（application/graphql 裸查询串）不在本通道内。

/**
 * GraphQL 字符串字面量的扫描结果。
 * @typedef {object} GraphQLInlineLiteral
 * @property {number} start 起始双引号下标（含）
 * @property {number} end 结束双引号下标（不含，指向最后一个引号后一位）
 * @property {string} raw 原始字面量（含两侧引号）
 * @property {string} value 解码后的值
 * @property {string|null} argName 紧邻的 GraphQL 参数名（无则 null）
 */

/**
 * 判断一个 query 字段是否像 GraphQL 查询串。
 *
 * 只做保守识别：显式 operation 关键字，或 `{ field(...) }` 形态。像 JSON 对象的
 * `{ "a": 1 }` 不会被误认（`{` 后必须是 GraphQL Name 字符）。
 * @param {unknown} src
 * @returns {boolean}
 */
export function looksLikeGraphQLQuery(src) {
  if (typeof src !== 'string') return false;
  const s = src.trim();
  if (!s) return false;
  if (/^(query|mutation|subscription|fragment)\b/.test(s)) return true;
  // 匿名查询：`{` 后必须是 GraphQL Name 字符；`{ "a": 1 }`（JSON 文本）不会命中。
  return /^\{\s*[A-Za-z_]/.test(s);
}

/**
 * 扫描 GraphQL 查询串里的内联字符串字面量。
 *
 * 返回顺序即文本顺序；遇到畸形/未闭合字符串时停止并返回已发现项（保守，不猜）。
 * 行注释（# …）与 block string 会被跳过；block string 不生成点（见文件头边界）。
 * @param {unknown} src
 * @returns {GraphQLInlineLiteral[]}
 */
export function findGraphQLInlineLiterals(src) {
  /** @type {GraphQLInlineLiteral[]} */
  const out = [];
  if (typeof src !== 'string' || !src) return out;
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === '#') {
      i = skipLineComment(src, i);
      continue;
    }
    if (ch !== '"') {
      i += 1;
      continue;
    }
    if (src.startsWith('"""', i)) {
      const end = skipBlockString(src, i);
      if (end < 0) return out;
      i = end;
      continue;
    }
    const end = skipQuotedString(src, i);
    if (end < 0) return out;
    const raw = src.slice(i, end);
    const value = decodeGraphQLString(raw);
    if (value !== null) {
      out.push({ start: i, end, raw, value, argName: argNameBefore(src, i) });
    }
    i = end;
    if (out.length >= 64) return out; // 防护上限与 JSON 叶子通道同量级
  }
  return out;
}

/**
 * 把值编码成 GraphQL 双引号字符串的内部形态（不含两侧引号）。
 * GraphQL 字符串转义与 JSON 基本一致；JSON.stringify 额外转义 U+2028/U+2029 以兼容
 * 常见 GraphQL 解析器。
 * @param {unknown} value
 * @returns {string}
 */
export function encodeGraphQLString(value) {
  return JSON.stringify(String(value ?? ''))
    .slice(1, -1)
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/**
 * 用注入值替换查询串中指定区间的字符串字面量。
 *
 * 基线请求（value === originalValue 且原串未变）保留原始字面量，确保基线与用户
 * 抓包逐字一致；注入请求重新编码，避免 payload 里的双引号/反斜杠把 GraphQL 语法打碎。
 * @param {string} query
 * @param {number} start
 * @param {number} end
 * @param {unknown} value
 * @param {unknown} originalValue
 * @param {unknown} raw
 * @returns {string|null} 替换后的 query；区间/引号不匹配返回 null（调用方保守降级）
 */
export function replaceGraphQLStringLiteral(query, start, end, value, originalValue, raw) {
  if (typeof query !== 'string') return null;
  if (!Number.isInteger(start) || !Number.isInteger(end)) return null;
  if (start < 0 || end <= start || end > query.length) return null;
  if (query[start] !== '"' || query[end - 1] !== '"') return null;
  const current = query.slice(start, end);
  const keepRaw =
    String(value) === String(originalValue) &&
    typeof raw === 'string' &&
    raw === current;
  const token = keepRaw ? current : `"${encodeGraphQLString(value)}"`;
  return query.slice(0, start) + token + query.slice(end);
}

/**
 * 扫描对白：`"` … `"`，反斜杠转义跳过下一个字符；裸换行视为畸形。
 * @param {string} src
 * @param {number} start
 * @returns {number} 结束下标（不含）；-1 = 未闭合/畸形
 */
function skipQuotedString(src, start) {
  let i = start + 1;
  while (i < src.length) {
    const ch = src[i];
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === '"') return i + 1;
    if (ch === '\n' || ch === '\r') return -1;
    i += 1;
  }
  return -1;
}

/**
 * 跳过 block string：`"""` … `"""`。
 * @param {string} src
 * @param {number} start
 * @returns {number} 结束下标（不含）；-1 = 未闭合
 */
function skipBlockString(src, start) {
  let i = start + 3;
  while (i < src.length) {
    // GraphQL block string 里 `"""` 可用 `\"""` 转义；反斜杠后的字符不参与终止判定。
    if (src[i] === '\\') { i += 2; continue; }
    if (src.startsWith('"""', i)) return i + 3;
    i += 1;
  }
  return -1;
}

/**
 * 跳过 `#` 行注释，返回下一行起点（或串尾）。
 * @param {string} src
 * @param {number} start
 * @returns {number}
 */
function skipLineComment(src, start) {
  let i = start + 1;
  while (i < src.length && src[i] !== '\n' && src[i] !== '\r') i += 1;
  return i;
}

/**
 * 解码 GraphQL 字符串字面量。GraphQL 标准转义是 JSON 转义的子集，
 * 因此 JSON.parse 可直接复用；非法转义返回 null（不猜）。
 * @param {string} raw
 * @returns {string|null}
 */
function decodeGraphQLString(raw) {
  try {
    const parsed = JSON.parse(raw);
    return typeof parsed === 'string' ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * 取字面量前面紧邻的参数名：`filter: "x"` → `filter`。
 *
 * 只认「标识符 + 冒号」形态；列表元素（前面是 `[`/`,`）或指令参数取不到时返回 null，
 * 由调用侧用序号兜底命名。
 * @param {string} src
 * @param {number} start 字面量起始引号下标
 * @returns {string|null}
 */
function argNameBefore(src, start) {
  let i = start - 1;
  while (i >= 0 && /\s/.test(src[i])) i -= 1;
  if (src[i] !== ':') return null;
  i -= 1;
  while (i >= 0 && /\s/.test(src[i])) i -= 1;
  const end = i + 1;
  while (i >= 0 && /[A-Za-z0-9_]/.test(src[i])) i -= 1;
  const name = src.slice(i + 1, end);
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name : null;
}
