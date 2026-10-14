#!/usr/bin/env node
// ============================================================================
// scripts/lib/jsLexer.mjs —— 逐字符词法内核（供复杂度/重复/死代码/类型覆盖四门禁复用）
//
// ── 为什么要抽这层 ──────────────────────────────────────────────────────────
// nesting-guard.mjs 里已验证过一套「逐字符扫描、跳过字符串/模板串/注释」的
// 内核（见其 analyzeNesting 与 selftest 反例）。本轮要新增的四类门禁（函数级
// 复杂度 / 重复代码 / 死代码 / 类型覆盖）都需要同一件事：把源码切成 token、
// 识别函数边界、数分支点。若各自再写一份扫描器，必然重蹈 nesting 当年的误算
// （朴素数 '{' 把模板串与注释算进深度，实测 extractScope.js 粗测 11、精确 10）。
// 故本模块是**唯一真源**：nesting-guard 改为复用本内核，输出契约逐字节不变。
//
// ── 保真约束（关键）────────────────────────────────────────────────────────
// 1. 正则字面量（D66 2026-10-14 补）：原内核刻意不处理，因为抽取验收要求与
//    analyzeNesting 输出逐字节一致。但该盲区会**静默吞代码**——正则体里的引号
//    （`/[\\"]/g`）被当字符串开，扫到"下一个引号"（不存在）⇒ 后续整个文件被
//    当字符串，函数全部丢失（实测：jsonescape.js 的 transform 在 typecoverage
//    统计中蒸发，core 覆盖率 48.7→48.5 触发 CI 红）。现补正则分支：
//    位置白名单（只在「期待表达式」位识别，除法不受影响）+ 转义对消费
//    （`\` + 下一字符成对跳过，天然满足奇偶性）+ 字符类（`[...]` 内的 `/`
//    不结束正则）。对**不含正则字面量**的文件输出逐字节不变（白名单位置判据
//    未命中时回落既有路径）。
// 2. 对象字面量 vs 代码块的判据逐行照搬 nesting-guard（保守高估方向），
//    因为它的基线就是照此口径建立的，改判据=改基线=门禁被放宽。
// 3. 扫描只产出 token 与「代码块括号配对」；对象字面量括号不进配对栈。
// ============================================================================

const IDENT_START = /[A-Za-z_$]/;
const IDENT_PART = /[\w$]/;
const DIGIT = /[0-9]/;

// 正则位置白名单（D66）：正则字面量只能出现在「期待表达式」的位置。
// 上一个 token 是 ident/num/str/)/]/} 时是除法或属性访问，不在白名单。
const REGEX_PREV_KEYWORDS = new Set([
  'return', 'typeof', 'case', 'in', 'of', 'new', 'delete', 'void',
  'instanceof', 'do', 'else', 'yield', 'await',
]);
const REGEX_PREV_PUNCT = new Set([
  '=', '(', ',', '[', '{', ';', ':', '!', '&', '|', '?', '+', '-', '*', '%',
  '<', '>', '~', '^', '=>', '&&', '||', '??', '+=', '-=', '*=', '%=', '&=',
  '|=', '^=', '==', '!=', '<=', '>=', '===', '!==', '...',
]);

/** 该位置（基于已产出的 token 流）是否可能开始一个正则字面量。 */
function isRegexPos(tokens) {
  const prev = tokens[tokens.length - 1];
  if (!prev) return true; // 文件开头（注释/空白不计 token）
  if (prev.type === 'ident') return REGEX_PREV_KEYWORDS.has(prev.value);
  if (prev.type === 'punct') return REGEX_PREV_PUNCT.has(prev.value);
  return false; // num / str / regex / brace
}

/**
 * 从 startI（`/` 的下标）尝试扫描一个正则字面量（含 flags）。
 * 转义对消费（`\` + 下一字符成对跳过，天然满足奇偶性）；`[...]` 字符类内
 * 的 `/` 不结束正则；换行即未闭合。
 * @param {string} src 源码
 * @param {number} startI `/` 的下标
 * @returns {{end:number, closed:boolean}} closed 时 end 为结束后一位（含 flags）；否则调用方回落
 */
function scanRegexLiteral(src, startI) {
  const n = src.length;
  let j = startI + 1, inClass = false, closed = false;
  while (j < n) {
    const ch = src[j];
    if (ch === '\n') break;
    if (ch === '\\') { j += 2; continue; }
    if (inClass) { if (ch === ']') inClass = false; j++; continue; }
    if (ch === '[') { inClass = true; j++; continue; }
    if (ch === '/') { j++; closed = true; break; }
    j++;
  }
  if (!closed) return { end: startI + 1, closed: false };
  while (j < n && src[j] >= 'a' && src[j] <= 'z') j++; // flags（gimsuyv）
  return { end: j, closed: true };
}

// 多字符运算符（按长度降序尝试）。覆盖门槛判据只需 && || ?? ?. 三目 ? ，
// 但为让 findFunctions 能正确切分 `=>`、`...`、`?.`，此处给全常见形态。
const OPS3 = ['>>>=', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=', '...'];
const OPS2 = ['=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '++', '--', '**', '<<', '>>'];

/**
 * 逐字符词法扫描：跳过空白/字符串/模板串/行注释/块注释，产出 token 流，
 * 并顺带算出代码块嵌套深度（与 nesting-guard 口径一致）。
 * @param {string} src 源码
 * @returns {{ maxDepth:number, maxDepthLine:number, tokens:Array<{type:string, value:string, line:number, col:number, block?:boolean}> }}
 */
export function lex(src) {
  const n = src.length;
  let i = 0, line = 1, col = 1;
  let depth = 0, maxDepth = 0, maxDepthLine = 0;
  const tokens = [];
  // 配对栈：每遇 '{' 压入「是否代码块」；遇 '}' 弹出对应项（对象字面量的收尾不减深度）。
  const braceStack = [];

  const push = (type, value, l, c, extra) => {
    const t = { type, value, line: l, col: c };
    if (extra) Object.assign(t, extra);
    tokens.push(t);
  };

  while (i < n) {
    const c = src[i];
    if (c === '\n') { line++; col = 1; i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r') { i++; col++; continue; }
    // 行注释
    if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') { i++; col++; } continue; }
    // 块注释（跳过，但计行以免行号错位）
    if (c === '/' && src[i + 1] === '*') {
      i += 2; col += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') { line++; col = 1; } else col++;
        i++;
      }
      i += 2; col += 2;
      continue;
    }
    // ── 正则字面量（D66 补，见头部注释 1）──────────────────────────────────
    // 未闭合（换行前找不到结束 `/`）⇒ 不进本分支，回落既有逐字符路径（保守）。
    if (c === '/' && isRegexPos(tokens)) {
      const r = scanRegexLiteral(src, i);
      if (r.closed) {
        push('regex', src.slice(i, r.end), line, col);
        col += r.end - i;
        i = r.end;
        continue;
      }
    }
    // 字符串 / 模板串（模板串内的 ${} 表达式保守整体跳过，与原内核一致）
    if (c === '"' || c === "'" || c === '`') {
      const q = c; const sl = line, sc = col;
      let value = c; i++; col++;
      while (i < n) {
        if (src[i] === '\\') { value += src[i] + (src[i + 1] ?? ''); i += 2; col += 2; continue; }
        if (src[i] === '\n') { line++; col = 1; value += '\n'; i++; continue; }
        value += src[i];
        if (src[i] === q) { i++; col++; break; }
        i++; col++;
      }
      push('str', value, sl, sc);
      continue;
    }
    if (c === '{') {
      // ── 对象字面量 vs 代码块（逐行照搬 nesting-guard，保守高估方向）──────────
      const peek = src.slice(i + 1).match(/^\s*([^\n]{0,24})/);
      const after = peek ? peek[1] : '';
      const looksLikeObject = /^(\.\.\.|,|\})/.test(after)
        || /^(['"`])/.test(after)
        || /^[A-Za-z_$][\w$]*\s*[:,(]/.test(after)
        || /^(get|set|async|static|\*)\b/.test(after);
      const afterIsNameThenColonOrComma = /^[A-Za-z_$][\w$]*\s*[:,]/.test(after);
      const isObjectLiteral = looksLikeObject && (afterIsNameThenColonOrComma
        || /^(\.\.\.|,|\})/.test(after)
        || /^(['"`])/.test(after)
        || /^(get|set|async|static|\*)\b/.test(after));
      const isBlock = !isObjectLiteral;
      braceStack.push(isBlock);
      push('brace', '{', line, col, { block: isBlock });
      if (isBlock) { depth++; if (depth > maxDepth) { maxDepth = depth; maxDepthLine = line; } }
      i++; col++;
      continue;
    }
    if (c === '}') {
      // 只有配对的是"代码块"才减深度；对象字面量的收尾不参与。
      const paired = braceStack.pop();
      const isBlock = paired !== false;
      push('brace', '}', line, col, { block: isBlock });
      if (isBlock) depth--;
      i++; col++;
      continue;
    }
    if (IDENT_START.test(c)) {
      const sl = line, sc = col;
      let j = i + 1;
      while (j < n && IDENT_PART.test(src[j])) j++;
      push('ident', src.slice(i, j), sl, sc);
      col += j - i; i = j;
      continue;
    }
    if (DIGIT.test(c)) {
      const sl = line, sc = col;
      let j = i + 1;
      while (j < n && /[0-9a-fA-FxXoObBeE._]/.test(src[j])) j++;
      push('num', src.slice(i, j), sl, sc);
      col += j - i; i = j;
      continue;
    }
    let op = null;
    for (const o of OPS3) if (src.startsWith(o, i)) { op = o; break; }
    if (!op) for (const o of OPS2) if (src.startsWith(o, i)) { op = o; break; }
    if (op) { push('punct', op, line, col); i += op.length; col += op.length; continue; }
    push('punct', c, line, col);
    i++; col++;
  }

  return { maxDepth, maxDepthLine, tokens };
}

const BRANCH_KEYWORDS = new Set(['if', 'for', 'while', 'case', 'catch']);
const BRANCH_OPS = new Set(['&&', '||', '??', '?.']);

/**
 * 统计 token 流中的分支点数量（圈复杂度基数另算，= 1 + 本返回值）。
 * 计数项：if / for / while / case / catch / && / || / ?? / ?. / 三目 ? 。
 * @param {Array<{type:string,value:string}>} tokens
 * @returns {number}
 */
export function countBranches(tokens) {
  let count = 0;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type === 'ident') {
      if (BRANCH_KEYWORDS.has(t.value)) count++;
    } else if (t.type === 'punct') {
      if (BRANCH_OPS.has(t.value)) count++;
      else if (t.value === '?') {
        // 三目 `? :`；但 TS 可选参数/属性标记 `a?:` 也是 `?` 紧跟 `:`，那不是分支。
        const next = tokens[i + 1];
        if (!(next && next.type === 'punct' && next.value === ':')) count++;
      }
    }
  }
  return count;
}

/**
 * 提取 [startLine, endLine] 区间内的**有效行数**（剔除纯空白行与纯注释行）。
 * 纯注释行不代表职责复杂度，故作为函数长度的主判据。
 * @param {string} src 源码
 * @param {number} startLine 1-based 起始行（含）
 * @param {number} endLine 1-based 结束行（含）
 * @returns {number}
 */
export function effectiveBodyLines(src, startLine, endLine) {
  const lines = src.split('\n');
  let count = 0;
  let inBlock = false;
  for (let i = startLine - 1; i <= endLine - 1 && i < lines.length; i++) {
    if (i < 0) continue;
    const line = lines[i];
    let j = 0;
    let hasCode = false;
    while (j < line.length) {
      if (inBlock) {
        const end = line.indexOf('*/', j);
        if (end === -1) { j = line.length; break; }
        j = end + 2; inBlock = false; continue;
      }
      const ch = line[j];
      if (ch === ' ' || ch === '\t' || ch === '\r') { j++; continue; }
      if (ch === '/' && line[j + 1] === '/') break; // 行注释到行尾
      if (ch === '/' && line[j + 1] === '*') { inBlock = true; j += 2; continue; }
      hasCode = true; break;
    }
    if (hasCode) count++;
  }
  return count;
}

const CONTROL_KEYWORDS = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'with', 'return', 'typeof', 'do',
  'else', 'new', 'delete', 'void', 'in', 'of', 'await', 'yield', 'throw', 'case',
]);

/**
 * 保守地找出函数边界。不确定者不返回（仅计入 unparsed），
 * 宁可少报，也不可把嵌套内函数误当外层函数长度。
 * 识别三类形态：`function NAME(...) {`、`(...) => {` / `x => {`、方法 `name(...) {`。
 * @param {string} src
 * @returns {{ functions:Array<{name:string,startLine:number,endLine:number,params:string[]}>, unparsed:number }}
 */
export function findFunctions(src) {
  const { tokens } = lex(src);
  const functions = [];
  let unparsed = 0;

  // 圆括号配对：'(' 索引 → ')' 索引
  const parenMatch = new Map();
  const pstack = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type === 'punct' && t.value === '(') pstack.push(i);
    else if (t.type === 'punct' && t.value === ')') {
      const j = pstack.pop();
      if (j !== undefined) { parenMatch.set(j, i); parenMatch.set(i, j); }
    }
  }
  // 代码块花括号配对：'{' 索引 → '}' 索引（对象字面量不参与）
  const braceMatch = new Map();
  const bstack = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type === 'brace' && t.value === '{' && t.block) bstack.push(i);
    else if (t.type === 'brace' && t.value === '}' && t.block) {
      const j = bstack.pop();
      if (j !== undefined) { braceMatch.set(j, i); braceMatch.set(i, j); }
    }
  }

  // class 上下文（用于「类名.方法名」稳定标识）
  const classRanges = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type === 'ident' && t.value === 'class') {
      let name = '<anonymous>';
      const next = tokens[i + 1];
      if (next && next.type === 'ident' && next.value !== 'extends') name = next.value;
      let k = i + 1;
      while (k < tokens.length && !(tokens[k].type === 'brace' && tokens[k].value === '{' && tokens[k].block)) k++;
      if (k < tokens.length && braceMatch.has(k)) classRanges.push({ open: k, close: braceMatch.get(k), name });
    }
  }
  const classNameAt = (idx) => {
    let found = null;
    for (const r of classRanges) {
      if (idx > r.open && idx < r.close && (!found || r.open > found.open)) found = r;
    }
    return found ? found.name : null;
  };

  const extractParams = (openIdx, closeIdx) => {
    const params = [];
    let depth = 0;
    let expectName = true;
    for (let i = openIdx + 1; i < closeIdx; i++) {
      const t = tokens[i];
      if (t.type === 'punct' && (t.value === '(' || t.value === '[')) depth++;
      else if (t.type === 'punct' && (t.value === ')' || t.value === ']')) depth--;
      else if (t.type === 'brace' && t.value === '{') depth++;
      else if (t.type === 'brace' && t.value === '}') depth--;
      else if (depth === 0 && t.type === 'punct' && t.value === ',') { expectName = true; continue; }
      else if (depth === 0 && t.type === 'punct' && t.value === '=') expectName = false;
      else if (depth === 0 && t.type === 'ident' && expectName) { params.push(t.value); expectName = false; }
    }
    return params;
  };

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (!(t.type === 'brace' && t.value === '{' && t.block)) continue;
    if (!braceMatch.has(i)) { unparsed++; continue; }
    const prev = tokens[i - 1];
    let name = null;
    let params = [];
    if (prev && prev.type === 'punct' && prev.value === ')') {
      const openParenIdx = parenMatch.get(i - 1);
      if (openParenIdx === undefined) { unparsed++; continue; }
      const before = tokens[openParenIdx - 1];
      if (before && before.type === 'ident') {
        if (before.value === 'function') {
          name = `<anonymous@${t.line}>`;
        } else if (CONTROL_KEYWORDS.has(before.value)) {
          continue; // if/for/while/switch/catch/... 的块不是函数体
        } else {
          const cls = classNameAt(i);
          name = cls ? `${cls}.${before.value}` : before.value;
        }
      } else {
        unparsed++; continue;
      }
      params = extractParams(openParenIdx, i - 1);
    } else if (prev && prev.type === 'punct' && prev.value === '=>') {
      name = `<arrow@${t.line}>`;
      const before = tokens[i - 2];
      if (before && before.type === 'punct' && before.value === ')' && parenMatch.has(i - 2)) {
        params = extractParams(parenMatch.get(i - 2), i - 2);
      } else if (before && before.type === 'ident') {
        params = [before.value];
      }
    } else {
      continue; // 既非 `) {` 也非 `=> {` ⇒ 不是函数体
    }
    const endIdx = braceMatch.get(i);
    functions.push({ name, startLine: t.line, endLine: tokens[endIdx].line, params });
  }

  return { functions, unparsed };
}