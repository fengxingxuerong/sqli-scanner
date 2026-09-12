// e2e/recall-lab/lab-server.js
// ============================================================================
// 检测召回靶场（detection-recall lab）：纯 node:http 实现，零新增依赖。
//
// 目标：给「注入场景 × 检测技术」的召回率回归提供一台**行为可控**的受感染目标。
// 与 e2e/waf-lab（WAF 绕过对比）、e2e/tamper-matrix（tamper 矩阵）互补，
// 本靶场不关心 WAF/tamper，只关心「引擎的技术检测器在各类注入上下文里能否命中」。
//
// 核心是一个微型「SQL 求值器」：对 URL 解码后的参数值做 case-insensitive 的
// 启发式解析（词法 → 引号/括号平衡校验 → 语句切分 → 语义分派），按上下文决定响应：
//
// | 端点               | 上下文                    | 求值器行为                                     |
// |--------------------|---------------------------|------------------------------------------------|
// | GET /num?id=1      | WHERE id = {v}（数值）    | 布尔真假页 / sleep( 任意出现即延迟(≤3s) /       |
// |                    |                           | extractvalue 族→MySQL 报错 / UNION 回显 3 列行  |
// |                    |                           | （SQLISCANNER 标记与 __S__..__E__ 原样回传）/    |
// |                    |                           | (SELECT 'x') 标量子查询回显（inline 通道）/      |
// |                    |                           | `;` 后第二条语句 sleep → 堆叠延迟                |
// | GET /str?name=foo  | WHERE name = '{v}'        | 同上，但必须先闭合 `'`（含 `''` 转义语义，       |
// |                    |                           | 未闭合/闭合错误的 payload 视为语法错误）          |
// | GET /paren?id=1    | WHERE id = ('{v}')        | 同上，但必须 `')` 闭合                           |
// | GET /orderby?sort=id | ORDER BY {v}（level≥2） | 逗号型：`,(SELECT 1)`→正常 / `,(...UNION...)`→  |
// |                    |                           | 多行子查询报错 / `,(SELECT SLEEP(n))`→延迟 /    |
// |                    |                           | 逗号型 extractvalue→报错；非法子句→语法错误页     |
// | GET /bool?uid=1    | WHERE uid = {v}           | 仅布尔差异（真/假页差异明显），无回显无报错无延迟 |
// | GET /time?tid=1    | WHERE tid = {v}           | 仅 sleep 生效（任意出现，含语法破坏的 payload）， |
// |                    |                           | 响应内容恒定                                    |
// | GET /stacked?i=1   | WHERE i = {v}             | 只有 `;` 后第二条语句含 sleep 才延迟（隔离 time） |
// | GET /search?q=…    | WHERE title LIKE '%{v}%'  | 搜索型注入：~% 闭合 + ' 闭合；`{v}' OR '1'='1`→    |
// |                    |                           | 全表，`{v}' AND '1'='2`→ 空（布尔差异明显）；       |
// |                    |                           | %…% 字面量恒真（全表基线）、尾部 % 比较走前缀匹配    |
// | GET /update?id=&name= | UPDATE items SET name='{v}' WHERE id={id} | UPDATE SET 注入：纯字面量恒真；|
// |                    |                           | `x',1=1-- -`→成功页 / `x',1=2-- -`→失败页（布尔差异）；|
// |                    |                           | id 数值/条件表达式按布尔求值                       |
//
// 通用约定：
//  - 所有页面带「等长时间戳噪声」<!-- ts=13位毫秒 -->，考验相似度判定对动态内容的鲁棒性
//    （等长 → 分块相似度可容忍；真/假页长度差刻意拉大 → 判定信号明确）。
//  - 语法错误页刻意**不含**引擎 ERROR_SIG 关键字（不把「闭合失败」伪装成报错注入），
//    报错注入只在报错函数真正出现在语法合法的语句里时回 MySQL 风格报错文本。
//  - 响应头 X-Powered-By: PHP/… → 引擎 DBFingerprinter 头特征直接定库 MySQL（确定性）。
// ============================================================================

import http from 'node:http';
import { pathToFileURL } from 'node:url';

// —— 伪 MySQL 环境（回显求值用）——
export const DB = {
  version: '8.0.36',
  database: 'labdb',
  user: 'root@localhost',
  datadir: '/var/lib/mysql/',
  hostname: 'labhost',
  tables: 'items,users', // group_concat(table_name)
  columns: 'id,name,note', // group_concat(column_name)
  schemas: 'information_schema,labdb',
};

const TABLE_COLUMNS = ['id', 'name', 'note'];
const ROWS = [
  { id: 1, name: 'alice', note: 'alpha record note number one' },
  { id: 2, name: 'foo', note: 'beta record note number two' },
  { id: 3, name: 'carol', note: 'gamma record note number three' },
];

// 稳定填充内容：把正常页拉到 ~1.6KB（25+ 个 64B 分块），等长噪声只影响 1 个分块，
// 引擎 chunkedSimilarity(≥0.85) 不受影响；真/假页长度差 >12% 容差 → 明确不相似。
const PAD =
  'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt in culpa qui officia deserunt mollit anim id est laborum. '.repeat(
    4
  );

// 动态噪声：页面嵌入时间戳注释，模拟动态页（训练引擎动态块判定器）。
// 粒度取秒级：真实应用的动态元素（时间戳/计数器）通常秒级更新；毫秒级会让
// sqlmap 的误报复查（checkFalsePositivity）无法收敛，超出合理拟真范围。
const NOISE = () => `<!-- ts=${Math.floor(Date.now() / 1000)} -->`;

// ============================================================================
// 一、词法层：quote-aware tokenizer（注释剥离 / 引号转义 / 括号平衡 / 尾部悬空引号容忍）
// ============================================================================

/**
 * 词法分析。注释（-- / # / 块注释）只在「字符串外」生效（与 MySQL 一致）。
 * 尾部悬空引号容忍：EOF 处未闭合的字符串若内容为空或仅含引号/括号字符（≤2 字符），
 * 视为「应用拼接的尾部闭合引号」直接丢弃 —— 模拟未注释掉尾部引号但整体仍可执行的场景
 * （UnionDetector 的标记 payload 不带注释，正是这种形态）。
 * 其余未闭合（内容很长）→ 语法错误。
 * @returns {{ok: boolean, tokens: Array<{t:'num'|'str'|'id'|'op'|'hex', v:string}>|null}}
 */
export function tokenize(sql) {
  const tokens = [];
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const c = sql[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      i++;
      continue;
    }
    // 行注释 --（MySQL 要求后跟空白/行尾，这里宽容处理）与 # 注释
    if (c === '-' && sql[i + 1] === '-' && (i + 2 >= n || /[\s]/.test(sql[i + 2]))) break;
    if (c === '#') break;
    if (c === '/' && sql[i + 1] === '*') {
      const e = sql.indexOf('*/', i + 2);
      if (e < 0) break;
      i = e + 2;
      continue;
    }
    if (c === "'" || c === '"') {
      const q = c;
      let j = i + 1;
      let s = '';
      let closed = false;
      while (j < n) {
        if (sql[j] === '\\' && j + 1 < n) {
          s += sql[j + 1];
          j += 2;
          continue;
        }
        if (sql[j] === q) {
          if (q === "'" && sql[j + 1] === "'") {
            s += "'"; // '' 转义（MySQL 语义）
            j += 2;
            continue;
          }
          closed = true;
          j++;
          break;
        }
        s += sql[j];
        j++;
      }
      if (!closed) {
        if (s.length <= 2 && /^['")\]]*$/.test(s)) {
          i = j; // 容忍尾部悬空引号：丢弃
          continue;
        }
        return { ok: false, tokens: null };
      }
      tokens.push({ t: 'str', v: s });
      i = j;
      continue;
    }
    if (c === '`') {
      const e = sql.indexOf('`', i + 1);
      if (e < 0) return { ok: false, tokens: null };
      tokens.push({ t: 'id', v: sql.slice(i + 1, e) });
      i = e + 1;
      continue;
    }
    const rest = sql.slice(i);
    const hex = /^0[xX][0-9a-fA-F]+/.exec(rest);
    if (hex) {
      tokens.push({ t: 'hex', v: hex[0] });
      i += hex[0].length;
      continue;
    }
    const num = /^[0-9]+(\.[0-9]+)?/.exec(rest);
    if (num && /^[0-9]/.test(c)) {
      tokens.push({ t: 'num', v: num[0] });
      i += num[0].length;
      continue;
    }
    const id = /^[@#$A-Za-z_][A-Za-z0-9_@$#]*/.exec(rest);
    if (id && /[A-Za-z_@#$]/.test(c)) {
      tokens.push({ t: 'id', v: id[0] });
      i += id[0].length;
      continue;
    }
    const two = rest.slice(0, 2);
    if (['<=', '>=', '<>', '!=', '||', '=='].includes(two)) {
      tokens.push({ t: 'op', v: two });
      i += 2;
      continue;
    }
    if ('=<>+-*/%(),;:.&|'.includes(c)) {
      tokens.push({ t: 'op', v: c });
      i++;
      continue;
    }
    return { ok: false, tokens: null }; // 未知字符 → 解析失败
  }
  return { ok: true, tokens };
}

/**
 * 语句切分 + 括号平衡校验（在 token 流上，字符串已被折叠为 str token）。
 * @returns {{ok: boolean, statements: Array<token[]>}}
 */
export function analyzeStmts(tokens) {
  // [拟真修正] 相邻字面量（num/str/hex 之间无运算符）在 MySQL 是语法错误
  // （如 `1 AND 82 51`）。此前宽松求值返回 'unknown' 按真页渲染，导致 sqlmap
  // 的误报复查（checkFalsePositivity 去运算符试探）把真注入判为误报。
  for (let i = 1; i < tokens.length; i++) {
    const prev = tokens[i - 1];
    const cur = tokens[i];
    if (
      ['num', 'str', 'hex'].includes(prev.t) &&
      ['num', 'str', 'hex'].includes(cur.t)
    ) {
      return { ok: false, statements: [] };
    }
  }
  const statements = [];
  let cur = [];
  let depth = 0;
  for (const tk of tokens) {
    if (tk.t === 'op' && tk.v === '(') {
      depth++;
      cur.push(tk);
      continue;
    }
    if (tk.t === 'op' && tk.v === ')') {
      depth--;
      if (depth < 0) return { ok: false, statements: [] };
      cur.push(tk);
      continue;
    }
    if (tk.t === 'op' && tk.v === ';' && depth === 0) {
      statements.push(cur);
      cur = [];
      continue;
    }
    cur.push(tk);
  }
  if (depth !== 0) return { ok: false, statements: [] };
  statements.push(cur);
  return { ok: true, statements };
}

// —— token 序列工具（「顶层」= 括号深度 0）——
function scanDepths(tokens) {
  const d = new Array(tokens.length);
  let depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    const tk = tokens[i];
    if (tk.t === 'op' && tk.v === '(') {
      d[i] = depth++;
      continue;
    }
    if (tk.t === 'op' && tk.v === ')') {
      d[i] = --depth;
      continue;
    }
    d[i] = depth;
  }
  return d;
}

function findTopIdent(tokens, name) {
  const d = scanDepths(tokens);
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].t === 'id' && d[i] === 0 && tokens[i].v.toLowerCase() === name.toLowerCase()) return i;
  }
  return -1;
}

function splitTop(tokens, isSep) {
  const d = scanDepths(tokens);
  const out = [];
  let cur = [];
  for (let i = 0; i < tokens.length; i++) {
    if (d[i] === 0 && isSep(tokens[i])) {
      out.push(cur);
      cur = [];
      continue;
    }
    cur.push(tokens[i]);
  }
  out.push(cur);
  return out;
}

const hasTopComma = (tokens) =>
  splitTop(tokens, (tk) => tk.t === 'op' && tk.v === ',').length > 1;

function stripOuterParens(tokens) {
  if (tokens.length < 2) return tokens;
  if (!(tokens[0].t === 'op' && tokens[0].v === '(' && tokens.at(-1).t === 'op' && tokens.at(-1).v === ')')) {
    return tokens;
  }
  const d = scanDepths(tokens);
  if (d[0] !== 0) return tokens; // 首个 ( 不与末尾 ) 配对
  return tokens.slice(1, -1);
}

// ============================================================================
// 二、表达式求值：UNION/子查询回显（SQLISCANNER 标记、__S__..__E__ 原样回传）
// ============================================================================

function hexToStr(hex) {
  const h = hex.replace(/^0[xX]/, '');
  let out = '';
  for (let i = 0; i + 1 < h.length; i += 2) out += String.fromCharCode(parseInt(h.slice(i, i + 2), 16));
  return out;
}

const SYS_VARS = {
  '@@version': DB.version,
  '@@hostname': DB.hostname,
  '@@datadir': DB.datadir,
  '@@basedir': '/usr/',
  '@@sql_mode': 'NO_ENGINE_SUBSTITUTION',
  '@@version_compile_os': 'Linux',
  '@@version_compile_machine': 'x86_64',
  '@@servername': 'labhost',
};

const SCALAR_FUNCS = {
  version: DB.version,
  sqlite_version: DB.version,
  database: DB.database,
  schema: DB.database,
  user: DB.user,
  current_user: DB.user,
  session_user: DB.user,
  system_user: DB.user,
};

/**
 * 求 UNION/子查询 select 列表中单个表达式的值。
 * @returns {{kind:'str'|'num'|'null'|'multirow'|'unknown', value?:string}}
 */
function evalItem(tokens) {
  if (!tokens.length) return { kind: 'unknown' };
  if (tokens.length === 1) {
    const tk = tokens[0];
    if (tk.t === 'num') return { kind: 'num', value: tk.v };
    if (tk.t === 'str') return { kind: 'str', value: tk.v };
    if (tk.t === 'hex') return { kind: 'str', value: hexToStr(tk.v) };
    if (tk.t === 'id') {
      const lv = tk.v.toLowerCase();
      if (lv === 'null') return { kind: 'null' };
      if (tk.v.startsWith('@@')) return { kind: 'str', value: SYS_VARS[lv] ?? DB.version };
      if (lv in SCALAR_FUNCS) return { kind: 'str', value: SCALAR_FUNCS[lv] }; // current_user 无括号形态
      return { kind: 'unknown' };
    }
    return { kind: 'unknown' };
  }
  // [跟进 2026-09-12 引擎 WRAP 修复] collate 尾巴：expr COLLATE xxx —— 排序规则声明
  // 不改变标量值，直接剥掉尾巴再求值。
  const colIdx = findTopIdent(tokens, 'collate');
  if (colIdx > 0) return evalItem(tokens.slice(0, colIdx));  // 函数调用：name(args)
  if (tokens[0].t === 'id' && tokens[1] && tokens[1].t === 'op' && tokens[1].v === '(' && tokens.at(-1).v === ')') {
    const name = tokens[0].v.toLowerCase();
    const args = splitTop(tokens.slice(2, -1), (tk) => tk.t === 'op' && tk.v === ',');
    switch (name) {
      case 'version':
      case 'sqlite_version':
      case 'database':
      case 'schema':
      case 'user':
      case 'session_user':
      case 'system_user':
        return { kind: 'str', value: SCALAR_FUNCS[name] };
      case 'count':
      case 'benchmark':
        return { kind: 'num', value: '3' };
      case 'sleep':
        return { kind: 'num', value: '0' };
      // [跟进 2026-09-12 引擎 WRAP 修复] CONVERT(x USING charset) / CONVERT(x, type)：
      // 引擎侧 MySQL 家族 WRAP 已升级为 CONVERT(... USING utf8mb4) COLLATE utf8mb4_bin
      // （修混 collation UNION 报错），mock 求值器必须同步支持，否则所有 UNION 提取
      // 场景在 detection-runner 回归里全灭（实测：databases/tables 提取全空）。
      // 语义：charset/类型子句不影响本 mock 的字符串求值，直接对主表达式求值即可。
      case 'convert': {
        // CONVERT(expr USING cs) 或 CONVERT(expr, type)：去掉 USING cs / , type 尾巴
        let inner = args[0] ?? [];
        if (args.length > 1) return evalItem(stripOuterParens(inner));
        const usingIdx = findTopIdent(inner, 'using');
        if (usingIdx >= 0) inner = inner.slice(0, usingIdx);
        return evalItem(stripOuterParens(inner));
      }      case 'cast': {
        const asIdx = args[0] ? findTopIdent(args[0], 'as') : -1;
        const inner = asIdx >= 0 ? args[0].slice(0, asIdx) : args[0];
        return evalItem(stripOuterParens(inner));
      }
      case 'concat': {
        const vals = args.map((a) => evalItem(a)).map((r) => (r.kind === 'str' || r.kind === 'num' ? r.value : ''));
        return { kind: 'str', value: vals.join('') };
      }
      case 'concat_ws': {
        const sep = evalItem(args[0] ?? []);
        const vals = args
          .slice(1)
          .map((a) => evalItem(a))
          .map((r) => (r.kind === 'str' || r.kind === 'num' ? r.value : ''));
        return { kind: 'str', value: vals.join(sep.kind === 'str' || sep.kind === 'num' ? sep.value : '') };
      }
      case 'group_concat': {
        const flat = (args[0] ?? []).filter((tk) => tk.t === 'id');
        const first = flat[0] ? flat[0].v.toLowerCase() : '';
        const map = {
          table_name: DB.tables,
          column_name: DB.columns,
          schema_name: DB.schemas,
          table_schema: DB.database,
          grantee: 'root@localhost',
          privilege_type: 'SELECT',
          user: 'root',
          host: 'localhost',
          banner: 'lab-MySQL-' + DB.version,
        };
        return { kind: 'str', value: map[first] ?? 'labdata' };
      }
      default:
        return { kind: 'unknown' };
    }
  }
  // (SELECT ...) 标量子查询 / 括号表达式
  if (tokens[0].t === 'op' && tokens[0].v === '(' && tokens.at(-1).t === 'op' && tokens.at(-1).v === ')') {
    const inner = tokens.slice(1, -1);
    if (inner.length && inner[0].t === 'id' && inner[0].v.toLowerCase() === 'select') {
      if (findTopIdent(inner, 'union') >= 0) return { kind: 'multirow' }; // 多行子查询
      const items = splitSelectList(inner.slice(1));
      if (items.length > 1) return { kind: 'multirow' };
      return evalItem(items[0]);
    }
    return evalItem(inner);
  }
  // 裸 SELECT 语句（CAST 剥掉外层括号后的形态，或直接 SELECT 的子查询表达式）：
  // SELECT <expr> [FROM ...] → 单列标量结果
  if (tokens[0].t === 'id' && tokens[0].v.toLowerCase() === 'select') {
    const fromIdx = findTopIdent(tokens, 'from');
    const list = fromIdx >= 0 ? tokens.slice(1, fromIdx) : tokens.slice(1);
    const items = splitTop(list, (tk) => tk.t === 'op' && tk.v === ',');
    if (items.length > 1) return { kind: 'multirow' };
    return evalItem(items[0]);
  }
  return { kind: 'unknown' };
}

/** select 列表（截到顶层 FROM 为止）按顶层逗号切分 */
function splitSelectList(tokens) {
  const fromIdx = findTopIdent(tokens, 'from');
  const list = fromIdx >= 0 ? tokens.slice(0, fromIdx) : tokens;
  return splitTop(list, (tk) => tk.t === 'op' && tk.v === ',');
}

// ============================================================================
// 三、语义层：布尔条件 / 报错函数 / 延迟原语
// ============================================================================

const ERROR_FUNCS = new Set([
  'extractvalue',
  'updatexml',
  'gtid_subset',
  'gtid_subtract',
  'json_keys',
  'json_value',
  'json_object_keys',
  'st_latfromgeohash',
  'st_longfromgeohash',
  'st_pointfromgeohash',
  'polygon',
  'geometrycollection',
  'exp',
]);

function findErrorFunc(tokens) {
  for (const tk of tokens) {
    if (tk.t === 'id' && ERROR_FUNCS.has(tk.v.toLowerCase())) return tk.v.toLowerCase();
  }
  return null;
}

/** 语法合法语句中的 sleep(n)/pg_sleep(n) → 秒数；MySQL 靶场不支持 WAITFOR DELAY */
function findSleep(tokens) {
  for (let i = 0; i < tokens.length; i++) {
    const tk = tokens[i];
    if (tk.t === 'id' && /^(sleep|pg_sleep)$/i.test(tk.v)) {
      let j = i + 1;
      while (j < tokens.length && !(tokens[j].t === 'num')) j++;
      if (j < tokens.length && tokens[i + 1] && tokens[i + 1].v === '(') {
        return Math.min(3, Math.max(1, parseInt(tokens[j].v, 10) || 1));
      }
    }
  }
  return 0;
}

const CMP_OPS = ['<=', '>=', '<>', '!=', '==', '=', '<', '>'];

function evalLiteral(tokens, likePattern) {
  if (tokens.length === 1) {
    const r = evalItem(tokens);
    if (r.kind === 'str' || r.kind === 'num') {
      if (likePattern && r.kind === 'str' && r.value.endsWith('%')) return { ...r, likePattern: true };
      return r;
    }
  }
  if (tokens.length >= 1 && tokens[0].t === 'id' && tokens[0].v.startsWith('@@')) {
    let v = SYS_VARS[tokens[0].v.toLowerCase()] ?? DB.version;
    if (likePattern && v.endsWith('%')) return { kind: 'str', value: v, likePattern: true };
    return { kind: 'str', value: v };
  }
  return { kind: 'unknown' };
}

function evalAtom(tokens, orig, likePattern) {
  if (!tokens.length) return 'unknown';
  const d = scanDepths(tokens);
  const cmpIdx = tokens.findIndex(
    (tk, i) => tk.t === 'op' && d[i] === 0 && CMP_OPS.includes(tk.v)
  );
  if (cmpIdx >= 0) {
    const l = evalLiteral(tokens.slice(0, cmpIdx), likePattern);
    const r = evalLiteral(tokens.slice(cmpIdx + 1), likePattern);
    if (l.kind === 'unknown' || r.kind === 'unknown') return 'unknown';
    const op = tokens[cmpIdx].v;
    // LIKE 尾部通配比较（search 上下文）：值在模式一侧 → 字符串前缀匹配
    //   '1'='1%' → value '1' startsWith 模式前缀 '1' → true
    if (likePattern && (l.likePattern || r.likePattern)) {
      const val = l.likePattern ? String(r.value) : String(l.value);
      const pat = l.likePattern ? String(l.value) : String(r.value);
      const prefix = pat.endsWith('%') ? pat.slice(0, -1) : pat;
      switch (op) {
        case '=':
        case '==':
          return val.startsWith(prefix);
        case '<>':
        case '!=':
          return !val.startsWith(prefix);
        default:
          return 'unknown';
      }
    }
    const ln = Number(l.value);
    const rn = Number(r.value);
    const bothNum = l.kind === 'num' && r.kind === 'num';
    const a = bothNum ? ln : String(l.value);
    const b = bothNum ? rn : String(r.value);
    switch (op) {
      case '=':
      case '==':
        return a === b;
      case '<>':
      case '!=':
        return a !== b;
      case '<':
        return bothNum ? ln < rn : String(a) < String(b);
      case '>':
        return bothNum ? ln > rn : String(a) > String(b);
      case '<=':
        return bothNum ? ln <= rn : String(a) <= String(b);
      case '>=':
        return bothNum ? ln >= rn : String(a) >= String(b);
      default:
        return 'unknown';
    }
  }
  // 裸原子：等于原始参数值 → 命中行（真）；否则 → 查无此行（假）
  if (tokens.length === 1) {
    const tk = tokens[0];
    if (tk.t === 'str' && likePattern) {
      const s = tk.v;
      // LIKE 模式字面量：%…%（无空白）→ 通配符命中全表 → 恒真
      if (s.startsWith('%') && s.endsWith('%') && s.length > 2 && !/\s/.test(s)) return true;
      // %x → 去前导通配符后与搜索词比对（闭合上下文残留 % 通配符语义）
      if (s.startsWith('%')) return String(s.slice(1)) === String(orig);
      // x% → 尾部通配符 → 命中（前缀匹配成功）
      if (s.endsWith('%')) return true;
    }
    if (['num', 'str', 'id'].includes(tk.t)) return String(tk.v) === String(orig);
  }
  // (…) 分组 / 标量子查询：递归求值
  const stripped = stripOuterParens(tokens);
  if (stripped !== tokens) return evalAtom(stripped, orig, likePattern);
  return 'unknown';
}

/** 布尔表达式求值（AND 优先于 OR）；返回 true/false/'unknown' */
function evalBoolExpr(tokens, orig, likePattern) {
  const orGroups = splitTop(tokens, (tk) => tk.t === 'id' && /^(or)$/i.test(tk.v));
  if (orGroups.length > 1) {
    const rs = orGroups.map((g) => evalBoolExpr(g, orig, likePattern));
    if (rs.some((r) => r === true)) return true;
    if (rs.every((r) => r === false)) return false;
    return 'unknown';
  }
  const andGroups = splitTop(tokens, (tk) => tk.t === 'id' && /^(and)$/i.test(tk.v));
  const rs = andGroups.map((g) => evalAtom(g, orig, likePattern));
  if (rs.some((r) => r === false)) return false;
  if (rs.some((r) => r === 'unknown')) return 'unknown';
  return true;
}

// ============================================================================
// 四、页面构造
// ============================================================================

const rowsHtml = (rows) =>
  rows.map((r) => `<tr><td>${r.id}</td><td>${r.name}</td><td>${r.note}</td></tr>`).join('\n');

function pageShell(inner, { withPad = true } = {}) {
  return [
    '<!DOCTYPE html><html><head><title>recall lab</title></head><body>',
    NOISE(),
    inner,
    withPad ? `<p>${PAD}</p>` : '',
    '</body></html>',
  ].join('\n');
}

const pageNormal = (rows, extra = '') =>
  pageShell(`<h1>query result</h1>\n<table border="1"><tr><th>id</th><th>name</th><th>note</th></tr>\n${rowsHtml(rows)}\n</table>\n${extra}`);

const pageEmpty = () =>
  pageShell('<h1>query result</h1>\n<p>no records found for this query (empty result set)</p>', { withPad: false });

const pageConstant = () =>
  pageShell('<h1>status board</h1>\n<p>service running, request accepted, content is invariant regardless of parameters.</p>');

const ERR_PARSE_TEXT = '查询执行失败：ERR_PARSE_FAILED（语句无法解析）';
const pageParseErr = () => pageShell(`<h1>query failed</h1>\n<pre>${ERR_PARSE_TEXT}</pre>`, { withPad: false });

// 报错文本刻意包含引擎 ERROR_SIG 关键字（extractvalue/updatexml/SQL syntax），
// 且命中 dbmsFromError 的 MySQL 签名。
function errorText(func) {
  if (func === 'extractvalue') {
    return `Query error: XPATH syntax error: '~${DB.version}' — extractvalue(1,concat(0x7e,(SELECT version()))) failed (mysql ${DB.version})`;
  }
  if (func === 'updatexml') {
    return `Query error: XPATH syntax error: '~${DB.database}' — updatexml(1,concat(0x7e,(SELECT database())),1) failed (mysql ${DB.version})`;
  }
  return `Query error: BIGINT/DOUBLE value is out of range — ${func}() failed (mysql ${DB.version}, SQL syntax family)`;
}
const pageError = (func) =>
  pageShell(`<h1>query failed</h1>\n<pre>${errorText(func)}</pre>`, { withPad: false });

const ERR_SUBQUERY_TEXT = `Query error: Subquery returns more than 1 row (mysql ${DB.version})`;
const pageSubqueryErr = () =>
  pageShell(`<h1>query failed</h1>\n<pre>${ERR_SUBQUERY_TEXT}</pre>`, { withPad: false });

// —— /update 上下文专用页（UPDATE SET 注入：成功页 vs 失败页的长度/内容差异即布尔信号）——
// 成功页带填充（≈1.7KB，与基线同构）；失败页无填充（≈200B），真/假差异明确。
const updateOk = () =>
  pageShell('<h1>update result</h1>\n<p>update executed successfully: 1 row(s) affected (id=1)</p>');
const updateFailed = () =>
  pageShell('<h1>update failed</h1>\n<pre>record update rejected: condition evaluated to false (0 rows affected)</pre>', {
    withPad: false,
  });
const updateErr = (func) =>
  pageShell(`<h1>update failed</h1>\n<pre>${errorText(func)}</pre>`, { withPad: false });

// ============================================================================
// 五、响应语义（{status, body, delayMs}）
// ============================================================================

const OK = (body) => ({ status: 200, body, delayMs: 0 });
const PARSE_ERR = () => ({ status: 500, body: pageParseErr(), delayMs: 0 });

const SLEEP_RE = /sleep\s*\(\s*(\d+)\s*\)/i;

function cap(sec) {
  return Math.min(3, Math.max(0, sec));
}

/**
 * WHERE 值上下文通用求值（num/str/paren/bool 共用骨架）。
 * opts:
 *   prefix/suffix —— 拼接上下文（str: `'`…`'`；paren: `'`…`')`；search: `'%`…`%'`）
 *   rawSleep      —— 真：raw 值出现 sleep( 即延迟（/num 宽松策略，与靶场表一致）
 *   allowError    —— 是否回报错文本（/bool 禁用）
 *   allowEcho     —— 是否回 UNION/子查询回显（/bool 禁用）
 *   allowEmpty    —— 假条件是否允许空页（全部允许）
 *   baselineRows  —— 基线行（真条件渲染的行）
 *   likePattern    —— 真：LIKE 上下文（% 通配符语义），裸 %…% 字面量恒真、尾部 % 比较走前缀匹配
 */
function evalWhereContext(rawValue, orig, opts) {
  if (opts.rawSleep) {
    const m = SLEEP_RE.exec(rawValue);
    if (m) return { status: 200, body: pageNormal(opts.baselineRows), delayMs: cap(parseInt(m[1], 10)) * 1000 };
  }
  const full = opts.prefix + rawValue + opts.suffix;
  const tok = tokenize(full);
  if (!tok.ok) return PARSE_ERR();
  const { ok, statements } = analyzeStmts(tok.tokens);
  if (!ok) return PARSE_ERR();

  // 堆叠：`;` 后的语句含 sleep 才延迟（第一条语句里的 sleep 不延迟——隔离 time 通道）
  if (statements.length > 1) {
    for (let i = 1; i < statements.length; i++) {
      const s = findSleep(statements[i]);
      if (s > 0) return { status: 200, body: pageNormal(opts.baselineRows), delayMs: s * 1000 };
    }
    // 无延迟语句：按第一条语句的布尔语义出页
    const st = statements[0].filter((tk) => true);
    return whereSingle(st, orig, opts);
  }
  return whereSingle(statements[0], orig, opts);
}

function whereSingle(stmt, orig, opts) {
  // 1) UNION：回显 3 列行（列数不符 → 语法错误，模拟 used SELECT statements have different number of columns）
  const ui = findTopIdent(stmt, 'union');
  if (ui >= 0) {
    if (!opts.allowEcho) return OK(pageEmpty());
    let k = ui + 1;
    if (stmt[k] && stmt[k].t === 'id' && /^all$/i.test(stmt[k].v)) k++;
    if (!(stmt[k] && stmt[k].t === 'id' && /^select$/i.test(stmt[k].v))) return PARSE_ERR();
    const items = splitSelectList(stmt.slice(k + 1));
    if (items.length !== TABLE_COLUMNS.length) return PARSE_ERR();
    const cells = items.map((it) => {
      const r = evalItem(it);
      if (r.kind === 'multirow') return null;
      if (r.kind === 'str' || r.kind === 'num') return r.value;
      if (r.kind === 'null') return 'NULL';
      return '?';
    });
    if (cells.some((c) => c === null)) return { status: 500, body: pageSubqueryErr(), delayMs: 0 };
    const echoRow = `<tr><td>${cells[0]}</td><td>${cells[1]}</td><td>${cells[2]}</td></tr>`;
    return OK(pageNormal(opts.baselineRows, `<table border="1">\n${echoRow}\n</table>`));
  }
  // 2) WHERE 值位置出现顶层逗号 → 语法错误（子句型 payload 只在 ORDER BY 上下文合法）
  if (hasTopComma(stmt)) return PARSE_ERR();
  // 3) 报错函数（语法合法语句中）→ MySQL 风格报错文本
  const errFunc = findErrorFunc(stmt);
  if (errFunc) {
    if (!opts.allowError) return OK(pageEmpty());
    return { status: 500, body: pageError(errFunc), delayMs: 0 };
  }
  // 4) sleep（语法合法语句中，任意嵌套深度）
  const s = findSleep(stmt);
  if (s > 0) return { status: 200, body: pageNormal(opts.baselineRows), delayMs: s * 1000 };
  // 5) ORDER BY 后缀（列数探测 `1 ORDER BY n-- -`）：真/假条件出页，n 超列数 → 报错
  const orderIdx = findTopIdent(stmt, 'order');
  if (orderIdx >= 0 && stmt[orderIdx + 1] && /^by$/i.test(stmt[orderIdx + 1].v || '')) {
    const cond = stmt.slice(0, orderIdx);
    const orderTokens = stmt.slice(orderIdx + 2);
    if (orderTokens.length === 1 && orderTokens[0].t === 'num') {
      const n = parseInt(orderTokens[0].v, 10);
      if (n > TABLE_COLUMNS.length || n < 1) return PARSE_ERR();
    } else if (orderTokens.length >= 1 && !(orderTokens[0].t === 'id' && TABLE_COLUMNS.includes(orderTokens[0].v.toLowerCase()))) {
      return PARSE_ERR();
    }
    const r = cond.length ? evalBoolExpr(cond, orig) : true;
    return OK(r === false ? pageEmpty() : pageNormal(opts.baselineRows));
  }
  // 6) 标量子查询回显（inline 通道）：单表达式为 (SELECT '字面量') → 求值结果回显
  if (opts.allowEcho && stmt.length >= 3) {
    const stripped = stripOuterParens(stmt);
    if (stripped !== stmt && stripped.length && stripped[0].t === 'id' && /^select$/i.test(stripped[0].v)) {
      const items = splitSelectList(stripped.slice(1));
      if (items.length === 1) {
        const r = evalItem(items[0]);
        if (r.kind === 'str') {
          return OK(pageNormal(opts.baselineRows, `<p>criteria echo: ${r.value}</p>`));
        }
      }
    }
  }
  // 7) 布尔语义：真 → 正常页；假 → 空页；unknown → 正常页（基线友好）
  const r = evalBoolExpr(stmt, orig, !!opts.likePattern);
  return OK(r === false ? pageEmpty() : pageNormal(opts.baselineRows));
}

/** /orderby 上下文：ORDER BY {v}（逗号型子句 payload；level≥2 场景） */
function evalOrderbyContext(rawValue) {
  const full = 'SELECT id,name,note FROM lab_items ORDER BY ' + rawValue;
  const tok = tokenize(full);
  if (!tok.ok) return PARSE_ERR();
  const { ok, statements } = analyzeStmts(tok.tokens);
  if (!ok || statements.length !== 1) return PARSE_ERR();
  // 只取 ORDER BY 之后的注入尾段做子句合法性判定——原实现把整个语句（含语句自带的
  // SELECT…ORDER BY）交给黑名单/逗号拆分，基线 sort=id 也命中 'order' 黑名单恒 500
  // （time 能命中纯因 sleep 检查在黑名单之前）。
  const all = statements[0];
  const ordIdx = findTopIdent(all, 'order');
  if (ordIdx < 0 || !(all[ordIdx + 1] && all[ordIdx + 1].t === 'id' && /^by$/i.test(all[ordIdx + 1].v))) {
    return PARSE_ERR();
  }
  const stmt = all.slice(ordIdx + 2);
  // 报错函数优先（`,(extractvalue(...))` 逗号型 / `id AND extractvalue(...)` 表达式型）
  const errFunc = findErrorFunc(stmt);
  if (errFunc) return { status: 500, body: pageError(errFunc), delayMs: 0 };
  const s = findSleep(stmt);
  if (s > 0) return { status: 200, body: pageNormal(ROWS), delayMs: s * 1000 };
  // 非法子句关键字（顶层）：ORDER BY 位置不能出现这些
  for (const kw of ['having', 'order', 'limit', 'union', 'procedure', 'group', 'where', 'into']) {
    if (findTopIdent(stmt, kw) >= 0) return PARSE_ERR();
  }
  // 逗号型条目：`(SELECT …)` 多行子查询 → 报错；其余（列名/数字/布尔表达式）→ 正常页
  const items = splitTop(stmt, (tk) => tk.t === 'op' && tk.v === ',');
  for (const it of items) {
    const stripped = stripOuterParens(it);
    if (stripped !== it && stripped.length && stripped[0].t === 'id' && /^select$/i.test(stripped[0].v)) {
      const sub = evalItem(it);
      if (sub.kind === 'multirow') return { status: 500, body: pageSubqueryErr(), delayMs: 0 };
    }
  }
  return OK(pageNormal(ROWS));
}

/**
 * /update 上下文：UPDATE items SET name='{name}' WHERE id={id}
 * 按 name 与 id 各自独立的布尔语义求值，任一为假返回失败页。
 * 纯字符串字面量（无逃逸）→ 恒真（赋值成功）；id 数值/条件表达式 → 布尔求值。
 */
function evalUpdateContext(idv, namev) {
  // —— SET name 部分 ——
  let setTrue = true;
  const fullName = "'" + namev + "'";
  const nTok = tokenize(fullName);
  if (nTok.ok) {
    const nStmts = analyzeStmts(nTok.tokens);
    if (nStmts.ok && nStmts.statements.length === 1) {
      const st = nStmts.statements[0];
      if (st.length === 1 && st[0].t === 'str') {
        setTrue = true; // 字面量赋值恒成功
      } else {
        const errFunc = findErrorFunc(st);
        if (errFunc) return { status: 500, body: updateErr(errFunc), delayMs: 0 };
        const s = findSleep(st);
        if (s > 0) return { status: 200, body: updateOk(), delayMs: s * 1000 };
        // UPDATE SET 逗号拼接语义：x',1=1-- - → 取逗号后的条件表达式为布尔判定源
        // 无逗号时取首个字符串字面量后的全部 token 为条件（AND/OR 布尔表达式）
        const commaIdx = st.findIndex((tk) => tk.t === 'op' && tk.v === ',');
        const tail = commaIdx >= 0 ? st.slice(commaIdx + 1) : st.slice(1);
        const r = tail.length ? evalBoolExpr(tail, 'alice') : 'unknown';
        setTrue = r !== false;
      }
    } else setTrue = false;
  } else setTrue = false;
  // —— WHERE id 部分 ——
  let whereTrue = true;
  const iTok = tokenize(idv);
  if (iTok.ok && iTok.tokens.length) {
    const r = evalBoolExpr(iTok.tokens, '1');
    whereTrue = r !== false;
  }
  return setTrue && whereTrue ? OK(updateOk()) : OK(updateFailed());
}

// ============================================================================
// 六、HTTP 胶水
// ============================================================================

const DEBUG = process.env.RECALL_LAB_DEBUG === '1';

/** 创建靶场服务器（工厂，便于 e2e 同进程复用） */
export function createRecallLab() {
  const stats = { total: 0, sleepMs: 0, byPath: {} };
  const resetStats = () => {
    stats.total = 0;
    stats.sleepMs = 0;
    stats.byPath = {};
  };

  const server = http.createServer((req, res) => {
    stats.total++;
    let u;
    try {
      u = new URL(req.url, 'http://recall-lab.local');
    } catch {
      res.statusCode = 400;
      return res.end('<h1>bad request</h1>');
    }
    stats.byPath[u.pathname] = (stats.byPath[u.pathname] || 0) + 1;
    const send = (out) => {
      if (DEBUG) console.log(`[recall-lab] ${u.pathname}${u.search} -> ${out.status} delay=${out.delayMs}ms`);
      const emit = () => {
        res.statusCode = out.status;
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('X-Powered-By', 'PHP/8.2.1-recall-lab');
        res.end(out.body);
      };
      if (out.delayMs > 0) {
        stats.sleepMs += out.delayMs;
        setTimeout(emit, out.delayMs);
      } else emit();
    };
    try {
      const v = (name) => u.searchParams.get(name) ?? '';
      switch (u.pathname) {
        // 数值型：宽松 sleep（任意出现即延迟）——靶场行为表约定
        case '/num': {
          const out = evalWhereContext(v('id') || '1', '1', {
            prefix: '',
            suffix: '',
            rawSleep: true,
            allowError: true,
            allowEcho: true,
            baselineRows: ROWS.filter((r) => r.id === 1),
          });
          return send(out);
        }
        // 单引号字符串：严格闭合（含 '' 转义语义）
        case '/str': {
          const out = evalWhereContext(v('name') || 'foo', 'foo', {
            prefix: "'",
            suffix: "'",
            rawSleep: false,
            allowError: true,
            allowEcho: true,
            baselineRows: ROWS.filter((r) => r.name === 'foo'),
          });
          return send(out);
        }
        // 括号包裹 ('…')：严格 ') 闭合
        case '/paren': {
          const out = evalWhereContext(v('id') || '1', '1', {
            prefix: "('",
            suffix: "')",
            rawSleep: false,
            allowError: true,
            allowEcho: true,
            baselineRows: ROWS.filter((r) => r.id === 1),
          });
          return send(out);
        }
        // ORDER BY 位置（level≥2 逗号型子句 payload）
        case '/orderby':
          return send(evalOrderbyContext(v('sort') || 'id'));
        // 仅布尔差异：无回显/无报错/无延迟
        case '/bool': {
          const out = evalWhereContext(v('uid') || '1', '1', {
            prefix: '',
            suffix: '',
            rawSleep: false,
            allowError: false,
            allowEcho: false,
            baselineRows: ROWS,
          });
          // /bool 永不 500（语法错误也回空结果页，保持「仅布尔差异」口径）
          return send(out.status >= 500 ? OK(pageEmpty()) : out);
        }
        // 仅时间：内容恒定，sleep( 任意出现即延迟
        case '/time': {
          const m = SLEEP_RE.exec(v('tid') || '1');
          return send({ status: 200, body: pageConstant(), delayMs: m ? cap(parseInt(m[1], 10)) * 1000 : 0 });
        }
        // 仅堆叠：`;` 后第二条语句含 sleep 才延迟
        case '/stacked': {
          const raw = v('i') || '1';
          const semi = raw.indexOf(';');
          let delayMs = 0;
          if (semi >= 0) {
            const m = SLEEP_RE.exec(raw.slice(semi));
            if (m) delayMs = cap(parseInt(m[1], 10)) * 1000;
          }
          return send({ status: 200, body: pageNormal(ROWS.filter((r) => r.id === 1)), delayMs });
        }
        // 搜索型注入（LIKE 上下文）：WHERE title LIKE '%{q}%'，需 % 闭合 + ' 闭合
        // likePattern 语义：裸 %…% 字面量恒真（全表基线）、尾部 % 比较走前缀匹配
        case '/search': {
          const out = evalWhereContext(v('q') || 'alice', 'alice', {
            prefix: "'%",
            suffix: "%'",
            rawSleep: false,
            allowError: true,
            allowEcho: true,
            likePattern: true,
            baselineRows: ROWS,
          });
          return send(out);
        }
        // UPDATE SET 注入：UPDATE items SET name='{name}' WHERE id={id}
        // 纯字符串字面量恒真；逃逸后追加条件按布尔判定（任一假 → 失败页）
        case '/update':
          return send(evalUpdateContext(v('id') || '1', v('name') || 'alice'));
        case '/__stats':
          res.setHeader('Content-Type', 'application/json');
          return res.end(JSON.stringify(stats));
        default:
          res.statusCode = 404;
          return res.end('<h1>404 not found (recall-lab)</h1>');
      }
    } catch (e) {
      res.statusCode = 500;
      return res.end(`<h1>lab internal error</h1><pre>${String(e && e.message)}</pre>`);
    }
  });

  return { server, stats, resetStats };
}

// 直接运行入口：node e2e/recall-lab/lab-server.js（端口取 PORT || 8123）
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT) || 8123;
  const { server } = createRecallLab();
  server.listen(port, '127.0.0.1', () => {
    console.log(`[recall-lab] listening on http://127.0.0.1:${port}`);
    console.log('[recall-lab] endpoints: /num /str /paren /orderby /bool /time /stacked /search /update (GET, 单参数)');
  });
}
