// 全量 tamper 插件对 CRS v4.1.0 的静态绕过率扫描（不发包）
// 目的：用数据回答「哪些 tamper 对 CRS PL1 有效」，而不是凭经验猜。
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { evaluate } from './crs-engine.js';
// [2026-09-27] 样本集上提到 samples.mjs：真机 ModSecurity 对拍（modsec-live.mjs）
// 用同一批 payload，否则「自实现 vs 真引擎」的差异里会混进「样本不同」这个假差异。
import { SAMPLES } from './samples.mjs';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const here = dirname(fileURLToPath(import.meta.url));
const { applyTampers } = require(resolve(here, '../../server/src/core/tamper/applyTampers.js'));
const { tamperRegistry } = require(resolve(here, '../../server/src/core/tamper/TamperRegistry.js'));

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
