// ============================================================================
// wafSamples.guard.test.js —— CRS 对拍样本集「单一来源」守卫
//
// 为什么必须有：静态扫描（tamper-sweep.mjs / crs-equivalence.mjs，走自实现 crs-engine）
// 与真机对拍（modsec-live.mjs，走真实 ModSecurity）结论要能横向比，前提是喂同一批 payload。
// 两边各自内联一份数组的代价：改了一边忘另一边 → 「自实现 vs 真引擎」的差异里混进
// 「样本不同」这个**假差异**，归因必然跑偏，且看数字的人看不出来。
//
// 判据用**源码文本**而不是 import：本仓反复出现的病灶是「守卫看不见它声称在管的东西」——
// 判 import 只能证明「模块能被加载」，证明不了「这个脚本真的用它当样本源」。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

const CONSUMERS = [
  '../../e2e/waf-real/tamper-sweep.mjs',
  '../../e2e/waf-real/modsec-live.mjs',
];
const SOURCE = '../../e2e/waf-real/samples.mjs';

test('每个对拍脚本都从 samples.mjs 取样本（防两份数组各自漂移）', () => {
  for (const f of CONSUMERS) {
    const src = read(f);
    assert.ok(
      /import\s*\{[^}]*\b(SAMPLES|SAFE_SAMPLES)\b[^}]*\}\s*from\s*'\.\/samples\.mjs'/.test(src),
      `${f} 没有从 ./samples.mjs 导入样本 —— 内联一份数组会让静态/真机两边样本悄悄分叉`
    );
  }
});

test('样本集自身非空且规模不缩水（防有人清空后守卫恒绿）', async () => {
  // 直接 import 取真实条数：源码正则数字符串会数进 ctx / note 这些非样本字符串，
  // 样本改成 {ctx,payload} 之后那个数已经不再是「样本条数」（判据与危害不同源 = 假绿）。
  const { SAMPLES: S, SAFE_SAMPLES: SAFE, CONTEXTS } = await import(new URL(SOURCE, import.meta.url));
  assert.ok(S.length >= 8, `攻击样本只剩 ${S.length} 条（基线 8）—— 缩水会弱化对拍，别默默改小`);
  assert.ok(SAFE.length >= 4, `安全样本只剩 ${SAFE.length} 条（基线 4）`);
  for (const s of [...S, ...SAFE]) {
    assert.ok(CONTEXTS[s.ctx], `样本 ctx「${s.ctx}」未在 CONTEXTS 登记 —— 打过去会打到不存在的端点`);
    assert.ok(typeof s.payload === 'string' && s.payload.length > 0, '样本 payload 不得为空');
  }
  const src = read(SOURCE);
  assert.ok(/export const SAMPLES = \[/.test(src), 'samples.mjs 里找不到 SAMPLES —— 改名了，本守卫需同步');
  assert.ok(/export const SAFE_SAMPLES = \[/.test(src), 'samples.mjs 里找不到 SAFE_SAMPLES —— 改名了，本守卫需同步');
});

test('样本必须覆盖 union / boolean / error / time 四类通道（防只测好过的那类）', () => {
  const src = read(SOURCE);
  const joined = src.toUpperCase();
  for (const kw of ['UNION', 'AND 1=1', 'EXTRACTVALUE', 'SLEEP']) {
    assert.ok(joined.includes(kw), `样本集缺 ${kw} 对应的通道 —— 少一类通道的实测等于没测`);
  }
});
