// P0 修复验证脚本（2026-09-05）——断言式，全绿即修复生效
import assert from 'node:assert/strict';
import { applyTampers } from './src/core/tamper/applyTampers.js';
import { chunkSimilarity } from './src/core/statsHelper.js';

const ctx = { config: { wafEvasion: {} } };
let pass = 0, fail = 0;
function check(name, fn) {
  try { fn(); pass++; console.log(`  PASS  ${name}`); }
  catch (e) { fail++; console.log(`  FAIL  ${name}\n        ${e.message}`); }
}

console.log('--- P0-B: charencode 对齐官方（全字符大写 %XX，%XX 透传） ---');
check("admin' OR 1=1-- - -> %61..6E%27%20%4F%52%20%31%3D%31%2D%2D%20%2D（- 也编码，官方语义）", () => {
  assert.equal(applyTampers("admin' OR 1=1-- -", ctx, ['charencode']),
    '%61%64%6D%69%6E%27%20%4F%52%20%31%3D%31%2D%2D%20%2D');
});
check('SELECT -> %53%45%4C%45%43%54（官方 doctest）', () => {
  assert.equal(applyTampers('SELECT', ctx, ['charencode']), '%53%45%4C%45%43%54');
});
check('已有 %20 透传不重复编码', () => {
  assert.equal(applyTampers('A%20B', ctx, ['charencode']), '%41%20%42');
});
check('非字符串入参不炸', () => {
  assert.equal(applyTampers(123, ctx, ['charencode']), 123);
});

console.log('--- chardoubleencode 对齐官方（%25+大写XX） ---');
check('SELECT -> %2553%2545%254C%2545%2543%2554（官方 doctest）', () => {
  assert.equal(applyTampers('SELECT', ctx, ['chardoubleencode']),
    '%2553%2545%254C%2545%2543%2554');
});
check('空格 -> %2520', () => {
  assert.equal(applyTampers(' ', ctx, ['chardoubleencode']), '%2520');
});
check('已有 %20 -> %2520', () => {
  assert.equal(applyTampers('%20', ctx, ['chardoubleencode']), '%2520');
});

console.log('--- percentage 对齐官方（每字符前置 %，空格/%XX 保留） ---');
check("SELECT FIELD FROM TABLE -> %S%E%L%E%C%T %F%I%E%L%D %F%R%O%M %T%A%B%L%E（官方 doctest）", () => {
  assert.equal(applyTampers('SELECT FIELD FROM TABLE', ctx, ['percentage']),
    '%S%E%L%E%C%T %F%I%E%L%D %F%R%O%M %T%A%B%L%E');
});

console.log('--- P0-A: 占位还原（数字粘连场景） ---');
check('__S__x__E__ + charunicodeencode → 标记完好（粘连宽松还原）', () => {
  const out = applyTampers('__S__x__E__ UNION SELECT', ctx, ['charunicodeencode']);
  assert.ok(out.includes('__S__'), `应含 __S__，实际: ${out}`);
  assert.ok(out.includes('__E__'), `应含 __E__，实际: ${out}`);
});
check('__S__x__E__7331999001（粘连+原生数字）→ 两标记均还原', () => {
  const out = applyTampers('__S__x__E__7331999001 UNION SELECT', ctx, ['charunicodeencode']);
  assert.ok(out.includes('__S__'), `应含 __S__，实际: ${out}`);
  assert.ok(out.includes('__E__'), `应含 __E__，实际: ${out}`);
});
check('多标记两两相邻 __S__x__E__y__S__ → 三标记全还原', () => {
  const out = applyTampers('__S__x__E__y__S__ AND 1=1', ctx, ['charunicodeencode']);
  assert.equal((out.match(/__S__/g) || []).length, 2, `__S__ 应出现 2 次，实际: ${out}`);
  assert.equal((out.match(/__E__/g) || []).length, 1, `__E__ 应出现 1 次，实际: ${out}`);
});
check('无标记 payload 不受影响（无占位残留）', () => {
  const out = applyTampers('1 UNION SELECT 2', ctx, ['charunicodeencode']);
  assert.ok(!/7331999/.test(out), `不应有占位残留: ${out}`);
});

console.log('--- P0-C: chunkSimilarity 边界 ---');
check("chunkSimilarity('','') === 1（双空响应=完全相同）", () => {
  assert.equal(chunkSimilarity('', ''), 1);
});
check("chunkSimilarity('abc','abc') === 1", () => {
  assert.equal(chunkSimilarity('abc', 'abc'), 1);
});
check("chunkSimilarity('','x') === 0（空 vs 非空仍为 0）", () => {
  assert.equal(chunkSimilarity('', 'x'), 0);
});

console.log(`\n结果: ${pass} pass, ${fail} fail`);
process.exit(fail === 0 ? 0 : 1);
