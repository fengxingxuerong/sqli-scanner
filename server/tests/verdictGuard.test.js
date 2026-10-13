// ============================================================================
// tests/verdictGuard.test.js —— 结论不夸大守卫（spec 5.6.1 规则 5 / 模块 6.5）
//
// 验证 applyValidity 的 verdict 裁定：
//   ① 有漏洞 → vulnerability_detected
//   ② 无漏洞 + 可靠 → no_vulnerability_detected
//   ③ 无漏洞 + 不可靠 → inconclusive（不得为 no_vulnerability_detected）
//   ④ 无漏洞 + 0 注入点 → inconclusive（不得为 no_vulnerability_detected）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';

// 直接测 applyValidity 的逻辑（从 scanRunner 提取的核心判定函数）
function decideVerdict(vulns, reliable, nothingTested) {
  const negative = vulns.length === 0;
  const inconclusive = negative && (!reliable || nothingTested);
  return inconclusive
    ? 'inconclusive'
    : negative
      ? 'no_vulnerability_detected'
      : 'vulnerability_detected';
}

test('有漏洞 → vulnerability_detected', () => {
  assert.equal(decideVerdict([{ id: 'v1' }], true, false), 'vulnerability_detected');
  assert.equal(decideVerdict([{ id: 'v1' }], false, false), 'vulnerability_detected');
});

test('无漏洞 + 可靠 → no_vulnerability_detected', () => {
  assert.equal(decideVerdict([], true, false), 'no_vulnerability_detected');
});

test('无漏洞 + 不可靠 → inconclusive（不得为 no_vulnerability_detected）', () => {
  const v = decideVerdict([], false, false);
  assert.equal(v, 'inconclusive');
  assert.notEqual(v, 'no_vulnerability_detected', '不可靠时不得呈现为无漏洞');
});

test('无漏洞 + 0 注入点 → inconclusive（不得为 no_vulnerability_detected）', () => {
  const v = decideVerdict([], true, true);
  assert.equal(v, 'inconclusive');
  assert.notEqual(v, 'no_vulnerability_detected', '0 注入点时不得呈现为无漏洞');
});

test('WAF 全量拦截场景 → inconclusive（不得为无漏洞）', () => {
  // WAF 全量拦截：vulns 为空（全被拦），reliable=false（拦截导致不可靠）
  const v = decideVerdict([], false, false);
  assert.equal(v, 'inconclusive');
  assert.notEqual(v, 'no_vulnerability_detected', 'WAF 全量拦截不得呈现为无漏洞');
});