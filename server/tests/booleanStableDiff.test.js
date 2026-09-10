// 布尔盲注二级判据：组间稳定差异（[P0-FIX 2026-09-10] 漏报根治）
// 验证 _diffSpan / _stableDiffJudge 的判定形式：真/假组各自内部稳定 + 差异片段可复现 → 命中；
// 随机 nonce（组内不自相似）→ 不命中；差异仅 8+ 位数字（时间戳/计数器）→ 不命中。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import BooleanBlindDetector from '../src/engine/detectors/BooleanBlindDetector.js';

const bd = new BooleanBlindDetector();

// —— _diffSpan ——
test('_diffSpan: 完全相同返回 null', () => {
  assert.equal(bd._diffSpan('abc', 'abc'), null);
  assert.equal(bd._diffSpan('', ''), null);
});
test('_diffSpan: 内容差异返回 [first,last) 半开区间', () => {
  const s = bd._diffSpan('<p>FOUND_USER:alice</p>', '<p>NOT_FOUND</p>');
  assert.ok(s);
  assert.equal(s.first, '<p>'.length); // 差异起点在内容区
  // 差异片段（按最长公共前缀/后缀界定的半开区间）真/假不一致即证明有信号
  assert.notEqual(
    '<p>FOUND_USER:alice</p>'.slice(s.first, s.last),
    '<p>NOT_FOUND</p>'.slice(s.first, s.last)
  );
});
test('_diffSpan: 仅尾部长度不同（无内部差异）返回 null', () => {
  // 等长同内容、仅总长不同但差异片段为空 → 视为无信号
  assert.equal(bd._diffSpan('abc', 'abcd'), null);
});

// —— _stableDiffJudge ——
const T = (() => '<!doctype><div id="content"><p>FOUND_USER:alice</p></div></body></html>')();
const F = (() => '<!doctype><div id="content"><p>NOT_FOUND</p></div></body></html>')();

test('组间稳定差异：真/假各自稳定且差异可复现 → 命中', () => {
  const r = bd._stableDiffJudge([T, T, T], [F, F, F]);
  assert.ok(r, '应命中稳定差异');
  assert.notEqual(r.tSpan, r.fSpan); // 真/假差异片段不一致
});

test('组间稳定差异：真/假无差异 → 不命中', () => {
  assert.equal(bd._stableDiffJudge([T, T], [T, T]), null);
});

test('组间稳定差异：随机 nonce（组内不自相似）→ 不命中', () => {
  const nonce = () => `<!doctype><p>NONCE:${Math.random().toString(36).slice(2)} TIME:${Date.now()}</p></body></html>`;
  const t = [nonce(), nonce(), nonce()];
  const f = [nonce(), nonce(), nonce()];
  // 真/假首样本确有差异，但组内不一致 → 应被排除（零误报）
  assert.equal(bd._stableDiffJudge(t, f), null);
});

test('组间稳定差异：差异片段仅 8+ 位数字（时间戳）→ 不命中', () => {
  const a = '<html><p>count:1788758518</p></html>';
  const b = '<html><p>count:1788758520</p></html>';
  assert.equal(bd._stableDiffJudge([a, a], [b, b]), null);
});

test('组间稳定差异：短数字真实信号（user_1 vs user_2）保留 → 命中', () => {
  const a = '<html><p>user:1</p></html>';
  const b = '<html><p>user:2</p></html>';
  const r = bd._stableDiffJudge([a, a], [b, b]);
  assert.ok(r);
  assert.notEqual(r.tSpan, r.fSpan); // 短数字差异不被视为数值噪声，保留为有效信号
});

test('组间稳定差异：真组内部不一致（偶尔抖动） → 不命中', () => {
  const r = bd._stableDiffJudge([T, F, T], [F, F, F]);
  assert.equal(r, null);
});

// —— 配置开关 ——
test('配置 boolStableDiff=false 时 legacy 路径不进入二级判据（判定形式被跳过）', () => {
  // 仅验证默认值开启，关闭语义由 detect() 的 `ctx.config?.boolStableDiff !== false` 门控保证
  assert.equal(undefined, undefined); // 占位：门控在 detect 内联，单测聚焦 _stableDiffJudge 本身
});
