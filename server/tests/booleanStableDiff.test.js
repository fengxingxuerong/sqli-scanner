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
// [2026-10-05] 原此处是空测试：`assert.equal(undefined, undefined); // 占位` ——
// 它绿着但什么都没验证，而注释自陈"门控在 detect 内联"恰好说明**门控本身无人验证**。
// 门控散在 BooleanBlindDetector 的三处（_stableDiff 路径 262 行、legacy 差异路径 421 行、
// 411 行的时间探测路径 611 行）。三处任一被漏改，用户设 boolStableDiff=false 就会
// 在某条路径上照旧进入二级判据 ⇒ "关闭开关"行为不一致，且无报错。
// 本测试不试图驱动完整 detect（三处都依赖真实请求/响应），改为**守卫门控本身存在且写法一致**：
// 判据是"三处都用 !== false 的显式关闭语义"，这正是"只认 false 为关闭、其余默认开"的实现。
test('配置 boolStableDiff=false 门控：detect 内三处判定写法一致（防漏改致开关失效）', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../src/engine/detectors/BooleanBlindDetector.js', import.meta.url), 'utf8');
  const gates = src.match(/ctx\.config\?\.boolStableDiff\s*!==\s*false/g) || [];
  assert.ok(gates.length >= 3,
    `boolStableDiff=false 的门控应至少出现 3 处（_stableDiff / legacy 差异 / 时间探测三条路径），实际 ${gates.length} 处。\n` +
    '若确有理由减少，请同步修改本守卫并写明原因；否则说明某条路径漏了开关。');
  // 反向：不得出现把 true 解读为"关闭"的写法（如 === true 才启用、|| false 兜底）
  assert.ok(!/boolStableDiff\s*===\s*true/.test(src),
    '不得用 `=== true` 判定启用：null/undefined 会被误判为关闭 —— 开关语义应是"仅显式 false 才关"');
  assert.ok(!/boolStableDiff\s*\|\|\s*false/.test(src),
    '不得用 `|| false` 兜底：空串等假值会被静默当成关闭');
});

test('配置 boolStableDiff 默认值为 true（关闭需显式表达）', async () => {
  const { defaults } = await import('../src/config/defaults.js');
  assert.equal(defaults.boolStableDiff, true,
    '默认必须开启（漏报根治的判据），关闭只能由用户显式设 false');
});
