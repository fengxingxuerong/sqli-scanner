import { test } from 'node:test';
import assert from 'node:assert/strict';
import { binaryGuessColumns, createColumnGuessCache } from '../src/engine/columnGuess.js';

test('binaryGuessColumns：ORDER BY 1 成功 → 返回 >=1', async () => {
  const probe = async (n) => {
    if (n <= 1) return { status: 200, data: 'a'.repeat(100) };
    return { status: 500, data: '' };
  };
  const cols = await binaryGuessColumns(probe, { baseLen: 100, maxCols: 50 });
  assert.equal(cols, 1);
});

test('binaryGuessColumns：ORDER BY maxCols+1 失败 → 实际列数 <= maxCols', async () => {
  let callCount = 0;
  const probe = async (n) => {
    callCount++;
    if (n <= 5) return { status: 200, data: 'OK'.repeat(50) };
    return { status: 500, data: '' };
  };
  const cols = await binaryGuessColumns(probe, { baseLen: 100, maxCols: 50 });
  assert.equal(cols, 5);
  // 收敛到 5 < maxCols → 判据有效 → 不触发形态自检，请求数与历史一致
  assert.ok(callCount <= 7);
});

test('缓存命中：同 cacheKey 第二次调用不发 probe 请求', async () => {
  const cache = createColumnGuessCache();
  let callCount = 0;
  const probe = async (n) => {
    callCount++;
    // 收敛到 7 < maxCols（capped=false）：判据有效的正常形态
    return n <= 7 ? { status: 200, data: 'x'.repeat(200) } : { status: 500, data: '' };
  };
  const first = await binaryGuessColumns(probe, { baseLen: 200, maxCols: 50, cache, cacheKey: 'p1' });
  assert.equal(first, 7);
  const firstCalls = callCount;
  const second = await binaryGuessColumns(probe, { baseLen: 200, maxCols: 50, cache, cacheKey: 'p1' });
  assert.equal(second, first);
  assert.equal(callCount, firstCalls, '缓存命中后不应再发 probe');
});

test('失败降级：所有请求失败返回保守值 1', async () => {
  const probe = async () => null;
  const cols = await binaryGuessColumns(probe, { baseLen: 100, maxCols: 50 });
  assert.equal(cols, 1);
});

test('maxColumnsGuess 参数控制上限', async () => {
  let maxProbed = 0;
  const probe = async (n) => {
    maxProbed = Math.max(maxProbed, n);
    return { status: 200, data: 'x'.repeat(200) };
  };
  const cols = await binaryGuessColumns(probe, { baseLen: 200, maxCols: 10 });
  // [2026-10-01 契约变更] 本用例的 mock「全 200 + 等长」是判据失效形态：二分顶到 maxCols
  // 且形态自检不可区分 ⇒ capped ⇒ 按 binaryProbe 调用方约定返回 null（UNION 放弃），
  // 不再把 10 这个荒谬值交给下游。
  assert.equal(cols, null, 'capped（判据失效顶到上限）必须返回 null');
  // [2026-09-17] 判据失效时会额外探一次 maxCols+1 作为形态自检基准，允许 maxProbed 比 maxCols 大 1。
  assert.ok(maxProbed <= 10 + 1, `maxProbed=${maxProbed} 应 <= 11`);
});

// ── 2026-10-01 新增：capped 契约与缓存键形态维度 ────────────────────────────
test('capped 结果【不写入缓存】（防跨扫描投毒）', async () => {
  const cache = createColumnGuessCache();
  const probe = async () => ({ status: 200, data: 'x'.repeat(200) }); // 判据失效 → capped
  const cols = await binaryGuessColumns(probe, { baseLen: 200, maxCols: 10, cache, cacheKey: 'cap1' });
  assert.equal(cols, null);
  assert.equal(cache.has('cap1'), false, 'capped 结果不得写入缓存');
});

test('缓存键形态维度：colGuessExtra 区分 tamper/obfuscate/boundary', async () => {
  const { colGuessExtra } = await import('../src/engine/columnGuess.js');
  const base = colGuessExtra({ config: {} }, '');
  const tampered = colGuessExtra({ config: { wafEvasion: { tamper: { enabled: true, plugins: ['space2comment'] } } } }, '');
  const obf = colGuessExtra({ config: { wafEvasion: { obfuscate: true } } }, '');
  const bounded = colGuessExtra({ config: {}, }, "')");
  assert.notEqual(base, tampered, 'tamper 链变化必须改变缓存键');
  assert.notEqual(base, obf, 'obfuscate 开关必须改变缓存键');
  assert.notEqual(base, bounded, '闭合符变化必须改变缓存键');
});

test('createColumnGuessCache 返回新 Map', () => {
  const c = createColumnGuessCache();
  assert.ok(c instanceof Map);
  assert.equal(c.size, 0);
});
// [CRS-FIX 2026-09-09] 缓存投毒回归：WAF 全量拦截时每个 ORDER BY 都返回 403 短响应，
// 既非 5xx 又远短于基线 → 被判据当成「超出列数」→ 二分收敛到 1。若把该 1 写入缓存，
// 后续换用有效 tamper 链的扫描会一直复用错误列数 → UNION 永远走不通。
test('WAF 全拦（403 短响应）→ 返回保守值 1 且【不写入缓存】', async () => {
  const cache = createColumnGuessCache();
  const probe = async () => ({ status: 403, data: '<html>403 blocked</html>' }); // 长度远小于 baseLen
  const cols = await binaryGuessColumns(probe, { baseLen: 1000, maxCols: 50, cache, cacheKey: 'k1' });
  assert.equal(cols, 1, '无有效探测时应回落保守值 1');
  assert.equal(cache.has('k1'), false, '不可信结果不得写入缓存（否则污染后续扫描）');
});

test('存在 2xx 响应 → 结果可信并正常写入缓存', async () => {
  const cache = createColumnGuessCache();
  const probe = async (n) => (n <= 3 ? { status: 200, data: 'x'.repeat(100) } : { status: 500, data: '' });
  const cols = await binaryGuessColumns(probe, { baseLen: 100, maxCols: 50, cache, cacheKey: 'k2' });
  assert.equal(cols, 3);
  assert.equal(cache.get('k2'), 3, '可信结果应写入缓存');
});

// ── 2026-09-17 新增：判据失效场景（复刻黑盒靶场 e2e/blackbox-lab 的真实形态）──────────
// 背景：目标「SQL 报错也返回 200 + 友好错误页 + 回显 SQL」时，原两条判据同时失效
// （状态码恒 200；错误页因回显 payload 而保持长度，实测 209 vs 正常页 224，
// 远超 baseLen*0.5 阈值）→ 二分一路判成功 → 收敛到 maxCols → UNION 提取必败。
test('恒 200 + 错误页回显 SQL（判据失效场景）→ 仍能猜出正确列数', async () => {
  const realCols = 4;
  const probe = async (n) => ({
    status: 200,
    data:
      `<div class="env">sql=SELECT id,username,email,role FROM users WHERE id=1 ORDER BY ${n}</div>` +
      (n <= realCols ? '<p>ok</p>' : '<p class="err">query failed</p>'),
  });
  const cols = await binaryGuessColumns(probe, { baseLen: 95, maxCols: 50 });
  assert.equal(cols, realCols, '判据失效场景下必须仍能猜对（修复前会返回 50）');
});

test('顶到上限但判据有效（长度随 n 变化）→ 不误启用形态判据', async () => {
  // 长度在某个 n 之后明显缩水 → 原长度判据有效 → 不应走到形态自检
  const realCols = 6;
  const probe = async (n) => ({
    status: 200,
    data: n <= realCols ? 'y'.repeat(200) : 'y'.repeat(40),
  });
  const cols = await binaryGuessColumns(probe, { baseLen: 200, maxCols: 50 });
  assert.equal(cols, realCols);
});
