// ============================================================================
// tests/timingBaseline.test.js —— 目标级动态基线测试（spec 5.6.1 规则 1 / 模块 6.1）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getTimingBaseline, updateTimingBaseline, getTimingBaselineState, _resetForTest, MIN_SAMPLES } from '../src/engine/detectorSupport/timingBaseline.js';

test('样本不足时返回 null（降级为扫描内基线）', () => {
  _resetForTest();
  updateTimingBaseline('http://example.com/', 100);
  updateTimingBaseline('http://example.com/', 110);
  assert.equal(getTimingBaseline('http://example.com/'), null, '样本 < MIN_SAMPLES 时应返回 null');
});

test('样本足够后返回基线（mean/std/count）', () => {
  _resetForTest();
  for (let i = 0; i < MIN_SAMPLES; i++) {
    updateTimingBaseline('http://example.com/', 100 + i * 10);
  }
  const bl = getTimingBaseline('http://example.com/');
  assert.ok(bl, '样本 ≥ MIN_SAMPLES 时应返回基线');
  assert.ok(bl.mean > 0, 'mean > 0');
  assert.ok(bl.std >= 0, 'std ≥ 0');
  assert.ok(bl.count >= MIN_SAMPLES, 'count ≥ MIN_SAMPLES');
});

test('不同 host 独立维护基线', () => {
  _resetForTest();
  for (let i = 0; i < MIN_SAMPLES; i++) {
    updateTimingBaseline('http://a.com?x', 100);
    updateTimingBaseline('http://b.com?y', 200);
  }
  const blA = getTimingBaseline('http://a.com?z');
  const blB = getTimingBaseline('http://b.com?w');
  assert.ok(blA && blB, '两个 host 都应有基线');
  assert.ok(blB.mean > blA.mean, 'b 的 mean 应大于 a（200 vs 100）');
});

test('EWMA 平滑：新样本权重高于旧样本', () => {
  _resetForTest();
  // 先喂 10 个 100ms 样本
  for (let i = 0; i < 10; i++) updateTimingBaseline('http://ewma.com/', 100);
  // 再喂 5 个 500ms 样本
  for (let i = 0; i < 5; i++) updateTimingBaseline('http://ewma.com/', 500);
  const bl = getTimingBaseline('http://ewma.com/');
  assert.ok(bl, '应有基线');
  // EWMA 偏向新样本，mean 应明显大于 (100+500)/2=300
  assert.ok(bl.mean > 300, `EWMA 应偏向新样本，mean=${bl.mean} 应 > 300`);
});

test('URL 字符串 / URL 对象 / {hostname} 均可提取 host', () => {
  _resetForTest();
  const url = 'http://test.example.com/page?id=1';
  for (let i = 0; i < MIN_SAMPLES; i++) {
    updateTimingBaseline(url, 100);
  }
  // 同 host 不同路径应命中同一基线
  const bl1 = getTimingBaseline('http://test.example.com/other');
  const bl2 = getTimingBaseline({ hostname: 'test.example.com' });
  const bl3 = getTimingBaseline({ url: 'http://test.example.com/x' });
  assert.ok(bl1 && bl2 && bl3, '三种形态都应命中基线');
  assert.equal(bl1.count, bl2.count, '同 host 同基线');
});

test('LRU 淘汰：超限时淘汰最旧 host', () => {
  _resetForTest();
  // 喂 MAX_HOSTS + 10 个不同 host
  const { maxHosts } = getTimingBaselineState();
  for (let i = 0; i < maxHosts + 10; i++) {
    updateTimingBaseline(`http://host${i}.com/`, 100);
  }
  const state = getTimingBaselineState();
  assert.ok(state.hosts <= maxHosts, `hosts=${state.hosts} 应 ≤ maxHosts=${maxHosts}`);
});

test('非法样本被忽略（NaN/负数）', () => {
  _resetForTest();
  updateTimingBaseline('http://valid.com/', 100);
  updateTimingBaseline('http://valid.com/', NaN);
  updateTimingBaseline('http://valid.com/', -50);
  updateTimingBaseline('http://valid.com/', 'not-a-number');
  const state = getTimingBaselineState();
  assert.equal(state.hosts, 1, '只应有 1 个有效 host');
});