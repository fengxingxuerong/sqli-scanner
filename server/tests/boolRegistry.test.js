// BooleanBlindDetector 注册表路径测试（node --test）
// 验证 useRegistry=true 时检测器从 selectPayloads 选取真假对，且 testFilter/testSkip 生效。
// useRegistry=false（默认）时回退到固定索引对，行为与历史一致（零回归）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { selectPayloads, listRegistry } from '../src/engine/payloadRegistry.js';

function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

// 确定性布尔响应 mock：真条件返回正常页面，假条件返回空/不同页面
function makeBooleanMock() {
  return {
    async request(opts) {
      const q = extractInjected(opts);
      const isFalse = /1=2|'1'='2|"1"="2|1=0/.test(q);
      if (isFalse) return { data: 'NO_RESULTS_PAGE', status: 200 };
      return { data: 'normal page content here stable prefix', status: 200 };
    },
  };
}

function buildCtx(httpClient, configOverrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {}, config: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: {
      timeoutMs: 5000,
      timeThresholdMs: 800,
      blindRobust: { enabled: false },
      ...configOverrides,
    },
  };
}

// ===== useRegistry=false 回退路径（零回归验证）=====
test('Boolean registry: useRegistry=false 走 legacy 索引对（确定性命中）', async () => {
  const d = new BooleanBlindDetector();
  const ctx = buildCtx(makeBooleanMock());
  // useRegistry 未设置 → 走 legacy 索引对
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'boolean');
  // legacy 路径 evidence 不含 test= 标签
  assert.ok(!res.evidence.includes('test='));
});

// ===== useRegistry=true 注册表路径 =====
test('Boolean registry: useRegistry=true 从注册表选取真假对（确定性命中）', async () => {
  const d = new BooleanBlindDetector();
  const ctx = buildCtx(makeBooleanMock(), { useRegistry: true, level: 1, risk: 1 });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'boolean');
  // 注册表路径 evidence 含 test= 标签（来自注册表条目 id）
  assert.ok(res.evidence.includes('test=') || res.evidence.includes('boundary'),
    `evidence should contain test= or boundary tag, got: ${res.evidence}`);
});

// ===== useRegistry=true + blindRobust 统计路径 =====
test('Boolean registry: useRegistry=true + blindRobust 统计判定（确定性命中）', async () => {
  const d = new BooleanBlindDetector();
  const ctx = buildCtx(makeBooleanMock(), {
    useRegistry: true,
    level: 1,
    risk: 1,
    blindRobust: { enabled: true, booleanSamples: 3, baselineSamples: 5, timeConfidenceZ: 2, minStableRatio: 0.66 },
  });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.ok(res.evidence.includes('统计'));
});

// ===== testFilter 过滤 =====
test('Boolean registry: testFilter 只跑匹配的 test-case', async () => {
  // 使用一个不存在的 filter → 无注册表条目匹配 → 只有 boundary 对（如果 point.boundary 存在）
  // point 无 boundary → pairs 为空 → 不检测 → vulnerable=false
  const d = new BooleanBlindDetector();
  const ctx = buildCtx(makeBooleanMock(), {
    useRegistry: true,
    level: 5,
    risk: 3,
    testFilter: 'nonexistent-test-id-xyz',
  });
  const res = await d.detect(ctx);
  // 无匹配的注册表条目 → 无真假对发送 → 不命中
  assert.equal(res.vulnerable, false);
});

// ===== testFilter 精确匹配 =====
test('Boolean registry: testFilter 匹配 mysql-bool 时命中', async () => {
  const d = new BooleanBlindDetector();
  const ctx = buildCtx(makeBooleanMock(), {
    useRegistry: true,
    level: 5,
    risk: 3,
    testFilter: 'mysql-bool',
  });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  // 匹配的条目 id 应出现在 evidence
  assert.ok(res.evidence.includes('mysql-bool'));
});

// ===== testSkip 排除 =====
test('Boolean registry: testSkip 排除所有 boolean 条目后不命中', async () => {
  const d = new BooleanBlindDetector();
  // 跳过所有 boolean 条目（用通配 "bool"）
  const ctx = buildCtx(makeBooleanMock(), {
    useRegistry: true,
    level: 5,
    risk: 3,
    testSkip: 'bool',
  });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, false);
});

// ===== selectPayloads 单元测试 =====
test('selectPayloads: testFilter 子串匹配（逗号分隔多 ID）', () => {
  const entries = selectPayloads({
    dbms: 'MySQL',
    technique: 'boolean',
    level: 5,
    risk: 3,
    testFilter: 'mysql-bool-sq,mysql-bool-dq',
  });
  // 应只返回 id 含 mysql-bool-sq 或 mysql-bool-dq 的条目
  assert.ok(entries.length > 0);
  for (const e of entries) {
    assert.ok(
      e.id.includes('mysql-bool-sq') || e.id.includes('mysql-bool-dq'),
      `unexpected entry: ${e.id}`
    );
  }
});

test('selectPayloads: testSkip 排除匹配 ID', () => {
  const all = selectPayloads({
    dbms: 'MySQL',
    technique: 'boolean',
    level: 5,
    risk: 3,
  });
  const filtered = selectPayloads({
    dbms: 'MySQL',
    technique: 'boolean',
    level: 5,
    risk: 3,
    testSkip: 'mysql-bool',
  });
  // 排除后应少于全集
  assert.ok(filtered.length < all.length, `filtered(${filtered.length}) should be < all(${all.length})`);
  for (const e of filtered) {
    assert.ok(!e.id.includes('mysql-bool'), `should not contain mysql-bool: ${e.id}`);
  }
});

test('selectPayloads: level 过滤（level=1 不含 level>1 条目）', () => {
  const entries = selectPayloads({
    dbms: 'MySQL',
    technique: 'boolean',
    level: 1,
    risk: 3,
  });
  for (const e of entries) {
    assert.ok(e.level <= 1, `entry ${e.id} has level ${e.level} > 1`);
  }
});

test('selectPayloads: risk 过滤（risk=1 不含 risk>1 条目）', () => {
  const entries = selectPayloads({
    dbms: 'MySQL',
    technique: 'boolean',
    level: 5,
    risk: 1,
  });
  for (const e of entries) {
    assert.ok(e.risk <= 1, `entry ${e.id} has risk ${e.risk} > 1`);
  }
});

// ===== 注册表完整性 =====
test('PAYLOAD_REGISTRY: 包含 MySQL boolean 条目且有 falseTemplate', () => {
  const entries = selectPayloads({
    dbms: 'MySQL',
    technique: 'boolean',
    level: 5,
    risk: 3,
  });
  assert.ok(entries.length > 0, 'should have MySQL boolean entries');
  // 至少有一条含 falseTemplate（boolean 技术的核心配对要求）
  const withFalse = entries.filter((e) => e.falseTemplate);
  assert.ok(withFalse.length > 0, 'should have at least one entry with falseTemplate');
  // 所有条目必须有 template
  for (const e of entries) {
    assert.ok(e.template, `entry ${e.id} missing template`);
  }
});

test('PAYLOAD_REGISTRY: 所有 id 唯一', () => {
  const all = listRegistry();
  const ids = new Set();
  for (const e of all) {
    assert.ok(!ids.has(e.id), `duplicate id: ${e.id}`);
    ids.add(e.id);
  }
});
