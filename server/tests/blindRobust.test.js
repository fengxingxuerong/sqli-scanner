// 盲注判定鲁棒性（统计判定）增强测试（node --test）
// 通过 mock httpClient 模拟确定性命中 / 抖动 / 慢目标 / 非注入 等场景，验证统计判定生效且不误报。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';
import { defaults } from '../src/config/defaults.js';

function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  if (opts.headers && opts.headers.Cookie) {
    const m = opts.headers.Cookie.match(/q=([^;]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.headers) {
    for (const [k, v] of Object.entries(opts.headers)) {
      if (k.toLowerCase() !== 'cookie' && typeof v === 'string') return v;
    }
  }
  return '';
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 布尔响应 mock 变体
function makeBooleanMock(variant) {
  let callN = 0; // 每实例独立计数，保证确定性（node:test 并发安全）
  return {
    async request(opts) {
      const q = extractInjected(opts);
      const i = callN++;
      const isFalse = /1=2|'1'='2|"1"="2/.test(q);
      if (variant === 'deterministic') {
        return { data: isFalse ? 'NO_RESULTS' : 'normal page content here stable prefix', status: 200 };
      }
      if (variant === 'jitter') {
        // 真/假区分稳定，但每次响应尾部加随机噪声（不影响前缀相似度 → 一致率容错）
        const base = isFalse ? 'NO_RESULTS' : 'normal page content here stable prefix';
        return { data: base + ' ' + Math.random().toString(36).slice(2, 8), status: 200 };
      }
      if (variant === 'same') {
        // 真/假响应完全相同（非注入）→ 不应误报
        return { data: 'identical page content stable prefix', status: 200 };
      }
      if (variant === 'noisyNoInject') {
        // 高抖动非注入目标：基线(true/默认)与 false 各返回互不相交、内部两两不相似的"稳定前缀+编号"集合。
        // 效果：false≠基线 一致率=1（满足一致率门槛），但基线自身抖动率也=1 → 显著性检验判"不显著"→不误报。
        if (isFalse) return { data: `FALSE_${(i % 5) + 1}`, status: 200 };
        return { data: `BASE_${(i % 5) + 1}`, status: 200 };
      }
      return { data: 'normal page content here stable prefix', status: 200 };
    },
  };
}

// 时间响应 mock 变体
function makeTimeMock(variant) {
  return {
    async request(opts) {
      const q = extractInjected(opts);
      const isSleep = /SLEEP\(|pg_sleep|WAITFOR DELAY/i.test(q);
      if (variant === 'hit') {
        if (isSleep) await sleep(1200); // 注入生效：额外延迟 1.2s
        return { data: '', status: 200 };
      }
      if (variant === 'slowNoInject') {
        // 目标本就慢（每次抖动 ~400ms），但 SLEEP 不生效（无额外延迟）→ 不应误判
        await sleep(350 + Math.random() * 100);
        return { data: '', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {}, config: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: {
      timeoutMs: 5000,
      timeThresholdMs: 800,
      blindRobust: { enabled: true, booleanSamples: 3, baselineSamples: 5, timeConfidenceZ: 2, minStableRatio: 0.66 },
    },
    ...overrides,
  };
}

// ===== Boolean 鲁棒 =====
test('Boolean 鲁棒：确定性命中', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(makeBooleanMock('deterministic')));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'boolean');
  assert.ok(res.evidence.includes('统计'));
});

test('Boolean 鲁棒：尾部抖动仍命中（一致率容错）', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(makeBooleanMock('jitter')));
  assert.equal(res.vulnerable, true);
});

test('Boolean 鲁棒：真/假响应完全相同不误报', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(makeBooleanMock('same')));
  assert.equal(res.vulnerable, false);
});

test('Boolean 鲁棒：enabled:false 回退 legacy（确定性仍命中、文案非统计）', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(
    buildCtx(makeBooleanMock('deterministic'), {
      config: { timeoutMs: 5000, timeThresholdMs: 800, blindRobust: { enabled: false } },
    })
  );
  assert.equal(res.vulnerable, true);
  assert.ok(!res.evidence.includes('统计'));
});

// ===== 显著性 / 默认合并 =====
test('Boolean 鲁棒：高抖动非注入目标被显著性门槛拦截（不误报）', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(makeBooleanMock('noisyNoInject')));
  assert.equal(res.vulnerable, false);
});

test('Boolean 鲁棒：依赖全局默认（config 合并 defaults）走统计分支', async () => {
  const d = new BooleanBlindDetector();
  const ctx = buildCtx(makeBooleanMock('deterministic'));
  ctx.config = { ...defaults, ...ctx.config }; // 模拟引擎对 config 的 defaults 合并（models.js:24）
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.ok(res.evidence.includes('统计'));
});

// ===== Time 鲁棒 =====
test('Time 鲁棒：注入延迟命中（分布感知阈值）', async () => {
  const d = new TimeBlindDetector();
  const res = await d.detect(buildCtx(makeTimeMock('hit')));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'time');
  assert.ok(res.evidence.includes('统计'));
});

test('Time 鲁棒：目标本就慢但无注入效果不误报', async () => {
  const d = new TimeBlindDetector();
  const res = await d.detect(buildCtx(makeTimeMock('slowNoInject')));
  assert.equal(res.vulnerable, false);
});

test('Time 鲁棒：enabled:false 回退 legacy（命中、文案非统计）', async () => {
  const d = new TimeBlindDetector();
  const res = await d.detect(
    buildCtx(makeTimeMock('hit'), {
      config: { timeoutMs: 5000, timeThresholdMs: 800, blindRobust: { enabled: false } },
    })
  );
  assert.equal(res.vulnerable, true);
  assert.ok(!res.evidence.includes('统计'));
});

// ===== 阈值自适应（v3）=====
const RB_ADAPTIVE = {
  enabled: true, adaptive: true, adaptiveHeadroom: 0.3,
  minStableRatioFloor: 0.66, minStableRatioCap: 0.95,
  adaptiveTimeFloorScale: 2, booleanSamples: 3, baselineSamples: 5,
  timeConfidenceZ: 2, minStableRatio: 0.66,
};

test('Boolean 鲁棒(自适应): 稳定目标命中且门槛=下限', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(
    buildCtx(makeBooleanMock('deterministic'), {
      config: { timeoutMs: 5000, timeThresholdMs: 800, blindRobust: { ...RB_ADAPTIVE } },
    })
  );
  assert.equal(res.vulnerable, true);
  assert.ok(res.evidence.includes('自适应'));
  assert.ok(res.evidence.includes('门槛0.66'));
});

test('Boolean 鲁棒(自适应): 高抖动非注入门槛抬高仍不误报', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(
    buildCtx(makeBooleanMock('noisyNoInject'), {
      config: { timeoutMs: 5000, timeThresholdMs: 800, blindRobust: { ...RB_ADAPTIVE } },
    })
  );
  // 非注入目标：基线自身抖动率=1 → 自适应门槛抬到 cap(0.95)，但 false≠基线一致率=0 远低于门槛，
  // 且显著性检验判"不显著"→ 正确不误报。阴性结果不写 evidence，仅校验 vulnerable=false。
  assert.equal(res.vulnerable, false);
});

test('Boolean 鲁棒(自适应关): 回退固定 minStableRatio 仍命中', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(
    buildCtx(makeBooleanMock('deterministic'), {
      config: {
        timeoutMs: 5000, timeThresholdMs: 800,
        blindRobust: { enabled: true, adaptive: false, booleanSamples: 3, baselineSamples: 5, timeConfidenceZ: 2, minStableRatio: 0.66 },
      },
    })
  );
  assert.equal(res.vulnerable, true);
  assert.ok(!res.evidence.includes('自适应'));
});

test('Time 鲁棒(自适应): 慢目标不误报、注入命中', async () => {
  const dNo = new TimeBlindDetector();
  const rNo = await dNo.detect(
    buildCtx(makeTimeMock('slowNoInject'), {
      config: { timeoutMs: 5000, timeThresholdMs: 800, blindRobust: { ...RB_ADAPTIVE } },
    })
  );
  assert.equal(rNo.vulnerable, false);

  const dHit = new TimeBlindDetector();
  const rHit = await dHit.detect(
    buildCtx(makeTimeMock('hit'), {
      config: { timeoutMs: 5000, timeThresholdMs: 800, blindRobust: { ...RB_ADAPTIVE } },
    })
  );
  assert.equal(rHit.vulnerable, true);
  assert.ok(rHit.evidence.includes('自适应'));
});

// ===== v5：并发采样 + trace 响应 diff 增强 =====
test('Boolean 鲁棒：trace 含 excerpt 与逐采样 diffs（命中场景）', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(makeBooleanMock('deterministic')));
  assert.ok(res.trace, '应透传结构化 trace');
  const pair = res.trace.pairs[0];
  assert.ok(pair, '应有至少一个真假对');
  // 每个样本带响应片段
  assert.ok(pair.trueSamples[0].excerpt && pair.trueSamples[0].excerpt.length > 0);
  assert.ok(pair.falseSamples[0].excerpt && pair.falseSamples[0].excerpt.length > 0);
  // 逐采样真假差异
  assert.equal(pair.diffs.length, 3); // booleanSamples=3
  const d0 = pair.diffs[0];
  assert.ok(d0.firstDiffOffset >= 0, '真/假响应应有差异');
  assert.ok(d0.changedSnippet.length > 0, '应记录变化片段');
});

test('Boolean 鲁棒：并发采样收集计数正确（基线/真假样本数）', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(
    buildCtx(makeBooleanMock('deterministic'), {
      config: { timeoutMs: 5000, timeThresholdMs: 800, blindRobust: { ...RB_ADAPTIVE } },
    })
  );
  assert.equal(res.trace.baselineSamples.length, 5); // baselineSamples=5
  assert.equal(res.trace.pairs[0].trueSamples.length, 3); // booleanSamples=3
  assert.equal(res.trace.pairs[0].falseSamples.length, 3);
  assert.equal(res.trace.pairs[0].diffs.length, 3);
});

test('Boolean 鲁棒：并发容错（部分请求失败不崩溃）', async () => {
  let n = 0;
  const flaky = {
    async request() {
      n++;
      if (n % 4 === 0) throw new Error('simulated network blip');
      return { data: n % 2 ? 'normal page content here stable prefix' : 'NO_RESULTS', status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  // 偶发失败降级空串，流程必须完成而非抛错
  const res = await d.detect(buildCtx(flaky));
  assert.ok(res.trace, '并发失败应仍产出 trace 而非抛错');
});

test('Time 鲁棒：trace 含 baseline 响应片段', async () => {
  const d = new TimeBlindDetector();
  const res = await d.detect(buildCtx(makeTimeMock('hit')));
  assert.ok(res.trace, '应透传结构化 trace');
  assert.ok('excerpt' in res.trace.baselineSamples[0], '基线样本应带 excerpt 字段');
  assert.ok('excerpt' in res.trace.injectSamples[0]);
});

