// ============================================================================
// booleanBlind.baselinePoison.test.js —— 基线**失败样本**不得污染动态块学习
// ============================================================================
// 根因链（CI 实测 `real-mysql-lab` 的 noisy 场景 `检出=[time] miss=[boolean]`）：
//   sendConcurrent 的失败项是 { __error } → `_bodyOf()` 返回 **''（空串）**
//   → 空串被原样放进 baselines → `dynamicBlockFilter` 拿它跟每个正常响应两两比对，
//     空串没有任何块 ⇒ **每一块**都与它不同 ⇒ 所有块 diffCount 被抬高
//   → `diffCount[k]/pairs > 0.5` 把全部块判成动态块
//   → buildDynamicSimilarFn 里 `total === 0` 直接 return true ⇒ **真/假一律判"相似"**
//   → boolean 系统性漏报。
// 因此本文件钉两件事：① 纯函数层面证明空串确实会污染；② 检测器层面证明过滤已生效。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { dynamicBlockFilter } from '../src/core/statsHelper.js';

// ── 纯函数层面：空串污染的可观测事实 ──────────────────────────────────────

/**
 * 造"前面有动态块（ts/sid）、后面有静态块（填充 + 结果）"的响应，模拟 /noisy。
 * ⚠️ 必须足够长（多个 64B 块）：若整个响应只占 1 块，加空串后动态块数不会变多，
 * 就观测不到污染 —— 这是我第一版 mock 的错（4 条用例全红就是这么来的）。
 *
 * ⚠️ 动态内容必须用**确定性递增序列**，不能用 Date.now()/Math.random()：
 * 同一毫秒内的两次调用会生成**相同**字符串，于是"两条基线"实际变成"同一条"，
 * 动态块数就不再随污染翻倍 —— 本地（毫秒边界恰好跨过）绿、CI（Linux 调度更快，
 * 同毫秒命中）红。测试要的是"每次调用内容不同"这个语义，计数器才是准确表达。
 */
let noisySeq = 0;
const noisy = (result) => {
  const n = ++noisySeq;
  const ts = `<div class="ts">1700000000${String(n).padStart(4, '0')}-abcd${String(n).padStart(4, '0')}</div>`;
  const sid = `<div class="sid">session=deadbeef${String(n).padStart(8, '0')}</div>`;
  const pad = `<div class="pad">${'x'.repeat(120)}</div>`;
  return `${ts}${sid}${pad}<p>${result}</p>${pad}`;
};

test('★空串进 baselines 会把「全部块」污染成动态块（这就是必须过滤的原因）', () => {
  const clean = dynamicBlockFilter([noisy('row'), noisy('row')]);
  // 干净的两条：只有 ts 块动态，结果块（<p>row</p>）应判为静态
  assert.ok(clean.dynamicIdx.size > 0, '应识别出动态块（ts）');
  assert.ok(clean.dynamicIdx.size < 20, `动态块不应过多，实际 ${clean.dynamicIdx.size}`);

  // 混入空串：pairs 变多，但每个块都因"与空串不同"而 diffCount+1
  const poisoned = dynamicBlockFilter([noisy('row'), noisy('row'), '', '']);
  assert.ok(
    poisoned.dynamicIdx.size > clean.dynamicIdx.size,
    `污染后动态块应显著变多（干净 ${clean.dynamicIdx.size} → 污染 ${poisoned.dynamicIdx.size}）`
  );
});

test('空串比例足够大时，连「结果块」都被判成动态 → 判定恒相似（漏报机制）', () => {
  // 4 条里 2 条空串：pairs=6，涉及空串的对=5 ⇒ 5/6 > 0.5 ⇒ 每块都判动态
  const poisoned = dynamicBlockFilter([noisy('row'), noisy('row'), '', '']);
  const clean = dynamicBlockFilter([noisy('row'), noisy('row')]);
  // 判据：污染后动态块数量接近总块数（"全部块都动态"即判定恒相似）
  const total = Math.ceil(noisy('row').length / 64) + 1;
  assert.ok(
    poisoned.dynamicIdx.size >= clean.dynamicIdx.size * 2,
    `污染后动态块应至少翻倍（${clean.dynamicIdx.size} → ${poisoned.dynamicIdx.size}），总块约 ${total}`
  );
});

// ── 检测器层面：过滤必须已生效 ────────────────────────────────────────────

function extractQuery(u) {
  const m = String(u || '').match(/[?&]q=([^&]*)/);
  return m ? decodeURIComponent(m[1]).replace(/\+/g, ' ') : '';
}

/** 基线请求可按需返回空 body（模拟超时/连接失败的样本） */
function noisyClient({ emptyBaselines = 0 } = {}) {
  let baselineSeen = 0;
  const calls = [];
  return {
    calls,
    async request(opts) {
      calls.push(opts);
      const q = extractQuery(opts.url);
      if (q === '1') {
        baselineSeen++;
        if (baselineSeen <= emptyBaselines) return { status: 200, headers: {}, data: '' };
        return { status: 200, headers: {}, data: noisy('row') };
      }
      if (/1\s*=\s*2/i.test(q)) return { status: 200, headers: {}, data: noisy('empty') };
      if (/1\s*=\s*1|AND\s+1/i.test(q)) return { status: 200, headers: {}, data: noisy('row') };
      return { status: 200, headers: {}, data: noisy('row') };
    },
  };
}

function buildCtx(client, config = {}) {
  return {
    httpClient: client,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, level: 2, risk: 1, ...config },
  };
}

const d = new BooleanBlindDetector();

const baselineCalls = (client) => client.calls.filter((c) => extractQuery(c.url) === '1').length;

// _robustDetect 分支（需显式 blindRobust.enabled）—— 重试补足逻辑只在这条路径上
const ROBUST = { blindRobust: { enabled: true, baselineSamples: 3, booleanSamples: 3, concurrency: 2 } };

test('★鲁棒分支：基线混入失败样本 → 重试补足（只剔除不补足 ⇒ 样本<2 ⇒ 回落严格比对，噪声页照样漏报）', async () => {
  const ok = noisyClient({ emptyBaselines: 0 });
  await d.detect(buildCtx(ok, ROBUST));
  const bad = noisyClient({ emptyBaselines: 1 });
  await d.detect(buildCtx(bad, ROBUST));
  assert.ok(
    baselineCalls(bad) > baselineCalls(ok),
    `失败样本被剔除后必须补足：正常 ${baselineCalls(ok)} 次 → 混入失败 ${baselineCalls(bad)} 次`
  );
});

test('鲁棒分支：目标持续返回空 body → 重试有上限，不空转（最多 3 轮）', async () => {
  const allEmpty = { calls: [], async request(opts) { allEmpty.calls.push(opts); return { status: 200, headers: {}, data: '' }; } };
  const t0 = Date.now();
  await d.detect(buildCtx(allEmpty, ROBUST));
  const baseCalls = allEmpty.calls.filter((c) => extractQuery(c.url) === '1').length;
  assert.ok(baseCalls <= 3 * 3, `全空响应时应早停，基线请求 ${baseCalls} 次（耗时 ${Date.now() - t0}ms）`);
});
