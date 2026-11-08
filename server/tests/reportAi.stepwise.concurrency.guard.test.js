// ============================================================================
// server/tests/reportAi.stepwise.concurrency.guard.test.js —— [D277]
//
// 钉住分步链路的有界并发契约：
//   ① 默认串行（concurrency=1）：并发峰值 = 1，与 D259/D275 行为逐字等价；
//   ② opt-in 并发 2：并发峰值 ≤2 且确实发生重叠（不是「配置了但没生效」）；
//   ③ 结果顺序恒按章节顺序（writer 5 章 / reviewer 5 章），不随完成先后漂移；
//   ④ 失败披露（failedSteps）也按章节顺序，不随失败先后漂移；
//   ⑤ 非法 env 值一律回落到串行，上限 4（防把慢网关/限流网关打爆）。
//
// 判据边界：链路单测（callLLM 注入），不替代真网关 e2e；并发只改变调度，
// 不改变「失败不冒充成功」的语义。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  runStepwiseStages,
  normalizeStepwiseConcurrency,
  STEPWISE_MAX_CONCURRENCY,
} from '../src/services/reportAiStepwise.js';

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 从 prompt 里取章节标题（writer/reviewer 都带「」）。
 * @param {string} user 用户消息
 * @returns {string} 标题
 */
function titleOf(user) {
  const m = String(user).match(/「([^」]+)」/);
  return m ? m[1] : 'unknown';
}

/**
 * 构造 runStepwiseStages 的最小依赖；未覆盖项给安全默认值。
 * @param {object} over 覆盖项
 * @returns {object} deps
 */
function baseDeps(over = {}) {
  return {
    facts: {
      url: '<目标Host>/***',
      urlPath: '/***?id=***',
      host: '<目标Host>（脱敏占位符）',
      method: 'GET',
      dbms: 'MySQL',
      params: 'id（url，原始值 ***）',
      paramsRaw: 'id',
      startedAt: '',
      analysis: '',
      extracted: null,
      boundary: { verdict: 'vulnerability_detected', reliable: true, unverified: null, uncovered: null, dbmsCaveat: null },
      vulns: [],
    },
    timeoutMs: 5000,
    stepwiseTimeoutMs: 5000,
    maxPromptChars: 1200,
    reviewMaxChars: 4000,
    sectionCount: 5,
    callLLM: async () => 'SECTION',
    getRoleConfig: (idx) => ({ role: idx === 1 ? 'writer' : 'reviewer', model: 'm', keyIdx: idx, apiKey: 'k', apiBase: 'http://x' }),
    legacyFallback: async () => { throw new Error('legacy fallback should not be called'); },
    ...over,
  };
}

/**
 * 统计并发峰值并在每个请求里加一点延迟（让并发真的重叠）。
 * @param {object} deps deps（原地替换 callLLM）
 * @returns {{deps:object, peak:()=>number, maxInFlight:()=>number}} 句柄
 */
function withTracking(deps) {
  let inFlight = 0;
  let maxInFlight = 0;
  let calls = 0;
  const wrapped = {
    ...deps,
    callLLM: async (cfg, system, user) => {
      calls++;
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      try {
        await delay(10);
        const title = titleOf(user);
        return user.includes('审阅并修订') ? `R:${title}` : `W:${title}`;
      } finally {
        inFlight--;
      }
    },
  };
  return { deps: wrapped, peak: () => calls, maxInFlight: () => maxInFlight };
}

test('[D277] normalizeStepwiseConcurrency：非法值回落 1，上限 4，小数向下取整', () => {
  assert.equal(normalizeStepwiseConcurrency(undefined), 1);
  assert.equal(normalizeStepwiseConcurrency(''), 1);
  assert.equal(normalizeStepwiseConcurrency('abc'), 1);
  assert.equal(normalizeStepwiseConcurrency('0'), 1);
  assert.equal(normalizeStepwiseConcurrency('-3'), 1);
  assert.equal(normalizeStepwiseConcurrency('1'), 1);
  assert.equal(normalizeStepwiseConcurrency('2'), 2);
  assert.equal(normalizeStepwiseConcurrency('2.9'), 2);
  assert.equal(normalizeStepwiseConcurrency('4'), 4);
  assert.equal(normalizeStepwiseConcurrency('99'), STEPWISE_MAX_CONCURRENCY);
});

test('[D277] 默认串行：并发峰值 = 1，5 章撰写 + 5 章审阅按序完成', async () => {
  const t = withTracking(baseDeps());
  const r = await runStepwiseStages(t.deps);
  assert.equal(t.maxInFlight(), 1, '默认必须串行（与 D259/D275 行为等价）');
  assert.equal(r.stepwise.concurrency, 1);
  assert.equal(r.stepwise.writerSteps, 5);
  assert.equal(r.stepwise.reviewedSections, 5);
  assert.equal(r.stepwise.partial, false);
  // 拼装顺序 = 章节顺序
  const order = ['一、漏洞概述', '二、漏洞描述', '三、漏洞证明（PoC）', '四、影响评估', '五、修复方案'];
  const positions = order.map((title) => r.finalReport.indexOf(`R:${title}`));
  assert.ok(positions.every((p) => p >= 0), `章节缺失：${JSON.stringify(positions)}`);
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b), '章节顺序不得随完成先后漂移');
});

test('[D277] 并发 2：峰值 ≤2 且确实重叠，结果仍按章节顺序', async () => {
  const t = withTracking(baseDeps({ concurrency: 2 }));
  const r = await runStepwiseStages(t.deps);
  assert.ok(t.maxInFlight() <= 2, `并发峰值 ${t.maxInFlight()} 超过配置 2`);
  assert.ok(t.maxInFlight() >= 2, `并发峰值 ${t.maxInFlight()} = 1 —— 配置了并发但没生效`);
  assert.equal(r.stepwise.concurrency, 2);
  assert.equal(r.stepwise.reviewedSections, 5);
  assert.equal(r.stepwise.partial, false);
  const order = ['一、漏洞概述', '二、漏洞描述', '三、漏洞证明（PoC）', '四、影响评估', '五、修复方案'];
  const positions = order.map((title) => r.finalReport.indexOf(`R:${title}`));
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b), '并发下章节顺序必须稳定');
});

test('[D277] 并发下失败披露仍按章节顺序（不随失败先后漂移）', async () => {
  // 让「二、漏洞描述」失败，其余成功；即使失败先返回，failedSteps 也必须只含它
  const deps = baseDeps({
    concurrency: 2,
    callLLM: async (cfg, system, user) => {
      await delay(user.includes('二、漏洞描述') ? 1 : 15);
      if (user.includes('二、漏洞描述') && !user.includes('审阅并修订')) {
        throw new Error('injected writer failure');
      }
      return user.includes('审阅并修订') ? `R:${titleOf(user)}` : `W:${titleOf(user)}`;
    },
  });
  const r = await runStepwiseStages(deps);
  assert.deepEqual(r.stepwise.failedSteps, ['writer:description']);
  assert.equal(r.stepwise.partial, true);
  assert.ok(!r.reviewNote.includes('✅'));
  // 失败章保留占位，其余章仍按序拼装
  assert.ok(r.finalReport.includes('需人工补全'));
});

test('[D277] 并发下超审阅预算章节仍不送审，failedSteps 按章节顺序', async () => {
  let reviewCalls = 0;
  const deps = baseDeps({
    concurrency: 2,
    reviewMaxChars: 10,
    callLLM: async (cfg, system, user) => {
      if (user.includes('审阅并修订')) reviewCalls++;
      return user.includes('审阅并修订') ? `R:${titleOf(user)}` : `W:${'X'.repeat(50)}:${titleOf(user)}`;
    },
  });
  const r = await runStepwiseStages(deps);
  assert.equal(reviewCalls, 0, '超预算章节不得送审');
  assert.equal(r.stepwise.reviewedSections, 0);
  assert.equal(r.stepwise.partial, true);
  assert.deepEqual(
    r.stepwise.failedSteps,
    ['reviewer:overview:too-long', 'reviewer:description:too-long', 'reviewer:poc:too-long', 'reviewer:impact:too-long', 'reviewer:fix:too-long'],
    '失败披露必须按章节顺序',
  );
});
