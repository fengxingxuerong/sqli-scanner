// ============================================================================
// server/tests/reportAi.stepwise.d278.guard.test.js —— [D278]
//
// 钉住「审阅硬上限」的真实章节尺度契约：
//   ① 默认硬上限是 16000（不是 D275 的 4000）；
//   ② D278 真网关实测的 4696 字「五、修复方案」章，在默认值下**必须送审**
//      （旧 4000 会判 too-long ⇒ 审阅 4/5 / partial=true，这是真实反证）；
//   ③ 真正超长（>16000）的章节仍不送审、保留原章、标 partial —— 硬上限不被取消；
//   ④ 显式 env/注入值仍优先于默认值（运维可调）。
//
// 判据边界：链路单测（callLLM 注入）；真实网关复跑见
// e2e/ai-gateway-lab/results/D278-真网关默认值-2026-11-08.md。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  runStepwiseStages,
  STEPWISE_REVIEW_MAX_CHARS,
} from '../src/services/reportAiStepwise.js';

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
    sectionCount: 5,
    callLLM: async () => 'SECTION',
    getRoleConfig: (idx) => ({ role: idx === 1 ? 'writer' : 'reviewer', model: 'm', keyIdx: idx, apiKey: 'k', apiBase: 'http://x' }),
    legacyFallback: async () => { throw new Error('legacy fallback should not be called'); },
    ...over,
  };
}

test('[D278] 默认审阅硬上限 = 16000（D275 的 4000 已由真网关反证作废）', () => {
  assert.equal(STEPWISE_REVIEW_MAX_CHARS, 16000);
});

test('[D278] 真实尺度的 4696 字修复章在默认值下必须送审，不得判 too-long', async () => {
  const longSection = 'A'.repeat(4696); // D278 真网关实测：五、修复方案 4696 字符
  const seen = [];
  const deps = baseDeps({
    callLLM: async (cfg, system, user) => {
      seen.push(user);
      return user.includes('审阅并修订') ? 'REVIEWED' : longSection;
    },
  });
  const r = await runStepwiseStages(deps);
  const reviewUsers = seen.filter((u) => u.includes('审阅并修订'));
  assert.equal(reviewUsers.length, 5, '5 章都必须送审（旧 4000 会漏掉修复章）');
  assert.ok(reviewUsers.every((u) => u.includes(longSection)), '送审必须是完整章节，不得截断');
  assert.equal(r.stepwise.reviewedSections, 5);
  assert.equal(r.stepwise.partial, false);
  assert.deepEqual(r.stepwise.failedSteps, []);
});

test('[D278] 超过 16000 的章节仍不送审、保留原章、标 partial（硬上限仍有效）', async () => {
  const tooLong = 'B'.repeat(16001);
  let reviewCalls = 0;
  const deps = baseDeps({
    callLLM: async (cfg, system, user) => {
      if (user.includes('审阅并修订')) reviewCalls++;
      return user.includes('审阅并修订') ? 'REVIEWED' : tooLong;
    },
  });
  const r = await runStepwiseStages(deps);
  assert.equal(reviewCalls, 0, '超硬上限章节不得送审');
  assert.equal(r.stepwise.reviewedSections, 0);
  assert.equal(r.stepwise.partial, true);
  assert.equal(r.stepwise.failedSteps.length, 5);
  assert.ok(r.stepwise.failedSteps.every((s) => /^reviewer:.+:too-long$/.test(s)));
  assert.ok(r.finalReport.includes(tooLong), '原章必须保留');
});

test('[D278] 显式 reviewMaxChars 仍优先于默认值（运维可调）', async () => {
  let reviewCalls = 0;
  const deps = baseDeps({
    reviewMaxChars: 100,
    callLLM: async (cfg, system, user) => {
      if (user.includes('审阅并修订')) reviewCalls++;
      return user.includes('审阅并修订') ? 'REVIEWED' : 'C'.repeat(200);
    },
  });
  const r = await runStepwiseStages(deps);
  assert.equal(reviewCalls, 0);
  assert.equal(r.stepwise.reviewMaxChars, 100);
  assert.equal(r.stepwise.partial, true);
});
