// [D263] AI 报告整场总预算判据（guard 类）
//
// 钉住的行为契约：调用方给的 timeoutMs 是「整场上限的意图」，但实现把它 /3 当每步超时，
// 慢网关上「三级降级 + 短重试 + 分步 11 章」可挂 10+ 分钟。本判据要求：
//   ① 所有 LLM 请求共享同一 deadline，单步超时被裁到剩余预算；
//   ② 预算耗尽抛明确错误并立即停止，不再降级/重试/冒充半成品报告；
//   ③ stepwise.partial=true 时头部与 reviewNote 不得写「✅ 已过审」。
// 判据边界：链路单测，不替代真网关 e2e；真网关能否出完整报告以 e2e/ai-gateway-lab 退出码为准。
import { test } from 'node:test';
import assert from 'node:assert/strict';

// 模块加载期读 env：总预算压到 600ms，慢网关用例才能秒级收敛（且能被 test timeout 判红）。
process.env.AI_REPORT_TOTAL_TIMEOUT_MS = '600';
process.env.AI_REPORT_KEY_1 = 'budget-key-1';
process.env.AI_REPORT_KEY_2 = 'budget-key-2';
process.env.AI_REPORT_KEY_3 = 'budget-key-3';
process.env.AI_REPORT_API_BASE = 'http://127.0.0.1:9/v1/chat/completions';
delete process.env.AI_REPORT_STEPWISE;

const { generateAiReport, clampToBudget } = await import('../src/services/ReportAI.js?d263-budget');
const { renderAiReportDoc } = await import('../src/services/aiReportCli.js?d263-budget');

process.env.AI_REPORT_STEPWISE = '1';
const genStepwise = await import('../src/services/ReportAI.js?d263-budget-stepwise');
delete process.env.AI_REPORT_STEPWISE;

const ANALYSIS = '{"vulns":[{"name":"SQL 注入","risk":"高危","poc_payload":"1 AND 1=1"}],"overall_risk":"高危"}';

function baseReport(scanId) {
  return {
    scanId,
    target: { baseUrl: 'https://example.com/secret/login' },
    dbms: 'MySQL',
    startedAt: '2026-01-01T00:00:00Z',
    vulns: [{ technique: 'boolean', dbms: 'MySQL', riskLevel: 'High', description: 'd', evidence: 'e' }],
  };
}

function ok(content) {
  return {
    ok: true, status: 200,
    json: async () => ({ choices: [{ message: { content }, finish_reason: 'stop' }] }),
  };
}

function installFetch(handler) {
  const orig = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, opts) => {
    const body = JSON.parse(opts.body);
    calls.push({ url, opts, body });
    return handler(calls.length, calls[calls.length - 1]);
  };
  return { calls, restore() { globalThis.fetch = orig; } };
}

function abortError() {
  const e = new Error('The operation was aborted');
  e.name = 'AbortError';
  return e;
}

/** 永不返回的网关：只有 AbortSignal 触发才 reject，模拟慢推理模型 */
function hangingGateway(onAbort) {
  return (_i, call) => new Promise((_resolve, reject) => {
    const signal = call.opts.signal;
    const done = () => { onAbort?.(); reject(abortError()); };
    if (signal?.aborted) return done();
    signal.addEventListener('abort', done, { once: true });
  });
}

// ── ① 纯函数：预算裁剪 ─────────────────────────────────────────────────────
test('[D263] clampToBudget：剩余充足时保留单步超时', () => {
  const r = clampToBudget(200000, 10000, 1000);
  assert.deepEqual(r, { ok: true, timeoutMs: 9000, remainingMs: 9000 });
});

test('[D263] clampToBudget：剩余不足时裁到剩余，耗尽/非法一律拒绝', () => {
  assert.equal(clampToBudget(200000, 1000, 900).timeoutMs, 100);
  assert.equal(clampToBudget(200000, 1000, 1000).ok, false);
  assert.equal(clampToBudget(200000, 1000, 2000).ok, false);
  assert.equal(clampToBudget(200000, NaN, 1000).ok, false);
  assert.equal(clampToBudget(0, 10000, 1000).timeoutMs, 9000, '非法单步超时回落 60s 但仍受总闸裁剪');
});

// ── ② 整场总闸：慢网关不再挂十几分钟 ──────────────────────────────────────
// test timeout=6000 同时是缺陷注入判据：若去掉总闸，单步超时回到 200s，本用例必超时判红。
test('[D263] 慢网关：第一次请求被裁到总预算，耗尽即抛明确错误并停止降级', { timeout: 6000 }, async () => {
  const t0 = Date.now();
  const abortTimes = [];
  const fh = installFetch(hangingGateway(() => abortTimes.push(Date.now() - t0)));
  try {
    await assert.rejects(
      generateAiReport(baseReport('d263-slow'), 600000),
      (e) => /总预算耗尽/.test(String(e.message)) && e.budgetExhausted === true,
    );
  } finally {
    fh.restore();
  }
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 3000, `总预算 600ms 应在 3s 内收口，实际 ${elapsed}ms`);
  assert.ok(abortTimes.length >= 1, '第一次请求必须真的被 abort，而不是空转');
  assert.ok(abortTimes[0] <= 900, `单步超时必须被裁到 600ms 预算内，实际 ${abortTimes[0]}ms`);
  assert.equal(fh.calls.length, 1, '预算耗尽后不得再发短重试/三级降级请求');
});

// ── ③ 半成品口径：partial=true 不得写「✅ 已过审」 ─────────────────────────
// 复现 D262 矛盾：分步 writer 全章失败 → 回退整篇 → legacy reviewer 成功写 ✅，
// 但 stepwise.partial=true（正文其实只是审阅意见）。
test('[D263] partial=true：头部与 reviewNote 一律声明报告不完整', async () => {
  const fh = installFetch((i) => {
    if (i === 1) return ok(ANALYSIS);
    if (i <= 7) throw new Error('simulated writer failure');
    return ok('# 审阅意见\n\nREVIEWED');
  });
  let r;
  try {
    r = await genStepwise.generateAiReport(baseReport('d263-partial'), 600000);
  } finally {
    fh.restore();
  }
  assert.equal(r.stepwise.fallback, 'legacy');
  assert.equal(r.stepwise.partial, true);
  assert.ok(!r.reviewNote.includes('✅'), '半成品不得标已过审');
  assert.ok(r.reviewNote.includes('不完整') && r.reviewNote.includes('部分完成'));
  const doc = renderAiReportDoc(r, { elapsedMs: 1, masked: false });
  assert.ok(!doc.includes('✅'), 'ai-report.md 头部同样不得标已过审');
  assert.ok(doc.includes('报告不完整'), 'ai-report.md 头部必须声明不完整');
});

// ── ④ 零回归：正常快速网关仍走完三角色，reviewNote 保持原文案 ─────────────
test('[D263] 快速网关（非分步）行为零变化', async () => {
  const fh = installFetch(async (i) => ok(i === 1 ? ANALYSIS : 'BODY'));
  let r;
  try {
    r = await generateAiReport(baseReport('d263-fast'), 600000);
  } finally {
    fh.restore();
  }
  assert.equal(fh.calls.length, 3);
  assert.equal(r.reviewNote, '✅ 已经过安全审阅角色校验');
  assert.equal(r.stepwise, undefined);
});
