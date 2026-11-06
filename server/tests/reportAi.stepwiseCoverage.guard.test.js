// [D259] 分步链路补测（**不带 query 的直接 import**）；[D260] 口径更正
//
// 旧口径（已作废）：D259 认为「带 query 的隔离实例不被 coverage 归因 ⇒ 补测即可拉回阈值」。
// D260 实测推翻：真因是 Node 的 --experimental-test-coverage 在**存在 `?query` 模块实例时
// 会把同一源文件的多进程快照合并退化成单快照**（Node 22 随机在两个值间跳；CI 的 Node 24
// 稳定取单快照），补多少测试都拉不回。证据与修法见 `docs/覆盖率门禁接线-D260.md`：
// 覆盖率测量由 `scripts/server-coverage-gate.mjs` 排除含 `?query` 导入的测试文件，
// 这些文件仍在 `npm test` 全量执行。本文件保留为链路行为补测，不再承担修覆盖率职责。
//
// 判据边界：这里断言的是链路事实，不是覆盖率数字本身；覆盖率以
// `cd server && npm run test:coverage` 的退出码为准。
import { test } from 'node:test';
import assert from 'node:assert/strict';

// 模块加载期读 env：先设好再 import（必须是无 query 的同一个实例）
process.env.AI_REPORT_KEY_1 = 'cov-key-1';
process.env.AI_REPORT_KEY_2 = 'cov-key-2';
process.env.AI_REPORT_KEY_3 = 'cov-key-3';
process.env.AI_REPORT_API_BASE = 'http://127.0.0.1:9/v1/chat/completions';
process.env.AI_REPORT_STEPWISE = '1';

const { generateAiReport } = await import('../src/services/ReportAI.js');

const ANALYSIS = '{"vulns":[{"name":"SQL 注入","risk":"高危","poc_payload":"1 AND 1=1"}],"overall_risk":"高危"}';

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

const userOf = (call) => call.body.messages[1].content;

function ok(content) {
  return {
    ok: true, status: 200,
    json: async () => ({ choices: [{ message: { content }, finish_reason: 'stop' }] }),
  };
}

// 用「非 AbortError 的网络异常」制造失败：callLLM 只在 AbortError / 空内容 / 429 / !ok
// 时 markKeyFail，普通异常直接 rethrow ⇒ 不给模块级 keyHealth 留 10~60s 冷却。
// 这是多个用例能共用同一个无 query 实例（覆盖率可归因到主模块）的前提。
const fail = () => { throw new Error('simulated network failure'); };

/** 默认：分析出 JSON，其余按章节标题回一段 Markdown */
async function allOk(i, call) {
  const user = userOf(call);
  if (user.startsWith('【分步·分析】')) return ok(ANALYSIS);
  const m = user.match(/「([^」]+)」/);
  return ok(`# ${m ? m[1] : '章节'}\n\n内容-${i}`);
}

function baseReport(scanId) {
  return {
    scanId,
    target: { baseUrl: 'http://127.0.0.1:8099/vulnerabilities/sqli/?id=1&Submit=Submit', method: 'GET' },
    dbms: 'MySQL',
    startedAt: '2026-01-01T00:00:00Z',
    points: [{ param: 'id', location: 'url', originalValue: '1' }],
    data: { databases: ['app'], tables: { users: [] }, rows: { users: [['a']] }, currentDb: 'app' },
    vulns: [{
      technique: 'boolean', dbms: 'MySQL', riskLevel: 'High',
      evidence: '真/假探针响应长度差', payloads: ["1' AND '1'='1"],
      trace: { pairs: [{ trueSamples: [{ len: 1617 }], falseSamples: [{ len: 30 }], diffs: [{ lenDelta: 1587, firstDiffOffset: 214 }] }] },
    }],
  };
}

test('[D259/cov] 正常分步路径：11 个短请求、逐章审阅完成', async () => {
  const fh = installFetch(allOk);
  try {
    const r = await generateAiReport(baseReport('cov-normal'));
    assert.equal(r.success, true);
    assert.equal(r.stepwise.partial, false);
    assert.equal(r.stepwise.reviewedSections, 5);
    assert.ok(r.content.includes('### 三、漏洞证明（PoC）'));
  } finally { fh.restore(); }
});

test('[D259/cov] writer 单章失败：该章标缺、其余章仍送审', async () => {
  const fh = installFetch(async (i, call) => (i === 4 ? fail() : allOk(i, call)));
  try {
    const r = await generateAiReport(baseReport('cov-429'));
    assert.equal(r.stepwise.partial, true);
    assert.ok(r.stepwise.failedSteps.includes('writer:poc'));
    assert.ok(r.content.includes('未由模型产出'));
  } finally { fh.restore(); }
});

test('[D259/cov] writer 全章空：回退整篇流水线', async () => {
  const fh = installFetch(async (i, call) => (
    userOf(call).startsWith('【分步·分析】') ? ok(ANALYSIS) : fail()
  ));
  try {
    const r = await generateAiReport(baseReport('cov-fallback'));
    assert.equal(r.stepwise.fallback, 'legacy');
    assert.ok(!r.reviewNote.includes('✅'));
  } finally { fh.restore(); }
});

test('[D259/cov] reviewer 逐章全空：保留原章、审阅口径如实降级', async () => {
  const fh = installFetch(async (i, call) => {
    if (userOf(call).startsWith('【分步·分析】')) return ok(ANALYSIS);
    return i <= 6 ? allOk(i, call) : fail();
  });
  try {
    const r = await generateAiReport(baseReport('cov-review-fail'));
    assert.equal(r.stepwise.reviewedSections, 0);
    assert.equal(r.stepwise.partial, true);
    assert.ok(r.reviewNote.includes('部分完成'));
    assert.ok(r.content.includes('内容-2'), '审阅失败不得清空已生成章节');
  } finally { fh.restore(); }
});

test('[D259/cov] 极简报告：points/data/dbms/method/startedAt/trace 全缺时的回落分支', async () => {
  const fh = installFetch(allOk);
  try {
    const r = await generateAiReport({
      scanId: 'cov-minimal',
      target: { baseUrl: 'http://127.0.0.1:8099/' },
      vulns: [],
    });
    assert.equal(r.success, true);
    assert.equal(r.stepwise.partial, false);
    assert.ok(r.content.includes('### 一、漏洞概述'));
  } finally { fh.restore(); }
});
