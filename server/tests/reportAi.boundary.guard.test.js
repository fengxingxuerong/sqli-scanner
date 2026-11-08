// [D275] AI 报告「结论口径 / 脱敏 / 超时 / trace」判据（guard 类）
//
// 钉住的行为契约：
//   ① 报告边界字段（verdict / validity / 未验证面 / 未覆盖面 / 爬取降级 / 定库告警 /
//      triage）必须进入 AI 报告，且正文末尾有**引擎确定性生成**的边界章节；
//   ② 脱敏态下 host、路径、query 值与参数值都不得原样进 prompt；
//   ③ 引擎 CVSS 必须进入 analyst 事实，模型被要求逐字引用；
//   ④ finish_reason=length（非空但截断）不算成功；usage/trace 逐请求如实记录；
//   ⑤ 半成品/未审阅结果不得写入缓存；
//   ⑥ REST/CLI 共用的超时矩阵默认值与 env 覆盖。
//
// 判据边界：链路单测（fetch 打桩），不替代真网关 e2e；真网关能否出完整报告
// 仍以 e2e/ai-gateway-lab/run.mjs 退出码为准。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildBoundaryFacts,
  renderBoundarySection,
  boundaryPromptBlock,
  boundaryFingerprint,
  compactBoundary,
  triageSummary,
  BOUNDARY_MARKER,
} from '../src/services/reportAiFacts.js';

// ── 纯函数：边界事实 ───────────────────────────────────────────────────────

function boundaryReport() {
  return {
    summary: {
      verdict: 'inconclusive',
      verdictNote: '会话失效：登录态被目标拒绝',
      validity: { status: 'session_expired', reliable: false, reason: '登录态失效' },
      unverifiedSurfaces: [{
        surface: 'header', label: 'HTTP 请求头注入面',
        points: 2, tested: 0, unverified: 2, reason: 'WAF 拦截', sampleParams: ['X-Token', 'Referer'],
      }],
      uncoveredSurfaces: [
        { surface: 'cookie', label: 'Cookie 注入面', hint: '提高 --level 到 2' },
        { surface: 'path', label: 'URL 路径段注入面', hint: '显式 --test-path' },
      ],
      crawlBrowserFallback: { reason: 'playwright 不可用' },
      dbmsEvidence: { dbms: 'MySQL', level: 'template-only', levelText: '模板适配', caveat: '未经真引擎验证' },
    },
    vulns: [
      { technique: 'boolean', triage: { status: 'confirmed' } },
      { technique: 'error', triage: { status: 'false_positive' } },
      { technique: 'union' },
    ],
  };
}

test('[D275] 边界事实：verdict / 可信度 / 未验证面 / 未覆盖面 / 爬取降级 / 定库告警 / triage 全量保留', () => {
  const f = buildBoundaryFacts(boundaryReport());
  assert.equal(f.verdict, 'inconclusive');
  assert.equal(f.reliable, false);
  assert.equal(f.validityStatus, 'session_expired');
  assert.equal(f.unverifiedSurfaces.length, 1);
  assert.equal(f.unverifiedSurfaces[0].unverified, 2);
  assert.deepEqual(f.unverifiedSurfaces[0].sampleParams, ['X-Token', 'Referer']);
  assert.deepEqual(f.uncoveredSurfaces.map((s) => s.surface), ['cookie', 'path']);
  assert.equal(f.crawlBrowserFallback.reason, 'playwright 不可用');
  assert.equal(f.dbmsEvidence.level, 'template-only');
  assert.equal(f.dbmsEvidence.caveat, '未经真引擎验证');
  assert.deepEqual(f.triage, {
    open: 0, confirmed: 1, false_positive: 1, accepted_risk: 0, untagged: 1, total: 3,
  });
  assert.deepEqual(f.missing, []);
});

test('[D275] 边界事实：字段缺失时明确记 missing，不兜底成「无漏洞」', () => {
  const f = buildBoundaryFacts({ vulns: [] });
  assert.equal(f.verdict, null);
  assert.equal(f.reliable, null);
  assert.ok(f.missing.includes('summary.verdict'));
  assert.ok(f.missing.includes('summary.validity'));
  const section = renderBoundarySection(f);
  assert.ok(section.includes('报告未提供 summary.verdict'));
  assert.ok(section.includes('报告未提供 summary.validity'));
  assert.ok(!section.includes('本次未检出'), '缺 verdict 不得写成未检出');
});

test('[D275] 确定性边界章节：marker + inconclusive 口径 + 未验证/未覆盖/告警逐条渲染，且两次调用逐字一致', () => {
  const f = buildBoundaryFacts(boundaryReport());
  const a = renderBoundarySection(f);
  const b = renderBoundarySection(f);
  assert.equal(a, b, '边界章节必须确定性生成');
  assert.ok(a.startsWith(BOUNDARY_MARKER));
  assert.ok(a.includes('verdict=inconclusive'));
  assert.ok(a.includes('不等于「未检出」'));
  assert.ok(a.includes('HTTP 请求头注入面 2/2'));
  assert.ok(a.includes('Cookie 注入面'));
  assert.ok(a.includes('URL 路径段注入面'));
  assert.ok(a.includes('浏览器爬取已降级'));
  assert.ok(a.includes('未经真引擎验证'));
  assert.ok(a.includes('confirmed 1'));
  assert.ok(a.includes('false_positive 1'));
});

test('[D275] 模型提示块必须显式禁止把 inconclusive / 未验证面写成未检出', () => {
  const block = boundaryPromptBlock(buildBoundaryFacts(boundaryReport()));
  assert.ok(block.includes('引擎事实，必须遵守，禁止改写'));
  assert.ok(block.includes('verdict=inconclusive'));
  assert.ok(block.includes('禁止把 inconclusive / 未验证面 / 未覆盖面写成「未检出」或「无漏洞」'));
});

test('[D275] 缓存指纹：verdict / 覆盖面 / triage 任一变化都必须换键', () => {
  const base = buildBoundaryFacts(boundaryReport());
  const fp = boundaryFingerprint(base);
  assert.equal(boundaryFingerprint(buildBoundaryFacts(boundaryReport())), fp, '同报告指纹稳定');

  const verdictChanged = buildBoundaryFacts({
    ...boundaryReport(),
    summary: { ...boundaryReport().summary, verdict: 'no_vulnerability_detected' },
  });
  assert.notEqual(boundaryFingerprint(verdictChanged), fp, 'verdict 变化必须换键');

  const coverageChanged = buildBoundaryFacts({
    ...boundaryReport(),
    summary: { ...boundaryReport().summary, uncoveredSurfaces: [] },
  });
  assert.notEqual(boundaryFingerprint(coverageChanged), fp, '覆盖面变化必须换键');

  const triageChanged = buildBoundaryFacts({
    ...boundaryReport(),
    vulns: [{ technique: 'boolean', triage: { status: 'open' } }],
  });
  assert.notEqual(boundaryFingerprint(triageChanged), fp, '人工裁决变化必须换键');
});

test('[D275] compactBoundary：短请求只带判定与覆盖面，体积足够小', () => {
  const c = compactBoundary(buildBoundaryFacts(boundaryReport()));
  assert.equal(c.verdict, 'inconclusive');
  assert.equal(c.reliable, false);
  assert.equal(c.unverified, 'header:2/2');
  assert.equal(c.uncovered, 'cookie,path');
  assert.ok(JSON.stringify(c).length < 260, `紧凑边界过大：${JSON.stringify(c).length}`);
});

test('[D275] triageSummary：未知状态计入 untagged，不改写 vuln 本体', () => {
  assert.deepEqual(triageSummary([
    { triage: { status: 'accepted_risk' } },
    { triage: { status: 'bogus' } },
    {},
  ]), { open: 0, confirmed: 0, false_positive: 0, accepted_risk: 1, untagged: 2, total: 3 });
});

// ── 超时契约（纯函数）─────────────────────────────────────────────────────

const { resolveRequestTimeoutMs, aiReportLimits } = await import('../src/services/ReportAI.js?d275-limits');

test('[D275] 超时矩阵：默认 REST/CLI 600s、整场 600s、单章 120s', () => {
  assert.equal(resolveRequestTimeoutMs({}), 600000);
  assert.deepEqual(aiReportLimits({}), {
    requestTimeoutMs: 600000,
    totalTimeoutMs: 600000,
    stepwiseTimeoutMs: 120000,
    stepwiseConcurrency: 1,
  });
});

test('[D275] 超时矩阵：env 覆盖逐项生效，非法/非正值回落默认', () => {
  assert.deepEqual(aiReportLimits({
    AI_REPORT_TIMEOUT_MS: '90000',
    AI_REPORT_TOTAL_TIMEOUT_MS: '120000',
    AI_REPORT_STEPWISE_TIMEOUT_MS: '45000',
    AI_REPORT_STEPWISE_CONCURRENCY: '3',
  }), { requestTimeoutMs: 90000, totalTimeoutMs: 120000, stepwiseTimeoutMs: 45000, stepwiseConcurrency: 3 });
  assert.deepEqual(aiReportLimits({
    AI_REPORT_TIMEOUT_MS: '0',
    AI_REPORT_TOTAL_TIMEOUT_MS: '-1',
    AI_REPORT_STEPWISE_TIMEOUT_MS: 'abc',
    AI_REPORT_STEPWISE_CONCURRENCY: '99',
  }), { requestTimeoutMs: 600000, totalTimeoutMs: 600000, stepwiseTimeoutMs: 120000, stepwiseConcurrency: 4 });
  assert.equal(aiReportLimits({ AI_REPORT_STEPWISE_CONCURRENCY: 'abc' }).stepwiseConcurrency, 1);
});

// ── 链路集成（fetch 打桩）─────────────────────────────────────────────────

process.env.AI_REPORT_KEY_1 = 'd275-key-1';
process.env.AI_REPORT_KEY_2 = 'd275-key-2';
process.env.AI_REPORT_KEY_3 = 'd275-key-3';
process.env.AI_REPORT_API_BASE = 'http://127.0.0.1:9/v1/chat/completions';
delete process.env.AI_REPORT_MASK;
delete process.env.AI_REPORT_STEPWISE;

const { generateAiReport } = await import('../src/services/ReportAI.js?d275-legacy');

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

function ok(content, finish = 'stop', usage = { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 }) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ choices: [{ message: { content }, finish_reason: finish }], usage }),
  };
}

const ANALYSIS = JSON.stringify({
  vulns: [{ name: 'SQL 注入', risk: '高危', cvss: '7.5', poc_payload: "1' AND '1'='1" }],
  overall_risk: '高危',
});

function richReport(scanId) {
  return {
    scanId,
    target: {
      baseUrl: 'https://internal.example.com/secret/login?token=abc123&id=7',
      method: 'GET',
    },
    dbms: 'MySQL',
    startedAt: '2026-01-01T00:00:00Z',
    points: [
      { param: 'id', location: 'url', originalValue: '7' },
      { param: 'token', location: 'url', originalValue: 'secret-token' },
    ],
    vulns: [{
      technique: 'boolean', dbms: 'MySQL', riskLevel: 'High',
      description: '布尔盲注', evidence: '真假响应长度差',
      payloads: ["1' AND '1'='1"],
      cvss: {
        score: 7.5,
        vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        severity: 'HIGH',
        note: '引擎启发式评分',
      },
    }],
    summary: {
      verdict: 'vulnerability_detected',
      verdictNote: '检出 1 条',
      validity: { status: 'ok', reliable: true, reason: '' },
      unverifiedSurfaces: [{
        surface: 'header', label: 'HTTP 请求头注入面',
        points: 2, tested: 1, unverified: 1, reason: 'WAF 拦截', sampleParams: ['X-Token'],
      }],
      uncoveredSurfaces: [{ surface: 'cookie', label: 'Cookie 注入面', hint: '提高 --level 到 2' }],
      crawlBrowserFallback: { reason: 'playwright 不可用' },
      dbmsEvidence: { dbms: 'MySQL', level: 'template-only', levelText: '模板适配', caveat: '未经真引擎验证' },
    },
  };
}

const allText = (call) => `${call.body.messages[0].content}\n${call.body.messages[1].content}`;

test('[D275] 脱敏：host / 路径 / query 值 / 参数值都不得进 prompt；边界与 CVSS 必须进 prompt', async () => {
  const fh = installFetch(async (i) => {
    if (i === 1) return ok(ANALYSIS);
    if (i === 2) return ok('DRAFT');
    return ok('FINAL');
  });
  try {
    const r = await generateAiReport(richReport('d275-mask'));
    const prompts = fh.calls.map(allText);
    const joined = prompts.join('\n');
    for (const secret of ['internal.example.com', '/secret/login', 'abc123', 'secret-token', 'originalValue: 7']) {
      assert.ok(!joined.includes(secret), `脱敏态泄露了 ${secret}`);
    }
    assert.ok(joined.includes('<目标Host>'), 'host 应替换为占位符');
    assert.ok(joined.includes('***'), 'query/参数值应替换为 ***');
    // 边界口径进入三类 prompt
    for (const p of prompts) assert.ok(p.includes('## 结论口径'), '每个角色都要看到结论口径');
    assert.ok(prompts[0].includes('verdict=vulnerability_detected'));
    assert.ok(prompts[0].includes('HTTP 请求头注入面 1/2'));
    assert.ok(prompts[0].includes('Cookie 注入面'));
    assert.ok(prompts[0].includes('未经真引擎验证'));
    // 引擎 CVSS 进入 analyst 事实（模型被要求逐字引用）
    assert.ok(prompts[0].includes('引擎 CVSS（必须引用）'));
    assert.ok(prompts[0].includes('7.5'));
    assert.ok(prompts[0].includes('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'));
    assert.ok(prompts[0].includes('禁止自行编造分数'));
    // 确定性边界章节追加在模型正文之后
    assert.ok(r.content.startsWith('FINAL'));
    assert.ok(r.content.includes(BOUNDARY_MARKER));
    assert.ok(r.content.includes('本次检出 1 条漏洞'));
    assert.ok(r.content.includes('未验证注入面'));
    assert.ok(r.content.includes('按当前配置未测的注入面'));
    assert.ok(r.content.includes('浏览器爬取已降级'));
    assert.equal(r.boundary.verdict, 'vulnerability_detected');
  } finally { fh.restore(); }
});

test('[D275] trace/usage：逐请求记录 role/model/status/finish_reason/ms，usage 汇总不伪造 0', async () => {
  const fh = installFetch(async (i) => (i === 1 ? ok(ANALYSIS) : ok(i === 2 ? 'DRAFT' : 'FINAL')));
  try {
    const r = await generateAiReport(richReport('d275-trace'));
    assert.equal(r.trace.length, 3);
    assert.deepEqual(r.trace.map((t) => t.role), ['analyst', 'writer', 'reviewer']);
    for (const t of r.trace) {
      assert.equal(t.status, 200);
      assert.equal(t.finish_reason, 'stop');
      assert.ok(Number.isFinite(t.ms) && t.ms >= 0);
      assert.ok(t.usage && t.usage.total_tokens === 15);
    }
    assert.deepEqual(r.usage, { prompt_tokens: 30, completion_tokens: 15, total_tokens: 45 });
  } finally { fh.restore(); }
});

test('[D275] 网关不返回 usage：result.usage=null（不把缺失记成 0）', async () => {
  const fh = installFetch(async (i) => {
    const res = i === 1 ? ok(ANALYSIS) : ok(i === 2 ? 'DRAFT' : 'FINAL');
    const payload = await res.json();
    return { ...res, json: async () => ({ ...payload, usage: undefined }) };
  });
  try {
    const r = await generateAiReport(richReport('d275-nousage'));
    assert.equal(r.usage, null);
  } finally { fh.restore(); }
});

test('[D275] finish_reason=length（非空截断）不算成功：触发短重试，重试成功才继续', async () => {
  const fh = installFetch(async (i) => {
    if (i === 1) return ok(ANALYSIS, 'length'); // 非空但被 max_tokens 截断
    if (i === 2) return ok(ANALYSIS);          // analyst 短重试
    if (i === 3) return ok('DRAFT');
    return ok('FINAL');
  });
  try {
    const r = await generateAiReport(richReport('d275-length'));
    assert.deepEqual(r.shortPromptRetries, ['analyst']);
    assert.equal(fh.calls.length, 4);
    assert.equal(r.trace[0].finish_reason, 'length');
    assert.equal(r.trace[0].error, 'length');
  } finally { fh.restore(); }
});

test('[D275] 三级 analyst 全部 finish_reason=length → 拒绝出报告，不把截断当成功', async () => {
  const fh = installFetch(async () => ok(ANALYSIS, 'length'));
  try {
    await assert.rejects(
      () => generateAiReport(richReport('d275-length-all')),
      /漏洞分析角色全部失败/,
    );
    assert.equal(fh.calls.length, 6, '三级 × (首轮 + 短重试)');
  } finally { fh.restore(); }
});

test('[D275] 半成品不缓存：reviewer 未过审的产物下次必须重新生成', async () => {
  const fh = installFetch(async (i) => {
    if (i === 1) return ok(ANALYSIS);
    if (i === 2) return ok('DRAFT');
    if (i === 3) return ok('', 'length'); // reviewer 首轮空
    if (i === 4) return ok('', 'length'); // reviewer 短重试空
    if (i === 5) return ok(ANALYSIS);
    if (i === 6) return ok('DRAFT');
    return ok('FINAL');
  });
  try {
    const r1 = await generateAiReport(richReport('d275-partial-cache'));
    assert.ok(r1.reviewNote.includes('⚠️'), '未过审必须显式标注');
    assert.equal(r1.cached, undefined);
    const r2 = await generateAiReport(richReport('d275-partial-cache'));
    assert.equal(r2.cached, undefined, '半成品不得命中缓存');
    assert.equal(fh.calls.length, 7, '第二次必须重新请求（4 + 3）');
  } finally { fh.restore(); }
});
