// [D275] 分步短 prompt 的脱敏 / 边界 / 合法 JSON / 审阅预算判据（guard 类）
//
// 钉住的行为契约：
//   ① 分步请求同样不得外发 host / 路径 / query 值 / 参数值；
//   ② 每个短请求带结论口径，analyst 事实带引擎 CVSS；
//   ③ factsJson 超预算时仍必须是**合法 JSON**（旧实现直接 slice 出半截 JSON）；
//   ④ 审阅输入不再 clamp 到 980 字符：预算内送全文，超预算**不送审**并标 partial，
//      绝不用节选审阅替换整章；
//   ⑤ 429/5xx 换 key/端点重试一次，新 cfg 留给后续章节。
//
// 判据边界：链路单测（callLLM 注入），不替代真网关 e2e。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  fitJson,
  runStepwiseStages,
  STEPWISE_REVIEW_MAX_CHARS,
} from '../src/services/reportAiStepwise.js';
import { BOUNDARY_MARKER } from '../src/services/reportAiFacts.js';

// ── 纯函数：fitJson ────────────────────────────────────────────────────────

test('[D275] fitJson：任何预算下都返回可解析 JSON，且不超预算', () => {
  const big = {
    params: 'p'.repeat(2000),
    method: 'GET',
    dbms: 'MySQL',
    analysis: JSON.stringify({ vulns: Array.from({ length: 20 }, (_, i) => ({ i, payload: 'x'.repeat(100) })) }),
    vulns: Array.from({ length: 10 }, (_, i) => ({ technique: `t${i}`, evidence: 'e'.repeat(200) })),
    boundary: { verdict: 'inconclusive', unverified: 'header:2/2', uncovered: 'cookie,path' },
    extracted: { databases: ['a', 'b'], tables: 3 },
  };
  for (const budget of [1200, 900, 600, 300, 120, 60]) {
    const s = fitJson(big, budget, ['analysis', 'extracted']);
    assert.ok(s.length <= budget, `预算 ${budget} 超长：${s.length}`);
    assert.doesNotThrow(() => JSON.parse(s), `预算 ${budget} 产出非法 JSON：${s.slice(0, 80)}`);
  }
});

test('[D275] fitJson：预算充足时逐字等于全量 JSON', () => {
  const obj = { a: 1, b: 'x' };
  assert.equal(fitJson(obj, 1000), JSON.stringify(obj));
});

// ── 分步链路集成（真实 generateAiReport + callLLM 打桩）────────────────────

process.env.AI_REPORT_KEY_1 = 'd275s-key-1';
process.env.AI_REPORT_KEY_2 = 'd275s-key-2';
process.env.AI_REPORT_KEY_3 = 'd275s-key-3';
process.env.AI_REPORT_API_BASE = 'http://127.0.0.1:9/v1/chat/completions';
process.env.AI_REPORT_STEPWISE = '1';
delete process.env.AI_REPORT_MASK;

const { generateAiReport } = await import('../src/services/ReportAI.js?d275-stepwise');

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

function ok(content) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      choices: [{ message: { content }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }),
  };
}

const ANALYSIS = JSON.stringify({
  vulns: [{
    name: 'SQL 注入', risk: '高危', cvss: '7.5',
    poc_payload: "1' AND '1'='1", poc_verify: '真假响应长度差',
  }],
  overall_risk: '高危',
});

const userOf = (call) => call.body.messages[1].content;
const titleOf = (call) => {
  const m = userOf(call).match(/「([^」]+)」/);
  return m ? m[1] : '';
};

function allOk(i, call) {
  const user = userOf(call);
  if (user.startsWith('【分步·分析】')) return ok(ANALYSIS);
  return ok(`# ${titleOf(call)}\n\nCONTENT:${titleOf(call)}:${i}`);
}

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
      dbmsEvidence: { dbms: 'MySQL', level: 'template-only', levelText: '模板适配', caveat: '未经真引擎验证' },
    },
  };
}

test('[D275] 分步请求：host/路径/query/参数值全脱敏；边界与引擎 CVSS 进入事实', async () => {
  const fh = installFetch(allOk);
  try {
    const r = await generateAiReport(richReport('d275s-mask'));
    const joined = fh.calls.map((c) => `${c.body.messages[0].content}\n${userOf(c)}`).join('\n');
    for (const secret of ['internal.example.com', '/secret/login', 'abc123', 'secret-token', '原始值 7']) {
      assert.ok(!joined.includes(secret), `分步请求泄露了 ${secret}`);
    }
    assert.ok(joined.includes('<目标Host>'), '分步 analyst 仍要看到脱敏 host 占位符');
    assert.ok(joined.includes('***'), '参数值应替换为 ***');
    assert.ok(joined.includes('"verdict":"vulnerability_detected"'), '每个短请求都带紧凑结论口径');
    assert.ok(joined.includes('"unverified":"header:1/2"'));
    assert.ok(joined.includes('"uncovered":"cookie"'));
    assert.ok(joined.includes('engineCvss'), '分步 analyst 事实必须带引擎 CVSS');
    assert.ok(joined.includes('7.5'));
    assert.ok(joined.includes('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'));
    assert.ok(r.content.includes(BOUNDARY_MARKER), '确定性边界章节仍追加在拼装正文之后');
    assert.ok(r.content.includes('本次检出 1 条漏洞'));
    assert.equal(r.stepwise.partial, false);
  } finally { fh.restore(); }
});

test('[D275] 分步审阅：预算内送全文，不截断章节', async () => {
  const longSection = `${'A'.repeat(1500)}END-OF-SECTION`;
  const seen = [];
  const deps = baseDeps({
    callLLM: async (cfg, system, user) => {
      seen.push(user);
      if (user.includes('审阅并修订')) return 'REVIEWED';
      return longSection;
    },
    reviewMaxChars: 4000,
  });
  const r = await runStepwiseStages(deps);
  const reviewUsers = seen.filter((u) => u.includes('审阅并修订'));
  assert.equal(reviewUsers.length, 5);
  for (const u of reviewUsers) {
    assert.ok(u.includes('END-OF-SECTION'), '审阅输入必须是完整章节，不得截断');
    assert.ok(u.length > 1500);
  }
  assert.equal(r.stepwise.reviewedSections, 5);
  assert.equal(r.stepwise.partial, false);
  assert.deepEqual(r.stepwise.failedSteps, []);
});

test('[D275] 分步审阅：超预算章节不送审、保留原章、标 partial（绝不用节选审阅冒充全文）', async () => {
  let calls = 0;
  const deps = baseDeps({
    callLLM: async (cfg, system, user) => {
      calls += 1;
      assert.ok(!user.includes('审阅并修订'), '超预算章节不得送审');
      return 'B'.repeat(50);
    },
    reviewMaxChars: 10,
  });
  const r = await runStepwiseStages(deps);
  assert.equal(calls, 5, '只发 5 次撰写请求');
  assert.equal(r.stepwise.reviewedSections, 0);
  assert.equal(r.stepwise.partial, true);
  assert.equal(r.stepwise.failedSteps.length, 5);
  assert.ok(r.stepwise.failedSteps.every((s) => /^reviewer:.+:too-long$/.test(s)), JSON.stringify(r.stepwise.failedSteps));
  assert.ok(!r.reviewNote.includes('✅'));
  assert.ok(r.finalReport.includes('B'.repeat(50)), '原章必须保留');
});

test('[D275] 分步 503：换 key/端点重试一次，新 cfg 留给后续章节', async () => {
  const seenKeys = [];
  let writerCalls = 0;
  const cfgA = { role: 'writer', model: 'm', keyIdx: 1, apiKey: 'a', apiBase: 'http://a' };
  const cfgB = { role: 'writer', model: 'm', keyIdx: 2, apiKey: 'b', apiBase: 'http://b' };
  const reviewCfg = { role: 'reviewer', model: 'r', keyIdx: 3, apiKey: 'c', apiBase: 'http://c' };
  const deps = baseDeps({
    getRoleConfig: (idx) => (idx === 1 ? (writerCalls === 0 ? cfgA : cfgB) : reviewCfg),
    callLLM: async (cfg, system, user) => {
      if (user.includes('审阅并修订')) return 'REVIEWED';
      writerCalls += 1;
      seenKeys.push(cfg.keyIdx);
      if (writerCalls === 1) {
        throw Object.assign(new Error('LLM API 503: upstream down'), { retryableWithAnotherKey: true });
      }
      return 'SECTION';
    },
  });
  const r = await runStepwiseStages(deps);
  assert.deepEqual(seenKeys, [1, 2, 2, 2, 2, 2], '首章 503 换 key，后续章节沿用新 key');
  assert.equal(r.stepwise.partial, false);
  assert.equal(r.stepwise.writerSteps, 5);
});

// ── 直接调度依赖 ───────────────────────────────────────────────────────────

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
    reviewMaxChars: STEPWISE_REVIEW_MAX_CHARS,
    sectionCount: 5,
    callLLM: async () => 'SECTION',
    getRoleConfig: (idx) => ({ role: idx === 1 ? 'writer' : 'reviewer', model: 'm', keyIdx: idx, apiKey: 'k', apiBase: 'http://x' }),
    legacyFallback: async () => { throw new Error('legacy fallback should not be called'); },
    ...over,
  };
}
