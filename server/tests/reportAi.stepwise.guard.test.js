// [D259] 分步短 prompt 判据（guard 类）
//
// 钉住的行为契约：AI_REPORT_STEPWISE=1 时每个请求本来就短（analyst 首轮短 +
// writer 逐章短 + reviewer 逐章短），按固定章节顺序拼装；缺章显式标注、
// 不编造内容、不冒充全文审阅；全章失败回退原整篇流水线并如实登记。
// 未开启开关时，D258 三角色链路逐字零变化。
//
// 判据边界：这些是链路单测，不替代真网关 e2e。短 prompt 在真模型上能否产出
// 可用内容，只能靠 e2e/ai-gateway-lab/run.mjs 的真 HTTP 退出码证明。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  stepwiseEnabled,
  buildStepwiseReviewerSteps,
  assembleStepwiseReport,
  runStepwiseStages,
  STEPWISE_MAX_CHARS,
  WRITER_SECTIONS,
  MISSING_SECTION,
} from '../src/services/reportAiStepwise.js';

// 模块加载期读 env：先把开关打开，再按 query 拿相互隔离的实例（独立 keyHealth / cache）
process.env.AI_REPORT_KEY_1 = 'guard-key-1';
process.env.AI_REPORT_KEY_2 = 'guard-key-2';
process.env.AI_REPORT_KEY_3 = 'guard-key-3';
process.env.AI_REPORT_API_BASE = 'http://127.0.0.1:9/v1/chat/completions';
process.env.AI_REPORT_STEPWISE = '1';

/** 每个用例一个独立实例，避免模块级 keyHealth 冷却 / 缓存跨用例污染 */
async function fresh(tag) {
  return import(`../src/services/ReportAI.js?d259-${tag}`);
}

// 关闭开关的对照实例（必须单独 query；ReportAI 在加载期把 stepwiseEnabled() 固化成常量）
delete process.env.AI_REPORT_STEPWISE;
const genOff = await import('../src/services/ReportAI.js?d259-off');
process.env.AI_REPORT_STEPWISE = '1';

const { writeAiReportFiles } = await import('../src/services/aiReportCli.js?d259');

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
    json: async () => ({ choices: [{ message: { content }, finish_reason: 'stop' }] }),
  };
}

const empty = () => ok('', 'length');
const ANALYSIS = '{"vulns":[{"name":"SQL 注入","risk":"高危","poc_payload":"1 AND 1=1"}],"overall_risk":"高危"}';

function baseReport(scanId) {
  return {
    scanId,
    target: { baseUrl: 'http://127.0.0.1:8099/vulnerabilities/sqli/?id=1&Submit=Submit', method: 'GET' },
    dbms: 'MySQL',
    startedAt: '2026-01-01T00:00:00Z',
    points: [{ param: 'id', location: 'url', originalValue: '1' }],
    vulns: [{
      technique: 'boolean', dbms: 'MySQL', riskLevel: 'High',
      evidence: '真/假探针响应长度差：真样本 1617B / 假样本 30B',
      payloads: ["1' AND '1'='1"],
    }],
  };
}

const userOf = (call) => call.body.messages[1].content;
const titleOf = (call) => {
  const m = userOf(call).match(/「([^」]+)」/);
  return m ? m[1] : '';
};

/** 默认 stub：analyst 出 JSON，其余每个短请求回一段带章节标题的 Markdown */
async function allOk(i, call) {
  const user = userOf(call);
  if (user.startsWith('【分步·分析】')) return ok(ANALYSIS);
  return ok(`# ${titleOf(call)}\n\nCONTENT:${titleOf(call)}:${i}`);
}

// ── 开关与非分步零回归 ─────────────────────────────────────────────────────
test('[D259] 开关关闭：仍是原三角色 3 次调用，无 stepwise 字段', async () => {
  const fh = installFetch(async (i) => ok(i === 1 ? ANALYSIS : 'BODY'));
  try {
    const r = await genOff.generateAiReport(baseReport('d259-off'));
    assert.equal(fh.calls.length, 3);
    assert.ok(!userOf(fh.calls[0]).startsWith('【分步'));
    assert.equal(r.stepwise, undefined);
    assert.equal(r.reviewNote, '✅ 已经过安全审阅角色校验');
  } finally { fh.restore(); }
});

// ── 分步链路 ───────────────────────────────────────────────────────────────
test('[D259] analyst 首轮即短 prompt：仍要求 JSON 结构并带引擎判据', async () => {
  const g = await fresh('analyst');
  const fh = installFetch(allOk);
  try {
    const r = await g.generateAiReport(baseReport('d259-analyst'));
    assert.equal(r.success, true);
    assert.equal(fh.calls.length, 1 + WRITER_SECTIONS.length * 2, '1 分析 + N 章撰写 + N 章审阅');
    const user = userOf(fh.calls[0]);
    assert.ok(user.startsWith('【分步·分析】'), '首轮就发短 prompt，不再先挂长报告');
    assert.ok(user.includes('"vulns"') && user.includes('overall_risk'), '短分析仍要同一份 JSON 结构');
    assert.ok(user.includes('id'), '注入参数名保留');
    assert.ok(user.includes('响应判据'), '引擎实测判据随事实带过去');
  } finally { fh.restore(); }
});

test('[D259] 每章一次短请求：全在预算内、不塞 SRC 长模板、章节顺序固定', async () => {
  const g = await fresh('budget');
  const fh = installFetch(allOk);
  try {
    await g.generateAiReport(baseReport('d259-budget'));
    const writer = fh.calls.slice(1, 1 + WRITER_SECTIONS.length);
    const review = fh.calls.slice(1 + WRITER_SECTIONS.length);
    assert.deepEqual(writer.map(titleOf), WRITER_SECTIONS.map((s) => s.title));
    assert.deepEqual(review.map(titleOf), WRITER_SECTIONS.map((s) => s.title), '审阅按章对齐');
    for (const call of [...writer, ...review]) {
      const user = userOf(call);
      assert.ok(user.startsWith('【分步'), '每个请求都以短 prompt 前缀开头');
      assert.ok(user.length <= STEPWISE_MAX_CHARS, `短请求超预算：${user.length}`);
      assert.ok(!user.includes('漏洞盒子 SRC 平台提交标准'), '不得把整篇长模板塞回去');
    }
    assert.ok(review.every((c) => userOf(c).includes('本节：')), '审阅输入是单章节选');
  } finally { fh.restore(); }
});

test('[D259] PoC 章保留参数名、原始 payload 与引擎判据（事实不因拆章丢失）', async () => {
  const g = await fresh('poc');
  const fh = installFetch(allOk);
  try {
    await g.generateAiReport(baseReport('d259-poc'));
    const poc = fh.calls[1 + WRITER_SECTIONS.findIndex((s) => s.key === 'poc')];
    const user = userOf(poc);
    assert.ok(user.includes('id'), '参数名逐字一致');
    assert.ok(user.includes("1' AND '1'='1"), '原始 payload 保留');
    assert.ok(user.includes('响应判据'), '引擎判据保留');
    assert.ok(user.includes('poc_verify'), '分析里的 PoC 验证判据保留');
  } finally { fh.restore(); }
});

test('[D259] 拼装：五章按序、内容来自各章短请求、审阅口径如实披露', async () => {
  const g = await fresh('assemble');
  const fh = installFetch(allOk);
  try {
    const r = await g.generateAiReport(baseReport('d259-assemble'));
    let cursor = -1;
    for (const s of WRITER_SECTIONS) {
      const at = r.content.indexOf(`### ${s.title}`);
      assert.ok(at > cursor, `章节顺序错乱：${s.title}`);
      cursor = at;
    }
    assert.ok(r.content.includes('CONTENT:一、漏洞概述'), '正文来自各章短请求');
    assert.equal(r.stepwise.enabled, true);
    assert.equal(r.stepwise.partial, false);
    assert.equal(r.stepwise.fallback, null);
    assert.equal(r.stepwise.writerSteps, WRITER_SECTIONS.length);
    assert.equal(r.stepwise.reviewedSections, WRITER_SECTIONS.length);
    assert.deepEqual(r.stepwise.failedSteps, []);
    assert.ok(r.reviewNote.includes('✅') && r.reviewNote.includes('5/5'));
    assert.equal(r.pipeline, 'analyst→writer→reviewer', '套件元数据头口径不变');
  } finally { fh.restore(); }
});

test('[D259] 某章返回空 → 显式标注缺章、partial=true、不冒充全文审阅', async () => {
  const g = await fresh('partial');
  const pocCallIdx = 1 + WRITER_SECTIONS.findIndex((s) => s.key === 'poc') + 1; // 1-based fetch 序号
  const fh = installFetch(async (i, call) => (i === pocCallIdx ? empty() : allOk(i, call)));
  try {
    const r = await g.generateAiReport(baseReport('d259-partial'));
    assert.ok(r.content.includes(MISSING_SECTION), '缺章必须显式标注，不得静默省略');
    assert.deepEqual(r.stepwise.failedSteps, ['writer:poc']);
    assert.equal(r.stepwise.partial, true);
    assert.equal(r.stepwise.reviewedSections, WRITER_SECTIONS.length - 1, '失败章节不送审');
    assert.ok(!r.reviewNote.includes('✅'), '部分章节失败不得标 ✅ 已审阅');
    assert.equal(fh.calls.length, 1 + 5 + 4);
  } finally { fh.restore(); }
});

test('[D259] 全章失败 → 回退原整篇流水线，并如实登记 fallback=legacy', async () => {
  const g = await fresh('fallback');
  const fh = installFetch(async (i, call) => (
    userOf(call).startsWith('【分步·分析】') ? ok(ANALYSIS) : empty()
  ));
  try {
    const r = await g.generateAiReport(baseReport('d259-fallback'));
    assert.equal(r.stepwise.fallback, 'legacy');
    assert.equal(r.stepwise.partial, true);
    assert.ok(r.content.includes('报告撰写角色暂不可用'), '回退后仍是 D255 的降级文案');
    assert.ok(!r.reviewNote.includes('✅'));
    assert.equal(fh.calls.length, 1 + 5 + 4, '5 章全空 + legacy writer/reviewer 各 2 次');
  } finally { fh.restore(); }
});

// ── 纯函数与落盘披露 ───────────────────────────────────────────────────────
test('[D259] 纯函数：缺章占位 / 审阅只送成功章节 / 开关注入可测', () => {
  const sections = [
    { key: 'a', title: '一', content: 'A', generated: true },
    { key: 'b', title: '二', content: '', generated: false },
  ];
  const md = assembleStepwiseReport(sections);
  assert.ok(md.includes('### 一') && md.includes('A'));
  assert.ok(md.includes('### 二') && md.includes(MISSING_SECTION));
  assert.equal(buildStepwiseReviewerSteps(sections).length, 1);
  assert.equal(stepwiseEnabled({ AI_REPORT_STEPWISE: '1' }), true);
  assert.equal(stepwiseEnabled({ AI_REPORT_STEPWISE: '0' }), false);
  assert.equal(stepwiseEnabled({}), false);
});

test('[D259] stepwise 写进 ai-report.json；未开启时元数据结构零变化', () => {
  const dir = mkdtempSync(join(tmpdir(), 'd259-meta-'));
  try {
    const report = baseReport('d259-meta');
    const on = writeAiReportFiles(join(dir, 'on'), {
      content: 'BODY', reviewNote: 'ok', stepwise: { enabled: true, partial: true, failedSteps: ['writer:poc'] },
    }, report, {});
    const off = writeAiReportFiles(join(dir, 'off'), { content: 'BODY', reviewNote: 'ok' }, report, {});
    const metaOn = JSON.parse(readFileSync(on.metaFile, 'utf-8'));
    const metaOff = JSON.parse(readFileSync(off.metaFile, 'utf-8'));
    assert.equal(metaOn.stepwise.partial, true);
    assert.deepEqual(metaOn.stepwise.failedSteps, ['writer:poc']);
    assert.equal(metaOff.stepwise, undefined);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── [D259] 调度层直接调用 ───────────────────────────────────────────────────
// 调度函数放在 reportAiStepwise.js（无 query 静态 import），由本文件直接调用，
// 目的是让它的分支能被 CI 的多进程 coverage 正确归因（见 CHANGELOG D259 收口段）。

function mockStepwiseDeps(handler) {
  const calls = [];
  return {
    calls,
    facts: {
      url: 'http://127.0.0.1:8099/***', urlPath: '/***', host: '<目标Host>',
      method: 'GET', dbms: 'MySQL', params: 'id（url，原始值 1）', paramsRaw: 'id',
      startedAt: '2026-01-01T00:00:00Z', analysis: ANALYSIS, extracted: null,
      vulns: [{ technique: 'boolean', risk: 'High', dbms: 'MySQL', evidence: '长度差', payload: "1' AND '1'='1", basis: '引擎判据' }],
    },
    timeoutMs: 2000,
    stepwiseTimeoutMs: 2000,
    maxPromptChars: STEPWISE_MAX_CHARS,
    sectionCount: WRITER_SECTIONS.length,
    callLLM: async (cfg, system, user) => {
      calls.push({ cfg, system, user });
      return handler(calls.length, user);
    },
    getRoleConfig: (idx) => ({ idx }),
    legacyFallback: async () => ({ draft: 'LEGACY', finalReport: 'LEGACY', reviewNote: '⚠️ 未过审', stepwise: null }),
  };
}

test('[D259] 调度层直调：全章成功 → 五章拼装 + 逐章审阅 ✅', async () => {
  const deps = mockStepwiseDeps((i) => `SEC-${i}`);
  const r = await runStepwiseStages(deps);
  assert.equal(r.stepwise.partial, false);
  assert.equal(r.stepwise.reviewedSections, WRITER_SECTIONS.length);
  assert.equal(r.stepwise.fallback, null);
  assert.ok(r.reviewNote.includes('✅'));
  assert.equal(deps.calls.length, WRITER_SECTIONS.length * 2);
  assert.equal((r.finalReport.match(/### /g) || []).length, WRITER_SECTIONS.length);
});

test('[D259] 调度层直调：单章失败 → 占位 + 失败章节不送审', async () => {
  const deps = mockStepwiseDeps((i) => {
    if (i === 3) throw new Error('simulated failure');
    return `SEC-${i}`;
  });
  const r = await runStepwiseStages(deps);
  assert.equal(r.stepwise.partial, true);
  assert.deepEqual(r.stepwise.failedSteps, ['writer:poc']);
  assert.equal(r.stepwise.reviewedSections, WRITER_SECTIONS.length - 1);
  assert.ok(r.finalReport.includes(MISSING_SECTION));
  assert.ok(!r.reviewNote.includes('✅'));
});

test('[D259] 调度层直调：全章失败 → 回退整篇流水线', async () => {
  const deps = mockStepwiseDeps(() => { throw new Error('simulated failure'); });
  const r = await runStepwiseStages(deps);
  assert.equal(r.stepwise.fallback, 'legacy');
  assert.equal(r.finalReport, 'LEGACY');
  assert.equal(deps.calls.length, WRITER_SECTIONS.length);
});

test('[D259] 调度层直调：审阅逐章失败 → 保留原章、口径降级', async () => {
  const deps = mockStepwiseDeps((i) => {
    if (i > WRITER_SECTIONS.length) throw new Error('simulated review failure');
    return `SEC-${i}`;
  });
  const r = await runStepwiseStages(deps);
  assert.equal(r.stepwise.reviewedSections, 0);
  assert.equal(r.stepwise.partial, true);
  assert.ok(r.reviewNote.includes('部分完成'));
  assert.ok(r.finalReport.includes('SEC-1'), '审阅失败不得清空已生成章节');
});

// ── [D260] 同进程无 query 实例：分步链路**行为**补测 ───────────────────────
// 口径更正（已推翻初版注释）：初版声称「同进程补测能修好 CI 覆盖率合并」，实测补测后
// `npm run test:coverage` 仍 exit 1（all files 73.18% branch，ReportAI.js 34.56% branch）。
// 真因是 Node 覆盖率在存在 `?query` 模块实例时单快照合并，与补测位置无关。
// 证据、最小复现样本与修法见 `docs/覆盖率门禁接线-D260.md` /
// `scripts/server-coverage-gate.mjs`。这几条用例只作行为守卫（正常 / 缺章 / 回退 /
// 审阅失败 / 极简报告），不再承担覆盖率修复职责。
// 失败一律用「非 AbortError 的普通异常」：callLLM 会直接 rethrow，不 markKeyFail，
// 模块级 keyHealth 不会给后续用例留冷却。
const genMain = await import('../src/services/ReportAI.js');
const fail = () => { throw new Error('simulated network failure'); };

/** 默认：分析出 JSON，其余按章节标题回一段 Markdown */
async function mainAllOk(i, call) {
  const user = userOf(call);
  if (user.startsWith('【分步·分析】')) return ok(ANALYSIS);
  const m = user.match(/「([^」]+)」/);
  return ok(`# ${m ? m[1] : '章节'}\n\nCONTENT-${i}`);
}

test('[D260] 同进程无 query：正常分步路径', async () => {
  const fh = installFetch(mainAllOk);
  try {
    const r = await genMain.generateAiReport(baseReport('d260-normal'));
    assert.equal(r.stepwise.partial, false);
    assert.equal(r.stepwise.reviewedSections, WRITER_SECTIONS.length);
    assert.ok(r.content.includes('### 三、漏洞证明（PoC）'));
  } finally { fh.restore(); }
});

test('[D260] 同进程无 query：writer 单章失败 → 缺章标注', async () => {
  const fh = installFetch(async (i, call) => (i === 4 ? fail() : mainAllOk(i, call)));
  try {
    const r = await genMain.generateAiReport(baseReport('d260-partial'));
    assert.equal(r.stepwise.partial, true);
    assert.ok(r.stepwise.failedSteps.includes('writer:poc'));
    assert.ok(r.content.includes(MISSING_SECTION));
  } finally { fh.restore(); }
});

test('[D260] 同进程无 query：全章失败 → 回退整篇流水线', async () => {
  const fh = installFetch(async (i, call) => (
    userOf(call).startsWith('【分步·分析】') ? ok(ANALYSIS) : fail()
  ));
  try {
    const r = await genMain.generateAiReport(baseReport('d260-fallback'));
    assert.equal(r.stepwise.fallback, 'legacy');
    assert.ok(!r.reviewNote.includes('✅'));
  } finally { fh.restore(); }
});

test('[D260] 同进程无 query：审阅逐章失败 → 保留原章、口径降级', async () => {
  const fh = installFetch(async (i, call) => {
    if (userOf(call).startsWith('【分步·分析】')) return ok(ANALYSIS);
    return i <= 6 ? mainAllOk(i, call) : fail();
  });
  try {
    const r = await genMain.generateAiReport(baseReport('d260-review'));
    assert.equal(r.stepwise.reviewedSections, 0);
    assert.ok(r.reviewNote.includes('部分完成'));
    assert.ok(r.content.includes('CONTENT-2'));
  } finally { fh.restore(); }
});

test('[D260] 同进程无 query：极简报告（points/data/dbms/method/trace 全缺）', async () => {
  const fh = installFetch(mainAllOk);
  try {
    const r = await genMain.generateAiReport({
      scanId: 'd260-minimal',
      target: { baseUrl: 'http://127.0.0.1:8099/' },
      vulns: [],
      data: { databases: ['app'], tables: { users: [] }, rows: { users: [['a']] } },
    });
    assert.equal(r.stepwise.partial, false);
    assert.ok(r.content.includes('### 一、漏洞概述'));
  } finally { fh.restore(); }
});
