// [D255/D258] 短 prompt 重试判据（guard 类）
//
// 钉住的行为契约：analyst / writer / reviewer 首次「空内容 / 超时」失败时，用压缩后的
// 短 prompt 再试一次；重试只接受真实非空内容，绝不把没产出记成成功；429 / HTTP 错误不重试；
// 开关可关；成功生效的重试随结果如实披露。
//
// [D258] 补 analyst 阶段：D255 的短重试只挂 writer/reviewer，双网关实测（545s）却显示
// 三级降级全在 analyst 失败 —— 流水线走不到后两步。analyst 主角色与两级降级现在都带短重试，
// 且短 prompt 仍要求同一份 JSON 结构（vulns / overall_risk），否则重试成功也会被判非 JSON。
//
// 判据边界：这些是**链路单测**，不替代真网关 e2e（e2e/ai-gateway-lab/run.mjs）。
// 「短 prompt 在真模型上能否返回内容」只能靠真跑证明，单测只证明请求确实变短、
// 且没有伪造成功。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// 模块加载期读 env：先设好再 import，拿到相互隔离的实例（独立 keyHealth / cache）
process.env.AI_REPORT_KEY_1 = 'guard-key-1';
process.env.AI_REPORT_KEY_2 = 'guard-key-2';
process.env.AI_REPORT_KEY_3 = 'guard-key-3';
process.env.AI_REPORT_API_BASE = 'http://127.0.0.1:9/v1/chat/completions';

// 关闭短重试的对照实例（必须单独 query，否则拿到同一模块实例）
process.env.AI_REPORT_SHORT_RETRY = '0';
const genOff = await import('../src/services/ReportAI.js?shortretryoff');
delete process.env.AI_REPORT_SHORT_RETRY;

/** 每个用例一个独立实例，避免模块级 keyHealth 冷却 / 缓存跨用例污染 */
async function fresh(tag) {
  return import(`../src/services/ReportAI.js?sr-${tag}`);
}

const { writeAiReportFiles } = await import('../src/services/aiReportCli.js?shortretry');

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

function ok(content, finish = 'stop') {
  return {
    ok: true,
    status: 200,
    json: async () => ({ choices: [{ message: { content }, finish_reason: finish }] }),
  };
}

const empty = () => ok('', 'length');
const limited = () => ({ ok: false, status: 429, text: async () => 'rate limited' });
const ANALYSIS = '{"vulns":[{"name":"SQL 注入","risk":"高危","poc_payload":"1 AND 1=1"}],"overall_risk":"高危"}';

function baseReport(scanId) {
  return {
    scanId,
    target: { baseUrl: 'http://127.0.0.1:8099/vulnerabilities/sqli/?id=1&Submit=Submit', method: 'GET' },
    dbms: 'MySQL',
    startedAt: '2026-01-01T00:00:00Z',
    points: [{ param: 'id', location: 'url', originalValue: '1' }],
    vulns: [{ technique: 'boolean', dbms: 'MySQL', riskLevel: 'High', evidence: '真假响应长度差', payloads: ["1' AND '1'='1"] }],
  };
}

const userOf = (call) => call.body.messages[1].content;
const systemOf = (call) => call.body.messages[0].content;

/**
 * [D275] 去掉引擎确定性追加的「结论口径」章节：本文件断言的是模型正文，
 * 边界章节另有判据（reportAiFacts.guard.test.js）。这样不放松「正文必须来自模型产出」。
 * @param {string} content 生成结果
 * @returns {string} 模型正文
 */
function modelBody(content) {
  const s = String(content || '');
  const i = s.indexOf('<!-- engine-boundary -->');
  return (i < 0 ? s : s.slice(0, i)).trimEnd();
}

// ── [D258] analyst 阶段的短重试 ─────────────────────────────────────────────
// D255 把短重试挂在 writer/reviewer，双网关实测（545s）却显示三级降级全在 analyst
// 阶段失败 —— 流水线根本没走到后两步。这组用例钉住：analyst 主角色与两级降级
// 都带短重试，且短 prompt 仍要求同一份 JSON 结构（否则重试成功也会被判非 JSON）。

test('[D258] analyst 空内容 → 短 prompt 重试成功，流水线继续走完', async () => {
  const g = await fresh('analyst');
  const fh = installFetch(async (i) => {
    if (i === 1) return empty();            // analyst 首轮空（长 prompt 挂起形态）
    if (i === 2) return ok(ANALYSIS);       // analyst 短重试
    if (i === 3) return ok('DRAFT');        // writer
    return ok('FINAL');                     // reviewer
  });
  try {
    const r = await g.generateAiReport(baseReport('sr-analyst'));
    assert.equal(modelBody(r.content), 'FINAL', 'analyst 短重试成功后流水线应继续');
    assert.deepEqual(r.shortPromptRetries, ['analyst']);
    assert.equal(fh.calls.length, 4, 'analyst 失败只应多一次短重试');
    assert.ok(userOf(fh.calls[1]).length < userOf(fh.calls[0]).length * 0.5, '短 analyst prompt 必须显著更短');
    assert.ok(userOf(fh.calls[1]).includes('"vulns"'), '短 prompt 仍须要求 JSON 的 vulns 字段');
    assert.ok(userOf(fh.calls[1]).includes('overall_risk'), '短 prompt 仍须要求 overall_risk（否则 validateAnalysisJson 降级）');
    assert.ok(userOf(fh.calls[1]).includes('id'), '短 prompt 仍保留注入参数等事实');
    assert.equal(fh.calls[1].url, fh.calls[0].url, '短重试复用同一端点，不借重试换网关');
    assert.equal(JSON.parse(fh.calls[1].opts.body).model, 'deepseek-v4-flash', '短重试复用同一角色模型');
  } finally { fh.restore(); }
});

test('[D258] analyst 短重试也失败 → 降级到 writer 角色，降级同样带短重试', async () => {
  const g = await fresh('analyst-fallback');
  const fh = installFetch(async (i) => {
    if (i === 1 || i === 2) return empty();  // analyst 首轮 + 短重试全空
    if (i === 3) return ok(ANALYSIS);        // 降级到 writer 角色（长 prompt）成功
    if (i === 4) return ok('DRAFT');
    return ok('FINAL');
  });
  try {
    const r = await g.generateAiReport(baseReport('sr-analyst-fallback'));
    assert.equal(modelBody(r.content), 'FINAL');
    assert.deepEqual(r.shortPromptRetries, [], '未产出内容的重试不得计入「生效重试」');
    assert.equal(fh.calls.length, 5);
    assert.equal(JSON.parse(fh.calls[2].opts.body).model, 'glm-5.2', '第二级降级应换到 writer 模型');
  } finally { fh.restore(); }
});

test('[D258] 三级 analyst 全失败（含短重试）→ 如实报「分析角色全挂」', async () => {
  const g = await fresh('analyst-allfail');
  const fh = installFetch(async () => empty());
  try {
    await assert.rejects(
      () => g.generateAiReport(baseReport('sr-analyst-allfail')),
      /漏洞分析角色全部失败（analyst→writer→reviewer 三轮降级均失败）/
    );
    assert.equal(fh.calls.length, 6, '三级 × (首轮 + 短重试) = 6 次，且不得伪造报告');
  } finally { fh.restore(); }
});

test('[D258] AI_REPORT_SHORT_RETRY=0：analyst 不重试，直接走原有角色降级', async () => {
  const fh = installFetch(async (i) => {
    if (i === 1) return empty();       // analyst 空
    if (i === 2) return ok(ANALYSIS);  // 直接降级到 writer 角色（非短重试）
    return ok('BODY');
  });
  try {
    const r = await genOff.generateAiReport(baseReport('sr-analyst-off'));
    assert.equal(modelBody(r.content), 'BODY');
    assert.deepEqual(r.shortPromptRetries, []);
    assert.equal(fh.calls.length, 4, 'analyst 空 → writer 角色 → writer 撰写 → reviewer');
    assert.equal(JSON.parse(fh.calls[1].opts.body).model, 'glm-5.2', '关闭短重试后走原降级，不是同角色短重试');
  } finally { fh.restore(); }
});

test('[D255] writer 空内容 → 短 prompt 重试：请求真的变短、内容来自重试、如实披露', async () => {
  const g = await fresh('writer');
  const fh = installFetch(async (i) => {
    if (i === 1) return ok(ANALYSIS);
    if (i === 2) return empty();       // writer 首轮空
    if (i === 3) return ok('SHORT-DRAFT'); // writer 短重试
    return ok('FINAL');                // reviewer
  });
  try {
    const r = await g.generateAiReport(baseReport('sr-writer'));
    assert.equal(modelBody(r.content), 'FINAL');
    assert.deepEqual(r.shortPromptRetries, ['writer']);
    assert.equal(fh.calls.length, 4, 'writer 失败应只多一次短重试');
    assert.ok(userOf(fh.calls[2]).length < userOf(fh.calls[1]).length * 0.5, '短 prompt 必须显著短于原 prompt');
    assert.ok(systemOf(fh.calls[2]).length < systemOf(fh.calls[1]).length, '短 system prompt 也要更短');
    assert.ok(userOf(fh.calls[2]).includes('id'), '短 prompt 仍保留注入参数等事实，不是空泛元指令');
    assert.equal(fh.calls[2].url, fh.calls[1].url, '复用同一端点，不借重试偷偷换网关');
  } finally { fh.restore(); }
});

test('[D255] reviewer 空内容 → 短 prompt 重试成功才标已审阅', async () => {
  const g = await fresh('reviewer');
  const fh = installFetch(async (i) => {
    if (i === 1) return ok(ANALYSIS);
    if (i === 2) return ok('DRAFT');
    if (i === 3) return empty();     // reviewer 首轮空
    return ok('FINAL');              // reviewer 短重试
  });
  try {
    const r = await g.generateAiReport(baseReport('sr-reviewer'));
    assert.equal(modelBody(r.content), 'FINAL');
    assert.ok(r.reviewNote.includes('已经过安全审阅'));
    assert.deepEqual(r.shortPromptRetries, ['reviewer']);
    assert.ok(userOf(fh.calls[3]).length < userOf(fh.calls[2]).length * 0.8, 'reviewer 短 prompt 截断 draft');
    assert.ok(userOf(fh.calls[3]).includes('报告节选'), '短审阅明确标注是节选，不冒充全文审阅');
  } finally { fh.restore(); }
});

test('[D255] 超时也触发短重试；重试成功清掉首轮冷却，后续角色不被误挡', async () => {
  const g = await fresh('timeout');
  const fh = installFetch(async (i) => {
    if (i === 1) return ok(ANALYSIS);
    if (i === 2) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
    if (i === 3) return ok('SHORT-DRAFT');
    return ok('FINAL');
  });
  try {
    const r = await g.generateAiReport(baseReport('sr-timeout'));
    assert.deepEqual(r.shortPromptRetries, ['writer']);
    assert.equal(modelBody(r.content), 'FINAL', '单 key 冷却被清除后 reviewer 仍能跑完');
    assert.equal(fh.calls.length, 4);
  } finally { fh.restore(); }
});

test('[D255] 短重试也返回空 → 保持原降级文案，不伪造成功', async () => {
  const g = await fresh('bothfail');
  const fh = installFetch(async (i) => {
    if (i === 1) return ok(ANALYSIS);
    return empty(); // writer 首轮/短重试、reviewer 首轮/短重试全空
  });
  try {
    const r = await g.generateAiReport(baseReport('sr-bothfail'));
    assert.ok(r.content.includes('报告撰写角色暂不可用'));
    assert.ok(!r.reviewNote.includes('已经过安全审阅'));
    assert.deepEqual(r.shortPromptRetries, [], '未产出内容的重试不得计入「生效重试」');
    assert.equal(fh.calls.length, 5, 'analyst 1 + writer 2 + reviewer 2');
  } finally { fh.restore(); }
});

test('[D255] 429 不触发短重试（配额问题交给原有 key 降级）', async () => {
  const g = await fresh('r429');
  const fh = installFetch(async (i) => {
    if (i === 1) return ok(ANALYSIS);
    return limited();
  });
  try {
    const r = await g.generateAiReport(baseReport('sr-429'));
    assert.ok(r.content.includes('报告撰写角色暂不可用'));
    assert.deepEqual(r.shortPromptRetries, []);
    assert.equal(fh.calls.length, 3, 'analyst + writer 1 次 + reviewer 1 次，无短重试');
  } finally { fh.restore(); }
});

test('[D255] AI_REPORT_SHORT_RETRY=0 关闭后空响应不重试，行为与变更前一致', async () => {
  const fh = installFetch(async (i) => (i === 1 ? ok(ANALYSIS) : ok('BODY')));
  try {
    const r = await genOff.generateAiReport(baseReport('sr-off'));
    assert.equal(fh.calls.length, 3, '关闭时仍是 3 次调用');
    assert.deepEqual(r.shortPromptRetries, []);
  } finally { fh.restore(); }
});

test('[D255] 生效的短重试写进 ai-report.json；未发生重试时元数据结构零变化', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sr-meta-'));
  try {
    const report = baseReport('sr-meta');
    const a = writeAiReportFiles(join(dir, 'on'), { content: 'BODY', reviewNote: 'ok', shortPromptRetries: ['writer'] }, report, {});
    const b = writeAiReportFiles(join(dir, 'off'), { content: 'BODY', reviewNote: 'ok' }, report, {});
    assert.ok(statSync(a.metaFile).isFile() && statSync(b.metaFile).isFile());
    assert.deepEqual(JSON.parse(readFileSync(a.metaFile, 'utf-8')).shortPromptRetries, ['writer']);
    assert.equal(JSON.parse(readFileSync(b.metaFile, 'utf-8')).shortPromptRetries, undefined);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
