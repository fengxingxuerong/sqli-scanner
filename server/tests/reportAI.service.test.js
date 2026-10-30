// ReportAI 服务单测（零覆盖补测）：key 容灾降级 / 缓存命中与容量淘汰 / prompt URL 脱敏
// 注意：API_KEYS 在模块加载期读取 env，故用查询串导入获取相互隔离的模块实例。
import { test } from 'node:test';
import assert from 'node:assert/strict';

for (const k of ['AI_REPORT_KEY_1', 'AI_REPORT_KEY_2', 'AI_REPORT_KEY_3']) delete process.env[k];

// ── fetch 打桩（拦截全局 fetch，不发真实网络请求）─────────────────────────
function installFetch(handler) {
  const orig = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, opts) => {
    calls.push({ url, opts });
    return handler(calls.length, url, opts);
  };
  return { calls, restore() { globalThis.fetch = orig; } };
}

function baseReport(scanId = 's1') {
  return {
    scanId,
    target: { baseUrl: 'https://example.com/secret/login' },
    dbms: 'MySQL',
    startedAt: '2026-01-01T00:00:00Z',
    vulns: [{ technique: 'boolean', dbms: 'MySQL', riskLevel: 'High', description: 'd', evidence: 'e' }],
  };
}

// 实例 A：无任何 key 无 base
const genNoKey = await import('../src/services/ReportAI.js?nokey');
// 实例 C：2 个 key 但未设置 AI_REPORT_API_BASE（外发 opt-in 拒绝路径；必须在设置 base 之前导入）
process.env.AI_REPORT_KEY_1 = 'test-key-1';
process.env.AI_REPORT_KEY_2 = 'test-key-2';
const genKeyNoBase = await import('../src/services/ReportAI.js?keynobase');
// 实例 B：2 个 key + 显式 AI_REPORT_API_BASE（外发 opt-in 已启用；主实例）
process.env.AI_REPORT_API_BASE = 'http://127.0.0.1:9/v1/chat/completions';
const gen = await import('../src/services/ReportAI.js?k2');
// 实例 D：AI_REPORT_MODEL_1..3 覆盖角色模型（[D192] 本地网关 provider/model 全名场景）
process.env.AI_REPORT_MODEL_1 = 'deepseek-auto/deepseek-v4-flash';
process.env.AI_REPORT_MODEL_2 = 'deepseek-auto/glm-5.2';
process.env.AI_REPORT_MODEL_3 = 'raccoon/sn-sensenova-6-8-flash-lite';
const genEnvModels = await import('../src/services/ReportAI.js?envmodels');
delete process.env.AI_REPORT_MODEL_1;
delete process.env.AI_REPORT_MODEL_2;
delete process.env.AI_REPORT_MODEL_3;

test('listAiConfigs：返回 3 个角色且字段齐全', () => {
  const cfgs = gen.listAiConfigs();
  assert.equal(cfgs.length, 3);
  assert.deepEqual(cfgs.map((c) => c.role), ['analyst', 'writer', 'reviewer']);
  for (const c of cfgs) {
    assert.ok(c.model && c.desc && c.label);
  }
});

test('[D192] AI_REPORT_MODEL_1..3 覆盖角色模型：默认名不变，覆盖后请求体带全名', async () => {
  // 不设 env 的主实例仍是默认裸名
  assert.deepEqual(
    gen.listAiConfigs().map((c) => c.model),
    ['deepseek-v4-flash', 'glm-5.2', 'sensenova-6.8-flash-lite'],
  );
  // 覆盖实例：configs 回显覆盖值
  assert.deepEqual(
    genEnvModels.listAiConfigs().map((c) => c.model),
    ['deepseek-auto/deepseek-v4-flash', 'deepseek-auto/glm-5.2', 'raccoon/sn-sensenova-6-8-flash-lite'],
  );
  // 覆盖实例真实发出的请求体带覆盖后的模型名
  const fh = installFetch(async () => ({
    ok: true, status: 200,
    json: async () => ({ choices: [{ message: { content: 'OUT' } }] }),
  }));
  try {
    const r = await genEnvModels.generateAiReport(baseReport('envm-1'));
    assert.equal(r.success, true);
    assert.equal(JSON.parse(fh.calls[0].opts.body).model, 'deepseek-auto/deepseek-v4-flash');
    assert.equal(r.model, 'deepseek-auto/deepseek-v4-flash→deepseek-auto/glm-5.2→raccoon/sn-sensenova-6-8-flash-lite');
  } finally { fh.restore(); }
});

test('未配置任何 key：generateAiReport 明确报错不崩溃', async () => {
  await assert.rejects(() => genNoKey.generateAiReport(baseReport()), /AI 报告功能未配置/);
});

test('有 key 未设置 AI_REPORT_API_BASE：拒绝默认外发并明确报错', async () => {
  await assert.rejects(() => genKeyNoBase.generateAiReport(baseReport()), /AI_REPORT_API_BASE/);
});

test('isAiReportEnabled：仅 key 无 base 为 false，key+base 为 true', () => {
  assert.equal(genKeyNoBase.isAiReportEnabled(), false); // 有 key 无 base → 未启用
  assert.equal(gen.isAiReportEnabled(), true); // 主实例有 key 且测试文件已设 base → 启用
});

test('三角色流水线成功：3 次 LLM 调用、按角色选 key/model、URL 打码进 prompt', async () => {
  const fh = installFetch(async () => ({
    ok: true, status: 200,
    json: async () => ({ choices: [{ message: { content: 'OUT' } }] }),
  }));
  try {
    const r = await gen.generateAiReport(baseReport());
    assert.equal(r.success, true);
    assert.equal(r.cached, undefined);
    assert.equal(fh.calls.length, 3);
    assert.ok(r.reviewNote.includes('已经过安全审阅'));
    // 步骤 1：analyst → key1/deepseek；步骤 2：writer → key2/glm；步骤 3：reviewer → 回落可用 key
    assert.equal(fh.calls[0].opts.headers.Authorization, 'Bearer test-key-1');
    assert.equal(JSON.parse(fh.calls[0].opts.body).model, 'deepseek-v4-flash');
    assert.equal(fh.calls[1].opts.headers.Authorization, 'Bearer test-key-2');
    assert.equal(JSON.parse(fh.calls[1].opts.body).model, 'glm-5.2');
    // 脱敏：prompt 只含 host+***，不含路径
    const user0 = JSON.parse(fh.calls[0].opts.body).messages[1].content;
    assert.ok(user0.includes('example.com/***'));
    assert.ok(!user0.includes('/secret/login'));
  } finally { fh.restore(); }
});

test('缓存命中：同报告二次调用不再发起 LLM 请求', async () => {
  const fh = installFetch(async () => ({
    ok: true, status: 200,
    json: async () => ({ choices: [{ message: { content: 'C' } }] }),
  }));
  try {
    const r1 = await gen.generateAiReport(baseReport('cache-1'));
    assert.equal(r1.cached, undefined);
    const n = fh.calls.length;
    const r2 = await gen.generateAiReport(baseReport('cache-1'));
    assert.equal(r2.cached, true);
    assert.equal(fh.calls.length, n);
  } finally { fh.restore(); }
});

test('429 触发冷却并自动降级到备用 key，扫描不失败', async () => {
  const g = await import('../src/services/ReportAI.js?failover'); // 独立实例（独立 keyHealth）
  const seenAuth = [];
  const fh = installFetch(async (i, url, opts) => {
    seenAuth.push(opts.headers.Authorization);
    if (i === 1) return { ok: false, status: 429, json: async () => ({}), text: async () => 'rate limited' };
    return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: 'OK' } }] }) };
  });
  try {
    const r = await g.generateAiReport(baseReport('s9'));
    assert.equal(r.success, true);
    assert.equal(seenAuth[0], 'Bearer test-key-1'); // 首选角色 key
    assert.ok(seenAuth.slice(1).includes('Bearer test-key-2')); // 降级到备用 key
  } finally { fh.restore(); }
});

test('缓存容量上限 100：最旧条目被淘汰后重新生成', async () => {
  const g = await import('../src/services/ReportAI.js?evict'); // 独立实例（独立 reportCache）
  const fh = installFetch(async () => ({
    ok: true, status: 200,
    json: async () => ({ choices: [{ message: { content: 'X' } }] }),
  }));
  try {
    for (let i = 0; i < 102; i++) await g.generateAiReport(baseReport(`bulk-${i}`));
    const before = fh.calls.length;
    await g.generateAiReport(baseReport('bulk-0')); // 最旧的 bulk-0 应已被挤出 → 需重新调 LLM
    assert.ok(fh.calls.length > before);
  } finally { fh.restore(); }
});

// ── [D205] 空响应不算成功（10-30 实测缺陷：reviewer 返回空 content 仍标「✅ 已审阅」，正文 0B）──
test('[D205] reviewer 返回空内容 ≠ 审阅通过：正文回退到撰写稿并如实标注', async () => {
  const g = await import('../src/services/ReportAI.js?emptyreview'); // 独立实例（独立 keyHealth/cache）
  const fh = installFetch(async (i) => ({
    ok: true,
    status: 200,
    json: async () => ({
      choices: [{ message: { content: i === 3 ? '' : `BODY-${i}` }, finish_reason: i === 3 ? 'length' : 'stop' }],
    }),
  }));
  try {
    const r = await g.generateAiReport(baseReport('empty-review'));
    assert.equal(r.success, true);
    assert.ok(!r.reviewNote.includes('已经过安全审阅'), '空返回不能被标成已审阅');
    assert.equal(r.content, 'BODY-2', '正文应回退到 writer 的产出，而不是空串');
  } finally { fh.restore(); }
});

test('[D205] 三角色全返回空 → 报错，不产出空报告', async () => {
  const g = await import('../src/services/ReportAI.js?allempty');
  const fh = installFetch(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ choices: [{ message: { content: '' }, finish_reason: 'length' }] }),
  }));
  try {
    // 三次空响应会把三个 key 依次标冷却，最终可能是「空内容」或「无可用 key」——
    // 两种都必须 reject（关键判据是**不产出空报告**，不是报哪句话）
    await assert.rejects(() => g.generateAiReport(baseReport('all-empty')), /空内容|AI 报告为空|无可用 key/);
  } finally { fh.restore(); }
});
