// ============================================================================
// wafRealSamples.guard.test.js —— 商业云 WAF 真机样本「有牙」守卫（P0-1）
//
// 为什么必须有：台账 `waf-fingerprint-coverage` 的剩余缺口是「真机样本只有 ModSecurity
// 1/62」（D89 的 18/18 是 wafw00f 规则**构造样本**，证明「同一份厂商特征我们认得」，
// 不证明「真机必然命中」）。本守卫把「补真机样本」变成可测状态机：
//
//   空快照（当前）→ 每个测试显式 SKIP 并打印待采集提示（不许假绿、不许当通过）；
//   非空快照    → 逐条断言「用样本特征构造的响应能被识别为样本标称厂商」+ 零误报反向
//                  + 变异自证（删掉该厂商 rules 必须识别不出 → 判据有牙，不是恒绿）。
//
// 判据约定（与 docs/WAF-真机样本采集-runbook.md 同一份口径，改任一侧必须同步另一侧）：
//   · 样本 schema：{ ours, kind:'header', key, value, sourceRule:'real-capture',
//                    capturedAt, target?, status?, evidence? }
//   · 采集只能来自**授权目标真实响应**（收集器 cloud-sample-collector.mjs 只发良性 GET，
//     不发任何攻击 payload；拦截页形态由用户在授权目标上自行触发后 --from-json 导入）；
//   · 空快照时 guards 不绿——no green on empty（防「没人采集也显示通过」的假闭环）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

import { WafIdentifier } from '../src/core/waf/WafIdentifier.js';
import { WAF_RULES } from '../src/core/waf/wafRules.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, 'fixtures/waf-real-samples.json');
const COLLECTOR = resolve(here, '../../e2e/waf-real/cloud-sample-collector.mjs');

// —— 0) 结构守卫：快照与收集器「单一来源」不漂移（防收集器写 A、守卫读 B 的假接线） ——
test('真机快照存在且 schema 合法；收集器写入路径与守卫读取路径同一份', () => {
  assert.ok(existsSync(FIXTURE), 'fixtures/waf-real-samples.json 缺失 —— 收集器与之配套，删了要同步删本守卫');
  const snap = JSON.parse(readFileSync(FIXTURE, 'utf8'));
  assert.ok(Array.isArray(snap.samples), '快照 samples 必须是数组');
  assert.ok(snap._source && snap._source.includes('真实'), '快照 _source 未按 runbook 标注「真实响应」来源');
  for (const s of snap.samples) {
    assert.equal(s.sourceRule, 'real-capture', `样本 ${s.ours} 必须是 real-capture（构造样本不许混入，进了就失去真机证言）`);
    assert.ok(typeof s.ours === 'string' && s.ours.length > 0, '样本缺 ours');
    assert.ok(s.kind === 'header' || s.kind === 'body' || s.kind === 'status', `样本 ${s.ours} kind 非法`);
    if (s.kind === 'header') {
      assert.ok(typeof s.key === 'string' && s.key.length > 0, `样本 ${s.ours} 缺 header key`);
      assert.ok(typeof s.value === 'string', `样本 ${s.ours} 缺 header value`);
    }
    assert.ok(typeof s.capturedAt === 'string' && s.capturedAt.length > 0, `样本 ${s.ours} 缺 capturedAt（采集时间戳）`);
  }
  // 收集器 SNAPSHOT 常量必须指向本守卫读的文件（文本判据：源码改动会使路径漂移，判据会红）
  const collectorSrc = readFileSync(COLLECTOR, 'utf8');
  assert.ok(
    /SNAPSHOT\s*=\s*resolve\(here, '\.\.\/\.\.\/server\/tests\/fixtures\/waf-real-samples\.json'\)/.test(collectorSrc),
    '收集器 SNAPSHOT 路径与守卫不一致 —— 两边写/读不同文件会让「采集了但守卫看不见」'
  );
});

// —— 1) 判据有牙自证：即使 fast 收集器缺依赖，WafIdentifier 对已知信息必须可识别 ——
test('WafIdentifier 可加载且 identify 返回候选（判据自身能跑，不是空转）', () => {
  const id = new WafIdentifier();
  const out = id.identify({ status: 200, headers: { 'cf-ray': 'abc123' }, body: '' });
  assert.ok(Array.isArray(out));
  assert.ok(out.length >= 1 && out[0].vendor === 'Cloudflare', '构造 cf-ray 响应应识别 Cloudflare —— 识别器本身坏了则本守卫全部失去意义');
});

// —— 主判据：基于快照状态分叉 ——
const snap = JSON.parse(readFileSync(FIXTURE, 'utf8'));
const samples = snap.samples || [];
const EMPTY = samples.length === 0;

if (EMPTY) {
  // 空快照：显式 SKIP（not pass）——台账维持 unverified 的机器可见证据。
  // 不要用 test.skip 静默跳过：要让 reporter 显示「被跳过 N 个」，而不是「PASS 0」。
  test('真机样本非空（当前为空 → 显式 SKIP，台账维持 unverified）', { skip: true }, () => {
    assert.fail('快照为空不该走到这里');
  });
  test('真机样本非空 —— 反向确认', { skip: true }, () => {});
  console.error('[wafRealSamples.guard] ⚠️ 真机样本为空：P0-1 待采集（无授权目标）。');
  console.error('[wafRealSamples.guard]    台账 waf-fingerprint-coverage 维持 unverified，本守卫拒绝假装通过。');
  console.error('[wafRealSamples.guard]    采集方法见 docs/WAF-真机样本采集-runbook.md（仅授权目标，良性 GET，禁攻击载荷）。');
} else {
  // —— 2) 正向：每条样本的特征必须被识别为样本标称厂商 ——
  test('每条真机样本都能被识别为标称厂商', () => {
    const id = new WafIdentifier();
    for (const s of samples) {
      const resp = buildResp(s);
      const cands = id.identify(resp);
      const hit = cands.find((c) => c.vendor === s.ours);
      assert.ok(hit, `样本 ${s.ours}（${describe(s)}）未能识别 —— 规则缺失或样本失真`);
      assert.ok(hit.confidence >= 0.6, `样本 ${s.ours} 置信度 ${hit.confidence} 过低`);
    }
  });

  // —— 3) 零误报反向：无该特征时的干净响应不得识别为该厂商 ——
  test('去掉样本特征后不得再识别为标称厂商（零误报反向）', () => {
    const id = new WafIdentifier();
    for (const s of samples) {
      const clean = cleanResp(s);
      const cands = id.identify(clean);
      const hit = cands.find((c) => c.vendor === s.ours);
      assert.ok(!hit, `干净响应被误识别为 ${s.ours}（样本 ${describe(s)}）—— matcher 过宽或样本失真`);
    }
  });

  // —— 4) 变异自证：删掉该厂商 rules 后必须识别不出（判据有牙，防「恒绿守卫」） ——
  test('变异自证：移除厂商规则后样本不再命中（判据有牙）', () => {
    const base = new WafIdentifier(WAF_RULES);
    for (const s of samples) {
      if (!WAF_RULES[s.ours]) continue; // 厂商不在内置规则（跑分自定义）→ 跳过变异
      // 深拷贝 rules 并删除该厂商 → 应识别不出
      const mutated = structuredClone(WAF_RULES);
      delete mutated[s.ours];
      const id = new WafIdentifier(mutated);
      const hit = id.identify(buildResp(s)).find((c) => c.vendor === s.ours);
      assert.ok(!hit, `删除 ${s.ours} 规则后仍能识别 —— 样本 ${describe(s)} 命中了他家规则（串台），或变异不生效`);
      // 反向：保留 rules 时命中（对照）
      assert.ok(base.identify(buildResp(s)).some((c) => c.vendor === s.ours), '对照失败：原规则应命中');
    }
  });

  // —— 5) 数量护栏：样本非空且每家至少一条（防只有一条充数） ——
  test('真机样本覆盖多家厂商且数量不缩水', () => {
    const vendors = new Set(samples.map((s) => s.ours));
    assert.ok(vendors.size >= 3, `真机样本只覆盖 ${vendors.size} 家（期望 ≥3）—— 单家样本不足以支撑「商业云真机」声明`);
    const dup = samples.length !== new Set(samples.map((s) => `${s.ours}:${s.key}:${s.value}`)).size;
    assert.ok(!dup, '快照存在重复样本 —— 去重后重跑收集器（收集器已有 dedup 逻辑）');
  });
}

// —— helpers ——
function buildResp(s) {
  if (s.kind === 'header') return { status: s.status ?? 200, headers: { [s.key.toLowerCase()]: s.value }, body: '' };
  if (s.kind === 'body') return { status: s.status ?? 200, headers: {}, body: s.value ?? '' };
  return { status: Number(s.value) || 403, headers: {}, body: '' };
}

function cleanResp(s) {
  const r = buildResp(s);
  if (s.kind === 'header') {
    // 保留除该 key 外的其它头（若快照一条记录只有单个 key，产物即空 headers）
    r.headers = {};
    r.status = 200;
    r.body = '<html><body>index</body></html>'; // 干净正文：任意普通页面
  }
  return r;
}

function describe(s) {
  return s.kind === 'header' ? `${s.key}: ${String(s.value).slice(0, 40)}` : (s.kind === 'body' ? `body~${String(s.value).slice(0, 40)}` : `status=${s.value}`);
}