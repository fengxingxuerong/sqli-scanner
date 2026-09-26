// finalize.report.test.js —— 扫描收尾（engine/scan/finalize.js）专属单测
// ============================================================================
// 为什么补这一份：finalize.js 188 行、**此前零测试挂载**（branch 覆盖仅 48%）。
// 它是交付物的「最后一道」——报告里写什么、怎么定级、怎么标注，全在这里收敛。
// 未覆盖的恰好是几条 P0/P1 修复后的判据：
//   · blockPolicy 自相矛盾校正（自适应重跑了却写「无拦截证据」）
//   · validity=blocked 时不得对外声称无拦截
//   · byRisk / byTechnique 计数（曾恒为 null，机读清单拿不到风险分布）
//   · scan_completed 事件脱敏（SSE 不得带 target 凭据）
//   · 会话落盘必须先于 status=completed（否则 resume 读到半成品）
// 这些改坏都不会报错，只会让交付报告变得自相矛盾或泄密 —— 必须有断言盯着。
//
// 手法：stub 只替掉外部依赖（sm / guard / validity / session），
// 报告本体的汇总函数（countBy / attachVulnContext / summarizeSkipped / publicReport
// / dbmsEvidenceOf）全部走**真实实现**，断言落在 report 与 SSE 事件上。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finalizeReport } from '../src/engine/scan/finalize.js';
import { createVulnerability } from '../src/engine/models.js';
import * as eventBus from '../src/core/eventBus.js';

let uid = 0;
const nextScanId = () => `finalize-${++uid}`;

function build(o = {}) {
  const scanId = nextScanId();
  const events = [];
  const em = eventBus.create(scanId);
  em.on('event', (e) => events.push(e));

  const calls = [];
  const order = [];

  const sm = {
    _hasData: () => o.hasData ?? false,
    reportGen: { riskOf: () => o.risk ?? 'Low' },
    _mergeExtractedForResume: (cur, old) => { calls.push('_mergeExtractedForResume'); return o.merged ?? { ...(cur || {}), ...(old || {}) }; },
    wafRecommend: () => o.suggestions ?? [],
    async _maybeClose(c) { calls.push('_maybeClose'); if (c) calls.push(`_maybeClose:${c.__tag ?? 'client'}`); },
    _retire(id) { calls.push(`_retire:${id}`); },
  };

  const session = o.session === null ? null : {
    setExtracted: async (d) => { order.push('setExtracted'); if (o.setExtractedThrows) throw new Error('磁盘满'); calls.push(`setExtracted:${JSON.stringify(d)?.slice(0, 20)}`); },
    finalize: async (r) => { order.push('finalize'); calls.push(`finalize:${(r.vulns || []).length}`); },
    ...(o.session || {}),
  };

  const s = { status: 'running' };
  const report = {
    vulns: [],
    summary: {},
    points: o.points || [],
    // 凭据只放 publicTarget 真实会剥离的那几处（config.auth/proxy、cookieParams、
    // headerParams、db.connectionString）—— 断言「不存在的字段会被脱敏」等于测了个空气
    target: o.target ?? {
      url: 'http://127.0.0.1:8080/',
      config: { ...(o.targetConfig || {}), auth: { username: 'root', password: 'p@ssw0rd' }, proxy: 'http://user:pw@127.0.0.1:8080' },
      cookieParams: { PHPSESSID: 'secretcookie' },
      headerParams: { 'X-Api-Key': 'secretkey' },
      db: { connectionString: 'mysql://root:pw@127.0.0.1/appdb' },
    },
    ...(o.report || {}),
  };

  const run = {
    sm,
    scanId,
    s,
    target: report.target,
    report,
    finalVulns: o.finalVulns ?? [],
    extracted: o.extracted ?? { databases: [], tables: {}, columns: {}, rows: {} },
    restored: o.restored ?? null,
    session,
    points: o.points ?? [],
    pointsToScan: o.pointsToScan ?? [],
    fullyTestedPoints: o.fullyTestedPoints ?? new Set(),
    stackedSelected: o.stackedSelected ?? false,
    corroborations: o.corroborations ?? 0,
    oobUnavailable: o.oobUnavailable ?? null,
    dbms: o.dbms ?? 'MySQL',
    guard: { fatalHits: 3, _abortLogged: false, summary: () => o.health ?? null },
    wafAgg: o.wafAgg ?? new Map(),
    blockPolicy: o.blockPolicy ?? { action: 'none', reason: 'x', tamperHint: [], backoffMs: null },
    blockAdaptiveInfo: o.blockAdaptiveInfo ?? null,
    validity: { summary: () => o.validitySummary ?? { status: 'ok' } },
    ctxBase: { httpClient: { __tag: 'hc' } },
    applyValidity: (r, arg) => { calls.push('applyValidity'); r.summary.validity = o.appliedValidity ?? { status: 'ok' }; if (arg) calls.push(`applyValidity:${arg.points.length}`); },
  };

  return {
    run, report, scanId, events, calls, order, s,
    byType: (t) => events.filter((e) => e.type === t),
    done: () => eventBus.dispose(scanId),
  };
}

// ① resume 合并历史命中（按 pointId+technique 去重，不重复计数）
test('① resume：历史会话命中合并进报告，同点同技术不重复（否则风险分布被放大）', async () => {
  const h = build({
    finalVulns: [createVulnerability('p1', 'union', 'High', [], '本轮命中')],
    restored: { vulns: [{ pointId: 'p1', technique: 'union' }, { pointId: 'p2', technique: 'boolean' }] },
  });
  try {
    await finalizeReport(h.run);
    const tech = h.report.vulns.map((v) => `${v.pointId}:${v.technique}`).sort();
    assert.deepEqual(tech, ['p1:union', 'p2:boolean'], 'p1:union 本轮已有，不得重复计入');
  } finally { h.done(); }
});

// ② 提取数据：开关 / resume 合并 / 落盘失败不阻断
test('② enableExtract 关闭时 report.data 为 null（不产出半截提取数据）', async () => {
  const h = build({ targetConfig: { enableExtract: false }, extracted: { databases: ['appdb'] } });
  try {
    await finalizeReport(h.run);
    assert.equal(h.report.data, null);
  } finally { h.done(); }
});

test('③ resume：历史提取数据合并回报告（拖库断点续跑不丢已拉数据）', async () => {
  const h = build({
    targetConfig: { enableExtract: true },
    restored: { vulns: [], extracted: { databases: ['old'] } },
  });
  try {
    await finalizeReport(h.run);
    assert.ok(h.calls.includes('_mergeExtractedForResume'), '必须走合并通道');
    assert.deepEqual(h.report.data.databases, ['old']);
  } finally { h.done(); }
});

test('④ 会话落盘失败不阻断收尾（落盘是尽力而为，不能让扫描失败）', async () => {
  const h = build({ setExtractedThrows: true });
  try {
    await finalizeReport(h.run);
    assert.equal(h.s.status, 'completed', '落盘失败也必须正常收尾');
    assert.equal(h.byType('scan_completed').length, 1);
  } finally { h.done(); }
});

// ⑤ 定级：有数据 = Critical（数据已出 = 最严重），否则按漏洞定级
test('⑤ 定级：提取到数据即 Critical，否则用漏洞定级结果', async () => {
  const a = build({ hasData: true, risk: 'Low' });
  const b = build({ hasData: false, risk: 'Medium' });
  try {
    await finalizeReport(a.run);
    await finalizeReport(b.run);
    assert.equal(a.report.riskLevel, 'Critical', '数据已被拖出 = 最严重，不能按漏洞数量降级');
    assert.equal(b.report.riskLevel, 'Medium');
  } finally { a.done(); b.done(); }
});

// ⑥ 跳过点汇总 + OOB 不可用标注：报告必须回答「有多少点没测」
test('⑥ 跳过点汇总进 summary（「没测」不能长得像「测了没漏洞」）', async () => {
  const h = build({ points: [{ id: 'p1', skipReason: 'static' }, { id: 'p2', skipReason: 'static' }, { id: 'p3' }] });
  try {
    await finalizeReport(h.run);
    assert.deepEqual(h.report.summary.skippedPoints, { total: 2, byReason: { static: 2 } });
  } finally { h.done(); }
});

test('⑦ OOB 接收端不可用必须写进 summary（否则「无带外」被读成「无漏洞」）', async () => {
  const h = build({ oobUnavailable: '端口被占用' });
  try {
    await finalizeReport(h.run);
    assert.deepEqual(h.report.summary.oobUnavailable, { reason: '端口被占用' });
  } finally { h.done(); }
});

// ⑧ db-guard 熔断：落报告 + 补发 abort 事件（且只播报一次）
test('⑧ 库健康状态落报告 + aborted 时补发 db_health_abort（只播报一次）', async () => {
  const h = build({ health: { aborted: true, fatalId: 'db-down', fatalHits: 3 } });
  try {
    await finalizeReport(h.run);
    assert.equal(h.report.dbHealth.aborted, true);
    assert.deepEqual(h.report.summary.dbHealth, { aborted: true, fatalId: 'db-down', fatalHits: 3 });
    assert.equal(h.byType('db_health_abort').length, 1, '补发也必须去抖，不能重复播报');
  } finally { h.done(); }
});

test('⑧ 反向：未熔断时不得出现 db_health_abort 事件（避免误报「目标已被打坏」）', async () => {
  const h = build({ health: { aborted: false, fatalHits: 0 } });
  try {
    await finalizeReport(h.run);
    assert.equal(h.byType('db_health_abort').length, 0);
    assert.equal(h.report.dbHealth.aborted, false);
  } finally { h.done(); }
});

// ⑨ WAF 指纹：事件 + 摘要
test('⑨ 识别到 WAF：发 waf_detected 事件并把厂商写进 summary', async () => {
  const h = build({
    wafAgg: new Map([['cloudflare', { vendor: 'cloudflare', confidence: 0.9 }]]),
    suggestions: [{ vendor: 'cloudflare', plugins: ['randomcase'] }],
  });
  try {
    await finalizeReport(h.run);
    const ev = h.byType('waf_detected');
    assert.equal(ev.length, 1);
    assert.deepEqual(ev[0].payload.suggestions, [{ vendor: 'cloudflare', plugins: ['randomcase'] }]);
    assert.equal(h.report.summary.wafDetected[0].vendor, 'cloudflare');
  } finally { h.done(); }
});

test('⑨ 反向：无 WAF 时不得发 waf_detected（零额外发包的识别不该刷事件）', async () => {
  const h = build();
  try {
    await finalizeReport(h.run);
    assert.equal(h.byType('waf_detected').length, 0);
  } finally { h.done(); }
});

// ⑩ 一致性校正：blockPolicy 与自适应重跑不得自相矛盾（P0-FIX）
test('⑩ blockPolicy 校正：已自适应重跑却仍写 action=none 时，必须改成实际动作', async () => {
  const h = build({
    blockPolicy: { action: 'none', reason: '无拦截证据', tamperHint: [], backoffMs: null },
    blockAdaptiveInfo: { triggered: true, blockHits: 8, chains: [['symboliclogical']] },
  });
  try {
    await finalizeReport(h.run);
    assert.equal(h.report.summary.blockPolicy.action, 'adaptiveTamper',
      '重跑都跑了却对外说「无拦截证据」= 自相矛盾的交付物');
    assert.match(h.report.summary.blockPolicy.reason, /blockHits=8/);
    assert.deepEqual(h.report.summary.blockPolicy.tamperHint, ['symboliclogical']);
    assert.equal(h.report.summary.wafAdaptive.triggered, true);
  } finally { h.done(); }
});

test('⑩ filterBypass 形态：mode 决定 action（不是一律 adaptiveTamper）', async () => {
  const h = build({
    blockPolicy: { action: 'none', reason: '无拦截证据' },
    blockAdaptiveInfo: { triggered: true, mode: 'filterBypass', errorOnlyPoints: 2, chains: [['duplicatekeyword']] },
  });
  try {
    await finalizeReport(h.run);
    assert.equal(h.report.summary.blockPolicy.action, 'filterBypass');
    // 标签必须与取值语义对齐：filterBypass 只有 errorOnlyPoints，不能写成 blockHits
    assert.match(h.report.summary.blockPolicy.reason, /errorOnlyPoints=2/);
    assert.doesNotMatch(h.report.summary.blockPolicy.reason, /blockHits=/);
  } finally { h.done(); }
});

test('⑪ validity=blocked 但 action=none → none_but_blocked（不得声称无拦截）', async () => {
  const h = build({
    blockPolicy: { action: 'none', reason: '无拦截证据' },
    validitySummary: { status: 'blocked' },
  });
  try {
    await finalizeReport(h.run);
    assert.equal(h.report.summary.blockPolicy.action, 'none_but_blocked');
    assert.match(h.report.summary.blockPolicy.reason, /validity.status=blocked/);
  } finally { h.done(); }
});

test('⑪ 反向：blockPolicy 已有明确动作时不得被覆盖（保留单一事实来源）', async () => {
  const h = build({
    blockPolicy: { action: 'preferTamper', reason: '识别到 WAF' },
    validitySummary: { status: 'blocked' },
  });
  try {
    await finalizeReport(h.run);
    assert.equal(h.report.summary.blockPolicy.action, 'preferTamper');
  } finally { h.done(); }
});

// ⑫ byRisk / byTechnique：机读清单的唯一来源（曾恒为 null）
test('⑫ byRisk / byTechnique 必须落进报告本体（机读清单直接取这两个字段）', async () => {
  const h = build({
    finalVulns: [
      createVulnerability('p1', 'union', 'High', [], 'a'),
      createVulnerability('p2', 'boolean', 'High', [], 'b'),
      createVulnerability('p3', 'error', 'Low', [], 'c'),
    ],
  });
  try {
    await finalizeReport(h.run);
    assert.deepEqual(h.report.summary.byRisk, { High: 2, Low: 1 });
    assert.deepEqual(h.report.summary.byTechnique, { union: 1, boolean: 1, error: 1 });
  } finally { h.done(); }
});

// ⑬ 收尾顺序：会话落盘必须早于 status=completed（否则 resume 读到空 vulns 的半成品）
test('⑬ 会话 finalize 必须先于 status=completed（顺序反了 resume 会读到半成品）', async () => {
  const h = build({
    finalVulns: [createVulnerability('p1', 'union', 'High', [], 'a')],
    // 落盘发生的那一刻记录 s.status：若顺序反了，这里会是 'completed'
    session: { finalize: async () => { h.order.push(`finalize@${h.s.status}`); } },
  });
  try {
    await finalizeReport(h.run);
    assert.ok(h.order.includes('finalize@running'), '落盘必须发生在置 completed 之前（否则 resume 读到空 vulns）');
    assert.ok(!h.order.includes('finalize@completed'), '顺序反了：落盘时状态已是 completed');
    assert.equal(h.s.status, 'completed');
  } finally { h.done(); }
});

// ⑭ SSE 脱敏：scan_completed 事件不得带 target 凭据
test('⑭ scan_completed 事件必须脱敏（SSE 不得携带凭据 / 代理 / 连接串）', async () => {
  const h = build();
  try {
    await finalizeReport(h.run);
    const ev = h.byType('scan_completed')[0];
    assert.ok(ev, '必须发 scan_completed');
    const serialized = JSON.stringify(ev.payload);
    for (const secret of ['p@ssw0rd', 'secretcookie', 'secretkey', 'mysql://root:pw@']) {
      assert.ok(!serialized.includes(secret), `凭据泄漏进 SSE：${secret}`);
    }
    // 脱敏是「置空」不是「删字段」：结构还在，调用方不会因为缺字段崩
    assert.equal(ev.payload.target.config.auth, null);
    assert.equal(ev.payload.target.config.proxy, null);
  } finally { h.done(); }
});

// ⑮ 收尾清理：关闭客户端 + 回收上下文
test('⑮ 收尾必须关客户端并回收扫描上下文（否则连接与 TTL 上下文泄漏）', async () => {
  const h = build();
  try {
    await finalizeReport(h.run);
    assert.ok(h.calls.includes('_maybeClose:hc'), '必须关掉本次扫描的 httpClient');
    assert.ok(h.calls.includes(`_retire:${h.scanId}`), '必须回收 scanId 上下文');
  } finally { h.done(); }
});

// ⑯ 方言验证等级：多点取最低（保守）
test('⑯ 方言验证等级取多点中最低（保守，不把「只有模板」说成「已验证」）', async () => {
  // MySQL=verified · H2=partial · ClickHouse=template-only → 汇总必须落到 template-only
  const h = build({ pointsToScan: [{ dbms: 'MySQL' }, { dbms: 'H2' }, { dbms: 'ClickHouse' }] });
  try {
    await finalizeReport(h.run);
    const ev = h.report.summary.dbmsEvidence;
    assert.ok(ev, '必须落盘验证等级');
    assert.equal(ev.level, 'template-only', '多点识别出不同库时按最保守的等级落盘');
    assert.ok(ev.caveat, 'template-only 必须带人工复核提示');
    assert.ok(ev.all.includes('MySQL:verified') && ev.all.includes('H2:partial'), 'all 要列出各点的等级');
  } finally { h.done(); }
});

test('⑯ 反向：全部已验证时等级为 verified（不得被保守逻辑压低）', async () => {
  const h = build({ pointsToScan: [{ dbms: 'MySQL' }, { dbms: 'PostgreSQL' }] });
  try {
    await finalizeReport(h.run);
    assert.equal(h.report.summary.dbmsEvidence.level, 'verified');
    assert.equal(h.report.summary.dbmsEvidence.caveat, null);
  } finally { h.done(); }
});

// ⑰ stacked 与 OOB 摘要
test('⑰ stacked 开关与二次确认数落进 summary（复现时要能看出跑过什么）', async () => {
  const h = build({ stackedSelected: true, corroborations: 2 });
  try {
    await finalizeReport(h.run);
    assert.equal(h.report.summary.stackedEnabled, true);
    assert.equal(h.report.summary.stackedCorroborations, 2);
  } finally { h.done(); }
});
