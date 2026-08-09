// ScanManager 二阶编排集成测试：验证 _runSecondOrder 门控（enabled/triggerUrls/存储点）、
// (存储点 × 触发页) 调用次数、命中并入报告（second_order → High），以及未启用时零写。
// 全部使用桩检测器 + 桩解析器，不发起任何真实请求。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';
import {
  createTarget,
  createInjectionPoint,
  createDetectionResult,
  createReport,
} from '../src/engine/models.js';
import * as eventBus from '../src/core/eventBus.js';

// 构造带二阶配置的目标（缺省走 defaults.secondOrder）
function makeTarget(secondOrder) {
  const config = secondOrder === undefined ? {} : { techniques: ['union', 'error', 'boolean', 'time'], secondOrder };
  return createTarget({ url: 'http://mock/page', method: 'GET', config });
}

// 构造一个潜在存储点（POST 表单点）或非存储点
function storePoint(id, isStore) {
  return createInjectionPoint('body', id, '1', {
    formMethod: isStore ? 'POST' : 'GET',
    actionUrl: `http://mock/${id}`,
    formValues: {},
    csrfTokenName: null,
    isStorePoint: isStore,
    storeKind: isStore ? 'registration' : null,
  });
}

// 构造一个二阶 DetectionResult（桩检测器返回）
function soResult(pointId, vulnerable, dbms = 'MySQL') {
  const r = createDetectionResult(pointId, 'second_order');
  r.vulnerable = vulnerable;
  r.dbms = dbms;
  r.evidence = vulnerable ? '二阶注入确认' : '';
  r.payloads = vulnerable ? ["'"] : [];
  return r;
}

// 可记录调用次数的桩二阶检测器；vulnFor(ctx) 决定每次结果
function makeStubDetector(vulnFor) {
  const calls = [];
  return {
    calls,
    async detect(ctx) {
      calls.push({ pointId: ctx.point.id, triggerUrl: ctx.triggerUrl });
      return vulnFor(ctx);
    },
  };
}

test('_runSecondOrder：未启用时直接跳过且零调用（对目标零写）', async () => {
  const sm = new ScanManager();
  const stub = makeStubDetector(() => soResult('x', true));
  sm.secondOrderDetector = stub;
  const target = makeTarget({ enabled: false, triggerUrls: ['http://t/u1'] });
  const pts = [storePoint('A', true)];
  const vulns = await sm._runSecondOrder('scanX', target, pts, null);
  assert.equal(vulns.length, 0);
  assert.equal(stub.calls.length, 0); // 未调用检测器 → 未发起任何写请求
});

test('_runSecondOrder：triggerUrls 为空时跳过', async () => {
  const sm = new ScanManager();
  const stub = makeStubDetector(() => soResult('x', true));
  sm.secondOrderDetector = stub;
  const target = makeTarget({ enabled: true, triggerUrls: [] });
  const pts = [storePoint('A', true)];
  const vulns = await sm._runSecondOrder('scanX', target, pts, null);
  assert.equal(vulns.length, 0);
  assert.equal(stub.calls.length, 0);
});

test('_runSecondOrder：无存储点时跳过', async () => {
  const sm = new ScanManager();
  const stub = makeStubDetector(() => soResult('x', true));
  sm.secondOrderDetector = stub;
  const target = makeTarget({ enabled: true, triggerUrls: ['http://t/u1'] });
  const pts = [storePoint('B', false)]; // GET 非存储点
  const vulns = await sm._runSecondOrder('scanX', target, pts, null);
  assert.equal(vulns.length, 0);
  assert.equal(stub.calls.length, 0);
});

test('_runSecondOrder：manualStorePoints 手动指定非存储点 → 运行时置 isStorePoint 并入验证', async () => {
  const sm = new ScanManager();
  // 仅参数名 'B' 命中二阶（B 本是非存储点，靠 manualStorePoints 提升）
  const stub = makeStubDetector((ctx) => soResult(ctx.point.param, ctx.point.param === 'B'));
  sm.secondOrderDetector = stub;
  const target = makeTarget({
    enabled: true,
    triggerUrls: ['http://t/u1'],
    refreshCsrf: false,
    negativeControl: false,
    oobTrigger: false,
    manualStorePoints: ['B', ''],
  });
  const b = storePoint('B', false); // 本非存储点
  assert.equal(b.isStorePoint, false); // 前置：确实不是启发式存储点
  const vulns = await sm._runSecondOrder('scanX', target, [b], 'MySQL');
  // 手动指定使 B 被纳入：调用 1 次（B × 1 触发页）
  assert.equal(stub.calls.length, 1);
  assert.equal(vulns.length, 1); // B 命中二阶
  assert.equal(vulns[0].pointId, b.id);
  assert.equal(b.isStorePoint, true); // 运行时置真，使报告/拓扑存储点高亮与一阶一致
});

test('_runSecondOrder：manualStorePoints 指定参数未命中任何注入点 → 仍无存储点跳过（零调用）', async () => {
  const sm = new ScanManager();
  const stub = makeStubDetector(() => soResult('x', true));
  sm.secondOrderDetector = stub;
  const target = makeTarget({
    enabled: true,
    triggerUrls: ['http://t/u1'],
    manualStorePoints: ['nonexistent'],
  });
  const pts = [storePoint('B', false)];
  const vulns = await sm._runSecondOrder('scanX', target, pts, null);
  assert.equal(vulns.length, 0);
  assert.equal(stub.calls.length, 0);
});

test('_runSecondOrder：enabled 时对每个(存储点×触发页)调用并合并命中→High', async () => {
  const sm = new ScanManager();
  // 仅参数名为 'A' 的存储点命中（注意注入点 id 为随机 nanoid，判定用 param 而非 id）
  const stub = makeStubDetector((ctx) => soResult(ctx.point.param, ctx.point.param === 'A'));
  sm.secondOrderDetector = stub;
  const target = makeTarget({
    enabled: true,
    triggerUrls: ['http://t/u1', 'http://t/u2'],
    refreshCsrf: false,
    negativeControl: true,
    oobTrigger: false,
  });
  const a = storePoint('A', true);
  const b = storePoint('B', false);
  const c = storePoint('C', true);
  const vulns = await sm._runSecondOrder('scanX', target, [a, b, c], 'MySQL');

  // 调用次数 = 2 个存储点(A,C) × 2 个触发页 = 4
  assert.equal(stub.calls.length, 4);
  // 仅 A 命中 → 2 条（A × 2 触发页）
  assert.equal(vulns.length, 2);
  for (const v of vulns) {
    assert.equal(v.technique, 'second_order');
    assert.equal(v.riskLevel, 'High'); // 经 ReportGenerator.riskOf 定级
    assert.equal(v.pointId, a.id); // 命中点是参数名 'A' 的存储点（pointId 为其随机 id）
  }
});

test('完整 _run：二阶命中并入报告（second_order → High），一阶流水线不受影响', async () => {
  const sm = new ScanManager();
  // 桩：一阶检测器全部未命中
  sm.detectors = sm.detectors.map((d) => ({
    technique: d.technique,
    async detect() {
      return createDetectionResult('x', d.technique);
    },
  }));
  // 桩：指纹/提取不触发真实请求
  sm.fp = { async fingerprint() { return null; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  // 桩：解析器只返回预设点（一个存储点）
  const sp = storePoint('username', true);
  sp.id = 'SO-1';
  sp.formValues = { username: '1', _token: 'c' };
  sp.csrfTokenName = '_token';
  sm.parser = { async discover() { return [sp]; } };
  // 桩：二阶检测器对该存储点返回命中
  sm.secondOrderDetector = {
    async detect(ctx) {
      assert.equal(ctx.triggerUrl, 'http://mock/trigger');
      return soResult(ctx.point.id, true, 'MySQL');
    },
  };

  const target = makeTarget({
    enabled: true,
    triggerUrls: ['http://mock/trigger'],
    refreshCsrf: false,
    negativeControl: true,
    oobTrigger: false,
  });
  const scanId = 'so-full-1';
  sm.scans.set(scanId, { target, report: createReport(scanId, target), status: 'running', cancelled: false });
  eventBus.create(scanId);

  await sm._run(scanId);
  const report = sm.getReport(scanId);
  assert.equal(sm.scans.get(scanId).status, 'completed');

  const so = report.vulns.find((v) => v.technique === 'second_order');
  assert.ok(so, '报告应含二阶漏洞');
  assert.equal(so.riskLevel, 'High');
  assert.equal(so.dbms, 'MySQL');
  assert.equal(report.riskLevel, 'High');
});

test('_runSecondOrder：autoDiscover 触发发现并用作触发页（手填为空）', async () => {
  const sm = new ScanManager();
  // 桩：二阶检测器对该存储点返回命中
  const stub = makeStubDetector((ctx) => soResult(ctx.point.param, ctx.point.param === 'A'));
  sm.secondOrderDetector = stub;
  // 桩：自动发现返回候选与确认结果
  const discRun = { calls: 0 };
  sm.secondOrderDiscovery = {
    async run() {
      discRun.calls++;
      return { candidates: ['http://t/c1', 'http://t/c2'], confirmed: ['http://t/c1'] };
    },
  };
  const target = makeTarget({
    enabled: true,
    triggerUrls: [], // 手填为空 → 应由 autoDiscover 接管
    autoDiscover: true,
    refreshCsrf: false,
    negativeControl: true,
    oobTrigger: false,
  });
  const a = storePoint('A', true);
  const scanId = 'so-auto-1';
  sm.scans.set(scanId, { target, report: createReport(scanId, target), status: 'running', cancelled: false });
  const vulns = await sm._runSecondOrder(scanId, target, [a], 'MySQL');

  assert.equal(discRun.calls, 1, '应调用一次自动发现');
  // 确认页作为唯一触发页 → 命中 A × 1
  assert.equal(stub.calls.length, 1);
  assert.equal(stub.calls[0].triggerUrl, 'http://t/c1');
  assert.equal(vulns.length, 1);
  // 发现结果应落入报告 summary
  const disc = sm.scans.get(scanId).report.summary.secondOrderDiscovery;
  assert.ok(disc, 'summary.secondOrderDiscovery 应被写入');
  assert.deepEqual(disc.candidates, ['http://t/c1', 'http://t/c2']);
  assert.deepEqual(disc.confirmed, ['http://t/c1']);
  // 发现期识别到的存储点应随 summary 透传（供前端实时链路图绘制完整拓扑）
  assert.ok(disc.storePoints, 'summary.secondOrderDiscovery 应含 storePoints');
  assert.equal(disc.storePoints.length, 1);
  assert.equal(disc.storePoints[0].param, 'A');
});

test('_runSecondOrder：second_order_discovery 事件载荷含 storePoints（供实时图）', async () => {
  const sm = new ScanManager();
  const stub = makeStubDetector((ctx) => soResult(ctx.point.param, ctx.point.param === 'A'));
  sm.secondOrderDetector = stub;
  sm.secondOrderDiscovery = {
    async run() {
      return { candidates: ['http://t/c1', 'http://t/c2'], confirmed: ['http://t/c1'] };
    },
  };
  const target = makeTarget({
    enabled: true,
    triggerUrls: [],
    autoDiscover: true,
    refreshCsrf: false,
    negativeControl: true,
    oobTrigger: false,
  });
  const a = storePoint('A', true);
  const scanId = 'so-event-1';
  sm.scans.set(scanId, { target, report: createReport(scanId, target), status: 'running', cancelled: false });
  // 订阅事件总线，捕获 second_order_discovery 载荷
  let captured = null;
  eventBus.create(scanId).on('event', (evt) => {
    if (evt.type === 'second_order_discovery') captured = evt.payload;
  });
  await sm._runSecondOrder(scanId, target, [a], 'MySQL');
  assert.ok(captured, '应经 SSE 推送 second_order_discovery 事件');
  assert.deepEqual(captured.candidates, ['http://t/c1', 'http://t/c2']);
  assert.deepEqual(captured.confirmed, ['http://t/c1']);
  assert.ok(captured.storePoints, '事件载荷应含 storePoints');
  assert.equal(captured.storePoints.length, 1);
  assert.equal(captured.storePoints[0].param, 'A');
});

test('_runSecondOrder：手动 triggerUrls 优先，autoDiscover 不触发发现', async () => {
  const sm = new ScanManager();
  // 若发现器被调用则抛错（验证未被调用）
  sm.secondOrderDiscovery = {
    async run() {
      throw new Error('autoDiscover 不应在手动 triggerUrls 时调用');
    },
  };
  const stub = makeStubDetector(() => soResult('x', true));
  sm.secondOrderDetector = stub;
  const target = makeTarget({
    enabled: true,
    triggerUrls: ['http://t/manual1'],
    autoDiscover: true, // 开启但手动已填 → 应跳过发现
    refreshCsrf: false,
    negativeControl: true,
    oobTrigger: false,
  });
  const a = storePoint('A', true);
  const vulns = await sm._runSecondOrder('scanX', target, [a], 'MySQL');
  assert.equal(stub.calls.length, 1, '仅对手动触发页调用一次');
  assert.equal(stub.calls[0].triggerUrl, 'http://t/manual1');
  assert.equal(vulns.length, 1);
});

test('完整 _run：manualStorePoints 把非存储点提升并写入报告（isStorePoint 运行时置真反映到 points）', async () => {
  const sm = new ScanManager();
  // 一阶检测器全部未命中（归一化到 Medium 但不触发二阶）
  sm.detectors = sm.detectors.map((d) => ({
    technique: d.technique,
    async detect() {
      return createDetectionResult('x', d.technique);
    },
  }));
  sm.fp = { async fingerprint() { return null; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  // 解析器只返回预设点：email 本不是启发式存储点（GET 表单点，isStorePoint=false）
  const sp = storePoint('email', false);
  sp.id = 'SO-MANUAL-1';
  sm.parser = { async discover() { return [sp]; } };
  // 二阶检测器：对 email 点返回命中（与 manualStorePoints 提升逻辑配合）
  sm.secondOrderDetector = {
    async detect(ctx) {
      assert.equal(ctx.triggerUrl, 'http://mock/trigger');
      return soResult(ctx.point.id, true, 'PostgreSQL');
    },
  };

  // 关键：config 带 manualStorePoints:['email']（含 risk:2 入口门控要求，但 _run 直连不受 gate 拦截）
  const target = makeTarget({
    enabled: true,
    triggerUrls: ['http://mock/trigger'],
    refreshCsrf: false,
    negativeControl: true,
    oobTrigger: false,
    manualStorePoints: ['email'],
  });
  const scanId = 'so-manual-full-1';
  sm.scans.set(scanId, { target, report: createReport(scanId, target), status: 'running', cancelled: false });
  eventBus.create(scanId);

  await sm._run(scanId);
  const report = sm.getReport(scanId);
  assert.equal(sm.scans.get(scanId).status, 'completed');

  // 1) 报告应含二阶漏洞（manualStorePoints 提升 email 后命中）
  const so = report.vulns.find((v) => v.technique === 'second_order');
  assert.ok(so, 'manualStorePoints 提升后报告应含二阶漏洞');
  assert.equal(so.riskLevel, 'High');
  assert.equal(so.dbms, 'PostgreSQL');
  assert.equal(so.pointId, sp.id); // 命中点是 email 注入点（运行时置真）
  // 2) 报告 points 中 email 的 isStorePoint 应被运行时置真（供前端拓扑/报告展示与启发式一致）
  const reportEmail = report.points.find((p) => p.param === 'email');
  assert.ok(reportEmail, '报告 points 应含 email 注入点');
  assert.equal(reportEmail.isStorePoint, true, '运行时置真 isStorePoint 必须反映到报告 points');
  // 3) 一阶流水线不受二阶手动提升影响（未被污染）
  assert.ok(!report.vulns.some((v) => v.technique === 'union' || v.technique === 'error'));
});

test('_runSecondOrder：autoDiscover 开启但发现为空 → 跳过（零检测器调用）', async () => {
  const sm = new ScanManager();
  const stub = makeStubDetector(() => soResult('x', true));
  sm.secondOrderDetector = stub;
  sm.secondOrderDiscovery = {
    async run() {
      return { candidates: ['http://t/c1'], confirmed: [] }; // 无一确认
    },
  };
  const target = makeTarget({
    enabled: true,
    triggerUrls: [],
    autoDiscover: true,
    refreshCsrf: false,
    negativeControl: true,
    oobTrigger: false,
  });
  const a = storePoint('A', true);
  const vulns = await sm._runSecondOrder('scanX', target, [a], 'MySQL');
  assert.equal(vulns.length, 0);
  assert.equal(stub.calls.length, 0, '无确认触发页 → 检测器不应被调用');
});

test('完整 _run：二阶默认关闭时不写入、不新增漏洞', async () => {
  const sm = new ScanManager();
  let soCalled = 0;
  sm.detectors = sm.detectors.map((d) => ({
    technique: d.technique,
    async detect() {
      return createDetectionResult('x', d.technique);
    },
  }));
  sm.fp = { async fingerprint() { return null; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  const sp = storePoint('username', true);
  sp.id = 'SO-2';
  sm.parser = { async discover() { return [sp]; } };
  // 即便桩检测器会返回命中，未启用也应被门控跳过
  sm.secondOrderDetector = {
    async detect() {
      soCalled++;
      return soResult('SO-2', true);
    },
  };

  // 不传 secondOrder → 走 defaults（enabled:false）
  const target = createTarget({ url: 'http://mock/page', method: 'GET', config: { techniques: ['union', 'error', 'boolean', 'time'] } });
  const scanId = 'so-full-2';
  sm.scans.set(scanId, { target, report: createReport(scanId, target), status: 'running', cancelled: false });
  eventBus.create(scanId);

  await sm._run(scanId);
  const report = sm.getReport(scanId);
  assert.equal(sm.scans.get(scanId).status, 'completed');
  assert.equal(soCalled, 0, '二阶默认关闭时检测器不应被调用');
  assert.ok(!report.vulns.some((v) => v.technique === 'second_order'));
});
