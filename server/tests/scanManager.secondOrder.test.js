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
