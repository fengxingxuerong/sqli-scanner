// scanRunner.runScanLoop 集成测试（此前零覆盖）：
// 用纯对象桩替代 ScanManager 内部件，验证「发现→检测→聚合→报告→收尾」主链路与 stop 中断路径。
// 不发起任何真实请求；事件经真实 eventBus 命名空间收集后断言。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScanLoop } from '../src/engine/scanRunner.js';
import * as eventBus from '../src/core/eventBus.js';
import {
  createTarget,
  createInjectionPoint,
  createDetectionResult,
} from '../src/engine/models.js';

function makePoint(id) {
  const p = createInjectionPoint('query', id, '1', {});
  p.boundaryProbed = true; // 跳过闭合上下文探测（无需 UnionDetector）
  return p;
}

function baseConfig() {
  return {
    concurrency: 2,
    ratePerSec: 100,
    level: 1,
    risk: 1,
    techniques: ['union'],
    enableExtract: false, // 跳过提取阶段（桩面最小化）
    prefilter: false,
    skipStatic: false,
    oob: { enabled: false },
  };
}

// 构造最小桩 sm：覆盖 runScanLoop 触及的全部实例成员
function makeSm({ scanId, point, vulnerable, points }) {
  const target = createTarget({
    url: 'http://mock/page?id=1',
    method: 'GET',
    config: baseConfig(),
  });
  const report = { vulns: [], data: null, summary: {}, points: [], riskLevel: null, dbms: null };
  const state = { target, report, cancelled: false, status: 'running' };
  const retired = [];
  const secondOrderCalls = [];

  const result = createDetectionResult(point.id, 'union');
  result.vulnerable = vulnerable;
  result.dbms = 'MySQL';
  result.evidence = vulnerable ? 'mock evidence' : '';
  result.payloads = vulnerable ? ['1 UNION SELECT 2-- -'] : [];

  const sm = {
    scans: new Map([[scanId, state]]),
    getScanClient: () => null,
    // points 显式传入 ⇒ 用它（0 注入点形态靠它构造）；否则退化为单注入点
    parser: { discover: async () => (Array.isArray(points) ? points : [point]) },
    _selectedTechs: () => ['union'],
    _fingerprintCached: async () => ({ dbms: 'MySQL', baseline: { status: 200, headers: {}, body: '' } }),
    wafIdentifier: { identify: () => [] }, // shouldAutoRetry 缺省走 confidence 兜底，无 vendor 即不重跑
    activeDetectors: () => [
      { technique: 'union', detect: async () => { if (state.cancelled) return { ...result, vulnerable: false }; return result; } },
    ],
    reportGen: { riskOf: (vulns) => (vulns.length ? 'High' : 'Info') },
    _runSecondOrder: async (..._a) => { secondOrderCalls.push(1); return []; },
    _runNoSql: async () => [],
    extractor: {},
    _hasData: () => false,
    wafRecommend: () => [],
    _maybeClose: async () => {},
    _retire: (id) => retired.push(id),
  };
  return { sm, state, retired, secondOrderCalls };
}

// 收集某命名空间的全部事件（订阅后由终态自动断开）
async function collectEvents(scanId, run) {
  const em = eventBus.create(scanId);
  const seen = [];
  em.on('event', (e) => seen.push(e));
  try {
    await run();
  } finally {
    eventBus.dispose(scanId);
  }
  return seen;
}

test('runScanLoop 主链路：命中点写入报告并按序发出生命周期事件', async () => {
  const scanId = 'sr-test-1';
  const point = makePoint('P1');
  const { sm, state, retired, secondOrderCalls } = makeSm({ scanId, point, vulnerable: true });

  await collectEvents(scanId, () => runScanLoop(sm, scanId));

  assert.equal(state.status, 'completed');
  assert.equal(state.report.vulns.length, 1);
  assert.equal(state.report.vulns[0].technique, 'union');
  assert.equal(state.report.vulns[0].riskLevel, 'High');
  assert.equal(state.report.dbms, 'MySQL');
  assert.ok(state.report.finishedAt);
  assert.equal(retired.length, 1); // 命名空间已回收
  assert.equal(secondOrderCalls.length, 1); // 二阶趟照常执行（返回空）
});

test('runScanLoop 生命周期事件顺序：discovering → point_discovered → detecting → detection_found → completed', async () => {
  const scanId = 'sr-test-2';
  const point = makePoint('P1');
  const { sm } = makeSm({ scanId, point, vulnerable: true });

  const events = await collectEvents(scanId, () => runScanLoop(sm, scanId));
  const types = events.map((e) => e.type);
  assert.ok(types.includes('scan_phase'));
  assert.ok(types.includes('point_discovered'));
  assert.ok(types.includes('point_testing'));
  assert.ok(types.includes('detection_found'));
  assert.equal(types[types.length - 1], 'scan_completed');
  // 顺序约束：发现先于检测先于命中
  const iDisc = types.indexOf('point_discovered');
  const iTesting = types.indexOf('point_testing');
  const iFound = types.indexOf('detection_found');
  assert.ok(iDisc < iTesting && iTesting < iFound, '事件顺序异常');
});

test('runScanLoop 未命中：报告零漏洞、无 detection_found', async () => {
  const scanId = 'sr-test-3';
  const point = makePoint('P1');
  const { sm, state } = makeSm({ scanId, point, vulnerable: false });

  const events = await collectEvents(scanId, () => runScanLoop(sm, scanId));
  assert.equal(state.status, 'completed');
  assert.equal(state.report.vulns.length, 0);
  assert.ok(!events.some((e) => e.type === 'detection_found'));
});

test('runScanLoop 用户中止：走 stopped 收尾，不再跑二阶趟', async () => {
  const scanId = 'sr-test-4';
  const point = makePoint('P1');
  const { sm, state, secondOrderCalls } = makeSm({ scanId, point, vulnerable: true });
  // 检测器执行时模拟用户 stop()（与真实 ScanManager.stop 一致：cancelled + status 同步翻转）
  sm.activeDetectors = () => [
    {
      technique: 'union',
      detect: async () => {
        state.cancelled = true;
        state.status = 'stopped';
        return { ...createDetectionResult(point.id, 'union'), vulnerable: false };
      },
    },
  ];

  const events = await collectEvents(scanId, () => runScanLoop(sm, scanId));
  assert.equal(state.status, 'stopped');
  assert.equal(secondOrderCalls.length, 0); // 中止后不再发起二阶（真实写）请求
  assert.equal(events[events.length - 1].type, 'scan_stopped_finalized');
});

test('runScanLoop 扫描不存在时静默返回', async () => {
  const { sm } = makeSm({ scanId: 'sr-test-5', point: makePoint('P1'), vulnerable: true });
  await runScanLoop(sm, 'no-such-scan'); // 不应抛出
});

// [2026-10-02 假阴性修复] 0 注入点 = 一个检测请求都没发 ⇒ 结论必须是 inconclusive。
// 实战形态：批量扫 100 个目标，其中 30 个不通（或 URL 根本不带参数），每个都产出
// 一份 points=0 的报告。旧实现 verdict 仍写 no_vulnerability_detected —— 使用者读到的是
// 「这 30 个站没有注入」，**把「根本没测」写成了安全结论**，比整批报错更危险。
test('runScanLoop 0 注入点：结论为 inconclusive（不得写成未检出漏洞）', async () => {
  const scanId = 'sr-test-6';
  const { sm, state } = makeSm({ scanId, point: makePoint('P1'), vulnerable: false, points: [] });

  await collectEvents(scanId, () => runScanLoop(sm, scanId));

  assert.equal(state.status, 'completed');
  assert.deepEqual(state.report.points, [], '本形态的前提是 0 注入点');
  assert.equal(state.report.summary.noInjectionPoints, true);
  assert.equal(
    state.report.summary.verdict,
    'inconclusive',
    '一次检测都没跑时，阴性结论不成立 —— 必须写 inconclusive',
  );
  // 文案要与「测过但不可靠」区分开：前者要人确认可达性/注入面，后者要人复扫未决点
  assert.match(state.report.summary.verdictNote, /可测注入点|一次检测都没跑/);
});

// 反向钉子：有注入点、可信度正常且未命中时，**仍然**是 no_vulnerability_detected。
// 防止上面那条修复把口径整体收紧成「一律 inconclusive」（那会让真实阴性结论失去意义）。
test('runScanLoop 有注入点且未命中：结论仍为 no_vulnerability_detected', async () => {
  const scanId = 'sr-test-7';
  const { sm, state } = makeSm({ scanId, point: makePoint('P1'), vulnerable: false });

  await collectEvents(scanId, () => runScanLoop(sm, scanId));

  assert.equal((state.report.points || []).length, 1);
  assert.equal(state.report.summary.noInjectionPoints, undefined);
  assert.equal(state.report.summary.verdict, 'no_vulnerability_detected');
});
