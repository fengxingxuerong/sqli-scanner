// [B-perf] skip-static 参数预筛选（对标 sqlmap --skip-static）测试
// 覆盖：
//   1) 默认关闭（skipStatic 未配置）→ 零行为变化（无哨兵请求、全部点完整检测）
//   2) 显式 false → 同上（零行为变化）
//   3) 开启后：静态参数（哨兵响应与基线完全一致且哨兵值未回显）被跳过完整检测，
//      动态参数（哨兵值回显）保守保留并完整检出
//   4) 同值去重：原始值完全相同的参数只测第一个（对重复点零哨兵请求）
//   5) 判定保守：哨兵探测失败 / 状态码不同 / 正文长度不同 → 照常检测
//   6) point_skipped(static) SSE 事件（沿用现有事件机制）
//   7) 哨兵值构造 / 正文规范化单元行为
// 说明：目标 URL 自带全部参数（?a=1&b=2&c=3），注入点为各参数——同页多点共享 1 次基线请求。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads.js';
import * as eventBus from '../src/core/eventBus.js';

// 构造 skip-static 测试用 ScanManager：parser 固定返回点；检测器桩记录调用点
function makeManager(points, httpClient, plan = { union: { vulnerable: true } }) {
  const detectPoints = [];
  const sm = new ScanManager();
  sm.httpClient = httpClient; // 哨兵探测走此 mock（无 forScan → getScanClient 原样返回）
  sm.detectors = TECHNIQUE_TYPES.map((t) => ({
    technique: t,
    async detect(ctx) {
      detectPoints.push(ctx.point.id);
      const spec = plan[t] || {};
      const hit = !!(spec && spec.vulnerable);
      return {
        pointId: ctx.point.id,
        technique: t,
        vulnerable: hit,
        dbms: hit ? 'MySQL' : null,
        evidence: hit ? `mock ${t} hit` : '',
        payloads: hit ? [`mock_${t}`] : [],
      };
    },
  }));
  sm.fp = { async fingerprint() { return { dbms: null, baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return points; } };
  sm._detectPoints = detectPoints;
  return sm;
}

const TARGET_URL = 'http://mock.test/?a=1&b=2&c=3';

async function runScan(sm, config) {
  const id = await sm.start({
    url: TARGET_URL,
    config: { concurrency: 2, ratePerSec: 100, prefilter: false, ...config },
  });
  // 订阅事件：start() 同步返回后 _run 尚未发出任何 point 级事件（首个 await 边界之后才开始），
  // 此处挂监听先于哨兵探测完成，point_skipped 不会丢失。
  const events = [];
  eventBus.create(id).on('event', (evt) => events.push(evt));
  for (let i = 0; i < 200; i++) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  return { id, events };
}

const pts = (specs) => specs.map(([id, param, val]) => ({ id, location: 'url', param, originalValue: val }));

test('skipStatic 默认关闭：无哨兵请求、所有点完整检测（零行为变化）', async () => {
  const points = pts([['p1', 'a', '1'], ['p2', 'b', '2'], ['p3', 'c', '3']]);
  let requests = 0;
  const mock = {
    async request() {
      requests++;
      return { data: 'stable page', status: 200 };
    },
  };
  const sm = makeManager(points, mock);
  const { id, events } = await runScan(sm, {});
  const report = sm.getReport(id);
  assert.equal(requests, 0, 'skipStatic 未开启时不应发任何哨兵请求');
  assert.equal(report.vulns.length, 3, '全部点应完整检测并命中（plan union=true）');
  assert.equal(report.points.length, 3);
  assert.ok(!events.some((e) => e.type === 'point_skipped' && e.payload?.reason === 'static'));
});

test('skipStatic:false 显式关闭：行为与默认一致（零行为变化）', async () => {
  const points = pts([['p1', 'a', '1'], ['p2', 'b', '2']]);
  let requests = 0;
  const mock = {
    async request() {
      requests++;
      return { data: 'stable page', status: 200 };
    },
  };
  const sm = makeManager(points, mock);
  const { id } = await runScan(sm, { skipStatic: false });
  assert.equal(requests, 0);
  assert.equal(sm.getReport(id).vulns.length, 2);
});

test('skipStatic 开启：静态参数被跳过、动态参数保留并完整检出 + point_skipped(static) 事件', async () => {
  const points = pts([['p1', 'a', '1'], ['p2', 'b', '2'], ['p3', 'c', '3']]);
  let requests = 0;
  const mock = {
    async request(opts) {
      requests++;
      // 参数 a 的值回显在页面（动态）；b/c 无论传什么值页面一致（静态）。
      // 基线（a=1）→ "page with value [1]"；p1 哨兵（a=1002）→ "[1002]"（回显+差异 → 保留）；
      // p2/p3 哨兵（a 仍为 1）→ 与基线完全一致 → 静态跳过。
      const a = new URL(opts.url).searchParams.get('a');
      if (a === '1' || a === '1002') return { data: `page with value [${a}]`, status: 200 };
      return { data: 'stable page', status: 200 };
    },
  };
  const sm = makeManager(points, mock);
  const { id, events } = await runScan(sm, { skipStatic: true });
  const report = sm.getReport(id);
  // 1 次共享基线（三点同 URL 同方法，基线=原样请求）+ 3 次哨兵（a=1002 / b=1003 / c=1004）
  assert.equal(requests, 4, `应发 1 基线 + 3 哨兵，实际 ${requests} 次`);
  assert.deepEqual([...new Set(sm._detectPoints)], ['p1'], '只有动态点进入完整检测');
  assert.equal(report.points.length, 3, '报告 point 列表不受影响');
  assert.equal(report.vulns.length, 1);
  assert.equal(report.vulns[0].pointId, 'p1');
  const skipped = events.filter((e) => e.type === 'point_skipped').map((e) => e.payload);
  assert.equal(skipped.length, 2, '应发出 2 条 point_skipped 事件');
  assert.ok(skipped.every((p) => p.reason === 'static'), '事件 reason 应为 static');
  assert.deepEqual(skipped.map((p) => p.pointId).sort(), ['p2', 'p3']);
});

test('skipStatic 同值去重：原始值完全相同的参数只测第一个（重复点零哨兵请求）', async () => {
  const points = pts([['p1', 'a', '1'], ['p2', 'b', '1'], ['p3', 'c', '3']]);
  let requests = 0;
  const mock = {
    async request(opts) {
      requests++;
      const a = new URL(opts.url).searchParams.get('a');
      if (a === '1' || a === '1002') return { data: `page with value [${a}]`, status: 200 };
      return { data: 'stable page', status: 200 };
    },
  };
  const sm = makeManager(points, mock);
  const { id, events } = await runScan(sm, { skipStatic: true });
  const report = sm.getReport(id);
  // 基线 1 次（共享：各点原值请求即原样 URL）+ 哨兵 2 次（p1→a=1002、p3→c=1004；p2 与 p1 同值 '1' → 去重不发哨兵）
  assert.equal(requests, 3, `应发 1 基线 + 2 哨兵（p2 同值去重），实际 ${requests} 次`);
  assert.deepEqual([...new Set(sm._detectPoints)], ['p1'], 'p1 动态保留、p3 静态跳过');
  const skipped = events.filter((e) => e.type === 'point_skipped').map((e) => e.payload.pointId).sort();
  assert.deepEqual(skipped, ['p2', 'p3']);
  assert.equal(report.points.length, 3);
});

// 保守判定用动态回显 mock：基线（原样 URL）返回 page base；任一参数被改（哨兵请求）返回 changed 页
// （与基线不同 → 动态保留）；special 钩子可对特定哨兵请求注入失败/状态码/正文差异。
// 注意：返回 { request } 对象形态（与 HttpClient 接口一致），不能是裸函数。
function makeEchoMock(special) {
  return {
    async request(opts) {
      const u = new URL(opts.url);
      const override = special && special(u);
      if (override) return override;
      if (u.toString() === TARGET_URL) return { data: 'page base', status: 200 };
      return { data: `page changed ${u.search}`, status: 200 };
    },
  };
}

test('skipStatic 保守判定：哨兵探测失败（网络错误）→ 照常检测', async () => {
  const points = pts([['p1', 'a', '1'], ['p2', 'b', '2']]);
  const mock = makeEchoMock((u) => {
    if (u.searchParams.get('b') === '1003') throw new Error('network down'); // p2 哨兵失败
    return undefined;
  });
  const sm = makeManager(points, mock);
  const { id, events } = await runScan(sm, { skipStatic: true });
  const report = sm.getReport(id);
  assert.equal(report.vulns.length, 2, '探测失败的点保守保留并完整检测');
  assert.equal(events.filter((e) => e.type === 'point_skipped').length, 0, '探测失败不产生跳过事件');
});

test('skipStatic 保守判定：状态码不同 → 照常检测', async () => {
  const points = pts([['p1', 'a', '1'], ['p2', 'b', '2']]);
  const mock = makeEchoMock((u) =>
    u.searchParams.get('b') === '1003' ? { data: 'page base', status: 500 } : undefined
  );
  const sm = makeManager(points, mock);
  const { id, events } = await runScan(sm, { skipStatic: true });
  assert.equal(sm.getReport(id).vulns.length, 2);
  assert.equal(events.filter((e) => e.type === 'point_skipped').length, 0);
});

test('skipStatic 保守判定：正文长度不同 → 照常检测；等长空白差异视为一致（规范化）', async () => {
  // ① 正文长度不同（动态内容）→ 保留
  {
    const points = pts([['p1', 'a', '1'], ['p2', 'b', '2']]);
    const mock = makeEchoMock((u) =>
      u.searchParams.get('b') === '1003' ? { data: 'page base with banner', status: 200 } : undefined
    );
    const sm = makeManager(points, mock);
    const { id, events } = await runScan(sm, { skipStatic: true });
    assert.equal(sm.getReport(id).vulns.length, 2, '正文长度不同不应判静态');
    assert.equal(events.filter((e) => e.type === 'point_skipped').length, 0);
  }
  // ② 等长正文仅空白排版差异（规范化后一致）→ 判静态跳过
  {
    const points = pts([['p1', 'a', '1'], ['p2', 'b', '2']]);
    // 基线 'a b c d'（7 字符）与哨兵 'a\tb c d'（7 字符）：长度一致、规范化后一致 → 静态
    // 基线与 p1 哨兵返回不同正文（p1 保留），仅 p2 哨兵与基线规范化一致
    const mock2 = {
      async request(opts) {
        const u = new URL(opts.url);
        if (u.searchParams.get('b') === '1003') return { data: 'a\tb c d', status: 200 };
        if (u.toString() === TARGET_URL) return { data: 'a b c d', status: 200 };
        return { data: `page changed ${u.search}`, status: 200 };
      },
    };
    const sm = makeManager(points, mock2);
    const { id, events } = await runScan(sm, { skipStatic: true });
    const report = sm.getReport(id);
    assert.equal(report.vulns.length, 1, '等长空白差异应视为静态跳过');
    assert.equal(report.vulns[0].pointId, 'p1');
    assert.equal(events.filter((e) => e.type === 'point_skipped').length, 1);
  }
});

test('skipStatic：单点目标不做哨兵探测（无跨点预算可省）', async () => {
  const points = pts([['p1', 'a', '1']]);
  let requests = 0;
  const mock = {
    async request() {
      requests++;
      return { data: 'stable page', status: 200 };
    },
  };
  const sm = makeManager(points, mock);
  const { id } = await runScan(sm, { skipStatic: true });
  assert.equal(requests, 0, '单点不发哨兵请求');
  assert.equal(sm.getReport(id).vulns.length, 1, '单点照常完整检测');
});

test('skipStatic：精确标记点（precisionMarked）不参与跳过', async () => {
  const points = [
    { id: 'p1', location: 'url', param: 'a', originalValue: '1', precisionMarked: true },
    { id: 'p2', location: 'url', param: 'b', originalValue: '1', precisionMarked: true },
  ];
  const mock = {
    async request() {
      return { data: 'stable page', status: 200 };
    },
  };
  const sm = makeManager(points, mock);
  const { id, events } = await runScan(sm, { skipStatic: true });
  assert.equal(sm.getReport(id).vulns.length, 2, '精确标记点即使响应静态也完整检测');
  assert.equal(events.filter((e) => e.type === 'point_skipped').length, 0);
});

test('_staticSentinel 哨兵值构造：数字 +1001、字符串加 _sst 后缀', () => {
  const sm = new ScanManager();
  assert.equal(sm._staticSentinel('1'), '1002');
  assert.equal(sm._staticSentinel('42'), '1043');
  assert.equal(sm._staticSentinel('-5'), '996');
  assert.equal(sm._staticSentinel('3.14'), '1004.14');
  assert.equal(sm._staticSentinel('abc'), 'abc_sst');
  assert.equal(sm._staticSentinel(''), '_sst');
  assert.equal(sm._staticSentinel('1e9'), '1e9_sst', '科学计数法串不当数字处理（保守当字符串）');
});

test('_normalizeForStatic 正文规范化：折叠空白 + 去首尾，其它差异保留', () => {
  const sm = new ScanManager();
  assert.equal(sm._normalizeForStatic('  a \n b \t c  '), 'a b c');
  assert.notEqual(sm._normalizeForStatic('page v1'), sm._normalizeForStatic('page v2'));
});
