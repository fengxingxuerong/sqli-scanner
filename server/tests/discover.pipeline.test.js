// discover.pipeline.test.js —— 注入点发现与点位准备（engine/scan/discover.js）专属单测
// ============================================================================
// 为什么补这一份：discover.js 226 行、**此前零测试挂载**（func 覆盖 31.25%）。
// 它是「哪些点进完整检测」的唯一决定者 —— 空点位告警、会话 resume、三层廉价跳过
// （skip-static / prefilter / validationSkip）与 --skip 排除全在这里。
// 这一层的失败形态不是报错，而是：
//   · 0 个注入点静默走成「无漏洞」（假阴性）
//   · 跨目标误 resume 旧会话（拿 A 站的点去续跑 B 站）
//   · 跳过不留痕（报告里「没测」长得像「测了且安全」）
// 这些改坏都不报错，只有断言能抓住。
//
// 手法：stub 只替掉 sm 的四个探测入口与 parser；会话走**真实 ScanSession**但指向
// 系统临时目录下的唯一文件（测完单文件清理），resume 语义因此是真语义而非桩语义。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { discoverPoints } from '../src/engine/scan/discover.js';
import { _colGuessCache } from '../src/engine/Extractor.js';
import * as eventBus from '../src/core/eventBus.js';

let uid = 0;
const nextScanId = () => `discover-${++uid}`;
const TMP = mkdtempSync(path.join(tmpdir(), 'sqli-discover-'));

/** 构造 discoverPoints 的 run 上下文 */
function build(o = {}) {
  const scanId = nextScanId();
  const events = [];
  eventBus.create(scanId).on('event', (e) => events.push(e));

  const points = (o.points ?? [{ id: 'p1', param: 'id' }, { id: 'p2', param: 'q' }]).map((p) => ({ ...p }));
  const calls = [];

  // 探测入口必须**返回 points 里的同一批对象**：生产代码用 `candidate.includes(p)` 判
  // 跳过，返回新建的等价对象会让「保留」的点也被判成跳过（断言就变成了测空气）。
  const keepOf = (ids) => points.filter((p) => ids.includes(p.id));
  const sm = {
    parser: { discover: async () => points },
    async _skipStaticPoints(_ctx, _target, ps) {
      calls.push(`skipStatic:${ps.length}`);
      return o.staticKeep ? keepOf(o.staticKeep) : (o.staticCandidate ?? ps);
    },
    async _prefilterPoints(_ctx, _target, ps) {
      calls.push(`prefilter:${ps.length}`);
      return o.prefilterKeep ? keepOf(o.prefilterKeep) : (o.prefilterCandidate ?? ps);
    },
    async _validationGuardedSkipPoints(_ctx, _target, ps) {
      calls.push(`validation:${ps.length}`);
      return o.validationResult ?? { candidate: ps, skipped: [] };
    },
  };

  const report = { points: [], summary: {}, ...(o.report || {}) };
  const run = {
    sm,
    scanId,
    target: o.target ?? { mode: 'http', url: 'http://127.0.0.1:8080/a.php?id=1', config: {} },
    cfg: { ...(o.cfg || {}) },
    ctxBase: { httpClient: {} },
    rawClient: {},
    report,
  };

  return {
    run, scanId, points, calls, events, report,
    byType: (t) => events.filter((e) => e.type === t),
    done: () => eventBus.dispose(scanId),
  };
}

// ── ① 空点位：必须显式告警（防「根本没测」被读成「测了且安全」） ────────────

test('① 发现 0 个注入点 → summary 明确告警并给出开启更多注入面的提示', async () => {
  const h = build({ points: [] });
  try {
    const out = await discoverPoints(h.run);
    assert.equal(out.points.length, 0);
    assert.equal(h.report.summary.noInjectionPoints, true);
    assert.match(h.report.summary.noInjectionPointsHint, /--test-headers/);
    assert.match(h.report.summary.noInjectionPointsHint, /--test-path/);
    assert.equal(h.byType('point_discovered').length, 1, '空点位也要播报（前端要能显示「没发现点」）');
  } finally { h.done(); }
});

test('① 反向：有点位时不得打上「无注入点」标记（否则报告自相矛盾）', async () => {
  const h = build();
  try {
    await discoverPoints(h.run);
    assert.equal(h.report.summary.noInjectionPoints, undefined);
  } finally { h.done(); }
});

// ── ② freshQueries：清缓存 + 强制全新扫描 ─────────────────────────────────

test('② --flush-session 语义：freshQueries 清空列数猜解缓存（不依赖历史结果）', async () => {
  _colGuessCache.set('discover-test-key', 42);
  const h = build({ cfg: { freshQueries: true } });
  try {
    await discoverPoints(h.run);
    assert.equal(_colGuessCache.has('discover-test-key'), false, 'freshQueries 必须清掉列数缓存');
  } finally { _colGuessCache.delete('discover-test-key'); h.done(); }
});

test('② freshQueries 下即使会话文件存在也不恢复（用户要的是全新扫描）', async () => {
  const file = path.join(TMP, `sess-${++uid}.json`);
  const h = build({ cfg: { freshQueries: true, sessionFile: file } });
  try {
    const out = await discoverPoints(h.run);
    assert.equal(out.restored, null, 'freshQueries 不是 resume');
    assert.ok(out.session, '但会话仍要落盘（后续扫描可续跑本次进度）');
  } finally {
    try { rmSync(file, { force: true }); } catch { /* 临时文件残留无害 */ }
    h.done();
  }
});

// ── ③ sessionDefault：跨目标不得误续跑 ────────────────────────────────────

test('③ sessionDefault 未显式给 sessionFile 时也自动建会话（默认落盘续跑）', async () => {
  const h = build({ cfg: { sessionDefault: true } });
  try {
    const out = await discoverPoints(h.run);
    assert.ok(out.session, 'sessionDefault 应自动建会话');
  } finally { h.done(); }
});

test('③ 跨目标保护：历史会话 URL 与当前目标不符时不 resume（拿 A 站的点续跑 B 站 = 污染）', async () => {
  const file = path.join(TMP, `sess-${++uid}.json`);
  try {
    const a = build({ cfg: { sessionDefault: true, sessionFile: file }, target: { mode: 'http', url: 'http://a.example.com/x.php?id=1', config: {} } });
    try { await discoverPoints(a.run); } finally { a.done(); }
    const b = build({ cfg: { sessionDefault: true, sessionFile: file }, target: { mode: 'http', url: 'http://b.example.com/y.php?id=1', config: {} } });
    try {
      const out = await discoverPoints(b.run);
      assert.equal(out.restored, null, 'URL 不符不得恢复历史会话');
      assert.ok(out.session, '应新建会话');
    } finally { b.done(); }
  } finally {
    try { rmSync(file, { force: true }); } catch { /* noop */ }
  }
});

test('③ direct 模式不做 sessionDefault（直连无 HTTP 目标 URL 语义，不该落盘续跑）', async () => {
  const h = build({ cfg: { sessionDefault: true }, target: { mode: 'direct', url: 'db://x', config: {} } });
  try {
    const out = await discoverPoints(h.run);
    assert.equal(out.session, null);
  } finally { h.done(); }
});

// ── ④ resume：已完成点本轮不重测 ─────────────────────────────────────────

test('④ resume：会话里 status=done 的点本轮排除（省请求，不重复测）', async () => {
  const file = path.join(TMP, `sess-${++uid}.json`);
  const h = build({ cfg: { sessionFile: file } });
  try {
    // 先建会话并把 p1 标记完成（真写盘，resume 语义走真实通道）
    const first = await discoverPoints(h.run);
    await first.session.savePointResult('p1', { found: [] }).catch(() => null);
    // 再跑一次：p1 应被排除
    const h2 = build({ cfg: { sessionFile: file } });
    try {
      const out = await discoverPoints(h2.run);
      const ids = out.pointsToScan.map((p) => p.id);
      assert.ok(!ids.includes('p1'), '已完成点不得再进本轮检测');
      assert.ok(ids.includes('p2'));
    } finally { h2.done(); }
  } finally {
    try { rmSync(file, { force: true }); } catch { /* noop */ }
    h.done();
  }
});

// ── ⑤ --skip：排除指定参数并留痕 ─────────────────────────────────────────

test('⑤ --skip：大小写不敏感排除，跳过点发 user-skip 事件（报告要能解释「为什么没测」）', async () => {
  // 参数名用大写、--skip 用小写：只有两侧都做 toLowerCase 才匹配得上（单侧归一会被漏掉）
  const h = build({ points: [{ id: 'p1', param: 'ID' }, { id: 'p2', param: 'q' }], cfg: { skipParams: ['id'] } });
  try {
    const out = await discoverPoints(h.run);
    assert.deepEqual(out.pointsToScan.map((p) => p.id), ['p2']);
    const skipped = h.byType('point_skipped').filter((e) => e.payload.reason === 'user-skip');
    assert.equal(skipped.length, 1);
    assert.equal(skipped[0].payload.pointId, 'p1');
    assert.equal(out.points.length, 2, '排除只影响待扫集合，report.points 仍保留全量点');
  } finally { h.done(); }
});

test('⑤ 反向：skipParams 为空数组时不排除任何点（防空集合被当成「排除一切」）', async () => {
  const h = build({ cfg: { skipParams: [] } });
  try {
    const out = await discoverPoints(h.run);
    assert.equal(out.pointsToScan.length, 2);
  } finally { h.done(); }
});

// ── ⑥ skip-static：opt-in 且多点才生效 ───────────────────────────────────

test('⑥ skip-static：opt-in 开启时对多点生效，跳过点发 static 事件', async () => {
  const h = build({ cfg: { skipStatic: true }, staticKeep: ['p2'] });
  try {
    const out = await discoverPoints(h.run);
    assert.deepEqual(out.pointsToScan.map((p) => p.id), ['p2']);
    const st = h.byType('point_skipped').filter((e) => e.payload.reason === 'static');
    assert.equal(st.length, 1);
    assert.ok(h.calls.includes('skipStatic:2'));
  } finally { h.done(); }
});

test('⑥ 单点目标不跑 skip-static（1 请求换 46 请求在单点上没有意义）', async () => {
  const h = build({ points: [{ id: 'p1', param: 'id' }], cfg: { skipStatic: true } });
  try {
    await discoverPoints(h.run);
    assert.ok(!h.calls.some((c) => c.startsWith('skipStatic')), '单点不得触发 skip-static');
  } finally { h.done(); }
});

// ── ⑦ 预筛选：默认开，跳过必须写 skipReason ───────────────────────────────

test('⑦ 预筛选：跳过的点必须写 skipReason=prefilter（没测 ≠ 测了没漏洞）', async () => {
  const h = build({ prefilterKeep: ['p2'] });
  try {
    const out = await discoverPoints(h.run);
    assert.deepEqual(out.pointsToScan.map((p) => p.id), ['p2']);
    assert.equal(h.points.find((p) => p.id === 'p1').skipReason, 'prefilter');
    assert.ok(h.calls.includes('prefilter:2'), '默认开启：多点目标必须走预筛选');
  } finally { h.done(); }
});

test('⑦ 单点默认不预筛（避免唯一注入点被无信号探针误杀）', async () => {
  const h = build({ points: [{ id: 'p1', param: 'id' }] });
  try {
    const out = await discoverPoints(h.run);
    assert.ok(!h.calls.some((c) => c.startsWith('prefilter')), '单点默认不做预筛选');
    assert.equal(out.pointsToScan.length, 1);
  } finally { h.done(); }
});

test('⑦ 单点 + prefilterSinglePoint=true 才预筛（opt-in，零回归）', async () => {
  const h = build({ points: [{ id: 'p1', param: 'id' }], cfg: { prefilterSinglePoint: true }, prefilterCandidate: [] });
  try {
    const out = await discoverPoints(h.run);
    assert.ok(h.calls.includes('prefilter:1'));
    assert.equal(out.pointsToScan.length, 0);
  } finally { h.done(); }
});

// ── ⑧ validationSkip：更强的判据，仅在单点且预筛选未接管时 ─────────────────

test('⑧ 输入校验型跳过：跳过点写 skipReason/skipNote 并发事件（省 200+ 请求/点）', async () => {
  const h = build({
    points: [{ id: 'p1', param: 'id' }],
    cfg: { techniques: ['union', 'boolean'] },
    validationResult: { candidate: [], skipped: [{ pointId: 'p1', reason: 'input_validation', note: '白名单拦死' }] },
  });
  try {
    const out = await discoverPoints(h.run);
    assert.equal(out.pointsToScan.length, 0);
    assert.equal(h.points[0].skipReason, 'input_validation');
    assert.equal(h.points[0].skipNote, '白名单拦死');
    const ev = h.byType('point_skipped').find((e) => e.payload.reason === 'input_validation');
    assert.ok(ev, '跳过必须留痕');
  } finally { h.done(); }
});

test('⑧ direct 模式不做输入校验跳过（直连无 HTTP 层「输入校验」语义）', async () => {
  const h = build({
    points: [{ id: 'p1', param: 'id' }],
    cfg: { techniques: ['union'] },
    target: { mode: 'direct', url: 'db://x', config: {} },
  });
  try {
    await discoverPoints(h.run);
    assert.ok(!h.calls.some((c) => c.startsWith('validation')));
  } finally { h.done(); }
});

test('⑧ 预筛选已接管（多点）时不再跑 validationSkip（两条跳过路径互斥）', async () => {
  const h = build({ cfg: { techniques: ['union'] } }); // 多点 → prefilter 接管
  try {
    await discoverPoints(h.run);
    assert.ok(h.calls.includes('prefilter:2'));
    assert.ok(!h.calls.some((c) => c.startsWith('validation')), '互斥：不得两条跳过链叠加');
  } finally { h.done(); }
});

test('⑧ 无回显类技术（stacked-only）不做输入校验跳过（探针无信号会误跳过）', async () => {
  const h = build({ points: [{ id: 'p1', param: 'id' }], cfg: { techniques: ['stacked'] } });
  try {
    await discoverPoints(h.run);
    assert.ok(!h.calls.some((c) => c.startsWith('validation')));
  } finally { h.done(); }
});
