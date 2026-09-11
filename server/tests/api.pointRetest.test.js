// ============================================================================
// tests/api.pointRetest.test.js —— 单点重测接口（实战最高频动作）
//
// 场景：调完参（level/risk/tamper/technique）只想重跑某个注入点，
// 旧做法只能整站重扫——验证一次要等几分钟。
// 本测试是**真接口集成测试**（起 app + 真起扫描），重点验证两件事：
//   ① 接口可用（返回新 scanId，point 信息回传正确）
//   ② onlyPoint 真的生效：新扫描只测那一个点（points.length === 1），请求量显著下降
// 避免"接口返回 200 但其实退化成整站重扫"这种假成功。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../index.js';

// 靶场（e2e/redteam-lab）需先启动：node e2e/redteam-lab/server.mjs
const LAB = 'http://127.0.0.1:8231';

// 靶场是本地一次性评测环境（node e2e/redteam-lab/env.mjs），起不来时测试应 skip 而不是 fail，
// 否则 CI / 日常单测会被环境依赖误伤。
async function labReachable() {
  try {
    const r = await fetch(`${LAB}/health`, { signal: AbortSignal.timeout(2000) });
    return r.ok;
  } catch {
    return false;
  }
}

async function withApp(fn) {
  const app = createApp();
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const postJson = (base, path, body) =>
  fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  }).then((r) => r.json());

const getJson = (base, path) => fetch(`${base}${path}`).then((r) => r.json());

// 轮询直到扫描完成。
// 注意 /api/scan/:id 返回的是**报告对象**（scanId/target/points/vulns/finishedAt…），
// 没有 status 字段 —— 完成标志是 finishedAt 非空。轮询间隔要短：报告在扫描结束后
// 会被回收，间隔太久会拿到空 data。
async function waitDone(base, scanId, ms = 180000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    const r = await getJson(base, `/api/scan/${scanId}`);
    if (r?.data?.finishedAt) return r;
    await new Promise((r2) => setTimeout(r2, 400));
  }
  return null;
}

test('单点重测：只重跑目标点（points 收敛到 1），并返回新 scanId', async (t) => {
  if (!(await labReachable())) return t.skip('红队靶场未启动（node e2e/redteam-lab/env.mjs）');
  await withApp(async (base) => {
    // 1) 起一次基线扫描（A1 靶点，含 id 一个 query 参数）
    const started = await postJson(base, '/api/scan/start', {
      url: `${LAB}/shop/item?id=1`,
      config: { level: 1, risk: 1, timeoutMs: 20000, ratePerSec: 100 },
    });
    assert.equal(started.code, 0, `基线扫描启动失败：${started.message}`);
    const baseId = started.data.scanId;
    const baseDone = await waitDone(base, baseId);
    assert.ok(baseDone, '基线扫描未能在超时内完成');
    const baseReport = (await getJson(base, `/api/scan/${baseId}/report`)).data;
    const points = baseReport.points || [];
    assert.ok(points.length >= 1, '基线报告应有注入点');
    const target = points[0];

    // 2) 单点重测：只重跑该点，config 覆盖 level
    const retest = await postJson(base, `/api/scan/${baseId}/point/${target.id}/retest`, {
      config: { level: 2 },
    });
    assert.equal(retest.code, 0, `重测启动失败：${retest.message}`);
    assert.ok(retest.data.scanId, '应返回新 scanId');
    assert.equal(retest.data.point.param, target.param, '回传的注入点参数名应一致');

    // 3) 关键断言：新扫描只测这一个点（否则等于退化成整站重扫）
    const done = await waitDone(base, retest.data.scanId);
    assert.ok(done, '重测扫描未能在超时内完成');
    const rep = (await getJson(base, `/api/scan/${retest.data.scanId}/report`)).data;
    assert.equal(
      (rep.points || []).length,
      1,
      `onlyPoint 应让注入点收敛到 1 个（实际 ${(rep.points || []).length}）`
    );
    assert.equal((rep.points || [])[0].param, target.param);
  });
});

test('单点重测：不存在的 pointId → 明确报错，不退化成整站重扫', async (t) => {
  if (!(await labReachable())) return t.skip('红队靶场未启动（node e2e/redteam-lab/env.mjs）');
  await withApp(async (base) => {
    const started = await postJson(base, '/api/scan/start', {
      url: `${LAB}/shop/item?id=1`,
      config: { level: 1, risk: 1, timeoutMs: 20000, ratePerSec: 100 },
    });
    assert.equal(started.code, 0);
    const baseId = started.data.scanId;
    await waitDone(base, baseId);
    const bad = await postJson(base, `/api/scan/${baseId}/point/nosuchpoint1/retest`, {});
    assert.notEqual(bad.code, 0, 'pointId 不存在应报错');
    assert.match(bad.message, /注入点不存在/);
    assert.equal(bad.data, null);
  });
});

test('onlyPoint 过滤（纯逻辑层）：未匹配到点位时抛带可用点位列表的错误', async () => {
  const { TargetParser } = await import('../src/engine/TargetParser.js');
  const { createTarget } = await import('../src/engine/models.js');
  const parser = new TargetParser();
  const t = createTarget({
    url: 'http://example.com/p?id=1&name=a',
    config: { onlyPoint: { location: 'url', param: 'notexist' } },
  });
  await assert.rejects(
    () => parser.discover(t),
    (e) => /onlyPoint 未匹配到注入点/.test(e.message) && /url:id/.test(e.message),
    '应提示未匹配且列出可用点位'
  );

  const t2 = createTarget({
    url: 'http://example.com/p?id=1&name=a',
    config: { onlyPoint: { location: 'url', param: 'name' } },
  });
  const pts = await parser.discover(t2);
  assert.equal(pts.length, 1);
  assert.equal(pts[0].param, 'name');
});

test('onlyPoint 缺省时行为不变（零回归）', async () => {
  const { TargetParser } = await import('../src/engine/TargetParser.js');
  const { createTarget } = await import('../src/engine/models.js');
  const parser = new TargetParser();
  const pts = await parser.discover(createTarget({ url: 'http://example.com/p?id=1&name=a' }));
  assert.equal(pts.length, 2);
});
