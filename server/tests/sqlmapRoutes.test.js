// 测试 server/src/api/sqlmapRoutes.js 路由层
import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { sqlmapRoutes } from '../src/api/sqlmapRoutes.js';

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/sqlmap', sqlmapRoutes);
  return app;
}

async function req(app, method, path, body) {
  const server = app.listen(0);
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test('GET /sqlmap/status 返回 {available, maxConcurrent}（不含 script/python）', async () => {
  const { json } = await req(buildApp(), 'GET', '/sqlmap/status');
  assert.equal(json.code, 0);
  const d = json.data;
  assert.equal(typeof d.available, 'boolean');
  assert.equal(typeof d.maxConcurrent, 'number');
  assert.ok(!('script' in d), '不应返回 script 路径');
  assert.ok(!('python' in d), '不应返回 python 路径');
});

test('POST /sqlmap/start 无 url 时返回错误', async () => {
  const { json } = await req(buildApp(), 'POST', '/sqlmap/start', {});
  assert.notEqual(json.code, 0, '无 url 应返回非零错误码');
  assert.equal(json.data, null);
});

test('GET /sqlmap/:id/report 不存在时返回 SCAN_NOT_FOUND', async () => {
  const { json } = await req(buildApp(), 'GET', '/sqlmap/no-such-id/report');
  assert.equal(json.code, 2001);
  assert.equal(json.data, null);
});

// 与内置引擎 /scan/:id/stop 同一口径（2026-09-28 接口靶场）：不存在的任务不得回 code:0。
// 前端 useScan 按 engine 选路径打同一个"停止"动作，两条链路必须给出同样的失败语义。
test('POST /sqlmap/:id/stop 不存在时返回 SCAN_NOT_FOUND（不得报成功）', async () => {
  const { json } = await req(buildApp(), 'POST', '/sqlmap/no-such-id/stop');
  assert.equal(json.code, 2001);
  assert.equal(json.data.stopped, false);
});

// ── [F2 2026-10-03] /sqlmap/:id/diff 与 /sqlmap/:id/report/export ──
import { bridge } from '../src/api/sqlmapRoutes.js';
import { diffSqlmapVulns, renderSqlmapMarkdown } from '../src/engine/sqlmapBridge.js';

const seed = (id, vulns) => {
  bridge.scans.set(id, { logs: [], vulns, state: 'completed', startedAt: Date.now() });
};
const unseed = (...ids) => ids.forEach((id) => bridge.scans.delete(id));

test('diff：缺 base 参数显式报错（不静默返回空 diff）', async () => {
  const { json } = await req(buildApp(), 'GET', '/sqlmap/whatever/diff');
  assert.notEqual(json.code, 0);
  assert.match(json.message, /base/);
});

test('diff：任一侧扫描不存在 ⇒ 显式 SCAN_NOT_FOUND（两侧都查，不拿空当一致）', async () => {
  const a = await req(buildApp(), 'GET', '/sqlmap/no-such/diff?base=also-nope');
  assert.equal(a.json.code, 2001);
  seed('real-base', []);
  const b = await req(buildApp(), 'GET', '/sqlmap/no-such/diff?base=real-base');
  assert.equal(b.json.code, 2001);
  const c = await req(buildApp(), 'GET', '/sqlmap/real-base/diff?base=no-such');
  assert.equal(c.json.code, 2001);
  unseed('real-base');
});

test('★diff：两条真实形状报告的 added/removed/unchanged（键 = param::technique）', async () => {
  seed('f2-base', [
    { param: 'id', technique: 'boolean', raw: 'a' },
    { param: 'id', technique: 'union', raw: 'b' },
  ]);
  seed('f2-cur', [
    { param: 'id', technique: 'boolean', raw: 'a' },
    { param: 'name', technique: 'error', raw: 'c' },
  ]);
  try {
    const { json } = await req(buildApp(), 'GET', '/sqlmap/f2-cur/diff?base=f2-base');
    assert.equal(json.code, 0);
    assert.equal(json.data.added.length, 1);
    assert.equal(json.data.added[0].technique, 'error');
    assert.equal(json.data.removed.length, 1);
    assert.equal(json.data.removed[0].technique, 'union');
    assert.equal(json.data.unchanged.length, 1);
    assert.equal(json.data.unchanged[0].technique, 'boolean');
  } finally {
    unseed('f2-base', 'f2-cur');
  }
});

test('★diffSqlmapVulns 纯函数：畸形条目（缺 param/technique）不崩 diff', () => {
  // 缺字段条目都归一到 '-::unknown' —— 两条畸形条目会**按键相撞**（键相同视为同一条），
  // 这是可接受的行为：diff 的语义是「同一注入点的发现变化」，无法归因的条目本来就不该
  // 各算各的。测试把该行为钉住，防止有人把它改成按对象身份比较。
  const d = diffSqlmapVulns([{}], [{ param: 'id', technique: 'time' }, null]);
  assert.equal(d.added.length, 1, 'time 条目为新增');
  assert.equal(d.unchanged.length, 1, 'null 条目与基线的 {} 撞同一个 -::unknown 键 ⇒ unchanged');
  assert.equal(d.removed.length, 0);
});

test('export：format 白名单外（html）显式 400 —— 不静默降级成 json', async () => {
  seed('f2-x', []);
  try {
    const r = await req(buildApp(), 'GET', '/sqlmap/f2-x/report/export?format=html');
    assert.equal(r.status, 400);
    assert.match(r.json.message, /json\/markdown/);
  } finally { unseed('f2-x'); }
});

test('export：未知 id ⇒ SCAN_NOT_FOUND', async () => {
  const r = await req(buildApp(), 'GET', '/sqlmap/no-such/report/export?format=json');
  assert.equal(r.json.code, 2001);
});

test('★export markdown：真实报告渲染（attachment 头 + 发现计数 + 单元格转义）', async () => {
  seed('f2-md', [
    { param: 'id', technique: 'boolean', raw: 'x' },
    { param: 'a|b', technique: 'union', raw: 'y' },
  ]);
  try {
    const server2 = buildApp().listen(0);
    const { port } = server2.address();
    try {
      const res = await fetch(`http://127.0.0.1:${port}/sqlmap/f2-md/report/export?format=md`);
      assert.equal(res.status, 200);
      assert.match(res.headers.get('content-type') || '', /markdown/);
      assert.match(res.headers.get('content-disposition') || '', /attachment; filename="sqlmap-f2-md\.md"/);
      const text = await res.text();
      assert.match(text, /发现：2 条/);
      assert.match(text, /a\\|b/, 'param 里的 | 必须转义（内容来自 sqlmap 输出解析，不可信）');
      // json 通道返回**文档本体**（不是 {code,data} 包装）—— 与内置 /report/export 的
      // 下载语义一致，别当漏包起重做
      const j = await req(buildApp(), 'GET', '/sqlmap/f2-md/report/export?format=json');
      assert.equal(j.json.engine, 'sqlmap');
      assert.ok(Array.isArray(j.json.vulns));
    } finally {
      await new Promise((r) => server2.close(r));
    }
  } finally { unseed('f2-md'); }
});

test('renderSqlmapMarkdown 纯函数：空报告渲染「无发现」行', () => {
  const md = renderSqlmapMarkdown({ status: 'completed', vulns: [] });
  assert.match(md, /无发现/);
  assert.match(md, /completed/);
});
