// ============================================================================
// server/tests/uncoveredSurfaces.test.js —— [D124 2026-10-21]
//
// 契约：「本次压根没测哪些注入面」必须按配置算出来并进报告。
//
// 背景：`level` 默认 1，只覆盖 URL query + POST body（cookie≥2 / header≥3 / path 靠
// --test-path / 表单需 level 5）。真实项目里多数人用默认档扫完就写报告，而这几类面
// 从未进入检测 —— 报告却只写「未检出」。这属于**覆盖范围没披露**，不是检出率问题。
//
// 判据：
//   ① 默认档（level=1）⇒ 必须报出 cookie/header/path/forms 四类未覆盖；
//   ② level=3 + testHeaders + testPath + level5 表单 ⇒ 不得报（已全覆盖，防狼来了）；
//   ③ testHeaders 单独开启 ⇒ cookie/header 两类都算覆盖（cookie 是 header 子集）；
//   ④ 端到端：真实扫描的 report.summary.uncoveredSurfaces 真的落盘。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { uncoveredSurfaces } from '../src/engine/scan/discover.js';
import { ScanManager } from '../src/engine/ScanManager.js';

process.env.SSRF_ALLOW_PRIVATE = '1';

const surfaces = (cfg) => uncoveredSurfaces(cfg).map((u) => u.surface);

test('D124-③: 默认档（level=1）报出 cookie / header / path / forms 四类未覆盖', () => {
  const got = surfaces({ level: 1 });
  assert.deepEqual(got, ['cookie', 'header', 'path', 'forms']);
  // 每项都必须带「怎么开」的指路，否则只是一句没用的警告
  for (const u of uncoveredSurfaces({ level: 1 })) {
    assert.ok(u.hint && u.hint.length > 0, `${u.surface} 缺 hint`);
    assert.ok(u.label && u.label.length > 0, `${u.surface} 缺 label`);
  }
});

test('D124-④: 全覆盖配置下不报任何未覆盖面（防「狼来了」）', () => {
  assert.deepEqual(surfaces({ level: 5, testHeaders: true, testPath: true, crawlForms: true }), []);
});

test('D124-⑤: testHeaders 单独开启 ⇒ cookie 与 header 都算已覆盖（cookie 是 header 子集）', () => {
  const got = surfaces({ level: 1, testHeaders: true });
  assert.ok(!got.includes('cookie'), `testHeaders 开时 cookie 不该再算未覆盖，实际=${got}`);
  assert.ok(!got.includes('header'), `testHeaders 开时 header 不该再算未覆盖，实际=${got}`);
  assert.deepEqual(got, ['path', 'forms'], 'path 与 forms 仍应正确列出');
});

test('D124-⑥: level=2 时 cookie 已覆盖、header 仍未覆盖（边界不能糊）', () => {
  const got = surfaces({ level: 2 });
  assert.ok(!got.includes('cookie'), 'level=2 已含 cookie 点');
  assert.ok(got.includes('header'), 'level=2 仍不含 header 点');
});

test('D124-⑦: 真实扫描的报告里真的带了 uncoveredSurfaces', async () => {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    const id = (u.searchParams.get('id') || '1').replace(/\s+/g, '');
    const rows = id.includes('1=2') ? [] : ['admin'];
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(rows.length ? 'Hello admin' : 'No results');
  });
  const lab = await new Promise((r) => server.listen(0, '127.0.0.1', () => r(server)));
  try {
    const { port } = lab.address();
    const sm = new ScanManager();
    const id = await sm.start({
      url: `http://127.0.0.1:${port}/item?id=1`,
      config: {
        techniques: ['boolean'], level: 1, risk: 1, concurrency: 1,
        ratePerSec: 400, prefilter: false, skipStatic: false, smart: false,
      },
    });
    const t0 = Date.now();
    while (Date.now() - t0 < 60000) {
      const s = sm.scans.get(id);
      if (s && (s.status === 'completed' || s.status === 'error')) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    const summary = sm.getReport(id).summary || {};
    assert.ok(Array.isArray(summary.uncoveredSurfaces), `应落盘数组，实际 keys=${Object.keys(summary).join(',')}`);
    assert.ok(summary.uncoveredSurfaces.length > 0, '默认档应至少报出 cookie/header/path/forms');
    assert.match(String(summary.uncoveredSurfacesHint || ''), /根本没测/);
  } finally {
    lab.close();
  }
});
