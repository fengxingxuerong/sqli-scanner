// SPA 外壳与 API 鉴权的分流契约（server/index.js）
//
// 背景（真浏览器实测，2026-09-19）：启用 SCAN_API_TOKEN 后，前端两个主路由 `/scan`、`/exploit`
// 被 `API_SEGMENTS` 白名单当成 API 拦掉 —— 浏览器直接访问/刷新/收藏这两页拿到的是
// `{"code":401,...}` 一段 JSON，页面打不开。开发模式（Vite 代理）与不带 token 时都看不到，
// 所以此前从没暴露。修复见 index.js 的 [SPA-DEEPLINK-FIX]。
//
// 本文件把修复后的判据钉死，四条边界缺一不可：
//   ① 浏览器形态（GET + 裸路径 + Accept: text/html）放行；
//   ② curl/API 客户端形态（不带 Accept: text/html）**仍 401** —— 不能因为放行就漏权；
//   ③ 带子路径（`/scan/<id>/report`）**仍 401** —— 那才是 API；
//   ④ 数据接口不受影响：带 token 正常返回业务码，不带 token 401。
//
// 注意：token 在 index.js 是**模块级**求值的，所以必须在 import 之前设置环境变量（动态 import）。
import http from 'node:http';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

const TOKEN = 'spa-shell-test-token';
process.env.SCAN_API_TOKEN = TOKEN;
process.env.HOST = '127.0.0.1';

const { createApp } = await import('../index.js');

const DIST_INDEX = path.resolve(
  path.dirname(fileURLToPath(new URL('../index.js', import.meta.url))),
  '../dist/index.html'
);

let server = null;
let port = 0;

function req(pathname, { headers = {}, method = 'GET' } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request(
      { host: '127.0.0.1', port, path: pathname, method, headers },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body })
        );
      }
    );
    r.on('error', reject);
    r.end();
  });
}

const BROWSER = { accept: 'text/html,application/xhtml+xml' };
const API_CLIENT = { accept: '*/*' };

before(async () => {
  const app = createApp();
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      port = server.address().port;
      resolve();
    });
  });
});

after(() => {
  if (server) server.close();
});

test('SPA 外壳：/scan 与 /exploit 在浏览器形态下放行', async (t) => {
  // 判据依赖 dist/index.html 真实存在（修复里第 ④ 条就是这条）；没构建过前端则无法验证，
  // 按纪律显式 SKIP 并说明原因，不静默通过。
  if (!existsSync(DIST_INDEX)) {
    return t.skip(`dist/index.html 不存在（未构建前端），本用例无法验证：${DIST_INDEX}`);
  }
  for (const p of ['/scan', '/exploit']) {
    const res = await req(p, { headers: BROWSER });
    assert.equal(res.status, 200, `${p} 浏览器形态应放行，实际 ${res.status}`);
    assert.match(
      String(res.headers['content-type'] || ''),
      /text\/html/i,
      `${p} 应返回 HTML 外壳而不是 JSON`
    );
  }
});

test('SPA 外壳放行不得扩大到 API 客户端（无 Accept: text/html 仍 401）', async () => {
  const res = await req('/scan', { headers: API_CLIENT });
  assert.equal(res.status, 401, 'curl 形态取 /scan 仍须鉴权');
});

test('SPA 外壳放行不得扩大到子路径（/scan/<id>/report 仍是 API，401）', async () => {
  const res = await req('/scan/abc/report', { headers: BROWSER });
  assert.equal(res.status, 401, '带子路径的 /scan/* 仍是数据接口');
});

test('数据接口：带 token 返回业务码，不带 token 401', async () => {
  const ok = await req('/api/scan/nonexistent/report', {
    headers: { ...BROWSER, 'x-api-token': TOKEN },
  });
  assert.equal(ok.status, 200);
  const parsed = JSON.parse(ok.body);
  assert.equal(parsed.code, 2001, '带 token 应走到业务逻辑（扫描不存在）');

  const noToken = await req('/api/scan/nonexistent/report', { headers: BROWSER });
  assert.equal(noToken.status, 401, '不带 token 的数据接口必须拒绝');
});
