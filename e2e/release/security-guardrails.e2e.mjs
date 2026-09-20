// ============================================================================
// e2e/release/security-guardrails.e2e.mjs —— 安全护栏回归（可直接进 CI）
// 用法：node e2e/release/security-guardrails.e2e.mjs
// 覆盖（均为"改坏了就红"的硬护栏，不是泛泛冒烟）：
//   A1 CSP 分流：API 响应 default-src 'none'；静态资源必须含 'self'（否则 Docker 部署白屏）
//   A2 默认鉴权：非回环监听且无 token → 拒绝启动；回环 + token → 无凭据 401、带凭据 200；
//                SCAN_API_TOKEN_EMIT=1 → stdout 输出 ENGINE_TOKEN 且该 token 可用
//   既有护栏：CSRF 403/415、利用端点默认关闭、scanId 形状校验、SSRF 拒绝云元数据
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const indexJs = resolve(ROOT, 'server/index.js');
const { createApp } = await import(pathToFileURL(indexJs).href);

let failed = 0;
const ok = (cond, label, extra = '') => {
  console.log(`[${cond ? 'PASS' : 'FAIL'}] ${label}${extra ? '  ' + extra : ''}`);
  if (!cond) failed += 1;
};

// 端口一律动态选取：CI/本地可能有残留进程占着固定端口（EADDRINUSE 会让整轮回归假红）
async function pickFreePort() {
  return new Promise((res, rej) => {
    const s = http.createServer();
    s.once('error', rej);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
  });
}

// ── 进程内：静态/API 响应头与既有护栏 ────────────────────────────────────────
const PORT = await pickFreePort();
const server = await new Promise((r) => { const s = createApp().listen(PORT, '127.0.0.1', () => r(s)); });

function req(method, path, { headers = {}, body = null } = {}) {
  return new Promise((res) => {
    const data = body === null ? null : Buffer.from(body);
    const r = http.request(
      { host: '127.0.0.1', port: PORT, method, path, headers: { ...(data ? { 'content-length': data.length } : {}), ...headers } },
      (resp) => {
        let buf = '';
        resp.setEncoding('utf8');
        resp.on('data', (c) => (buf += c));
        resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: buf }));
      }
    );
    r.on('error', (e) => res({ status: 0, error: e.message }));
    if (data) r.write(data);
    r.end();
  });
}

const apiHealth = await req('GET', '/api/health');
const staticRoot = await req('GET', '/');
ok((apiHealth.headers['content-security-policy'] || '').includes("default-src 'none'"), "API 响应 CSP = default-src 'none'");
ok(
  (staticRoot.headers['content-security-policy'] || '').includes("'self'"),
  "静态资源 CSP 含 'self'（Docker 单端口部署不白屏）",
  staticRoot.headers['content-security-policy'] || '(无)'
);

const csrf1 = await req('POST', '/api/scan/start', {
  headers: { 'content-type': 'application/json', 'sec-fetch-site': 'cross-site' },
  body: JSON.stringify({ target: { url: 'http://example.com/' } }),
});
ok(csrf1.status === 403, '跨站驱动（无 Origin + Sec-Fetch-Site）→ 403', `实际 ${csrf1.status}`);

const csrf2 = await req('POST', '/api/scan/start', { headers: { 'content-type': 'text/plain' }, body: 'url=http://example.com/' });
ok(csrf2.status === 415, '简单请求 content-type=text/plain → 415', `实际 ${csrf2.status}`);

const exp = await req('POST', '/api/exploit/sql', {
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ target: { url: 'http://example.com/?id=1' }, point: { originalValue: '1' }, sql: 'SELECT 1' }),
});
ok(JSON.parse(exp.body || '{}').code === 6005, '利用端点默认关闭（code 6005）', exp.body?.slice(0, 60));

const badId = await req('GET', '/api/scan/..%2f..%2fetc%2fpasswd/report');
ok(badId.status === 400, '非法 scanId（路径遍历）→ 400', `实际 ${badId.status}`);

const ssrf = await req('POST', '/api/scan/start', {
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ target: { url: 'http://169.254.169.254/latest/meta-data/' } }),
});
ok(JSON.parse(ssrf.body || '{}').code === 1003, 'SSRF：云元数据地址被拒（code 1003）', ssrf.body?.slice(0, 60));

server.close();

// ── 子进程：启动期护栏 ───────────────────────────────────────────────────────
function startEngine(port, env) {
  const child = spawn(process.execPath, [indexJs], {
    env: { ...process.env, HOST: '127.0.0.1', PORT: String(port), ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  let err = '';
  child.stdout.on('data', (d) => (out += d.toString()));
  child.stderr.on('data', (d) => (err += d.toString()));
  return { child, get out() { return out; }, get err() { return err; } };
}

async function waitHealth(port, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = await new Promise((res) => {
      const rq = http.get({ host: '127.0.0.1', port, path: '/api/health' }, (resp) => { resp.resume(); res(resp.statusCode); });
      rq.on('error', () => res(0));
      rq.setTimeout(1000, () => { rq.destroy(); res(0); });
    });
    if (r === 200) return true;
    await new Promise((r2) => setTimeout(r2, 300));
  }
  return false;
}
function stop(child) { try { child.kill(); } catch { /* ignore */ } }

// ① 非回环监听且无 token → 必须拒绝启动
{
  const p = await pickFreePort();
  const child = spawn(process.execPath, [indexJs], {
    env: { ...process.env, HOST: '0.0.0.0', PORT: String(p), SCAN_API_TOKEN: '', SCAN_API_TOKEN_FILE: '' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let err = '';
  child.stderr.on('data', (d) => (err += d.toString()));
  const code = await new Promise((r) => child.on('exit', r));
  ok(code !== 0 && err.includes('拒绝以无鉴权方式监听'), '非回环监听 + 无 token → 拒绝启动（fail-closed）', `exit=${code}`);
}

// ② 回环 + token → 无凭据 401、带凭据 200；sqlmap --eval 门控
{
  // [A4 2026-09-18] 用一个"存在但不会被真正执行"的假 sqlmap 脚本，
  // 让 bridge 走到 buildArgs（否则会在「未找到 sqlmap 脚本」处提前返回，门控就测不到）。
  const fakeDir = mkdtempSync(join(tmpdir(), 'sqli-eval-guard-'));
  const fakeSqlmap = join(fakeDir, 'sqlmap.py');
  writeFileSync(fakeSqlmap, '# fake sqlmap（仅用于通过 existsSync 检查，永不执行）\n', 'utf-8');

  const p2 = await pickFreePort();
  const h = startEngine(p2, { SCAN_API_TOKEN: 'guardrail-token', SQLMAP_PATH: fakeSqlmap });
  const up = await waitHealth(p2);
  ok(up, '带 token 的引擎可正常启动');
  const noAuth = await new Promise((res) => {
    http.get({ host: '127.0.0.1', port: p2, path: '/api/scan/aaaaaaaaaa' }, (r) => { r.resume(); res(r.statusCode); }).on('error', () => res(0));
  });
  ok(noAuth === 401, '无凭据访问受保护端点 → 401', `实际 ${noAuth}`);
  const withAuth = await new Promise((res) => {
    http.get({ host: '127.0.0.1', port: p2, path: '/api/scan/aaaaaaaaaa', headers: { 'x-api-token': 'guardrail-token' } }, (r) => { r.resume(); res(r.statusCode); }).on('error', () => res(0));
  });
  ok(withAuth === 200, '带正确 token → 200', `实际 ${withAuth}`);

  // [P0-FIX 2026-09-18 发布冒烟实测] 启用 token 后，前端外壳不得被一起拦掉：
  // 旧实现只放行 PUBLIC_READONLY 精确集合，`GET /` 返回 401 JSON → Docker 部署打不开 Web UI。
  const get = (path) => new Promise((res) => {
    http.get({ host: '127.0.0.1', port: p2, path }, (r) => { r.resume(); res(r.statusCode); }).on('error', () => res(0));
  });
  const shellRoot = await get('/');
  ok(shellRoot === 200, '带 token 部署下前端首页 GET / 必须 200（否则 Web UI 打不开）', `实际 ${shellRoot}`);
  // 反向：路由同时挂在 / 上，"不带 /api 前缀的 API"仍必须鉴权
  const legacyApi = await get('/scan/aaaaaaaaaa');
  ok(legacyApi === 401, '非 /api 前缀的 API（/scan/:id）无 token 仍 401', `实际 ${legacyApi}`);

  // [A4] sqlmap --eval 默认必须被拒（它等于让服务端执行 Python 表达式）。
  // 注意契约：bridge.start() 会先回 scanId，再把 buildArgs 的失败作为 SSE `scan_error` 事件送出，
  // 所以断言必须落在事件流上——只看 HTTP 码会误判成"放行了"（本地踩过）。
  const evalProbe = await new Promise((res) => {
    const payload = JSON.stringify({
      target: { url: 'http://example.com/item?id=1' },
      config: { sqlmap: { evalCode: 'import os; os.system("id")' } },
    });
    const r = http.request(
      { host: '127.0.0.1', port: p2, method: 'POST', path: '/api/sqlmap/start',
        headers: { 'content-type': 'application/json', 'content-length': payload.length, 'x-api-token': 'guardrail-token' } },
      (resp) => { let b = ''; resp.setEncoding('utf8'); resp.on('data', (c) => (b += c)); resp.on('end', () => res({ status: resp.statusCode, body: b })); }
    );
    r.on('error', () => res({ status: 0, body: '' }));
    r.setTimeout(10000, () => r.destroy());
    r.write(payload);
    r.end();
  });
  let evalScanId = null;
  try { evalScanId = JSON.parse(evalProbe.body)?.data?.scanId || null; } catch { /* noop */ }

  let sse = '';
  let reportBody = null;
  if (evalScanId) {
    // lastEventId=0 → 触发服务端回放环形缓冲，把连接前已发出的事件补回来（否则会 race 掉）
    sse = await new Promise((res) => {
      let buf = '';
      const rq = http.get(
        { host: '127.0.0.1', port: p2, path: `/api/sqlmap/${evalScanId}/events?token=guardrail-token&lastEventId=0` },
        (resp) => {
          resp.setEncoding('utf8');
          resp.on('data', (c) => {
            buf += c;
            if (/scan_error/.test(buf)) { resp.destroy(); res(buf); }
          });
        }
      );
      rq.on('error', () => res(buf));
      rq.setTimeout(6000, () => { rq.destroy(); res(buf); });
    });
    // 主判据（带 token，读 body）：门控生效时 bridge 会删掉该 scan（`scans.delete`）→
    // 报告端点应回 code 2001「扫描不存在」。若门控失效，这里会拿到真实报告（code 0）→ 断言变红。
    reportBody = await new Promise((res) => {
      const rq = http.get(
        { host: '127.0.0.1', port: p2, path: `/api/sqlmap/${evalScanId}/report`, headers: { 'x-api-token': 'guardrail-token' } },
        (resp) => {
          let b = '';
          resp.setEncoding('utf8');
          resp.on('data', (c) => (b += c));
          resp.on('end', () => { try { res(JSON.parse(b)); } catch { res({ code: -1, raw: b.slice(0, 80) }); } });
        }
      );
      rq.on('error', () => res({ code: -2 }));
      rq.setTimeout(6000, () => { rq.destroy(); res({ code: -3 }); });
    });
  }
  const sseRejected = /scan_error/.test(sse) && /--eval 未启用/.test(sse);
  const scanDiscarded = reportBody?.code === 2001; // 扫描不存在 ⇒ 被门控丢弃
  ok(
    sseRejected || scanDiscarded,
    'sqlmap --eval 默认被拒（scan 被丢弃 / SSE scan_error 报「未启用」）',
    `sse=${sse ? sse.replace(/\s+/g, ' ').slice(0, 90) : '空'} report.code=${reportBody ? reportBody.code : 'n/a'}`
  );

  rmSync(fakeDir, { recursive: true, force: true });
  stop(h.child);
}

// ③ SCAN_API_TOKEN_EMIT=1（桌面 sidecar）→ stdout 输出 ENGINE_TOKEN，且该 token 可用
{
  const p3 = await pickFreePort();
  const h = startEngine(p3, { SCAN_API_TOKEN_EMIT: '1' });
  const up = await waitHealth(p3);
  ok(up, 'emit 模式引擎可启动');
  const m = /ENGINE_TOKEN=([a-f0-9]{64})/.exec(h.out);
  ok(!!m, 'stdout 输出 ENGINE_TOKEN（64 hex，供 Tauri 捕获）', m ? 'ok' : h.out.slice(0, 120));
  if (m) {
    const code = await new Promise((res) => {
      http.get({ host: '127.0.0.1', port: p3, path: '/api/scan/aaaaaaaaaa', headers: { 'x-api-token': m[1] } }, (r) => { r.resume(); res(r.statusCode); }).on('error', () => res(0));
    });
    ok(code === 200, 'emit 出的 token 可正常鉴权', `实际 ${code}`);
    const noAuth = await new Promise((res) => {
      http.get({ host: '127.0.0.1', port: p3, path: '/api/scan/aaaaaaaaaa' }, (r) => { r.resume(); res(r.statusCode); }).on('error', () => res(0));
    });
    ok(noAuth === 401, 'emit 模式下无凭据 → 401', `实际 ${noAuth}`);
  }
  stop(h.child);
}

// ④ 桌面端链路（A3）：Tauri WebView 的 origin 必须被引擎放行，否则桌面版所有变更请求 403
{
  const p4 = await pickFreePort();
  const h = startEngine(p4, {
    SCAN_API_TOKEN_EMIT: '1',
    ALLOWED_ORIGINS: 'http://tauri.localhost,tauri://localhost',
  });
  const up = await waitHealth(p4);
  ok(up, '桌面模式引擎可启动');
  const m = /ENGINE_TOKEN=([a-f0-9]{64})/.exec(h.out);
  const post = (origin) => new Promise((res) => {
    const body = JSON.stringify({});
    const r = http.request(
      { host: '127.0.0.1', port: p4, method: 'POST', path: '/api/scan/aaaaaaaaaa/stop',
        headers: { 'content-type': 'application/json', 'content-length': body.length, origin, 'x-api-token': m ? m[1] : '' } },
      (resp) => { resp.resume(); res(resp.statusCode); }
    );
    r.on('error', () => res(0));
    r.write(body); r.end();
  });
  const tauriOrigin = await post('http://tauri.localhost');
  ok(tauriOrigin !== 403, 'Tauri origin 的变更请求不被 CSRF 拦截（≠403）', `实际 ${tauriOrigin}`);
  const evilOrigin = await post('http://evil.example');
  ok(evilOrigin === 403, '恶意 origin 仍被拦截 → 403', `实际 ${evilOrigin}`);
  stop(h.child);
}

console.log(failed === 0 ? '\n[结果] 全部通过' : `\n[结果] ${failed} 项失败`);
process.exit(failed === 0 ? 0 : 1);
