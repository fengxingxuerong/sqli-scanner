// ============================================================================
// e2e/release/release-smoke.mjs —— 发布冒烟（沙箱）：**生产配置**下跑一遍完整链路
// 用法：node e2e/release/release-smoke.mjs
//
// 与既有门禁的区别（为什么要单独一个）：
//   · 单测/e2e 用的是「开发便利」配置（无 token、不托管前端）；
//   · 真实交付是「带 token + Express 托管 dist + 引擎常驻」——A1/A2 两个缺陷都只在这个
//     组合下才现形（Docker 白屏、鉴权生效性）。本脚本就把这个组合完整跑一遍。
//
// 覆盖：
//   ① 服务健康与鉴权（公开只读 200 / 受保护 401 / 跨站 403）
//   ② 静态托管与 CSP 分流（/ 与 /assets/*.js 必须放行 'self'，API 必须 'none'）
//   ③ 前端首页引用的资源全部可 200（模拟浏览器取资源，防 404 型白屏）
//   ④ 真实扫描（真 PostgreSQL/PGlite 靶场，非 mock）经 API 与 CLI 两条路径
//   ⑤ 交付物：五种报告格式非空 + JSON 可解析 + 退出码语义（2=发现高危）
//
// 依赖：无 MySQL（靶场用 PGlite）；前端需已构建（npm run build 产出 dist/）
// ============================================================================
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import http from 'node:http';
import crypto from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');

let failed = 0;
const ok = (cond, label, extra = '') => {
  console.log(`[${cond ? 'PASS' : 'FAIL'}] ${label}${extra ? '  ' + extra : ''}`);
  if (!cond) failed += 1;
};

// 全局看门狗：任何一步挂死都要留下非 0 退出，而不是把 CI 拖到超时（超时会被误读成"环境慢"）
const WATCHDOG = setTimeout(() => {
  console.log('\n[结果] 冒烟超时（>8min），强制退出');
  try { engine && engine.kill(); } catch { /* noop */ }
  process.exit(1);
}, 8 * 60 * 1000);
WATCHDOG.unref();

const SANDBOX = mkdtempSync(join(tmpdir(), 'sqli-release-smoke-'));
console.log(`[sandbox] 工作目录 ${SANDBOX}`);

function pickPort() {
  return new Promise((res) => {
    const s = http.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
  });
}

function req(port, method, path, { headers = {}, body = null } = {}) {
  return new Promise((res) => {
    const data = body === null ? null : Buffer.from(body);
    const r = http.request(
      { host: '127.0.0.1', port, method, path, headers: { ...(data ? { 'content-length': data.length } : {}), ...headers } },
      (resp) => {
        let buf = '';
        resp.setEncoding('utf8');
        resp.on('data', (c) => (buf += c));
        resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: buf }));
      }
    );
    r.on('error', (e) => res({ status: 0, error: e.message }));
    // 超时保护：http.request 默认无超时，服务端不回包会把整轮冒烟永久挂住（真踩过）
    r.setTimeout(15000, () => r.destroy(new Error('request timeout')));
    if (data) r.write(data);
    r.end();
  });
}

async function waitHealth(port, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = await req(port, 'GET', '/api/health').catch(() => ({ status: 0 }));
    if (r.status === 200) return true;
    await new Promise((r2) => setTimeout(r2, 300));
  }
  return false;
}

// ── ① 起靶场（真 PGlite PostgreSQL，不依赖 MySQL）────────────────────────────
const labPort = await pickPort();
const { createRealLabApp } = await import(pathToFileURL(resolve(ROOT, 'e2e/real-world-lab/lab-app.js')).href);
const labApp = await createRealLabApp({});
const labServer = await new Promise((r) => {
  const s = labApp.listen(labPort, '127.0.0.1', () => r(s));
});
ok(true, `靶场就绪 http://127.0.0.1:${labPort}（真 PostgreSQL/PGlite）`);

// ── ② 起引擎（生产配置：token + 托管 dist + 允许本地靶场）────────────────────
const hasDist = existsSync(resolve(ROOT, 'dist/index.html'));
ok(hasDist, '前端产物 dist/ 存在（静态托管前置）', hasDist ? '' : '请先 npm run build');

const enginePort = await pickPort();
const TOKEN = crypto.randomBytes(24).toString('hex');
const engine = spawn(process.execPath, [resolve(ROOT, 'server/index.js')], {
  env: {
    ...process.env,
    HOST: '127.0.0.1',
    PORT: String(enginePort),
    SCAN_API_TOKEN: TOKEN,
    // 靶场在回环：生产默认拒绝内网，这里显式放行（模拟"已授权的内网目标"）
    SSRF_ALLOW_PRIVATE: '1',
    EXPLOIT_ENABLED: '0',
    LOG_TO_FILE: '0',
  },
  cwd: resolve(ROOT, 'server'),
  stdio: ['ignore', 'pipe', 'pipe'],
});
let engineOut = '';
engine.stdout.on('data', (d) => (engineOut += d.toString()));
engine.stderr.on('data', (d) => (engineOut += d.toString()));

const up = await waitHealth(enginePort);
ok(up, `引擎以生产配置启动（token + 静态托管）http://127.0.0.1:${enginePort}`, up ? '' : engineOut.slice(-300));
if (!up) {
  labServer.close();
  console.log('\n[结果] 引擎未启动，后续断言跳过');
  process.exit(1);
}

// ── ③ 鉴权与跨站防护 ────────────────────────────────────────────────────────
const health = await req(enginePort, 'GET', '/api/health');
ok(health.status === 200, '公开只读端点 /api/health 无需 token → 200');

const noAuth = await req(enginePort, 'GET', '/api/scan/aaaaaaaaaa');
ok(noAuth.status === 401, '受保护端点无 token → 401', `实际 ${noAuth.status}`);

const withAuth = await req(enginePort, 'GET', '/api/scan/aaaaaaaaaa', { headers: { 'x-api-token': TOKEN } });
ok(withAuth.status === 200, '带正确 token → 200', `实际 ${withAuth.status}`);

const crossSite = await req(enginePort, 'POST', '/api/scan/start', {
  headers: { 'content-type': 'application/json', origin: 'http://evil.example', 'x-api-token': TOKEN },
  body: JSON.stringify({ target: { url: `http://127.0.0.1:${labPort}/items?cat=1` } }),
});
ok(crossSite.status === 403, '跨站变更请求（恶意 Origin）→ 403', `实际 ${crossSite.status}`);

// 路由同时挂在 /api 与 / 两个基址：放行静态外壳不能顺带把「不带 /api 前缀的 API」也放行
for (const p of ['/scan/aaaaaaaaaa', '/scan/aaaaaaaaaa/report', '/api/scan/aaaaaaaaaa']) {
  const r = await req(enginePort, 'GET', p);
  ok(r.status === 401, `API（非静态路径）${p} 无 token → 401`, `实际 ${r.status}`);
}

// ── ④ 静态托管与 CSP 分流（Docker 单端口部署的关键回归）──────────────────────
const rootHtml = await req(enginePort, 'GET', '/');
const cspRoot = rootHtml.headers['content-security-policy'] || '';
ok(
  rootHtml.status === 200 && /<!doctype html>/i.test(rootHtml.body),
  'GET / 返回前端 HTML',
  `status=${rootHtml.status} len=${rootHtml.body.length} head=${JSON.stringify(rootHtml.body.slice(0, 60))}`
);
ok(cspRoot.includes("'self'"), "静态首页 CSP 放行 'self'（不放行 = 浏览器白屏）", cspRoot.slice(0, 60));

const cspApi = (health.headers['content-security-policy'] || '');
ok(cspApi.includes("default-src 'none'"), "API 响应 CSP 仍为 default-src 'none'", cspApi.slice(0, 46));

const refs = [...rootHtml.body.matchAll(/(?:src|href)="(\/[^"]+)"/g)].map((m) => m[1]);
const assetChecks = await Promise.all(refs.map(async (p) => ({ p, r: await req(enginePort, 'GET', p) })));
const badAssets = assetChecks.filter(({ r }) => r.status !== 200);
ok(refs.length > 0 && badAssets.length === 0, '首页引用的静态资源全部 200（防 404 型白屏）',
  `引用 ${refs.length} 个，失败 ${badAssets.length}${badAssets.length ? '：' + badAssets.map((b) => b.p).join(',') : ''}`);

// ── ⑤ 真实扫描（API 路径 + CLI 路径）─────────────────────────────────────────
const TARGET = `http://127.0.0.1:${labPort}/items?cat=1`;

const started = await req(enginePort, 'POST', '/api/scan/start', {
  headers: { 'content-type': 'application/json', 'x-api-token': TOKEN },
  body: JSON.stringify({ target: { url: TARGET }, config: { enableExtract: false } }),
});
let scanId = null;
try { scanId = JSON.parse(started.body)?.data?.scanId || null; } catch { /* noop */ }
ok(!!scanId, 'API 启动扫描返回 scanId', scanId || started.body.slice(0, 80));

let apiVulns = -1;
if (scanId) {
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const rep = await req(enginePort, 'GET', `/api/scan/${scanId}`, { headers: { 'x-api-token': TOKEN } });
    let body = null;
    try { body = JSON.parse(rep.body)?.data || null; } catch { /* noop */ }
    // 报告对象本身没有 status 字段（status 在引擎 scans Map 上，黑盒不可见）；
    // 收尾标志是 applyValidity 写入的 validity + summary.verdict —— 出现即代表扫描已终结。
    const done = !!body && (!!body.validity || (body.summary && body.summary.verdict !== undefined));
    if (done) {
      apiVulns = Array.isArray(body.vulns) ? body.vulns.length : 0;
      ok(true, 'API 扫描完成（报告已带 validity/verdict，即收尾）');
      ok(apiVulns >= 1, `API 路径检出漏洞 ≥1 条（实际 ${apiVulns}）`);
      ok(typeof body.summary?.verdict === 'string', '报告含 verdict 字段（结论可信度）');
      break;
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  if (apiVulns < 0) ok(false, 'API 扫描在 60s 内未收尾（未见 validity/verdict）');
}

// CLI 交付路径（one-click-scan：扫描 + 五种报告落盘 + 退出码语义）
const outDir = join(SANDBOX, 'reports');
const cli = spawn(process.execPath, [resolve(ROOT, 'scripts/one-click-scan.mjs'), '-u', TARGET,
  '-o', outDir, '-F', 'html,json,markdown,sarif,csv'], {
  env: { ...process.env, SSRF_ALLOW_PRIVATE: '1', EXPLOIT_ENABLED: '0' },
  cwd: ROOT,
  stdio: ['ignore', 'pipe', 'pipe'],
});
let cliOut = '';
cli.stdout.on('data', (d) => (cliOut += d.toString()));
cli.stderr.on('data', (d) => (cliOut += d.toString()));
const cliCode = await new Promise((r) => cli.on('exit', r));
ok(cliCode === 2 || cliCode === 0, `one-click-scan 退出码语义正常（${cliCode}：2=发现高危/0=无高危）`,
  cliCode === 1 ? cliOut.slice(-300) : '');

for (const f of ['report.html', 'report.json', 'report.md', 'report.sarif', 'report.csv', 'manifest.json']) {
  const p = join(outDir, f);
  const good = existsSync(p) && statSync(p).size > 0;
  ok(good, `交付物 ${f} 存在且非空`, good ? `${statSync(p).size} B` : '');
}
const rp = join(outDir, 'report.json');
if (existsSync(rp)) {
  try {
    const j = JSON.parse(readFileSync(rp, 'utf8'));
    const n = Array.isArray(j.vulns) ? j.vulns.length : 0;
    ok(n >= 1, `CLI 报告 JSON 可解析且含漏洞 ≥1 条（实际 ${n}）`);
    ok(Array.isArray(j.vulns) && j.vulns.every((v) => !v.poc || typeof v.poc.curl === 'string'), '每条漏洞的 PoC 证据链结构完整');
  } catch (e) {
    ok(false, `report.json 解析失败：${e.message}`);
  }
}

// ── ⑥ 沙箱内不留敏感明文（引擎 stdout 不应出现 token）────────────────────────
ok(!engineOut.includes(TOKEN), '引擎日志/输出未回显 token 明文');

// ── 清理 ────────────────────────────────────────────────────────────────────
try { engine.kill(); } catch { /* noop */ }
labServer.close();
try { rmSync(SANDBOX, { recursive: true, force: true }); } catch { /* noop */ }
console.log(`[sandbox] 已清理 ${SANDBOX}`);

console.log(failed === 0 ? '\n[结果] 发布冒烟全部通过' : `\n[结果] ${failed} 项失败`);
process.exit(failed === 0 ? 0 : 1);
