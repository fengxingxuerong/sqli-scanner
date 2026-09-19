// 端到端测试 + API 契约测试
// 1) 用 Node 内置 http 起一个自包含、无需外部数据库的 mock 易受攻击目标
// 2) 启动引擎 server/index.js（监听 4567）
// 3) POST /api/scan/start 指向 mock 目标，GET 报告，断言检测到注入
// 4) 校验 /health、/api/health、/api/payloads 契约
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

const SERVER_DIR = path.dirname(fileURLToPath(new URL('../index.js', import.meta.url)));
const INDEX_JS = path.join(SERVER_DIR, 'index.js');

// [ENV-COUPLING-FIX 2026-09-19] 旧实现把引擎端口**写死 4567 且复用**该端口上已存在的进程：
// 只要本机跑着一个带 SCAN_API_TOKEN 的实例（手动起的 server / 桌面版 sidecar / 上一次门禁残留），
// 受保护端点就全部返 401，而本文件断言的是 2001 —— 稳定假红，且与被测代码毫无关系
// （实测：另起一个无 token 实例请求同一路径返回 {"code":2001}，证明引擎契约本身没问题）。
// 现改为三条：① 取空闲端口（不再与任何常驻实例抢 4567）；② 自己 spawn 一个带一次性 token
// 的实例（不再复用别人的进程）；③ 所有请求显式带 token。
// 副作用是好的：鉴权链路顺带被真实覆盖，见下方「鉴权契约」两条用例。
let ENGINE_PORT = 0;
let ENGINE_BASE = '';
let ENGINE_TOKEN = '';

let child = null;
let mockServer = null;

// ===== 工具 =====
// 默认带 token；显式传 `{}` 表示「不带任何凭据」（用于断言 401）
function authHeaders(headers) {
  return headers || { 'x-api-token': ENGINE_TOKEN };
}

function getJson(urlStr, headers) {
  return new Promise((resolve, reject) => {
    http
      .get(urlStr, { headers: authHeaders(headers) }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            reject(new Error(`无法解析 JSON: ${body.slice(0, 200)}`));
          }
        });
      })
      .on('error', reject);
  });
}

function postJson(urlStr, payload, headers) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const u = new URL(urlStr);
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
          ...authHeaders(headers),
        },
      },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            reject(new Error(`无法解析 JSON: ${body.slice(0, 200)}`));
          }
        });
      }
    );
    req.on('error', reject);
    req.end(data);
  });
}

async function waitForHealth(base, timeoutMs = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await getJson(`${base}/health`);
      if (r && r.code === 0) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('引擎健康检查超时');
}

// 向内核要一个空闲端口：先 listen(0) 拿到再关闭交给子进程。
// 存在极小的时间窗被别的进程抢占，届时 spawn 会 EADDRINUSE → waitForHealth 超时并给出明确错误，
// 不会像旧实现那样「静默连上一个来路不明的引擎」。
function pickFreePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

async function startEngine() {
  ENGINE_PORT = await pickFreePort();
  ENGINE_BASE = `http://127.0.0.1:${ENGINE_PORT}`;
  ENGINE_TOKEN = randomBytes(24).toString('hex');
  child = spawn(process.execPath, [INDEX_JS], {
    cwd: SERVER_DIR,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(ENGINE_PORT),
      // 一次性 token：本实例专属，不读宿主环境里可能存在的 SCAN_API_TOKEN
      SCAN_API_TOKEN: ENGINE_TOKEN,
    },
    stdio: 'ignore',
  });
  child.on('error', (e) => {
    throw new Error(`启动引擎失败: ${e.message}`);
  });
  await waitForHealth(ENGINE_BASE);
}

// ===== mock 易受攻击目标 =====
// 行为：① 回显参数 ② 报错特征 ③ 布尔差异 ④ 时间延迟
function startMockTarget() {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://mock/');
    const q = u.searchParams.get('q') || '';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    const send = (body, status = 200) => {
      res.statusCode = status;
      res.end(body);
    };

    // ④ 时间延迟
    const sleepMatch = q.match(/SLEEP\((\d+)\)|pg_sleep\((\d+)\)|WAITFOR DELAY '0:0:(\d+)'/);
    if (sleepMatch) {
      const secs = Number(sleepMatch[1] || sleepMatch[2] || sleepMatch[3] || 2);
      setTimeout(() => send(`delayed ${secs}s`), secs * 1000);
      return;
    }
    // ② 报错特征
    if (/extractvalue|updatexml|SLEEP|pg_sleep|WAITFOR/i.test(q)) {
      return send('You have an error in your SQL syntax near ...', 200);
    }
    // ③ 布尔差异
    if (/1=2|'1'='2/.test(q)) return send('NO_RESULTS', 200);
    if (/1=1|'1'='1/.test(q)) return send('HAS_RESULTS', 200);
    // ORDER BY 模拟列数超出 → 短错误（让指纹/列数探测提前结束）
    if (/ORDER BY/i.test(q)) return send('ERR', 500);
    // ① 回显
    return send(`<html><body>Result: ${q}</body></html>`, 200);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

// ===== 生命周期 =====
before(async () => {
  mockServer = await startMockTarget();
  await startEngine();
});

after(() => {
  if (mockServer) mockServer.close();
  if (child) child.kill();
});

// ===== API 契约 =====
test('API 契约：GET /health 与 /api/health', async () => {
  const h1 = await getJson(`${ENGINE_BASE}/health`);
  const h2 = await getJson(`${ENGINE_BASE}/api/health`);
  for (const h of [h1, h2]) {
    assert.equal(h.code, 0);
    assert.equal(h.data.status, 'up');
    assert.equal(h.data.version, '1.0.0');
    assert.equal(h.message, 'ok');
  }
});

test('API 契约：GET /api/payloads?dbms=MySQL&technique=union', async () => {
  const r = await getJson(`${ENGINE_BASE}/api/payloads?dbms=MySQL&technique=union`);
  assert.equal(r.code, 0);
  assert.ok(Array.isArray(r.data), 'data 应为数组');
  // 深度扩充后 union 变体 >=8（对标 sqlmap 深度）；兼容 UNION ALL SELECT 变体
  assert.ok(r.data.length >= 8, `MySQL union 变体应 >=8，实际 ${r.data.length}`);
  assert.ok(r.data.every((p) => p.includes('UNION SELECT') || p.includes('UNION ALL SELECT')));
});

test('API 契约：GET /api/payloads?dbms=PostgreSQL 返回全部技术', async () => {
  const r = await getJson(`${ENGINE_BASE}/api/payloads?dbms=PostgreSQL`);
  assert.equal(r.code, 0);
  assert.ok(r.data.union && r.data.error && r.data.boolean && r.data.time);
});

test('API 契约：未知 scanId 返回 SCAN_NOT_FOUND', async () => {
  const r = await getJson(`${ENGINE_BASE}/api/scan/nonexistent/report`);
  assert.equal(r.code, 2001);
  assert.equal(r.data, null);
});

// ===== 鉴权契约（本实例自带一次性 token，可确定性断言）=====
// 这两条同时是上面 ENV-COUPLING-FIX 的回归钉：旧实现复用外部 4567 实例，
// 遇到带 token 的实例时下面第一条会拿到 401、第二条会拿到 2001 —— 全靠外部环境掷骰子。
test('鉴权：不带 token 访问受保护端点应 401', async () => {
  const r = await getJson(`${ENGINE_BASE}/api/scan/nonexistent/report`, {});
  assert.equal(r.code, 401, '受保护端点在无凭据时必须拒绝');
});

test('鉴权：带错 token 访问受保护端点应 401', async () => {
  const r = await getJson(`${ENGINE_BASE}/api/scan/nonexistent/report`, {
    'x-api-token': 'definitely-not-the-token',
  });
  assert.equal(r.code, 401);
});

// ===== 端到端检测 =====
test('端到端：引擎真实检测注入并产出报告', async (t) => {
  const mockPort = mockServer.address().port;
  const mockUrl = `http://127.0.0.1:${mockPort}/search?q=1`;

  // 启动扫描（指向 mock 目标，关闭提取以提速）
  const startRes = await postJson(`${ENGINE_BASE}/api/scan/start`, {
    url: mockUrl,
    method: 'GET',
    config: { enableExtract: false, concurrency: 1, ratePerSec: 20 },
  });
  assert.equal(startRes.code, 0);
  assert.ok(
    typeof startRes.data.scanId === 'string' && startRes.data.scanId.length > 0,
    '应返回 scanId'
  );
  const scanId = startRes.data.scanId;

  // 轮询报告直到完成
  let report = null;
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const r = await getJson(`${ENGINE_BASE}/api/scan/${scanId}/report`);
    if (r.code === 0 && r.data && r.data.finishedAt) {
      report = r.data;
      break;
    }
    await new Promise((res) => setTimeout(res, 300));
  }
  assert.ok(report, '扫描未在限定时间内完成');

  // 报告结构
  assert.equal(report.scanId, scanId);
  assert.ok(Array.isArray(report.points), 'points 应为数组');
  assert.ok(Array.isArray(report.vulns), 'vulns 应为数组');
  assert.ok(['Critical', 'High', 'Medium', 'Low'].includes(report.riskLevel));

  // 关键断言：至少识别出一种注入技术（检测管线真实生效，不是空跑）
  assert.ok(report.vulns.length >= 1, `应至少发现一个漏洞，实际 points=${JSON.stringify(report.points)}`);
  for (const v of report.vulns) {
    assert.ok(
      ['union', 'error', 'boolean', 'time'].includes(v.technique),
      `未知技术 ${v.technique}`
    );
    assert.ok(
      ['Critical', 'High', 'Medium', 'Low'].includes(v.riskLevel),
      `未知风险 ${v.riskLevel}`
    );
  }

  // 注入点应被标记为 confirmed
  const confirmed = report.points.filter((p) => p.confirmed);
  assert.ok(confirmed.length >= 1, '应有注入点被确认');
});
