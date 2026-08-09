// 端到端测试 + API 契约测试
// 1) 用 Node 内置 http 起一个自包含、无需外部数据库的 mock 易受攻击目标
// 2) 启动引擎 server/index.js（监听 4567）
// 3) POST /api/scan/start 指向 mock 目标，GET 报告，断言检测到注入
// 4) 校验 /health、/api/health、/api/payloads 契约
import http from 'node:http';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

const SERVER_DIR = path.dirname(fileURLToPath(new URL('../index.js', import.meta.url)));
const INDEX_JS = path.join(SERVER_DIR, 'index.js');
const ENGINE_PORT = 4567;
const ENGINE_BASE = `http://127.0.0.1:${ENGINE_PORT}`;

let child = null;
let spawned = false;
let mockServer = null;

// ===== 工具 =====
function getJson(urlStr) {
  return new Promise((resolve, reject) => {
    http
      .get(urlStr, (res) => {
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

function postJson(urlStr, payload) {
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

async function startEngine() {
  // 若已有引擎在跑则复用，否则新启动
  try {
    const r = await getJson(`${ENGINE_BASE}/health`);
    if (r && r.code === 0) return false;
  } catch {}
  child = spawn(process.execPath, [INDEX_JS], {
    cwd: SERVER_DIR,
    env: { ...process.env },
    stdio: 'ignore',
  });
  child.on('error', (e) => {
    throw new Error(`启动引擎失败: ${e.message}`);
  });
  await waitForHealth(ENGINE_BASE);
  return true;
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
  spawned = await startEngine();
});

after(() => {
  if (mockServer) mockServer.close();
  if (spawned && child) child.kill();
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
  assert.equal(r.data.length, 3);
  assert.ok(r.data.every((p) => p.includes('UNION SELECT')));
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
