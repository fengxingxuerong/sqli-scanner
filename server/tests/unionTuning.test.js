// UNION 调优（对标 sqlmap --union-cols / --union-char）测试
//
// 覆盖：
//  1) resolveUnionColumns 纯函数各分支（null / 精确值 / 范围 / 逆序 / 无效）
//  2) UnionDetector 接入 --union-cols 精确值 → 跳过 ORDER BY 枚举（orderBy 计数=0）
//  3) UnionDetector 接入 --union-cols 范围 → 约束枚举上下界（有界且命中真实列数）
//  4) UnionDetector 接入 --union-char → 标记基串被覆盖（不再用默认 SQLISCANNER）
//  5) discoverEchoColumns 接入 --union-char（单元级）
//  6) 真实 SQLite 靶机端到端：--union-cols 精确值下完整检测+指纹+拖库不回归
import http from 'node:http';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { resolveUnionColumns, discoverEchoColumns } from '../src/engine/injection.js';
import { UnionDetector } from '../src/engine/detectors/UnionDetector.js';
import { ScanManager } from '../src/engine/ScanManager.js';

// ===== 1. resolveUnionColumns 纯函数分支 =====
test('resolveUnionColumns: 各分支解析正确', () => {
  assert.equal(resolveUnionColumns(null), null);
  assert.equal(resolveUnionColumns({}), null);
  assert.deepEqual(resolveUnionColumns({ unionCols: 5 }, 50), { exact: 5 });
  assert.deepEqual(resolveUnionColumns({ unionCols: '5' }, 50), { exact: 5 });
  assert.deepEqual(resolveUnionColumns({ unionCols: ' 5 ' }, 50), { exact: 5 });
  assert.deepEqual(resolveUnionColumns({ unionCols: '3-8' }, 50), { min: 3, max: 8 });
  // 逆序自动归一化
  assert.deepEqual(resolveUnionColumns({ unionCols: '8-3' }, 50), { min: 3, max: 8 });
  // 无法解析 → 退回 null（由调用方忽略，走默认枚举）
  assert.equal(resolveUnionColumns({ unionCols: 'abc' }, 50), null);
  assert.equal(resolveUnionColumns({ unionCols: '3-' }, 50), null);
});

// ===== mock 靶机（回显注入值；ORDER BY 越界 500）=====
function makeUnionMock(realColumns, calls) {
  return {
    async request(opts) {
      const url = opts.url || '';
      const q = decodeURIComponent(typeof url === 'string' ? url : '').replace(/\+/g, ' ');
      const m = q.match(/[?&]q=([^&]*)/);
      const injected = m ? m[1] : '';
      if (/ORDER BY/i.test(injected)) {
        if (calls) calls.orderBy++;
        const n = Number(injected.match(/ORDER BY (\d+)/i)[1]);
        if (n > realColumns) return { status: 500, data: 'ERR', headers: {} };
        return { status: 200, data: 'normal page body '.repeat(5), headers: {} };
      }
      return { status: 200, data: `echo:${injected}`, headers: {} };
    },
  };
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: {
      method: 'GET',
      baseUrl: 'http://mock/?q=1',
      headerParams: {},
      cookieParams: {},
      config: {},
    },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, timeThresholdMs: 800, maxColumnsGuess: 50 },
    ...overrides,
  };
}

// ===== 2. --union-cols 精确值：跳过 ORDER BY 枚举 =====
test('UnionDetector --union-cols 精确值跳过 ORDER BY 枚举', async () => {
  const calls = { orderBy: 0 };
  const httpClient = makeUnionMock(4, calls);
  const d = new UnionDetector();
  const ctx = buildCtx(httpClient, {
    config: { timeoutMs: 5000, timeThresholdMs: 800, maxColumnsGuess: 50, unionCols: '4' },
  });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true, '精确列数下应命中 UNION');
  assert.equal(calls.orderBy, 0, '精确列数不应发任何 ORDER BY 探测（直接省掉枚举请求）');
  assert.equal(ctx.point.columns, 4, 'columns 应直接等于精确值 4');
  assert.deepEqual(ctx.point.echoCols, [0, 1, 2, 3]);
});

// ===== 3. --union-cols 范围：约束枚举上下界 =====
test('UnionDetector --union-cols 范围约束枚举上下界', async () => {
  const calls = { orderBy: 0 };
  const httpClient = makeUnionMock(4, calls); // 真实列数 4（落在 [3,8] 内）
  const d = new UnionDetector();
  const ctx = buildCtx(httpClient, {
    config: { timeoutMs: 5000, timeThresholdMs: 800, maxColumnsGuess: 50, unionCols: '3-8' },
  });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.ok(calls.orderBy > 0, '范围模式仍应发 ORDER BY 探测');
  assert.ok(calls.orderBy <= 6, `范围枚举应有界（实测 ${calls.orderBy} 次，应 ≤6）`);
  assert.equal(ctx.point.columns, 4, '范围枚举应找到真实列数 4');
});

// ===== 4. --union-char：覆盖标记基串 =====
test('UnionDetector --union-char 覆盖标记基串', async () => {
  const seen = [];
  const httpClient = {
    async request(opts) {
      const q = decodeURIComponent(opts.url || '').replace(/\+/g, ' ');
      const m = q.match(/[?&]q=([^&]*)/);
      const injected = m ? m[1] : '';
      seen.push(injected);
      if (/ORDER BY/i.test(injected)) {
        const n = Number(injected.match(/ORDER BY (\d+)/i)[1]);
        if (n > 4) return { status: 500, data: 'ERR', headers: {} };
        return { status: 200, data: 'normal page body '.repeat(5), headers: {} };
      }
      return { status: 200, data: `echo:${injected}`, headers: {} };
    },
  };
  const d = new UnionDetector();
  const ctx = buildCtx(httpClient, {
    config: { timeoutMs: 5000, timeThresholdMs: 800, maxColumnsGuess: 4, unionChar: 'MYMARK' },
  });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.ok(seen.some((s) => /MYMARK0/.test(s)), '应注入 MYMARK 标记');
  assert.ok(!seen.some((s) => /SQLISCANNER/.test(s)), '不应再用默认 SQLISCANNER 标记');
  assert.deepEqual(ctx.point.echoCols, [0, 1, 2, 3]);
});

// ===== 5. discoverEchoColumns 接入 --union-char（单元级）=====
test('discoverEchoColumns --union-char 覆盖标记基串（单元）', async () => {
  const httpClient = {
    async request(opts) {
      const q = decodeURIComponent(opts.url || '').replace(/\+/g, ' ');
      const m = q.match(/[?&]q=([^&]*)/);
      const injected = m ? m[1] : '';
      return { status: 200, data: `echo:${injected}`, headers: {} };
    },
  };
  const ctx = buildCtx(httpClient, { config: { unionChar: 'ZZZ' } });
  const hits = await discoverEchoColumns(httpClient, ctx, 3);
  assert.deepEqual(hits, [0, 1, 2], '自定义基串 ZZZ 下应定位全部 3 个回显列');
});

// ===== 6. 真实 SQLite 靶机端到端：--union-cols 精确值不回归 =====
function startVulnTarget() {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)');
  const ins = db.prepare('INSERT INTO users(id, username, email, password) VALUES(?,?,?,?)');
  ins.run(1, 'alice', 'alice@example.com', 'secret1');
  ins.run(2, 'bob', 'bob@example.com', 'secret2');
  ins.run(3, 'carol', 'carol@example.com', 'secret3');

  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://mock/');
    const id = u.searchParams.get('id') || '1';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    let html = '<html><body>';
    try {
      const rows = db
        .prepare(`SELECT id, username, email FROM users WHERE id = ${id}`)
        .all();
      for (const r of rows) {
        html += `<div class="user">id=${r.id} name=${r.username} email=${r.email}</div>`;
      }
    } catch {
      res.statusCode = 500;
      res.end('SQL error');
      return;
    }
    html += '</body></html>';
    res.statusCode = 200;
    res.end(html);
  });

  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }))
  );
}

test('真实靶机 + --union-cols 精确值：端到端检测+指纹+拖库不回归', async () => {
  const { server, port } = await startVulnTarget();
  const targetUrl = `http://127.0.0.1:${port}/?id=1`;

  const mgr = new ScanManager();
  const scanId = await mgr.start({
    url: targetUrl,
    method: 'GET',
    config: {
      enableExtract: true,
      techniques: ['union', 'error', 'boolean', 'time'],
      concurrency: 1,
      ratePerSec: 50,
      maxColumnsGuess: 10,
      unionCols: '3', // 精确值（等于靶机真实列数 3），跳过 ORDER BY 枚举
      blindRobust: { enabled: false },
    },
  });

  let report = null;
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const r = mgr.getReport(scanId);
    if (r && r.finishedAt) {
      report = r;
      break;
    }
    await new Promise((res) => setTimeout(res, 300));
  }
  server.close();
  assert.ok(report, '扫描未在限定时间内完成');

  assert.equal(report.dbms, 'SQLite', `指纹应识别为 SQLite，实际 ${report.dbms}`);
  const techniques = report.vulns.map((v) => v.technique);
  assert.ok(techniques.includes('union'), `应检出 union，实际 ${JSON.stringify(techniques)}`);
  assert.deepEqual(report.data.databases, ['main'], 'SQLite 库名应为 main');
  assert.deepEqual(report.data.tables.main, ['users'], '应枚举出 users 表');
  assert.equal(report.data.rows['main.users'].length, 3, '应拖出 3 行');
  assert.equal(report.riskLevel, 'Critical');
});
