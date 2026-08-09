// 强制 DBMS（--dbms）回归测试：跳过自动指纹，直接采用强制值，仍能检测+拖库
import http from 'node:http';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { ScanManager } from '../src/engine/ScanManager.js';

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
      const rows = db.prepare(`SELECT id, username, email FROM users WHERE id = ${id}`).all();
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

async function pollReport(mgr, scanId, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = mgr.getReport(scanId);
    if (r && r.finishedAt) return r;
    await new Promise((res) => setTimeout(res, 300));
  }
  return null;
}

test('强制 dbms：fp.fingerprint 不被调用，但仍能检测 union 并拖出 3 行', async () => {
  const { server, port } = await startVulnTarget();
  const targetUrl = `http://127.0.0.1:${port}/?id=1`;

  const mgr = new ScanManager();
  // 把指纹器换成"一旦被调用就抛错"的探针：若强制路径仍正常完成，证明 fingerprint 被跳过。
  let fingerprintCalled = false;
  mgr.fp = { fingerprint: async () => { fingerprintCalled = true; throw new Error('fp should be skipped'); } };

  const scanId = await mgr.start({
    url: targetUrl,
    method: 'GET',
    config: {
      dbms: 'SQLite',
      enableExtract: true,
      techniques: ['union', 'error', 'boolean', 'time'],
      concurrency: 1,
      ratePerSec: 50,
      maxColumnsGuess: 10,
      blindRobust: { enabled: false },
    },
  });

  const report = await pollReport(mgr, scanId);
  server.close();
  assert.ok(report, '扫描未完成');
  assert.equal(fingerprintCalled, false, '强制 dbms 时不应调用 fp.fingerprint');
  assert.equal(report.dbms, 'SQLite', `应直接采用强制值 SQLite，实际 ${report.dbms}`);
  const techniques = report.vulns.map((v) => v.technique);
  assert.ok(techniques.includes('union'), `应检出 union，实际 ${JSON.stringify(techniques)}`);
  assert.deepEqual(report.data.databases, ['main']);
  assert.deepEqual(report.data.tables.main, ['users']);
  const rows = report.data.rows['main.users'];
  assert.equal(rows.length, 3, `应拖出 3 行，实际 ${rows && rows.length}`);
  const byName = Object.fromEntries(rows.map((r) => [r.username, r]));
  assert.equal(byName.alice.password, 'secret1');
  assert.equal(report.riskLevel, 'Critical');
});

test('未指定 dbms：fp.fingerprint 正常被调用', async () => {
  const { server, port } = await startVulnTarget();
  const targetUrl = `http://127.0.0.1:${port}/?id=1`;

  const mgr = new ScanManager();
  let fingerprintCalled = false;
  const realFp = mgr.fp;
  mgr.fp = {
    fingerprint: async (ctx) => {
      fingerprintCalled = true;
      return realFp.fingerprint(ctx);
    },
  };

  const scanId = await mgr.start({
    url: targetUrl,
    method: 'GET',
    config: {
      enableExtract: false,
      techniques: ['union'],
      concurrency: 1,
      ratePerSec: 50,
      maxColumnsGuess: 10,
    },
  });
  const report = await pollReport(mgr, scanId);
  server.close();
  assert.ok(report, '扫描未完成');
  assert.equal(fingerprintCalled, true, '未指定 dbms 时应调用 fp.fingerprint');
});
