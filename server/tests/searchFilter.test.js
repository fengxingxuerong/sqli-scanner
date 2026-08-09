// --search 关键字搜索（表名/列名枚举后过滤）测试
//
// 覆盖：
//  1) filterBySearch 纯函数（空关键字不过滤 / 大小写不敏感 / 部分匹配 / 无匹配 / 空输入）
//  2) 真实 SQLite 靶机 e2e：--search 端到端过滤表名+列名，且「无匹配」对照证明过滤真实发生
import http from 'node:http';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { filterBySearch } from '../src/engine/Extractor.js';
import { ScanManager } from '../src/engine/ScanManager.js';

// ===== 1. filterBySearch 纯函数 =====
test('filterBySearch: 空关键字原样返回（不过滤）', () => {
  assert.deepEqual(filterBySearch(['users', 'admin'], null), ['users', 'admin']);
  assert.deepEqual(filterBySearch(['users', 'admin'], ''), ['users', 'admin']);
  assert.deepEqual(filterBySearch(['users', 'admin'], undefined), ['users', 'admin']);
});

test('filterBySearch: 大小写不敏感包含匹配', () => {
  assert.deepEqual(filterBySearch(['Users', 'Admin'], 'user'), ['Users']);
  assert.deepEqual(filterBySearch(['USERNAME', 'id'], 'Name'), ['USERNAME']);
});

test('filterBySearch: 部分子串匹配（如 name 命中 username）', () => {
  assert.deepEqual(filterBySearch(['username', 'email', 'id'], 'name'), ['username']);
  assert.deepEqual(filterBySearch(['col1', 'col2', 'col3'], '2'), ['col2']);
});

test('filterBySearch: 无匹配返回空数组', () => {
  assert.deepEqual(filterBySearch(['users', 'admin'], 'zzz'), []);
  assert.deepEqual(filterBySearch([], 'x'), []);
});

// ===== 2. 真实 SQLite 靶机 e2e =====
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

async function runScan(targetUrl, config) {
  const mgr = new ScanManager();
  const scanId = await mgr.start({ url: targetUrl, method: 'GET', config });
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
  if (!report) throw new Error('扫描超时未完成');
  return report;
}

const BASE = {
  enableExtract: true,
  techniques: ['union', 'error', 'boolean', 'time'],
  concurrency: 1,
  ratePerSec: 50,
  maxColumnsGuess: 10,
  blindRobust: { enabled: false },
};

// enumerateColumns 返回 `name:TYPE`（如 email:TEXT），dumpData 以该全串为行键。
// 测试统一剥离 :TYPE 后缀后再比对，避免与扫描器列命名契约耦合。
const stripType = (s) => String(s).split(':')[0];
const normCols = (arr) => (arr || []).map(stripType);
const normRows = (rows) =>
  (rows || []).map((row) => {
    const o = {};
    for (const k of Object.keys(row)) o[stripType(k)] = row[k];
    return o;
  });

test('真实靶机：-search 表名/列名枚举后过滤（含无匹配对照）', async () => {
  const { server, port } = await startVulnTarget();
  const url = `http://127.0.0.1:${port}/?id=1`;

  // CASE 0: 无 search（对照，导出全部 4 列）
  const r0 = await runScan(url, { ...BASE });
  assert.equal(r0.dbms, 'SQLite');
  assert.deepEqual(normCols(r0.data.columns['main.users']).sort(), ['email', 'id', 'password', 'username']);
  const r0rows = normRows(r0.data.rows['main.users']);
  assert.equal(r0rows.length, 3);
  assert.equal(r0rows[0].username, 'alice');

  // CASE A: --search user → 表 users 保留（users 含 user），列只剩 username
  const rA = await runScan(url, { ...BASE, search: 'user' });
  assert.deepEqual(rA.data.tables.main, ['users'], '表名过滤：users 含 user 应保留');
  assert.deepEqual(normCols(rA.data.columns['main.users']), ['username'], '列名过滤：仅 username 含 user');
  // 导出行的键应只有 username
  const rArows = normRows(rA.data.rows['main.users']);
  const row0 = rArows[0];
  assert.ok('username' in row0, '行应含 username 键');
  assert.ok(!('email' in row0) && !('id' in row0) && !('password' in row0), '行不应含被过滤掉的列');
  assert.equal(row0.username, 'alice');

  // 同时反证：带 :TYPE 后缀的列串确实参与过滤（user 命中 username:*）
  assert.equal(rA.data.columns['main.users'].length, 1);
  assert.ok(rA.data.columns['main.users'][0].startsWith('username:'), '过滤后列串以 username: 开头');

  // CASE B: --search zzz（无匹配）→ 0 表导出（证明过滤真实发生，而非 search 被忽略）
  const rB = await runScan(url, { ...BASE, search: 'zzz' });
  assert.deepEqual(rB.data.tables.main, [], '无匹配表名 → 导出表列表应为空');
  assert.deepEqual(rB.data.rows['main.users'] || [], [], '无匹配 → 行应为空');

  server.close();
});
