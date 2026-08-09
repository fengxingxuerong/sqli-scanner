// 真实数据库后端拖库 e2e（对标 sqlmap 最有说服力的证据）
// 用 Node 内置 node:sqlite 起一个真实 SQLite 后端，外加一个"参数直接拼接进 SELECT 且回显 username 列"的
// 易受攻击 HTTP 靶机。拉起 ScanManager 对该靶机跑完整扫描（检测 → 指纹 → UNION 拖库），
// 断言引擎把 users 表数据端到端拖出（不依赖任何 mock 预言机，是真·真实数据库）。
//
// 关键契约（来自 Extractor.dumpData）：行以 '||' 分隔、列以 '|' 分隔；标量以 __S__...__E__ 包裹。
// 靶机把 username 列回显到 HTML，UNION 注入即可把标记/数据送到回显列。
import http from 'node:http';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { ScanManager } from '../src/engine/ScanManager.js';

// ===== 真实 SQLite 后端 + 易受攻击靶机 =====
function startVulnTarget() {
  const db = new DatabaseSync(':memory:');
  db.exec(
    'CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)'
  );
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
      // 漏洞：id 直接拼接进 SELECT（无引号包裹），经典 UNION/报错注入点
      const rows = db
        .prepare(`SELECT id, username, email FROM users WHERE id = ${id}`)
        .all();
      for (const r of rows) {
        // 回显 username 列（UNION 注入的回显列）
        html += `<div class="user">id=${r.id} name=${r.username} email=${r.email}</div>`;
      }
    } catch {
      // SQL 报错（含 ORDER BY 列数越界）→ 500 短响应，供二分猜列数作为"异常"信号
      res.statusCode = 500;
      res.end('SQL error');
      return;
    }
    html += '</body></html>';
    res.statusCode = 200;
    res.end(html);
  });

  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve({ server, port: server.address().port })
    )
  );
}

test('真实 SQLite 靶机：引擎端到端检测 UNION 注入并拖出 users 表', async () => {
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
      blindRobust: { enabled: false }, // e2e 关闭统计判定分支，加速且避免盲注误判噪声
    },
  });

  // 轮询报告直到完成
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

  // 1) 指纹正确识别 SQLite
  assert.equal(report.dbms, 'SQLite', `指纹应识别为 SQLite，实际 ${report.dbms}`);

  // 2) 至少检出 union 注入
  const techniques = report.vulns.map((v) => v.technique);
  assert.ok(techniques.includes('union'), `应检出 union，实际 ${JSON.stringify(techniques)}`);

  // 3) 真实拖库：SQLite 库名回到 'main'，表 'users'，行数=3 且含种子数据
  assert.ok(report.data, '应产出提取数据');
  assert.deepEqual(report.data.databases, ['main'], 'SQLite 库名应为 main');
  assert.deepEqual(report.data.tables.main, ['users'], '应枚举出 users 表');

  const rows = report.data.rows['main.users'];
  assert.ok(Array.isArray(rows), 'main.users 应为数组');
  assert.equal(rows.length, 3, `应拖出 3 行，实际 ${rows && rows.length}`);

  // 校验拖出的数据与真实库一致（验证不是 mock 造假）
  const byName = Object.fromEntries(rows.map((r) => [r.username, r]));
  assert.ok(byName.alice, '应含 alice');
  assert.equal(byName.alice.email, 'alice@example.com');
  assert.equal(byName.alice.password, 'secret1');
  assert.equal(byName.bob.password, 'secret2');
  assert.equal(byName.carol.email, 'carol@example.com');

  // 4) 因已拖出数据，报告风险应为 Critical
  assert.equal(report.riskLevel, 'Critical');
});
