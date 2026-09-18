// ============================================================================
// e2e/oob-real-lab/lab-app.mjs —— OOB 带外通道真机靶场（真实 PostgreSQL 16.2）
// 场景设计（模拟无回显 + WAF 的最难场景）：
//   /oob?id=1  —— 数值型注入点，查询结果不回显（盲），页面恒定
//                 payload 里若带 SLEEP/报错/union 会被 CRS 拦（无 WAF 情况另行对照）
// 目标 DB 以超管运行 COPY TO PROGRAM 'curl {CALLBACK}' → 数据库进程真实发起 HTTP 回连
// → 引擎 oobReceiver（127.0.0.1:8899）收到 /oob/:token → OobDetector 判定命中。
// 全链路：引擎 payload → HTTP 靶场 → PG 执行 → OS curl 回连 → 接收端捕获 → 检出。
// ============================================================================
import { createRequire } from 'node:module';
const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = _require('express');
const pg = _require('pg');
const { Client, Pool } = pg;

// [2026-09-18] 连接参数改读环境变量：默认值不变（127.0.0.1:5432/postgres/postgres），
// 但可指向其他 PG 部署（如 e2e/run-with-pg.py 拉起的本机 pg-smoke 实例，
// 其 pg_hba.conf 为 trust 认证，密码被忽略）。
const PG_CONF = {
  host: process.env.PGHOST || '127.0.0.1',
  port: Number(process.env.PGPORT) || 5432,
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD ?? 'postgres',
  database: process.env.PGDATABASE || 'oob_lab',
};

export async function initDb() {
  const c = new Client({ ...PG_CONF, database: 'postgres' });
  await c.connect();
  await c.query("SELECT 'CREATE DATABASE oob_lab' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'oob_lab')").catch(() => {});
  try { await c.query('CREATE DATABASE oob_lab'); } catch { /* 已存在 */ }
  await c.end();
  const c2 = new Client(PG_CONF);
  await c2.connect();
  await c2.query('DROP TABLE IF EXISTS users');
  await c2.query('CREATE TABLE users (id INT PRIMARY KEY, name TEXT, secret TEXT)');
  for (let i = 1; i <= 5; i++) await c2.query('INSERT INTO users VALUES ($1, $2, $3)', [i, `user${i}`, `sec-${i}`]);
  await c2.end();
}

// 单连接顺序执行（COPY TO PROGRAM 需要会话一致性；多语句注入用 simple query 协议）
let pool = null;
function getPool() {
  if (!pool) pool = new Pool({ ...PG_CONF, max: 8 });
  return pool;
}
export function createOobLabApp({ waf = true } = {}) {
  const app = express();
  app.use(express.urlencoded({ extended: true }));

  if (waf) {
    // 简化 WAF：拦含 SLEEP/BENCHMARK/WAITFOR/extractvalue/union select 的 payload，
    // 不拦 COPY（OOB 通道的价值正是绕过此类基于报错/union/时间特征的拦截）
    const BLOCK_RE = /sleep\s*\(|benchmark\s*\(|waitfor|extractvalue|updatexml|union\s+select/i;
    app.use((req, res, next) => {
      const vals = Object.values(req.query).join(' ') + ' ' + Object.values(req.body || {}).join(' ');
      if (BLOCK_RE.test(vals)) {
        res.status(403).send('<!DOCTYPE html><html><body><h1>403</h1><p>Request blocked by lab WAF</p></body></html>');
        return;
      }
      next();
    });
  }

  // 无回显注入点（字符串上下文）：结果集不渲染（恒定页面），只有 OOB 回连能证明注入。
  // 用 name='${id}' 字符串包裹：与 PG OOB 模板 {ORIG}'; COPY... 的引号闭合形态匹配。
  app.get('/oob', async (req, res) => {
    const name = req.query.name || 'user1';
    try {
      await getPool().query(`SELECT * FROM users WHERE name = '${name}'`);
      res.send('<!DOCTYPE html><html><head><title>Done</title></head><body><p>request processed</p></body></html>');
    } catch (e) {
      // 报错也不回显内容（最难场景：无回显 + 无报错 + 无时间差异 → 只有 OOB）
      res.send('<!DOCTYPE html><html><head><title>Done</title></head><body><p>request processed</p></body></html>');
    }
  });

  // [pg-osshell 闭环 2026-09-14] 有回显数值型注入点：os-shell（COPY FROM PROGRAM 落表
  // 再 UNION 回显）需要一个能把查询结果渲染出来的点。/oob 是恒定页盲点（OOB 专用），
  // 走不了 COPY 落表回读。/shell?id= 数值型直拼，结果表渲染（真实回显）。
  app.get('/shell', async (req, res) => {
    const id = req.query.id || '1';
    try {
      const { rows } = await getPool().query(`SELECT id, name, secret FROM users WHERE id = ${id}`);
      const rowsHtml = (rows || [])
        .map((r) => `<tr><td>${r.id ?? ''}</td><td>${r.name ?? ''}</td><td>${r.secret ?? ''}</td></tr>`)
        .join('');
      res.send(`<!DOCTYPE html><html><head><title>shell-pt</title></head><body><h1>user detail</h1><table border="1"><tr><th>id</th><th>name</th><th>secret</th></tr>${rowsHtml}</table></body></html>`);
    } catch (e) {
      res.status(500).send(`Query error: ${e.message}`);
    }
  });

  return { app, close: async () => { if (pool) await pool.end().catch(() => {}); pool = null; } };
}
