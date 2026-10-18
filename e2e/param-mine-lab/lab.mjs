// ============================================================================
// e2e/param-mine-lab/lab.mjs —— [D102] 参数挖掘（--param-mine）专测靶场（Express + 真 MySQL）
//
// 为什么单独一个靶场：既有靶场的注入点全部来自「URL/表单里**已出现**的参数」；参数挖掘
// 能力（Arjun 式字典猜测）的判据必须是「参数在链接/表单里**不存在**，只能靠字典猜出来」：
//   /api/items?id=1        —— 可见参数只有 id（参数化，安全）；隐藏参数 kw 仅当被猜中
//                             （?kw=...）才进入 SQL 字符串拼接 ⇒ 不开挖掘就整体漏检。
//   /api/safe?id=1         —— 同款隐藏参数 kw 但走占位符 ⇒ 挖到也不该检出（对照零点）。
//
// 真值不依赖本文件自报（判据在 run.mjs：开挖掘必须检出 kw、关挖掘零检出、安全点零检出）。
// 依赖：MySQL（自带幂等夹具：自建 parammine_lab.products + 种子；未就绪时 run.mjs 报 SKIP）。
//
// 用法：node e2e/param-mine-lab/lab.mjs          # 监听 8126
// ============================================================================

// 依赖解析：本目录没有独立 node_modules，统一从 server（引擎运行时依赖所在地）取，
// 与 redteam-lab / param-name-lab 同一做法（`createRequire` 指向 server/package.json）。
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = require('express');
const mysql = require('mysql2/promise');

const PORT = Number(process.env.PARAMMINE_LAB_PORT || 8126);
const DB = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || 'root',
  // 与 param-name-lab 同默认（本机 mysqld 的 root 口令是 root；sandbox 注入的 env 优先）
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: 'parammine_lab',
  charset: 'utf8mb4',
};

// 幂等自建夹具（与 param-name-lab / recall-lab 同惯例：只需要一个可连的 mysqld 就能跑）
const bootstrap = mysql.createPool({ host: DB.host, port: DB.port, user: DB.user, password: DB.password, connectionLimit: 1 });
try {
  await bootstrap.query('CREATE DATABASE IF NOT EXISTS parammine_lab CHARACTER SET utf8mb4');
  await bootstrap.query(`CREATE TABLE IF NOT EXISTS parammine_lab.products (
    id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(96) NOT NULL, category VARCHAR(48),
    price DECIMAL(10,2), stock INT DEFAULT 0) ENGINE=InnoDB`);
  await bootstrap.query(`INSERT IGNORE INTO parammine_lab.products (id, name, category, price, stock) VALUES
    (1,'Mechanical Keyboard','peripherals',499.00,12),
    (2,'Noise Cancel Headphone','audio',1299.00,5),
    (3,'USB-C Hub','peripherals',199.00,40),
    (4,'27 inch Monitor','display',1899.00,3),
    (5,'Webcam 1080p','video',289.00,18),
    (6,'Laptop Stand','accessories',89.00,60)`);
} catch (e) {
  console.error('[param-mine-lab] 夹具初始化失败（探针会 500 ⇒ run.mjs 报 SKIP）：', e && e.message);
} finally {
  await bootstrap.end().catch(() => {});
}

process.on('uncaughtException', (e) => console.error('[lab][uncaught]', e && e.message));
process.on('unhandledRejection', (e) => console.error('[lab][unhandledRejection]', e && (e.message || e)));

const pool = mysql.createPool({ ...DB, connectionLimit: 4, waitForConnections: true });
const app = express();

const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>${body}</body></html>`;
const rowsHtml = (rows) => rows.map((r) => `<p>${r.id} | ${r.name} | ${r.price}</p>`).join('') || '<p>NO_ROWS</p>';
const esc = (s) => String(s).replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));

// ── 漏洞点：隐藏参数 kw 进字符串拼接（可见参数 id 安全）──────────────────────
// 挖掘信号：kw 出现在请求里时页面回显 `Results for: <kw>` ⇒ 分组探测的随机标记被回显，
// 反射信号成立（哨兵参数不回显 ⇒ reflectsAll=false，不会退化）；不开挖掘时此分支永远
// 走不到（kw 从未出现在链接里），扫描器只能见到安全的 id。
app.get('/api/items', async (req, res) => {
  const kw = req.query.kw;
  if (kw !== undefined) {
    const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${kw}%' LIMIT 3`;
    try {
      const [rows] = await pool.query(sql);
      res.send(page('items', `<p>Results for: ${esc(kw)}</p>${rowsHtml(rows)}`));
    } catch {
      // 与既有靶场同口径：报错只回显「query failed」，不把 SQL 错误原文给出去
      res.status(200).send(page('items', `<p>Results for: ${esc(kw)}</p><p class="err">query failed</p>`));
    }
    return;
  }
  const sql = 'SELECT id, name, price FROM products WHERE id = ? LIMIT 3';
  try {
    const [rows] = await pool.query(sql, [String(req.query.id ?? '1')]);
    res.send(page('items', rowsHtml(rows)));
  } catch {
    res.status(200).send(page('items', '<p class="err">query failed</p>'));
  }
});

// ── 安全对照点：同款隐藏参数 kw（回显形态一致），但值走占位符 ────────────────
// 零检出才有证明力：证明「kw 会被挖出并进入探测」但参数化挡住了注入 —— 挖到 ≠ 必报。
app.get('/api/safe', async (req, res) => {
  const kw = req.query.kw;
  if (kw !== undefined) {
    const sql = 'SELECT id, name, price FROM products WHERE name LIKE ? LIMIT 3';
    try {
      const [rows] = await pool.query(sql, [`%${kw}%`]);
      res.send(page('safe', `<p>Results for: ${esc(kw)}</p>${rowsHtml(rows)}`));
    } catch {
      res.status(200).send(page('safe', `<p>Results for: ${esc(kw)}</p><p class="err">query failed</p>`));
    }
    return;
  }
  const sql = 'SELECT id, name, price FROM products WHERE id = ? LIMIT 3';
  try {
    const [rows] = await pool.query(sql, [String(req.query.id ?? '1')]);
    res.send(page('safe', rowsHtml(rows)));
  } catch {
    res.status(200).send(page('safe', '<p class="err">query failed</p>'));
  }
});

app.listen(PORT, '127.0.0.1', () => console.log(`[param-mine-lab] http://127.0.0.1:${PORT}`));
