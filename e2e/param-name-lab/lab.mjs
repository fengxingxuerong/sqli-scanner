// ============================================================================
// e2e/param-name-lab/lab.mjs —— [D93] 参数名注入专测靶场（Express + 真 MySQL）
//
// 为什么单独一个靶场：既有 22 点 blackbox-lab 的每个点都是「值注入」，没有任何一处
// 把 **query 键名**拼进 SQL。参数名注入（SQLiDetector 同型）在真实系统里并不罕见：
//   `const col = Object.keys(req.query)[0]; SELECT ... WHERE ${col} = ?`
// 值走参数化 ⇒ 值注入扫不到，只有改键名能打。缺这个靶点，D93 的能力就没有真值证据。
//
// 真值不依赖本文件自报（判据在 run.mjs：vuln 端点必须检出、safe 端点必须零检出）。
// 依赖：MySQL（自带幂等夹具：自建 paramname_lab.products + 种子；未就绪时 run.mjs 报 SKIP 不计过）。
//
// 用法：node e2e/param-name-lab/lab.mjs          # 监听 8123
// ============================================================================

// 依赖解析：本目录没有独立 node_modules，统一从 server（引擎运行时依赖所在地）取，
// 与 redteam-lab 同一做法（`createRequire` 指向 server/package.json）。
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = require('express');
const mysql = require('mysql2/promise');

const PORT = Number(process.env.PARAMNAME_LAB_PORT || 8123);
const DB = {
  host: '127.0.0.1',
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || 'root',
  // 与 blackbox-lab 同默认（本机 mysqld 的 root 口令是 root；env.mjs 拉起的实例同此）
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: 'paramname_lab',
  charset: 'utf8mb4',
};

// [D95] 自带夹具（与 recall-lab 同惯例：只需要一个可连的 mysqld）——
// D93 版复用 blackbox_lab.products，但没跑过 blackbox-lab 的环境里整库不存在
// （CI acceptance 的 docker mysqld 就是这种环境）⇒ 探针失败 ⇒ 永久 SKIP、从不产生判据。
// 现改为幂等自建 paramname_lab（列结构与 blackbox_lab.products 一致），不跨靶场耦合。
const bootstrap = mysql.createPool({ host: DB.host, port: DB.port, user: DB.user, password: DB.password, connectionLimit: 1 });
try {
  await bootstrap.query('CREATE DATABASE IF NOT EXISTS paramname_lab CHARACTER SET utf8mb4');
  await bootstrap.query(`CREATE TABLE IF NOT EXISTS paramname_lab.products (
    id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(96) NOT NULL, category VARCHAR(48),
    price DECIMAL(10,2), stock INT DEFAULT 0) ENGINE=InnoDB`);
  await bootstrap.query(`INSERT IGNORE INTO paramname_lab.products (id, name, category, price, stock) VALUES
    (1,'Mechanical Keyboard','peripherals',499.00,12),
    (2,'Noise Cancel Headphone','audio',1299.00,5),
    (3,'USB-C Hub','peripherals',199.00,40),
    (4,'27 inch Monitor','display',1899.00,3),
    (5,'Webcam 1080p','video',289.00,18),
    (6,'Laptop Stand','accessories',89.00,60)`);
} catch (e) {
  console.error('[param-name-lab] 夹具初始化失败（探针会 500 ⇒ run.mjs 报 SKIP）：', e && e.message);
} finally {
  await bootstrap.end().catch(() => {});
}

process.on('uncaughtException', (e) => console.error('[lab][uncaught]', e && e.message));
process.on('unhandledRejection', (e) => console.error('[lab][unhandledRejection]', e && (e.message || e)));

const pool = mysql.createPool({ ...DB, connectionLimit: 4, waitForConnections: true });
const app = express();

const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>${body}</body></html>`;
const rowsHtml = (rows) => rows.map((r) => `<p>${r.id} | ${r.name} | ${r.price}</p>`).join('') || '<p>NO_ROWS</p>';

// ── 漏洞点：键名当列名（值参数化）────────────────────────────────────────────
// 真实写法：后台筛选器从 query 取「第一项」当排序列 / 过滤列，值本身走占位符。
// 注入生效形态：键名 = `name OR 1=1-- -` ⇒ `WHERE name OR 1=1-- - = ?`（注释吃掉尾部）。
app.get('/colfilter', async (req, res) => {
  const key = Object.keys(req.query)[0] || 'id';
  const val = req.query[key] ?? '1';
  const sql = `SELECT id, name, price FROM products WHERE ${key} = ? LIMIT 3`;
  try {
    const [rows] = await pool.query(sql, [String(val)]);
    res.send(page('colfilter', `<p>sql=${sql}</p>${rowsHtml(rows)}`));
  } catch {
    // 与 blackbox-lab 同口径：报错只回显「query failed」，不把 SQL 错误原文给出去
    // （否则 error 通道靠靶场回显自证，不是真检出）
    res.status(200).send(page('colfilter', `<p>sql=${sql}</p><p class="err">query failed</p>`));
  }
});

// ── 安全对照点：列名白名单（同样的键名拼接写法，但先校验）────────────────────
// 零检出才有证明力：证明「参数名点点位会被生成/探测」，但白名单挡住了注入。
app.get('/colfilter-safe', async (req, res) => {
  const raw = Object.keys(req.query)[0] || 'id';
  const ALLOW = new Set(['id', 'name', 'price']);
  const key = ALLOW.has(raw) ? raw : 'id';
  const val = req.query[raw] ?? '1';
  const sql = `SELECT id, name, price FROM products WHERE ${key} = ? LIMIT 3`;
  try {
    const [rows] = await pool.query(sql, [String(val)]);
    res.send(page('colfilter-safe', `<p>sql=${sql}</p>${rowsHtml(rows)}`));
  } catch {
    res.status(200).send(page('colfilter-safe', `<p>sql=${sql}</p><p class="err">query failed</p>`));
  }
});

app.listen(PORT, '127.0.0.1', () => console.log(`[param-name-lab] http://127.0.0.1:${PORT}`));
