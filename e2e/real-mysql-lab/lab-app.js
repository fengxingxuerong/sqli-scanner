// ============================================================================
// e2e/real-mysql-lab/lab-app.js —— 真实 MySQL 驱动靶场（8.0.28，mysql2 直连）
// ============================================================================
// 目的：补「真实环境验证」短板——mock lab 是语义模拟器，无真实 SQL 引擎行为
// （错误文本、时间盲注抖动、语法细节均不真实）。本靶场：
//   · mysql2 直连本机 MySQL 8.0.28（sqli_lab 库，root/root@3306）
//   · 每端点真实拼 SQL 执行，回显真实结果集 / 真实报错文本 / 真实 SLEEP 延迟
// 注入端点（开发者缺陷风格）：
//   GET /num?id=1          WHERE id = {v}            数值型（union/error/boolean/time 全可用）
//   GET /str?name=alice    WHERE username = '{v}'    字符串型（需 ' 闭合）
//   GET /like?q=key        WHERE title LIKE '%{v}%'  搜索型（% 闭合 + ' 闭合）
//   GET /orderby?sort=id   ORDER BY {v}              排序位置注入
//   GET /blind?uid=1       布尔差异（无报错回显：语法错误吞掉回空页）
//   GET /time?tid=1       仅时间通道（内容恒定，SLEEP 生效）
//   POST /stacked?i=1     堆叠：多条语句逐条执行（; 第二条 SLEEP）
// 安全对照（应 0 检出）：
//   GET /safe?id=1         参数化占位符（?）查询
//   GET /echo?key=abc     输入仅回显文本，不进 SQL
// 环境变量：MYSQL_LAB_PORT（默认 8140）、MYSQL_HOST/PORT/USER/PASSWORD/DATABASE
// ============================================================================
import { createRequire } from 'node:module';
const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = _require('express');
const mysql = _require('mysql2/promise');

const PORT = Number(process.env.MYSQL_LAB_PORT) || 8140;
const MYSQL_CONF = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root', // 空密码兼容（?? 而非 ||）
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
  connectionLimit: 8,
  // 多语句执行（堆叠端点需要）：仅本靶场演示，真实应用切勿开启
  multipleStatements: false,
};

export function createMysqlLabApp(pool, preMiddleware = null) {
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  // [P1] 可选前置中间件（如真实 WAF 规则引擎），必须先于业务路由注册才生效
  if (preMiddleware) app.use(preMiddleware);

  const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
  const html = (title, body) =>
    `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title></head><body><h1>${title}</h1>${body}</body></html>`;
  const table = (rows) => {
    if (!rows || rows.length === 0) return '<p>No results found.</p>';
    const cols = Object.keys(rows[0]);
    return `<table border="1"><tr>${cols.map((c) => `<th>${c}</th>`).join('')}</tr>${rows
      .map((r) => `<tr>${cols.map((c) => `<td>${r[c] ?? ''}</td>`).join('')}</tr>`)
      .join('\n')}</table>`;
  };

  // —— 数值型注入：WHERE id = {v} ——
  app.get('/num', wrap(async (req, res) => {
    const id = req.query.id || '1';
    const [rows] = await pool.query(`SELECT * FROM users WHERE id = ${id}`);
    res.send(html('User Detail', table(rows)));
  }));

  // —— 字符串型注入：WHERE username = '{v}' ——
  app.get('/str', wrap(async (req, res) => {
    const name = req.query.name || 'alice';
    const [rows] = await pool.query(`SELECT * FROM users WHERE username = '${name}'`);
    res.send(html('Profile', table(rows)));
  }));

  // —— 搜索型注入：LIKE '%{v}%' ——
  app.get('/like', wrap(async (req, res) => {
    const q = req.query.q || 'keyboard';
    const [rows] = await pool.query(`SELECT * FROM products WHERE title LIKE '%${q}%'`);
    res.send(html('Search', table(rows)));
  }));

  // —— ORDER BY 位置注入 ——
  app.get('/orderby', wrap(async (req, res) => {
    const sort = req.query.sort || 'id';
    const [rows] = await pool.query(`SELECT id, title, price FROM products ORDER BY ${sort}`);
    res.send(html('Products', table(rows)));
  }));

  // —— 布尔盲注：无报错回显（错误吞掉回空页），真假页差异 ——
  app.get('/blind', wrap(async (req, res) => {
    const uid = req.query.uid || '1';
    try {
      const [rows] = await pool.query(`SELECT * FROM users WHERE id = ${uid}`);
      res.send(html('Dashboard', rows.length ? table(rows) : '<p>empty</p>'));
    } catch {
      res.send(html('Dashboard', '<p>empty</p>')); // 永不 500：语法错误回空页
    }
  }));

  // —— 时间盲注：内容恒定，SLEEP 生效 ——
  app.get('/time', wrap(async (req, res) => {
    const tid = req.query.tid || '1';
    try {
      await pool.query(`SELECT * FROM users WHERE id = ${tid}`);
    } catch { /* 延迟语句在错误前已执行（MySQL SLEEP 语义） */ }
    res.send(html('Status', '<p>ok</p>'));
  }));

  // —— 堆叠注入：手动按 ; 拆分逐条执行（模拟允许多语句的驱动）——
  app.get('/stacked', wrap(async (req, res) => {
    const i = req.query.i || '1';
    const stmts = String(i).split(';').filter((s) => s.trim());
    for (const s of stmts) {
      try { await pool.query(s); } catch { /* 每条独立，错误不中断 */ }
    }
    res.send(html('Batch', `<p>executed ${stmts.length} statement(s)</p>`));
  }));

  // —— 安全对照 1：参数化占位符 ——
  app.get('/safe', wrap(async (req, res) => {
    const id = req.query.id || '1';
    const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [id]);
    res.send(html('User Detail (Safe)', table(rows)));
  }));

  // —— 安全对照 2：输入不进 SQL ——
  app.get('/echo', (req, res) => {
    const key = String(req.query.key ?? '');
    res.send(html('Echo', `<p>key = ${key.replace(/</g, '&lt;')}</p>`));
  });

  // 错误页（真实 MySQL 报错文本，供 ErrorDetector 识别）
  app.use((err, req, res, next) => {
    res.status(500).send(html('Error', `<pre>${String(err?.message ?? err).replace(/</g, '&lt;')}</pre>`));
  });
  return app;
}

// 直接运行入口
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
const _isMain = (() => {
  try { return process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; }
})();
if (_isMain) {
  const pool = mysql.createPool({ ...MYSQL_CONF, multipleStatements: true }); // 堆叠演示需要
  const app = createMysqlLabApp(pool);
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`[mysql-lab] http://127.0.0.1:${PORT}  mysql=${MYSQL_CONF.host}:${MYSQL_CONF.port}/${MYSQL_CONF.database}`);
    console.log('[mysql-lab] endpoints: /num /str /like /orderby /blind /time /stacked (vuln) | /safe /echo (clean)');
  });
}
