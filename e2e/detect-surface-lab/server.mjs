// 检测面探针靶场（D154）
//
// 目的：现有靶场把「数值/字符串/LIKE/ORDER BY/POST/JSON/Cookie/Header/Path/二阶/堆叠」
// 都覆盖了，但**注入点所在的载体形态**还有几类没人用真库验过。本靶场只做一件事：
// 把每类载体单独做成一个真实可注入的端点 + 一个同形态的安全对照（参数化），
// 让 `run.mjs` 逐条实测「引擎到底测没测到这个位置」。
//
// 载体清单（全部真 MariaDB，SQL 拼接方式写死为最原始的字符串拼接）：
//   1. 多段路径中间段   GET /api/users/:id/orders   —— 只有末段 `orders` 会被现有
//      `--test-path` 收成注入点，中间的数字 id 从来不是点位（REST 最常见的形态）。
//   2. .json 后缀段     GET /api/item/:id.json      —— 现有静态资源判定 `\.[a-z]+$`
//      会把整个段当静态文件跳过（Rails/Spring 常见的 `/users/5.json`）。
//   3. 矩阵参数         GET /api/matrix;cat=1       —— JAX-RS/Spring 的 `;name=value`，
//      现有实现把整段当一个值替换，`;` 前的名字与 `=` 后的值一起被破坏。
//   4. 重复 query 键    GET /dup?a=1&a=2            —— 后端取末值时，引擎替换首值等于没注入。
//
// 安全对照（同名形态、参数化）：/safe/... 四个端点，要求 0 误报。
//
// 启动：node e2e/detect-surface-lab/server.mjs（run.mjs 会自动拉起）
import http from 'node:http';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');

const PORT = Number(process.env.DS_LAB_PORT || 8234);
const DB_CFG = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.LAB_DB_PASSWORD ?? 'root',
  multipleStatements: false,
};

/** 建库 + 建表 + 灌固定数据（每次启动重建，保证基线稳定） */
async function setupDb() {
  const root = await mysql.createConnection({ ...DB_CFG, multipleStatements: true });
  await root.query('CREATE DATABASE IF NOT EXISTS ds_lab');
  await root.query('DROP TABLE IF EXISTS ds_lab.users');
  await root.query(`CREATE TABLE ds_lab.users (id INT PRIMARY KEY, name VARCHAR(32))`);
  await root.query(`INSERT INTO ds_lab.users (id, name) VALUES (1,'alice'),(2,'bob'),(3,'carol')`);
  await root.end();
}

/**
 * 跑一条 SQL，返回 rows 或抛错（错误文本原样回显 —— 报错注入通道靠它）。
 * @param {string} sql
 * @param {any[]} [params] 安全对照走 `?` 占位符（真参数化，注入值不进 SQL 语法）
 * @returns {Promise<any[]>}
 */
async function runSql(sql, params = []) {
  const c = await mysql.createConnection({ ...DB_CFG, database: 'ds_lab' });
  try {
    const [rows] = await c.query(sql, params);
    return rows;
  } finally {
    await c.end();
  }
}

/**
 * 统一响应：成功回 rows，失败回 500 + 错误文本（真实站点也是这么泄的）。
 * @param {http.ServerResponse} res
 * @param {() => Promise<any[]>} fn
 */
async function respond(res, fn) {
  try {
    const rows = await fn();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ rows }));
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`SQL error: ${e.message}`);
  }
}

/**
 * 安全解码：payload 里常有裸 `%`（如 `%'`），decodeURIComponent 会抛 URIError 把整个
 * 靶场进程带走 —— 那会让后续用例全部变成「连接失败」（实测：连续 97 次无有效回包）。
 * @param {string} s
 * @returns {string}
 */
function dec(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * 路由分发。每条路由都刻意只做「从载体取值 → 拼 SQL」这一件事。
 * @param {URL} u
 * @param {http.ServerResponse} res
 * @returns {boolean} 是否命中路由
 */
function route(u, res) {
  const p = u.pathname;

  // 1) 多段路径中间段：/api/users/<id>/orders 与 /safe/users/<id>/orders
  const multi = /^\/(api|safe)\/users\/([^/]+)\/orders$/.exec(p);
  if (multi) {
    const id = dec(multi[2]);
    if (multi[1] === 'safe') {
      void respond(res, () => runSql('SELECT id,name FROM users WHERE id = ?', [id]));
    } else {
      void respond(res, () => runSql(`SELECT id,name FROM users WHERE id = ${id}`));
    }
    return true;
  }

  // 2) .json 后缀段：/api/item/<id>.json 与 /safe/item/<id>.json
  const jsonSeg = /^\/(api|safe)\/item\/([^/]+)\.json$/.exec(p);
  if (jsonSeg) {
    const raw = dec(jsonSeg[2]);
    if (jsonSeg[1] === 'safe') {
      void respond(res, () => runSql('SELECT id,name FROM users WHERE id = ?', [raw]));
    } else {
      void respond(res, () => runSql(`SELECT id,name FROM users WHERE id = ${raw}`));
    }
    return true;
  }

  // 3) 矩阵参数：/api/matrix;cat=<v> 与 /safe/matrix;cat=<v>
  const matrix = /^\/(api|safe)\/matrix;cat=(.*)$/.exec(p);
  if (matrix) {
    const val = dec(matrix[2]);
    if (matrix[1] === 'safe') {
      void respond(res, () => runSql('SELECT id,name FROM users WHERE id = ?', [val]));
    } else {
      void respond(res, () => runSql(`SELECT id,name FROM users WHERE id = ${val}`));
    }
    return true;
  }

  // 4) 重复 query 键：/dup?a=1&a=2（后端取末值）
  if (p === '/dup' || p === '/safe/dup') {
    const all = u.searchParams.getAll('a');
    const val = all.length ? all[all.length - 1] : '1';
    if (p === '/safe/dup') {
      void respond(res, () => runSql('SELECT id,name FROM users WHERE id = ?', [val]));
    } else {
      void respond(res, () => runSql(`SELECT id,name FROM users WHERE id = ${val}`));
    }
    return true;
  }

  return false;
}

await setupDb();
const server = http.createServer((req, res) => {
  let u;
  try {
    u = new URL(req.url || '/', `http://127.0.0.1:${PORT}`);
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('bad request');
    return;
  }
  if (u.pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }
  try {
    if (!route(u, res)) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
    }
  } catch (e) {
    // 任何异常都必须变成 500：靶场进程挂了会让整批用例变成「连接失败」，
    // 那会把「引擎漏检」和「靶场没了」混成同一个数字。
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end(`lab error: ${e.message}`);
  }
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[detect-surface-lab] http://127.0.0.1:${PORT}`);
});
