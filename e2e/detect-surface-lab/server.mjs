// 检测面探针靶场（D154/D155/D159/D166）
//
// 目的：现有靶场把「数值/字符串/LIKE/ORDER BY/POST/JSON/Cookie/Header/Path/二阶/堆叠」
// 都覆盖了，但**注入点所在的载体形态**还有几类没人用真库验过。本靶场只做一件事：
// 把每类载体单独做成一个真实可注入的端点 + 一个同形态的安全对照（参数化/白名单），
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
//   5. [D155] JSON body 载体（只吃 application/json，CT 不对 415）。
//   6. [D159] multipart 文件字段 filename（上传接口把文件名落库再拼 SQL）。
//   7. [D166] multipart 文本字段**名**（`--test-param-names`：后端把字段名当排序列）。
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

/**
 * [D155] JSON API 端点：**只**接受 `Content-Type: application/json` 的 body。
 *
 * 真实现代 API 就是这样：CT 不对直接 400/415，body 根本不进业务逻辑。
 * 用途：验证「CLI 拿到扁平 JSON body + 显式 JSON CT 时，到底按 JSON 发还是按
 * urlencoded 发」——按 urlencoded 发就是静默 0 检出（与「这个站没洞」同形）。
 * @param {import('node:http').IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {boolean} safe 是否参数化（安全对照）
 */
function handleJson(req, res, safe) {
  const ct = String(req.headers['content-type'] || '');
  if (!/^application\/json/i.test(ct)) {
    res.writeHead(415, { 'Content-Type': 'text/plain' });
    res.end('unsupported media type: expected application/json');
    return;
  }
  let raw = '';
  req.on('data', (c) => {
    raw += c;
    if (raw.length > 64 * 1024) req.destroy();
  });
  req.on('end', () => {
    let id;
    try {
      const body = JSON.parse(raw || '{}');
      id = body && body.id != null ? String(body.id) : '1';
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('invalid json');
      return;
    }
    if (safe) void respond(res, () => runSql('SELECT id,name FROM users WHERE id = ?', [id]));
    else void respond(res, () => runSql(`SELECT id,name FROM users WHERE id = ${id}`));
  });
}

/**
 * [D159] multipart 上传端点：**只**接受 multipart/form-data，且把文件字段的 **filename**
 * 拼进 SQL（`SELECT ... WHERE name = '<filename>'`）—— 真实上传接口就是把文件名落库的那种。
 *
 * 用途：验证两件事一起修好没有：
 *   ① `-r` 抓到的 multipart 不再被降级成 urlencoded（那样目标 415，注入值从未进业务逻辑）；
 *   ② 文件字段按 `name="x"; filename="…"` 重建，注入值写进 filename 而不是文本字段内容。
 * 安全对照走 `?` 参数化（注入值永远不进 SQL 语法）。
 * @param {import('node:http').IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {boolean} safe 是否参数化
 */
function handleUpload(req, res, safe) {
  const ct = String(req.headers['content-type'] || '');
  if (!/^multipart\/form-data/i.test(ct)) {
    res.writeHead(415, { 'Content-Type': 'text/plain' });
    res.end('unsupported media type: expected multipart/form-data');
    return;
  }
  const bm = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(ct);
  if (!bm) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('missing boundary');
    return;
  }
  const boundary = bm[1] || bm[2];
  let raw = '';
  req.on('data', (c) => {
    raw += c;
    if (raw.length > 256 * 1024) req.destroy();
  });
  req.on('end', () => {
    let filename = '';
    for (const part of raw.split(`--${boundary}`)) {
      const m = /filename="([^"]*)"/i.exec(part);
      if (m) { filename = m[1]; break; }
    }
    if (!filename) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('no file field');
      return;
    }
    if (safe) void respond(res, () => runSql('SELECT id,name FROM users WHERE name = ?', [filename]));
    else void respond(res, () => runSql(`SELECT id,name FROM users WHERE name = '${filename}'`));
  });
}

/**
 * [D166] multipart **字段名**当排序列的端点：**只**接受 multipart/form-data，且把
 * 第一个**文本字段的名**（不是值）拼进 ORDER BY —— 「上传+排序+筛选」表单页的常见
 * 形态：字段值被参数化/忽略，列名却来自字段名（框架把 field name 当排序列的那种）。
 *
 * 用途：验证 `--test-param-names` 的第五个宿主（form carrier）——把字段 name="…"
 * 改成序数探针（`id, 1-- -` 合法 vs `id, 9999-- -` 越界）时到底检不检出。
 * 安全对照：列名白名单（id/name），改名不在白名单 ⇒ 回落固定列，两探针同页 ⇒ 0 误报。
 * @param {import('node:http').IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {boolean} safe 是否走白名单（安全对照）
 */
function handleFormSort(req, res, safe) {
  const ct = String(req.headers['content-type'] || '');
  if (!/^multipart\/form-data/i.test(ct)) {
    res.writeHead(415, { 'Content-Type': 'text/plain' });
    res.end('unsupported media type: expected multipart/form-data');
    return;
  }
  const bm = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(ct);
  if (!bm) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('missing boundary');
    return;
  }
  const boundary = bm[1] || bm[2];
  let raw = '';
  req.on('data', (c) => {
    raw += c;
    if (raw.length > 256 * 1024) req.destroy();
  });
  req.on('end', () => {
    // 按报文顺序收集**文本字段名**（文件段跳过——它的名不是排序列）；
    // quoted-pair 反转义（`name="id\""` 的名是 `id"`，RFC 2045 口径，与真实框架一致）
    const names = [];
    for (const part of raw.split(`--${boundary}`)) {
      if (/filename="/i.test(part)) continue;
      const m = /name="([^"]*)"/i.exec(part);
      if (m) names.push(m[1].replace(/\\"/g, '"'));
    }
    const firstName = names[0];
    if (!firstName) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('no text field');
      return;
    }
    let col = firstName;
    if (safe && !['id', 'name'].includes(col)) col = 'id'; // 列名白名单：改名无效
    // 安全对照的 col 已被白名单收敛为字面量 id/name（不是用户输入），可直接拼接；
    //  vulnerable 侧就是缺陷本体：字段名原样进 ORDER BY。
    void respond(res, () => runSql(`SELECT id,name FROM users ORDER BY ${col}`));
  });
}

/**
 * [D168] 页面表单（enctype=multipart/form-data）：爬取/`--forms` 路径发现的**上传表单**。
 *
 * 真实形态：上传页里除了文件字段还有可写的文本字段（caption / title / author），
 * 后端把它们拼进 SQL。这类表单没有对应的请求头 —— 编码类型只写在 `<form enctype>` 上，
 * 按 urlencoded 提交会被 415/400 挡掉，字段从未进业务逻辑（与 D159 的 -r 场景同型）。
 * @param {http.ServerResponse} res
 * @param {string} [action] 表单提交地址（安全对照走 /safe/form-upload）
 */
function handleFormPage(res, action = '/api/form-upload') {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(
    '<!DOCTYPE html><html><body>'
    + '<h1>upload</h1>'
    + `<form action="${action}" method="post" enctype="multipart/form-data">`
    + '<input type="text" name="caption" value="alice">'
    + '<input type="file" name="file">'
    + '<input type="submit" name="go" value="upload">'
    + '</form></body></html>'
  );
}

/**
 * [D168] 该表单的提交端点：只认 multipart，把 caption 拼进 SQL（`name = '<caption>'`）。
 * @param {import('node:http').IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {boolean} safe 参数化对照
 */
function handleFormUpload(req, res, safe) {
  const ct = String(req.headers['content-type'] || '');
  if (!/^multipart\/form-data/i.test(ct)) {
    res.writeHead(415, { 'Content-Type': 'text/plain' });
    res.end('unsupported media type: expected multipart/form-data');
    return;
  }
  const bm = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(ct);
  if (!bm) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('missing boundary');
    return;
  }
  const boundary = bm[1] || bm[2];
  let raw = '';
  req.on('data', (c) => {
    raw += c;
    if (raw.length > 256 * 1024) req.destroy();
  });
  req.on('end', () => {
    let caption = '';
    for (const part of raw.split(`--${boundary}`)) {
      const nm = /name="([^"]*)"/i.exec(part);
      if (!nm || nm[1] !== 'caption') continue;
      const ci = part.indexOf('\r\n\r\n');
      caption = (ci >= 0 ? part.slice(ci + 4) : '').replace(/\r\n$/, '');
      break;
    }
    if (!caption) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('no caption');
      return;
    }
    if (safe) void respond(res, () => runSql('SELECT id,name FROM users WHERE name = ?', [caption]));
    else void respond(res, () => runSql(`SELECT id,name FROM users WHERE name = '${caption}'`));
  });
}

/**
 * [D174] JSON 多键筛选：把 **JSON body 的键名**拼成 WHERE 条件
 * （`{"name":"alice","go":"1"}` → `WHERE name = 'alice' AND go = '1'`），值做转义。
 * 与 D169（form）、D173（query）是同一判据的第三个载体：键名进布尔位置，值不是注入面。
 * @param {import('node:http').IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {{safe?: boolean, blind?: boolean}} [opts]
 */
function handleJsonFilter(req, res, opts = {}) {
  const { safe = false, blind = false } = opts;
  let raw = '';
  req.on('data', (c) => {
    raw += c;
    if (raw.length > 64 * 1024) req.destroy();
  });
  req.on('end', () => {
    let body;
    try {
      body = JSON.parse(raw || '{}');
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('invalid json');
      return;
    }
    if (!/^application\/json/i.test(String(req.headers['content-type'] || ''))) {
      res.writeHead(415, { 'Content-Type': 'text/plain' });
      res.end('expected application/json');
      return;
    }
    const keys = Object.keys(body || {}).filter((k) => k !== 'go');
    if (!keys.length) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('no field');
      return;
    }
    const where = keys
      .map((k) => {
        const col = safe && k !== 'name' && k !== 'id' ? 'name' : k;
        return `${col} = '${String(body[k]).replace(/'/g, "''")}'`;
      })
      .join(' AND ');
    const sql = `SELECT id,name FROM users WHERE ${where}`;
    if (!blind) {
      void respond(res, () => runSql(sql));
      return;
    }
    runSql(sql)
      .then((rows) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ rows }));
      })
      .catch(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ rows: [] }));
      });
  });
}

/**
 * [D173] query 多键筛选：把**URL 参数名**拼成 WHERE 条件（`?name=alice&go=1` →
 * `WHERE name = 'alice' AND go = '1'`），值做转义。query 键名进布尔位置的形态。
 * @param {import('node:http').IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {{safe?: boolean, blind?: boolean}} [opts]
 */
function handleQueryFilter(req, res, opts = {}) {
  const { safe = false, blind = false } = opts;
  const u = new URL(req.url || '/', 'http://127.0.0.1');
  const pairs = [...u.searchParams.entries()].filter(([k]) => k !== 'go');
  if (!pairs.length) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('no field');
    return;
  }
  const where = pairs
    .map(([k, v]) => {
      const col = safe && k !== 'name' && k !== 'id' ? 'name' : k;
      return `${col} = '${String(v).replace(/'/g, "''")}'`;
    })
    .join(' AND ');
  const sql = `SELECT id,name FROM users WHERE ${where}`;
  if (!blind) {
    void respond(res, () => runSql(sql));
    return;
  }
  runSql(sql)
    .then((rows) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ rows }));
    })
    .catch(() => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ rows: [] }));
    });
}

/**
 * [D172] SPA 入口页：静态 HTML 只有空壳，数据靠 JS fetch 打 REST 接口
 * （`/api/users/5/orders`，**没有 query 参数**）—— 浏览器爬取的主发现面。
 * @param {http.ServerResponse} res
 * @param {string} [href] 要 fetch 的接口（安全对照指向 /safe/users/5/orders）
 */
function handleSpa(res, href = '/api/users/5/orders') {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(
    '<!DOCTYPE html><html><body><h1>spa</h1><div id="out"></div>'
    + '<script>fetch(' + JSON.stringify(href) + ').then(function(r){return r.text();})'
    + '.then(function(t){document.getElementById("out").textContent=t;});</script>'
    + '</body></html>'
  );
}

/**
 * [D171] 下拉筛选表单：注入面在 `<select>` 的选项值上（`sort`/`status`/`id` 这类）。
 * 表单解析此前只认 `<input>`/`<textarea>` ⇒ 这类表单只剩按钮字段 ⇒ 0 个注入点。
 * @param {http.ServerResponse} res
 * @param {string} [action] 提交地址（安全对照指向 /safe/select-filter）
 */
function handleSelectPage(res, action = '/api/select-filter') {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(
    '<!DOCTYPE html><html><body><h1>filter</h1>'
    + `<form action="${action}" method="post">`
    + '<select name="id"><option value="1" selected>one</option><option value="2">two</option></select>'
    + '<input type="submit" name="go" value="filter">'
    + '</form></body></html>'
  );
}

/**
 * [D171] 下拉筛选的提交端点：把 `id` 字段值拼进 SQL（`WHERE id = <id>`）。
 * @param {import('node:http').IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {boolean} safe 参数化对照
 */
function handleSelectFilter(req, res, safe) {
  let raw = '';
  req.on('data', (c) => {
    raw += c;
    if (raw.length > 64 * 1024) req.destroy();
  });
  req.on('end', () => {
    const q = new URLSearchParams(raw);
    const id = q.get('id') || '';
    if (!id) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('no id');
      return;
    }
    if (safe) void respond(res, () => runSql('SELECT id,name FROM users WHERE id = ?', [id]));
    else void respond(res, () => runSql(`SELECT id,name FROM users WHERE id = ${id}`));
  });
}

/**
 * [D170] 站内链接页：REST 形态的链接（没有 query 参数，注入面在路径段）。
 * 爬取只抽 query 键时这类链接产出 0 个注入点 ⇒ 路径面在爬取路径上整体缺失。
 * @param {http.ServerResponse} res
 * @param {string} href 链接目标（安全对照指向 /safe/users/5/orders）
 */
function handlePathLinks(res, href = '/api/users/5/orders') {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(
    '<!DOCTYPE html><html><body><h1>links</h1>'
    + `<a href="${href}">order detail</a>`
    + '</body></html>'
  );
}

/**
 * [D169] 多键拼接端点：把**全部字段名**拼成 WHERE 条件（`WHERE k1 = 'v1' AND k2 = 'v2'`），
 * 值做过简单转义（不是注入面），列名直接来自字段名。
 *
 * 真实形态：动态筛选/多条件查询构造器把 `Object.keys(body)` 拼进 SQL。字段名在
 * **布尔表达式位置**（不是 ORDER BY），所以 orderByKey 的序数差分（`{k}, 1-- -`）
 * 在这里只会语法错误；要用「把键名换成恒真/恒假布尔式」的探针才能打出来。
 * 安全对照走列名白名单（不在名单里回退 name）。
 * @param {import('node:http').IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {boolean} safe 是否走列名白名单
 */
function handleFormFilter(req, res, opts = {}) {
  const { safe = false, blind = false } = opts;
  const ct = String(req.headers['content-type'] || '');
  if (!/^multipart\/form-data/i.test(ct)) {
    res.writeHead(415, { 'Content-Type': 'text/plain' });
    res.end('unsupported media type: expected multipart/form-data');
    return;
  }
  const bm = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(ct);
  if (!bm) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('missing boundary');
    return;
  }
  const boundary = bm[1] || bm[2];
  let raw = '';
  req.on('data', (c) => {
    raw += c;
    if (raw.length > 256 * 1024) req.destroy();
  });
  req.on('end', () => {
    /** @type {Array<{name: string, value: string}>} */
    const fields = [];
    for (const part of raw.split(`--${boundary}`)) {
      const nm = /name="([^"]*)"/i.exec(part);
      if (!nm) continue;
      if (/filename="/i.test(part)) continue; // 文件字段不参与 WHERE 构造
      const ci = part.indexOf('\r\n\r\n');
      const value = (ci >= 0 ? part.slice(ci + 4) : '').replace(/\r\n$/, '');
      fields.push({ name: nm[1], value });
    }
    const usable = fields.filter((f) => f.name !== 'go');
    if (!usable.length) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('no field');
      return;
    }
    const where = usable
      .map((f) => {
        const col = safe && f.name !== 'name' && f.name !== 'id' ? 'name' : f.name;
        const val = String(f.value).replace(/'/g, "''");
        return `${col} = '${val}'`;
      })
      .join(' AND ');
    const sql = `SELECT id,name FROM users WHERE ${where}`;
    if (!blind) {
      void respond(res, () => runSql(sql));
      return;
    }
    // 盲档：把 SQL 错误吞成「没查到」，唯一信号只剩响应差异（布尔通道）
    runSql(sql)
      .then((rows) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ rows }));
      })
      .catch(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ rows: [] }));
      });
  });
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
  // [D155] JSON body 载体：与上面 4 类不同，它的判据是「发送侧形态」而不是「取值位置」
  if (u.pathname === '/api/json' || u.pathname === '/safe/json') {
    handleJson(req, res, u.pathname === '/safe/json');
    return;
  }
  // [D159] multipart 上传：注入面在文件字段的 filename 上
  if (u.pathname === '/api/upload' || u.pathname === '/safe/upload') {
    handleUpload(req, res, u.pathname === '/safe/upload');
    return;
  }
  // [D166] multipart 字段名：注入面在文本字段的 name 上（--test-param-names）
  if (u.pathname === '/api/form-sort' || u.pathname === '/safe/form-sort') {
    handleFormSort(req, res, u.pathname === '/safe/form-sort');
    return;
  }
  // [D168] 页面表单（enctype=multipart）：--forms / 爬取路径发现后必须按 multipart 提交
  if (u.pathname === '/form-upload') {
    handleFormPage(res);
    return;
  }
  if (u.pathname === '/safe-form-upload') {
    handleFormPage(res, '/safe/form-upload');
    return;
  }
  // [D169] 多键拼接：字段名进 WHERE（布尔位置），值已转义
  if (u.pathname === '/api/form-filter' || u.pathname === '/safe/form-filter'
    || u.pathname === '/api/form-filter-blind' || u.pathname === '/safe/form-filter-blind') {
    const safe = u.pathname.includes('/safe/');
    const blind = u.pathname.endsWith('-blind');
    handleFormFilter(req, res, { safe, blind });
    return;
  }
  // [D170] 站内链接页：链接本身是 REST 路径（无 query 参数）
  if (u.pathname === '/path-links') {
    handlePathLinks(res);
    return;
  }
  if (u.pathname === '/safe-path-links') {
    handlePathLinks(res, '/safe/users/5/orders');
    return;
  }
  // [D171] 下拉筛选表单：注入面在 <select> 的选项值上
  if (u.pathname === '/select-filter-page') {
    handleSelectPage(res);
    return;
  }
  if (u.pathname === '/safe-select-filter-page') {
    handleSelectPage(res, '/safe/select-filter');
    return;
  }
  if (u.pathname === '/api/select-filter' || u.pathname === '/safe/select-filter') {
    handleSelectFilter(req, res, u.pathname === '/safe/select-filter');
    return;
  }
  // [D172] SPA：接口靠 JS fetch，端点无 query 参数
  if (u.pathname === '/spa') {
    handleSpa(res);
    return;
  }
  if (u.pathname === '/safe-spa') {
    handleSpa(res, '/safe/users/5/orders');
    return;
  }
  // [D173] query 多键筛选：参数名进 WHERE（布尔位置）
  if (u.pathname === '/api/query-filter' || u.pathname === '/safe/query-filter'
    || u.pathname === '/api/query-filter-blind' || u.pathname === '/safe/query-filter-blind') {
    handleQueryFilter(req, res, {
      safe: u.pathname.includes('/safe/'),
      blind: u.pathname.endsWith('-blind'),
    });
    return;
  }
  // [D174] JSON 多键筛选：body 键名进 WHERE（布尔位置）
  if (u.pathname === '/api/json-filter' || u.pathname === '/safe/json-filter'
    || u.pathname === '/api/json-filter-blind' || u.pathname === '/safe/json-filter-blind') {
    handleJsonFilter(req, res, {
      safe: u.pathname.includes('/safe/'),
      blind: u.pathname.endsWith('-blind'),
    });
    return;
  }
  if (u.pathname === '/api/form-upload' || u.pathname === '/safe/form-upload') {
    handleFormUpload(req, res, u.pathname === '/safe/form-upload');
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
