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
// [D105] XML 元素名载体：复用引擎自己的极简解析器（靶场与解析口径同源，避免靶场自造
// 「引擎认不出的 XML」或反之）；只取第一个叶子元素的标签名 + 文本，与 JSON 端点的
// `Object.keys(body)[0]` 同型。
const { parseXmlBody, xmlLeafPaths, getXmlLeaf } = await import('../../server/src/core/xmlBody.js');

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
// [D103] JSON body 键名载体：POST application/json 的请求体解析
// （strict 默认只收对象/数组；16kb 上限对齐 scanRoutes 的 jsonBody 10KB + 余量）
app.use(express.json({ limit: '16kb' }));
// [D105] XML body 元素名载体：application/xml / text/xml 原文进 req.body（string）
app.use(express.text({ type: ['application/xml', 'text/xml'], limit: '16kb' }));

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

// ── [D103] JSON body 键名：键名当列名（值参数化），与 /colfilter 同型换载体 ──
// `const col = Object.keys(req.body)[0]; SELECT ... WHERE ${col} = ?`
// 键是合法 JSON 字符串（可含空格/引号）⇒ 布尔载荷 `name AND 1=1-- -` 可直接承载
// （XML 元素名就承载不了 —— NameChar 不允许空格，所以才需要本靶场钉 JSON 面）。
app.post('/colfilter-json', async (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const key = Object.keys(body)[0] || 'id';
  const val = body[key] ?? '1';
  const sql = `SELECT id, name, price FROM products WHERE ${key} = ? LIMIT 3`;
  try {
    const [rows] = await pool.query(sql, [String(val)]);
    res.send(page('colfilter-json', `<p>sql=${sql}</p>${rowsHtml(rows)}`));
  } catch {
    res.status(200).send(page('colfilter-json', `<p>sql=${sql}</p><p class="err">query failed</p>`));
  }
});

// JSON 安全对照：列名白名单（同键名拼接写法 + 先校验）
app.post('/colfilter-json-safe', async (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const raw = Object.keys(body)[0] || 'id';
  const ALLOW = new Set(['id', 'name', 'price']);
  const key = ALLOW.has(raw) ? raw : 'id';
  const val = body[raw] ?? '1';
  const sql = `SELECT id, name, price FROM products WHERE ${key} = ? LIMIT 3`;
  try {
    const [rows] = await pool.query(sql, [String(val)]);
    res.send(page('colfilter-json-safe', `<p>sql=${sql}</p>${rowsHtml(rows)}`));
  } catch {
    res.status(200).send(page('colfilter-json-safe', `<p>sql=${sql}</p><p class="err">query failed</p>`));
  }
});

// ── [D105] XML body 元素名：元素名当列名（值参数化），与 /colfilter 同型换载体 ──
// `const el = doc.firstElementChild; SELECT ... WHERE ${el.tagName} = ?`（文本走占位符）。
// NameChar 不允许空格/引号 ⇒ 布尔载荷承载不了；判据是**算术位移**（price-0 恒等 / price-1 位移），
// 探测请求本身是合法 XML（不以畸形报文换检出）。
// 注意：本端点**不回显 SQL**（回显会让「-0 与基线一致」因为名字出现在页面上而天然破裂，
// 判据必须只落在行集差异上——这也更接近真实系统）。
const firstLeaf = (xmlText) => {
  const parsed = parseXmlBody(xmlText);
  if (!parsed.ok) return null;
  const path = xmlLeafPaths(parsed.tree)[0];
  if (!path) return null;
  const segs = path.split('.').filter((s) => s && !/^\d+$/.test(s));
  return { tag: segs[segs.length - 1] || '', val: getXmlLeaf(parsed.tree, path) ?? '' };
};

app.post('/colfilter-xml', async (req, res) => {
  const leaf = firstLeaf(typeof req.body === 'string' ? req.body : '');
  if (!leaf || !leaf.tag) return res.status(200).send(page('colfilter-xml', '<p class="err">parse failed</p>'));
  const sql = `SELECT id, name, price FROM products WHERE ${leaf.tag} = ? LIMIT 3`;
  try {
    const [rows] = await pool.query(sql, [String(leaf.val)]);
    res.send(page('colfilter-xml', rowsHtml(rows)));
  } catch {
    res.status(200).send(page('colfilter-xml', '<p class="err">query failed</p>'));
  }
});

// XML 安全对照：元素名白名单（同样的拼接写法 + 先校验）
app.post('/colfilter-xml-safe', async (req, res) => {
  const leaf = firstLeaf(typeof req.body === 'string' ? req.body : '');
  if (!leaf || !leaf.tag) return res.status(200).send(page('colfilter-xml-safe', '<p class="err">parse failed</p>'));
  const ALLOW = new Set(['id', 'name', 'price']);
  const key = ALLOW.has(leaf.tag) ? leaf.tag : 'id';
  const sql = `SELECT id, name, price FROM products WHERE ${key} = ? LIMIT 3`;
  try {
    const [rows] = await pool.query(sql, [String(leaf.val)]);
    res.send(page('colfilter-xml-safe', rowsHtml(rows)));
  } catch {
    res.status(200).send(page('colfilter-xml-safe', '<p class="err">query failed</p>'));
  }
});

// ── [D106] 固定后缀形态：键名后跟固定尾部语法（`ORDER BY ${key} DESC`）────────
// 与 /colfilter 的差异：注入位之后还有「 DESC」这样的尾部语法。union 通道在 ORDER BY
// 之后无法追加（SQL 语法里 ORDER BY 是 UNION 之后才允许的末段）⇒ 验证各通道真实行为。
// 不回显 SQL：判据必须落在行集顺序/错误页差异上（回显会把载荷字符串差异当信号）。
app.get('/colsort', async (req, res) => {
  const key = Object.keys(req.query)[0] || 'price';
  const sql = `SELECT id, name, price FROM products ORDER BY ${key} DESC`;
  try {
    const [rows] = await pool.query(sql);
    res.send(page('colsort', rowsHtml(rows)));
  } catch {
    res.status(200).send(page('colsort', '<p class="err">query failed</p>'));
  }
});

// 安全对照：列名白名单（同样的键名拼接写法，但先校验；error/union 探针连语法错误都进不去）
app.get('/colsort-safe', async (req, res) => {
  const raw = Object.keys(req.query)[0] || 'price';
  const ALLOW = new Set(['id', 'name', 'price']);
  const key = ALLOW.has(raw) ? raw : 'price';
  const sql = `SELECT id, name, price FROM products ORDER BY ${key} DESC`;
  try {
    const [rows] = await pool.query(sql);
    res.send(page('colsort-safe', rowsHtml(rows)));
  } catch {
    res.status(200).send(page('colsort-safe', '<p class="err">query failed</p>'));
  }
});

app.listen(PORT, '127.0.0.1', () => console.log(`[param-name-lab] http://127.0.0.1:${PORT}`));
