// ============================================================================
// blackbox-lab / lab-app.mjs —— 外部视角独立评测靶场（Express + 真 MySQL）
//
// [独立评测] 由评测方另建，不复用项目自带靶场 —— 工具作者自带的靶场会自证。
// 每个靶点都是**真实拼接 SQL**，不是模拟。22 个点：
//   15 个漏洞点（回显 4 / 报错 1 / 盲注 2 / 其他通道 6 / 高阶 2）
//   + 7 个安全对照点（参数化、随机 nonce、恒 500、恒 403、302、静态、白名单）
//
// 环境变量：
//   LAB_PORT=8099       监听端口
//   LAB_WAF=1           开启前置 WAF 正则层（拦 union select / sleep / 注释符 / ' or 1=1）
//   MYSQL_PORT/USER/PASSWORD  数据库连接
//
// 靶场自身兜底 uncaughtException：一个未捕获异常会让进程退出，后续靶点全变
// 「连接失败」，看起来像工具漏报（评测里最容易误判的形式）。
// ============================================================================

import express from 'express';
import mysql from 'mysql2/promise';

const PORT = Number(process.env.LAB_PORT || 8099);
const WAF_ON = process.env.LAB_WAF === '1';
const DB = {
  host: '127.0.0.1',
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || 'root',
  database: 'blackbox_lab',
  charset: 'utf8mb4',
};

process.on('uncaughtException', (e) => {
  console.error('[lab][uncaught]', e && e.message);
});
process.on('unhandledRejection', (e) => {
  console.error('[lab][unhandledRejection]', e && (e.message || e));
});

const pool = mysql.createPool({ ...DB, connectionLimit: 8, waitForConnections: true });

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.text({ type: 'text/plain', limit: '1mb' }));

// ── 前置 WAF 层（可开关）：模拟真实部署里的正则拦截 ────────────────────────
// 注意「评测靶场自身也是被测代码」：规则只匹配**参数值**，不做全请求头遍历
// （旧教训：遍历全部请求头会让 Accept: */* 命中 /\/\*/ 注释符规则，把良性探针也拦死，
//  结果被误读成「工具绕不过 WAF」）。
const WAF_RULES = [
  { id: 'union-select', re: /\bunion\b[\s\S]{0,12}\bselect\b/i, why: 'union select 关键词' },
  { id: 'sleep', re: /\bsleep\s*\(|\bbenchmark\s*\(|pg_sleep/i, why: '时间盲注函数' },
  { id: 'comment', re: /--\s|\/\*|\*\//, why: '注释符' },
  { id: 'or-true', re: /['"]?\s*or\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, why: "' or 1=1 类恒真" },
  { id: 'extractvalue', re: /\bextractvalue\b|\bupdatexml\b/i, why: '报错注入函数' },
];
function wafMiddleware(req, res, next) {
  if (!WAF_ON) return next();
  const vals = [];
  for (const [, v] of Object.entries(req.query || {})) vals.push(String(v));
  for (const [, v] of Object.entries(req.body || {})) {
    if (typeof v === 'string') vals.push(v);
  }
  for (const h of ['x-forwarded-for', 'user-agent', 'referer']) {
    if (req.headers[h]) vals.push(String(req.headers[h]));
  }
  if (req.headers.cookie) vals.push(String(req.headers.cookie));
  for (const v of vals) {
    for (const r of WAF_RULES) {
      if (r.re.test(v)) {
        return res.status(403).type('text/html').send(
          `<html><body>403 Forbidden<hr>Blocked by lab WAF rule: ${r.id} (${r.why})</body></html>`);
      }
    }
  }
  return next();
}
app.use(wafMiddleware);

const env = (extra = '') => `<div class="env">${extra}</div>`;
const page = (title, body) =>
  `<!DOCTYPE html><html><head><title>${title}</title></head><body><h1>${title}</h1>${body}</body></html>`;

async function q(sql, params) {
  const conn = await pool.getConnection();
  try {
    const [rows] = params ? await conn.query(sql, params) : await conn.query(sql);
    return rows;
  } finally {
    conn.release();
  }
}

// ══════════════════════════════════════════════════════════════════════════
// A. 回显型漏洞点（4）
// ══════════════════════════════════════════════════════════════════════════

// A1 数字型：WHERE id=${id}
app.get('/api/user', async (req, res) => {
  const id = req.query.id ?? '1';
  const sql = `SELECT id, username, email, role FROM users WHERE id=${id}`;
  try {
    const rows = await q(sql);
    res.send(page('user', env(`sql=${sql}`) +
      rows.map((r) => `<p>${r.id} | ${r.username} | ${r.email} | ${r.role}</p>`).join('') ||
      '<p>no row</p>'));
  } catch (e) {
    res.status(200).send(page('user', env(`sql=${sql}`) + `<p class="err">query failed</p>`));
  }
});

// A2 字符串型：WHERE username='${name}'
app.get('/api/search', async (req, res) => {
  const name = req.query.name ?? 'alice';
  const sql = `SELECT id, username, email FROM users WHERE username='${name}'`;
  try {
    const rows = await q(sql);
    res.send(page('search', env(`sql=${sql}`) +
      (rows.map((r) => `<p>${r.id} | ${r.username} | ${r.email}</p>`).join('') || '<p>no row</p>')));
  } catch (e) {
    res.status(200).send(page('search', env(`sql=${sql}`) + '<p class="err">query failed</p>'));
  }
});

// A3 LIKE 型：WHERE name LIKE '%${kw}%'
app.get('/api/like', async (req, res) => {
  const kw = req.query.q ?? 'key';
  const sql = `SELECT id, name, category, price FROM products WHERE name LIKE '%${kw}%'`;
  try {
    const rows = await q(sql);
    res.send(page('like', env(`sql=${sql}`) +
      (rows.map((r) => `<p>${r.id} | ${r.name} | ${r.category} | ${r.price}</p>`).join('') || '<p>no row</p>')));
  } catch (e) {
    res.status(200).send(page('like', env(`sql=${sql}`) + '<p class="err">query failed</p>'));
  }
});

// A4 ORDER BY 位置型：ORDER BY ${by}
app.get('/api/sort', async (req, res) => {
  const by = req.query.by ?? 'price';
  const sql = `SELECT id, name, price FROM products ORDER BY ${by} LIMIT 5`;
  try {
    const rows = await q(sql);
    res.send(page('sort', env(`sql=${sql}`) +
      rows.map((r) => `<p>${r.id} | ${r.name} | ${r.price}</p>`).join('')));
  } catch (e) {
    res.status(200).send(page('sort', env(`sql=${sql}`) + '<p class="err">query failed</p>'));
  }
});

// ══════════════════════════════════════════════════════════════════════════
// B. 报错型（1）：extractvalue 报错文本回显
// 关键：必须是**真可注入**的拼接（早期误写成 Number(id)||1 → 实际不可注入，
// 真值阶段就会被识破；评测靶场自身也是被测代码）。
// 与 A1 的区别只在「是否把数据库错误原文回显」。
// ══════════════════════════════════════════════════════════════════════════
app.get('/api/product', async (req, res) => {
  const id = req.query.id ?? '1';
  const sql = `SELECT id, name, price FROM products WHERE id=${id}`;
  try {
    const rows = await q(sql);
    res.send(page('product', env(`sql=${sql}`) +
      (rows.map((r) => `<p>${r.id} | ${r.name} | ${r.price}</p>`).join('') || '<p>no row</p>')));
  } catch (e) {
    // 报错型靶点的关键：把数据库错误原文回显
    res.status(200).send(page('product', env(`sql=${sql}`) +
      `<p class="err">SQL Error: ${String(e.message).replace(/</g, '&lt;')}</p>`));
  }
});

// ══════════════════════════════════════════════════════════════════════════
// C. 盲注型（2）
// ══════════════════════════════════════════════════════════════════════════

// C1 布尔盲注：HTTP 恒 200，靠内容差异区分真假
app.get('/api/blind', async (req, res) => {
  const id = req.query.id ?? '1';
  const sql = `SELECT id FROM users WHERE id=${id}`;
  let hit = false;
  try {
    const rows = await q(sql);
    hit = Array.isArray(rows) && rows.length > 0;
  } catch {
    hit = false;
  }
  // 真：显示 "welcome back"；假：显示 "guest"
  res.status(200).send(page('blind', hit ? env('welcome back, alice') : env('guest')));
});

// C2 时间盲注：内容恒定，仅响应时间随注入变化
app.get('/api/sleep', async (req, res) => {
  const id = req.query.id ?? '1';
  const sql = `SELECT COUNT(*) AS c FROM users WHERE id=${id}`;
  try {
    await q(sql);
  } catch {
    /* 时间通道只看耗时，忽略错误 */
  }
  res.status(200).send(page('sleep', env('operation completed')));
});

// ══════════════════════════════════════════════════════════════════════════
// D. 其他注入通道（6）
// ══════════════════════════════════════════════════════════════════════════

// D1 POST form
app.post('/api/login', async (req, res) => {
  const u = req.body.username ?? 'alice';
  const p = req.body.password ?? 'x';
  const sql = `SELECT id, username, role FROM users WHERE username='${u}' AND passwd='${p}'`;
  try {
    const rows = await q(sql);
    res.send(page('login', env(`sql=${sql}`) +
      (rows.length ? `<p>login ok: ${rows[0].username} (${rows[0].role})</p>` : '<p>invalid credentials</p>')));
  } catch {
    res.status(200).send(page('login', env(`sql=${sql}`) + '<p class="err">query failed</p>'));
  }
});

// D2 JSON body
app.post('/api/order', async (req, res) => {
  const item = req.body.item ?? 'hub';
  const sql = `SELECT id, name, price FROM products WHERE name='${item}'`;
  try {
    const rows = await q(sql);
    res.json({ ok: true, sql, rows });
  } catch (e) {
    res.json({ ok: false, sql, error: String(e.message) });
  }
});

// D3 Cookie
app.get('/api/profile', async (req, res) => {
  const cookie = String(req.headers.cookie || '');
  const m = /(?:^|;\s*)uid=([^;]*)/.exec(cookie);
  // [LAB-FIX 2026-09-18] 靶场自身缺陷，非被测属性：本 handler 是 async，Express 4 不会捕获
  // async 回调里抛出的异常 → `decodeURIComponent("1%'…")` 的 URIError 变成 unhandledRejection，
  // 该请求**永不应答**（客户端只能等超时）。注入器投放的闭合候选里 `%'` / `%"` 是正常形态，
  // 于是这条缺陷会把「D3 cookie 点」整个测段拖成分钟级停顿。真值标定阶段（uid=1）碰不到，
  // 所以此前从未暴露。
  // 修的是「靶场不应因非 SQL 原因挂住连接」；SQL 拼接形态一字未改，注入难度与真值不变。
  let uid = '1';
  try { uid = m ? decodeURIComponent(m[1]) : '1'; } catch { uid = m ? m[1] : '1'; }
  const sql = `SELECT id, username, email, role FROM users WHERE id=${uid}`;
  try {
    const rows = await q(sql);
    res.send(page('profile', env(`sql=${sql}`) +
      (rows.map((r) => `<p>${r.id} | ${r.username} | ${r.email}</p>`).join('') || '<p>no row</p>')));
  } catch {
    res.status(200).send(page('profile', env(`sql=${sql}`) + '<p class="err">query failed</p>'));
  }
});

// D4 X-Forwarded-For（服务端按请求头取值拼 SQL —— 实战常见）
app.get('/api/visitor', async (req, res) => {
  const ip = String(req.headers['x-forwarded-for'] || '127.0.0.1').split(',')[0].trim();
  const sql = `SELECT username FROM users WHERE username='${ip}'`;
  try {
    const rows = await q(sql);
    res.send(page('visitor', env(`sql=${sql}`) +
      `<p>visitor: ${rows.length ? rows[0].username : 'unknown'}</p>`));
  } catch {
    res.status(200).send(page('visitor', env(`sql=${sql}`) + '<p class="err">query failed</p>'));
  }
});

// D5 参数经 base64 解码后拼入（工具需支持编码参数）
app.get('/api/encoded', async (req, res) => {
  let raw = String(req.query.d ?? '');
  let decoded = raw;
  try {
    decoded = Buffer.from(raw, 'base64').toString('utf8');
  } catch {
    /* 非 base64 则原样用 */
  }
  if (!decoded) decoded = '1';
  const sql = `SELECT id, username FROM users WHERE id=${decoded}`;
  try {
    const rows = await q(sql);
    res.send(page('encoded', env(`decoded=${decoded}`) +
      (rows.map((r) => `<p>${r.id} | ${r.username}</p>`).join('') || '<p>no row</p>')));
  } catch {
    res.status(200).send(page('encoded', env(`decoded=${decoded}`) + '<p class="err">query failed</p>'));
  }
});

// D6 REST path 段
app.get('/api/rest/:id', async (req, res) => {
  const id = req.params.id;
  const sql = `SELECT id, name, price FROM products WHERE id=${id}`;
  try {
    const rows = await q(sql);
    res.send(page('rest', env(`sql=${sql}`) +
      (rows.map((r) => `<p>${r.id} | ${r.name} | ${r.price}</p>`).join('') || '<p>no row</p>')));
  } catch {
    res.status(200).send(page('rest', env(`sql=${sql}`) + '<p class="err">query failed</p>'));
  }
});

// ══════════════════════════════════════════════════════════════════════════
// E. 高阶（2）：二阶跨角色 + 堆叠
// ══════════════════════════════════════════════════════════════════════════

// E1a 二阶：低权写入（用户可控内容落库）
app.post('/api/comment', async (req, res) => {
  const item = String(req.body.item ?? 'note');
  const addr = String(req.body.address ?? 'somewhere');
  const user = String(req.body.username ?? 'bob');
  try {
    await q('INSERT INTO orders (username, item, address, status) VALUES (?, ?, ?, ?)',
      [user, item, addr, 'pending']);
    res.json({ ok: true, stored: { item, addr } });
  } catch (e) {
    res.json({ ok: false, error: String(e.message) });
  }
});

// E1b 触发页：admin-only 面板。
// [2026-09-20 勘误] 原注释写「把存储内容拼进 SQL（跨角色才能触发）」，**与实现不符**：
// 拼进 SQL 的是 **HTTP query 的 status**（见下方 `WHERE status='${req.query.status}'`），
// 而 /api/comment 写入的 username/item/address 只出现在 **SELECT 列表（输出）**，
// 不参与 WHERE —— 即写入不影响查询结构，本点**并非二阶注入**，
// 而是「需 admin 会话的直接 query 注入」。
// 依据：① 如上的代码；② 实测不带任何前置写入、直接对 `?status=` 注入即产生响应差异。
// **SQL 拼接形态一字未改**，只订正分类与注释（靶点的能力本身没变）。
app.get('/api/admin/orders', async (req, res) => {
  const cookie = String(req.headers.cookie || '');
  const m = /(?:^|;\s*)token=([^;]*)/.exec(cookie);
  const token = m ? m[1] : '';
  let role = 'anon';
  try {
    const s = await q('SELECT username, role FROM sessions WHERE token=?', [token]);
    if (s.length) role = s[0].role;
  } catch { /* 会话查询失败按匿名处理 */ }
  if (role !== 'admin') {
    return res.status(403).send(page('admin orders', '<p>403 admin only</p>'));
  }
  const status = req.query.status ?? 'pending';
  const sql = `SELECT id, username, item, address FROM orders WHERE status='${status}'`;
  try {
    const rows = await q(sql);
    res.send(page('admin orders', env(`sql=${sql}`) +
      rows.map((r) => `<p>${r.id} | ${r.username} | ${r.item} | ${r.address}</p>`).join('')));
  } catch (e) {
    res.status(200).send(page('admin orders', env(`sql=${sql}`) +
      `<p class="err">SQL Error: ${String(e.message).replace(/</g, '&lt;')}</p>`));
  }
});

// E2 堆叠：多语句通道（mysql2 默认禁多语句 → 显式开启多条语句能力）
app.get('/api/batch', async (req, res) => {
  const id = req.query.id ?? '1';
  const sql = `SELECT id, username FROM users WHERE id=${id}`;
  try {
    // multipleStatements 需在连接上开启；这里用独立连接以真实支持堆叠
    const conn = await mysql.createConnection({ ...DB, multipleStatements: true });
    try {
      const [rows] = await conn.query(sql);
      const flat = Array.isArray(rows) ? rows : [rows];
      res.send(page('batch', env(`sql=${sql}`) +
        JSON.stringify(flat[0]).slice(0, 400)));
    } finally {
      await conn.end();
    }
  } catch (e) {
    res.status(200).send(page('batch', env(`sql=${sql}`) +
      `<p class="err">SQL Error: ${String(e.message).replace(/</g, '&lt;')}</p>`));
  }
});

// ══════════════════════════════════════════════════════════════════════════
// F. 安全对照点（7）—— 误报率比检出率更能决定工具能不能上生产
// ══════════════════════════════════════════════════════════════════════════

// F1 参数化查询（真安全）
app.get('/api/safe/user', async (req, res) => {
  const id = req.query.id ?? '1';
  try {
    const rows = await q('SELECT id, username FROM users WHERE id=?', [id]);
    res.send(page('safe user', `<p>rows: ${rows.length}</p>`));
  } catch {
    res.status(200).send(page('safe user', '<p>rows: 0</p>'));
  }
});

// F2 随机 nonce 页（动态内容，无注入）
app.get('/api/safe/nonce', (_req, res) => {
  const nonce = Math.random().toString(36).slice(2) + Date.now().toString(36);
  res.send(page('nonce', `<p>nonce=${nonce}</p><p>ts=${Date.now()}</p><p>block=${Math.random().toString(16).slice(2)}</p>`));
});

// F3 恒定 500
app.get('/api/safe/error', (_req, res) => {
  res.status(500).send('<html><body><h1>Internal Server Error</h1><p>unexpected condition</p></body></html>');
});

// F4 恒定 403
app.get('/api/safe/forbidden', (_req, res) => {
  res.status(403).send('<html><body><h1>403 Forbidden</h1><p>access denied</p></body></html>');
});

// F5 302 重定向
app.get('/api/safe/redirect', (_req, res) => {
  res.redirect(302, '/api/safe/nonce');
});

// F6 静态页
app.get('/static/hello.html', (_req, res) => {
  res.type('text/html').send('<!DOCTYPE html><html><body><h1>Welcome</h1><p>static content, no parameters.</p></body></html>');
});

// F7 白名单（intval）校验
app.get('/api/safe/intval', async (req, res) => {
  const raw = String(req.query.id ?? '1');
  const id = parseInt(raw, 10);
  if (!Number.isFinite(id)) return res.status(200).send(page('safe intval', '<p>invalid id</p>'));
  try {
    const rows = await q(`SELECT id, username FROM users WHERE id=${id}`);
    res.send(page('safe intval', `<p>rows: ${rows.length}</p>`));
  } catch {
    res.status(200).send(page('safe intval', '<p>rows: 0</p>'));
  }
});

// 健康探测（评测驱动用来确认靶场已就绪）
app.get('/__lab/health', (_req, res) => {
  res.json({ ok: true, waf: WAF_ON, port: PORT, ts: Date.now() });
});

const server = app.listen(PORT, '127.0.0.1', () => {
  console.log(`[blackbox-lab] listening on http://127.0.0.1:${PORT}  WAF=${WAF_ON ? 'ON' : 'OFF'}`);
  console.log(`[blackbox-lab] db=blackbox_lab @ ${DB.host}:${DB.port}`);
});

export { app, server, pool };
