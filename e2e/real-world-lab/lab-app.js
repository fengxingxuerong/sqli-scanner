// ============================================================================
// e2e/real-world-lab/lab-app.js —— 拟真业务靶场（真实 PostgreSQL / PGlite）
//
// 模拟「二手集市 + 用户点评」Web 应用（Express + 真实 PG 18.3 WASM）：
//   业务表：users/categories/items/orders/reviews（真实数据 + 密码哈希）
//   注入点（开发者遗留缺陷）：items(cat) / s(q,LIKE) / u(id) / api/item(JSON body)
//     / order(id,需登录) / reviews(id) / comment→panel(二阶)
//   安全对照（参数化，应 0 检出）：blog / login
//   会话：POST /login 发 sid cookie；动态页含秒级时间戳；可选 WAF
// 依赖解析：express / @electric-sql/pglite 在 server/node_modules，createRequire。
// ============================================================================
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const _e2eRequire = createRequire(import.meta.url); // 解析 e2e 本地模块（waf-profiles 等）
const express = _require('express');
const PROFILES = await import(pathToFileURL(_e2eRequire.resolve('../waf-lab/waf-profiles.js')).href);

const INIT_SQL = `
CREATE TABLE users (
  id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, email TEXT NOT NULL, admin BOOLEAN DEFAULT false
);
INSERT INTO users (username, password_hash, email, admin) VALUES
  ('admin', 'pbkdf2$dummy$admin@market', 'admin@market.local', true),
  ('alice', 'pbkdf2$dummy$alice@example', 'alice@example.com', false),
  ('bob',   'pbkdf2$dummy$bob@example', 'bob@example.com', false),
  ('张三',   'pbkdf2$dummy$zs@example', 'zhangsan@example.com', false);
CREATE TABLE categories (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
INSERT INTO categories VALUES (1, '数码'), (2, '家具'), (3, '图书');
CREATE TABLE items (
  id SERIAL PRIMARY KEY, title TEXT NOT NULL, price NUMERIC(10,2) NOT NULL,
  category_id INTEGER NOT NULL REFERENCES categories(id), seller_id INTEGER NOT NULL REFERENCES users(id)
);
INSERT INTO items (title, price, category_id, seller_id) VALUES
  ('九成新 iPad 9', 1899.00, 1, 2), ('机械键盘 87 键', 329.00, 1, 3),
  ('人体工学椅', 699.00, 2, 4), ('《深入浅出 PostgreSQL》', 59.80, 3, 2);
CREATE TABLE orders (
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  item_id INTEGER NOT NULL REFERENCES items(id), qty INTEGER NOT NULL DEFAULT 1, note TEXT
);
INSERT INTO orders (user_id, item_id, qty, note) VALUES
  (1, 1, 1, '顺丰到付'), (1, 3, 2, '工作日送货'), (2, 2, 1, '要全新未拆');
CREATE TABLE reviews (
  id SERIAL PRIMARY KEY, item_id INTEGER NOT NULL REFERENCES items(id),
  user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO reviews (item_id, user_id, body) VALUES
  (1, 2, '成色不错，电池健康 92%'), (1, 3, '屏幕有轻微划痕，整体满意');
`;
const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const errPage = (e) => html('系统错误', `<pre>${e?.message ?? String(e)}</pre>`);
const hash = (pw) => `pbkdf2$dummy$${pw}`; // 靶场登录比对（演示），真实校验一致即可

function html(title, body, extra = '') {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title></head><body>
<!-- generated at ${Math.floor(Date.now() / 1000)} -->
<h1>${title}</h1>
${body}
${extra}
</body></html>`;
}

function tableHtml(rows) {
  if (!rows || rows.length === 0) return '<p>暂无数据</p>';
  const cols = Object.keys(rows[0]);
  const head = cols.map((c) => `<th>${c}</th>`).join('');
  const trs = rows.map((r) => `<tr>${cols.map((c) => `<td>${r[c] ?? ''}</td>`).join('')}</tr>`).join('\n');
  return `<table border="1"><tr>${head}</tr>\n${trs}</table>`;
}

/** 创建靶场应用（工厂函数，供 e2e 同进程复用） */
export async function createRealLabApp(opts = {}) {
  const { PGlite } = await import(pathToFileURL(_require.resolve('@electric-sql/pglite')).href);
  const db = new PGlite();
  await db.exec(INIT_SQL);

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // —— 请求统计（供 e2e 请求数对比）——
  const stats = { total: 0, byPath: {} };
  app.use((req, _res, next) => {
    stats.total++;
    stats.byPath[req.path] = (stats.byPath[req.path] || 0) + 1;
    next();
  });

  // —— 可选 WAF 前置（对齐 waf-profiles modsecurity_crs）——
  if (opts.waf) {
    const profile = PROFILES.PROFILES.find((p) => p.id === opts.waf) || PROFILES.MODSECURITY_CRS;
    app.use((req, res, next) => {
      if (req.path.startsWith('/__')) return next();
      const probe = JSON.stringify(req.query) + JSON.stringify(req.body || '') + JSON.stringify(req.headers.cookie || '');
      const hit = profile.rules.find((r) => r.re.test(probe));
      if (hit) return res.status(403).send(html('403 Forbidden', `<p>Rule: ${hit.id}</p>`));
      next();
    });
  }

  // —— 会话（内存 Map + sid cookie）——
  const sessions = new Map();
  app.post('/login', async (req, res) => {
    const { username, password } = req.body || {};
    try {
      // 参数化查询（安全）——与业务侧一致
      const r = await db.query('SELECT * FROM users WHERE username = $1', [username]);
      const u = r.rows[0];
      if (!u || hash(password) !== u.password_hash) return res.status(401).send(html('登录失败', '<p>用户名或密码错误</p>'));
      const sid = Math.random().toString(36).slice(2);
      sessions.set(sid, u.id);
      res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Path=/`);
      res.send(html('登录成功', `<p>欢迎回来，${u.username}</p>`));
    } catch (e) {
      res.status(500).send(html('系统错误', `<pre>${e.message}</pre>`));
    }
  });
  const requireAuth = (req, res, next) => {
    const sid = (req.headers.cookie || '').match(/sid=([^;]+)/)?.[1];
    const uid = sid ? sessions.get(sid) : null;
    if (!uid) return res.status(401).send(html('未登录', '<p>请先 <a href="/login">登录</a></p>'));
    req.uid = uid;
    next();
  };
// —— 首页（含"我要点评"表单，供引擎爬取二阶 store 点）——
  app.get('/', (_req, res) => {
    res.send(
      html(
        '二手集市',
        `<p><a href="/items?cat=1">数码</a> · <a href="/s?q=键盘">搜索</a> · <a href="/u?id=1">用户</a> · <a href="/blog?id=1">博文</a></p>
<form method="POST" action="/comment">
  <label>商品ID <input name="item_id" value="1"></label>
  <textarea name="body" rows="3" cols="40">成色不错</textarea>
  <button type="submit">提交点评</button>
</form>`
      )
    );
  });

  // ============ 注入点 ①：GET /items?cat= 类别筛选（数值拼接） ============
  app.get('/items', wrap(async (req, res) => {
    const cat = req.query.cat ?? '1';
    // SECURITY-REVIEW: 模板字符串拼接注入，未参数化（真实缺陷）
    const r = await db.query(`SELECT * FROM items WHERE category_id = ${cat}`);
    res.send(html('商品列表', tableHtml(r.rows)));
  }));

  // ============ 注入点 ②：GET /s?q= 商品搜索（LIKE 拼接） ============
  app.get('/s', wrap(async (req, res) => {
    const q = req.query.q ?? '';
    // SECURITY-REVIEW: LIKE 模糊搜索直接拼接（真实缺陷）
    const r = await db.query(`SELECT * FROM items WHERE title LIKE '%${q}%'`);
    res.send(html('搜索结果', tableHtml(r.rows)));
  }));

  // ============ 注入点 ③：GET /u?id= 用户资料（数值拼接，回显） ============
  app.get('/u', wrap(async (req, res) => {
    const id = req.query.id ?? '1';
    // SECURITY-REVIEW: 直接拼接 id（真实缺陷）
    const r = await db.query(`SELECT id, username, email, admin FROM users WHERE id = ${id}`);
    res.send(html('用户资料', tableHtml(r.rows)));
  }));

  // ============ 注入点 ④：POST /api/item（JSON body 数值拼接） ============
  app.post('/api/item', wrap(async (req, res) => {
    const id = req.body?.id ?? '1';
    // SECURITY-REVIEW: JSON 字段直接拼接（真实缺陷）
    const r = await db.query(`SELECT * FROM items WHERE id = ${id}`);
    res.json(r.rows);
  }));

  // ============ 注入点 ⑤：GET /order?id= 订单详情（需登录 + 数值拼接） ============
  app.get('/order', requireAuth, wrap(async (req, res) => {
    const id = req.query.id ?? '1';
    // SECURITY-REVIEW: 已登录用户在订单查询处仍拼接 id（真实缺陷）
    const r = await db.query(
      `SELECT o.id, o.qty, o.note, i.title, i.price FROM orders o JOIN items i ON i.id=o.item_id WHERE o.id = ${id}`
    );
    res.send(html('订单详情', tableHtml(r.rows)));
  }));

  // ============ 注入点 ⑥：GET /reviews?id= 评论列表（数值拼接，报错直出） ============
  app.get('/reviews', wrap(async (req, res) => {
    const id = req.query.id ?? '1';
    // SECURITY-REVIEW: 评论查询拼接（真实缺陷）
    const r = await db.query(`SELECT r.id, r.body, u.username FROM reviews r JOIN users u ON u.id=r.user_id WHERE r.item_id = ${id}`);
    res.send(html('商品评论', tableHtml(r.rows)));
  }));

  // ============ 二阶注入链：POST /comment（store）→ GET /panel?id=（触发拼接） ============
  app.post('/comment', requireAuth, wrap(async (req, res) => {
    const { item_id, body } = req.body || {};
    if (!item_id || !body) return res.status(400).send('item_id/body 必填');
    await db.query('INSERT INTO reviews (item_id, user_id, body) VALUES ($1, $2, $3)', [Number(item_id), req.uid, String(body)]);
    res.send(html('评论已提交', '<p>感谢你的点评</p>'));
  }));

  app.get('/panel', requireAuth, async (req, res) => {
    const id = req.query.id ?? '1';
    // SECURITY-REVIEW: 触发页把「最新一条评论正文」拼进 SQL —— 真正二阶注入点
    const latest = await db.query('SELECT body FROM reviews WHERE item_id = $1 ORDER BY id DESC LIMIT 1', [Number(id)]);
    const body = latest.rows[0]?.body ?? '';
    let rows;
    try {
      rows = (await db.query(`SELECT * FROM items WHERE id = ${id} AND title != '${body}'`)).rows;
    } catch (e) {
      return res.status(500).send(html('点评面板错误', `<pre>${e.message}</pre>`));
    }
    res.send(html('点评面板', tableHtml(rows) + `<p>点评摘要：${body}</p>`));
  });

  // ============ 安全对照：参数化查询（引擎应当 0 检出） ============
  app.get('/blog', wrap(async (req, res) => {
    const id = Number(req.query.id ?? '1');
    const r = await db.query('SELECT * FROM items WHERE id = $1', [Number.isFinite(id) ? id : 1]);
    res.send(html('博文', tableHtml(r.rows)));
  }));

  // 统一错误处理：SQL 抛错 → 500 + 报错文本（真实应用行为；报错文本供检测器识别）
  app.use((err, _req, res, _next) => {
    if (res.headersSent) return;
    res.status(500).send(errPage(err));
  });

  app._stats = { ...stats, db: 'postgresql', ver: 'PostgreSQL 18.3 (PGlite)' };
  app._db = db;
  app._sessions = sessions;
  return app;
}