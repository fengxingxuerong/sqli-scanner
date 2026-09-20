// ============================================================================
// redteam-lab —— 独立红队评测靶场（2026-09-10）
//   * 真实 MySQL 8.0.37 拼接 SQL，不做任何模拟
//   * 24 个靶点：16 个真实可注入 + 8 个安全对照（误报检测）
//   * 与项目自带 e2e 靶场无复用，用于外部视角复评
// ============================================================================
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = require('express');
const mysql = require('mysql2/promise');

// 口令走环境变量：本机 MySQL 的 root 口令未必为空（其它 e2e 靶场用的是 root/root），
// 硬编码空口令会让靶场在不同机器上莫名连不上。默认值保持空以兼容原环境。
const DB_PASSWORD = process.env.LAB_DB_PASSWORD ?? '';
const DB_CFG = {
  host: '127.0.0.1', port: 3306, user: 'root', password: DB_PASSWORD,
  database: 'redteam_lab', multipleStatements: true,
};
const DB_CFG_SAFE = { ...DB_CFG, multipleStatements: false };
// [stability-FIX 2026-09-14 / TODO 3b] q() 原实现**每条查询新建 TCP 连接再销毁**——
// 26 靶点全量扫描 ≈ 2600 次高频短连。连接风暴下观测到两个进程先后 native 崩溃：
// node（靶场）0xC0000409 fast-fail（无栈、killed=false）+ mysqld（CrashDumps 有
// mysqld.exe.5948.dmp）。改为常驻连接池消除连接风暴。两个池严格保留
// multipleStatements 语义边界：堆叠靶点（E16）用 true 池，安全对照（F18-F24）
// 与参数化查询用 false 池——防止堆叠能力泄漏到安全端点造成真值漂移。
const poolVuln = mysql.createPool({ ...DB_CFG, connectionLimit: 12 });
const poolSafe = mysql.createPool({ ...DB_CFG_SAFE, connectionLimit: 6 });

export async function createLabApp() {
  // ── 初始化数据 ──
  const root = await mysql.createConnection({ host: '127.0.0.1', port: 3306, user: 'root', password: DB_PASSWORD });
  await root.query(`CREATE DATABASE IF NOT EXISTS redteam_lab DEFAULT CHARSET utf8mb4`);
  await root.query('USE redteam_lab');
  await root.query(`CREATE TABLE IF NOT EXISTS users(
    id INT PRIMARY KEY, name VARCHAR(64), email VARCHAR(64), secret VARCHAR(64)) ENGINE=InnoDB`);
  await root.query(`CREATE TABLE IF NOT EXISTS products(
    id INT PRIMARY KEY, title VARCHAR(64), price INT) ENGINE=InnoDB`);
  const seedU = [[1,'alice','alice@lab.io','SEC-A-9f21'],[2,'bob','bob@lab.io','SEC-B-3312'],
    [3,'carol','carol@lab.io','SEC-C-77aa'],[4,'dave','dave@lab.io','SEC-D-0c19'],
    [5,'erin','erin@lab.io','SEC-E-5520']];
  for (const r of seedU) await root.query('REPLACE INTO users VALUES(?,?,?,?)', r);
  const seedP = [[1,'Keyboard',199],[2,'Mouse',99],[3,'Monitor',1299]];
  for (const r of seedP) await root.query('REPLACE INTO products VALUES(?,?,?)', r);
  // D16 COLLATE 混存靶点：老库迁移常见「同表两列 collation 不同」。
  // 若提取 SQL 在此表上抛 Illegal mix of collations → UNION/GROUP_CONCAT 聚合提取全灭。
  await root.query(`DROP TABLE IF EXISTS mixcols`);
  await root.query(`CREATE TABLE mixcols(
    id INT PRIMARY KEY,
    a VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci,
    b VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci) ENGINE=InnoDB`);
  for (const r of [[1,'alpha','beta-x9'],[2,'gamma','delta-x8'],[3,'epsilon','zeta-x7']]) {
    await root.query('REPLACE INTO mixcols VALUES(?,?,?)', r);
  }
  await root.end();

  const app = express();
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());
  app.use((req, _res, next) => { req.__t0 = Date.now(); next(); });

  const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>
<style>body{font:14px/1.6 system-ui;padding:24px;max-width:900px;margin:auto}table{border-collapse:collapse;margin:12px 0}td,th{border:1px #ccc;padding:4px 10px}</style>
</head><body><h2>${title}</h2><div id="content">${body}</div></body></html>`;
  const rowsHtml = (rows) => (!rows || !rows.length) ? '<p>NO_ROWS</p>'
    : `<table>${rows.map(r => `<tr>${Object.values(r).map(v => `<td>${v}</td>`).join('')}</tr>`).join('')}</table>`;

  const q = async (sql, safe = false) => {
    // [stability-FIX 2026-09-14 / TODO 3b] 原 createConnection-per-query 已换常驻池（见顶部注释）
    const pool = safe ? poolSafe : poolVuln;
    const [rows] = await pool.query(sql);
    return rows;
  };

  // 统一异常出口（模拟开启 debug 的站点，把 SQL 错误吐给前端）
  const run = async (res, title, fn, { leak = true } = {}) => {
    try {
      const out = await fn();
      res.status(200).send(page(title, out));
    } catch (e) {
      res.status(500).send(page(title, leak ? `<pre>SQL_ERROR: ${e.message}</pre>` : '<pre>INTERNAL_ERROR</pre>'));
    }
  };

  // ───────────────────────── A. 回显型 ─────────────────────────
  // A1 数字型 UNION
  app.get('/shop/item', (req, res) => run(res, 'item', async () => {
    const id = req.query.id ?? '1';
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE id=${id}`));
  }));

  // A2 字符串单引号 UNION
  app.get('/shop/search', (req, res) => run(res, 'search', async () => {
    const name = req.query.name ?? 'alice';
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE name='${name}'`));
  }));

  // A3 LIKE 模糊
  app.get('/shop/find', (req, res) => run(res, 'find', async () => {
    const w = req.query.q ?? 'a';
    return rowsHtml(await q(`SELECT id,name FROM users WHERE name LIKE '%${w}%'`));
  }));

  // A4 ORDER BY 位置注入（无引号）
  app.get('/shop/sort', (req, res) => run(res, 'sort', async () => {
    const by = req.query.by ?? 'id';
    return rowsHtml(await q(`SELECT id,name FROM users ORDER BY ${by}`));
  }));

  // A5 双参数：仅 id 可注入，cat 参数化（考验参数定位 + 误报）
  app.get('/shop/detail', (req, res) => run(res, 'detail', async () => {
    const id = req.query.id ?? '1';
    const rawCat = Number(req.query.cat ?? 0);
    const cat = Number.isFinite(rawCat) ? rawCat : 0; // 白名单数字：cat 不可注入
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE id=${id} AND id > ${cat}`));
  }));

  // ───────────────────────── B. 报错型 ─────────────────────────
  // B6 数字型 + 错误回显（extractvalue/updatexml 通道）
  app.get('/shop/err', (req, res) => run(res, 'err', async () => {
    const id = req.query.id ?? '1';
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE id=${id}`));
  }));

  // ───────────────────────── C. 盲注 ─────────────────────────
  // C7 布尔盲注（内容差异，HTTP 码恒定 200，不吐错误）
  app.get('/shop/blind', async (req, res) => {
    const id = req.query.id ?? '1';
    try {
      const rows = await q(`SELECT id,name FROM users WHERE id=${id}`);
      res.status(200).send(page('blind', rows.length ? `<p>FOUND_USER:${rows[0].name}</p>` : '<p>NOT_FOUND</p>'));
    } catch { res.status(200).send(page('blind', '<p>NOT_FOUND</p>')); }
  });

  // C8 时间盲注（响应恒定，仅 SLEEP 生效）
  app.get('/shop/time', async (req, res) => {
    const id = req.query.id ?? '1';
    try { await q(`SELECT id,name FROM users WHERE id=${id}`); } catch { /* 静默 */ }
    res.status(200).send(page('time', '<p>CONSTANT_PAGE</p>'));
  });

  // ───────────────────────── D. 其他注入通道 ─────────────────────────
  // D9 POST form
  app.post('/login', (req, res) => run(res, 'login', async () => {
    const u = req.body.username ?? '';
    const p = req.body.password ?? '';
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE name='${u}' AND secret='${p}'`));
  }));

  // D10 POST JSON
  app.post('/api/profile', (req, res) => run(res, 'profile', async () => {
    const uid = req.body.uid ?? 1;
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE id=${uid}`));
  }));

  // D11 Cookie 注入
  app.get('/shop/cookie', (req, res) => run(res, 'cookie', async () => {
    const raw = req.headers.cookie || 'uid=1';
    const m = /uid=([^;]+)/.exec(raw);
    const uid = m ? m[1] : '1';
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE id=${uid}`));
  }));

  // D12 X-Forwarded-For 注入
  app.get('/shop/ip', (req, res) => run(res, 'xff', async () => {
    const ip = req.headers['x-forwarded-for'] || '1';
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE id=${ip}`));
  }));

  // D13 Path 参数。不用 :id 路由参数：Express 在**路由匹配阶段**就对路径段做
  // decodeURIComponent，payload 含非法序列（如 `1%%22`）时直接 URIError → 400，
  // handler 根本进不去（这也是上一版 decodeSafe 补丁无效的原因——它写在 handler 里，
  // 而 decode 发生在 handler 之前）。改为 app.use 前缀匹配 + 手工取最后一段原样拼 SQL
  //（保留「直接拼进查询」的注入语义，非法序列由 decodeSafe 容错）。
  app.use('/shop/user', (req, res) => {
    const rawSeg = decodeSafe(String(req.originalUrl).split('?')[0].split('/').pop() ?? '1');
    run(res, 'user', async () =>
      rowsHtml(await q(`SELECT id,name,email FROM users WHERE id=${rawSeg}`)));
  });

  // D14 base64 编码参数（考验能否处理编码）
  app.get('/shop/b64', (req, res) => run(res, 'b64', async () => {
    let id = '1';
    try { id = Buffer.from(String(req.query.id ?? ''), 'base64').toString('utf8') || '1'; } catch { /* 保持默认 */ }
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE id=${id}`));
  }));

// 容错 decode：非法序列原样返回（模拟"站点自己 decode 失败时拿原始值凑合用"的真实行为，
// 也让扫描端看到 200 + 注入差异，而不是 500 噪声）
function decodeSafe(v) {
  try { return decodeURIComponent(v); } catch { return v; }
}
  // D15 自定义参数分隔符（; ）——模拟只认分号的站点。
  // Express 默认按 & 解析会把 `a=1;id=1` 整体塞进 a 的值，所以这里从 originalUrl 手工切。
  app.get('/shop/semi', (req, res) => run(res, 'semi', async () => {
    const qs = String(req.originalUrl).split('?')[1] || '';
    const map = {};
    for (const part of qs.split(';')) {
      if (!part) continue;
      const i = part.indexOf('=');
      // [LAB-FIX 2026-09-20 / TODO §D] 原先四处 decodeURIComponent 裸调（本文件 187 行已备好
      // decodeSafe 却没接上）。实测后果：payload 含裸 `%`（如 `1%`、`1%zz`）时抛 URIError，
      // 被外层 run() 的 try 兜成 **500 + `SQL_ERROR: URIError` 回显**——不是「挂连接」，
      // 但这个靶点的真值是 tech=union（测 --param-del 切分），返回的却是「数据库报错」，
      // 等于靶场亲手给扫描器的 error 通道喂了假信号：明明该看 UNION 结果行，却看到一个
      // 伪 SQL 错误。真实站点只认分号时也不会对已切好的片段二次 decode，失败即用原值，
      // 故改用 decodeSafe（与 187-191 行既有容错语义一致）。
      if (i < 0) {
        map[decodeSafe(part)] = '';
        continue;
      }
      map[decodeSafe(part.slice(0, i))] = decodeSafe(part.slice(i + 1));
    }
    const id = map.id ?? '1';
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE id=${id}`));
  }));

  // D16 COLLATE 混存靶点：字符串上下文注入，dumpData 会对 a/b 两列做多列聚合提取
  app.get('/shop/mix', (req, res) => run(res, 'mix', async () => {
    const kw = String(req.query.kw ?? 'alpha');
    return rowsHtml(await q(`SELECT a,b FROM mixcols WHERE a LIKE '%${kw}%'`));
  }));

  // ───────────────────────── E. 高阶场景 ─────────────────────────
  // E15 二阶注入：POST 存储 → GET 触发（触发页需会话，无 cookie 401）
  const store = new Map();
  app.post('/account/update', (req, res) => {
    const sid = /sid=([^;]+)/.exec(req.headers.cookie || '')?.[1] || 'anon';
    store.set(sid, String(req.body.name ?? 'alice'));
    res.status(200).send(page('update', '<p>SAVED</p>'));
  });
  app.get('/account/me', async (req, res) => {
    const sid = /sid=([^;]+)/.exec(req.headers.cookie || '')?.[1];
    if (!sid || !store.has(sid)) return res.status(401).send(page('me', '<p>UNAUTHORIZED</p>'));
    const name = store.get(sid);
    try {
      const rows = await q(`SELECT id,name,email,secret FROM users WHERE name='${name}'`);
      res.status(200).send(page('me', rowsHtml(rows)));
    } catch (e) {
      res.status(500).send(page('me', `<pre>SQL_ERROR: ${e.message}</pre>`));
    }
  });

  // E16 堆叠查询
  app.get('/shop/stack', (req, res) => run(res, 'stack', async () => {
    const id = req.query.id ?? '1';
    return rowsHtml(await q(`SELECT id,name FROM users WHERE id=${id}`));
  }));

  // E17 WAF 前置（中等强度正则，模拟云 WAF 常见规则）
  const WAF_RULES = [
    /\bunion\b[\s\S]{0,20}\bselect\b/i,
    /\bselect\b[\s\S]{0,40}\bfrom\b[\s\S]{0,40}information_schema/i,
    /\bsleep\s*\(/i, /\bbenchmark\s*\(/i, /\bpg_sleep\s*\(/i, /\bwaitfor\s+delay\b/i,
    /'\s*(or|and)\s+['"]?\d+\s*=\s*\d+/i,
    /(--\s|#\s|\/\*)/,
    /\bconcat\s*\(/i, /\bextractvalue\s*\(/i, /\bupdatexml\s*\(/i,
    /\binformation_schema\b/i,
    /\bor\b\s+\d+\s*=\s*\d+/i,
  ];
  const wafHit = (vals) => vals.some(v => WAF_RULES.some(r => r.test(String(v))));
  // [FIX 2026-09-10] 只检查「用户可控输入」相关的头：真实 WAF 不会因为 Accept/Connection/
  // Accept-Encoding 这类协议头里的 */* 就拦截请求。原实现遍历全部请求头，导致 curl/扫描器
  // 默认的 `Accept: */*` 命中注释符规则 → 连良性探针都被 403，靶场等同「全拦死」，
  // 失去评测意义（曾据此误判工具 WAF 绕过能力）。现排除协议性头，保留 UA / XFF / Cookie
  // 等真实 WAF 会检查的字段。
  const WAF_SKIP_HEADERS = new Set([
    'accept', 'accept-encoding', 'accept-language', 'connection', 'host',
    'content-length', 'content-type', 'user-agent', 'referer', 'origin',
  ]);
  app.use('/waf', (req, res, next) => {
    const headerVals = Object.entries(req.headers || {})
      .filter(([k, v]) => typeof v === 'string' && !WAF_SKIP_HEADERS.has(k.toLowerCase()))
      .map(([, v]) => v);
    const vals = [...Object.values(req.query || {}), ...Object.values(req.body || {}), ...headerVals].map(String);
    if (wafHit(vals)) return res.status(403).send(page('blocked', '<p>REQUEST_BLOCKED_BY_WAF</p>'));
    next();
  });
  app.get('/waf/item', (req, res) => run(res, 'waf-item', async () => {
    const id = req.query.id ?? '1';
    return rowsHtml(await q(`SELECT id,name,email FROM users WHERE id=${id}`));
  }));

  // ───────────────────────── F. 安全对照（误报检测） ─────────────────────────
  app.get('/safe/item', async (req, res) => {
    const raw = Number(req.query.id ?? 1);
    const id = Number.isFinite(raw) ? raw : 1;
    try {
      await q('SELECT id,name,email FROM users WHERE id=?', true)
        .catch(() => []);
      const [r] = await poolSafe.query('SELECT id,name,email FROM users WHERE id=?', [id]);
      const out = r;
      res.send(page('safe-item', rowsHtml(out && out.length ? out : [])));
    } catch { res.status(500).send(page('safe-item', '<pre>INTERNAL_ERROR</pre>')); }
  });
  app.get('/safe/search', async (req, res) => {
    try {
      const [rows] = await poolSafe.query("SELECT id,name FROM users WHERE name LIKE ?", [`%${String(req.query.q ?? '')}%`]);
      res.send(page('safe-search', rowsHtml(rows)));
    } catch { res.status(500).send(page('safe-search', '<pre>INTERNAL_ERROR</pre>')); }
  });
  // 动态内容：每次随机 nonce（考验把随机性当布尔差异）
  app.get('/safe/rand', (_req, res) =>
    res.send(page('rand', `<p>NONCE:${Math.random().toString(36).slice(2)} TIME:${Date.now()}</p>`)));
  // 恒定 500 错误页（考验把错误码当注入）
  app.get('/safe/boom', (_req, res) => res.status(500).send(page('boom', '<pre>INTERNAL_ERROR</pre>')));
  // 恒定 403 拦截页（考验把 WAF 403 差异当注入）
  app.get('/safe/blocked', (_req, res) => res.status(403).send(page('blocked', '<p>REQUEST_BLOCKED_BY_WAF</p>')));
  // 302 跳转
  app.get('/safe/redirect', (_req, res) => res.redirect(302, '/safe/item?id=1'));
  // 静态页
  app.get('/safe/static', (_req, res) => res.send(page('static', '<p>HELLO_WORLD</p>')));
  // 输入被强校验（白名单数字）后仍走拼接：不可注入
  app.get('/safe/guard', (req, res) => {
    const id = /^\d+$/.test(String(req.query.id ?? '')) ? req.query.id : '1';
    return run(res, 'guard', async () => rowsHtml(await q(`SELECT id,name FROM users WHERE id=${id}`, true)));
  });

  app.get('/health', (_req, res) => res.json({ ok: true, db: 'redteam_lab' }));
  // 靶场自身健壮性：任何未捕获异常不得让靶场进程退出（否则后续靶点全变成「连接失败」）
  process.on('uncaughtException', (e) => console.error('[lab] uncaught:', e.message));
  process.on('unhandledRejection', (e) => console.error('[lab] rejection:', (e && e.message) || e));
  return app;
}
