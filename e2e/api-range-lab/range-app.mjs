// ============================================================================
// e2e/api-range-lab/range-app.mjs —— 「接口 × 靶场」专用真实靶站
//
// 与既有靶场的分工差异（为什么要新写一个，而不是复用 real-mysql-lab/lab-app.js）：
//   既有靶场回答的是「**引擎**能不能检出这个注入点」，它的端点只覆盖 url query；
//   本靶场回答的是「**HTTP 接口**把这个能力交付给用户了没有」，故它必须能观测：
//     ① 注入位置族：url / body / cookie / header 四类各自独立成端点 —— 接口的
//        target.bodyParams / cookieParams / headerParams 三条入参路径要有真目标可打；
//     ② 会话依赖：/account 与 /report 缺凭据直接 401 —— 用来验「扫描建立的会话，
//        利用接口是否继承」（不继承就是接口的半截功能）；
//     ③ 流量取证：/__range/stats 逐条记录打到靶站的请求。pause/resume、stop、
//        retest 的「只重跑一个点」这类承诺，只有靶站侧计数才算证据，
//        接口自报 paused:true 不算（本仓反复踩过"注册成功≠在干活"）。
//     ④ 可修复开关：/patch 端点按 patched 标志在「拼接 SQL」与「参数化」之间切换，
//        于是 /scan/:id/diff 的 fixed 集合能在真库上取证，而不是拿两个不同 URL 糊弄。
//
// 数据库：真实 MySQL（由 e2e/run-with-sandbox.py 注入 MYSQL_* 环境变量；默认 127.0.0.1:3308）
// 用法：node e2e/api-range-lab/range-app.mjs            # 独立常驻（调试用）
//       由 run.mjs 以 createRangeApp(pool) 形式在同一进程内拉起（门禁用）
// ============================================================================
import { createRequire } from 'node:module';

const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = _require('express');
const mysql = _require('mysql2/promise');

// 会话/凭据常量：靶站侧硬编码，测试侧引用同一份导出（避免两边各写一份漂移）
export const LAB_SESSION_COOKIE = 'sid=lab-sess-2026';
export const LAB_AUTH_HEADER = 'lab-secret-2026';

const PORT = Number(process.env.API_RANGE_LAB_PORT) || 8260;

/**
 * 构造靶站 app。
 * @param {import('mysql2/promise').Pool} pool 真实 MySQL 连接池
 * @param {{recordLimit?: number}} [opts]
 */
export function createRangeApp(pool, opts = {}) {
  const recordLimit = opts.recordLimit ?? 2000;
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json({ limit: '256kb' }));
  // [2026-10-01] XML / SOAP 通道：声明 xml/soap 的 body 按**原文字符串**收（不能被 JSON
  // 解析器吃掉）。放在 urlencoded/json 之后作兜底 —— 无 body 或已解析过的请求不受影响。
  app.use(express.text({ type: ['text/xml', 'application/xml', 'application/soap+xml', '*/xml'], limit: '256kb' }));

  // ── 流量取证 ──────────────────────────────────────────────────────────────
  const state = {
    patched: false,
    total: 0,
    byPath: Object.create(null),
    byParam: Object.create(null), // `${location}:${param}` -> { hits, values:Set }
    // 受保护端点的两种命中分开计数：这是"利用接口有没有继承扫描凭据"的唯一外部证据。
    // 只看接口返回 ok:true 是不够的 —— 401 页面也可能被当成一次正常响应走完流程。
    authOk: Object.create(null),
    authDenied: Object.create(null),
    deniedSamples: [],
    recent: [],
  };
  const noteAuth = (p, ok, req) => {
    const bucket = ok ? state.authOk : state.authDenied;
    bucket[p] = (bucket[p] || 0) + 1;
    // 失败现场：被拒时记下这发实际带了哪些头/什么查询串，
    // 否则"凭据没继承"这类结论只能靠猜（本仓教训：断言要能自己解释为什么红）
    if (!ok && req) {
      state.deniedSamples.push({
        ts: Date.now(),
        path: p,
        headerNames: Object.keys(req.headers || {}).sort().join(','),
        query: req.url || '',
        cookie: String(req.headers?.cookie || ''),
      });
    }
  };
  const note = (location, param, value) => {
    if (!param) return;
    const key = `${location}:${param}`;
    if (!state.byParam[key]) state.byParam[key] = { hits: 0, values: new Set() };
    state.byParam[key].hits += 1;
    if (state.byParam[key].values.size < 50) state.byParam[key].values.add(String(value ?? '').slice(0, 160));
  };
  const record = (req, location, param, value) => {
    state.total += 1;
    const p = req.path;
    state.byPath[p] = (state.byPath[p] || 0) + 1;
    note(location, param, value);
    if (state.recent.length < recordLimit) {
      state.recent.push({ ts: Date.now(), method: req.method, path: p, location, param, value: String(value ?? '').slice(0, 200) });
    }
  };

  const html = (title, body) =>
    `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title></head><body><h1>${title}</h1>${body}</body></html>`;
  const table = (rows) => {
    if (!rows || rows.length === 0) return '<p>No results found.</p>';
    const cols = Object.keys(rows[0]);
    return `<table border="1"><tr>${cols.map((c) => `<th>${c}</th>`).join('')}</tr>${rows
      .map((r) => `<tr>${cols.map((c) => `<td>${String(r[c] ?? '')}</td>`).join('')}</tr>`)
      .join('\n')}</table>`;
  };
  const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
  // 把 mysql 报错原文回显（真实"开发者缺陷风格"站点就是这样泄露堆栈的），
  // 但 /blind 用 swallow=true 路径吞掉——两类目标行为都要有真目标可打。
  const runQuery = async (sql, params, { swallow = false } = {}) => {
    try {
      return params ? await pool.query(sql, params) : await pool.query(sql);
    } catch (e) {
      if (swallow) return [ [], [] ];
      throw e;
    }
  };

  // ── url query：数值型（union / error / boolean / time 全可用） ──
  app.get('/num', wrap(async (req, res) => {
    const v = req.query.id ?? '1';
    record(req, 'url', 'id', v);
    const [rows] = await runQuery(`SELECT * FROM users WHERE id = ${v}`);
    res.send(html('User Detail', table(rows)));
  }));

  // ── WAF 前置端点（F1 2026-10-03）：命中**原始签名**的探测一律 403，基线放行进 SQL ──
  // 存在的目的：给「拦截证据驱动的自适应链验证 + 驱动重跑」一个真实触发源 —— 这两条
  // 路径的 HTTP 走 detect.js 的两支 ad-hoc 客户端（裸 getScanClient 视图）。配合 cases.mjs
  // 的「wafEvasion 目标暂停零流量」用例：暂停闸若只挂 ctxBase 包装层，这里就是漏网之鱼。
  // ⚠️ 拦截判据只拦**原始签名**（' " -- AND OR UNION …），刻意放行 tamper 变换形态
  // （&& / # / 0x.. / char( / /**/）—— 若把变换形态也拦光，链验证 3 条全被拦、引擎按
  // 「跳过自动重跑」收场（省掉注定失败的整轮请求），重跑根本不发生，本用例就没有相位可锚。
  app.get('/wafnum', wrap(async (req, res) => {
    const v = req.query.id ?? '1';
    record(req, 'url', 'id', v);
    if (/('|"|--\s|\bAND\b|\bOR\b|\bUNION\b|\bSELECT\b|\bSLEEP\b|\bFROM\b|\/\*)/i.test(String(v))) {
      return res.status(403).type('html').send('<!DOCTYPE html><html><body><p>blocked by waf rule 942100</p></body></html>');
    }
    const [rows] = await runQuery(`SELECT * FROM users WHERE id = ${v}`);
    res.send(html('User Detail', table(rows)));
  }));

  // ── url query：字符串型（' 闭合） ──
  app.get('/str', wrap(async (req, res) => {
    const v = req.query.name ?? 'alice';
    record(req, 'url', 'name', v);
    const [rows] = await runQuery(`SELECT * FROM users WHERE username = '${v}'`);
    res.send(html('Profile', table(rows)));
  }));

  // ── url query：布尔盲注（错误吞掉、无回显差异之外的信息） ──
  app.get('/blind', wrap(async (req, res) => {
    const v = req.query.uid ?? '1';
    record(req, 'url', 'uid', v);
    let [rows] = await runQuery(`SELECT id, username FROM users WHERE id = ${v}`, null, { swallow: true });
    const body = rows.length
      ? `<div class="card">found:${rows[0].username}</div>`
      : '<div class="card">not found</div>';
    res.send(html('Blind Lookup', body));
  }));

  // ── POST body：字符串型注入（接口的 bodyParams 入参路径要有真目标） ──
  app.post('/search', wrap(async (req, res) => {
    const v = (req.body && req.body.q) ?? 'chair';
    record(req, 'body', 'q', v);
    const [rows] = await runQuery(`SELECT * FROM products WHERE title LIKE '%${v}%'`);
    res.send(html('Search', table(rows)));
  }));

  // ── POST body：XML / SOAP（[2026-10-01] 竞品对标 ghauri 的 XML·SOAP 支持）──────
  // 为什么要这个端点：JSON 嵌套通道早就有真目标（/search 表单 + jsonBody），XML 通道此前
  // **没有任何真目标** —— 加通道不加靶场，等于把能力声明做成无证据的口号。
  // 形态刻意做成真实 SOAP：XML 声明 + Envelope/Body 包裹 + 响应也是 XML。
  // 注入面在 `<id>` 叶子（数值上下文，union/error/boolean 全可用）；
  // 靶站侧自己用最小正则取叶子值（不 import 引擎的 xmlBody.js —— 靶站若与被验代码共用
  // 解析器，解析对了也不能证明"引擎的解析对了"）。
  app.post('/soap', wrap(async (req, res) => {
    const raw = typeof req.body === 'string' ? req.body : String(req.body ?? '');
    const m = /<id>([\s\S]*?)<\/id>/.exec(raw);
    const v = m ? m[1] : '1';
    record(req, 'body', 'id', v);
    const [rows] = await runQuery(`SELECT id, username FROM users WHERE id = ${v}`, null, { swallow: true });
    const items = rows.map((r) => `<item><id>${r.id}</id><username>${r.username}</username></item>`).join('');
    res.type('text/xml').send(
      `<?xml version="1.0" encoding="UTF-8"?>`
      + `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>`
      + `<GetUserResponse><count>${rows.length}</count>${items}</GetUserResponse>`
      + `</soap:Body></soap:Envelope>`,
    );
  }));

  // ── Cookie：需要会话 Cookie 才可达（验「会话是否被接口继承」） ──
  app.get('/account', wrap(async (req, res) => {
    const cookies = String(req.headers.cookie || '');
    if (!cookies.includes('sid=lab-sess-2026')) {
      noteAuth('/account', false, req);
      return res.status(401).send(html('Login required', '<p>missing session cookie</p>'));
    }
    noteAuth('/account', true);
    const m = /(?:^|;\s*)uid=([^;]+)/.exec(cookies);
    const v = m ? decodeURIComponent(m[1]) : '1';
    record(req, 'cookie', 'uid', v);
    const [rows] = await runQuery(`SELECT id, username, role FROM users WHERE id = ${v}`);
    res.send(html('Account', table(rows)));
  }));

  // ── Header：需要自定义鉴权头（验 headerParams 入参路径 + 利用继承） ──
  app.get('/report', wrap(async (req, res) => {
    if (String(req.headers['x-auth'] || '') !== LAB_AUTH_HEADER) {
      noteAuth('/report', false, req);
      return res.status(401).send(html('Forbidden', '<p>missing X-Auth</p>'));
    }
    noteAuth('/report', true);
    const v = String(req.headers['x-section'] || 'users');
    record(req, 'header', 'x-section', v);
    const [rows] = await runQuery(`SELECT id, username FROM users WHERE role IN (SELECT role FROM users WHERE username LIKE '%${v}%')`);
    res.send(html('Section report', table(rows)));
  }));

  // ── 可修复开关：diff 接口的真取证目标 ──
  // patched=false 拼接（可注入）；patched=true 走参数化占位符（修好了）。
  // 同一个 URL、同一段业务代码，只换可控变量 —— 这样 diff 报出来的 fixed 才有意义。
  app.get('/patch', wrap(async (req, res) => {
    const v = req.query.id ?? '1';
    record(req, 'url', 'id', v);
    if (state.patched) {
      const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [Number(v) || 1]);
      return res.send(html('Patched User', table(rows)));
    }
    const [rows] = await runQuery(`SELECT * FROM users WHERE id = ${v}`);
    res.send(html('User (vulnerable)', table(rows)));
  }));

  // ── 安全对照：恒参数化（接口层误报要有真目标可测） ──
  app.get('/safe', wrap(async (req, res) => {
    const v = req.query.id ?? '1';
    record(req, 'url', 'id', v);
    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [Number(v) || 1]);
    res.send(html('Safe User', table(rows)));
  }));

  // ── 靶站控制面（只服务取证，不参与注入） ──
  app.get('/__range/stats', (req, res) => {
    const byParam = Object.entries(state.byParam).map(([key, v]) => ({
      key,
      location: key.split(':')[0],
      param: key.split(':')[1],
      hits: v.hits,
      distinctValues: v.values.size,
      sampleValues: [...v.values].slice(0, 12),
    }));
    res.json({
      total: state.total,
      byPath: state.byPath,
      byParam,
      authOk: state.authOk,
      authDenied: state.authDenied,
      deniedSamples: state.deniedSamples.slice(-8),
      patched: state.patched,
      recent: state.recent.slice(-Number(req.query.recent || 40)),
    });
  });
  app.post('/__range/reset', (req, res) => {
    state.total = 0;
    state.byPath = Object.create(null);
    state.byParam = Object.create(null);
    state.authOk = Object.create(null);
    state.authDenied = Object.create(null);
    state.deniedSamples = [];
    state.recent = [];
    res.json({ ok: true });
  });
  app.post('/__range/config', express.json(), (req, res) => {
    if (typeof req.body?.patched === 'boolean') state.patched = req.body.patched;
    res.json({ ok: true, patched: state.patched });
  });

  app.use((err, req, res, next) => {
    // 真实报错回显：把 SQL 错误原文交给响应体（error 通道靠它）
    res.status(500).send(html('Server Error', `<pre>${String(err.message || err)}</pre>`));
  });

  return app;
}

// ── 独立常驻模式（调试用；门禁走 run.mjs 同进程内拉起） ──
const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (isMain && process.argv[1].replace(/\\/g, '/').endsWith('e2e/api-range-lab/range-app.mjs')) {
  const pool = mysql.createPool({
    host: process.env.MYSQL_HOST ?? '127.0.0.1',
    port: Number(process.env.MYSQL_PORT) || 3306,
    user: process.env.MYSQL_USER ?? 'root',
    password: process.env.MYSQL_PASSWORD ?? 'root',
    database: process.env.MYSQL_DATABASE || 'sqli_lab',
    connectionLimit: 8,
  });
  createRangeApp(pool).listen(PORT, '127.0.0.1', () => {
    console.log(`[range-app] 靶站就绪 http://127.0.0.1:${PORT} (MySQL ${process.env.MYSQL_HOST || '127.0.0.1'}:${process.env.MYSQL_PORT || 3306})`);
  });
}

export default createRangeApp;
