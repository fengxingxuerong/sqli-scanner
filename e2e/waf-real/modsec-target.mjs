// ============================================================================
// modsec-target.mjs —— 真机 WAF 对拍用的**靶站后端**
//
// 存在的理由：ModSecurity 容器是反代，必须有个上游。CI 里它要比容器先起来
// （nginx 启动时上游不在会有概率直接退出），所以拆成独立进程由 workflow 后台拉起。
//
// 两种模式：
//   · echo（默认）—— 原样回显 id，不碰数据库。测的是「WAF 放不放行」。
//   · db（MODSEC_TARGET_DB=1）—— 把 id **原样拼进 SQL** 交给真 MySQL 执行，
//     结果与错误都回显。测的是「过了 WAF 之后，注入**真的打穿了没有**」。
//
// 为什么要加 db 模式（2026-09-28）：
//   首轮真机对拍（09-27）只证明了「WAF 放行」，而放行 ≠ 能打穿 —— 靶站是 echo，
//   后端会不会按 SQL 执行、执行了能不能取数，一个都没测。仓库当时就把这条写进了
//   诚实边界、禁止对外声明绕过率。本模式补的就是那一环：同一条样本要同时满足
//   「过了 WAF」+「SQL 真的执行并吐出证据」，才算一次真绕过。
//
// ⚠️ 响应码纪律（判据与危害同源）：
//   SQL 执行失败也返回 **200**，body 前缀 `SQLERR:`。
//   原因：WAF 拦截是 403；若后端报错也用 5xx，对拍脚本的「非 2xx = 被拦」判据
//   会把「到后端了但 SQL 报错」误算成「被 WAF 拦」—— 与本仓踩过的
//   「依赖真库但环境里没起库 → ECONNREFUSED 被记成产品 FAIL」是同一类假象。
//
// 用法：
//   node e2e/waf-real/modsec-target.mjs                       # echo 模式
//   MODSEC_TARGET_DB=1 node e2e/waf-real/modsec-target.mjs    # 真库模式
// ============================================================================
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(new URL('../../server/package.json', import.meta.url));

const PORT = Number(process.env.MODSEC_TARGET_PORT || 8151);
const WANT_DB = process.env.MODSEC_TARGET_DB === '1';
const DB_CFG = {
  host: process.env.MODSEC_DB_HOST || '127.0.0.1',
  port: Number(process.env.MODSEC_DB_PORT || 3306),
  user: process.env.MODSEC_DB_USER || 'root',
  password: process.env.MODSEC_DB_PASSWORD || 'root',
  database: process.env.MODSEC_DB_NAME || 'sqli_lab',
};

// 靶表列数 = 4：samples.mjs 里 `1' UNION SELECT NULL,CONCAT(...),NULL,NULL-- -`
// 与 `1 UNION SELECT 'SQLISCANNER0'...'SQLISCANNER3'` 都是 4 列形态，
// 让**至少一部分样本具备可打穿上界** —— 否则「打穿率」的分母恒为 0，测量没有意义。
// ⚠️ 2 列形态（`SQLISCANNER0','SQLISCANNER1'`）在这张表上必然报列数不匹配，
//    这是**真实结果**而非缺陷：由 modsec-live 的直连上界如实记录，不挑端点、不放宽判据。
const TABLE = 'waf_items';
const SEED_SQL = [
  `CREATE TABLE IF NOT EXISTS ${TABLE} (id INT PRIMARY KEY, name VARCHAR(64), note VARCHAR(64), extra VARCHAR(64))`,
  `INSERT IGNORE INTO ${TABLE} (id, name, note, extra) VALUES (1,'alpha','n1','e1'),(2,'beta','n2','e2'),(3,'gamma','n3','e3')`,
];
// 时间盲注样本会真睡：会话级上限 1s，避免 228 插件 × 5s 把 CI 拖到超时。
// （被中断的查询返回 SQLERR，属「抵达 SQL 层」而非「取数成功」，判据分层处理。）
const MAX_EXEC_MS = Number(process.env.MODSEC_TARGET_MAX_EXEC_MS || 1000);

/** 真库连接；连不上返回 { conn: null, reason } —— 由调用方决定是否降级 */
async function connectDb() {
  let mysql;
  try {
    mysql = require(resolve(here, '../../server/node_modules/mysql2/promise.js'));
  } catch (e) {
    return { conn: null, reason: `mysql2 不可用：${e.message}` };
  }
  try {
    const conn = await mysql.createConnection(DB_CFG);
    for (const sql of SEED_SQL) await conn.query(sql);
    try {
      await conn.query(`SET SESSION max_execution_time = ${MAX_EXEC_MS}`);
    } catch { /* 老版本无此变量 → 时间样本退回真睡，由 CI 超时兜底 */ }
    return { conn, reason: null };
  } catch (e) {
    return { conn: null, reason: `连不上 ${DB_CFG.user}@${DB_CFG.host}:${DB_CFG.port}/${DB_CFG.database}：${e.message}` };
  }
}

const db = WANT_DB ? await connectDb() : { conn: null, reason: '未开启（MODSEC_TARGET_DB 未设为 1）' };
const MODE = db.conn ? 'db' : 'echo';
if (WANT_DB && !db.conn) console.warn(`[modsec-target] 真库模式不可用，降级为 echo：${db.reason}`);
if (db.conn) console.log(`[modsec-target] 真库模式已就绪：${DB_CFG.user}@${DB_CFG.host}:${DB_CFG.port}/${DB_CFG.database} · max_execution_time=${MAX_EXEC_MS}ms`);

/** 原样拼接（这就是注入点）；结果/错误都回显，供对拍脚本判定「打穿到哪一层」 */
async function queryDb(raw) {
  const sql = `SELECT id, name, note, extra FROM ${TABLE} WHERE id = ${raw}`;
  try {
    const [rows] = await db.conn.query(sql);
    return `ROWS:${rows.map((r) => Object.values(r).join('|')).join(';')}`;
  } catch (e) {
    return `SQLERR:${String(e && e.message ? e.message : e).replace(/\r?\n/g, ' ')}`;
  }
}

const server = createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
  // 模式探针：对拍脚本据此判断本轮数字是「放行率」还是「打穿率」
  if (u.pathname === '/__mode') {
    res.end(JSON.stringify({ mode: MODE, reason: db.reason || null, port: PORT }));
    return;
  }
  const id = u.searchParams.get('id') ?? '';
  if (MODE === 'db') {
    res.end(await queryDb(id));
    return;
  }
  res.end(`OK id=${id}`);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`modsec-target: ${MODE} backend on 127.0.0.1:${PORT}`);
});

// 收摊：CI 的 workflow 会 kill 本进程；显式关连接能让容器日志少一类噪音
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    try { db.conn?.end(); } catch { /* 忽略：收摊阶段的连接错误不影响结果 */ }
    server.close(() => process.exit(0));
  });
}
