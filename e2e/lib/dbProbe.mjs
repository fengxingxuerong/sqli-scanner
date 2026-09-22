// ============================================================================
// e2e/lib/dbProbe.mjs —— 外部 DBMS「连不上就跳过」的统一出口
// ============================================================================
// 背景：mssql-lab / oracle-lab 是**本机静默安装的真机靶场**（非 Docker），
//   依赖固定端口 + 硬编码凭证。原先它们直接 `await sql.connect(...)`，
//   连不上就抛异常裸退 —— 没有第三态。run-all.mjs 靠端口探测拦在前面才没炸，
//   但**探测与实际连接是两套判据**：端口通 ≠ 凭证对/库就绪。
//   一旦两者不一致（端口通但认证失败、库名不存在），靶场会以「FAIL」报出，
//   把**环境缺项**误报成**产品缺陷**。
//
// 本仓既定口径（见 e2e/redteam-lab/env.mjs:48-55 与本文件调用方注释）：
//   **缺依赖 → 打印 `[SKIP]` + exit 0**，让跳过理由出现在日志里，
//   而不是一条查不出原因的失败。run-all.mjs 认 `/\bSKIP\b/i` + code===0。
//
// ⚠️ 与 FAIL 的边界：只有「**连不上/认证失败**」才 SKIP。
//   连上了但断言不通过 → 那是真回归，必须 FAIL。绝不放水。
// ============================================================================

/** 跳过原因里一律带上「环境缺项」字样，便于在 CI 日志中一眼区分于真失败 */
const skip = (label, detail) => {
  console.log(`[SKIP] ${label} 不可用（${detail}）—— 环境缺项，非产品缺陷；本用例按项目红线拒绝 mock 自证，直接跳过`);
  process.exit(0);
};

/**
 * 探测 SQL Server 可连性；不可连则打印 [SKIP] 并 exit 0。
 * 可连时返回已连接的 ConnectionPool，调用方继续各自的断言。
 *
 * @param {object} sql        mssql 驱动（调用方 require 后传入，避免本模块硬依赖）
 * @param {object} sqlConfig  连接配置
 * @param {number} timeoutMs  连接超时（默认 8s：CI 上不拖长流水线）
 */
export async function connectMssqlOrSkip(sql, sqlConfig, timeoutMs = 8000) {
  const label = `SQL Server @127.0.0.1:${sqlConfig.port}`;
  try {
    // 显式设置连接超时：mssql 驱动默认 15s，CI 上缺服务时会白等
    const cfg = {
      ...sqlConfig,
      connectionTimeout: timeoutMs,
      requestTimeout: timeoutMs,
      options: { ...(sqlConfig.options || {}), encrypt: false, trustServerCertificate: true },
    };
    const pool = await sql.connect(cfg);
    // 连上后**再探一步**：只看端口通不算数，要能真跑一条查询（库名/权限都可能错）
    await pool.request().query('SELECT 1 AS ok');
    console.log(`[pre] ${label} 可连（认证与查询均通过）`);
    return pool;
  } catch (e) {
    const msg = String(e?.message || e).split('\n')[0];
    // 常见缺项形态：ECONNREFUSED / ETIMEOUT / Login failed / Cannot open database
    skip(label, msg);
  }
}

/**
 * 探测 Oracle 可连性；不可连则打印 [SKIP] 并 exit 0。
 * 可连时返回已连接的 Connection（调用方负责 close）。
 */
export async function getOracleConnectionOrSkip(oracledb, dbConfig, timeoutMs = 8000) {
  const label = `Oracle @${dbConfig.connectString}`;
  try {
    // oracledb thin 模式的连接超时通过 connectString 之外的参数控制有限，
    // 用 Promise.race 兜底：超时即判环境缺项（而不是无限挂住 CI）。
    const conn = await Promise.race([
      oracledb.getConnection(dbConfig),
      new Promise((_, rej) => setTimeout(() => rej(new Error(`连接超时 ${timeoutMs}ms`)), timeoutMs)),
    ]);
    await conn.execute('SELECT 1 FROM DUAL');
    console.log(`[pre] ${label} 可连（认证与查询均通过）`);
    return conn;
  } catch (e) {
    const msg = String(e?.message || e).split('\n')[0];
    skip(label, msg);
  }
}
