// e2e/recall-lab/real-lab-driver.js
// ============================================================================
// 真实 SQLite 靶场驱动（基于 sql.js / SqlJsDriver）。
//
// 与 lab-server.js（伪 SQL 求值器，启发式解析非真实执行）互补：本驱动用
// 真实 SQLite WASM 引擎初始化一个有漏洞的业务库，让检测器在真实 DB 上执行
// 完整检测链路（UNION 列数对齐 / 报错文本差异 / 布尔真假差异），暴露 mock
// 发现不了的方言 payload 在真实执行下的行为差异。
//
// 导出：
//   - INIT_SQL        建表 + 数据（users 4 列 5 行含中文名 / items 3 列 3 行）
//   - CONTEXT_TEMPLATES  各上下文 SQL 模板（含 {INJECT} 占位，DirectConnector 约定）
//   - buildTarget(val, ctxType)  构造 direct 模式 target（可直接传 ScanManager.start）
//   - sqljsAvailable()  检查 sql.js 是否可加载
// ============================================================================

import { createRequire } from 'node:module';

// sql.js 安装在 server/node_modules 下，故从 server 目录解析；
// 从 e2e 目录直接 import('sql.js') 会失败（node_modules 不在解析链上）。
const _serverRequire = createRequire(new URL('../../server/package.json', import.meta.url));

// —— 真实有漏洞业务库：建表 + 初始数据 ——
// users 表 4 列（id/name/email/password），5 行真实数据（含中文名）；
// items 表 3 列（id/title/price），3 行数据。供 UNION 列数对齐（4 列）等场景使用。
export const INIT_SQL = [
  'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT);',
  "INSERT INTO users VALUES (1, '张三', 'zhangsan@example.com', 'pass123');",
  "INSERT INTO users VALUES (2, '李四', 'lisi@example.com', 'secret456');",
  "INSERT INTO users VALUES (3, '王五', 'wangwu@example.com', 'p@ss789');",
  "INSERT INTO users VALUES (4, 'Alice', 'alice@example.com', 'alice_pass');",
  "INSERT INTO users VALUES (5, 'Bob', 'bob@example.com', 'bob_pass');",
  'CREATE TABLE items (id INTEGER, title TEXT, price REAL);',
  "INSERT INTO items VALUES (1, '笔记本电脑', 5999.99);",
  "INSERT INTO items VALUES (2, '无线鼠标', 99.50);",
  "INSERT INTO items VALUES (3, '机械键盘', 299.00);",
].join('\n');

// —— 上下文 SQL 模板：{INJECT} 为 DirectConnector 注入占位 ——
// DirectConnector 把注入 payload 原样替换进 {INJECT}，产出完整 SQL 执行。
export const CONTEXT_TEMPLATES = {
  // 数值型上下文：无引号包裹，payload 直接拼接
  numeric: 'SELECT * FROM users WHERE id={INJECT}',
  // 字符串上下文：单引号包裹，payload 需闭合 '
  str: "SELECT * FROM users WHERE name='{INJECT}'",
  // UNION 场景：同 numeric，用于验证真实提取链（dumpData）
  union: 'SELECT * FROM users WHERE id={INJECT}',
  // 括号包裹上下文：('…')，需 ') 闭合
  paren: "SELECT * FROM users WHERE id=('{INJECT}')",
  // 搜索型上下文：LIKE '%…%'，需 % 与 ' 双闭合
  search: "SELECT * FROM items WHERE title LIKE '%{INJECT}%'",
  // UPDATE SET 注入：赋值上下文，引号闭合后逗号拼接条件
  update: "UPDATE items SET title='{INJECT}' WHERE id=1",
};

/**
 * 构造直连模式 target（可直接传给 ScanManager.start）。
 * @param {string|number} injectValue 注入参数原始值（基线请求用）
 * @param {string} ctxType 上下文类型：numeric/str/union/paren/search/update
 * @returns {{mode:'direct', db:{driverType:'sqljs', initSql:string}, sqlTemplate:string, originalValue:string}}
 */
export function buildTarget(injectValue, ctxType = 'numeric') {
  const template = CONTEXT_TEMPLATES[ctxType] || CONTEXT_TEMPLATES.numeric;
  return {
    mode: 'direct',
    db: { driverType: 'sqljs', initSql: INIT_SQL },
    sqlTemplate: template,
    originalValue: String(injectValue),
  };
}

/**
 * 检查 sql.js 是否可加载。
 * @returns {Promise<boolean>}
 */
export async function sqljsAvailable() {
  try {
    _serverRequire('sql.js');
    return true;
  } catch {
    return false;
  }
}

// —— 真实 PostgreSQL（PGlite WASM）靶场扩展 ——
// PGlite 是真实 PostgreSQL 的 WASM 编译版，可验证 PG 方言 payload 在真实 DB 上的行为。
// 与 SQLite 的关键差异：UNION 类型严格匹配（text≠integer）、# 注释不支持、报错文本不同。

export const PG_INIT_SQL = [
  'CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT, email TEXT, password TEXT);',
  "INSERT INTO users (name, email, password) VALUES ('alice', 'alice@example.com', 'pass123');",
  "INSERT INTO users (name, email, password) VALUES ('bob', 'bob@example.com', 'secret456');",
  "INSERT INTO users (name, email, password) VALUES ('张三', 'zhangsan@example.com', 'p@ss789');",
  'CREATE TABLE items (id INTEGER, title TEXT, price REAL);',
  "INSERT INTO items VALUES (1, '笔记本电脑', 5999.99);",
  "INSERT INTO items VALUES (2, '无线鼠标', 99.50);",
].join('\n');

export const PG_CONTEXT_TEMPLATES = {
  numeric: 'SELECT * FROM users WHERE id={INJECT}',
  str: "SELECT * FROM users WHERE name='{INJECT}'",
  union: 'SELECT * FROM users WHERE id={INJECT}',
};

export function buildPgTarget(injectValue, ctxType = 'numeric') {
  const template = PG_CONTEXT_TEMPLATES[ctxType] || PG_CONTEXT_TEMPLATES.numeric;
  return {
    mode: 'direct',
    db: { driverType: 'pglite', initSql: PG_INIT_SQL },
    sqlTemplate: template,
    originalValue: String(injectValue),
  };
}

export async function pgAvailable() {
  try {
    _serverRequire('@electric-sql/pglite');
    return true;
  } catch {
    return false;
  }
}

// —— 真实 MySQL/MariaDB 靶场（需本地 mysqld，便携 ZIP 即可）——
export const MYSQL_INIT_SQL = [
  "CREATE DATABASE IF NOT EXISTS sqli_test CHARACTER SET utf8mb4",
  "USE sqli_test",
  "CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, name VARCHAR(50), email VARCHAR(50), password VARCHAR(50)) CHARACTER SET utf8mb4",
  "INSERT IGNORE INTO users VALUES (1, 'alice', 'alice@example.com', 'pass123'), (2, 'bob', 'bob@example.com', 'secret456'), (3, '张三', 'zhangsan@example.com', 'p@ss789')",
].join('; ');

export function buildMysqlTarget(injectValue, ctxType = 'numeric') {
  const templates = {
    numeric: 'SELECT * FROM users WHERE id={INJECT}',
    str: "SELECT * FROM users WHERE name='{INJECT}'",
    union: 'SELECT * FROM users WHERE id={INJECT}',
  };
  return {
    mode: 'direct',
    // [P0-FIX 2026-09-11] password：本机 3307 实例为 root/root（root 无密码会 Access denied，
    // 该场景自 09-10 新增以来因 mysql2 不可用被跳过，从未真正跑通）。MYSQL_PASSWORD 兜底。
    db: { driverType: 'mysql', host: '127.0.0.1', port: 3307, user: 'root', password: process.env.MYSQL_PASSWORD ?? 'root', initSql: MYSQL_INIT_SQL },
    sqlTemplate: templates[ctxType] || templates.numeric,
    originalValue: String(injectValue),
    config: { dbms: 'MySQL' },
  };
}

export async function mysqlAvailable() {
  try {
    _serverRequire('mysql2');
  } catch {
    return false;
  }
  // 驱动存在 ≠ 服务端就绪：探测 127.0.0.1:3307 TCP 连通性，未连通时 skip，避免 ECONNREFUSED 误判为 must-miss。
  return _probeMysql('127.0.0.1', 3307);
}

function _probeMysql(host, port) {
  return new Promise((resolve) => {
    const net = _serverRequire('net');
    const s = new net.Socket();
    let settled = false;
    const ok = () => { if (settled) return; settled = true; try { s.destroy(); } catch { /* ignore */ } resolve(true); };
    const no = () => { if (settled) return; settled = true; try { s.destroy(); } catch { /* ignore */ } resolve(false); };
    s.setTimeout(1500);
    s.once('connect', ok);
    s.once('error', no);
    s.once('timeout', no);
    try { s.connect(port, host); } catch { no(); }
  });
}
