// 直连模式（对标 sqlmap -d）的数据库驱动层。
//
// driver 接口契约：
//   connect()                       建立/准备连接
//   query(sql) -> { rows, columns } 执行 SQL；rows 为字符串数组（每行列值已 join('\t')），columns 为列名数组
//   close()                         关闭连接
//
// 内置驱动：
//   - MemoryRecordDriver：零依赖自检驱动，模拟一个有注入点的 SQLite 风格库。仅用于直连通道自检/演示，
//     不替代真实数据库。它能按注入特征（UNION 回显 / 报错 / 布尔差异 / 时间延迟）产出差异化响应，
//     从而在不依赖任何外部包与真实库的前提下，端到端验证直连通道复用整条检测链路。
//   - SqlJsDriver：基于 sql.js（纯 WASM，无需原生编译）的真实 SQLite 驱动；sql.js 未安装时自动回退 MemoryRecordDriver。
//
// 真实生产驱动（mysql2 / pg / mssql / oracledb 等）需用户自备并 `npm install`，再按 target.db.driverType 注册接入。

import { logger } from './logger.js';

const TABLE = { columns: ['id', 'name'], rows: [[1, 'alice'], [2, 'bob']] };

// 零依赖自检驱动：模拟"把 SQL 查询结果回显到页面"的有注入点应用。
export class MemoryRecordDriver {
  constructor(opts = {}) {
    this.name = 'memory';
    this.dialect = opts.dialect || 'sqlite';
    this._connected = false;
  }
  async connect() {
    this._connected = true;
  }
  async close() {
    this._connected = false;
  }
  async query(sql) {
    sql = String(sql);
    // 时间盲注：SLEEP(n) / WAITFOR DELAY '0:0:n'
    const tm = sql.match(/SLEEP\s*\(\s*([\d.]+)\s*\)/i) || sql.match(/WAITFOR\s+DELAY\s+'0:0:([\d.]+)'/i);
    if (tm) {
      const s = Math.min(parseFloat(tm[1]) || 0, 5);
      await new Promise((r) => setTimeout(r, s * 1000));
    }
    // 列数探测（ORDER BY n）：n 超过表列数则报错（模拟列数超限），供 binaryGuessColumns 二分收敛。
    const obm = sql.match(/ORDER\s+BY\s+(\d+)/i);
    if (obm && parseInt(obm[1], 10) > TABLE.columns.length) {
      throw new Error('SQL error code 22018: ORDER BY column index out of range (simulated)');
    }
    // 报错注入：把字符串 CAST 成整数 / 调用不存在的函数 / MySQL 报错函数 → 抛错（被 DirectConnector 捕获为 body）
    if (
      /CAST\s*\([^)]*\)\s*AS\s+(INT|INTEGER)/i.test(sql) ||
      /_sqli_probe_nonexist_func\s*\(\s*\)/i.test(sql) ||
      /extractvalue\s*\(|updatexml\s*\(/i.test(sql)
    ) {
      throw new Error('SQL error code 22018: datatype mismatch / function does not exist (simulated)');
    }
    // UNION 注入：把注入列求值后作为额外回显行返回（模拟应用把查询结果回显到响应）
    const ui = sql.toUpperCase().indexOf('UNION SELECT');
    if (ui !== -1) {
      const colsRaw = sql.slice(ui + 'UNION SELECT'.length);
      const cols = splitTopLevel(colsRaw, ',').map((c) => evalColumn(c.trim()));
      return { rows: [cols.join('\t')], columns: cols.map((_, i) => 'c' + i) };
    }
    // 基线 / 布尔：id=N 过滤；布尔假（'1'='2 或 "1"="2，含未闭合引号变体）返回空结果集（与布尔真产生行数差异）
    const isFalse = /'\s*1'\s*=\s*'2/.test(sql) || /"\s*1"\s*=\s*"2/.test(sql);
    if (isFalse) return { rows: [], columns: [] };
    const idm = sql.match(/id\s*=\s*'?(\d+)'?/i);
    let rows = TABLE.rows.map((r) => r.join('\t'));
    if (idm) rows = rows.filter((r) => r.startsWith(idm[1] + '\t'));
    return { rows, columns: TABLE.columns };
  }
}

// 真实 PostgreSQL 驱动（@electric-sql/pglite，PG WASM 编译版）
// 接口对标 SqlJsDriver：query(sql) -> { rows, columns }，rows 为字符串数组（每行列值已 join('\t')）。
// PGlite 的 query() 返回 { rows: [{col:val,...}], fields: [{name,dataTypeID}] }；
// 此处标准化为数组数组格式（对标 SqlJsDriver 的 rowsToText 消费格式）。
// 注意：PGlite query() 仅支持单语句；多语句（堆叠注入 ; ...）会抛错，由 DirectConnector 捕获为 status 500。
export class PgDriver {
  constructor(opts = {}) {
    this.name = 'pglite';
    this.dialect = 'postgres';
    this._opts = opts;
    this._db = null;
  }
  async connect() {
    let PGlite;
    try {
      ({ PGlite } = await import('@electric-sql/pglite'));
    } catch {
      throw new Error(
        "[direct] @electric-sql/pglite 未安装。请在 server 目录执行 npm install @electric-sql/pglite"
      );
    }
    this._db = new PGlite();
    await this._db.ready;
    if (this._opts.initSql) {
      // PGlite exec() 支持多语句（建表+插入），query() 仅支持单语句
      await this._db.exec(this._opts.initSql);
    }
  }
  async query(sql) {
    sql = String(sql);
    if (!this._db) throw new Error('[direct] 直连驱动未初始化')
    const res = await this._db.query(sql);
    const columns = (res.fields || []).map((f) => f.name);
    const rows = (res.rows || []).map((r) =>
      columns.map((c) => (r[c] == null ? '' : String(r[c]))).join('\t')
    );
    return { rows, columns };
  }
  async close() {
    if (this._db) {
      try { await this._db.close(); } catch { /* ignore */ }
      this._db = null;
    }
  }
}

// 真实 MySQL/MariaDB 驱动（mysql2 包）
// 连接到本地 mysqld 实例（需用户自行启动，可用便携 ZIP 版）
export class MysqlDriver {
  constructor(opts = {}) {
    this.name = 'mysql';
    this.dialect = 'mysql';
    this._opts = opts;
    this._conn = null;
  }
  async connect() {
    let mysql;
    try {
      mysql = await import('mysql2/promise');
    } catch {
      throw new Error('[direct] mysql2 未安装。请在 server 目录执行 npm install mysql2');
    }
    const host = this._opts.host || '127.0.0.1';
    const port = this._opts.port || 3306;
    const user = this._opts.user || 'root';
    // [P0-FIX 2026-09-11] password 支持：真实 MySQL 场景（recall-lab real_mysql_*）此前从未
    // 跑通过——mysql2 不可用时静默跳过，可用后立即暴露 Access denied（root 无密码连 root/root 实例）。
    // 选项优先，MYSQL_PASSWORD 环境变量兜底；undefined 保持旧「无密码」行为（零回归）。
    const password = this._opts.password ?? process.env.MYSQL_PASSWORD ?? undefined;
    this._conn = await mysql.createConnection({ host, port, user, password, charset: 'utf8mb4' });
    if (this._opts.initSql) {
      for (const sql of this._opts.initSql.split(';').map((s) => s.trim()).filter(Boolean)) {
        await this._conn.query(sql);
      }
    }
  }
  async query(sql) {
    if (!this._conn) throw new Error('[direct] MySQL 连接未建立')
    const [rows, fields] = await this._conn.query(String(sql));
    const columns = fields ? fields.map((f) => String(f.name)) : [];
    // mysql2 的 query 返回类型含非数组分支，此处 rows 运行时必为数组（并有 || [] 兜底）
    const data = (/** @type {any[]} */ (rows) || []).map((r) => {
      if (Array.isArray(r)) return r.map((v) => (v == null ? '' : String(v))).join('\t');
      return columns.map((c) => {
        const v = r[c];
        return v == null ? '' : String(v);
      }).join('\t');
    });
    return { rows: data, columns };
  }
  async close() {
    if (this._conn) {
      try { await this._conn.end(); } catch { /* ignore */ }
      this._conn = null;
    }
  }
}

// 真实 SQLite 驱动（sql.js，纯 WASM）
export class SqlJsDriver {
  constructor(opts = {}) {
    this.name = 'sqljs';
    this.dialect = 'sqlite';
    this._opts = opts;
    this._db = null;
  }
  async connect() {
    const initSqlJs = (await import('sql.js')).default;
    const SQL = await initSqlJs();
    this._db = new SQL.Database();
    if (this._opts.initSql) this._db.run(this._opts.initSql);
  }
  async query(sql) {
    sql = String(sql);
    // 列数探测（ORDER BY n）：n 超过结果实际列数则报错，对齐 binaryGuessColumns 的"报错=超出列数"判据。
    // 用真实 SQLite 执行"去掉 ORDER BY 子句"的语句来确定列数，仅对越界情况抛错（其余交给 SQLite 正常执行）。
    const obm = sql.match(/ORDER\s+BY\s+(\d+)/i);
    if (obm) {
      const n = parseInt(obm[1], 10);
      const baseSql = sql.replace(/\s+ORDER\s+BY\s+\d+.*$/is, '').trim();
      let colCount = 0;
      try {
        const r = this._db.exec(baseSql);
        colCount = r.length ? r[0].columns.length : 0;
      } catch {
        /* 基线 ORDER BY 1 等也可能带残余语法，忽略后交给下方 exec 统一报错 */
      }
      if (n > colCount) throw new Error('SQL error code 22018: ORDER BY column index out of range (sqlite)');
    }
    const res = this._db.exec(sql);
    if (!res.length) return { rows: [], columns: [] };
    const { columns, values } = res[0];
    const rows = values.map((v) => v.map((c) => (c == null ? '' : String(c))).join('\t'));
    return { rows, columns };
  }
  async close() {
    if (this._db) {
      this._db.close();
      this._db = null;
    }
  }
}

// 从连接串 scheme 推断驱动类型（对标 sqlmap -d 的连接串语义）。
// 支持：mysql:// postgres:// postgresql:// mssql:// sqlserver:// oracle:// sqlite://（路径或 :memory:）
// 返回 'memory' 表示无法识别（回退自检）。
export function driverTypeFromConnectionString(connStr) {
  if (typeof connStr !== 'string' || !connStr.trim()) return 'memory';
  const m = connStr.trim().match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//);
  if (!m) return connStr.trim().endsWith('.db') || connStr.trim().endsWith('.sqlite') ? 'sqlite' : 'memory';
  switch (m[1].toLowerCase()) {
    case 'mysql': return 'mysql';
    case 'postgres':
    case 'postgresql': return 'postgres';
    case 'mssql':
    case 'sqlserver': return 'mssql';
    case 'oracle': return 'oracle';
    case 'sqlite': return 'sqlite';
    default: return 'memory';
  }
}

// 真实生产驱动注册表：driverType → 工厂函数（用户自备驱动包并 npm install 后注册）。
// 未注册的 driverType 在 getDriver 中会给出明确错误（而非静默回退 memory 掩盖问题）。
// 约定工厂签名：async (dbOpts) => ({ connect(), query(sql) -> {rows, columns}, close() })
// 示例（mysql2）：
//   registerDriver('mysql', async (o) => { const mysql = await import('mysql2/promise'); ... });
const DRIVER_REGISTRY = new Map();

export function registerDriver(type, factory) {
  const t = String(type).toLowerCase();
  if (typeof factory !== 'function') throw new Error(`registerDriver: ${t} 工厂必须是函数`);
  DRIVER_REGISTRY.set(t, factory);
}

export function registeredDrivers() {
  return [...DRIVER_REGISTRY.keys()];
}

// 按 target.db.driverType 解析驱动。
// - driverType 显式指定（sqljs/sqlite/memory）走内置实现；
// - driverType 在注册表 → 调工厂加载（真实驱动，调用方注入依赖）；
// - driverType 未注册且非内置 → 抛清晰错误（不再静默回退 memory）；
// - driverType 缺省 → 从 connectionString scheme 推断；推断不出回退 memory 自检。
export async function getDriver(target) {
  const db = (target && target.db) || {};
  const connStr = typeof db.connectionString === 'string' ? db.connectionString : '';
  let type = String(db.driverType || '').toLowerCase();
  if (!type && connStr) type = driverTypeFromConnectionString(connStr);

  // 内置驱动
  if (type === 'sqljs' || type === 'sqlite') {
    try {
      const d = new SqlJsDriver({ initSql: db.initSql });
      await d.connect();
      return d;
    } catch (e) {
      logger.warn('[direct] sql.js 不可用，回退到内存自检驱动：', e && e.message);
      return new MemoryRecordDriver(db);
    }
  }
  // PGlite：真实 PostgreSQL WASM 驱动（@electric-sql/pglite），不自动回退——显式 pglite 类型说明
  // 用户意图明确，应抛清晰错误而非静默退化为 memory（防"看起来连上了其实是测试桩"）
  if (type === 'pglite') {
    const d = new PgDriver({ initSql: db.initSql });
    await d.connect();
    return d;
  }
  // MySQL/MariaDB：真实 MySQL 驱动（mysql2），连接到本地 mysqld 实例
  // 需用户自行安装 mysql2 并启动 mysqld（或 MariaDB）
  if (type === 'mysql' || type === 'mariadb') {
    const d = new MysqlDriver(db);
    await d.connect();
    return d;
  }
  // 真实驱动注册表
  if (type && DRIVER_REGISTRY.has(type)) {
    const factory = DRIVER_REGISTRY.get(type);
    const d = await factory(db);
    if (d && typeof d.connect === 'function') await d.connect();
    return d;
  }
  // 明确要求真实驱动但未注册 → 报错而非静默回退（防"看起来连上了其实是测试桩"）
  if (type && type !== 'memory') {
    throw new Error(
      `[direct] 驱动 '${type}' 未注册。请用 registerDriver('${type}', factory) 接入真实驱动，` +
        `或使用内置 sqljs/sqlite/memory。`
    );
  }
  // 缺省/无法识别 → memory 自检
  return new MemoryRecordDriver(db);
}

// 顶层逗号分隔（忽略括号内的逗号）
function splitTopLevel(s, sep) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth--;
    if (ch === sep && depth === 0) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

// 求值一个 UNION 列表达式（字符串/数字/函数/WRAP 包裹），供内存自检驱动回显模拟。
function evalColumn(expr) {
  expr = String(expr).trim();
  // WRAP 包裹（如 '__S__' || CAST((version()) AS ...) || '__E__'）：保留标记并求值内部函数
  const wrap = expr.match(/__S__([\s\S]*?)__E__/);
  if (wrap) {
    const fn = wrap[1].match(/\(\s*([a-zA-Z_]\w*)\s*\(\s*\)\s*\)/);
    return '__S__' + (fn ? evalSimpleFn(fn[1]) : wrap[1]) + '__E__';
  }
  if (/^'.*'$/.test(expr)) return expr.slice(1, -1); // 字符串字面量
  if (/^-?\d+$/.test(expr)) return expr; // 数字
  const fn = expr.match(/([a-zA-Z_]\w*)\s*\(\s*\)/); // 裸函数调用
  if (fn) return evalSimpleFn(fn[1]);
  return expr;
}

function evalSimpleFn(name) {
  switch (String(name).toLowerCase()) {
    case 'version':
      return '5.7.25-sqlite-sim';
    case 'user':
    case 'current_user':
      return 'sqlite_user';
    case 'database':
      return 'sqlite_db';
    default:
      return name;
  }
}
