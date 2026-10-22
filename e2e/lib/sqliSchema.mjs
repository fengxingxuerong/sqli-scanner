// ============================================================================
// e2e/lib/sqliSchema.mjs —— sqli_lab 测试库 schema 的幂等初始化与状态判定
// ============================================================================
// 背景（D126，2026-10-22 实测）：
//   `e2e/pentest-lab` 与 `e2e/real-mysql-lab` 的靶站直接 `SELECT ... FROM users/products`，
//   但两个套件都**不假设表与种子数据存在**。空库（只有 CREATE DATABASE）时每条查询都
//   SQL 报错 ⇒ 真/假条件响应同形（都落到错误页）⇒ boolean / time 通道全 miss。
//   实测对照（同一份代码、同一台机器）：
//     · 空库   → pentest-lab 1/11、real-mysql-lab 3/11，报告写的是「真值漏检」
//     · 有表   → pentest-lab 11/11、real-mysql-lab 11/11
//   也就是说：**环境缺失被伪装成了能力退化**，门禁红得指错方向。
//   本模块把「缺库建库 / 缺表建表 / 空表灌种子」收敛成一处幂等实现，
//   init-db 与各套件、acceptance 前置共用同一份，避免三处口径漂移。
// ============================================================================

/** 表 → DDL（与 init-db 历史定义逐字一致，改动会影响 drag 行切分类用例） */
const TABLES = {
  users: `
    CREATE TABLE IF NOT EXISTS \`users\` (
      id INT PRIMARY KEY AUTO_INCREMENT,
      username VARCHAR(64),
      email VARCHAR(128),
      password VARCHAR(128),
      role VARCHAR(32)
    ) DEFAULT CHARSET=utf8mb4`,
  products: `
    CREATE TABLE IF NOT EXISTS \`products\` (
      id INT PRIMARY KEY AUTO_INCREMENT,
      title VARCHAR(128),
      price DECIMAL(10,2),
      category VARCHAR(64),
      stock INT
    ) DEFAULT CHARSET=utf8mb4`,
};

/**
 * 种子数据：刻意混入实战疑难值（中文、单引号、逗号/竖线、ID 跳号），
 * 用于验证拖库行切分与分页——改这些值会让相关 e2e 判据失效，勿随手调整。
 */
const SEEDS = {
  users: [
    [1, 'admin', 'admin@lab.local', 'admin123', 'admin'],
    [2, 'bob', 'bob@lab.local', 'bob456', 'user'],
    [3, 'carol', 'carol@lab.local', 'carol789', 'user'],
    [4, '张三', 'zhang@lab.local', 'zh123', 'user'],
    [5, "o'brien", 'ob@lab.local', 'ob123', 'user'],
    [100, 'alice', 'alice@lab.local', 'alice123', 'user'], // ID 跳号 + /str 场景默认查询值
  ],
  products: [
    [1, 'Mechanical Keyboard', 399.0, 'electronics', 12],
    [2, 'Office Chair', 899.5, 'furniture', 5],
    [3, 'USB-C Hub, 7-in-1', 129.0, 'electronics', 30], // 逗号（行分隔符混淆用例）
    [4, '中文商品名 | 特殊,字符', 59.9, 'misc', 7], // 中文 + 竖线 + 逗号
  ],
};

const SEED_COLS = {
  users: 'id, username, email, password, role',
  products: 'id, title, price, category, stock',
};

/**
 * 库名合法性：只允许标识符字符（防 `USE \`${db}\`` 拼接注入）。
 * 非法直接抛错——测试库名写错时宁可立刻失败，也别把语句拼成别的东西。
 * @param {string} db
 * @returns {string}
 */
export function assertSafeDbName(db) {
  const s = String(db ?? '');
  if (!/^[A-Za-z0-9_$]+$/.test(s)) {
    throw new Error(`[sqliSchema] 非法库名 ${JSON.stringify(db)}（只允许字母/数字/_/$）`);
  }
  return s;
}

/**
 * schema 状态判定（纯函数，供单测与报告文案使用）。
 * @param {{users?: number|null, products?: number|null}} counts 缺表用 null 表示
 * @returns {{ok: boolean, missing: string[], empty: string[], reason: string}}
 */
export function schemaVerdict(counts) {
  const missing = [];
  const empty = [];
  for (const t of Object.keys(TABLES)) {
    const n = counts && counts[t];
    if (n == null) missing.push(t);
    else if (Number(n) === 0) empty.push(t);
  }
  const ok = missing.length === 0 && empty.length === 0;
  let reason = '';
  if (missing.length) reason = `缺表：${missing.join('、')}`;
  else if (empty.length) reason = `空表：${empty.join('、')}`;
  return { ok, missing, empty, reason };
}

/**
 * 只读探测：库能否 USE、每张表多少行（缺表 → null）。
 * 两个 ok 必须分开（D126 自查发现：早前用同一个 `ok` 表示「库可访问」又被
 * `schemaVerdict` 的 ok 覆盖，调用方无法区分「连不上库」与「库在但缺表」）：
 *   · ok       —— 库可访问（USE 成功）
 *   · schemaOk —— 表齐且有数据（可支撑依赖数据的套件）
 * 探测失败不抛错，交给调用方决定 SKIP/自愈。
 * @param {import('mysql2/promise').Connection} conn
 * @param {{database?: string}} [opts]
 */
export async function probeSqliSchema(conn, opts = {}) {
  const db = assertSafeDbName(opts.database || 'sqli_lab');
  try {
    await conn.query(`USE \`${db}\``);
  } catch (e) {
    return {
      ok: false,
      schemaOk: false,
      database: db,
      counts: {},
      missing: Object.keys(TABLES),
      empty: [],
      reason: `库不可用（${e.code || e.message}）`,
    };
  }
  const counts = {};
  for (const table of Object.keys(TABLES)) {
    try {
      const [rows] = await conn.query(`SELECT COUNT(*) n FROM \`${table}\``);
      counts[table] = Number(rows[0].n);
    } catch {
      counts[table] = null; // 缺表
    }
  }
  const v = schemaVerdict(counts);
  return { ok: true, schemaOk: v.ok, database: db, counts, missing: v.missing, empty: v.empty, reason: v.reason };
}

/**
 * 幂等初始化：缺库建库、缺表建表、空表灌种子；已有数据一律不覆盖。
 * @param {import('mysql2/promise').Connection} conn
 * @param {{database?: string, quiet?: boolean}} [opts]
 * @returns {Promise<{database: string, created: string[], seeded: string[], existing: Record<string, number>}>}
 */
export async function ensureSqliSchema(conn, opts = {}) {
  const db = assertSafeDbName(opts.database || 'sqli_lab');
  const log = (m) => { if (!opts.quiet) console.log(`[sqliSchema] ${m}`); };
  await conn.query(`CREATE DATABASE IF NOT EXISTS \`${db}\` DEFAULT CHARACTER SET utf8mb4`);
  // 先探一次拿到「哪些表原本就缺」——CREATE TABLE IF NOT EXISTS 不回报是否真的建了，
  // 只有建表前探测才能给出准确的 created 语义（报告里要能区分「新建」与「已存在」）。
  const before = await probeSqliSchema(conn, { database: db });
  await conn.query(`USE \`${db}\``);
  const created = before.missing.slice();
  const seeded = [];
  const existing = {};
  for (const [table, ddl] of Object.entries(TABLES)) {
    await conn.query(ddl);
    const [n] = await conn.query(`SELECT COUNT(*) n FROM \`${table}\``);
    const rows = Number(n[0].n);
    if (rows === 0) {
      const ph = SEEDS[table].map(() => '(?,?,?,?,?)').join(',');
      await conn.query(`INSERT INTO \`${table}\` (${SEED_COLS[table]}) VALUES ${ph}`, SEEDS[table].flat());
      seeded.push(table);
      log(`${table}: 空表 → 已灌入 ${SEEDS[table].length} 行种子数据`);
    } else {
      existing[table] = rows;
      log(`${table}: ${rows} 行（已存在，未覆盖）`);
    }
  }
  return { database: db, created, seeded, existing };
}
