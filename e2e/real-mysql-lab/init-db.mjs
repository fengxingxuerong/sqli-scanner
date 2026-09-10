// 真实 MySQL 靶场初始化：建库 + 建表 + 种子数据 + 自检（一键可复现）
// 用法：node e2e/real-mysql-lab/init-db.mjs
// 环境变量：MYSQL_HOST/PORT/USER/PASSWORD/DATABASE（默认 127.0.0.1:3306 root/空 sqli_lab）
//
// [P2-FIX 2026-09-10] 原脚本只做「自检」，库/表不存在直接抛 ER_BAD_DB_ERROR / ER_NO_SUCH_TABLE，
// 新人 clone 下来跑不起来真库验证；且默认端口 3307 与常见本机实例（3306）不一致。
// 现在：缺库建库、缺表建表、空表灌种子（中文/单引号/逗号/特殊字符），已存在则只计数不覆盖。
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');

const CONF = {
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER ?? 'root',
  // 密码允许空串（本机 root 常为空密码），故用 ?? 而非 ||
  password: process.env.MYSQL_PASSWORD ?? 'root',
  multipleStatements: true,
};
const DB = process.env.MYSQL_DATABASE || 'sqli_lab';

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

// 种子数据刻意混入实战疑难值：中文、单引号、逗号/竖线、ID 跳号（验证拖库行切分与分页）
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

const c = await mysql.createConnection(CONF);
const [ver] = await c.query('SELECT VERSION() v');
await c.query(`CREATE DATABASE IF NOT EXISTS \`${DB}\` DEFAULT CHARACTER SET utf8mb4`);
await c.query(`USE \`${DB}\``);

for (const [table, ddl] of Object.entries(TABLES)) {
  await c.query(ddl);
  const [n] = await c.query(`SELECT COUNT(*) n FROM \`${table}\``);
  const rows = Number(n[0].n);
  if (rows === 0) {
    const cols = { users: 'id, username, email, password, role', products: 'id, title, price, category, stock' }[table];
    const ph = SEEDS[table].map(() => '(?,?,?,?,?)').join(',');
    await c.query(`INSERT INTO \`${table}\` (${cols}) VALUES ${ph}`, SEEDS[table].flat());
    console.log(`[init-db] ${table}: 空表 → 已灌入 ${SEEDS[table].length} 行种子数据`);
  } else {
    console.log(`[init-db] ${table}: ${rows} 行（已存在，未覆盖）`);
  }
}

console.log(`[init-db] MySQL ${ver[0].v} @ ${CONF.host}:${CONF.port}/${DB} 就绪`);
await c.end();
process.exit(0);
