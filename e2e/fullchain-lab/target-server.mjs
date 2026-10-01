// ============================================================================
// e2e/fullchain-lab/target-server.mjs —— 全链路套件的靶站进程（薄壳）
// 复用 real-mysql-lab 的靶场应用（createMysqlLabApp）与连接配置，只负责：
//   建 pool → 挂 app → listen(MYSQL_LAB_PORT, 127.0.0.1)。
// 由 fullchain-lab/run.mjs 作为子进程拉起，环境变量由 run-with-sandbox.py 注入
// （MYSQL_HOST/PORT/USER/PASSWORD/DATABASE）。退出码语义：listen 失败硬退出（1），
// 对齐 real-mysql-lab/verify.mjs 的「端口被占 = 废报告还 exit 0」守卫。
// ============================================================================
import { createRequire } from 'node:module';
const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = _require('mysql2/promise');

import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';

const PORT = Number(process.env.MYSQL_LAB_PORT) || 8141;
const CONF = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
};

const pool = mysql.createPool({ ...CONF, connectionLimit: 8, multipleStatements: true });
// 启动即探活：连不上真库就硬退出（让 run.mjs 快速失败，而不是扫描阶段报「目标不可达」）
try {
  await pool.query('SELECT 1');
} catch (e) {
  console.error(`[fullchain-target] MySQL 不可达（${CONF.host}:${CONF.port}）：${e.message}`);
  process.exit(1);
}
const app = createMysqlLabApp(pool);
const server = app.listen(PORT, '127.0.0.1');
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  server.once('error', reject);
}).catch((e) => {
  console.error(`[fullchain-target] listen ${PORT} 失败：${e.message}`);
  process.exit(1);
});
console.log(`[fullchain-target] listening http://127.0.0.1:${PORT}（MySQL ${CONF.host}:${CONF.port}/${CONF.database}）`);
