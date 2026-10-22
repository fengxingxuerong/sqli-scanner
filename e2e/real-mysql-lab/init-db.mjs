// 真实 MySQL 靶场初始化：建库 + 建表 + 种子数据 + 自检（一键可复现）
// 用法：node e2e/real-mysql-lab/init-db.mjs
// 环境变量：MYSQL_HOST/PORT/USER/PASSWORD/DATABASE（默认 127.0.0.1:3306 root/root sqli_lab）
//
// [P2-FIX 2026-09-10] 原脚本只做「自检」，库/表不存在直接抛 ER_BAD_DB_ERROR / ER_NO_SUCH_TABLE，
// 新人 clone 下来跑不起来真库验证；且默认端口 3307 与常见本机实例（3306）不一致。
//    现在：缺库建库、缺表建表、空表灌种子（中文/单引号/逗号/特殊字符），已存在则只计数不覆盖。
// [D126 2026-10-22] 幂等实现抽到 e2e/lib/sqliSchema.mjs，与 pentest-lab / real-mysql-lab /
//    acceptance 前置共用一份 —— 之前这四处各写一遍，空库时套件会把「缺表」报成「真值漏检」。
import { createRequire } from 'node:module';
import { ensureSqliSchema } from '../lib/sqliSchema.mjs';

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

const c = await mysql.createConnection(CONF);
const [ver] = await c.query('SELECT VERSION() v');
const r = await ensureSqliSchema(c, { database: DB });
console.log(`[init-db] MySQL ${ver[0].v} @ ${CONF.host}:${CONF.port}/${r.database} 就绪`);
await c.end();
process.exit(0);
