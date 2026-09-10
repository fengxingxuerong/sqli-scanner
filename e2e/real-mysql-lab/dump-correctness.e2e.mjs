// ============================================================================
// e2e/real-mysql-lab/dump-correctness.e2e.mjs —— 拖库「生成 SQL → 真库执行 → 解析」闭环验证
// 用法：node e2e/real-mysql-lab/dump-correctness.e2e.mjs   （无 MySQL 时自动 SKIP）
// 背景（2026-09-09 实测回归）：
//   修复前 SYS_QUERIES.MySQL.data 生成 GROUP_CONCAT(...) 缺 SEPARATOR → 行间用 ',' 连接，
//   解析按 0x1E 切行 → sqli_lab.users 真实 5 行被落成 1 行且跨行串列。
// 验证矩阵：多行 / 中文 / 值内含逗号·竖线·换行 / NULL 列（列不得左移）/ 行数自检。
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = dirname(fileURLToPath(import.meta.url));
const require2 = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require2('mysql2/promise');
const { SYS_QUERIES } = await import(pathToFileURL(resolve(HERE, '../../server/src/engine/extractionMaps.js')).href);

const CONF = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3307,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || 'root',
};

const ROW_SEP = String.fromCharCode(0x1e); // 与 Extractor.dumpTable 解析一致
const COL_SEP = String.fromCharCode(0x1f);

// —— 与 Extractor.dumpTable 相同的切分逻辑（复制以锁定「生成 ↔ 解析」契约）——
function parseDump(val, cols) {
  const rowStrs = val.split(ROW_SEP).map((r) => r.trim()).filter(Boolean);
  return rowStrs.map((rs) => {
    const cells = rs.split(COL_SEP).map((c) => c.trim());
    const obj = {};
    cols.forEach((c, i) => { obj[c] = cells[i] ?? null; });
    return obj;
  });
}

let pool;
try {
  pool = mysql.createPool({ ...CONF, connectionLimit: 2, multipleStatements: true });
  await pool.query('SELECT 1');
} catch (e) {
  console.log(`[SKIP] 真实 MySQL 不可达（${e.code || e.message}）：本用例按项目红线拒绝 mock 自证，直接跳过`);
  process.exit(0);
}

const DB = '__dump_check__';
const COLS = ['id', 'name', 'note', 'email'];
const ROWS = [
  [1, 'admin', '普通行', 'a@lab.local'],
  [2, '张三', '值,含逗号|含竖线', 'z@lab.local'],
  [3, 'bob', '值内换行\n第二行', null],          // NULL 列：不得让后续列左移
  [4, 'guest', '  首尾空格  ', 'g@lab.local'],
  [5, 'eve', "值内'单引号", 'e@lab.local'],
];

let failed = 0;
const ok = (cond, label, extra = '') => {
  console.log(`[${cond ? 'PASS' : 'FAIL'}] ${label}${extra ? '  ' + extra : ''}`);
  if (!cond) failed += 1;
};

try {
  await pool.query(`DROP DATABASE IF EXISTS \`${DB}\``);
  await pool.query(`CREATE DATABASE \`${DB}\` CHARACTER SET utf8mb4`);
  await pool.query(
    `CREATE TABLE \`${DB}\`.\`t1\` (id INT PRIMARY KEY, name VARCHAR(64), note VARCHAR(255), email VARCHAR(128))`
  );
  for (const r of ROWS) {
    await pool.query(`INSERT INTO \`${DB}\`.\`t1\` VALUES (?,?,?,?)`, r);
  }

  // ① 引擎真实生成的 SQL 直接打真库
  const sql = SYS_QUERIES.MySQL.data(DB, 't1', COLS, 10, 0);
  console.log('[sql]', sql);
  const [rs] = await pool.query(sql.replace(/;$/, ''));
  const val = rs[0] ? String(Object.values(rs[0])[0] ?? '') : '';
  const parsed = parseDump(val, COLS);

  ok(parsed.length === 5, `行数=5（修复前会落成 1 行）`, `实际=${parsed.length}`);
  ok(parsed[0]?.name === 'admin' && parsed[0]?.email === 'a@lab.local', '第 1 行各列就位');
  ok(parsed[1]?.note === '值,含逗号|含竖线', '值内逗号/竖线不串列', JSON.stringify(parsed[1]?.note));
  ok((parsed[2]?.email == null || parsed[2]?.email === '') && parsed[2]?.name === 'bob' && parsed[2]?.note === '值内换行\n第二行', 'NULL 列不左移（email 空但 name/note 就位）', JSON.stringify(parsed[2]));
  ok(parsed[3]?.note === '  首尾空格  ' || parsed[3]?.note === '首尾空格', '第 4 行就位（trim 语义与解析器一致）');
  ok(parsed[4]?.name === 'eve', '第 5 行就位（修复前整表只落 1 行，此行必然缺失）');

  // ② 分页第二页：OFFSET 语义不被行分隔符破坏
  const sql2 = SYS_QUERIES.MySQL.data(DB, 't1', COLS, 2, 2);
  const [rs2] = await pool.query(sql2.replace(/;$/, ''));
  const val2 = rs2[0] ? String(Object.values(rs2[0])[0] ?? '') : '';
  const parsed2 = parseDump(val2, COLS);
  ok(parsed2.length === 2 && parsed2[0]?.id === '3' && parsed2[1]?.id === '4', 'OFFSET 分页正确', `ids=${parsed2.map((r) => r.id)}`);

  // ③ 空表：解析结果为 0 行（不得产出幽灵行）
  await pool.query(`CREATE TABLE \`${DB}\`.\`empty\` (id INT PRIMARY KEY, name VARCHAR(64), note VARCHAR(255), email VARCHAR(128))`);
  const [rs3] = await pool.query(SYS_QUERIES.MySQL.data(DB, 'empty', COLS, 10, 0).replace(/;$/, ''));
  const val3 = rs3[0] ? String(Object.values(rs3[0])[0] ?? '') : '';
  ok(parseDump(val3, COLS).length === 0, '空表解析为 0 行');
} catch (e) {
  ok(false, `执行异常：${e.message}`);
} finally {
  try { await pool.query(`DROP DATABASE IF EXISTS \`${DB}\``); } catch { /* ignore */ }
  await pool.end().catch(() => {});
}

console.log(failed === 0 ? '\n[结果] 全部通过' : `\n[结果] ${failed} 项失败`);
process.exit(failed === 0 ? 0 : 1);
