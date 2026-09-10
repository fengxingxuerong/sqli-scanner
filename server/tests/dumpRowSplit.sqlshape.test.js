// [P0-FIX 2026-09-09] 拖库行切分回归防线（SQL 形状层）
// 背景（真实 MySQL 8.0.28 实测）：SYS_QUERIES.MySQL.data 生成
//   `GROUP_CONCAT(CONCAT_WS(CHAR(31), …))` —— 省略 SEPARATOR → 行与行之间用默认 ',' 连接，
// 而 Extractor.dumpTable 按 0x1E 切行 → 整表被当成 1 行、列值按索引错位回填
// （users 真实 5 行 → 落 1 行，username="admin,bob@lab.local"）。
// 本测试锁死「行分隔符 / 列分隔符 / NULL 安全」三个 SQL 形状，防止模板再漂移。
import test from 'node:test';
import assert from 'node:assert/strict';
import { SYS_QUERIES } from '../src/engine/extractionMaps.js';
import { buildStackPageSql } from '../src/engine/Exploiter.js';
import { escColsNN } from '../src/engine/DialectSqlBuilder.js';

const COLS = ['email', 'id', 'is_admin', 'password', 'username'];

test('MySQL data：行分隔 0x1E 显式声明 + 分页下推进子查询（真库实测双缺陷）', () => {
  const sql = SYS_QUERIES.MySQL.data('db1', 'users', COLS, 10, 0);
  assert.match(sql, /SEPARATOR 0x1E\)/, '行分隔符缺失会让整表落成 1 行；且必须是字面量（真库不接受 CHAR(30)）');
  assert.match(sql, /CONCAT_WS\(CHAR\(31\)/, '列分隔符必须显式');
  assert.match(sql, /FROM \(SELECT .* LIMIT 10 OFFSET 0\) __p/, '分页必须作用于源表行：顶层 LIMIT/OFFSET 对聚合输出（恒 1 行）无意义，第 2 页起恒为空');
});

test('MySQL data：列表达式 NULL 安全（CONCAT_WS 会跳过 NULL 参数导致整行左移）', () => {
  const sql = SYS_QUERIES.MySQL.data('db1', 'users', COLS, 10, 0);
  assert.match(sql, /IFNULL\(CAST\(`id` AS CHAR\),''\)/, '任一列 NULL 会让该行列位前移');
});

test('escColsNN：MySQL 包 IFNULL，PG 包 COALESCE，未知方言原样透出', () => {
  assert.equal(escColsNN(['a', 'b'], 'MySQL'), "IFNULL(CAST(`a` AS CHAR),''),IFNULL(CAST(`b` AS CHAR),'')");
  assert.equal(escColsNN(['a'], 'PostgreSQL'), "COALESCE(CAST(\"a\" AS text),'')");
  assert.equal(escColsNN(['a'], 'SQLite'), "IFNULL(CAST(\"a\" AS TEXT),'')");
  assert.equal(escColsNN(['a'], 'UnknownDialect'), 'a');
  assert.equal(escColsNN([], 'MySQL'), '*');
});

test('buildStackPageSql：MySQL 堆叠分页走 CONCAT_WS + SEPARATOR 0x0A + 子查询分页', () => {
  const sql = buildStackPageSql('MySQL', 'db1', 'users', COLS, 0, 10);
  assert.match(sql, /GROUP_CONCAT\(CONCAT_WS\(CHAR\(31\)/);
  assert.match(sql, /SEPARATOR 0x0A\)/, '真库只接受字面量 SEPARATOR');
  assert.match(sql, /FROM \(SELECT .* LIMIT 10 OFFSET 0\) __p/, '分页作用于源表行');
  // 旧实现把列名直接并列进 GROUP_CONCAT 多参数位（列间无分隔符），回归即红
  assert.doesNotMatch(sql, /GROUP_CONCAT\(`email`,/);
});

test('buildStackPageSql：SQLite 不用 SEPARATOR 关键字（group_concat 仅两参形态）', () => {
  const sql = buildStackPageSql('SQLite', 'main', 'users', COLS, 0, 10);
  assert.doesNotMatch(sql, /SEPARATOR/, 'SQLite 的 group_concat 不支持 SEPARATOR');
  assert.match(sql, /, CHAR\(10\)\) FROM \(SELECT/, '行分隔用 group_concat 第二参数 + 子查询分页');
  assert.match(sql, /\|\| CHAR\(31\) \|\|/, '列分隔用拼接表达式');
});

test('buildStackPageSql：PostgreSQL 列 NULL 安全（PG concat_ws 同样跳过 NULL）', () => {
  const sql = buildStackPageSql('PostgreSQL', null, 'users', COLS, 0, 10);
  assert.match(sql, /COALESCE\(CAST\("id" AS text\),''\)/);
  assert.match(sql, /STRING_AGG\(/);
  assert.match(sql, /FROM \(SELECT .* LIMIT 10 OFFSET 0\) __p/, 'PG 分页同样必须下推');
});

test('buildStackPageSql：SQL Server 现代路径 NULL 安全（+ 拼接遇 NULL 整行变 NULL）', () => {
  const sql = buildStackPageSql('SQL Server', null, 'users', COLS, 0, 10, 2019);
  assert.match(sql, /ISNULL\(CAST\("id" AS nvarchar\(max\)\),''\)/);
  assert.match(sql, /STRING_AGG\(/);
});
