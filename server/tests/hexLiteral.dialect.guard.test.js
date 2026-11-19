// ============================================================================
// hexLiteral.dialect.guard.test.js —— [D304] `--hex` 字面量方言语义守卫
//
// 为什么需要：`--hex` 从「搜索 LIKE」扩到「提取链」（[D301]）后，字面量不再只出现在
// LIKE 上下文，还大量出现在**等值比较**里（标记定位 `BETWEEN __S__ AND __E__`、
// `WHERE table_schema='…'`、SEPARATOR）。SQLite 的 `x'..'` 是 BLOB：
//   `SELECT 'abc' = x'616263'`          → 0（类型不同，恒假）
//   `SELECT 'abc' = CAST(x'616263' AS TEXT)` → 1
// ⇒ 旧形态在等值上下文**恒假**，拖库会静默空结果（与 D301 空串裸 `0x` 同族缺陷）。
//
// 判据用**真引擎**（node:sqlite），不是字符串比对；D304-4 用旧形态做反例，
// 证明 D304-1 的断言真能抓到回归（否则改回 `x'..'` 也全绿 = 判据空转）。
// PG 形态用 PGlite 手工复核过（命令见 D304-5 注释），单测只钉形态与方言名单。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { toHexLiteral, hexifyStringLiterals, HEX_SUPPORTED_DBMS } from '../src/engine/hexLiteral.js';

/** 用真 SQLite 引擎求一个布尔表达式的值（0/1） */
function sqliteEval(expr) {
  const db = new DatabaseSync(':memory:');
  try {
    const rows = db.prepare(`SELECT ${expr} AS v`).all();
    return rows[0].v;
  } finally {
    db.close();
  }
}

test('D304-1 SQLite 等值：hex 字面量必须与 TEXT 相等（提取链的标记/WHERE 上下文）', () => {
  assert.equal(sqliteEval(`'abc' = ${toHexLiteral('abc', 'SQLite')}`), 1);
  assert.equal(sqliteEval(`'{"a":1}' = ${toHexLiteral('{"a":1}', 'SQLite')}`), 1);
});

test('D304-2 SQLite LIKE：hex 模式串仍能匹配（搜索路径不得回归）', () => {
  assert.equal(sqliteEval(`'abc' LIKE ${toHexLiteral('%a%', 'SQLite')}`), 1);
  assert.equal(sqliteEval(`'abc' LIKE ${toHexLiteral('%z%', 'SQLite')}`), 0);
});

test('D304-3 SQLite 空串：空字面量 hex 化后仍等于空串（D301 空串坑的 SQLite 侧）', () => {
  assert.equal(sqliteEval(`'' = ${toHexLiteral('', 'SQLite')}`), 1);
});

test('D304-4 反例（判据不空转）：裸 x\'..\' 在等值上下文恒假，正是 D304-1 要抓的回归', () => {
  assert.equal(sqliteEval(`'abc' = x'616263'`), 0, '裸 BLOB 与 TEXT 不等 ⇒ 旧形态一旦回归，D304-1 必红');
});

test('D304-5 形态钉住：PG 用 convert_from(decode(...))、SQLServer 用 0x、SQLite 用 CAST', () => {
  assert.equal(toHexLiteral('abc', 'PostgreSQL'), "convert_from(decode('616263','hex'),'UTF8')");
  assert.equal(toHexLiteral('abc', 'SQLServer'), '0x616263');
  assert.equal(toHexLiteral('abc', 'SQLite'), "CAST(x'616263' AS TEXT)");
  // 方言名单：报错文案与文档据此声明支持面
  assert.deepEqual([...HEX_SUPPORTED_DBMS].sort(), ['MariaDB', 'MySQL', 'PostgreSQL', 'SQLServer', 'SQLite', 'TiDB']);
});

test('D304-6 提取链形态：WHERE 等值字面量被整体转成 CAST 形态（无裸 x\' 残留）', () => {
  const sql = "SELECT table_name FROM information_schema.tables WHERE table_schema='dvwa' AND table_name='users'";
  const out = hexifyStringLiterals(sql, 'SQLite');
  assert.ok(!/=\s*x'/.test(out), `不得出现裸 x' 字面量：${out}`);
  assert.ok(out.includes("CAST(x'64767761' AS TEXT)"), `schema 字面量应 CAST 化：${out}`);
  assert.ok(out.includes("CAST(x'7573657273' AS TEXT)"), `表名字面量应 CAST 化：${out}`);
});

test('D304-7 未实现方言显式抛错（不静默产出错误 SQL）', () => {
  assert.throws(() => toHexLiteral('abc', 'Oracle'), (e) => /暂不支持 Oracle/.test(e.message));
  assert.throws(() => toHexLiteral('abc', 'DB2'), /暂不支持/);
});
