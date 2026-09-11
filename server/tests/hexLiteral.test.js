// ============================================================================
// tests/hexLiteral.test.js —— --hex（字符常量十六进制化）单测
//
// 两个必须守住的性质：
//   ① 未开启 --hex 时行为**完全不变**（零回归，含单引号转义）
//   ② 不支持的方言必须**显式报错**，不能静默产出错误 SQL
//      （各库十六进制字面量写法不同，写错就是一条"看起来能用其实不能用"的语句）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toHexLiteral, buildLikePattern, hexifyLikeInQuery, HEX_SUPPORTED_DBMS } from '../src/engine/hexLiteral.js';

test('toHexLiteral：MySQL/PostgreSQL/SQLite 各按其语法生成', () => {
  assert.equal(toHexLiteral('ab', 'MySQL'), '0x6162');
  assert.equal(toHexLiteral('ab', 'PostgreSQL'), "convert_from(decode('6162','hex'),'UTF8')");
  assert.equal(toHexLiteral('ab', 'SQLite'), "x'6162'");
});

test('toHexLiteral：未支持方言显式抛错（不静默回退）', () => {
  for (const db of ['Oracle', 'DB2', 'Firebird', 'Unknown']) {
    assert.throws(() => toHexLiteral('ab', db), /--hex 暂不支持/, `${db} 应抛错`);
  }
});

test('支持方言清单是显式白名单（防止误以为"全库支持"）', () => {
  assert.ok(HEX_SUPPORTED_DBMS.includes('MySQL'));
  assert.ok(HEX_SUPPORTED_DBMS.includes('PostgreSQL'));
  assert.ok(!HEX_SUPPORTED_DBMS.includes('Oracle'), 'Oracle 未被验证过，不应在清单里');
});

test('buildLikePattern：未开启 --hex 时保持原行为（含单引号转义）', () => {
  assert.equal(buildLikePattern('admin', 'MySQL', false), "'%admin%'");
  assert.equal(buildLikePattern("a'b", 'MySQL', false), "'%a''b%'", '单引号必须转义');
});

test('buildLikePattern：开启 --hex 后模式转十六进制（元字符 % 也在其中）', () => {
  const out = buildLikePattern('admin', 'MySQL', true);
  assert.equal(out, '0x2561646D696E25');
  // 解码回来应等于 '%admin%'
  const hex = out.slice(2);
  assert.equal(Buffer.from(hex, 'hex').toString('utf8'), '%admin%');
});

test('hexifyLikeInQuery：只替换 LIKE 字面量，SQL 其余部分不动', () => {
  const sql = "SELECT x FROM t WHERE name LIKE '%admin%' AND id > 5";
  const out = hexifyLikeInQuery(sql, 'admin', 'MySQL', true);
  assert.equal(out, 'SELECT x FROM t WHERE name LIKE 0x2561646D696E25 AND id > 5');
});

test('hexifyLikeInQuery：未开启 / 不匹配时原样返回（零副作用）', () => {
  const sql = "SELECT x FROM t WHERE name LIKE '%admin%'";
  assert.equal(hexifyLikeInQuery(sql, 'admin', 'MySQL', false), sql, '未开启应原样');
  assert.equal(hexifyLikeInQuery(sql, 'other', 'MySQL', true), sql, '搜索词不匹配应原样');
});

test('hexifyLikeInQuery：方言不支持时抛错，由调用方降级（不产出错误 SQL）', () => {
  const sql = "SELECT x FROM t WHERE name LIKE '%a%'";
  assert.throws(() => hexifyLikeInQuery(sql, 'a', 'Oracle', true), /--hex 暂不支持/);
});
