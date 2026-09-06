// 扩展 payload 库验收测试（1200+ 扩容方向）
// 覆盖：MySQL 多重括号 / EXP·JSON 报错；PG 多重括号 / regclass·CAST('a')；
// MSSQL IF WAITFOR；Oracle UTL_INADDR·DBMS_PIPE；SQLite sqlite_version() 子查询；
// 固定索引 [0,2]/[1,3]/[4,5]/[6,7] 保护；新增模板结构；总模板数 > 1000（目标 ≥ 1200）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PAYLOADS } from '../src/engine/payloads.js';

const DBMS5 = ['MySQL', 'PostgreSQL', 'SQL Server', 'Oracle', 'SQLite'];
const ends = (p) => p.endsWith('-- -') || p.endsWith('#') || p.endsWith('/**/');

test('MySQL boolean 含多重括号嵌套闭合变体（\')) 与 ")，且位于索引 ≥8', () => {
  const b = PAYLOADS.MySQL.boolean;
  assert.ok(b.includes("{ORIG}')) AND 1=1-- -"), 'MySQL 应含 \')) AND 1=1');
  assert.ok(b.includes("{ORIG}')) AND 1=2-- -"), 'MySQL 应含 \')) AND 1=2');
  assert.ok(b.includes('{ORIG}")) AND 1=1-- -'), 'MySQL 应含 ")) AND 1=1');
  assert.ok(b.includes('{ORIG}")) AND 1=2-- -'), 'MySQL 应含 ")) AND 1=2');
  assert.ok(b.indexOf("{ORIG}')) AND 1=1-- -") >= 8, '多重括号变体必须位于索引 ≥8');
  assert.ok(b.indexOf('{ORIG}")) AND 1=1-- -') >= 8, '多重括号变体必须位于索引 ≥8');
});

test('MySQL error 含 EXP double 溢出与 JSON_KEYS(AS JSON) 报错变体', () => {
  const e = PAYLOADS.MySQL.error;
  assert.ok(e.some((p) => p.includes('EXP(~')), 'MySQL error 应含 EXP(~ 溢出报错');
  assert.ok(
    e.some((p) => p.includes('JSON_KEYS') && p.includes('AS JSON')),
    'MySQL error 应含 JSON_KEYS(AS JSON) 报错'
  );
});

test('PG boolean 含多重括号嵌套闭合变体（\')）', () => {
  const b = PAYLOADS.PostgreSQL.boolean;
  assert.ok(b.includes("{ORIG}')) AND 1=1-- -"), 'PG 应含 \')) AND 1=1');
  assert.ok(b.includes("{ORIG}')) AND 1=2-- -"), 'PG 应含 \')) AND 1=2');
});

test('PG error 含 regclass 无效 OID 与 CAST(\'a\' AS integer) 报错', () => {
  const e = PAYLOADS.PostgreSQL.error;
  assert.ok(e.some((p) => p.includes('1::regclass')), 'PG error 应含 1::regclass 报错');
  assert.ok(
    e.some((p) => p.includes("CAST('a' AS integer)")),
    "PG error 应含 CAST('a' AS integer) 报错"
  );
});

test('MSSQL time 含 IF(1=1) WAITFOR DELAY 条件延迟变体', () => {
  const t = PAYLOADS['SQL Server'].time;
  assert.ok(
    t.some((p) => p.includes('IF(1=1) WAITFOR DELAY')),
    'MSSQL time 应含 IF(1=1) WAITFOR DELAY 变体'
  );
});

test('Oracle error 含 UTL_INADDR.GET_HOST_NAME；time 含 1=DBMS_PIPE.RECEIVE_MESSAGE 谓词化变体', () => {
  const e = PAYLOADS.Oracle.error;
  assert.ok(
    e.some((p) => p.includes('UTL_INADDR.GET_HOST_NAME')),
    'Oracle error 应含 UTL_INADDR.GET_HOST_NAME 报错'
  );
  const t = PAYLOADS.Oracle.time;
  assert.ok(
    t.some((p) => p.includes('1=DBMS_PIPE.RECEIVE_MESSAGE')),
    'Oracle time 应含 1=DBMS_PIPE.RECEIVE_MESSAGE 谓词化变体'
  );
});

test('SQLite boolean 含 sqlite_version() 子查询布尔', () => {
  const b = PAYLOADS.SQLite.boolean;
  assert.ok(
    b.some((p) => p.includes('(SELECT SUBSTR(sqlite_version(),1,1))')),
    'SQLite boolean 应含 sqlite_version() 子查询'
  );
});

test('固定索引对 [0,2]/[1,3]/[4,5]/[6,7] 未被扩容破坏（5 库）', () => {
  for (const dbms of DBMS5) {
    const b = PAYLOADS[dbms].boolean;
    assert.equal(b[0], "{ORIG}' AND '1'='1", `${dbms} [0]`);
    assert.equal(b[2], "{ORIG}' AND '1'='2", `${dbms} [2]`);
    assert.equal(b[1], '{ORIG}" AND "1"="1', `${dbms} [1]`);
    assert.equal(b[3], '{ORIG}" AND "1"="2', `${dbms} [3]`);
    assert.equal(b[4], '{ORIG} AND 1=1', `${dbms} [4]`);
    assert.equal(b[5], '{ORIG} AND 1=2', `${dbms} [5]`);
    assert.equal(b[6], "{ORIG}' OR '1'='1", `${dbms} [6]`);
    assert.equal(b[7], "{ORIG}' OR '1'='2", `${dbms} [7]`);
    assert.equal(b.slice(0, 8).length, 8, `${dbms} 前 8 项数量不变`);
  }
});

test('新增模板结构：union/error/time 全部以 {ORIG} 开头且以 -- - / # / /**/ 结尾；boolean.slice(8) 同', () => {
  for (const dbms of DBMS5) {
    for (const tech of ['union', 'error', 'time']) {
      for (const p of PAYLOADS[dbms][tech]) {
        assert.ok(p.startsWith('{ORIG}'), `${dbms}.${tech} 应以 {ORIG} 开头: ${p}`);
        assert.ok(ends(p), `${dbms}.${tech} 应以 -- - / # / /**/ 结尾: ${p}`);
      }
    }
    for (const p of PAYLOADS[dbms].boolean.slice(8)) {
      assert.ok(p.startsWith('{ORIG}'), `${dbms}.boolean 新增应以 {ORIG} 开头: ${p}`);
      assert.ok(ends(p), `${dbms}.boolean 新增应以 -- - / # / /**/ 结尾: ${p}`);
    }
  }
});

test('总模板数 > 1000（扩展目标 ≥ 1200）', () => {
  let total = 0;
  for (const dbms of Object.keys(PAYLOADS)) {
    for (const tech of Object.keys(PAYLOADS[dbms])) {
      total += PAYLOADS[dbms][tech].length;
    }
  }
  assert.ok(total > 1000, `总模板数应 > 1000，实际 ${total}`);
  assert.ok(total >= 1200, `扩展目标 ≥ 1200，实际 ${total}`);
});
