// D 方向：扩展 DBMS 广度（Access/HSQLDB/Derby/MonetDB）最小适配回归
// 验证：纳入 DBMS_LIST、SUPPORTED 标记（Access/Derby 无 error-based）、WRAP 包裹、
//       PAYLOADS 结构（error 数组随 SUPPORTED 同步为空/非空）、DB_VERSION 回显、
//       ERROR_SIG 覆盖、Exploiter capabilities 矩阵。
// 方言 payload 未经真实环境验证，本测试只验结构与一致性（不触真实目标）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DBMS_LIST, SUPPORTED, PAYLOADS, ERROR_SIG, DB_VERSION } from '../src/engine/payloads.js';
import { WRAP, fromDummy } from '../src/engine/DBFingerprinter.js';
import { Exploiter } from '../src/engine/Exploiter.js';

const NEW = ['Access', 'HSQLDB', 'Derby', 'MonetDB'];
// 无 error-based 技术的库：error payload 必须留空（与 SUPPORTED.error 同步）
const NO_ERROR = ['Access', 'Derby'];

test('D: 4 个新 DBMS 已纳入 DBMS_LIST', () => {
  for (const db of NEW) assert.ok(DBMS_LIST.includes(db), `${db} 应在 DBMS_LIST`);
});

test('D: SUPPORTED 标记正确（union/boolean=true；time 仅 MonetDB，stacked/oob=false）', () => {
  for (const db of NEW) {
    const s = SUPPORTED[db];
    assert.equal(s.union, true);
    assert.equal(s.boolean, true);
    if (db === 'MonetDB') {
      // [P1] MonetDB 有内建 sys.sleep(sec) → time:true
      assert.equal(s.time, true, `${db} time 应为 true`);
    } else {
      assert.equal(s.time, false, `${db} time 应为 false`);
    }
    assert.ok(!s.stacked, `${db} stacked 应为未声明/false`);
    assert.equal(s.oob, false, `${db} oob 应为 false`);
    // Access/Derby 无 error-based（Jet SQL 无报错回显、Derby 报错不落响应）
    assert.equal(s.error, !NO_ERROR.includes(db), `${db} error 标记应=${!NO_ERROR.includes(db)}`);
  }
});

test('D: PAYLOADS 结构合法（union/boolean 非空；error 随 SUPPORTED 同步）', () => {
  for (const db of NEW) {
    const p = PAYLOADS[db];
    assert.ok(Array.isArray(p.union) && p.union.length >= 3, `${db} union 应≥3`);
    assert.ok(Array.isArray(p.boolean) && p.boolean.length >= 8, `${db} boolean 应≥8`);
    if (NO_ERROR.includes(db)) {
      assert.ok(Array.isArray(p.error) && p.error.length === 0, `${db} error 应为空`);
    } else {
      assert.ok(Array.isArray(p.error) && p.error.length >= 1, `${db} error 应非空`);
    }
    if (db === 'MonetDB') {
      // [P1] MonetDB 有 sys.sleep(sec) time 模板
      assert.ok(Array.isArray(p.time) && p.time.length >= 1, `${db} time 应非空`);
    } else {
      assert.ok(Array.isArray(p.time) && p.time.length === 0, `${db} time 应为空`);
    }
    assert.ok(Array.isArray(p.stacked) && p.stacked.length === 0, `${db} stacked 应为空`);
  }
});

test('D: union payload 使用正确的方言伪表（fromDummy 一致）', () => {
  const expectFrom = { Access: 'MSysObjects', HSQLDB: 'VALUES(0)', Derby: 'SYSIBM.SYSDUMMY1', MonetDB: 'sys.version' };
  for (const db of NEW) {
    const union = PAYLOADS[db].union[0];
    assert.ok(union.includes(expectFrom[db]), `${db} union 应引用 ${expectFrom[db]}`);
    assert.ok(fromDummy(db).includes(expectFrom[db]), `${db} fromDummy 应引用 ${expectFrom[db]}`);
  }
});

test('D: DB_VERSION 回显标识设置正确（常量串/子查询）', () => {
  const expectVers = {
    Access: "'ACCESS'",
    HSQLDB: "'HSQLDB'",
    Derby: "'DERBY'",
    MonetDB: 'sys_version',
  };
  for (const db of NEW) {
    assert.ok(DB_VERSION[db], `${db} 应有 DB_VERSION 条目`);
    assert.ok(DB_VERSION[db].func.includes(expectVers[db]), `${db} 版本回显应含 ${expectVers[db]}`);
  }
  // 货币符号/标识签名可命中对应常量串
  assert.ok(DB_VERSION.Access.sig.test('ACCESS'), 'Access 签名应命中 ACCESS');
  assert.ok(DB_VERSION.MonetDB.sig.test('11.39.11'), 'MonetDB 签名应命中版本号');
});

test('D: WRAP 对各新 DBMS 是函数且产出来回显标记（方言拼接）', () => {
  for (const db of NEW) {
    assert.equal(typeof WRAP[db], 'function', `${db} WRAP 应为函数`);
    const out = WRAP[db]('version()');
    assert.ok(out.includes('__S__') && out.includes('__E__'), `${db} WRAP 应包含回显标记`);
    // Access 用 & 拼接；其余用 ||
    if (db === 'Access') {
      assert.ok(out.includes(' & '), 'Access WRAP 应用 & 拼接');
    } else {
      assert.ok(out.includes('||'), `${db} WRAP 应用 || 拼接`);
    }
  }
});

test('D: Exploiter.capabilities 返回 sqlShell 支持、利用 false、maxRisk=LOW', () => {
  const ex = new Exploiter({});
  for (const db of NEW) {
    const r = ex.capabilities(db);
    assert.equal(r.supported, true);
    assert.equal(r.capabilities.sqlShell.supported, true);
    assert.equal(r.capabilities.osShell.supported, false);
    assert.equal(r.capabilities.fileRead.supported, false);
    assert.equal(r.maxRisk, 'LOW');
  }
});

test('D: ERROR_SIG 覆盖新 DBMS 报错特征', () => {
  assert.ok(ERROR_SIG.test('Microsoft Access ODBC driver'), 'ERROR_SIG 应命中 Access');
  assert.ok(ERROR_SIG.test('org.hsqldb HSQLDB Exception'), 'ERROR_SIG 应命中 HSQLDB');
  assert.ok(ERROR_SIG.test('org.apache.derby Derby Syntax'), 'ERROR_SIG 应命中 Derby');
  assert.ok(ERROR_SIG.test('MonetDB 42000'), 'ERROR_SIG 应命中 MonetDB');
});

test('D: 新库不得意外复用 MySQL 模板（自有方言，非继承）', () => {
  for (const db of NEW) {
    assert.notDeepEqual(PAYLOADS[db], PAYLOADS.MySQL, `${db} 不应 === MySQL 模板`);
    assert.notDeepEqual(PAYLOADS[db], PAYLOADS.Oracle, `${db} 不应 === Oracle 模板`);
  }
});