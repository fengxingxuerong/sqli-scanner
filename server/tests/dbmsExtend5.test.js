// C 方向：扩展 DBMS 广度（DB2/Sybase/Firebird/Informix/H2）最小适配回归
// 验证：纳入 DBMS_LIST、SUPPORTED 标记、WRAP 包裹、PAYLOADS 结构、capabilities 矩阵、ERROR_SIG 覆盖。
// 方言 payload 未经真实环境验证，本测试只验结构与一致性（不触真实目标）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DBMS_LIST, SUPPORTED, PAYLOADS, ERROR_SIG } from '../src/engine/payloads.js';
import { WRAP } from '../src/engine/DBFingerprinter.js';
import { Exploiter } from '../src/engine/Exploiter.js';

const NEW = ['DB2', 'Sybase', 'Firebird', 'Informix', 'H2'];

test('C: 5 个新 DBMS 已纳入 DBMS_LIST', () => {
  for (const db of NEW) assert.ok(DBMS_LIST.includes(db), `${db} 应在 DBMS_LIST`);
});

test('C: SUPPORTED 标记正确（union/error/boolean=true，oob=false，time 仅 Sybase/H2）', () => {
  for (const db of NEW) {
    const s = SUPPORTED[db];
    assert.equal(s.union, true);
    assert.equal(s.error, true);
    assert.equal(s.boolean, true);
    assert.equal(s.oob, false, `${db} oob 应为 false`);
    if (db === 'Sybase') {
      assert.equal(s.time, true);
      assert.equal(s.stacked, true);
    } else if (db === 'H2') {
      // [P1] H2 有内建 SLEEP(ms) → time:true
      assert.equal(s.time, true, `${db} time 应为 true`);
    } else {
      assert.equal(s.time, false, `${db} time 应为 false`);
    }
  }
});

test('C: WRAP 对各新 DBMS 是函数且产出来回显标记', () => {
  for (const db of NEW) {
    assert.equal(typeof WRAP[db], 'function', `${db} WRAP 应为函数`);
    const out = WRAP[db]('version()');
    assert.ok(out.includes('__S__') && out.includes('__E__'), `${db} WRAP 应包含回显标记`);
  }
});

test('C: PAYLOADS 含 union/error/boolean 非空，time 仅 Sybase/H2 非空', () => {
  for (const db of NEW) {
    const p = PAYLOADS[db];
    assert.ok(Array.isArray(p.union) && p.union.length >= 1);
    assert.ok(Array.isArray(p.error) && p.error.length >= 1);
    assert.ok(Array.isArray(p.boolean) && p.boolean.length >= 1);
    if (db === 'Sybase') {
      assert.ok(p.time.length >= 1 && p.stacked.length >= 1, 'Sybase 应支持 time/stacked');
    } else if (db === 'H2') {
      // [P1] H2 有 SLEEP(ms) time 模板
      assert.ok(p.time.length >= 1, `${db} time 应非空`);
    } else {
      assert.ok(Array.isArray(p.time) && p.time.length === 0, `${db} time 应为空`);
    }
  }
});

test('C: Exploiter.capabilities 返回 sqlShell 支持、利用 false、maxRisk=LOW', () => {
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

test('C: ERROR_SIG 覆盖新 DBMS 报错特征', () => {
  assert.ok(ERROR_SIG.test('SQL0104N DB2 SQL Error'));
  assert.ok(ERROR_SIG.test('Adaptive Server message'));
  assert.ok(ERROR_SIG.test('Firebird SQL error code'));
  assert.ok(ERROR_SIG.test('Informix SQL -206'));
  assert.ok(ERROR_SIG.test('H2 JDBC Syntax error'));
});
