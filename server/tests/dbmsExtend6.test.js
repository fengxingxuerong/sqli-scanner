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
    // [EXCL-FIX 2026-09-20] HSQLDB/Derby 不再是裸常量串：裸串的执行结果永远匹配不上
    // 09-16 收紧后的 sig（sig 要 `HSQLDB\s+\d`，常量里没有数字），定库恒 null 就是这么来的。
    // 现在改成 exclusive 探针（区分力来自只在自家库存在的 FROM），标识串仍在 func 里。
    HSQLDB: "'HSQLDB '",
    Derby: "'DERBY '",
    MonetDB: 'sys_version',
  };
  for (const db of NEW) {
    assert.ok(DB_VERSION[db], `${db} 应有 DB_VERSION 条目`);
    assert.ok(DB_VERSION[db].func.includes(expectVers[db]), `${db} 版本回显应含 ${expectVers[db]}`);
  }
  // [P1-FIX 2026-09-16 口径跟随] sig 已收紧为「真机回显产品特征文本」：
  //   · 必须命中真机典型版本/产品串（有定库区分度的证据）
  //   · 不得命中裸常量串（防回归回无区分度的旧口径）
  assert.ok(DB_VERSION.Access.sig.test('Microsoft Access Database Engine 2016'), 'Access 签名应命中真机产品串');
  assert.ok(!DB_VERSION.Access.sig.test('ACCESS'), 'Access 签名不应命中裸常量串（收紧口径）');
  assert.ok(DB_VERSION.HSQLDB.sig.test('HSQLDB 2.7.1'), 'HSQLDB 签名应命中真机版本串');
  assert.ok(DB_VERSION.Derby.sig.test('Apache Derby 10.17'), 'Derby 签名应命中真机产品串');
  assert.ok(DB_VERSION.MonetDB.sig.test('11.39.11'), 'MonetDB 签名应命中版本号');
});

// [EXCL-FIX 2026-09-20] 这条是上面那支测试**没抱住**的那个 bug 的正面对策。
// 旧测试只查「func 里有没有标识串」和「sig 能不能命中一个手写的漂亮串」，
// 于是 `'HSQLDB'` + `sig:/HSQLDB\s+\d/` 这种**自己回显自己也匹配不上**的组合可以长期全绿：
// sig 要求一个数字，而裸常量串里根本没有数字的来源。定库恒 null 就是这么来的。
//
// 这里钉住真正的不变量：**sig 若要求数字，func 就必须有产出数字的来源**。
// 注意这是**必要条件**检查、不是充分证明——它能拦住"探针与判据互不满足"这一整类形状，
// 不能替代真引擎验证（那部分在 e2e/multi-engine-lab 的定库列里）。
// 复验方式：把 func 改回旧值 `"'HSQLDB'"` → 本测试立刻红。
test('不变量：sig 要求数字时 func 必须有数字来源（防"自回显也匹配不上"的死探针）', () => {
  // sig 源文本里出现裸 \d（不含在 \d+ 之外的转义歧义）即视为"要求数字"
  const DIGIT_SOURCE = /(version|COUNT\(|sys_version|@@version|SYSCS_|[0-9])/i;
  const offenders = [];
  for (const [db, info] of Object.entries(DB_VERSION)) {
    if (!/\\d/.test(info.sig.source)) continue;         // sig 不要求数字 → 不适用
    if (!DIGIT_SOURCE.test(info.func)) offenders.push(`${db}: sig=${info.sig} 要求 \\d，而 func=${info.func} 没有任何数字来源`);
  }
  assert.deepEqual(offenders, [], `死探针（回显结果永远匹配不上自身 sig）：\n${offenders.join('\n')}`);
});

// 真机实测回显必须命中自身 sig（数字来源检查的落地佐证，样例取自 multi-engine-lab）
test('不变量：exclusive 探针的真机回显命中自身 sig，且区分力来自 FROM', () => {
  const MEASURED = {
    HSQLDB: 'HSQLDB 103',          // COUNT(*) over INFORMATION_SCHEMA.SYSTEM_TABLES
    Derby: 'DERBY 24        ',     // CAST(.. AS CHAR(10)) 会右补空格，一并测进来
  };
  for (const [db, realEcho] of Object.entries(MEASURED)) {
    assert.ok(
      DB_VERSION[db].sig.test(realEcho),
      `${db} 的探针在真机上回显 ${JSON.stringify(realEcho)}，却被自己的 sig 判不命中`
    );
    // 区分力必须来自 FROM 而非字面量，所以这两条**必须**声明 from
    assert.ok(DB_VERSION[db].from, `${db} 是 exclusive 探针，必须带自己的 FROM（否则退化成谁都能执行的常量串）`);
  }
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