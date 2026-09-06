// others.js 十个边缘 DBMS payload 模板完整性测试：
// 结构一致性（union/error/boolean 数组非空且含 {ORIG} 占位符、boolean 真假对齐全）、
// 方言锚点（DB2/SYSIBM、ClickHouse/version()）、以及 PAYLOADS 注册表接线。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  clickhousePayload, db2Payload, sybasePayload, firebirdPayload,
  informixPayload, h2Payload, accessPayload, hsqldbPayload,
  derbyPayload, monetdbPayload,
} from '../src/engine/payloads/others.js';
import { PAYLOADS } from '../src/engine/payloads/index.js';

const ALL = {
  ClickHouse: clickhousePayload, DB2: db2Payload, Sybase: sybasePayload,
  Firebird: firebirdPayload, Informix: informixPayload, H2: h2Payload,
  Access: accessPayload, HSQLDB: hsqldbPayload, Derby: derbyPayload,
  MonetDB: monetdbPayload,
};

test('十个库的 payload 均已注册进 PAYLOADS 注册表（键名一致）', () => {
  for (const [dbms, p] of Object.entries(ALL)) {
    assert.equal(PAYLOADS[dbms], p, `${dbms} 未接线到 PAYLOADS`);
  }
});

test('union 模板：非空、每条含 {ORIG} 与 {NUM} 占位符', () => {
  for (const [dbms, p] of Object.entries(ALL)) {
    assert.ok(Array.isArray(p.union) && p.union.length > 0, `${dbms} union 为空`);
    for (const t of p.union) {
      assert.ok(t.includes('{ORIG}'), `${dbms} union 模板缺 {ORIG}: ${t}`);
      assert.ok(t.includes('{NUM}'), `${dbms} union 模板缺 {NUM}: ${t}`);
    }
  }
});

test('boolean 模板：真假成对（=1/=2 各至少一条）且含 {ORIG}', () => {
  for (const [dbms, p] of Object.entries(ALL)) {
    assert.ok(Array.isArray(p.boolean) && p.boolean.length >= 4, `${dbms} boolean 样本不足`);
    const hasTrue = p.boolean.some((t) => /'1'='1|"1"="1|1=1/.test(t));
    const hasFalse = p.boolean.some((t) => /'1'='2|"1"="2|1=2/.test(t));
    assert.ok(hasTrue && hasFalse, `${dbms} boolean 缺真假对`);
    for (const t of p.boolean) assert.ok(t.includes('{ORIG}'), `${dbms} boolean 缺 {ORIG}`);
  }
});

test('error/stacked 形态与能力声明一致：Access/Derby 无 error 向量，仅 Sybase 有堆叠', () => {
  // 能力表（payloads/index.js DBMS_CAPABILITIES）：Access/Derby error=false
  assert.ok(!accessPayload.error || accessPayload.error.length === 0, 'Access 不应投放 error 向量');
  assert.ok(!derbyPayload.error || derbyPayload.error.length === 0, 'Derby 不应投放 error 向量');
  // 其余八库至少一条 error 模板
  for (const dbms of ['ClickHouse', 'DB2', 'Sybase', 'Firebird', 'Informix', 'H2', 'HSQLDB', 'MonetDB']) {
    assert.ok(ALL[dbms].error && ALL[dbms].error.length > 0, `${dbms} 缺 error 向量`);
  }
  // 堆叠：仅 Sybase 非空（ClickHouse 单语句限制等）
  for (const [dbms, p] of Object.entries(ALL)) {
    const stacked = p.stacked ?? [];
    if (dbms !== 'Sybase') assert.ok(stacked.length === 0, `${dbms} 不应有堆叠模板`);
    else assert.ok(stacked.length > 0, 'Sybase 应有堆叠模板');
    for (const t of stacked) assert.ok(t.includes('{ORIG}') || t.includes(';'), `${dbms} stacked 模板异常`);
  }
});

test('方言锚点：DB2 全部 UNION 走 SYSIBM.SYSDUMMY1；ClickHouse 用 version() 回显', () => {
  for (const t of db2Payload.union) assert.ok(t.includes('SYSIBM.SYSDUMMY1'), `DB2 模板缺伪表: ${t}`);
  for (const t of clickhousePayload.union) assert.ok(t.includes('version()'), `ClickHouse 模板缺 version(): ${t}`);
});
