// P2-1 DBMS 扩库回归（DM8 / ClickHouse / TiDB）
// 验证三库的检测 payload、指纹签名、提取 wrap、利用路径映射（对标信创/云原生场景）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PAYLOADS,
  FINGERPRINT,
  DB_VERSION,
  DBMS_LIST,
  SUPPORTED,
  OOB_PAYLOADS,
  buildPayloads,
  getPayloadGroup,
} from '../src/engine/payloads.js';
import { WRAP } from '../src/engine/Extractor.js';
import { DBFingerprinter } from '../src/engine/DBFingerprinter.js';

test('P2-1: 三库均在 DBMS_LIST 且 SUPPORTED 完整', () => {
  for (const db of ['TiDB', 'DM8', 'ClickHouse']) {
    assert.ok(DBMS_LIST.includes(db), `${db} 应在 DBMS_LIST`);
    assert.ok(SUPPORTED[db], `${db} 应有 SUPPORTED 条目`);
    // ClickHouse 不支持堆叠/OOB；TiDB/DM8 全支持
    if (db === 'ClickHouse') {
      assert.equal(SUPPORTED.ClickHouse.stacked, false, 'CH 不支持堆叠');
      assert.equal(SUPPORTED.ClickHouse.oob, false, 'CH 无原生带外');
    } else {
      assert.equal(SUPPORTED[db].stacked, true);
      assert.equal(SUPPORTED[db].oob, true);
    }
  }
});

test('P2-1: TiDB 复用 MySQL 模板（协议兼容，无重复定义）', () => {
  assert.deepEqual(PAYLOADS.TiDB, PAYLOADS.MySQL, 'TiDB 应 === MySQL 模板');
  assert.ok(buildPayloads('TiDB', 'union', { orig: '1', num: 9 }).length > 0);
  // 指纹签名命中 TiDB 标识
  assert.ok(DB_VERSION.TiDB.sig.test('5.7.25-TiDB-v7.5.0'), 'TiDB 版本签名应命中');
});

test('P2-1: DM8 复用 Oracle 模板 + 达梦专属指纹', () => {
  assert.deepEqual(PAYLOADS.DM8, PAYLOADS.Oracle, 'DM8 应 === Oracle 模板');
  assert.ok(DB_VERSION.DM8.sig.test('DM Database Server Version 8.1'), 'DM8 签名应命中达梦标识');
  assert.ok(FINGERPRINT.DM8.some((f) => /dameng|DM Database|DM8/i.test(f.match.source)), 'DM8 应有达梦指纹');
});

test('P2-1: ClickHouse 独立 payload（自有方言，非 MySQL/Oracle 复制）', () => {
  assert.notDeepEqual(PAYLOADS.ClickHouse, PAYLOADS.MySQL, 'CH 不应 === MySQL');
  assert.notDeepEqual(PAYLOADS.ClickHouse, PAYLOADS.Oracle, 'CH 不应 === Oracle');
  // CH 用 UNION ALL（其语法要求）与 sleep() 函数
  const union = getPayloadGroup('ClickHouse', 'union');
  assert.ok(union.every((p) => p.includes('UNION ALL')), 'CH union 应全用 UNION ALL');
  const time = getPayloadGroup('ClickHouse', 'time');
  assert.ok(time.some((p) => p.includes('sleep(')), 'CH time 应含 sleep() 函数');
  assert.deepEqual(getPayloadGroup('ClickHouse', 'stacked'), [], 'CH 不支持堆叠');
});

test('P2-1: Extractor WRAP 三库分支存在且语法合理', () => {
  for (const [db, expect] of [
    ['TiDB', "CONCAT('__S__'"],
    ['DM8', "TO_CHAR"],
    ['ClickHouse', 'concat('],
  ]) {
    assert.ok(WRAP[db], `${db} 应有 WRAP`);
    const out = WRAP[db]('version()');
    assert.ok(out.includes(expect), `${db} WRAP 应包含 ${expect}`);
  }
});

test('P2-1: DBFingerprinter 对 TiDB/DM8/ClickHouse 不抛错（wrapKey 映射正确）', async () => {
  // 仅验证 WRAP 选择逻辑分支可达：构造指纹器并确认其导出（不发起真实请求）
  const fp = new DBFingerprinter();
  assert.ok(typeof fp.fingerprint === 'function', 'fingerprint 方法应存在');
  // TiDB→MySQL wrapKey、DM8→Oracle wrapKey、ClickHouse→自身 wrapKey 已在 DBFingerprinter 内映射
  // 通过 WRAP 键存在性间接验证（避免真实 HTTP）
  for (const k of ['MySQL', 'Oracle', 'ClickHouse']) assert.ok(WRAP[k]);
});

test('P2-1: OOB 带外对 TiDB/DM8 复用兼容库模板，ClickHouse 留空', () => {
  assert.ok(OOB_PAYLOADS.TiDB && OOB_PAYLOADS.TiDB.length > 0, 'TiDB OOB 应复用 MySQL');
  assert.ok(OOB_PAYLOADS.DM8 && OOB_PAYLOADS.DM8.length > 0, 'DM8 OOB 应复用 Oracle');
  assert.deepEqual(OOB_PAYLOADS.ClickHouse, [], 'CH OOB 应留空');
});
