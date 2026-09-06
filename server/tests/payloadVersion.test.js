// payload 注册表版本分支回归（[P2-2]）：声明 minVersion 的条目按目标版本投放
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { selectPayloads, PAYLOAD_REGISTRY } from '../src/engine/payloadRegistry.js';

const ver = (major, minor = 0) => ({ major, minor, raw: `${major}.${minor}` });
const ids = (o) => selectPayloads(o).map((p) => p.id);

test('注册表至少包含 4 条版本声明条目（minVersion/maxVersion 已实际使用）', () => {
  const n = PAYLOAD_REGISTRY.filter((p) => p.minVersion != null || p.maxVersion != null).length;
  assert.ok(n >= 4, `版本声明条目应 >=4，实际 ${n}`);
});

test('MySQL：JSON 报错条目仅 5.7+ 投放', () => {
  const v8 = ids({ dbms: 'MySQL', technique: 'error', level: 2, dbmsVersion: ver(8) });
  const v56 = ids({ dbms: 'MySQL', technique: 'error', level: 2, dbmsVersion: ver(5, 6) });
  assert.ok(v8.includes('mysql-err-json-1'), 'MySQL 8 应投放 JSON 报错向量');
  assert.ok(v8.includes('mysql-err-json-2'));
  assert.ok(!v56.includes('mysql-err-json-1'), 'MySQL 5.6 无 JSON 类型，不应投放');
  assert.ok(!v56.includes('mysql-err-json-2'));
});

test('MySQL：版本未知（null）不过滤（保守投放，不因未知砍 payload）', () => {
  const all = ids({ dbms: 'MySQL', technique: 'error', level: 2 });
  assert.ok(all.includes('mysql-err-json-1'), '版本未知时应保留版本声明条目');
});

test('PostgreSQL：pg_sleep_for 仅 9.6+ 投放', () => {
  const v14 = ids({ dbms: 'PostgreSQL', technique: 'time', level: 2, dbmsVersion: ver(14) });
  const v95 = ids({ dbms: 'PostgreSQL', technique: 'time', level: 2, dbmsVersion: ver(9, 5) });
  assert.ok(v14.includes('pg-time-sleepfor-1'), 'PG 14 应投放 pg_sleep_for 变体');
  assert.ok(!v95.includes('pg-time-sleepfor-1'), 'PG 9.5 无 pg_sleep_for');
});

test('Oracle：JSON_VALUE 报错条目仅 12c+ 投放', () => {
  const v19 = ids({ dbms: 'Oracle', technique: 'error', level: 2, dbmsVersion: ver(19) });
  const v11 = ids({ dbms: 'Oracle', technique: 'error', level: 2, dbmsVersion: ver(11) });
  assert.ok(v19.includes('ora-err-json-1'), 'Oracle 19c 应投放 JSON_VALUE 向量');
  assert.ok(!v11.includes('ora-err-json-1'), 'Oracle 11g 无 JSON_VALUE');
});

test('版本边界：恰好等于 minVersion 时投放（>= 语义）', () => {
  const v57 = ids({ dbms: 'MySQL', technique: 'error', level: 2, dbmsVersion: ver(5, 7) });
  assert.ok(v57.includes('mysql-err-json-1'), '5.7.0 应满足 >= 5.7');
});
