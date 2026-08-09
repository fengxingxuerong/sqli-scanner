// payloads.js 单元测试：PAYLOADS 结构 / FINGERPRINT / fillPayload / nullSequence
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PAYLOADS,
  FINGERPRINT,
  DB_VERSION,
  fillPayload,
  nullSequence,
} from '../src/engine/payloads.js';

const DBMS_LIST = ['MySQL', 'PostgreSQL', 'SQLite', 'SQL Server', 'Oracle'];
const TECH_LIST = ['union', 'error', 'boolean', 'time'];

test('PAYLOADS 包含全部 5 个数据库且每个都有 4 种技术', () => {
  for (const dbms of DBMS_LIST) {
    assert.ok(PAYLOADS[dbms], `缺少数据库 ${dbms}`);
    for (const tech of TECH_LIST) {
      assert.ok(Array.isArray(PAYLOADS[dbms][tech]), `${dbms}.${tech} 应为数组`);
      assert.ok(PAYLOADS[dbms][tech].length > 0, `${dbms}.${tech} 不应为空`);
    }
  }
});

test('每个注入 payload 都包含 {ORIG} 占位符', () => {
  for (const dbms of DBMS_LIST) {
    for (const tech of TECH_LIST) {
      for (const p of PAYLOADS[dbms][tech]) {
        assert.ok(p.includes('{ORIG}'), `${dbms}.${tech} 的 payload 缺少 {ORIG}: ${p}`);
      }
    }
  }
});

test('time payload 包含对应数据库延迟关键字', () => {
  // Oracle 的时间盲注在 SUPPORTED.Oracle.time=false 下被禁用，其 time 模板为占位空操作，
  // 故仅校验其余 4 库的真实延迟关键字。
  const sleepKw = {
    MySQL: 'SLEEP',
    PostgreSQL: 'pg_sleep',
    'SQL Server': 'WAITFOR',
    SQLite: 'sqlite_master',
  };
  for (const dbms of Object.keys(sleepKw)) {
    for (const p of PAYLOADS[dbms].time) {
      assert.ok(p.includes(sleepKw[dbms]), `${dbms} time payload 缺少 ${sleepKw[dbms]}: ${p}`);
    }
  }
});

test('各库 UNION payload 使用 -- - 注释并含 UNION SELECT', () => {
  for (const dbms of DBMS_LIST) {
    for (const p of PAYLOADS[dbms].union) {
      assert.ok(p.includes('UNION SELECT'), `${dbms} union payload 缺 UNION SELECT: ${p}`);
      assert.ok(p.includes('-- -'), `${dbms} union payload 缺 -- - 注释: ${p}`);
    }
  }
});

test('Oracle UNION 使用 v$version 作为源表（FROM dual 在提取/指纹时按需追加）', () => {
  assert.ok(PAYLOADS.Oracle.union[0].includes('v$version'));
});

test('FINGERPRINT 对每个库都有响应头特征；DB_VERSION 有 func 与 sig', () => {
  for (const dbms of DBMS_LIST) {
    assert.ok(FINGERPRINT[dbms], `缺少指纹 ${dbms}`);
    assert.ok(Array.isArray(FINGERPRINT[dbms]) && FINGERPRINT[dbms].length > 0, `${dbms} 指纹应为非空数组`);
    assert.ok(FINGERPRINT[dbms][0].header && FINGERPRINT[dbms][0].match instanceof RegExp, `${dbms} 指纹缺 header/match`);
    // UNION 版本指纹映射（DB_VERSION）：供 DBFingerprinter 判定 dbms
    assert.equal(typeof DB_VERSION[dbms].func, 'string');
    assert.ok(DB_VERSION[dbms].sig instanceof RegExp);
  }
});

test('fillPayload 正确替换 {ORIG}/{NUM}/{SLEEP}/{SEP}', () => {
  const tpl = '{ORIG} UNION SELECT {NUM} AND SLEEP({SLEEP}) {SEP}';
  const out = fillPayload(tpl, { orig: '1', num: 42, sleep: 3, sep: '-- -' });
  assert.equal(out, '1 UNION SELECT 42 AND SLEEP(3) -- -');
});

test('fillPayload 缺省值：orig 空、num 随机、sleep 为 1、sep 为 -- -', () => {
  // NUM 缺省为随机 4 位数，故只校验结构：空格(空orig) + 4位数字 + 空格 + '1'(sleep) + 空格 + '-- -'
  const out = fillPayload('{ORIG} {NUM} {SLEEP} {SEP}');
  const m = out.match(/^ (\d{4}) 1 -- -$/);
  assert.ok(m, `缺省值输出不符合预期: ${JSON.stringify(out)}`);
});

test('nullSequence 生成正确数量的 NULL', () => {
  assert.equal(nullSequence(1), 'NULL');
  assert.equal(nullSequence(3), 'NULL,NULL,NULL');
  assert.equal(nullSequence(5), 'NULL,NULL,NULL,NULL,NULL');
});

test('nullSequence 非正数时至少为 1 个 NULL（防御）', () => {
  assert.equal(nullSequence(0), 'NULL');
  assert.equal(nullSequence(-3), 'NULL');
});
