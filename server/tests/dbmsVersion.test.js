// [P2-2] DBMS 版本解析与比较单元测试（dbmsVersion.js）
// 覆盖：parseDbmsVersion 各厂商版本串（SQL Server 年份版/内部版本号、Oracle 11g/19c/Release、
// PostgreSQL、MySQL、空串）、versionAtLeast/versionBelow 语义（数字/对象/未知版本保守语义）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDbmsVersion, versionAtLeast, versionBelow } from '../src/engine/dbmsVersion.js';

// —— parseDbmsVersion ——
test('parseDbmsVersion: SQL Server 年份版优先（Microsoft SQL Server 2019）', () => {
  const v = parseDbmsVersion('SQL Server', 'Microsoft SQL Server 2019 (RTM-CU12) 15.0.4140');
  assert.equal(v.major, 2019);
  assert.equal(v.minor, 0);
});

test('parseDbmsVersion: SQL Server 内部版本号映射为年份（10.0.x → 2008）', () => {
  const v = parseDbmsVersion('SQL Server', '10.0.5500');
  assert.equal(v.major, 2008);
});

test('parseDbmsVersion: Oracle Release/xxc 形式', () => {
  assert.equal(parseDbmsVersion('Oracle', 'Oracle Database 11g Release 11.2.0.4.0').major, 11);
  assert.equal(parseDbmsVersion('Oracle', 'Oracle Database 19c Enterprise Edition').major, 19);
});

test('parseDbmsVersion: PostgreSQL / MySQL 常规主次版本', () => {
  const pg = parseDbmsVersion('PostgreSQL', 'PostgreSQL 14.2 on x86_64-pc-linux-gnu');
  assert.deepEqual([pg.major, pg.minor], [14, 2]);
  const my = parseDbmsVersion('MySQL', '5.7.25-log');
  assert.deepEqual([my.major, my.minor], [5, 7]);
});

test('parseDbmsVersion: 空串/垃圾串 → major=null（未知版本）', () => {
  assert.equal(parseDbmsVersion('MySQL', '').major, null);
  assert.equal(parseDbmsVersion('MySQL', null).major, null);
  assert.equal(parseDbmsVersion('MySQL', 'unknown').major, null);
});

// —— versionAtLeast ——
test('versionAtLeast: 数字入参支持带次版本（5.7 → major=5, minor=7）', () => {
  assert.equal(versionAtLeast({ major: 5, minor: 7 }, 5.7), true);
  assert.equal(versionAtLeast({ major: 5, minor: 6 }, 5.7), false);
  assert.equal(versionAtLeast({ major: 8, minor: 0 }, 5.7), true);
});

test('versionAtLeast: 对象入参 / 年份版本', () => {
  assert.equal(versionAtLeast({ major: 2019 }, { major: 2017 }), true);
  assert.equal(versionAtLeast({ major: 2014 }, { major: 2017 }), false);
});

test('versionAtLeast: 未知版本（major=null）保守返回 true（不砍 payload）', () => {
  assert.equal(versionAtLeast({ major: null }, 5.7), true);
  assert.equal(versionAtLeast(null, 5.7), true);
});

// —— versionBelow ——
test('versionBelow: 上界比较（仅老版本适用 payload）', () => {
  assert.equal(versionBelow({ major: 5, minor: 6 }, 5.7), true);
  assert.equal(versionBelow({ major: 5, minor: 7 }, 5.7), false);
  assert.equal(versionBelow({ major: 8 }, 5.7), false);
});

test('versionBelow: 未知版本保守返回 false（不投放老版本专属 payload）', () => {
  assert.equal(versionBelow({ major: null }, 5.7), false);
  assert.equal(versionBelow(null, 5.7), false);
});
