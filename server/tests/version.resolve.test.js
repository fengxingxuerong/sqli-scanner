// ============================================================================
// version.resolve.test.js —— 版本解析器（D128）
//
// 为什么值得单独测：旧实现只从**文件系统**向上找 package.json，于是
// 「开发树上跑得到 1.1.1 / sidecar 装到用户机器上报 0.0.0+unknown」——
// 一种开发环境永远复现不出来的谎报。本测试把四条来源逐条钉死：
//   ① ENGINE_VERSION 环境变量（部署/壳注入）
//   ② SEA 内嵌 package.json（sidecar 随包走版本）
//   ③ 仓库根 package.json（开发态）
//   ④ server/package.json（引擎独立发布兜底）
// 以及 ⑤ 全空时必须报 unknown，不许编一个版本号。
// ============================================================================
import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveVersion, ENGINE_VERSION, VERSION_SOURCE } from '../src/core/version.js';

test('① ENGINE_VERSION 环境变量优先级最高', () => {
  const r = resolveVersion({
    envVersion: '9.9.9',
    seaVersion: '8.8.8',
    rootPkgVersion: '7.7.7',
    serverPkgVersion: '6.6.6',
  });
  assert.deepEqual(r, { version: '9.9.9', source: 'env:ENGINE_VERSION' });
});

test('② SEA 内嵌版本压过文件系统（sidecar 装在用户机器上的真实路径）', () => {
  const r = resolveVersion({ seaVersion: '1.2.0', rootPkgVersion: '0.9.9' });
  assert.deepEqual(r, { version: '1.2.0', source: 'sea:package.json' });
});

test('③ 无 env / 无 SEA 时用仓库根 package.json（开发态）', () => {
  const r = resolveVersion({ rootPkgVersion: '1.2.0', serverPkgVersion: '1.0.0' });
  assert.deepEqual(r, { version: '1.2.0', source: 'package.json(root)' });
});

test('④ 根包读不到时回落到 server/package.json', () => {
  const r = resolveVersion({ serverPkgVersion: '1.1.0' });
  assert.deepEqual(r, { version: '1.1.0', source: 'package.json(server)' });
});

test('⑤ 四条来源全空 ⇒ 如实报 unknown，不许编版本号', () => {
  assert.deepEqual(resolveVersion({}), { version: '0.0.0+unknown', source: 'unknown' });
  // 空串 / 纯空白必须等同于「没有」，否则 env 里一个空格就会覆盖真实版本
  assert.equal(resolveVersion({ envVersion: '   ', rootPkgVersion: '1.2.0' }).version, '1.2.0');
  assert.equal(resolveVersion({ seaVersion: '', rootPkgVersion: '1.2.0' }).version, '1.2.0');
});

test('来源标注与实际取值同源（排障时不能自相矛盾）', () => {
  for (const src of [
    { envVersion: '3.0.0' },
    { seaVersion: '3.0.1' },
    { rootPkgVersion: '3.0.2' },
    { serverPkgVersion: '3.0.3' },
  ]) {
    const r = resolveVersion(src);
    assert.match(r.version, /^3\.0\.\d$/);
    assert.notEqual(r.source, 'unknown');
  }
});

test('本仓当前运行态：版本可读且不是 unknown（防「静默降级」回归）', () => {
  assert.match(ENGINE_VERSION, /^\d+\.\d+\.\d+/, `实际版本：${ENGINE_VERSION}`);
  assert.notEqual(ENGINE_VERSION, '0.0.0+unknown');
  assert.ok(
    ['package.json(root)', 'package.json(server)', 'sea:package.json', 'env:ENGINE_VERSION'].includes(VERSION_SOURCE),
    `未知来源标注：${VERSION_SOURCE}`
  );
});
