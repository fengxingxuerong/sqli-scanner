// Phase 1 安全治理回归（P0-S1 sessionFile 白名单 / P0-S2 并发上限 / P0-S3 配置白名单+clamp / P0-P1③ ratePerSec 透传）
// 直接驱动 sanitizeStart / acquireScanSlot / isSafeSessionPath，另含一条路由级 ENGINE_BUSY 集成断言。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'os';
import path from 'path';
import express from 'express';
import {
  sanitizeStart,
  scanRoutes,
  _scanGovernance,
  acquireScanSlot,
} from '../src/api/scanRoutes.js';
import { ErrorCode, AppError } from '../src/core/errors.js';
import { isSafeSessionPath } from '../src/core/sessionStore.js';

// 构造合法目标入参（config 可覆盖）
function start(cfg) {
  return sanitizeStart({
    url: 'http://127.0.0.1:9999/x?id=1',
    method: 'GET',
    config: cfg || {},
  });
}

// ── P0-S1 sessionFile 白名单 ─────────────────────────────────────
test('sessionFile：合法裸文件名通过，原样落入 config', () => {
  const out = start({ sessionFile: 'sqli-session-abc123.json' });
  assert.equal(out.config.sessionFile, 'sqli-session-abc123.json');
});

test('sessionFile：系统临时目录内路径允许', () => {
  const tmp = path.join(os.tmpdir(), 'sqli-session-tmp-test.json');
  const out = start({ sessionFile: tmp });
  assert.equal(out.config.sessionFile, tmp);
});

test('sessionFile：绝对路径被拒绝（INVALID_PARAM）', () => {
  assert.throws(() => start({ sessionFile: '/etc/passwd' }), (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM);
  assert.throws(() => start({ sessionFile: 'C:\\Windows\\system32\\evil.json' }), (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM);
});

test('sessionFile：.. 逃逸 / 路径分隔符 / 非法字符被拒绝', () => {
  assert.throws(() => start({ sessionFile: '../secret/sess.json' }), (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM);
  assert.throws(() => start({ sessionFile: '..' }), (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM);
  assert.throws(() => start({ sessionFile: 'a..b.json' }), (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM);
  assert.throws(() => start({ sessionFile: 'sub\\dir\\s.json' }), (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM);
  assert.throws(() => start({ sessionFile: 'semi;colon.json' }), (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM);
});

test('sessionStore.isSafeSessionPath 单元判定', () => {
  assert.equal(isSafeSessionPath('sqli-session-1.json'), true);
  assert.equal(isSafeSessionPath(path.join(os.tmpdir(), 's.json')), true);
  assert.equal(isSafeSessionPath('/etc/passwd'), false);
  assert.equal(isSafeSessionPath('..\\..\\x'), false);
  assert.equal(isSafeSessionPath('..'), false);
  assert.equal(isSafeSessionPath(''), false);
  assert.equal(isSafeSessionPath(123), false);
  assert.equal(isSafeSessionPath('dir/s.json'), false); // 非 tmpdir 内分隔符路径
});

// ── P0-S2 并发扫描上限 ───────────────────────────────────────────
test('并发槽位：达到上限拒绝，释放后恢复，重复释放幂等', () => {
  _scanGovernance.resetForTest();
  const n = _scanGovernance.maxConcurrent;
  assert.ok(n >= 1);
  const releases = [];
  for (let i = 0; i < n; i++) {
    const r = acquireScanSlot();
    assert.ok(r, `第 ${i + 1} 个槽位应可获取`);
    releases.push(r);
  }
  assert.equal(_scanGovernance.activeScanCount, n);
  assert.equal(acquireScanSlot(), null, '超限应返回 null（路由层映射为 ENGINE_BUSY）');

  // 释放一个 → 可重新获取
  releases[0]();
  assert.equal(_scanGovernance.activeScanCount, n - 1);
  const r2 = acquireScanSlot();
  assert.ok(r2, '释放后应可重新获取');
  r2();
  assert.equal(_scanGovernance.activeScanCount, n - 1);

  // 重复释放幂等
  releases[1]();
  releases[1]();
  assert.equal(_scanGovernance.activeScanCount, n - 2);

  // 全部释放 → 归零（再放一遍验证幂等）
  releases.forEach((rel) => rel());
  releases.forEach((rel) => rel());
  assert.equal(_scanGovernance.activeScanCount, 0);
});

test('POST /scan/start 超限并发返回 ENGINE_BUSY(2002)', async () => {
  _scanGovernance.resetForTest();
  const releases = [];
  for (let i = 0; i < _scanGovernance.maxConcurrent; i++) releases.push(acquireScanSlot());

  const app = express();
  app.use(express.json());
  app.use('/api', scanRoutes);
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const port = server.address().port;
  try {
    const resp = await fetch(`http://127.0.0.1:${port}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'http://127.0.0.1:1/x?id=1', config: {} }),
    });
    const json = await resp.json();
    assert.equal(json.code, ErrorCode.ENGINE_BUSY);
    assert.equal(json.data, null);
    assert.ok(json.message.includes('上限'), '错误信息应说明已达上限');
  } finally {
    server.close();
    releases.forEach((r) => r());
  }
});

// ── P0-S3 配置白名单 + clamp ─────────────────────────────────────
test('配置白名单：越界大值被 clamp 到上界', () => {
  const out = start({
    extractConcurrency: 1e9,
    dumpMaxRows: 1e12,
    timeBlindSamples: 100,
    maxColumnsGuess: 1e6,
    dumpRowLimit: 99999,
    wafEvasion: { jitterMs: 99999 },
  });
  assert.equal(out.config.extractConcurrency, 16);
  assert.equal(out.config.dumpMaxRows, 50000);
  assert.equal(out.config.timeBlindSamples, 10);
  assert.equal(out.config.maxColumnsGuess, 100);
  assert.equal(out.config.dumpRowLimit, 1000);
  assert.equal(out.config.wafEvasion.jitterMs, 5000);
});

test('配置白名单：过低值被 clamp 到下界', () => {
  const out = start({
    extractConcurrency: 0,
    dumpMaxRows: 0,
    timeBlindSamples: 1,
    maxColumnsGuess: 0,
    dumpRowLimit: 0,
    jitterMs: -5,
  });
  assert.equal(out.config.extractConcurrency, 1);
  assert.equal(out.config.dumpMaxRows, 1);
  assert.equal(out.config.timeBlindSamples, 3);
  assert.equal(out.config.maxColumnsGuess, 1);
  assert.equal(out.config.dumpRowLimit, 1);
  assert.equal(out.config.jitterMs, undefined, '顶层 jitterMs 不在白名单（应位于 wafEvasion 下）→ 忽略');
});

test('配置白名单：blindRobust 布尔化 + 采样/阈值 clamp', () => {
  const out = start({
    blindRobust: {
      enabled: 'yes', // 非布尔 → true
      booleanSamples: 999, // → 10
      baselineSamples: -5, // → 1
      minStableRatio: 5, // → 1
      timeConfidenceZ: 'abc', // 非数值 → 默认 2
      adaptive: 0, // → false
      concurrency: 0, // → 1
    },
  });
  const br = out.config.blindRobust;
  assert.equal(br.enabled, true);
  assert.equal(br.booleanSamples, 10);
  assert.equal(br.baselineSamples, 1);
  assert.equal(br.minStableRatio, 1);
  assert.equal(br.timeConfidenceZ, 2);
  assert.equal(br.adaptive, false);
  assert.equal(br.concurrency, 1);
});

test('ratePerSec 不再 clamp：原样透传（P0-P1③）', () => {
  assert.equal(start({ ratePerSec: 1000 }).config.ratePerSec, 1000);
  assert.equal(start({ ratePerSec: 0.5 }).config.ratePerSec, 0.5);
  assert.equal(start({ ratePerSec: -3 }).config.ratePerSec, -3);
});

test('未知配置字段被忽略（不进 config、不报错）', () => {
  const out = start({ extractConcurrency: 4, someEvilField: 1, anotherWeird: 'x' });
  assert.equal(out.config.extractConcurrency, 4);
  assert.equal(out.config.someEvilField, undefined);
  assert.equal(out.config.anotherWeird, undefined);
});

test('level/risk：白名单 + clamp（level 1-5、risk 1-3，对标 sqlmap）', () => {
  assert.equal(start({ level: 9, risk: 0 }).config.level, 5);
  assert.equal(start({ level: 9, risk: 0 }).config.risk, 1);
  assert.equal(start({ level: -3, risk: 99 }).config.level, 1);
  assert.equal(start({ level: -3, risk: 99 }).config.risk, 3);
  assert.equal(start({ level: 2, risk: 3 }).config.level, 2);
  assert.equal(start({ level: 2, risk: 3 }).config.risk, 3);
  assert.equal(start({ level: '4', risk: '2' }).config.level, 4);
  assert.equal(start({ level: '4', risk: '2' }).config.risk, 2);
});

test('level/risk：未显式提供时不写入 config（由 createTarget 合并 defaults: 1/1）', () => {
  const out = start({});
  assert.equal(out.config.level, undefined);
  assert.equal(out.config.risk, undefined);
});

test('enableExtract 缺省 false、显式 true 保留（既有语义不变）', () => {
  assert.equal(start({}).config.enableExtract, false);
  assert.equal(start({ enableExtract: true }).config.enableExtract, true);
});
