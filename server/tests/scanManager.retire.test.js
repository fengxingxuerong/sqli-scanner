// ScanManager 退役/淘汰/清理/脱敏/停止 关键方法回归测试
// 全部使用桩依赖与真实 eventBus 行为断言，不发起任何真实网络请求。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager, publicTarget } from '../src/engine/ScanManager.js';
import {
  createTarget,
  createInjectionPoint,
  createReport,
} from '../src/engine/models.js';
import * as eventBus from '../src/core/eventBus.js';

// 1) _retire：TTL 到期后清理 scans 条目 + 释放 eventBus 命名空间（退役定时器已 unref，
//    但测试自身的等待定时器会让事件循环存活，使 TTL 定时器照常触发）
test('_retire：TTL 到期后 scans 条目被删除 + eventBus dispose 生效', async () => {
  const sm = new ScanManager({ retireTtlMs: 20 });
  const scanId = 'retire-1';
  sm.scans.set(scanId, { status: 'completed', createdAt: Date.now() });
  eventBus.create(scanId);
  let fired = 0;
  eventBus.create(scanId).on('event', () => fired++);

  sm._retire(scanId);
  // TTL 未到期：条目仍在，_retired 标记已置位
  assert.equal(sm.scans.has(scanId), true);
  assert.equal(sm.scans.get(scanId)._retired, true);
  // 幂等：再次 _retire 不应调度第二个定时器（_retired 已置位直接返回）
  sm._retire(scanId);

  await new Promise((r) => setTimeout(r, 60));
  assert.equal(sm.scans.has(scanId), false, 'TTL 到期后 scans 条目应被清理');
  eventBus.emit(scanId, 'after-ttl', {});
  assert.equal(fired, 0, 'dispose 后 emit 不应再命中任何监听器');
  // 不存在的 scanId 调用 _retire 为 no-op，不应抛错
  sm._retire('not-exist');
});

// 1b) _retire：TTL 未到期时 scans 条目与 eventBus 命名空间仍在
test('_retire：TTL 未到期时条目与命名空间均保留', async () => {
  const sm = new ScanManager({ retireTtlMs: 5000 });
  const scanId = 'retire-keep';
  sm.scans.set(scanId, { status: 'stopped', createdAt: Date.now() });
  eventBus.create(scanId);
  sm._retire(scanId);
  assert.equal(sm.scans.has(scanId), true);
  assert.ok(sm.scans.get(scanId)._retireTimer, '应已调度退役定时器');
});

// 2) _evictIfOverLimit：超限淘汰最旧非 running 扫描；全部 running 时宁可超限也不淘汰在途
test('_evictIfOverLimit：淘汰最旧非 running 扫描，运行中扫描保留', () => {
  const sm = new ScanManager({ maxScans: 2 });
  sm.scans.set('old-done', { status: 'completed', createdAt: 1000 });
  sm.scans.set('mid-running', { status: 'running', createdAt: 2000 });
  sm.scans.set('new-error', { status: 'error', createdAt: 3000 });
  // 持有淘汰前的 emitter 引用；淘汰后 dispose 会 removeAllListeners + 删 Map 条目，
  // emit 将因找不到命名空间而 no-op，原 emitter 上的监听器不再被触发。
  const em = eventBus.create('old-done');
  let fired = 0;
  em.on('event', () => fired++);
  sm._evictIfOverLimit();
  assert.deepEqual([...sm.scans.keys()].sort(), ['mid-running', 'new-error']);
  eventBus.emit('old-done', 'probe', {});
  assert.equal(fired, 0, '被淘汰扫描的 eventBus 命名空间应已释放');
});

test('_evictIfOverLimit：全部 running 时宁可超限也不淘汰在途扫描', () => {
  const sm = new ScanManager({ maxScans: 1 });
  sm.scans.set('a', { status: 'running', createdAt: 1 });
  sm.scans.set('b', { status: 'running', createdAt: 2 });
  sm._evictIfOverLimit();
  assert.equal(sm.scans.size, 2, '无非 running 可淘汰时应全部保留');
});

// 3) _disposeScan：清理 scans Map + eventBus 命名空间 + 限速桶 + 退役定时器
test('_disposeScan：scans/限速桶/eventBus 全部清理 + clearTimeout 退役定时器', async () => {
  const sm = new ScanManager();
  const removed = [];
  sm.httpClient = { removeBucket: (id) => removed.push(id) };
  const scanId = 'dispose-1';
  let timerFired = false;
  const timer = setTimeout(() => { timerFired = true; }, 10);
  sm.scans.set(scanId, { status: 'completed', _retireTimer: timer, createdAt: Date.now() });
  sm._scanClients.set(scanId, {});
  eventBus.create(scanId);
  let fired = 0;
  eventBus.create(scanId).on('event', () => fired++);

  sm._disposeScan(scanId);
  assert.equal(sm.scans.has(scanId), false);
  assert.equal(sm._scanClients.has(scanId), false);
  assert.deepEqual(removed, [scanId], 'removeBucket 应被调用一次');
  eventBus.emit(scanId, 'probe', {});
  assert.equal(fired, 0, 'eventBus 命名空间应已释放');

  await new Promise((r) => setTimeout(r, 30));
  assert.equal(timerFired, false, '退役定时器应被 clearTimeout 清除');
});

// 4) publicTarget：auth/proxy 脱敏、cookieParams/headerParams 剥离、connectionString 打码；原对象不可变
test('publicTarget：auth/proxy 脱敏、cookie/header 剥离、connectionString 打码', () => {
  const target = {
    baseUrl: 'http://x.test/?id=1',
    method: 'GET',
    config: { auth: { user: 'u', pass: 'p' }, proxy: 'http://proxy', ratePerSec: 5, timeoutMs: 100 },
    cookieParams: { sess: 'secret' },
    headerParams: { Authorization: 'Bearer x' },
    db: { connectionString: 'mysql://u:p@h/db', name: 'x' },
  };
  const out = publicTarget(target);
  assert.equal(out.config.auth, null);
  assert.equal(out.config.proxy, null);
  assert.equal(out.config.ratePerSec, 5);
  assert.equal(out.config.timeoutMs, 100);
  assert.ok(!('cookieParams' in out), 'cookieParams 应被剥离');
  assert.ok(!('headerParams' in out), 'headerParams 应被剥离');
  assert.equal(out.db.connectionString, '***');
  assert.equal(out.db.name, 'x');
  // 原对象不可变
  assert.deepEqual(target.config.auth, { user: 'u', pass: 'p' });
  assert.equal(target.config.proxy, 'http://proxy');
  assert.ok('cookieParams' in target);
  assert.equal(target.db.connectionString, 'mysql://u:p@h/db');
});

test('publicTarget：非对象原样返回', () => {
  assert.equal(publicTarget(null), null);
  assert.equal(publicTarget(undefined), undefined);
  assert.equal(publicTarget('x'), 'x');
});

// 5) stop：扫描中立即停止，stopped 后不再跑二阶/NoSQL，status 不被覆盖为 completed
test('stop：扫描中停止后不再跑二阶/NoSQL，status 保持 stopped', async () => {
  const sm = new ScanManager({ retireTtlMs: 60000 });
  // mock httpClient（不发起真实网络）
  sm.httpClient = {};
  // 桩检测器：union 慢速以制造停止窗口；全部未命中（仅验证停止路径，不验证命中）
  sm.detectors = [
    { technique: 'union', async detect() { await new Promise((r) => setTimeout(r, 80)); return { vulnerable: false }; } },
    { technique: 'error', async detect() { return { vulnerable: false }; } },
    { technique: 'boolean', async detect() { return { vulnerable: false }; } },
    { technique: 'time', async detect() { return { vulnerable: false }; } },
    { technique: 'stacked', async detect() { return { vulnerable: false }; } },
    { technique: 'oob', async detect() { return { vulnerable: false }; } },
    { technique: 'inline', async detect() { return { vulnerable: false }; } },
  ];
  sm.fp = { async fingerprint() { return { dbms: 'MySQL', baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return [createInjectionPoint('url', 'id', '1')]; } };
  // 计数二阶/NoSQL 是否被调用（停止后不应被调用）
  let soCalled = 0, noSqlCalled = 0;
  sm._runSecondOrder = async () => { soCalled++; return []; };
  sm._runNoSql = async () => { noSqlCalled++; return []; };

  const target = createTarget({
    url: 'http://x.test/?id=1', method: 'GET',
    config: { concurrency: 1, ratePerSec: 100, enableExtract: false, secondOrder: { enabled: true, triggerUrls: ['http://x.test/trigger'] } },
  });
  const scanId = 'stop-1';
  sm.scans.set(scanId, { target, report: createReport(scanId, target), status: 'running', cancelled: false, createdAt: Date.now() });
  eventBus.create(scanId);

  const runPromise = sm._run(scanId);
  // 等扫描进入检测后停止（union 检测需要 80ms，10ms 时仍在运行中）
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(sm.stop(scanId), true);
  await runPromise;

  const s = sm.scans.get(scanId);
  assert.ok(s, 'retireTtl 较长，条目应在停止后仍保留');
  assert.equal(s.status, 'stopped', 'status 应保持 stopped，不被覆盖为 completed');
  assert.equal(soCalled, 0, '停止后不应再跑二阶检测');
  assert.equal(noSqlCalled, 0, '停止后不应再跑 NoSQL 检测');
  assert.ok(s.report.finishedAt, 'stopped 路径应写入 finishedAt');
  assert.equal(s._retired, true, '停止路径应触发 _retire');
  // 未知 scanId 停止返回 false
  assert.equal(sm.stop('not-exist'), false);
});
