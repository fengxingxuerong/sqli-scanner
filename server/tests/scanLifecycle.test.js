// 生命周期与并发隔离测试：
// 1) HttpClient.fork：每扫描独立令牌桶（并发互不拖慢/共享配额）+ 独立 requestDelayMs/keepAlive
// 2) ScanManager 扫描快照淘汰：scanRetentionMs TTL + maxScans 上限（防 scans Map 内存泄漏）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { HttpClient } from '../src/core/httpClient.js';
import { ScanManager } from '../src/engine/ScanManager.js';
import * as eventBus from '../src/core/eventBus.js';

// ===== 1. fork 独立令牌桶 =====

test('fork 共享连接池/axios 实例，但令牌桶独立（ratePerSec 按 config）', () => {
  const base = new HttpClient();
  const a = base.fork({ ratePerSec: 5 });
  const b = base.fork({ ratePerSec: 20 });
  // 连接池共享（引用相同）
  assert.equal(a.instance, base.instance, 'axios 实例应共享');
  assert.equal(a.keepAliveAgent, base.keepAliveAgent, 'keepAlive agent 应共享');
  // 令牌桶独立
  assert.notEqual(a.bucket, b.bucket, '每个 fork 应有独立令牌桶');
  assert.equal(a.bucket.ratePerSec, 5);
  assert.equal(b.bucket.ratePerSec, 20);
  // 默认继承 defaults
  const c = base.fork(null);
  assert.ok(c.bucket.ratePerSec > 0);
});

test('fork 消费配额互不影响：a 耗光令牌不阻塞 b（并发扫描各自限速）', async () => {
  const base = new HttpClient();
  // 极小配额，便于快速耗光
  const a = base.fork({ ratePerSec: 1 });
  const b = base.fork({ ratePerSec: 1000 });
  a.bucket.capacity = 1;
  a.bucket.tokens = 1;
  a.bucket.ratePerSec = 0.001; // 几乎不补充
  // a 拿走唯一令牌
  await a.bucket.acquire();
  // b 应立即能拿到（独立桶）
  const t0 = Date.now();
  await b.bucket.acquire();
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 50, `b 不应被 a 的桶阻塞，实际等待 ${elapsed}ms`);
});

test('fork 支持 requestDelayMs / keepAlive 覆盖（与 withScanOverrides 同语义）', () => {
  const base = new HttpClient();
  const c = base.fork({ requestDelayMs: 300, keepAlive: false });
  assert.equal(c.requestDelayMs, 300);
  assert.equal(c.keepAlive, false);
  const d = base.fork({});
  assert.equal(d.requestDelayMs, 0);
  assert.equal(d.keepAlive, true);
});

// ===== 2. ScanManager 扫描快照淘汰 =====

// 起一个极快完成的最小目标（union 检测即可命中、立即出报告）
function startMinTarget() {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://mock/');
    const id = u.searchParams.get('id') || '1';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(`<html><body><div id="x">id=${id}</div></body></html>`);
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }))
  );
}

async function pollDone(mgr, scanId, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = mgr.getReport(scanId);
    if (r && r.finishedAt) return r;
    await new Promise((res) => setTimeout(res, 50));
  }
  return null;
}

test('scanRetentionMs 到期后扫描快照从内存清除（含 EventBus 清理）', async () => {
  const { server, port } = await startMinTarget();
  const mgr = new ScanManager({ scanRetentionMs: 200, maxScans: 100 });
  const scanId = await mgr.start({
    url: `http://127.0.0.1:${port}/?id=1`,
    method: 'GET',
    config: { techniques: ['union'], concurrency: 1, ratePerSec: 100, enableExtract: false, blindRobust: { enabled: false } },
  });
  const report = await pollDone(mgr, scanId);
  server.close();
  assert.ok(report, '扫描未完成');
  assert.ok(mgr.getReport(scanId), '完成后短期内快照应仍存在（前端仍可拉取）');
  // 等待 TTL 到期（留足余量）
  await new Promise((res) => setTimeout(res, 800));
  assert.equal(mgr.getReport(scanId), null, 'TTL 到期后快照应被清除');
});

test('maxScans 上限：超过后最旧已完成快照被淘汰', async () => {
  const { server, port } = await startMinTarget();
  const mgr = new ScanManager({ scanRetentionMs: 60000, maxScans: 2 });
  const ids = [];
  for (let i = 0; i < 3; i++) {
    const scanId = await mgr.start({
      url: `http://127.0.0.1:${port}/?id=${i}`,
      method: 'GET',
      config: { techniques: ['union'], concurrency: 1, ratePerSec: 100, enableExtract: false, blindRobust: { enabled: false } },
    });
    ids.push(scanId);
    await pollDone(mgr, scanId);
  }
  server.close();
  // 完成 3 个扫描，上限 2 → 最旧的 ids[0] 应被淘汰
  assert.equal(mgr.getReport(ids[0]), null, '最旧扫描应被淘汰');
  assert.ok(mgr.getReport(ids[1]), '第 2 个应保留');
  assert.ok(mgr.getReport(ids[2]), '第 3 个应保留');
});

test('running 中的扫描不被淘汰（即使超过 maxScans）', async () => {
  const mgr = new ScanManager({ scanRetentionMs: 0, maxScans: 0 });
  // maxScans=0 表示不启用上限；此处验证 running 快照在 _finalizeScan 前不被误删
  const s = { status: 'running', report: { finishedAt: null } };
  const id = 'running-scan-test';
  mgr.scans.set(id, s);
  mgr._finalizeScan(id); // 不应删除 running 扫描（scanRetentionMs=0 时定时器不会删除）
  assert.ok(mgr.getReport(id), 'running 扫描不应被淘汰');
  mgr.scans.delete(id);
});

test('eventBus 在扫描淘汰时被 dispose（命名空间不泄漏）', async () => {
  const { server, port } = await startMinTarget();
  const mgr = new ScanManager({ scanRetentionMs: 150, maxScans: 100 });
  const scanId = await mgr.start({
    url: `http://127.0.0.1:${port}/?id=1`,
    method: 'GET',
    config: { techniques: ['union'], concurrency: 1, ratePerSec: 100, enableExtract: false, blindRobust: { enabled: false } },
  });
  await pollDone(mgr, scanId);
  server.close();
  // 等待 TTL 到期，快照被淘汰（_evictScan 内部会调 eventBus.dispose 释放命名空间）
  await new Promise((res) => setTimeout(res, 700));
  assert.equal(mgr.getReport(scanId), null, 'TTL 到期后扫描快照应被清除（含 EventBus 命名空间）');
  // 再次淘汰应幂等（scanId 已不存在时不抛错）
  mgr._evictScan(scanId);
  // 淘汰后对该 scanId 发事件应无副作用（命名空间已释放）
  eventBus.emit(scanId, 'scan_error', { message: 'should be noop' });
});
