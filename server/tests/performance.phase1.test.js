// Phase 1（性能 + 资源生命周期）增量回归：
// 1) ratePerSec 透传生效：按 scanId 独立令牌桶限速且互不干扰
// 2) 扫描上下文回收：completed 后 retiredAt + TTL 到期清 scans/eventBus
// 3) 共享缓存：同目标多注入点指纹只跑一次；columnGuess 命中缓存后零探测请求
// 4) eventBus.toSSE 对未知 scanId 补 res.end()（连接不悬挂）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpClient } from '../src/core/httpClient.js';
import { ScanManager } from '../src/engine/ScanManager.js';
import { binaryGuessColumns, createColumnGuessCache } from '../src/engine/columnGuess.js';
import * as eventBus from '../src/core/eventBus.js';

// ===== 1. 限速治理（P0-P1①+②）=====
test('ratePerSec 透传生效：按 scanId 独立桶限速且互不干扰', async () => {
  const client = new HttpClient();
  let calls = 0;
  client.instance.request = async () => {
    calls++;
    return { status: 200, data: '' };
  };
  // 两个扫描各自的桶：slow=10 req/s，fast=1000 req/s
  client.createBucket('scan-slow', 10);
  client.createBucket('scan-fast', 1000);

  // slow 桶：11 并发 → 前 10 个立即放行，第 11 个须等待约 100ms（限速真正生效）
  const t0 = Date.now();
  await Promise.all(Array.from({ length: 11 }, () => client.request({ url: 'http://127.0.0.1:9999/?sid=slow', scanId: 'scan-slow' })));
  const slowMs = Date.now() - t0;
  assert.ok(slowMs >= 90, `限速桶应生效（11 个@10req/s ≥100ms），实际 ${slowMs}ms`);

  // fast 桶：11 并发几乎瞬时，不被 slow 桶拖累（桶相互隔离）
  const t1 = Date.now();
  await Promise.all(Array.from({ length: 11 }, () => client.request({ url: 'http://127.0.0.1:9999/?sid=fast', scanId: 'scan-fast' })));
  const fastMs = Date.now() - t1;
  assert.ok(fastMs < 300, `独立桶不应互相拖累，实际 ${fastMs}ms`);
  assert.equal(calls, 22, '两个桶共发出 22 次请求');

  client.removeBucket('scan-slow');
  client.removeBucket('scan-fast');
});

test('request 缺省走默认单例桶（ratePerSec 缺省 defaults）', async () => {
  const client = new HttpClient();
  let captured = null;
  client.instance.request = async (cfg) => {
    captured = cfg;
    return { status: 200, data: 'ok' };
  };
  const res = await client.request({ method: 'GET', url: 'http://127.0.0.1:9999/', headers: {} });
  assert.ok(res && res.data === 'ok');
  assert.equal(captured.proxy, false);
});

// ===== 2. 扫描上下文回收（P0-R1）=====
// 构造可快速完成的扫描（全部 mock，不发真实请求）
function makeFastScanManager(opts = {}) {
  const sm = new ScanManager({ retireTtlMs: opts.retireTtlMs ?? 50 });
  sm.detectors = []; // 无检测器 → 检测阶段零请求
  sm.fp = { async fingerprint() { return { dbms: null, baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.parser = { async discover() { return [{ id: 'p1', location: 'url', param: 'q', originalValue: '1' }]; } };
  sm.httpClient = { async request() { return { status: 200, headers: {}, data: 'ok' }; } }; // 无 forScan → getScanClient 原样返回
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  return sm;
}

async function waitScanDone(sm, scanId, tries = 200) {
  for (let i = 0; i < tries; i++) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) return s;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(`扫描未在预期时间内结束：${scanId}`);
}

test('扫描 completed 后置 retiredAt，TTL 到期自动回收 scans/eventBus', async () => {
  const sm = makeFastScanManager({ retireTtlMs: 50 });
  const id = await sm.start({ url: 'http://x/?q=1', config: { concurrency: 1, ratePerSec: 100, techniques: ['union'] } });
  const emBefore = eventBus.create(id); // 与 start 时同一发射器（捕获于回收前）
  const s = await waitScanDone(sm, id);

  assert.equal(s.status, 'completed');
  assert.ok(s.retiredAt, 'completed 后应置 retiredAt');
  assert.ok(sm.scans.has(id), 'TTL 未到期前 scans 条目仍在（报告仍可读）');
  assert.deepStrictEqual(sm.getReport(id), s.report, 'TTL 内可获取最终报告');

  // 等待 TTL 过后清理
  await new Promise((r) => setTimeout(r, 120));
  assert.equal(sm.scans.has(id), false, 'TTL 到期后 scans 条目应被清空');
  assert.equal(sm.getReport(id), null, '回收后报告不可再读');
  // eventBus 已 dispose：重建得到新发射器（原命名空间已清理）
  const emAfter = eventBus.create(id);
  assert.notEqual(emAfter, emBefore, 'dispose 后 create 重建为新的发射器');
  eventBus.dispose(id);
});

// ===== 3. 共享缓存（P0-P2）=====
test('同目标多注入点共享指纹：并发下首点跑一次，后续点零指纹请求', async () => {
  let fpCalls = 0;
  const sm = new ScanManager();
  sm.detectors = [];
  sm.fp = {
    async fingerprint() {
      fpCalls++;
      return { dbms: 'MySQL', baseline: { status: 200, headers: {}, body: '' } };
    },
  };
  sm.parser = {
    async discover() {
      return [
        { id: 'a', location: 'url', param: 'a', originalValue: '1' },
        { id: 'b', location: 'url', param: 'b', originalValue: '2' },
      ];
    },
  };
  sm.httpClient = { async request() { return { status: 200, headers: {}, data: 'ok' }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  const id = await sm.start({
    url: 'http://x/?a=1&b=2',
    // 本测试只验证指纹跨点共享（两点都须进入调度）；关闭预筛选以隔离该关注点（预筛选默认会跳过"无注入迹象"点）
    config: { concurrency: 2, ratePerSec: 100, techniques: ['union'], prefilter: false },
  });
  await waitScanDone(sm, id);
  assert.equal(fpCalls, 1, '两个注入点应共享同一次指纹（原实现会重复跑 2 次 8-9 请求指纹）');
});

test('columnGuess 共享缓存命中后不再发探测请求', async () => {
  const cache = createColumnGuessCache();
  let probes = 0;
  // 3 列为真实列数：ORDER BY n>3 时 status=500
  const probe = async (n) => {
    probes++;
    return n <= 3 ? { status: 200, data: 'x'.repeat(100) } : { status: 500, data: '' };
  };
  const opts = { baseLen: 100, maxCols: 10, cache, cacheKey: 'point-a' };
  const r1 = await binaryGuessColumns(probe, opts);
  const afterFirst = probes;
  const r2 = await binaryGuessColumns(probe, opts);

  assert.equal(r1, 3);
  assert.equal(r2, 3);
  assert.equal(probes, afterFirst, '缓存命中后探测请求数不再增长（零请求复用猜列结果）');
  assert.ok(afterFirst > 0 && afterFirst < 6, `首次二分探测应有限（实际 ${afterFirst} 次）`);
});

// ===== 4. eventBus.toSSE 未知 scanId 补 res.end() =====
test('toSSE 对未知 scanId 写 scan_error 后 res.end() 关闭连接', () => {
  const writes = [];
  let ended = false;
  const res = {
    writeHead() {},
    write: (s) => writes.push(s),
    end: () => {
      ended = true;
    },
  };
  const req = { on() {} };
  eventBus.toSSE('unknown-scan-xyz', req, res);
  assert.ok(writes.some((w) => w.includes('scan_error')), '应推送 scan_error');
  assert.equal(ended, true, '未知 scanId 分支应调用 res.end()，避免 SSE 连接悬挂泄漏');
});
