// 端到端吞吐基准测试（性能审查：缺少端到端吞吐基准 N 点 × ratePerSec 变化）
//
// 用 ScanManager + mock httpClient（保留真实 TokenBucket 限速，仅替换 axios 网络层为即时
// 模拟响应，无真实网络）构造 4 注入点干净目标，验证：
//   (a) ratePerSec=100，4 注入点，prefilter off：记录墙钟与请求数，扫描正常完成
//   (b) ratePerSec=10，4 注入点，prefilter off：请求数与 (a) 一致（限速只降吞吐不丢/不重发请求）
//   (c) prefilter 开启时请求数 < 关闭时（干净目标被预筛跳过完整检测）
//
// 断言仅覆盖「请求数符合预期」与「扫描正常完成」；不做耗时断言（CI 波动大），墙钟仅记录。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpClient } from '../src/core/httpClient.js';
import { ScanManager } from '../src/engine/ScanManager.js';

// 构造带计数器的 mock HttpClient：保留真实 TokenBucket（ratePerSec 限速真正生效），
// 仅替换 axios instance.request 为即时返回的模拟响应（无真实网络）。
// 这样 ratePerSec 的限速语义在端到端扫描中被真实验证，而非仅 mock 自检。
function makeMockHttpClient() {
  const client = new HttpClient();
  let count = 0;
  client.instance.request = async () => {
    count++;
    // 模拟无注入的干净目标：状态 200，空 headers，固定正文（所有探测响应一致 → 无注入信号）
    return { status: 200, headers: {}, data: 'normal' };
  };
  return { client, getCount: () => count };
}

// 构造 ScanManager：注入 mock httpClient + parser 直接返回 4 个 URL 注入点（无表单爬取/零 HTTP）
function makeScanner(client) {
  const sm = new ScanManager();
  sm.httpClient = client;
  sm.parser = {
    async discover() {
      return [
        { id: 'p1', location: 'url', param: 'id', originalValue: '1' },
        { id: 'p2', location: 'url', param: 'name', originalValue: 'test' },
        { id: 'p3', location: 'url', param: 'cat', originalValue: '2' },
        { id: 'p4', location: 'url', param: 'tag', originalValue: '3' },
      ];
    },
  };
  return sm;
}

// 轮询 sm.scans.get(scanId).status 直到 completed/error
// 默认轮询 60s（ratePerSec=10 时 ~140 请求需 ~14s，留足余量）
async function waitScanDone(sm, scanId, tries = 6000) {
  for (let i = 0; i < tries; i++) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) return s;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`扫描未在预期时间内结束：${scanId}`);
}

// 4 注入点干净目标 URL（127.0.0.1 避免 DNS 解析；SSRF 默认策略放行回环 IP）
const TARGET_URL = 'http://127.0.0.1:9999/?id=1&name=test&cat=2&tag=3';

// 基准数据收集（node:test 同文件测试默认顺序执行，跨测试共享安全）
const bench = { a: null, b: null, c: null };

// (a) ratePerSec=100，4 注入点，prefilter off：基线吞吐
test(
  '(a) ratePerSec=100, 4 注入点, prefilter off',
  { timeout: 60000 },
  async () => {
    const { client, getCount } = makeMockHttpClient();
    const sm = makeScanner(client);
    const t0 = Date.now();
    const scanId = await sm.start({
      url: TARGET_URL,
      config: { concurrency: 4, ratePerSec: 100, techniques: ['boolean'], prefilter: false },
    });
    const s = await waitScanDone(sm, scanId);
    const wall = Date.now() - t0;
    const count = getCount();
    assert.equal(s.status, 'completed', 'ratePerSec=100 扫描应正常完成');
    assert.ok(count > 0, 'ratePerSec=100 应发出请求（完整检测流水线）');
    bench.a = { ratePerSec: 100, requests: count, wallMs: wall };
    console.log(`[a] rate=100/s → ${count} reqs, 墙钟 ${wall}ms`);
  }
);

// (b) ratePerSec=10，4 注入点，prefilter off：限速仅降吞吐，请求数与 (a) 一致
test(
  '(b) ratePerSec=10, 4 注入点, prefilter off（请求数受限一致）',
  { timeout: 120000 },
  async () => {
    const { client, getCount } = makeMockHttpClient();
    const sm = makeScanner(client);
    const t0 = Date.now();
    const scanId = await sm.start({
      url: TARGET_URL,
      config: { concurrency: 4, ratePerSec: 10, techniques: ['boolean'], prefilter: false },
    });
    const s = await waitScanDone(sm, scanId);
    const wall = Date.now() - t0;
    const count = getCount();
    assert.equal(s.status, 'completed', 'ratePerSec=10 扫描应正常完成');
    // 限速只影响吞吐（墙钟），不影响请求数：每个请求仍完整执行一次，不丢/不重发
    // 容差 ±10（并发+预筛选+检测器内部缓存命中可能导致少量差异）
    const diff = Math.abs(count - bench.a.requests);
    assert.ok(
      diff <= 10,
      `ratePerSec=10 请求数应接近 ratePerSec=100（容差±10），实际 ${count} vs ${bench.a.requests}（差 ${diff}）`
    );
    bench.b = { ratePerSec: 10, requests: count, wallMs: wall };
    console.log(`[b] rate=10/s  → ${count} reqs, 墙钟 ${wall}ms`);
  }
);

// (c) prefilter 开启时请求数 < 关闭时（干净目标被预筛跳过完整检测）
test(
  '(c) prefilter on 请求数 < prefilter off',
  { timeout: 60000 },
  async () => {
    // prefilter ON（默认开启）
    const onMock = makeMockHttpClient();
    const smOn = makeScanner(onMock.client);
    const idOn = await smOn.start({
      url: TARGET_URL,
      config: { concurrency: 4, ratePerSec: 100, techniques: ['boolean'] }, // prefilter 默认 true
    });
    const sOn = await waitScanDone(smOn, idOn);
    const onCount = onMock.getCount();

    // prefilter OFF
    const offMock = makeMockHttpClient();
    const smOff = makeScanner(offMock.client);
    const idOff = await smOff.start({
      url: TARGET_URL,
      config: { concurrency: 4, ratePerSec: 100, techniques: ['boolean'], prefilter: false },
    });
    const sOff = await waitScanDone(smOff, idOff);
    const offCount = offMock.getCount();

    assert.equal(sOn.status, 'completed', 'prefilter=on 扫描应正常完成');
    assert.equal(sOff.status, 'completed', 'prefilter=off 扫描应正常完成');
    assert.ok(
      onCount < offCount,
      `prefilter 开启时请求数应少于关闭时：on=${onCount} off=${offCount}`
    );
    bench.c = { prefilterOn: onCount, prefilterOff: offCount };
    console.log(`[c] prefilter on=${onCount} reqs < off=${offCount} reqs`);
  }
);

// 汇总报告（同文件最后顺序执行，此时 bench.a/b/c 均已填充）
test('吞吐基准报告汇总', () => {
  const a = bench.a, b = bench.b, c = bench.c;
  const lines = ['=== 吞吐基准报告 ==='];
  if (a) lines.push(`(a) rate=100/s  4pts prefilter=off → ${a.requests} reqs, 墙钟 ${a.wallMs}ms`);
  if (b) lines.push(`(b) rate=10/s   4pts prefilter=off → ${b.requests} reqs, 墙钟 ${b.wallMs}ms`);
  if (a && b) lines.push(`    限速仅降吞吐：req 数与 (a) 一致 (${a.requests})，墙钟差 ${b.wallMs - a.wallMs}ms`);
  if (c) lines.push(`(c) prefilter on=${c.prefilterOn} reqs < off=${c.prefilterOff} reqs (省 ${c.prefilterOff - c.prefilterOn} reqs)`);
  lines.push('=== 报告结束 ===');
  console.log(lines.join('\n'));
});
