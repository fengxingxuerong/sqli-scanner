// P2-P1 参数预筛选（性能）测试（node --test）
// 验证：1) 无注入迹象目标只发少量请求（预筛选探测），完整检测被跳过、报告 point 列表不受影响；
//       2) 任一探测有信号（单引号报错）的点保守保留并完整检出（不漏检）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads.js';

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]v=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.v !== 'undefined') return String(opts.data.v);
  return '';
}

// 构造预筛选测试用 ScanManager：parser 固定返回点；检测器桩记录调用次数
function makeManager(points, httpClient, plan = { union: { vulnerable: true } }) {
  const detectCalls = [];
  const sm = new ScanManager();
  sm.httpClient = httpClient; // 预筛选探测走此 mock（无 forScan → getScanClient 原样返回）
  sm.detectors = TECHNIQUE_TYPES.map((t) => ({
    technique: t,
    async detect(ctx) {
      detectCalls.push(t);
      const spec = plan[t] || {};
      const hit = !!(spec && spec.vulnerable);
      return {
        pointId: ctx.point.id,
        technique: t,
        vulnerable: hit,
        dbms: hit ? 'MySQL' : null,
        evidence: hit ? `mock ${t} hit` : '',
        payloads: hit ? [`mock_${t}`] : [],
      };
    },
  }));
  sm.fp = { async fingerprint() { return { dbms: null, baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return points; } };
  sm._detectCalls = detectCalls;
  return sm;
}

async function runScan(sm, config) {
  const id = await sm.start({
    url: 'http://mock.test/?id=1',
    config: { concurrency: 2, ratePerSec: 100, ...config },
  });
  for (let i = 0; i < 200; i++) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  return id;
}

test('预筛选：无注入迹象目标只发少量请求，完整检测被跳过且报告点列表不受影响', async () => {
  const points = [
    { id: 'p1', location: 'url', param: 'v', originalValue: '1' },
    { id: 'p2', location: 'url', param: 'v', originalValue: '2' },
    { id: 'p3', location: 'url', param: 'v', originalValue: '3' },
  ];
  let requests = 0;
  const cleanMock = {
    async request() {
      requests++;
      return { data: 'stable page content', status: 200 };
    },
  };
  const sm = makeManager(points, cleanMock);
  const id = await runScan(sm, { prefilter: true });
  const report = sm.getReport(id);
  // [P1-FIX 2026-09-05] 1 次基线 RTT 测量（共享）+ 3 点 × 4 探针（基线/单引号/MySQL SLEEP/pg_sleep
  // 双族时间探针，dbms 未知）= 13 次预筛选请求，完整检测（含指纹）零请求
  assert.equal(requests, 13, `应只发预筛选探测请求，实际 ${requests} 次`);
  assert.equal(sm._detectCalls.length, 0, '无注入迹象点不应进入完整检测');
  assert.equal(report.points.length, 3, '预筛选不应影响报告 point 列表');
  assert.equal(report.vulns.length, 0);
});

test('预筛选：单引号报错有信号的点保守保留并完整检出（不漏检）', async () => {
  const points = [
    { id: 'p1', location: 'url', param: 'v', originalValue: '1' }, // 干净
    { id: 'p2', location: 'url', param: 'v', originalValue: '2' }, // 单引号报错 → 可疑
  ];
  let requests = 0;
  const suspiciousMock = {
    async request(opts) {
      requests++;
      const q = extractQuery(opts);
      // 仅 p2（原值 '2'）的闭合探测（单引号注入值以 2 开头）触发报错 → 响应偏离基线 → 可疑保留
      if (q.startsWith('2') && q.includes("'")) return { data: 'SQL ERROR PAGE', status: 500 };
      return { data: 'stable page content', status: 200 };
    },
  };
  const sm = makeManager(points, suspiciousMock, { union: { vulnerable: true } });
  const id = await runScan(sm, { prefilter: true });
  const report = sm.getReport(id);
  assert.ok(report.vulns.find((v) => v.technique === 'union'), '可疑点应保留并完整检出');
  // [P1-FIX 2026-09-05] 1 次基线 RTT + 2 点 × 4 探针（未知库双族时间探针）+ p2 完整检测
  // （指纹桩 0 请求，仅 union 检测命中；union 命中后慢速层不跑）
  // [OPT-FIX 2026-09-08] p2 单引号探针报错 → 追加 1 次良性非法值甄别探针（响应异构 →
  // 真实 SQL 报错信号 → 保守保留），探测请求 9 → 10。
  assert.equal(requests, 10, `2 点应发 10 次预筛选探测（含 1 次基线 RTT + 1 次良性甄别探针），实际 ${requests} 次`);
  // 只有可疑点进入完整检测；默认 techniques 不含 inline，且 union 命中后 time 层跳过
  assert.deepEqual([...sm._detectCalls].sort(), ['boolean', 'error', 'union']);
});

test('预筛选：prefilter:false 关闭后所有点进入完整检测（零探测请求）', async () => {
  const points = [
    { id: 'p1', location: 'url', param: 'v', originalValue: '1' },
    { id: 'p2', location: 'url', param: 'v', originalValue: '2' },
  ];
  let requests = 0;
  const cleanMock = {
    async request() {
      requests++;
      return { data: 'stable page content', status: 200 };
    },
  };
  const sm = makeManager(points, cleanMock, { union: { vulnerable: true } });
  const id = await runScan(sm, { prefilter: false });
  const report = sm.getReport(id);
  assert.equal(requests, 0, 'prefilter:false 不应发任何探测请求');
  assert.ok(report.vulns.find((v) => v.technique === 'union'), '关闭预筛选后所有点完整检测');
});

// [P1-FIX 2026-09-05] dbms 感知时间探针：指定 PostgreSQL → 时间探针用 pg_sleep 而非 SLEEP
test('预筛选：dbms=PostgreSQL 时时间探针为 pg_sleep（无 MySQL SLEEP 探针）', async () => {
  const points = [
    { id: 'p1', location: 'url', param: 'v', originalValue: '1' },
    { id: 'p2', location: 'url', param: 'v', originalValue: '2' },
  ];
  const urls = [];
  const cleanMock = {
    async request(opts) {
      urls.push(decodeURIComponent(opts.url || ''));
      return { data: 'stable page content', status: 200 };
    },
  };
  const sm = makeManager(points, cleanMock);
  await runScan(sm, { prefilter: true, dbms: 'PostgreSQL' });
  assert.ok(urls.some((u) => /pg_sleep/i.test(u)), '应发 pg_sleep 时间探针');
  // 注意：'pg_sleep(' 含子串 'sleep('，负断言须用 'AND SLEEP' 精确匹配 MySQL 探针
  assert.ok(!urls.some((u) => /AND SLEEP\(/i.test(u)), '指定 PG 后不应再发 MySQL SLEEP 探针');
});

// [P1-FIX 2026-09-05] 动态预算：公网 RTT（模拟 300ms）下预筛选仍生效（旧固定 120ms 预算必然超时全保留）
test('预筛选：高 RTT 目标动态预算生效，干净点仍被跳过', async () => {
  const points = [
    { id: 'p1', location: 'url', param: 'v', originalValue: '1' },
    { id: 'p2', location: 'url', param: 'v', originalValue: '2' },
  ];
  const cleanMock = {
    async request() {
      await new Promise((r) => setTimeout(r, 300)); // RTT 300ms > 旧预算 120ms
      return { data: 'stable page content', status: 200 };
    },
  };
  const sm = makeManager(points, cleanMock);
  const id = await runScan(sm, { prefilter: true });
  const report = sm.getReport(id);
  assert.equal(sm._detectCalls.length, 0, '高 RTT 干净点应被预筛跳过（动态预算生效）');
  assert.equal(report.vulns.length, 0);
});
