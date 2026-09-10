// [P0-FIX 2026-09-08] scanValidityGuard.js 单元测试 + 流水线集成用例
// 覆盖点：
//   1) 连续失败达阈 → shouldAbort + unreachable（且状态粘滞：目标恢复也不洗白结论）
//   2) 保守不误判：200/403 混合但占比不足 → ok；200 页面含拦截文案 → 不判 blocked
//   3) blocked 暴露 suggestBackoffMs（来自 Retry-After）
//   4) 会话过期（注入请求连续 401 / 302 跳登录页）→ session_expired；整站 401 反例不判
//   5) summary 契约字段齐全（前端与报告都按固定字段名消费）
//   6) scanRunner 集成：httpClient 全程返回 null → report.summary.verdict === 'inconclusive'
//      且 inconclusivePoints 非空；健康目标（全 200）→ 点全部完整检测（零检出回归）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ScanValidityGuard,
  evaluateStatus,
  isBlockedResponse,
  isLoginRedirect,
  looksLikeInjection,
  parseRetryAfterMs,
  VALIDITY_DEFAULTS,
} from '../src/core/scanValidityGuard.js';
import { ScanManager } from '../src/engine/ScanManager.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads.js';

const INJ_URL = "http://t.test/item?id=1%27%20AND%20%271%27=%271";

function obs(g, n, make) {
  for (let i = 0; i < n; i++) g.observe(make(i));
}

test('连续失败 10 次 → shouldAbort + unreachable；成功后状态仍粘滞', () => {
  const g = new ScanValidityGuard();
  obs(g, 9, () => ({ req: { url: INJ_URL }, res: null }));
  assert.equal(g.shouldAbort, false, '9 次未达阈不得中止（保守）');
  assert.equal(g.summary().status, 'ok');
  g.observe({ req: { url: INJ_URL }, res: null });
  assert.equal(g.shouldAbort, true);
  assert.equal(g.summary().status, 'unreachable');
  assert.equal(g.summary().reliable, false);
  assert.match(g.summary().reason, /连续 10 次/);
  // 目标后来恢复：结论不可信必须留在报告里（否则中途挂掉会被尾部成功样本洗白）
  obs(g, 20, () => ({ req: { url: INJ_URL }, res: { status: 200, data: 'ok', headers: {} } }));
  assert.equal(g.summary().status, 'unreachable');
  assert.equal(g.summary().reliable, false);
});

test('抛错（error）同样计为失败；AbortError（用户 stop）不计入', () => {
  const g = new ScanValidityGuard();
  obs(g, 10, () => ({ req: { url: INJ_URL }, res: null, error: new Error('ECONNRESET') }));
  assert.equal(g.summary().status, 'unreachable');
  const g2 = new ScanValidityGuard();
  for (let i = 0; i < 30; i++) {
    const e = new Error('canceled');
    e.name = 'AbortError';
    g2.observe({ req: { url: INJ_URL }, res: null, error: e });
  }
  assert.equal(g2.total, 0, '取消请求不得计入目标失败样本');
  assert.equal(g2.summary().status, 'ok');
});

test('200/403 混合但拦截占比不足阈值 → ok（不误判）', () => {
  const g = new ScanValidityGuard();
  for (let i = 0; i < 10; i++) {
    g.observe({ req: { url: INJ_URL }, res: { status: 403, data: 'Forbidden', headers: {} } });
    g.observe({ req: { url: INJ_URL }, res: { status: 200, data: 'page', headers: {} } });
  }
  const s = g.summary();
  assert.equal(s.status, 'ok', `blockRatio=0.5 未过 0.6 阈值应判 ok，实际 ${JSON.stringify(s)}`);
  assert.equal(s.reliable, true);
  assert.equal(s.blockRatio, 0.5);
  assert.equal(s.counts.blockHits, 10);
});

test('高比例 403 → blocked（不 abort）+ suggestBackoffMs 取自 Retry-After', () => {
  const g = new ScanValidityGuard();
  obs(g, 25, () => ({
    req: { url: INJ_URL },
    res: { status: 403, data: '<html>Request blocked by WAF</html>', headers: { 'retry-after': '90' } },
  }));
  obs(g, 5, () => ({ req: { url: INJ_URL }, res: { status: 200, data: 'ok', headers: {} } }));
  const s = g.summary();
  assert.equal(s.status, 'blocked');
  assert.equal(s.reliable, false);
  assert.equal(s.suggestBackoffMs, 90000);
  assert.equal(g.shouldAbort, false, '被封只标注不中止（使用者可能想换 IP/加白后再看）');
  assert.match(s.advice, /白名单|降速/);
});

test('Retry-After 支持秒数与 HTTP-date 两种形式', () => {
  assert.equal(parseRetryAfterMs('120'), 120000);
  assert.equal(parseRetryAfterMs(45), 45000);
  assert.equal(parseRetryAfterMs(null), null);
  assert.equal(parseRetryAfterMs(''), null);
  assert.equal(parseRetryAfterMs('garbage'), null);
  const now = Date.UTC(2026, 8, 8, 12, 0, 0);
  assert.equal(parseRetryAfterMs(new Date(now + 30_000).toUTCString(), now), 30_000);
});

test('429 限速封禁 + Retry-After 头 → blocked 且退避建议取头值', () => {
  const g = new ScanValidityGuard();
  obs(g, 20, () => ({
    req: { url: INJ_URL },
    res: { status: 429, data: 'too many requests', headers: { 'Retry-After': '120' } },
  }));
  assert.equal(g.summary().status, 'blocked');
  assert.equal(g.summary().suggestBackoffMs, 120000);
});

test('注入请求连续 401 → session_expired；302 跳登录页同样命中', () => {
  const g = new ScanValidityGuard();
  g.observe({ req: { url: INJ_URL }, res: { status: 200, data: 'page', headers: {} } });
  obs(g, 3, () => ({ req: { url: INJ_URL }, res: { status: 401, data: 'Unauthorized', headers: {} } }));
  const s = g.summary();
  assert.equal(s.status, 'session_expired');
  assert.equal(s.counts.authLostHits, 3);
  assert.match(s.reason, /401/);

  const g2 = new ScanValidityGuard();
  obs(g2, 3, () => ({
    req: { url: INJ_URL },
    res: { status: 302, data: '', headers: { location: 'https://t.test/login?next=%2Fitem' } },
  }));
  assert.equal(g2.summary().status, 'session_expired');
  assert.equal(isLoginRedirect({ status: 302, headers: { location: '/cas/login' } }), true);
  assert.equal(isLoginRedirect({ status: 302, headers: { location: '/item/2' } }), false);
});

test('整站都 401（基线请求也 401）不判会话过期（那是缺凭据，不是会话失效）', () => {
  const g = new ScanValidityGuard();
  obs(g, 6, () => ({ req: { url: 'http://t.test/item?id=1' }, res: { status: 401, data: '', headers: {} } }));
  assert.equal(g.summary().status, 'ok');
  assert.equal(g.baselineAuthHits, 6);
});

test('拦截文案出现在 200 页面不得判 blocked（防误判回归）', () => {
  const g = new ScanValidityGuard();
  obs(g, 40, () => ({
    req: { url: 'http://t.test/help?id=1' },
    res: { status: 200, data: '<h1>安全狗防火墙已拦截恶意请求</h1><p>cf-ray challenge 安全验证</p>', headers: {} },
  }));
  const s = g.summary();
  assert.equal(s.counts.blockHits, 0);
  assert.equal(s.status, 'ok');
  assert.equal(s.reliable, true);
  // 同样的文案在 4xx 上才算拦截
  assert.equal(isBlockedResponse({ status: 200, data: 'blocked by waf' }), false);
  assert.equal(isBlockedResponse({ status: 404, data: 'Access Denied' }), true);
  assert.equal(isBlockedResponse({ status: 500, data: '普通 SQL 报错页面' }), false);
});

test('持续 5xx（样本充足）→ target_error；样本不足不判', () => {
  const g = new ScanValidityGuard();
  obs(g, 12, () => ({ req: { url: INJ_URL }, res: { status: 502, data: 'bad gateway', headers: {} } }));
  assert.equal(g.summary().status, 'target_error');
  assert.equal(g.shouldAbort, false);

  const g2 = new ScanValidityGuard();
  obs(g2, 6, () => ({ req: { url: INJ_URL }, res: { status: 502, data: 'bad gateway', headers: {} } }));
  assert.equal(g2.summary().status, 'ok', '样本 <10 不得下 target_error 结论');
});

test('evaluateStatus 阈值优先级：不可达 > 被封 > 会话 > 目标错误', () => {
  const base = { failStreak: 0, blockRatio: 0, blockHits: 0, serverErrRatio: 0, samples: 40, authLost: false, cfg: VALIDITY_DEFAULTS };
  assert.equal(evaluateStatus({ ...base, failStreak: 10, blockRatio: 1, blockHits: 40, authLost: true }), 'unreachable');
  assert.equal(evaluateStatus({ ...base, blockRatio: 0.9, blockHits: 20, authLost: true }), 'blocked');
  assert.equal(evaluateStatus({ ...base, blockRatio: 0.9, blockHits: 3 }), 'ok', 'blockHits 未过绝对下限 → 不判封禁');
  assert.equal(evaluateStatus({ ...base, authLost: true, serverErrRatio: 1 }), 'session_expired');
  assert.equal(evaluateStatus({ ...base, serverErrRatio: 0.9, samples: 3 }), 'ok');
});

test('summary 契约字段齐全（前端/报告按固定字段名消费）', () => {
  const g = new ScanValidityGuard();
  g.addInconclusive('p2');
  g.addInconclusive('p2');
  g.addInconclusive('p3');
  obs(g, 10, () => ({ req: { url: INJ_URL }, res: null }));
  const s = g.summary();
  assert.deepEqual(
    Object.keys(s).sort(),
    ['advice', 'blockRatio', 'counts', 'inconclusivePoints', 'reason', 'reliable', 'status', 'suggestBackoffMs'].sort()
  );
  // counts 契约（[P1-FIX 2026-09-08] 新增 injection5xx：注入请求引发的 5xx 计数问）：
  // 不参与状态裁定（那是 error 技术的正常产物），但必须可见——不能与「目标本身在报错」混为一谈。
  // [P0-FIX 2026-09-09] 新增 netErrPoints：网络层失败导致未测成的点数（该点阴性结论不成立）。
  assert.deepEqual(
    Object.keys(s.counts).sort(),
    ['authLostHits', 'blockHits', 'failStreak', 'injection5xx', 'netErrPoints', 'serverErr', 'total'].sort()
  );
  assert.ok(['ok', 'blocked', 'unreachable', 'session_expired', 'target_error'].includes(s.status));
  assert.equal(typeof s.reliable, 'boolean');
  assert.equal(typeof s.reason, 'string');
  assert.ok(s.reason.length > 0 && typeof s.advice === 'string' && s.advice.length > 0);
  assert.equal(typeof s.blockRatio, 'number');
  assert.ok(s.blockRatio >= 0 && s.blockRatio <= 1);
  assert.ok(s.suggestBackoffMs === null || typeof s.suggestBackoffMs === 'number');
  assert.deepEqual(s.inconclusivePoints, ['p2', 'p3'], '去重且保持记录顺序');
  assert.equal(s.counts.total, 10);
});

test('looksLikeInjection 区分基线请求与注入请求', () => {
  assert.equal(looksLikeInjection({ url: 'http://t.test/item?id=1' }), false);
  assert.equal(looksLikeInjection('http://t.test/item?id=1'), false);
  assert.equal(looksLikeInjection({ url: 'http://t.test/item?id=1%27' }), true);
  assert.equal(looksLikeInjection({ url: 'http://t.test/item?id=1', data: { v: "1' UNION SELECT NULL-- -" } }), true);
  assert.equal(looksLikeInjection(null), false);
});

// ── 流水线集成：ScanManager + scanRunner 接线 ────────────────────────────────
// 桩法参考 tests/phase3.prefilter.test.js：mock httpClient + 桩检测器（每技术发 4 个请求，
// 与真实检测器一样经 ctxBase.httpClient.request 出口，从而被守卫 observe 到）。
function makeManager(points, httpClient) {
  const detectCalls = [];
  const testedPoints = new Set();
  const sm = new ScanManager();
  sm.httpClient = httpClient;
  sm.detectors = TECHNIQUE_TYPES.map((t) => ({
    technique: t,
    async detect(ctx) {
      detectCalls.push(t);
      testedPoints.add(ctx.point.id);
      for (let i = 0; i < 4; i++) {
        // 与真实检测器一致：payload 走统一请求出口（失败时返回 null，不抛错）
        await ctx.httpClient.request({ url: `${ctx.target.url}${i}${encodeURIComponent("' or '1'='1")}` });
      }
      return { pointId: ctx.point.id, technique: t, vulnerable: false, dbms: null, evidence: '', payloads: [] };
    },
  }));
  sm.fp = { async fingerprint() { return { dbms: null, baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return points; } };
  sm._detectCalls = detectCalls;
  sm._testedPoints = testedPoints;
  return sm;
}

async function runScan(sm, config) {
  const id = await sm.start({
    url: 'http://mock.test/?v=1',
    config: { concurrency: 1, ratePerSec: 200, prefilter: false, ...config },
  });
  for (let i = 0; i < 400; i++) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error' || s.status === 'stopped')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  return id;
}

test('集成：httpClient 全程返回 null → 报告 verdict=inconclusive 且 inconclusivePoints 非空', async () => {
  const points = [
    { id: 'p1', location: 'url', param: 'v', originalValue: '1' },
    { id: 'p2', location: 'url', param: 'v', originalValue: '2' },
    { id: 'p3', location: 'url', param: 'v', originalValue: '3' },
  ];
  let requests = 0;
  const deadMock = {
    async request() {
      requests++;
      return null; // 缺陷根因：网络错误被吞成 null → 调用方视为「200 空页」
    },
  };
  const sm = makeManager(points, deadMock);
  const id = await runScan(sm);
  const report = sm.getReport(id);
  const v = report.validity;
  assert.ok(v, 'report.validity 必须落盘');
  assert.equal(v.status, 'unreachable');
  assert.equal(v.reliable, false);
  assert.equal(report.summary.validity.status, 'unreachable');
  assert.equal(report.vulns.length, 0);
  assert.equal(report.summary.verdict, 'inconclusive', '0 漏洞 + 不可信 → 必须显式表达「未检出 ≠ 无漏洞」');
  assert.match(report.summary.verdictNote, /未检出漏洞 ≠ 无漏洞/);
  assert.ok(v.inconclusivePoints.length >= 1, `应记录未完成检测点，实际 ${JSON.stringify(v.inconclusivePoints)}`);
  assert.ok(!v.inconclusivePoints.includes('p1'), '熔断前已跑完的点不算未决');
  assert.ok(requests >= 10, `应确实发过请求后被熔断，实际 ${requests}`);
  // 熔断后剩余点不再投放 payload（省掉注定无效的整轮请求）
  assert.ok(sm._testedPoints.size < points.length, '目标已不可达，后续点应被熔断跳过');
});

test('集成：健康目标（全 200）→ 零行为变化，verdict=no_vulnerability_detected', async () => {
  const points = [
    { id: 'p1', location: 'url', param: 'v', originalValue: '1' },
    { id: 'p2', location: 'url', param: 'v', originalValue: '2' },
  ];
  let requests = 0;
  const healthyMock = {
    async request() {
      requests++;
      return { status: 200, data: 'stable page content', headers: {} };
    },
  };
  const sm = makeManager(points, healthyMock);
  const id = await runScan(sm);
  const report = sm.getReport(id);
  const v = report.validity;
  assert.equal(v.status, 'ok');
  assert.equal(v.reliable, true);
  assert.deepEqual(v.inconclusivePoints, []);
  assert.equal(report.summary.verdict, 'no_vulnerability_detected');
  // 守卫未跳过任何点、未减少任何请求：每个点都完整走完检测器调度（每技术 4 请求）
  assert.equal(requests, sm._detectCalls.length * 4, '守卫不得改变正常目标的请求数');
  assert.equal(sm._testedPoints.size, points.length, '健康目标每个点都应进入完整检测');
});
