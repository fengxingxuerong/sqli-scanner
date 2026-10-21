// ============================================================================
// server/tests/unverifiedSurfaces.scan.test.js —— [D123 2026-10-21] 端到端回归
//
// 单元测试（unverifiedSurfaces.test.js）钉的是「算得对」，本文件钉的是**「真的进了报告」**：
// 该仓最贵的一类教训就是「字段算出来了、但没人读/没落盘」——`summary.byRisk` 曾经恒为 null、
// 推荐 tamper 链曾经只走 SSE 不落盘、`noInjectionPoints` 标记曾经只活在 summary 里没人消费。
//
// 场景构造（真实 ScanManager + 本地靶场）：
//   · 目标对 **Cookie 面**的请求一律返回 403 + 拦截页文案（模拟 WAF 只拦 cookie 注入面）；
//   · URL query 面正常（且真的有注入）。
// 期望：扫描 completed（整体没到 blocked 阈值），但报告必须列出 cookie 面「未测成」，
// 且 verdictNote 里出现该提示 —— 而不是只写「检出 1 条漏洞」了事。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { ScanManager } from '../src/engine/ScanManager.js';

process.env.SSRF_ALLOW_PRIVATE = '1';

/**
 * 靶场：`?id=` 是**真**注入（布尔可分）；Cookie 里带引号/注释即判拦截（403 + 拦截页）。
 * 这样：query 面能检出（有证据），cookie 面被拦（未测成）——两个面结论必须分开。
 */
function startLab() {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    const cookie = req.headers.cookie || '';
    // WAF 模拟：cookie 面出现任何注入特征 ⇒ 拦截。
    // ⚠ 必须 try/catch：payload 里含裸 `%`/非法转义时 decodeURIComponent 会抛 URIError，
    // 抛在请求处理函数里 = 服务器直接 500/断开，场景会退化成「网络失败」而非「被拦」。
    let ck = cookie;
    try { ck = decodeURIComponent(cookie); } catch { ck = cookie; }
    if (/['"()#-]|\b(and|or|union|select)\b/i.test(ck)) {
      res.writeHead(403, { 'content-type': 'text/html' });
      res.end('<html><body>Request blocked by Web Application Firewall</body></html>');
      return;
    }
    const id = u.searchParams.get('id') || '1';
    const safe = id.replace(/\s+/g, '');
    // 布尔判据：含 1=2 ⇒ 空行集；含 1=1 ⇒ 有行；否则基线一行
    const rows = safe.includes('1=2') ? [] : safe.includes('1=1') ? ['admin'] : ['admin'];
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(rows.length ? `Hello ${rows[0]}` : 'No results');
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function waitDone(sm, id, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) return s;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('scan timeout');
}

test('D123-⑧: 部分注入面被拦时，报告显式列出「未验证面」而不是只报未检出', async () => {
  const lab = await startLab();
  try {
    const { port } = lab.address();
    const sm = new ScanManager();
    const id = await sm.start({
      url: `http://127.0.0.1:${port}/item?id=1`,
      cookieParams: { session: 'abc123' },
      config: {
        techniques: ['boolean'],
        level: 2, // level≥2 ⇒ 生成 cookie 点
        risk: 1,
        concurrency: 1,
        ratePerSec: 400,
        prefilter: false,
        skipStatic: false,
        smart: false,
        testHeaders: true,
      },
    });
    const state = await waitDone(sm, id);
    assert.notEqual(state.status, 'error', state.error || 'scan errored');
    const report = sm.getReport(id);
    const summary = report.summary || {};

    // ① 报告必须出现未验证面字段（不是「只在 wiki 里说过」）
    assert.ok(
      summary.unverifiedSurfaces || summary.unverifiedSentence,
      `报告应含未验证面信息，实际 summary keys=${Object.keys(summary).join(',')}；` +
        `verdict=${summary.verdict} verdictNote=${summary.verdictNote}`
    );
    // ② 若有未验证面，结论文案必须点明「没测成 ≠ 无漏洞」
    if (summary.unverifiedSentence) {
      assert.match(summary.unverifiedSentence, /未能完成有效检测|不等于「无漏洞」/);
      // ③ 该句必须真的进 verdictNote（消费方是 verdictNote，不是这个孤立字段）
      assert.ok(
        String(summary.verdictNote || '').includes(summary.unverifiedSentence),
        `verdictNote 应引用未验证面结论，实际="${summary.verdictNote}"`
      );
    }
  } finally {
    lab.close();
  }
});

test('D123-⑨: 全部注入面都测完时，不出现「未验证面」噪声段', async () => {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    const id = (u.searchParams.get('id') || '1').replace(/\s+/g, '');
    const rows = id.includes('1=2') ? [] : ['admin'];
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(rows.length ? 'Hello admin' : 'No results');
  });
  const lab = await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
  try {
    const { port } = lab.address();
    const sm = new ScanManager();
    const id = await sm.start({
      url: `http://127.0.0.1:${port}/item?id=1`,
      config: {
        techniques: ['boolean'],
        level: 1,
        risk: 1,
        concurrency: 1,
        ratePerSec: 400,
        prefilter: false,
        skipStatic: false,
        smart: false,
      },
    });
    const state = await waitDone(sm, id);
    assert.notEqual(state.status, 'error', state.error || 'scan errored');
    const summary = sm.getReport(id).summary || {};
    // level=1 单一点、目标健康 ⇒ 不应刷出「未验证面」
    assert.equal(
      summary.unverifiedSentence,
      undefined,
      `健康扫描不该有未验证面提示，实际="${summary.unverifiedSentence}"`
    );
  } finally {
    lab.close();
  }
});
