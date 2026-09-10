// P2-P4 会话默认落盘（sessionDefault）测试（node --test）
// 验证：1) sessionDefault:true 自动按目标 URL 哈希落盘（sqli-session-<hash8>.json）；
//       2) 同 URL 二次扫描自动 resume（跳过已完成点，复扫 0 检测请求）且历史命中并入报告；
//       3) 不同 URL 不续跑旧会话（新会话覆盖不同哈希文件）。
// 注意：文件落在进程 CWD（server/），测试内清理，且全部串行避免竞态。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import crypto from 'node:crypto';
import { ScanManager } from '../src/engine/ScanManager.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads.js';

function urlHash(url) {
  return crypto.createHash('md5').update(String(url)).digest('hex').slice(0, 8);
}

function sessionFile(url) {
  return `sqli-session-${urlHash(url)}.json`;
}

function sessionPath(url) {
  return path.join(process.cwd(), sessionFile(url));
}

// 环境对 fs.rmSync 有 safe-delete 拦截，统一用 unlinkSync 且忽略错误（清理非断言目标）。
// Windows 上异步写盘结束后文件句柄可能未立即释放，unlinkSync 会 EPERM 失败；
// 重试 10 次（共 ~100ms）等句柄释放，避免「删除失败 → 下一用例断言文件存在」的偶发竞态
// （曾导致本文件全量跑必挂、单跑通过：删除的是上一用例异步写盘的残留）。
function rmQuiet(p) {
  for (let i = 0; i < 10; i++) {
    try {
      fs.unlinkSync(p);
      return;
    } catch {
      /* 句柄未释放，稍候重试 */
    }
    const buf = new SharedArrayBuffer(4);
    Atomics.wait(new Int32Array(buf), 0, 0, 10);
  }
}

function makeManager(plan) {
  const detectCalls = [];
  const sm = new ScanManager();
  // [P0-FIX 2026-09-08] 注入可用 httpClient 桩：本文件原靠「真发 http://x/ 必失败」跑扫描，
  // 而新的结论可信度守卫（scanValidityGuard）会在「目标连续无有效响应」时熔断剩余注入点，
  // 被跳过的点**故意不写 session**（写 done 会让 resume 把「根本没测」永久当成「测过且无洞」）。
  // 本用例考的是会话落盘与 resume，不是死目标行为，因此把 HTTP 补成可用（真实扫描里目标本就可达）。
  sm.httpClient = { async request() { return { status: 200, data: '<html>ok</html>', headers: {} }; } };
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
  sm.fp = { async fingerprint() { return { dbms: 'MySQL', baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return [{ id: 'p1', location: 'url', param: 'v', originalValue: '1' }]; } };
  sm._detectCalls = detectCalls;
  return sm;
}

async function runScan(sm, url, config) {
  const id = await sm.start({ url, config: { concurrency: 1, ratePerSec: 100, ...config } });
  for (let i = 0; i < 300; i++) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  return id;
}

// [FLAKY-FIX 2026-09-10] 三个 URL 曾共用固定值，而会话文件名按 URL 哈希派生、
// 落在进程 CWD，于是用例之间（以及上一次全量运行的残留文件）通过文件系统隐式耦合：
//   - 用例1 落盘 URL_A 会话 → 用例3 断言「URL_A 不应落盘」时可能撞上用例1 的异步写盘残留 → 挂；
//   - 用例2 判定「URL_C 应完整检测」时，若 CWD 存在上次运行残留的 URL_C 会话文件 → 走 resume
//     → 检测器零调用 → 断言失败（全量跑偶发，单跑通过）。
// 修法：URL 带运行内随机 token，保证文件名跨运行、跨用例都唯一；用例3 另用独立 URL_D。
const RND = Math.random().toString(36).slice(2, 10);
const URL_A = `http://x/${RND}-a/?id=1`;
const URL_B = `http://x/${RND}-b/?a=1`;
const URL_C = `http://x/${RND}-c/?b=2`;
const URL_D = `http://x/${RND}-d/?c=3`; // 用例3 专用，避免与用例1 共享会话文件

test('sessionDefault：自动落盘按 URL 哈希文件名 + 同 URL resume 复扫 0 检测请求', { concurrency: false }, async () => {
  const sp = sessionPath(URL_A);
  try {
    rmQuiet(sp);
    // 第一轮：union 命中并落盘
    const m1 = makeManager({ union: { vulnerable: true } });
    await runScan(m1, URL_A, { sessionDefault: true });
    assert.ok(fs.existsSync(sp), `sessionDefault 应自动落盘 ${sessionFile(URL_A)}`);
    const snap = JSON.parse(fs.readFileSync(sp, 'utf-8'));
    assert.equal(snap.url, URL_A, '会话应记录目标 URL');
    assert.equal(snap.perPoint.p1.status, 'done');

    // 第二轮：同 URL → resume，p1 已完成被跳过 → 检测器零调用，历史命中并入报告
    const m2 = makeManager({ union: { vulnerable: false } });
    const id2 = await runScan(m2, URL_A, { sessionDefault: true });
    const report = m2.getReport(id2);
    assert.equal(m2._detectCalls.length, 0, 'resume 应跳过已完成点，复扫 0 检测请求');
    const unionVuln = report.vulns.find((v) => v.technique === 'union');
    assert.ok(unionVuln, 'resume 应并入历史 union 命中');
    assert.match(unionVuln.description, /\[resume\]/);
  } finally {
    rmQuiet(sp);
  }
});

test('sessionDefault：不同 URL 各自独立文件不互踩', { concurrency: false }, async () => {
  const spA = sessionPath(URL_B);
  const spC = sessionPath(URL_C);
  try {
    rmQuiet(spA);
    rmQuiet(spC);
    // 对 URL B 扫描落盘
    const m1 = makeManager({ error: { vulnerable: true } });
    await runScan(m1, URL_B, { sessionDefault: true });
    assert.ok(fs.existsSync(spA), `URL B 应落盘 ${sessionFile(URL_B)}`);

    // 不同 URL C 扫描 → 不同文件，不续跑旧会话，完整检测
    const m2 = makeManager({ error: { vulnerable: true } });
    const id2 = await runScan(m2, URL_C, { sessionDefault: true });
    const report = m2.getReport(id2);
    assert.ok(m2._detectCalls.includes('error'), '不同 URL 应完整检测（不续跑旧会话）');
    assert.ok(report.vulns.find((v) => v.technique === 'error'), '新扫描应产出自己的命中');
    // URL C 的文件应存在且与 URL B 不同
    assert.ok(fs.existsSync(spC), `URL C 应落盘独立文件 ${sessionFile(URL_C)}`);
  } finally {
    rmQuiet(spA);
    rmQuiet(spC);
  }
});

test('sessionDefault 缺省（false）：不自动落盘（与旧行为一致）', { concurrency: false }, async () => {
  const sp = sessionPath(URL_D);
  try {
    rmQuiet(sp);
    const m = makeManager({ error: { vulnerable: true } });
    await runScan(m, URL_D, {});
    assert.ok(!fs.existsSync(sp), '未开启 sessionDefault 不应落盘会话文件');
  } finally {
    rmQuiet(sp);
  }
});