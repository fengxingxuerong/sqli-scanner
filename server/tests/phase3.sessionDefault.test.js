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

const URL_A = 'http://x/?id=1';
const URL_B = 'http://x/?a=1';
const URL_C = 'http://x/?b=2';

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
  const sp = sessionPath(URL_A);
  try {
    rmQuiet(sp);
    const m = makeManager({ error: { vulnerable: true } });
    await runScan(m, URL_A, {});
    assert.ok(!fs.existsSync(sp), '未开启 sessionDefault 不应落盘会话文件');
  } finally {
    rmQuiet(sp);
  }
});