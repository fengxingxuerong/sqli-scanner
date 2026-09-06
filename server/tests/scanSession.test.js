// P1 会话持久化 + 断点续拉回归（对标 sqlmap --session/--resume）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { ScanSession } from '../src/core/sessionStore.js';
import { ScanManager } from '../src/engine/ScanManager.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads.js';

// 每个测试独立临时路径：node:test 同文件子测试默认并发，共享路径会互相删文件导致竞态
function freshTmp() {
  return path.join(os.tmpdir(), `sqli-sess-${Date.now()}-${Math.floor(Math.random() * 1e6)}.json`);
}
function rmTmp(p) { try { fs.unlinkSync(p); } catch {} }

// 构造桩 ScanManager：检测器按 plan 命中，discover 返回固定点
function makeManager(plan, points = [{ id: 'p1', location: 'url', param: 'v', originalValue: '1' }]) {
  const sm = new ScanManager();
  sm.detectors = TECHNIQUE_TYPES.map((t) => ({
    technique: t,
    async detect(ctx) {
      const hit = !!(plan[t] && plan[t].vulnerable);
      return { pointId: ctx.point.id, technique: t, vulnerable: hit, dbms: hit ? 'MySQL' : null, evidence: hit ? `m ${t}` : '', payloads: hit ? [`p_${t}`] : [] };
    },
  }));
  sm.fp = { async fingerprint() { return { dbms: 'MySQL', baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return points; } };
  return sm;
}

async function waitDone(sm, scanId) {
  for (let i = 0; i < 300; i++) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
}

test('ScanSession: setPoints 初始化 pending，savePointResult 标记 done 并落盘', { concurrency: false }, async () => {
  const p = freshTmp();
  const s = new ScanSession('s1', { url: 'http://x/', config: {} }, p);
  await s.setPoints([{ id: 'p1' }, { id: 'p2' }]);
  assert.equal(s.pendingPointIds().length, 2);
  await s.savePointResult('p1', { found: [{ technique: 'union', result: { dbms: 'MySQL' } }] });
  assert.equal(s.perPoint.p1.status, 'done');
  assert.equal(s.pendingPointIds().length, 1);
  // 落盘校验
  const reloaded = JSON.parse(fs.readFileSync(p, 'utf-8'));
  assert.equal(reloaded.perPoint.p1.status, 'done');
  assert.equal(reloaded.vulns.length, 1);
  rmTmp(p);
});

test('ScanSession.load: 损坏文件 → 返回 null（容错）', { concurrency: false }, async () => {
  const p = freshTmp();
  fs.writeFileSync(p, 'not json{{{');
  const s = await ScanSession.load(p);
  assert.equal(s, null);
  rmTmp(p);
});

test('resume 模式：已完成点跳过、历史漏洞并入报告', { concurrency: false }, async () => {
  const p = freshTmp();
  // 第一轮：p1 命中 union，落盘
  const m1 = makeManager({ union: { vulnerable: true } });
  const id1 = await m1.start({ url: 'http://x/?id=1', config: { concurrency: 1, ratePerSec: 100, sessionFile: p } });
  await waitDone(m1, id1);
  assert.ok(fs.existsSync(p), 'session 文件应已落盘');

  // 第二轮：resume 同一 sessionFile，p1 应被跳过（不重测），且历史 union 命中并入报告
  const m2 = makeManager({ union: { vulnerable: false } }); // 这次即使检测全失败，resume 也应保留历史
  const id2 = await m2.start({ url: 'http://x/?id=1', config: { concurrency: 1, ratePerSec: 100, sessionFile: p } });
  await waitDone(m2, id2);
  const report = m2.getReport(id2);
  const unionVuln = report.vulns.find((v) => v.technique === 'union');
  assert.ok(unionVuln, 'resume 应并入历史 union 命中');
  assert.match(unionVuln.description, /\[resume\]/, '历史命中应有 resume 标注');
  rmTmp(p);
});

test('无 sessionFile 配置 → 不落盘、不 resume（向后兼容）', { concurrency: false }, async () => {
  const noSessionTmp = path.join(os.tmpdir(), `sqli-sess-nosess-${Date.now()}-${Math.floor(Math.random() * 1e6)}.json`);
  const m = makeManager({ error: { vulnerable: true } });
  const id = await m.start({ url: 'http://x/?id=1', config: { concurrency: 1, ratePerSec: 100 } });
  await waitDone(m, id);
  const report = m.getReport(id);
  assert.ok(report.vulns.find((v) => v.technique === 'error'));
  assert.ok(!fs.existsSync(noSessionTmp), '无 sessionFile 时不应落盘');
});
