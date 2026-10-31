// ============================================================================
// sideEffectRoutes.test.js —— [D90 2026-10-18] 写副作用端点的门控与语义
//
// 补的是 P2-5（「写副作用无自动清理/回滚」，此前只有人工条款 R5/R6）。
// 本文件钉住两件事，都是安全相关、且最容易在后续重构中被"顺手放宽"的：
//
//   ① **GET 只读**：查看副作用不改目标 ⇒ 不需要 EXPLOIT 门（与 ledger show 同口径）。
//      它若被误加门，运维在关掉利用能力后就看不清残留了什么，反而更危险。
//   ② **POST 清理必须与写类端点同门控**：清理会对目标再发一次命令/写请求，
//      属利用动作 ⇒ 必须过 EXPLOIT_ENABLED + 授权声明 + scope 声明。
//      它若被漏加门，就成了「绕过门控的第二条写链路」——本仓最忌的形状。
//
// 环境搭建沿用 exploitRoutes.guards.test.js 的 cache-busting 动态 import
// （EXPLOIT_ENABLED 在模块加载时固化 ⟹ 必须先设 env 再 import）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorCode } from '../src/core/errors.js';
import { listenAppSafe } from './support/listenSafe.js';

let importSeq = 0;

async function loadApp(exploitEnabled) {
  if (exploitEnabled) process.env.EXPLOIT_ENABLED = '1';
  else delete process.env.EXPLOIT_ENABLED;
  process.env.AUTH_DECLARATION_STRICT = 'lenient';
  const { createApp } = await import(`../index.js?se=${++importSeq}`);
  return createApp;
}

async function withApp(exploitEnabled, fn) {
  const createApp = await loadApp(exploitEnabled);
  const app = createApp();
  const server = await listenAppSafe(app);
  try {
    await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const json = async (r) => {
  try { return await r.json(); } catch { return {}; }
};

test('GET /exploit/side-effects：只读取副作用，**不经 EXPLOIT 门**（关掉利用能力也能查残留）', async () => {
  await withApp(false, async (base) => {
    const r = await fetch(`${base}/api/exploit/side-effects?scanId=d90-readonly`);
    const j = await json(r);
    assert.notEqual(j.code, ErrorCode.EXPLOIT_UNAUTHORIZED,
      '只读端点不应要求 EXPLOIT_ENABLED —— 否则关掉利用能力就查不到残留了');
    assert.equal(j.code, 0, `应成功返回（实际 code=${j.code} ${j.message || ''}）`);
    assert.equal(j.data.scanId, 'd90-readonly');
    assert.deepEqual(j.data.effects, [], '无登记的扫描应返回空列表而非报错');
  });
});

test('GET /exploit/side-effects：缺 scanId 报 INVALID_PARAM（不静默返回全量）', async () => {
  await withApp(false, async (base) => {
    const r = await fetch(`${base}/api/exploit/side-effects`);
    const j = await json(r);
    assert.equal(j.code, ErrorCode.INVALID_PARAM, '缺 scanId 应判参数错误');
  });
});

test('POST /exploit/side-effects/cleanup：**关掉利用能力必须被拒**（不得成为绕过门控的写链路）', async () => {
  await withApp(false, async (base) => {
    const r = await fetch(`${base}/api/exploit/side-effects/cleanup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scanId: 'd90-cleanup',
        authorized: true,
        scope: ['127.0.0.1'],
        dbms: 'MySQL',
        target: { url: 'http://127.0.0.1:1/p.php?id=1' },
        point: { id: 'p1', location: 'url', param: 'id', originalValue: '1' },
      }),
    });
    const j = await json(r);
    assert.equal(j.code, ErrorCode.EXPLOIT_UNAUTHORIZED,
      `清理是写类动作，必须过 EXPLOIT 门（实际 code=${j.code}）`);
  });
});

test('POST /exploit/side-effects/cleanup：开了门但缺 scope 声明仍被拒（写类需显式声明）', async () => {
  await withApp(true, async (base) => {
    const r = await fetch(`${base}/api/exploit/side-effects/cleanup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scanId: 'd90-noscope',
        authorized: true,
        dbms: 'MySQL',
        target: { url: 'http://127.0.0.1:1/p.php?id=1' },
        point: { id: 'p1', location: 'url', param: 'id', originalValue: '1' },
      }),
    });
    const j = await json(r);
    assert.notEqual(j.code, 0, '缺 scope 声明不应放行（写类闸门）');
    assert.match(String(j.message || ''), /scope|声明|越界/i,
      `应给出与 scope 声明相关的拒绝理由（实际：${j.message}）`);
  });
});
