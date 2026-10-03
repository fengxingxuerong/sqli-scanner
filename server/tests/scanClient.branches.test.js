// ============================================================================
// tests/scanClient.branches.test.js —— scan/scanClient.js 的包装链分支直测
// ----------------------------------------------------------------------------
// 背景：五期拆分后 test:coverage:core 里 scanClient.js 分支仅 38.10%，未覆盖的恰是
// getScanClient 的四段包装分支（safeUrl / csrfUrl / egressPatch 的 request+headRequest
// 双路注入）与 _maybeClose 的异常兜底。本套件用假 self（capturing 基座客户端）逐分支
// 观测「opts 是否真的被注入」，不触网。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getConnector, _maybeClose, getScanClient } from '../src/engine/scan/scanClient.js';
import { DirectConnector } from '../src/core/directConnector.js';

/** 构造假 self：httpClient 为捕获型基座，forScan 返回携带 scanId/rate 的视图 */
function makeSelf() {
  const captured = { requests: [], heads: [], forScanCalls: [] };
  const request = async (opts) => {
    captured.requests.push(opts);
    return { status: 200, data: 'ok' };
  };
  const headRequest = async (url, opts) => {
    captured.heads.push({ url, opts });
    return { status: 200, headers: {}, data: '' };
  };
  const base = {
    request,
    headRequest,
    forScan(scanId, ratePerSec) {
      captured.forScanCalls.push({ scanId, ratePerSec });
      return { scanId, ratePerSec, request, headRequest };
    },
  };
  // [F1 2026-10-03] 暂停闸已下沉到 getScanClient 视图（request/headRequest 都过闸），
  //   fake 的 this 必须显式建模该契约 —— 缺 _waitWhilePaused 时视图构造当场抛错，而非静默放行。
  const self = { httpClient: base, _scanClients: new Map(), _waitWhilePaused: async () => {} };
  self.getConnector = (target) => getConnector.call(self, target);
  return { self, captured };
}

test('getConnector：direct 目标返回 DirectConnector，http 目标返回 httpClient 单例', () => {
  const { self } = makeSelf();
  const direct = getConnector.call(self, { mode: 'direct', config: {} });
  assert.ok(direct instanceof DirectConnector, 'direct 模式应返回 DirectConnector');
  assert.equal(getConnector.call(self, { mode: 'http', config: {} }), self.httpClient);
  assert.equal(getConnector.call(self, null), self.httpClient, '无目标回落 httpClient');
});

test('_maybeClose：非单例且持有 close 才调用；close 抛错被吞掉；单例不关', async () => {
  const { self } = makeSelf();
  let closed = 0;
  await _maybeClose.call(self, { close: () => { closed += 1; } });
  assert.equal(closed, 1, '非单例连接器应被关闭');
  await _maybeClose.call(self, self.httpClient);
  assert.equal(closed, 1, 'httpClient 单例不关（防全局连接被误杀）');
  await _maybeClose.call(self, {});
  await _maybeClose.call(self, null);
  assert.equal(closed, 1, '无 close / null 连接器为 no-op');
  await _maybeClose.call(self, { close: () => { throw new Error('close 炸了'); } });
  assert.equal(closed, 1, 'close 抛错必须被吞掉（回收失败不得打断扫描收尾）');
});

test('getScanClient：无协议/出口配置时零包装（proto=null 分支，view 原样）', async () => {
  const { self, captured } = makeSelf();
  const view = getScanClient.call(self, 's1', { config: {} });
  assert.equal(view.scanId, 's1');
  assert.equal(captured.forScanCalls[0].ratePerSec, undefined);
  await view.request({ url: 'http://t/?id=1' });
  assert.deepEqual(captured.requests[0], { url: 'http://t/?id=1' }, '零配置不得注入任何字段');
});

test('getScanClient：reqRate>0 覆盖 ratePerSec；否则透传 ratePerSec', () => {
  const { self, captured } = makeSelf();
  getScanClient.call(self, 's1', { config: { reqRate: 7, ratePerSec: 3 } });
  getScanClient.call(self, 's2', { config: { ratePerSec: 3 } });
  getScanClient.call(self, 's3', { config: { reqRate: 0, ratePerSec: 3 } });
  assert.equal(captured.forScanCalls[0].ratePerSec, 7, 'reqRate>0 覆盖');
  assert.equal(captured.forScanCalls[1].ratePerSec, 3);
  assert.equal(captured.forScanCalls[2].ratePerSec, 3, 'reqRate=0 回落 ratePerSec');
});

test('getScanClient：safeUrl 包装分支生效（view 被换出，且 per-scan 缓存复用同一视图）', () => {
  const { self } = makeSelf();
  const target = { config: { safeUrl: 'http://127.0.0.1:1/keepalive', safeFreq: 5 } };
  const v1 = getScanClient.call(self, 's1', target);
  assert.notEqual(v1.scanId, 's1', 'withSafeUrl 包装后的视图不再是 forScan 裸视图');
  const v2 = getScanClient.call(self, 's1', target);
  assert.equal(v1, v2, '同 scanId 命中缓存');
});

test('getScanClient：csrfUrl 包装分支生效（挂在 safeUrl 之上）', () => {
  const { self } = makeSelf();
  const view = getScanClient.call(self, 's1', { config: { csrfUrl: 'http://127.0.0.1:1/token' } });
  assert.notEqual(view.scanId, 's1', 'withCsrf 包装后的视图应被换出');
});

test('getScanClient：egressPatch 分支——request 与 headRequest 双路注入协议/出口语义', async () => {
  const { self, captured } = makeSelf();
  const target = {
    config: {
      forceSsl: true,
      ignoreRedirects: true,
      insecureTls: true,
      trustProxyEnv: false,
      ssrfViaProxy: 'off',
    },
  };
  const view = getScanClient.call(self, 's1', target);
  await view.request({ url: 'http://t/?id=1' });
  const req = captured.requests[0];
  assert.equal(req.forceSsl, true);
  assert.equal(req.ignoreRedirects, true);
  assert.equal(req.insecureTls, true, 'UI 勾的忽略自签证书必须真的到达 HttpClient');
  assert.equal(req.trustProxyEnv, false);
  assert.equal(req.ssrfViaProxy, 'off');
  // headRequest（--null-connection）走同一层包装：不经过 view.request
  await view.headRequest('http://t/?id=1', { extra: 1 });
  const head = captured.heads[0];
  assert.equal(head.opts.forceSsl, true);
  assert.equal(head.opts.insecureTls, true);
  assert.equal(head.opts.extra, 1, '透传调用方 opts 不被吃掉');
});

test('getScanClient：direct 目标原样返回（不经 forScan 包装），且不进缓存', () => {
  const { self, captured } = makeSelf();
  const connector = getScanClient.call(self, 's1', { mode: 'direct', config: {} });
  assert.ok(connector instanceof DirectConnector);
  assert.equal(captured.forScanCalls.length, 0, 'direct 不走 forScan');
  assert.equal(self._scanClients.has('s1'), false, 'direct 视图不入 per-scan 缓存');
});

test('getScanClient：缓存按 scanId 隔离（同 self 不同 scanId 各建各的桶）', () => {
  const { self } = makeSelf();
  const v1 = getScanClient.call(self, 's1', { config: { forceSsl: true } });
  const v2 = getScanClient.call(self, 's2', { config: {} });
  assert.notEqual(v1, v2);
  assert.equal(self._scanClients.size, 2);
});
