// Oracle 时间盲注测试：验证 DBMS_PIPE.RECEIVE_MESSAGE / DBMS_LOCK.SLEEP 真实延迟可触发命中
// （v6 前 Oracle time 模板为占位 1=1，SUPPORTED.time=false，时间盲注对 Oracle 不可用）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';
import { defaults } from '../src/config/defaults.js';

// 模拟 Oracle：请求含延迟函数时挂起 sleepMs，基线（无延迟函数）瞬时返回
function makeOracleSleepMock(sleepMs) {
  return {
    async request(opts) {
      const q = typeof opts.url === 'string' ? opts.url : '';
      if (/RECEIVE_MESSAGE|DBMS_LOCK/.test(q)) {
        await new Promise((r) => setTimeout(r, sleepMs));
      }
      return { data: 'oracle page', status: 200, headers: {} };
    },
  };
}

function buildCtx(httpClient, dbms = 'Oracle') {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms,
    config: { timeoutMs: 10000, retry: 0, blindRobust: { ...defaults.blindRobust } },
  };
}

test('Oracle 时间盲注：DBMS_PIPE.RECEIVE_MESSAGE 延迟触发命中', async () => {
  const d = new TimeBlindDetector();
  const ctx = buildCtx(makeOracleSleepMock(2000), 'Oracle');
  const r = await d.detect(ctx);
  assert.equal(r.vulnerable, true);
  assert.equal(r.dbms, 'Oracle');
});

test('Oracle 时间盲注：无延迟（非 Oracle 目标）不误报', async () => {
  const d = new TimeBlindDetector();
  // 不延迟的 Oracle mock → 不应命中
  const ctx = buildCtx(
    {
      async request() {
        return { data: 'page', status: 200, headers: {} };
      },
    },
    'Oracle'
  );
  const r = await d.detect(ctx);
  assert.equal(r.vulnerable, false);
});
