// OobDetector 单元测试：模拟目标带外回连验证 vulnerable=true；未启动抛 OOB_DISABLED
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OobDetector } from '../src/engine/detectors/OobDetector.js';
import { oobReceiver } from '../src/core/oobReceiver.js';
import { ErrorCode } from '../src/core/errors.js';

const PORT = 19010;
const CALLBACK_BASE = `127.0.0.1:${PORT}`;
const OOB_CFG = { enabled: true, callbackBase: CALLBACK_BASE, httpPort: PORT, timeoutMs: 2000 };

// 模拟目标：从请求中提取 oob token 并"回连"接收端（真实环境由 DBMS 执行）
// 注意：注入值经 URL 编码后 '/' 会变成 '%2F'，正则需兼容两种写法。
function makeMockWithCallback() {
  return {
    async request(opts) {
      const text = JSON.stringify(opts);
      const m = text.match(/oob(?:%2[fF]|\/)([A-Za-z0-9_-]+)/i);
      if (m) oobReceiver.receive(m[1]); // 目标 DBMS 执行带外回连
      return { data: '', status: 200 };
    },
  };
}

// 不发回连的 mock（模拟目标未触发带外）
function makeSilentMock() {
  return { async request() { return { data: '', status: 200 }; } };
}

function makeCtx(httpClient, dbms = 'MySQL') {
  const config = { timeoutMs: 5000, oob: OOB_CFG };
  const target = {
    method: 'GET',
    baseUrl: 'http://mock/?q=1',
    headerParams: {},
    cookieParams: {},
    config,
  };
  const point = { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false, dbms: null };
  return { httpClient, target, point, dbms, config };
}

test('模拟回连 → vulnerable=true 且标记注入点', async () => {
  await oobReceiver.start(OOB_CFG);
  const d = new OobDetector();
  const ctx = makeCtx(makeMockWithCallback(), 'MySQL');
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'oob');
  assert.equal(res.dbms, 'MySQL');
  assert.ok(res.evidence.includes('OOB'));
  assert.ok(Array.isArray(res.payloads) && res.payloads.length > 0);
  // 与现有检测器一致：同步标记注入点
  assert.equal(ctx.point.confirmed, true);
  assert.equal(ctx.point.technique, 'oob');
  await oobReceiver.stop();
});

test('接收端未启动 → 抛 OOB_DISABLED', async () => {
  await oobReceiver.stop(); // 确保未启动
  const d = new OobDetector();
  const ctx = makeCtx(makeSilentMock(), 'MySQL');
  await assert.rejects(
    () => d.detect(ctx),
    (e) => e instanceof Error && e.code === ErrorCode.OOB_DISABLED
  );
});

test('已启动但目标未回连 → vulnerable=false', async () => {
  await oobReceiver.start({ ...OOB_CFG, timeoutMs: 150 });
  const d = new OobDetector();
  const ctx = makeCtx(makeSilentMock(), 'MySQL');
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, false);
  assert.equal(ctx.point.confirmed, false);
  await oobReceiver.stop();
});

test('未知 dbms 时遍历支持库仍可被回连确认', async () => {
  await oobReceiver.start(OOB_CFG);
  const d = new OobDetector();
  const ctx = makeCtx(makeMockWithCallback(), null); // dbms 未知
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'oob');
  await oobReceiver.stop();
});
