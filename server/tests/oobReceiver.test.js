// OOB 接收端单元测试：start 幂等 / receive→waitForToken / 超时 / 路由
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { oobReceiver } from '../src/core/oobReceiver.js';

// 封装一次 GET 请求，返回 { statusCode, body }
function httpGet(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ statusCode: res.statusCode, body }));
    });
    req.on('error', reject);
  });
}

test('start 幂等 + 引用计数：连续两次 start 同一端口共享一个服务，两次 stop 才真正关闭', async () => {
  const cfg = { callbackBase: '127.0.0.1:19001', httpPort: 19001, timeoutMs: 1000 };
  await oobReceiver.start(cfg);
  assert.equal(oobReceiver.isStarted(), true);
  assert.equal(oobReceiver.refCount(), 1);
  // 第二次 start 应为 no-op（不抛、不重复监听），但引用计数 +1
  await oobReceiver.start(cfg);
  assert.equal(oobReceiver.isStarted(), true);
  assert.equal(oobReceiver.refCount(), 2);
  // 第一次 stop：引用未归零，仍保持监听（并发扫描 A 结束不误杀 B）
  oobReceiver.stop();
  assert.equal(oobReceiver.isStarted(), true, '引用未归零不应关闭接收端');
  assert.equal(oobReceiver.refCount(), 1);
  // 第二次 stop：引用归零，真正关闭
  oobReceiver.stop();
  assert.equal(oobReceiver.isStarted(), false);
  assert.equal(oobReceiver.refCount(), 0);
});

test('receive 先于 waitForToken：直接命中返回 true', async () => {
  await oobReceiver.start({ callbackBase: '127.0.0.1:19002', httpPort: 19002, timeoutMs: 1000 });
  const token = 'tok_pre';
  oobReceiver.receive(token);
  const hit = await oobReceiver.waitForToken(token, 300);
  assert.equal(hit, true);
  oobReceiver.stop();
});

test('waitForToken 等待中 receive 唤醒：返回 true', async () => {
  await oobReceiver.start({ callbackBase: '127.0.0.1:19003', httpPort: 19003, timeoutMs: 2000 });
  const token = 'tok_wait';
  const p = oobReceiver.waitForToken(token, 2000);
  // 模拟目标 DBMS 回连
  oobReceiver.receive(token);
  assert.equal(await p, true);
  oobReceiver.stop();
});

test('超时未收到：返回 false', async () => {
  await oobReceiver.start({ callbackBase: '127.0.0.1:19004', httpPort: 19004, timeoutMs: 1000 });
  const hit = await oobReceiver.waitForToken('never', 150);
  assert.equal(hit, false);
  oobReceiver.stop();
});

test('真实 HTTP GET /oob/:token 路由触发 receive', async () => {
  const port = 19005;
  await oobReceiver.start({ callbackBase: `127.0.0.1:${port}`, httpPort: port, timeoutMs: 1000 });
  const token = 'route123';
  const { statusCode, body } = await httpGet(`http://127.0.0.1:${port}/oob/${token}`);
  assert.equal(statusCode, 200);
  assert.equal(body, 'ok');
  const hit = await oobReceiver.waitForToken(token, 300);
  assert.equal(hit, true);
  oobReceiver.stop();
});

test('未知路径返回 404 且不唤醒任何 token', async () => {
  const port = 19006;
  await oobReceiver.start({ callbackBase: `127.0.0.1:${port}`, httpPort: port, timeoutMs: 1000 });
  const { statusCode } = await httpGet(`http://127.0.0.1:${port}/unknown`);
  assert.equal(statusCode, 404);
  const hit = await oobReceiver.waitForToken('xyz', 120);
  assert.equal(hit, false);
  oobReceiver.stop();
});
