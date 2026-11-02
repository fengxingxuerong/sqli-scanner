// [D236] 事件循环滞后观测：纯决策真值表（注入假直方图，零墙钟断言——本仓纪律：
// 拿墙钟当活性上限 = 在测机器负载）+ 受控滞后诱导（同步阻塞制造真实滞后，断言
// 「测到了 >0 的滞后」而非「耗时等于某值」）+ 启停/幂等 + health 接线形态。
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import {
  summarizeHistogram,
  shouldWarnLag,
  startEventLoopWatch,
  stopEventLoopWatch,
  sampleWindow,
  getEventLoopStats,
} from '../src/core/eventLoopWatch.js';
import { healthRoutes } from '../src/api/healthRoutes.js';

const NS = 1e6; // 1ms = 1e6 ns

/** 假直方图：给定 p99/max（毫秒），返回 summarizeHistogram 可消费的形状 */
function fakeHist({ p99Ms, maxMs }) {
  return { max: maxMs * NS, percentile: (p) => (p === 99 ? p99Ms * NS : 0) };
}

/** 同步阻塞事件循环 ms 毫秒（制造真实滞后，不是 sleep） */
function blockEventLoop(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) { /* spin */ }
}

beforeEach(() => stopEventLoopWatch());
afterEach(() => stopEventLoopWatch());

test('D236 纯函数：summarizeHistogram 纳秒折算毫秒（含 0 与亚毫秒取整）', () => {
  assert.deepEqual(summarizeHistogram(fakeHist({ p99Ms: 123.4, maxMs: 456.7 })), { p99Ms: 123.4, maxMs: 456.7 });
  assert.deepEqual(summarizeHistogram(fakeHist({ p99Ms: 0, maxMs: 0 })), { p99Ms: 0, maxMs: 0 });
  // 0.04ms → 0（一位小数取整）：小滞后不产生噪声读数
  assert.equal(summarizeHistogram(fakeHist({ p99Ms: 0.04, maxMs: 0.04 })).maxMs, 0);
});

test('D236 纯函数：shouldWarnLag 真值表（阈值 / 冷却期 / 首次告警）', () => {
  const s = { maxMs: 150 };
  assert.equal(shouldWarnLag(s, 100, 0, 1000, 30000), true, '超阈值且从未告警 → 告警');
  assert.equal(shouldWarnLag({ maxMs: 100 }, 100, 0, 1000, 30000), false, '等于阈值不算超（严格大于）');
  assert.equal(shouldWarnLag({ maxMs: 99.9 }, 100, 0, 1000, 30000), false, '低于阈值不告警');
  assert.equal(shouldWarnLag(s, 100, 500, 1000, 30000), false, '冷却期内不重复告警');
  assert.equal(shouldWarnLag(s, 100, 500, 31000, 30000), true, '冷却期过后再次告警');
  assert.equal(shouldWarnLag({ maxMs: 0 }, 100, 0, 1000, 30000), false, '零滞后不告警');
});

test('D236 集成：未启动时统计量全零（形状恒定，消费方免判空）', () => {
  assert.deepEqual(getEventLoopStats(), { p99Ms: 0, maxMs: 0, samples: 0 });
});

test('D236 集成：重复启动是调用方 bug（显式抛错，不静默复用）', () => {
  startEventLoopWatch({ sampleMs: 50 });
  assert.throws(() => startEventLoopWatch({ sampleMs: 50 }), /已启动/);
});

test('D236 集成：受控滞后诱导——同步阻塞落账后手动采样必测到（确定性驱动，绕开 reset 竞态）', { timeout: 15000 }, async () => {
  // threshold 给大（10s）避免测试期间打 warn 日志；sampleMs 给大（60s）让 interval
  // 在本测试内不触发，采样由测试显式调用 sampleWindow()——消除「内部观察回调 vs reset」
  // 的同相位竞态（该竞态在真实服务里只是让长条延迟一个窗口可见，见模块注释）。
  startEventLoopWatch({ sampleMs: 60000, thresholdMs: 10000 });
  blockEventLoop(120);
  // 让出事件循环：monitorEventLoopDelay 的内部观察回调（阻塞期间到期）在循环恢复后
  // 立即落账，30ms 的空转周期足够它跑完——之后直方图必有该次滞后记录。
  await new Promise((r) => setTimeout(r, 30));
  const s = sampleWindow();
  assert.ok(s.samples >= 1, `手动采样应完成（实际 ${s.samples}）`);
  assert.ok(s.maxMs > 0, `120ms 同步阻塞应被测到（实际 maxMs=${s.maxMs}）`);
});

test('D236 集成：stop 后统计量复位且采样停止', { timeout: 15000 }, async () => {
  startEventLoopWatch({ sampleMs: 30, thresholdMs: 10000 });
  const deadline = Date.now() + 5000;
  while (getEventLoopStats().samples < 1 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 20));
  }
  assert.ok(getEventLoopStats().samples >= 1);
  stopEventLoopWatch();
  assert.deepEqual(getEventLoopStats(), { p99Ms: 0, maxMs: 0, samples: 0 }, 'stop 复位全零');
  const frozen = getEventLoopStats().samples;
  await new Promise((r) => setTimeout(r, 120));
  assert.equal(getEventLoopStats().samples, frozen, 'stop 后不再采样');
});

// ===== /api/health 接线形态 =====
function request(app, path) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      const req = http.request({ host: '127.0.0.1', port, method: 'GET', path }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          server.close();
          resolve({ status: res.statusCode, body: JSON.parse(body || '{}') });
        });
      });
      req.on('error', (e) => { server.close(); reject(e); });
      req.end();
    });
  });
}

test('D236 接线：/api/health 携带 eventLoop 字段（未启动时全零，形状稳定）', async () => {
  const app = express();
  app.use('/api', healthRoutes);
  const res = await request(app, '/api/health');
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.data.eventLoop, { p99Ms: 0, maxMs: 0, samples: 0 });
});
