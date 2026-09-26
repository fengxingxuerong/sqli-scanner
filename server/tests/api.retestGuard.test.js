// ============================================================================
// api.retestGuard.test.js —— 单点重测必须走与 /scan/start 同一套入口守卫
//
// 为什么单独一条文件（2026-09-25，审计入口层时**执行**复现）：
//   这条端点历史上是 `merged 直送 sm.start`，整条 sanitizeStart 被绕开。同一个旋钮
//   从两个入口进来就有两种效力。实测当时真的到了引擎里的 config：
//     {concurrency:9999, timeoutMs:99999999, ratePerSec:"20",
//      dumpWhere:'id=1; DROP TABLE x', totallyBogusKey:1}
//   · concurrency 主入口 clamp 到 1..10，这里直通 9999（打爆目标的方向）
//   · dumpWhere 会**拼进提取 SQL**，主入口因"分号是把一个条件变成第二条语句的那一步"
//     明确拒收，这里原样进引擎
//   · ratePerSec 字符串在主入口经类型归一后仍限速，这里直送就被下游判成"不限速"
//   · 未知键主入口会 warn（设置没生效必须喊出来），这里静默
//   入口守卫的正确形状不是"给最显眼那条路加检查"，而是**两条路共用同一个函数**。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createRoutes } from '../src/api/scanRoutes.js';

const BASE_URL = 'http://127.0.0.1:9999/x?id=1';

function makeStub(overrides = {}) {
  const captured = { payload: null };
  // scanGovernance.js:83 会读 `sm.scans.get(scanId).status` ⇒ 桩必须提供 scans，
  // 否则路由在 start 之后抛 "Cannot read properties of undefined (reading 'get')"，
  // 症状看起来像端点坏了，其实缺的是桩。
  const scans = new Map();
  const sm = {
    scans,
    getReport: () => ({
      target: { baseUrl: BASE_URL, method: 'GET', config: { concurrency: 3, level: 2 }, ...(overrides.target || {}) },
      points: [{ id: 'p1', param: 'id', location: 'url' }],
    }),
    start: async (p) => {
      captured.payload = p;
      scans.set('scan-new', { status: 'running' });
      return 'scan-new';
    },
  };
  // 只给到路由用得上的最小面：trackScanTerminal 会 bus.create(id) 要一个 emitter，
  // 并在收到终态事件时 release()。**必须让它真的终结** —— 否则模块级的并发槽位
  // 不回收，同文件后面的测试会拿到 ENGINE_BUSY，症状看起来像"路由坏了"，其实是桩漏了。
  const bus = {
    create: () => {
      let handler = null;
      return {
        on: (_evt, fn) => {
          handler = fn;
          setTimeout(() => handler && handler({ type: 'scan_completed' }), 0);
        },
        off: () => { handler = null; },
      };
    },
  };
  return { sm, bus, captured };
}

async function withApp(stub, fn) {
  const app = express();
  app.use(express.json());
  app.use('/api', createRoutes({ scanManager: stub.sm, eventBus: stub.bus }));
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  try {
    await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const retest = (base, config) =>
  fetch(`${base}/api/scan/base/point/p1/retest`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ config }),
  });

test('重测与 start 共用 clamp：越界值收敛、分号 dumpWhere 与未知键都进不了引擎', async () => {
  const stub = makeStub();
  await withApp(stub, async (base) => {
    const res = await retest(base, {
      concurrency: 9999,
      timeoutMs: 99999999,
      ratePerSec: '20',
      dumpWhere: 'id=1; DROP TABLE x',
      totallyBogusKey: 1,
    });
    const j = await res.json();
    assert.equal(j.code, 0, `重测应成功：${JSON.stringify(j)}`);
    const cfg = stub.captured.payload.config;
    assert.equal(cfg.concurrency, 10, 'concurrency 必须 clamp 到 1..10（主入口同款）');
    assert.equal(cfg.timeoutMs, 60000, 'timeoutMs 必须 clamp 到 1000..60000');
    assert.equal(cfg.ratePerSec, 20, '数字字符串要归一成数字，否则下游按"不限速"建桶');
    assert.ok(!('dumpWhere' in cfg), '带分号的 dumpWhere 绝不允许进引擎（它拼进提取 SQL）');
    assert.ok(!('totallyBogusKey' in cfg), '未知键不得静默进引擎');
  });
});

test('非法 technique 白名单外取值：重测当场拒绝，且不启动任何扫描', async () => {
  const stub = makeStub();
  await withApp(stub, async (base) => {
    const res = await retest(base, { techniques: ['union', '__bogus__'] });
    const j = await res.json();
    assert.notEqual(j.code, 0, '非法技术类型必须被拒');
    assert.equal(stub.captured.payload, null, '被拒的入参不得已经启动扫描（先校验后启动）');
  });
});

test('onlyPoint 仍由服务端算出并贴在净化之后（伪造值不得生效，重测不退化成整站重扫）', async () => {
  const stub = makeStub();
  await withApp(stub, async (base) => {
    const res = await retest(base, { onlyPoint: { location: 'body', param: 'evil' }, extractScope: { databases: ['x'] } });
    assert.equal((await res.json()).code, 0);
    const cfg = stub.captured.payload.config;
    assert.deepEqual(cfg.onlyPoint, { location: 'url', param: 'id' },
      'onlyPoint 必须来自报告里的真实点位，而不是 override');
    assert.ok(!('extractScope' in cfg), '重测只做检测：原 extractScope 不得带进去（会重复枚举）');
  });
});

test('自报字段指向引擎真正读的键：tamper 在 wafEvasion 下，顶层 tamper 不算已应用', async () => {
  const stub = makeStub();
  await withApp(stub, async (base) => {
    const tamper = { enabled: true, plugins: ['space2comment'], intensity: 'medium' };
    const res = await retest(base, { wafEvasion: { tamper } });
    const j = await res.json();
    assert.equal(j.code, 0, JSON.stringify(j));
    assert.deepEqual(j.data.configApplied.tamper, tamper,
      '设了 tamper 却回显 null = 对用户说了"没做"；历史实现读的是引擎不看的顶层 merged.tamper');
  });
});

test('回显不得替顶层 tamper 背书（内置引擎根本不信这个键）', async () => {
  const stub = makeStub();
  await withApp(stub, async (base) => {
    const res = await retest(base, { tamper: ['space2comment'] });
    const j = await res.json();
    assert.equal(j.data.configApplied.tamper, null,
      '把 sqlmap 面板串过来的顶层 tamper 报成"已应用"，等于报了一个不存在的效果');
  });
});
