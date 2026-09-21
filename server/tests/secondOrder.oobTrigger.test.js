// SecondOrderDetector OOB 触发判定单元测试：
// oobTrigger 开启 + oob 启用时，存储探针改用 OOB 外带语句，触发页执行后带外回连判定命中；
// 未收到回连不误报；oobTrigger 关闭时回归报错回显老路径。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SecondOrderDetector } from '../src/engine/detectors/SecondOrderDetector.js';

// 假 oobReceiver：收到回调即 resolve；waitForToken 检查已收集合（模拟真实 receive→waitForToken 语义）。
function makeFakeReceiver() {
  const received = new Set();
  return {
    receive(token) {
      received.add(token);
    },
    waitForToken(token) {
      return Promise.resolve(received.has(token));
    },
  };
}

// 模拟目标：POST 存储探针；GET 触发页按 triggerOob 决定是否从存储值提取 oob token 并"回连"。
function makeOobMock({ param = 'username', triggerOob = true } = {}) {
  const fakeReceiver = makeFakeReceiver();
  const state = { stored: '1', posts: 0, gets: 0 };
  const httpClient = {
    async request(opts) {
      if (opts.method === 'POST') {
        state.posts++;
        // [P0-FIX 2026-09-15] 表单点 data 已序列化为 urlencoded 字符串（Content-Type 修正），
        // mock 按新口径解析回对象后取参。
        let data = opts.data && typeof opts.data === 'object' ? opts.data : {};
        if (typeof opts.data === 'string' && opts.data) {
          data = Object.fromEntries(new URLSearchParams(opts.data));
        } else {
          data = {};
        }
        state.stored = param && data[param] != null ? data[param] : Object.values(data)[0] ?? state.stored;
        return { data: 'OK', status: 200 };
      }
      if (opts.method === 'GET') {
        state.gets++;
        if (triggerOob) {
          const m = String(state.stored).match(/oob(?:%2[fF]|\/)([A-Za-z0-9_-]+)/i);
          if (m) fakeReceiver.receive(m[1]); // 模拟目标 DBMS 执行带外回连
        }
        return { data: '<html>triggered</html>', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
  return { httpClient, fakeReceiver, state };
}

// 报错回显 mock（回归用）：与 secondOrderDetector.test.js 同构，触发页按已存值含单引号回显报错。
function makeErrorMock({ param = 'username' } = {}) {
  const state = { value: '1', posts: 0, gets: 0 };
  const httpClient = {
    async request(opts) {
      if (opts.method === 'POST') {
        state.posts++;
        // [P0-FIX 2026-09-15] 表单点 data 已序列化为 urlencoded 字符串（Content-Type 修正），
        // mock 按新口径解析回对象后取参。
        let data = opts.data && typeof opts.data === 'object' ? opts.data : {};
        if (typeof opts.data === 'string' && opts.data) {
          data = Object.fromEntries(new URLSearchParams(opts.data));
        } else {
          data = {};
        }
        state.value = param && data[param] != null ? data[param] : Object.values(data)[0] ?? state.value;
        return { data: 'OK', status: 200 };
      }
      if (opts.method === 'GET') {
        state.gets++;
        const hasQuote = String(state.value).includes("'");
        const body = hasQuote ? 'You have an error in your SQL syntax' : '<html>profile ok</html>';
        return { data: body, status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
  return { httpClient, state };
}

function makeCtx({ httpClient, fakeReceiver = null, dbms = 'MySQL', oobTrigger = true, oobEnabled = true } = {}) {
  const config = {
    timeoutMs: 5000,
    retry: 1,
    oob: {
      enabled: oobEnabled,
      callbackBase: '127.0.0.1:8899',
      httpPort: 8899,
      timeoutMs: 200,
    },
    secondOrder: {
      enabled: true,
      triggerUrls: ['http://mock/trigger'],
      refreshCsrf: false,
      negativeControl: false,
      oobTrigger,
    },
  };
  const target = {
    method: 'GET',
    baseUrl: 'http://mock/?q=1',
    headerParams: {},
    cookieParams: {},
    config,
  };
  const point = {
    id: 'p1',
    location: 'body',
    param: 'username',
    originalValue: '1',
    confirmed: false,
    technique: null,
    dbms: null,
    formMethod: 'POST',
    actionUrl: 'http://mock/store',
    formValues: { username: '1', _token: 'csrf' },
    csrfTokenName: '_token',
  };
  const ctx = {
    httpClient,
    target,
    point,
    dbms,
    config,
    triggerUrl: 'http://mock/trigger',
    scanId: 'scan123',
  };
  if (fakeReceiver) ctx.oobReceiver = fakeReceiver;
  return ctx;
}

test('oobTrigger 开启 + oob 启用 → 使用 OOB 探针，收到回调判定命中', async () => {
  const { httpClient, fakeReceiver, state } = makeOobMock({ triggerOob: true });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, fakeReceiver, dbms: 'MySQL', oobTrigger: true });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'second_order');
  assert.equal(res.dbms, 'MySQL');
  assert.ok(res.evidence.includes('OOB'), 'evidence 应含 OOB 外带确认');
  assert.ok(Array.isArray(res.payloads) && res.payloads.length > 0);
  // 探针为 OOB 外带语句（非报错型），且嵌入带外回调路径
  assert.ok(res.payloads.some((p) => p.includes('LOAD_FILE')), `探针应含 OOB 原语: ${res.payloads[0]}`);
  assert.ok(res.payloads.some((p) => p.includes('/oob/')), '探针应嵌入带外回调路径');
  // 存储与触发均已发生
  assert.ok(state.posts > 0 && state.gets > 0);
  // 与现有检测器一致：同步标记注入点
  assert.equal(ctx.point.confirmed, true);
  assert.equal(ctx.point.technique, 'second_order');
});

test('oobTrigger 开启但未收到回调 → 不误报（vulnerable=false）', async () => {
  const { httpClient, fakeReceiver, state } = makeOobMock({ triggerOob: false });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, fakeReceiver, dbms: 'MySQL', oobTrigger: true });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, false);
  assert.equal(ctx.point.confirmed, false);
  // 确实做了存储 + 触发，只是无带外回连
  assert.ok(state.posts > 0 && state.gets > 0);
});

test('oobTrigger 关闭 → 回归报错回显老路径（不借用 OOB）', async () => {
  const { httpClient } = makeErrorMock({ param: 'username' });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, dbms: 'MySQL', oobTrigger: false, oobEnabled: false });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.ok(res.evidence.includes('二阶注入确认'), '应走报错回显判定');
  assert.ok(!res.evidence.includes('OOB'), '不应出现 OOB 判定');
  assert.ok(res.payloads[0].includes("'"), '探针应为报错型（含单引号）');
});

test('oobTrigger 开启但 oob 未启用 → 回退报错回显老路径', async () => {
  const { httpClient } = makeErrorMock({ param: 'username' });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, dbms: 'MySQL', oobTrigger: true, oobEnabled: false });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.ok(res.evidence.includes('二阶注入确认'));
  assert.ok(!res.evidence.includes('OOB'));
});

test('未知 dbms 时遍历支持库仍可被 OOB 回连确认', async () => {
  const { httpClient, fakeReceiver } = makeOobMock({ triggerOob: true });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, fakeReceiver, dbms: null, oobTrigger: true });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'second_order');
  assert.equal(res.dbms, null);
});

test('OOB 标记唯一：两次检测产生不同 token', async () => {
  const d = new SecondOrderDetector();
  const t1 = d._buildOobToken({ scanId: 's1', point: { id: 'p1' } });
  await new Promise((r) => setTimeout(r, 5)); // 时间戳推进
  const t2 = d._buildOobToken({ scanId: 's1', point: { id: 'p1' } });
  assert.notEqual(t1, t2);
});

// ── [DNS-LABEL-FIX 2026-09-21] OOB token 必须放得进 DNS 单个标签 ─────────────
// 根因：token 会被拼成 `{CALLBACK}` 的子域标签（见 _detectOob），而接收端 _handleDns
// **只取第一个标签**当 token、waitForToken 又是**精确匹配** —— 超 63 字节时目标端 DNS 库
// 要么拒绝发送、要么被拆/截断，收到的字符串永远不等于完整 token ⇒ **有回连却判未命中**。
test('OOB token ≤63 字节（DNS 单标签上限）—— 常规规模', () => {
  const d = new SecondOrderDetector();
  const t = d._buildOobToken({ scanId: 'a1b2c3d4e5f6', point: { id: 'dec9ec92' } });
  assert.ok(t.length <= 63, `实际 ${t.length}`);
  assert.match(t, /^[A-Za-z0-9_-]+$/, 'token 必须是 DNS 安全字符集');
});

test('★OOB token 遇到超长 scanId/pointId 仍须压到 63 字节内（修复前必然超限）', () => {
  const d = new SecondOrderDetector();
  const t = d._buildOobToken({ scanId: 'x'.repeat(60), point: { id: 'y'.repeat(60) } });
  assert.ok(t.length <= 63, `实际 ${t.length}（超限即静默漏报）`);
  assert.match(t, /^[A-Za-z0-9_-]+$/);
});

test('OOB token 压缩后仍保持唯一性（唯一性来自时间戳+随机段，不是长 id）', () => {
  const d = new SecondOrderDetector();
  const longCtx = { scanId: 'x'.repeat(60), point: { id: 'y'.repeat(60) } };
  const set = new Set();
  for (let i = 0; i < 50; i++) set.add(d._buildOobToken(longCtx));
  assert.equal(set.size, 50, '50 次生成应互不相同（若把随机段也截掉就会撞）');
});
