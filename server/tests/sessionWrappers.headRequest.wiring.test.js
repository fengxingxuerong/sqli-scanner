// ============================================================================
// sessionWrappers.headRequest.wiring.test.js —— 会话包装不得丢 headRequest（D279）
// ============================================================================
// TODO §10（2026-10-10 立）的缺陷：withSafeUrl / withCsrf / withLoginFlow 三个会话层
// 返回 { request } 视图，把内层的 headRequest 整个丢掉 ⇒ 配了任一会话开关后，
// --null-connection 的 HEAD 通道在 sendHead（egress.js）里**静默回退 GET**：
//   · null-connection 的省带宽语义失效；
//   · HEAD 不经过 csrf 挂 token / safeUrl 保活计数 / login 重登编排 —— 会话层对 HEAD 全盲；
//   · 「能力没了而没有任何东西变红」—— 本仓最典型的静默降级形状。
// D279 修法（与 withBearerRefresh / withLiveCookies 的既有正确形状对齐）：
//   三个包装统一 `{ ...client, request, headRequest }`，且 HEAD 走**同一套加工**
//   （csrf 挂 token、safeUrl 计保活、login 重登重试）——只透传方法名等于 HEAD 绕过加工。
//
// 判据（全部可证伪，TODO §10 的验证口径 ①②）：
//   ① 三个开关各配一个（模块级 + getScanClient 产品装配级），view.headRequest 必须是函数；
//   ② HEAD 实收参数带加工结果（csrf token 在 URL 上、保活 GET 被触发、401 后重登重试），
//     从内层视图捕获比对，不采信包装层自报；
//   ③ 内层没有 headRequest 时不得凭空造一个（`...(typeof client.headRequest === 'function')`
//     的门必须在 —— 对无 HEAD 通道的连接器零行为变化）。
// ============================================================================
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { withSafeUrl } from '../src/core/safeUrlKeeper.js';
import { withCsrf } from '../src/core/csrfKeeper.js';
import { withLoginFlow } from '../src/core/loginFlow.js';
import { ScanManager } from '../src/engine/ScanManager.js';

const TOKEN_PAGE = '<form><input type="hidden" name="csrf_token" value="T1"></form>';
const LOGIN_PAGE = '<form><input type="text" name="user"><input type="password" name="pass"></form>';
const ok = (data = 'ok') => ({ status: 200, data, headers: {} });

/** 可捕获 request/headRequest 的内层假客户端（headRequest 归一成 {url, method:'HEAD', ...opts} 供分支） */
function innerClient(responder) {
  const sent = [];
  const client = {
    sent,
    request: async (opts) => {
      sent.push({ kind: 'request', opts });
      return responder(opts, sent.length);
    },
    headRequest: async (url, opts = {}) => {
      sent.push({ kind: 'head', url, opts });
      return responder({ ...opts, url, method: 'HEAD' }, sent.length);
    },
  };
  return client;
}

// ── ①② 模块级：每个包装的 HEAD 语义 ────────────────────────────────────────
describe('withSafeUrl：HEAD 与 GET 共用保活计数', () => {
  test('① headRequest 保留；② HEAD 计入保活频率，边界触发对 safeUrl 的 GET', async () => {
    const inner = innerClient(() => ok());
    const view = withSafeUrl(inner, { safeUrl: 'http://t.test/keepalive', safeFreq: 2 });
    assert.equal(typeof view.headRequest, 'function', 'safeUrl 包装不得丢 headRequest');

    await view.headRequest('http://t.test/p?id=1', {});
    let ka = inner.sent.filter((s) => s.kind === 'request' && String(s.opts.url).includes('/keepalive'));
    assert.equal(ka.length, 0, '第 1 个扫描请求（HEAD）不该触发保活（freq=2）');

    await view.headRequest('http://t.test/p?id=1', {});
    ka = inner.sent.filter((s) => s.kind === 'request' && String(s.opts.url).includes('/keepalive'));
    assert.equal(ka.length, 1, `第 2 个扫描请求是 HEAD，也必须触发保活，实得 ${ka.length} 次`);
  });

  test('③ 内层没有 headRequest 时不凭空造一个（对无 HEAD 通道的连接器零行为变化）', () => {
    const bare = { request: async () => ok() };
    const view = withSafeUrl(bare, { safeUrl: 'http://t.test/keepalive', safeFreq: 1 });
    assert.equal(typeof view.headRequest, 'undefined');
  });
});

describe('withCsrf：HEAD 同样取页、挂 token、计刷新', () => {
  test('① 保留；② 首个 HEAD 先取 token，且 token 挂在**传给内层的 URL 实参**上', async () => {
    const inner = innerClient((opts) =>
      String(opts.url || '').includes('/csrf') ? ok(TOKEN_PAGE) : ok('<p>page</p>'),
    );
    const view = withCsrf(inner, {
      csrfUrl: 'http://t.test/csrf',
      csrfTokenName: 'csrf_token',
      refreshFreq: 50,
    });
    assert.equal(typeof view.headRequest, 'function', 'csrf 包装不得丢 headRequest');

    const res = await view.headRequest('http://t.test/p?id=1', {});
    assert.equal(res.status, 200);
    const fetches = inner.sent.filter((s) => s.kind === 'request' && String(s.opts.url).includes('/csrf'));
    assert.equal(fetches.length, 1, '首个 HEAD 之前必须先取页（HEAD 也可能是一轮的第一条请求）');
    const head = inner.sent.find((s) => s.kind === 'head');
    assert.ok(head, 'HEAD 必须真的发到内层（不再被回退成 GET）');
    assert.match(
      head.url,
      /csrf_token=T1/,
      `token 必须挂在 headRequest 的 **url 实参**上（HttpClient.headRequest 用显式 url 覆盖 opts.url），实得：${head.url}`,
    );
  });

  test('②b HEAD 与 GET 共用刷新计数器（HEAD 不计数 = 刷新按构造永不轮到 HEAD 密集的一轮）', async () => {
    const inner = innerClient((opts) =>
      String(opts.url || '').includes('/csrf') ? ok(TOKEN_PAGE) : ok('<p>page</p>'),
    );
    const view = withCsrf(inner, { csrfUrl: 'http://t.test/csrf', csrfTokenName: 'csrf_token', refreshFreq: 2 });
    await view.request({ url: 'http://t.test/p?id=1', method: 'GET', headers: {} }); // count=1，无 token ⇒ 取
    await view.headRequest('http://t.test/p?id=1', {});                              // count=2 ⇒ 刷新
    await view.request({ url: 'http://t.test/p?id=1', method: 'GET', headers: {} }); // count=3 ⇒ 不刷
    await view.headRequest('http://t.test/p?id=1', {});                              // count=4 ⇒ 刷新
    const fetches = inner.sent.filter((s) => s.kind === 'request' && String(s.opts.url).includes('/csrf'));
    assert.equal(fetches.length, 3, `取页序列应为 1(首次)+2(HEAD 边界)+3(HEAD 边界)，实得 ${fetches.length}`);
  });

  test('③ 内层没有 headRequest 时不凭空造一个', () => {
    const bare = { request: async () => ok() };
    const view = withCsrf(bare, { csrfUrl: 'http://t.test/csrf', csrfTokenName: 'csrf_token' });
    assert.equal(typeof view.headRequest, 'undefined');
  });
});

describe('withLoginFlow：HEAD 遇挑战同样重登并重试一次', () => {
  function loginInner() {
    let targetCalls = 0;
    let loginPosts = 0;
    const inner = innerClient((opts) => {
      const url = String(opts.url || '');
      const method = String(opts.method || 'GET').toUpperCase();
      if (url.includes('/login')) {
        if (method === 'POST') {
          loginPosts += 1;
          return ok('<p>dashboard</p>');
        }
        return ok(LOGIN_PAGE);
      }
      targetCalls += 1;
      return targetCalls <= 1 ? { status: 401, data: 'expired', headers: {} } : ok('<p>page</p>');
    });
    return { inner, loginPosts: () => loginPosts, targetCalls: () => targetCalls };
  }

  const LOGIN = { url: 'http://t.test/login', username: 'u', password: 'p' };

  test('① 保留；② HEAD 收 401 ⇒ 自动重登一次 ⇒ HEAD 原样重试一次', async () => {
    const { inner, loginPosts, targetCalls } = loginInner();
    const view = withLoginFlow(inner, LOGIN);
    assert.equal(typeof view.headRequest, 'function', 'login 包装不得丢 headRequest');

    const res = await view.headRequest('http://t.test/target', {});
    assert.equal(res.status, 200, '重登成功后 HEAD 必须重试成功');
    assert.equal(loginPosts(), 1, '恰好登录一次');
    assert.equal(targetCalls(), 2, '原 HEAD（401）+ 重试 HEAD（200）');
    const heads = inner.sent.filter((s) => s.kind === 'head');
    assert.equal(heads.length, 2, `HEAD 通道必须真的在内层发生（不是回退 GET），实得 ${heads.length}`);
  });

  test('②b GET 与 HEAD 并发撞挑战时共享 inFlight：只登一次', async () => {
    const { inner, loginPosts } = loginInner();
    const view = withLoginFlow(inner, LOGIN);
    await Promise.all([
      view.request({ url: 'http://t.test/target', method: 'GET', headers: {} }),
      view.headRequest('http://t.test/target', {}),
    ]);
    assert.equal(loginPosts(), 1, `并发挑战必须共享同一次登录，实得 ${loginPosts()} 次`);
  });

  test('③ 内层没有 headRequest 时不凭空造一个', () => {
    const bare = { request: async () => ok() };
    const view = withLoginFlow(bare, LOGIN);
    assert.equal(typeof view.headRequest, 'undefined');
  });
});

// ── ①② getScanClient 产品装配级：开关 → 视图 → 内层捕获 ────────────────────
// 形状对齐 bearerKeeper.wiring.test.js 的 stubHttp/manager（最小 ScanManager：只用到
// httpClient / getConnector / _scanClients）。
function stubHttp(responder) {
  const sent = [];
  return {
    sent,
    forScan() {
      return {
        request: async (opts) => {
          sent.push({ kind: 'request', opts });
          return responder(opts, sent.length);
        },
        headRequest: async (url, opts = {}) => {
          sent.push({ kind: 'head', url, opts });
          return responder({ ...opts, url, method: 'HEAD' }, sent.length);
        },
      };
    },
    removeBucket() {},
    releaseGroupBucket() {},
    removeRequestCount() {},
    clearJar() {},
  };
}

function manager(responder) {
  const stub = stubHttp(responder);
  const sm = new ScanManager();
  sm.httpClient = stub;
  return { sm, stub };
}

describe('getScanClient 装配级：会话开关配上后 headRequest 必须活着且被加工', () => {
  test('①a 只配 --csrf-url：视图有 headRequest，且 HEAD 带着从靶页取的 token（TODO §10 口径②）', async () => {
    const { sm, stub } = manager((opts) =>
      String(opts.url || '').includes('/csrf') ? ok(TOKEN_PAGE) : ok('<p>page</p>'),
    );
    const view = sm.getScanClient('wire-csrf-1', {
      url: 'http://target.test/p?id=1',
      config: { csrfUrl: 'http://target.test/csrf', csrfTokenName: 'csrf_token' },
    });
    assert.equal(typeof view.headRequest, 'function', 'TODO §10：三个包装丢 headRequest 的缺陷不得回归');
    await view.headRequest('http://target.test/p?id=1', {});
    const head = stub.sent.find((s) => s.kind === 'head');
    assert.ok(head, 'HEAD 必须抵达内层视图');
    assert.match(head.url, /csrf_token=T1/, `HEAD 必须带 token，实得：${head.url}`);
  });

  test('①b 只配 --safe-url：视图有 headRequest，HEAD 计入保活', async () => {
    const { sm, stub } = manager(() => ok());
    const view = sm.getScanClient('wire-safe-1', {
      url: 'http://target.test/p?id=1',
      config: { safeUrl: 'http://target.test/keepalive', safeFreq: 1 },
    });
    assert.equal(typeof view.headRequest, 'function');
    await view.headRequest('http://target.test/p?id=1', {});
    const ka = stub.sent.filter((s) => s.kind === 'request' && String(s.opts.url).includes('/keepalive'));
    assert.equal(ka.length, 1, 'freq=1 时首个 HEAD 也应触发保活 GET');
  });

  test('①c 只配 --login-url：视图有 headRequest，HEAD 正常通道（无挑战不触发登录）', async () => {
    const { sm, stub } = manager(() => ok('<p>page</p>'));
    const view = sm.getScanClient('wire-login-1', {
      url: 'http://target.test/p?id=1',
      config: { login: { url: 'http://target.test/login', username: 'u', password: 'p' } },
    });
    assert.equal(typeof view.headRequest, 'function');
    await view.headRequest('http://target.test/p?id=1', {});
    assert.equal(stub.sent.filter((s) => s.kind === 'head').length, 1);
    assert.equal(stub.sent.filter((s) => s.kind === 'request').length, 0, '无挑战不得多发任何请求');
  });

  test('②c 三层全配（safeUrl+csrfUrl+login）：HEAD 穿过整条链且带 token —— 任何一层丢掉都会红', async () => {
    const { sm, stub } = manager((opts) => {
      const url = String(opts.url || '');
      if (url.includes('/csrf')) return ok(TOKEN_PAGE);
      return ok('<p>page</p>');
    });
    const view = sm.getScanClient('wire-all-1', {
      url: 'http://target.test/p?id=1',
      config: {
        safeUrl: 'http://target.test/keepalive',
        safeFreq: 100,
        csrfUrl: 'http://target.test/csrf',
        csrfTokenName: 'csrf_token',
        login: { url: 'http://target.test/login', username: 'u', password: 'p' },
      },
    });
    assert.equal(typeof view.headRequest, 'function', '三层串联后 headRequest 必须仍然存在');
    await view.headRequest('http://target.test/p?id=1', {});
    const head = stub.sent.find((s) => s.kind === 'head');
    assert.ok(head, 'HEAD 抵达内层');
    assert.match(head.url, /csrf_token=T1/, `穿过三层后 token 仍必须在 URL 上，实得：${head.url}`);
  });
});
