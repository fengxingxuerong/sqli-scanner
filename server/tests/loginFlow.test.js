// ============================================================================
// loginFlow.test.js — 登录编排最小版（批次14，实战分析 P1-6）
// ============================================================================
// 四层覆盖：
//   ① detectLoginFields 纯函数（密码框定位/用户名框回溯/hidden 透传/无密码框 → null）
//   ② isLoginChallenge（401/403/登录跳转/正常响应）
//   ③ withLoginFlow 集成（本地 http server：会话过期 → 自动重登 → 重试原请求成功；
//      凭据错误不重试不死循环；正常响应零额外请求）
//   ④ guardLogin 形状收紧（非法 url 整体丢弃/字段名白名单/长度截断）
// ============================================================================
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { HttpClient } from '../src/core/httpClient.js';
import { detectLoginFields, isLoginChallenge, performLogin, withLoginFlow } from '../src/core/loginFlow.js';
import { guardLogin } from '../src/api/scanGuard/objectGroups.js';

// ─── ① detectLoginFields ───
describe('[loginFlow] detectLoginFields', () => {
  test('标准登录页：type=password 定位 + 用户名回溯 + hidden 透传', () => {
    const html = `<form method="post" action="/login">
      <input type="hidden" name="csrf_token" value="abc123">
      <input type="text" name="uname" value="">
      <input type="password" name="pwd" value="">
      <button>登录</button></form>`;
    const f = detectLoginFields(html);
    assert.equal(f.usernameField, 'uname');
    assert.equal(f.passwordField, 'pwd');
    assert.deepEqual(f.hidden, { csrf_token: 'abc123' });
  });

  test('email 输入框 / 候选名兜底', () => {
    const emailForm = '<input type="email" name="mail"><input type="password" name="pass">';
    assert.equal(detectLoginFields(emailForm).usernameField, 'mail');
    // 用户名框在密码框之后：按候选名兜底
    const oddOrder = '<input type="password" name="pwd"><input type="text" name="username">';
    assert.equal(detectLoginFields(oddOrder).usernameField, 'username');
  });

  test('无密码框 → null（非标准表单登录页）', () => {
    assert.equal(detectLoginFields('<input type="text" name="q">'), null);
    assert.equal(detectLoginFields(''), null);
  });
});

// ─── ② isLoginChallenge ───
describe('[loginFlow] isLoginChallenge', () => {
  test('401/403 是；200 否；302 跳登录是；302 跳普通页否', () => {
    assert.equal(isLoginChallenge({ status: 401, headers: {} }), true);
    assert.equal(isLoginChallenge({ status: 403, headers: {} }), true);
    assert.equal(isLoginChallenge({ status: 200, headers: {} }), false);
    assert.equal(isLoginChallenge({ status: 302, headers: { location: 'http://x/login' } }), true);
    assert.equal(isLoginChallenge({ status: 302, headers: { location: 'http://x/next' } }), false);
    assert.equal(isLoginChallenge(null), false);
  });
});

// ─── ③ withLoginFlow 集成 ───
describe('[loginFlow] withLoginFlow 集成', () => {
  let server;
  let baseUrl;
  let loginPosts = 0;
  let sessionValid = false;
  const SID = 'sess-ok-1';
  const GOOD = { u: 'admin', p: 's3cret' };

  before(async () => {
    server = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      const cookies = Object.fromEntries(
        String(req.headers.cookie || '').split('; ').filter(Boolean).map((c) => {
          const i = c.indexOf('=');
          return [c.slice(0, i), c.slice(i + 1)];
        })
      );
      if (u.pathname === '/login' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<form><input type="hidden" name="csrf" value="t0k"><input name="username"><input type="password" name="password"></form>');
        return;
      }
      if (u.pathname === '/login' && req.method === 'POST') {
        loginPosts += 1;
        let raw = '';
        req.on('data', (c) => (raw += c));
        req.on('end', () => {
          const sp = new URLSearchParams(raw);
          const okCreds = sp.get('username') === GOOD.u && sp.get('password') === GOOD.p;
          const okCsrf = sp.get('csrf') === 't0k';
          if (okCreds && okCsrf) {
            sessionValid = true;
            res.setHeader('Set-Cookie', `sid=${SID}; Path=/`);
            res.writeHead(302, { Location: '/home' });
            res.end();
          } else {
            sessionValid = false;
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<form><input type="password" name="password"></form>'); // 仍在登录页
          }
        });
        return;
      }
      if (u.pathname === '/home') {
        // 登录成功后的 302 落点页（登录启发式只看「不再是登录页 + 未被打回挑战」）
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body>welcome</body></html>');
        return;
      }
      if (u.pathname === '/data') {
        if (cookies.sid === SID && sessionValid) {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('protected-data');
        } else {
          res.writeHead(401, { 'Content-Type': 'text/plain' });
          res.end('unauthorized');
        }
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    for (const { client, scanId } of views) client.clearJar(scanId);
    await new Promise((resolve) => server.close(resolve));
  });

  // 生产接线口径（scanClient.getScanClient）：withLoginFlow 包的是 `client.forScan(scanId)`
  // 视图，Set-Cookie 入 jar / 限速桶都按 scanId 生效（httpClient.js:281 的 jar 合并要求
  // opts.scanId）。裸 `new HttpClient()` 没有 scanId ⇒ 登录回发的 sid 进不了 jar ⇒ 重登后
  // 仍 401，测到的是一条产品里不存在的链路。每条用例用独立 scanId，避免 jar 跨用例污染。
  let scanSeq = 0;
  const views = [];
  function loginView(login) {
    const client = new HttpClient();
    const scanId = `loginFlow-test-${scanSeq}`;
    scanSeq += 1;
    views.push({ client, scanId });
    return withLoginFlow(client.forScan(scanId), login);
  }

  const makeLogin = (over = {}) => ({
    url: `${baseUrl}/login`,
    username: GOOD.u,
    password: GOOD.p,
    ...over,
  });

  test('会话过期 → 自动重登一次 → 重试原请求成功（hidden/CSRF 透传）', async () => {
    const view = loginView(makeLogin());
    sessionValid = false; // 首个请求必然 401（未登录）
    const res = await view.request({ method: 'GET', url: `${baseUrl}/data` });
    assert.equal(res.status, 200, `重登后应成功，实际 ${res.status}`);
    assert.equal(String(res.data), 'protected-data');
    assert.equal(loginPosts, 1, '应恰好一次登录提交');
  });

  test('凭据错误：重登失败不重试、不死循环（原 401 放行）', async () => {
    const view = loginView(makeLogin({ username: 'admin', password: 'wrong' }));
    sessionValid = false;
    const before = loginPosts;
    const res = await view.request({ method: 'GET', url: `${baseUrl}/data` });
    assert.equal(res.status, 401, '登录失败应放行原响应');
    assert.equal(loginPosts, before + 1, '只提交一次，不重试不死循环');
  });

  test('正常响应直通零登录（带有效会话 cookie，未触发挑战）', async () => {
    const view = loginView(makeLogin());
    sessionValid = true;
    const before = loginPosts;
    const res = await view.request({
      method: 'GET',
      url: `${baseUrl}/data`,
      headers: { Cookie: `sid=${SID}` },
    });
    assert.equal(res.status, 200);
    assert.equal(loginPosts, before, '正常响应零登录提交');
  });

  // [2026-10-02 补缺口] 上面三条测的是**包装层**的结果，判不到 `performLogin` 自己的
  // 成功启发式 —— 缺陷注入实测：把「响应仍是登录页」这条判定去掉（ok 恒真），12 条用例
  // **全绿**。后果很具体：凭据错/被验证码打回时仍判「登录成功」⇒ 白重试一次，
  // 且 withLoginFlow 拿不到「重登失败」的信号去收尾。故必须直测 performLogin 的返回值。
  describe('[loginFlow] performLogin 成功启发式', () => {
    const rawClient = () => {
      const c = new HttpClient();
      const scanId = `loginFlow-perform-${scanSeq}`;
      scanSeq += 1;
      views.push({ client: c, scanId });
      return c.forScan(scanId);
    };

    test('凭据正确：302 + 落点页无密码框 ⇒ ok=true', async () => {
      sessionValid = false;
      const r = await performLogin({ client: rawClient(), login: makeLogin() });
      assert.equal(r.ok, true, `正确凭据应判登录成功，实得 ok=${r.ok} status=${r.status}`);
      // ⚠ 站端发的是 302 → /home，但 httpClient 跟随跳转 ⇒ 落到落点页的 200。
      // 别在这里写死 302：那测的是「是否跟随跳转」，不是登录是否成功。
      assert.ok(r.status === 200 || r.status === 302, `落点状态码异常：${r.status}`);
      assert.match(String(r.detail || ''), /^$/, '成功时不应给失败原因');
    });

    test('★凭据错误：响应仍是登录页 ⇒ ok=false 且 detail 点名原因', async () => {
      sessionValid = false;
      const r = await performLogin({
        client: rawClient(),
        login: makeLogin({ password: 'wrong' }),
      });
      assert.equal(r.ok, false, '响应里还有密码框 = 还在登录页 = 登录没成功 ⇒ 必须判 false');
      assert.match(r.detail, /登录页/, `失败要给出原因，实得 detail="${r.detail}"`);
    });

    test('被明确打回认证挑战（401）⇒ ok=false', async () => {
      sessionValid = false;
      // /data 在无有效会话时恒 401 —— 借它当「登录接口直接 401」的形态
      const r = await performLogin({
        client: rawClient(),
        login: makeLogin({ url: `${baseUrl}/data` }),
      });
      assert.equal(r.status, 401);
      assert.equal(r.ok, false, '401 是明确的认证挑战，不能算登录成功');
    });
  });
});

// ─── ④ guardLogin 形状收紧 ───
describe('[loginFlow] guardLogin', () => {
  test('合法形态收下；非法 url 整体丢弃；字段名白名单 + 长度截断', () => {
    const config = {};
    guardLogin(config, {
      login: {
        url: 'http://t.local/login',
        username: 'admin',
        password: 'p',
        usernameField: 'user-name_1',
        passwordField: 'bad field!', // 非法字符 → 丢弃（回落自动探测）
        passwordField2: 'x',
      },
    });
    assert.equal(config.login.url, 'http://t.local/login');
    assert.equal(config.login.usernameField, 'user-name_1');
    assert.equal(config.login.passwordField, undefined);

    const dropped = {};
    guardLogin(dropped, { login: { url: 'ftp://t.local/x', username: 'a' } });
    assert.equal(dropped.login, undefined, '非 http(s) 登录地址整体丢弃');

    const truncated = {};
    guardLogin(truncated, { login: { url: `http://t.local/${'a'.repeat(3000)}`, username: 'u' } });
    assert.equal(truncated.login.url.length, 2048);
  });
});
