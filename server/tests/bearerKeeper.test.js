// ============================================================================
// bearerKeeper.test.js —— Bearer/Token 自动续期（批次 D36，实战 P0-2）
// ============================================================================
// 四层覆盖：
//   ① 纯函数：isAuthChallenge / pickField / extractToken（取不到 token 时的可诊断文案）
//      / normalizeRefreshConfig（形状与"空值语义"）/ buildRefreshRequest（json|form|cookie-only）
//      / applyBearer（头模板与"不清原头"）
//   ② 登记表与计数：register/refreshActive/setRefreshObserver/refreshOnce 的 attempts/successes/failures
//   ③ withBearerRefresh 行为（本批主判据）：
//      · 401 ⇒ 续期 ⇒ 重试**一次**；续期后仍挑战 ⇒ 放行，绝不续第二次（不给客户认证服务加压）
//      · 续期失败 ⇒ 原样放行，且不再发目标请求（由 authLost 既有口径收尾）
//      · 拿到新 token 之前**不动用户带来的 Authorization**（口径 ①，最容易被写反的一条）
//      · 并发去重：20 条同时 401 只打一次续期端点
//      · eager / 默认档零前置请求 / 未登记原样返回 / headRequest 不被包装层丢掉
//   ④ 可观测性：失败原因（why）既回传观察者也落进 entry.lastWhy（守卫与报告共用一份真相）
// ============================================================================
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isAuthChallenge, pickField, extractToken, buildRefreshRequest, normalizeRefreshConfig,
  registerScanRefresh, getScanRefresh, refreshActiveForScan, releaseScanRefresh,
  setRefreshObserver, refreshOnce, applyBearer, withBearerRefresh,
} from '../src/core/bearerKeeper.js';
import { AppError } from '../src/core/errors.js';

let seq = 0;
const newScanId = () => `t-bearer-${process.pid}-${seq++}`;

const REFRESH_PATH = '/refresh';
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 可控假客户端：/refresh 走 handlers.refresh，其余走 handlers.target（HEAD 优先 handlers.head）。
 * log 记录**实际发出**的每条请求，断言"动了哪个头 / 发了几条"只能看这里，不能看返回值。
 */
function fakeClient(handlers) {
  const log = [];
  const dispatch = async (opts) => {
    log.push(opts);
    const fn = String(opts.url || '').includes(REFRESH_PATH)
      ? handlers.refresh
      : (opts.method === 'HEAD' && handlers.head) ? handlers.head : handlers.target;
    return fn(opts, log.filter((o) => !String(o.url).includes(REFRESH_PATH)).length, log.length);
  };
  const client = { request: (o = {}) => dispatch(o) };
  client.headRequest = async (url, o = {}) => dispatch({ ...o, url, method: 'HEAD' });
  return { client, log };
}

// ─── ① 纯函数 ───
describe('[bearerKeeper] 纯函数', () => {
  test('isAuthChallenge：只认 401/403（与 loginFlow 的 302 跳登录刻意不同）', () => {
    assert.equal(isAuthChallenge({ status: 401 }), true);
    assert.equal(isAuthChallenge({ status: 403 }), true);
    assert.equal(isAuthChallenge({ status: '403' }), true);
    assert.equal(isAuthChallenge({ status: 302, headers: { location: 'http://x/login' } }), false);
    assert.equal(isAuthChallenge({ status: 200 }), false);
    assert.equal(isAuthChallenge(null), false);
    assert.equal(isAuthChallenge(undefined), false);
  });

  test('pickField：点路径 + 数组下标 + 缺路径/非对象返回 undefined', () => {
    const o = { data: { items: [{ token: 'T' }] } };
    assert.equal(pickField(o, 'data.items.0.token'), 'T');
    assert.equal(pickField(o, 'data.missing.token'), undefined);
    assert.equal(pickField(null, 'x'), undefined);
    assert.equal(pickField(o, 'data'), o.data);
    // 空路径没有段可走 ⇒ 返回对象本身。没有调用方会传空串（extractToken 的候选表非空、
    // tokenField 入口已剔掉空白），这里钉住现语义，防它哪天被当成"取第一个字段"用。
    assert.equal(pickField(o, ''), o);
  });

  test('extractToken：显式 tokenField 优先；未给时按候选表顺序取第一个命中的', () => {
    const body = JSON.stringify({ code: 0, data: { access_token: 'AAA' }, token: 'BBB' });
    assert.equal(extractToken(body, 'data.access_token').token, 'AAA');
    // 同时有顶层 token 和嵌套 data.access_token 时，候选表顺序决定结果（顶层 token 在前）。
    // 这不是"猜错了"，而是这种响应本身就有歧义 —— 文档口径：两种都有时必须配 tokenField。
    assert.equal(extractToken(body).token, 'BBB');
    assert.equal(extractToken(JSON.stringify({ access_token: 'A1', token: 'B1' })).token, 'A1', '语义更强的 access_token 优先');
    assert.equal(extractToken(JSON.stringify({ code: 0, data: { access_token: 'AAA' } })).token, 'AAA', '顶层没有 token 时嵌套兜底');
    assert.equal(extractToken(JSON.stringify({ token: 'BBB' })).token, 'BBB');
    assert.equal(extractToken(JSON.stringify({ result: { accessToken: 'CCC' } })).token, 'CCC');
    assert.equal(extractToken(JSON.stringify({ access_token: '  ' })).token, null, '空白 token 不算拿到');
  });

  test('extractToken：取不到时 why 必须说出"试过哪些字段 + 响应顶层有什么"', () => {
    const r = extractToken(JSON.stringify({ code: 1, msg: 'no' }), 'data.token');
    assert.equal(r.token, null);
    assert.match(r.why, /data\.token/);
    assert.match(r.why, /code/, '没配字段名时最容易的错是字段写错：文案必须给出响应顶层键');
    const html = extractToken('<html>login</html>');
    assert.equal(html.token, null);
    assert.match(html.why, /不是 JSON/);
    assert.equal(extractToken(JSON.stringify('a-string')).token, null);
    assert.equal(extractToken(null).token, null);
  });

  test('normalizeRefreshConfig：null/空串=未启用；坏 url / 非对象 = 抛错（不静默）', () => {
    assert.equal(normalizeRefreshConfig(null), null);
    assert.equal(normalizeRefreshConfig(undefined), null);
    assert.equal(normalizeRefreshConfig('   '), null);
    assert.deepEqual(normalizeRefreshConfig('http://a.test/refresh'), { url: 'http://a.test/refresh' });
    // '{}' 必须是错：defaults.bearerRefresh = null，出现空对象说明调用方传歪了
    assert.throws(() => normalizeRefreshConfig({}), (e) => e instanceof AppError && /url/.test(e.message),
      '空对象应报「url 必须是 http(s) 地址」');
    assert.throws(() => normalizeRefreshConfig({ url: 'ftp://a/r' }), AppError);
    assert.throws(() => normalizeRefreshConfig({ url: 'javascript:alert(1)' }), AppError);
    assert.throws(() => normalizeRefreshConfig([1, 2]), AppError);
    assert.throws(() => normalizeRefreshConfig(7), AppError);
  });

  test('normalizeRefreshConfig：只收白名单子键；eager 只认真 true；headerTemplate 必须含 {token}', () => {
    const out = normalizeRefreshConfig({
      url: 'http://a.test/r', evil: 'x', method: 'get', eager: 'yes',
      tokenField: 'data.token', headerTemplate: 'Bearer static-value',
    });
    assert.equal(out.evil, undefined);
    assert.equal(out.method, 'get', '入口只校验形状，大小写归一在 buildRefreshRequest');
    assert.equal(out.eager, undefined, '字符串 "yes" 不得当成开启');
    assert.equal(out.headerTemplate, undefined, '不含 {token} 的模板会把每条请求带成同一串字面量，必须忽略');
    assert.equal(out.tokenField, 'data.token');
    assert.equal(normalizeRefreshConfig({ url: 'http://a/r', eager: true }).eager, true);
  });

  test('buildRefreshRequest：json 默认 / form / 无 refreshToken 时靠 Cookie 且 body 可空', () => {
    const j = buildRefreshRequest({ url: 'http://a/r', refreshToken: 'RT' });
    assert.equal(j.method, 'POST');
    assert.equal(j.headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(j.data), { refreshToken: 'RT' });

    const f = buildRefreshRequest({ url: 'http://a/r', refreshToken: 'RT', bodyFormat: 'form', bodyField: 'refresh_token', body: { scope: 's' } });
    assert.match(f.headers['Content-Type'], /x-www-form-urlencoded/);
    assert.equal(f.data, 'refresh_token=RT&scope=s');

    const c = buildRefreshRequest({ url: 'http://a/r' });
    assert.equal(c.data, undefined, 'cookie-only 续期不该发空 body');
    assert.deepEqual(JSON.parse(buildRefreshRequest({ url: 'http://a/r', body: { tenant: 't' } }).data), { tenant: 't' });
    assert.equal(buildRefreshRequest({ url: 'http://a/r', method: 'get' }).method, 'GET', '小写 method 必须归一');
    assert.equal(buildRefreshRequest({ url: 'http://a/r', headers: { 'X-A': '1' } }).headers['X-A'], '1');
  });

  test('applyBearer：默认 Bearer 模板 / 自定义头名配裸 token / 模板覆盖 / 不清原头', () => {
    assert.equal(applyBearer({}, { url: 'x' }, 'T').headers.Authorization, 'Bearer T');
    assert.equal(applyBearer({}, { url: 'x', headerName: 'X-Api-Key' }, 'T').headers['X-Api-Key'], 'T');
    assert.equal(applyBearer({}, { url: 'x', headerName: 'X-Api-Key' }, 'T').headers.Authorization, undefined);
    assert.equal(applyBearer({}, { url: 'x', headerTemplate: 'Token {token}' }, 'T').headers.Authorization, 'Token T');
    const kept = applyBearer({ headers: { A: '1' }, url: 'u' }, { url: 'x' }, 'T');
    assert.equal(kept.headers.A, '1', '不得清掉原请求头');
    assert.equal(kept.url, 'u', '不得原地修改 opts（HttpClient 重试会复用同一个对象）');
    const noTok = applyBearer({ headers: { Authorization: 'Bearer OLD' } }, { url: 'x' }, null);
    assert.equal(noTok.headers.Authorization, 'Bearer OLD', '没有 token 时原样返回');
  });

  test('applyBearer 必须摘掉 auth.headers 里的同名键 —— 出口层是 auth.headers 覆盖 per-request 头', () => {
    // 缺陷现场（e2e/bearer-lab B 场景实测抓到）：抓包带来的 Authorization 走 config.auth.headers，
    // mergeAuthHeaders 把它合在**最后** ⇒ 续期换来的新令牌被就地盖掉 ⇒
    // 日志说"已取到新 token"，线上还是老令牌，整轮继续 401。
    const shared = { basic: { username: 'u' }, cookie: 'sid=1', headers: { Authorization: 'Bearer OLD', 'X-Tenant': 't1' } };
    const out = applyBearer({ headers: {}, auth: shared }, { url: 'x' }, 'NEW');
    assert.equal(out.headers.Authorization, 'Bearer NEW');
    assert.equal(out.auth.headers.Authorization, undefined, 'auth.headers 里的同名键必须在这条请求上被摘掉');
    assert.equal(out.auth.headers['X-Tenant'], 't1', '只摘冲突的那一键，其它认证配置照旧');
    assert.equal(out.auth.cookie, 'sid=1');
    assert.equal(out.auth.basic.username, 'u');
    assert.equal(shared.headers.Authorization, 'Bearer OLD', '绝不能原地改共享的 config.auth（多扫描共用）');
    // 自定义头名时冲突面也跟着走
    const k = applyBearer(
      { headers: {}, auth: { headers: { 'X-Api-Key': 'OLD', Keep: '1' } } },
      { url: 'x', headerName: 'X-Api-Key' },
      'NEW',
    );
    assert.equal(k.headers['X-Api-Key'], 'NEW');
    assert.equal(k.auth.headers['X-Api-Key'], undefined);
    assert.equal(k.auth.headers.Keep, '1');
    // 无冲突时不得凭空造出 auth（零配置形态不变）
    assert.equal(applyBearer({ headers: {}, auth: { headers: { 'X-Other': '1' } } }, { url: 'x' }, 'T').auth.headers['X-Other'], '1');
    assert.equal(applyBearer({ headers: {} }, { url: 'x' }, 'T').auth, undefined);
  });
});

// ─── ② 登记表 + refreshOnce 计数 ───
describe('[bearerKeeper] 登记表与计数', () => {
  test('register 需要 url；重复登记不覆盖状态；release 与 refreshActive 成对', () => {
    const id = newScanId();
    assert.equal(registerScanRefresh(id, {}), null, '缺 url 不登记');
    assert.equal(registerScanRefresh('', { url: 'http://a/r' }), null, '缺 scanId 不登记');
    assert.equal(refreshActiveForScan(id), false);
    assert.ok(registerScanRefresh(id, { url: 'http://a/r' }));
    assert.equal(refreshActiveForScan(id), true);
    const first = getScanRefresh(id);
    registerScanRefresh(id, { url: 'http://b/r' });
    assert.equal(getScanRefresh(id), first, '重复登记不得换掉已有 token/计数（状态只有一份真相）');
    assert.equal(setRefreshObserver(id, () => {}), true);
    releaseScanRefresh(id);
    assert.equal(refreshActiveForScan(id), false);
    assert.equal(setRefreshObserver(id, () => {}), false, '未登记时接线失败必须可判');
    assert.equal(refreshActiveForScan(null), false);
  });

  test('refreshOnce：成功计 successes，失败计 failures 并留 lastWhy，两侧同源', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh', tokenField: 'data.access_token' });
    const evs = [];
    assert.equal(setRefreshObserver(id, (e) => evs.push(e)), true);
    const { client } = fakeClient({
      refresh: () => ({ status: 200, data: JSON.stringify({ data: { access_token: 'NEW' } }) }),
      target: () => ({ status: 200, data: 'ok' }),
    });
    assert.deepEqual(await refreshOnce(id, client), { ok: true, why: '' });
    assert.equal(getScanRefresh(id).token, 'NEW');
    assert.equal(evs.length, 1);
    assert.equal(evs[0].ok, true);

    const bad = fakeClient({ refresh: () => ({ status: 400, data: '{}' }), target: () => ({ status: 200, data: 'x' }) });
    const f = await refreshOnce(id, bad.client);
    assert.equal(f.ok, false);
    assert.match(f.why, /400/);
    const st = getScanRefresh(id);
    assert.equal(st.attempts, 2);
    assert.equal(st.successes, 1);
    assert.equal(st.failures, 1);
    assert.equal(st.lastWhy, f.why, 'entry.lastWhy 必须与回传给守卫的是同一句话');
    assert.equal(evs[1].ok, false);
    releaseScanRefresh(id);
  });

  test('refreshOnce：拿到 200 但 body 里没有 token ⇒ 失败且不发第二趟', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh' });
    const { client, log } = fakeClient({
      refresh: () => ({ status: 200, data: JSON.stringify({ code: 0, msg: 'ok' }) }),
      target: () => ({ status: 200, data: 'x' }),
    });
    const r = await refreshOnce(id, client);
    assert.equal(r.ok, false);
    assert.match(r.why, /没有可用 token/);
    assert.equal(getScanRefresh(id).token, null);
    assert.equal(log.length, 1);
    releaseScanRefresh(id);
  });

  test('refreshOnce：网络异常不得冒泡打断发包，折算成失败计数', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh' });
    const evs = [];
    setRefreshObserver(id, (e) => evs.push(e));
    const r = await refreshOnce(id, { async request() { throw new Error('ECONNREFUSED'); } });
    assert.equal(r.ok, false);
    assert.match(r.why, /ECONNREFUSED/);
    assert.equal(evs[0].status, 0, '发送失败用 status=0 表达，守卫侧才不会把它当成"端点返回 0"');
    assert.equal(getScanRefresh(id).failures, 1);
    releaseScanRefresh(id);
  });

  test('观察者故障绝不影响发包（观察者只是旁证）', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh', tokenField: 'token' });
    setRefreshObserver(id, () => { throw new Error('observer boom'); });
    const { client } = fakeClient({ refresh: () => ({ status: 200, data: '{"token":"T"}' }), target: () => ({ status: 200, data: 'x' }) });
    assert.deepEqual(await refreshOnce(id, client), { ok: true, why: '' });
    releaseScanRefresh(id);
  });
});

// ─── ③ withBearerRefresh 行为 ───
describe('[bearerKeeper] withBearerRefresh 行为', () => {
  test('401 ⇒ 续期 ⇒ 重试一次即成功；续期端点只被打一次，重试带新 token', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh', tokenField: 'token' });
    let refreshHits = 0;
    const { client, log } = fakeClient({
      refresh: () => { refreshHits++; return { status: 200, data: JSON.stringify({ token: 'NEW' }) }; },
      target: (o, n) => (n === 1 ? { status: 401, data: 'expired' } : { status: 200, data: 'auth=' + (o.headers || {}).Authorization }),
    });
    const view = withBearerRefresh(client, id);
    const res = await view.request({ method: 'GET', url: 'http://t/api/item?id=1' });
    assert.equal(res.status, 200);
    assert.match(res.data, /auth=Bearer NEW/);
    assert.equal(refreshHits, 1);
    assert.equal(log.length, 3, '原请求 + 续期 + 重试 = 3 条');
    releaseScanRefresh(id);
  });

  test('续期后仍 401 ⇒ 放行，且绝不续第二次（不给客户认证服务加压）', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh', tokenField: 'token' });
    let refreshHits = 0;
    const { client, log } = fakeClient({
      refresh: () => { refreshHits++; return { status: 200, data: JSON.stringify({ token: 'NEW' }) }; },
      target: () => ({ status: 403, data: 'still forbidden' }),
    });
    const view = withBearerRefresh(client, id);
    const res = await view.request({ url: 'http://t/api' });
    assert.equal(res.status, 403, '续期救不回来时必须放行原响应，让 authLost 按既有口径收尾');
    assert.equal(refreshHits, 1, `一次挑战只允许一次续期，实际 ${refreshHits} 次`);
    assert.equal(log.length, 3, `应停在 3 条（原+续+重试），实际 ${log.length} 条 = 在循环`);
    releaseScanRefresh(id);
  });

  test('续期失败 ⇒ 原样放行 401 且不再发目标请求', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh' });
    const { client, log } = fakeClient({
      refresh: () => ({ status: 500, data: 'auth service down' }),
      target: () => ({ status: 401, data: 'expired' }),
    });
    const view = withBearerRefresh(client, id);
    const res = await view.request({ url: 'http://t/api' });
    assert.equal(res.status, 401);
    assert.equal(log.filter((o) => !String(o.url).includes(REFRESH_PATH)).length, 1, '续期失败不得再发目标请求');
    assert.equal(getScanRefresh(id).failures, 1);
    releaseScanRefresh(id);
  });

  test('口径①：没拿到新 token 之前，绝不覆盖用户带来的 Authorization', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh' });
    const { client, log } = fakeClient({
      refresh: () => ({ status: 400, data: '{}' }),
      target: () => ({ status: 401, data: 'x' }),
    });
    const view = withBearerRefresh(client, id);
    const res = await view.request({ url: 'http://t/api', headers: { Authorization: 'Bearer FROM-PACKET' } });
    assert.equal(res.status, 401);
    const t = log.filter((o) => !String(o.url).includes(REFRESH_PATH));
    assert.equal(t.length, 1, '续期失败 ⇒ 一次都不重试');
    assert.equal(t[0].headers.Authorization, 'Bearer FROM-PACKET', '把一个还能用的抓包 token 换成空的，比不配更糟');
    releaseScanRefresh(id);
  });

  test('拿到 token 后覆盖抓包头（那个头正是过期的那个），且后续请求零额外开销', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh', tokenField: 'access_token' });
    let refreshHits = 0;
    const { client, log } = fakeClient({
      refresh: () => { refreshHits++; return { status: 200, data: JSON.stringify({ access_token: 'NEW' }) }; },
      target: (o) => ({ status: 200, data: 'auth=' + ((o.headers || {}).Authorization || 'none') }),
    });
    const view = withBearerRefresh(client, id);
    const r1 = await view.request({ url: 'http://t/a', headers: { Authorization: 'Bearer OLD' } });
    assert.equal(r1.data, 'auth=Bearer OLD', '首取未挑战 ⇒ 不动原头');
    const before = log.length;
    const r2 = await view.request({ url: 'http://t/b', headers: { Authorization: 'Bearer OLD' } });
    assert.equal(r2.data, 'auth=Bearer OLD', '手里仍无 token ⇒ 继续不动');
    assert.equal(log.length - before, 1, '没有挑战就不该产生任何续期请求');
    // 现在过期了：401 → 续期 → 重试必须带 NEW
    const { client: c2, log: l2 } = fakeClient({
      refresh: () => { refreshHits++; return { status: 200, data: JSON.stringify({ access_token: 'NEW' }) }; },
      target: (o, n) => (n === 1 ? { status: 401, data: 'x' } : { status: 200, data: 'auth=' + (o.headers || {}).Authorization }),
    });
    const v2 = withBearerRefresh(c2, id);
    const r3 = await v2.request({ url: 'http://t/c', headers: { Authorization: 'Bearer OLD' } });
    assert.equal(r3.data, 'auth=Bearer NEW', '续期成功后重试必须换成新 token');
    assert.equal(refreshHits, 1, '登记后第二次续期不该发生（token 已在 entry 里）');
    assert.equal(l2.length, 3);
    releaseScanRefresh(id);
  });

  test('并发去重：20 条同时 401 只打一次续期端点', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh', tokenField: 'token' });
    let refreshHits = 0;
    const client = {
      async request(o) {
        if (String(o.url).includes(REFRESH_PATH)) {
          refreshHits++;
          await delay(5);
          return { status: 200, data: JSON.stringify({ token: 'NEW' }) };
        }
        return (o.headers || {}).Authorization === 'Bearer NEW' ? { status: 200, data: 'ok' } : { status: 401, data: 'x' };
      },
    };
    const view = withBearerRefresh(client, id);
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => view.request({ url: `http://t/api?i=${i}` })));
    assert.deepEqual(rs.map((r) => r.status), Array(20).fill(200));
    assert.equal(refreshHits, 1, `并发去重失效：实际打了 ${refreshHits} 次`);
    releaseScanRefresh(id);
  });

  test('eager:true 前置一次续期；默认档零前置请求（不给每个目标多打认证端点）', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh', tokenField: 'token', eager: true });
    const { client, log } = fakeClient({
      refresh: () => ({ status: 200, data: JSON.stringify({ token: 'NEW' }) }),
      target: () => ({ status: 200, data: 'ok' }),
    });
    const view = withBearerRefresh(client, id);
    assert.equal((await view.request({ url: 'http://t/api' })).status, 200);
    assert.equal(log[0].url, 'http://a/refresh', 'eager 模式第一条必须是续期请求');
    assert.equal(log[1].headers.Authorization, 'Bearer NEW');
    releaseScanRefresh(id);

    const id2 = newScanId();
    registerScanRefresh(id2, { url: 'http://a/refresh', tokenField: 'token' });
    const c2 = fakeClient({
      refresh: () => ({ status: 200, data: JSON.stringify({ token: 'NEW' }) }),
      target: () => ({ status: 200, data: 'ok' }),
    });
    const v2 = withBearerRefresh(c2.client, id2);
    await v2.request({ url: 'http://t/api' });
    assert.equal(c2.log.length, 1, '默认档不该前置续期请求');
    assert.equal(c2.log[0].headers, undefined);
    releaseScanRefresh(id2);
  });

  test('未登记 scanId ⇒ 原样返回视图（零配置零行为变化）', async () => {
    const client = { request: async () => ({ status: 401, data: 'x' }) };
    assert.equal(withBearerRefresh(client, newScanId()), client);
  });

  test('headRequest 保留且同样续期（不复制 TODO §10 那三个包装的缺陷）', async () => {
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh', tokenField: 'token' });
    const { client, log } = fakeClient({
      refresh: () => ({ status: 200, data: JSON.stringify({ token: 'NEW' }) }),
      target: () => ({ status: 200, data: 'never' }),
      head: (o, n) => ((o.headers || {}).Authorization === 'Bearer NEW'
        ? { status: 200, headers: {}, data: 'head-ok' }
        : { status: 401, headers: {}, data: 'head-gone' }),
    });
    const view = withBearerRefresh(client, id);
    assert.equal(typeof view.headRequest, 'function', '包装层丢了 headRequest ⇒ --null-connection 静默降级成 GET');
    const r = await view.headRequest('http://t/api', { headers: { Accept: '*/*' } });
    assert.equal(r.data, 'head-ok', 'HEAD 也必须走「挑战→续期→重试」');
    const heads = log.filter((o) => o.method === 'HEAD');
    assert.equal(heads.length, 2, `原 HEAD + 重试 HEAD = 2，实际 ${heads.length}`);
    assert.equal(heads[1].headers.Accept, '*/*', '重试必须带上原请求头');
    assert.equal(getScanRefresh(id).successes, 1);
    releaseScanRefresh(id);
  });

  test('反向：摘掉「一次挑战只重试一次」会立刻变成循环 —— 用计数上限钉住', async () => {
    // 这条不改动生产代码，只用一个"续期永远成功、目标永远 401"的桩把上限定量：
    // 若哪天把重试改成 while 或去掉了 ok 判定，log.length 会超过 3 而这里红。
    const id = newScanId();
    registerScanRefresh(id, { url: 'http://a/refresh', tokenField: 'token' });
    const { client, log } = fakeClient({
      refresh: () => ({ status: 200, data: JSON.stringify({ token: 'NEW' }) }),
      target: () => ({ status: 401, data: 'x' }),
    });
    const view = withBearerRefresh(client, id);
    await view.request({ url: 'http://t/api' });
    assert.equal(log.length, 3);
    assert.equal(log.filter((o) => String(o.url).includes(REFRESH_PATH)).length, 1);
    releaseScanRefresh(id);
  });
});
