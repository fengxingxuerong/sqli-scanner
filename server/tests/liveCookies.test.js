// ============================================================================
// server/tests/liveCookies.test.js —— 每请求重读的 cookie 文件（[D198] 对标 sqlmap --live-cookies）
//
// 本文件钉四件事，每件都对应一种「看起来在扫、实际裸跑」的失效：
//   ① **新鲜度**：文件改了，下一次请求必须带上新值（这是这个旗标存在的全部理由）；
//   ② **缓存**：文件没变时不重复解析（mtime+size），但改了必须立刻生效（缓存不能吃掉新鲜度）；
//   ③ **注入点不被顶回**：cookieParams 里的键必须排除在外，否则 cookie 型注入静默假阴性
//      —— 与 D101「注入点在 auth 里要除去同名副本」同一条纪律，方向相反；
//   ④ **读不到就如实降级**：不静默用旧值假装在扫（目标侧会 401 ⇒ 结论是不确定）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  registerLiveCookies,
  liveCookiesActiveForScan,
  liveCookieHeaderForScan,
  releaseLiveCookies,
  resetLiveCookies,
  withLiveCookies,
} from '../src/core/liveCookies.js';

let seq = 0;
const tmp = mkdtempSync(join(tmpdir(), 'sqli-livecookies-'));
process.on('exit', () => {
  try { rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
});

/** 写一份 live cookie 文件（Netscape 形态，domain 通用由 host-only 决定）。 */
function writeCookies(body) {
  const p = join(tmp, `c${++seq}.txt`);
  writeFileSync(p, body, 'utf8');
  return p;
}

/** 记录每请求 opts 的假客户端。 */
function fakeClient(seen) {
  return {
    async request(opts) { seen.push(opts); return { status: 200, data: 'ok', headers: {} }; },
    async headRequest(url, opts) { seen.push({ ...opts, url, head: true }); return { status: 200, headers: {} }; },
  };
}

test('freshness：文件改了，下一个请求必须带新值（含 headRequest 通道）', async () => {
  resetLiveCookies();
  const file = writeCookies('example.com\tTRUE\t/\tFALSE\t0\tsid\tV1');
  const seen = [];
  const client = withLiveCookies(fakeClient(seen), 'lc-fresh', { file });
  await client.request({ url: 'http://example.com/a', headers: {} });
  assert.match(seen[0].headers.Cookie, /sid=V1/);
  // 外部进程刷新令牌
  writeFileSync(file, 'example.com\tTRUE\t/\tFALSE\t0\tsid\tV2', 'utf8');
  await client.request({ url: 'http://example.com/b', headers: {} });
  assert.match(seen[1].headers.Cookie, /sid=V2/, '文件变了却没有重新读取 ⇒ 短时效会话必失效');
  await client.headRequest('http://example.com/c', {});
  assert.ok(seen[2].head === true, 'headRequest 也必须走 live 层（否则 --null-connection 型盲注不带会话）');
  assert.match(seen[2].headers.Cookie, /sid=V2/);
  releaseLiveCookies('lc-fresh');
});

test('优先级：live 文件覆盖同名静态 cookie、补齐其余、不动其它头', async () => {
  resetLiveCookies();
  const file = writeCookies('example.com\tTRUE\t/\tFALSE\t0\tsid\tFRESH\nexample.com\tTRUE\t/\tFALSE\t0\ttok\tT9');
  const seen = [];
  const client = withLiveCookies(fakeClient(seen), 'lc-merge', { file });
  await client.request({ url: 'http://example.com/a', headers: { Cookie: 'sid=STALE; keep=1', 'X-Test': 'y' } });
  const h = seen[0].headers;
  assert.equal(h.Cookie, 'sid=FRESH; tok=T9; keep=1', 'live 值优先，静态其余保留，顺序稳定');
  assert.equal(h['X-Test'], 'y', '不得改其它头');
  assert.equal(seen[0].headers === h, true);
});

test('注入点键排除：cookieParams 里的 cookie 不得被 live 覆盖（D101 同一纪律）', async () => {
  resetLiveCookies();
  const file = writeCookies('example.com\tTRUE\t/\tFALSE\t0\tuid\t1\nexample.com\tTRUE\t/\tFALSE\t0\tsid\tFRESH');
  const seen = [];
  const client = withLiveCookies(fakeClient(seen), 'lc-inj', { file, excludeNames: ['uid'] });
  await client.request({ url: 'http://example.com/a', headers: {} });
  assert.doesNotMatch(seen[0].headers.Cookie, /uid=/, 'uid 是注入点，live 不得把它顶回原值');
  assert.match(seen[0].headers.Cookie, /sid=FRESH/);
  releaseLiveCookies('lc-inj');
});

test('主机过滤：文件里别的主机的 cookie 不发给目标', async () => {
  resetLiveCookies();
  const file = writeCookies(['example.com\tTRUE\t/\tFALSE\t0\tsid\tMINE', 'other.test\tTRUE\t/\tFALSE\t0\tsecret\tLEAK'].join('\n'));
  const seen = [];
  const client = withLiveCookies(fakeClient(seen), 'lc-host', { file });
  await client.request({ url: 'http://example.com/a', headers: {} });
  assert.match(seen[0].headers.Cookie, /sid=MINE/);
  assert.doesNotMatch(seen[0].headers.Cookie, /LEAK/, 'cookie 是凭据，不得发给别的域');
  releaseLiveCookies('lc-host');
});

test('读不到/解析失败：沿用原值 + 只告警一次（不静默用旧值假装在扫）', async () => {
  resetLiveCookies();
  const seen = [];
  const client = withLiveCookies(fakeClient(seen), 'lc-missing', { file: join(tmp, 'nope-does-not-exist.txt') });
  await client.request({ url: 'http://example.com/a', headers: { Cookie: 'sid=STATIC' } });
  assert.equal(seen[0].headers.Cookie, 'sid=STATIC', '读不到文件时必须保留调用方原值，不得清空/不得假装有值');
  assert.equal(liveCookiesActiveForScan('lc-missing'), true, '登记仍在（扫描继续，结论由 401 → inconclusive 如实体现）');
  releaseLiveCookies('lc-missing');
  assert.equal(liveCookiesActiveForScan('lc-missing'), false);

  const bad = writeCookies('既不是 cookie 也不是 JSON');
  resetLiveCookies();
  registerLiveCookies('lc-bad', bad);
  assert.equal(liveCookieHeaderForScan('lc-bad', 'http://example.com/'), '', '解析失败返回空串（调用方据此不改写请求）');
  releaseLiveCookies('lc-bad');
});

test('注册表按 scanId 隔离（批量扫描不串台）', async () => {
  resetLiveCookies();
  const f1 = writeCookies('a.test\tTRUE\t/\tFALSE\t0\tsid\tA');
  const f2 = writeCookies('b.test\tTRUE\t/\tFALSE\t0\tsid\tB');
  const seen = [];
  const c1 = withLiveCookies(fakeClient(seen), 'lc-a', { file: f1 });
  const c2 = withLiveCookies(fakeClient(seen), 'lc-b', { file: f2 });
  await c1.request({ url: 'http://a.test/x', headers: {} });
  await c2.request({ url: 'http://b.test/x', headers: {} });
  assert.match(seen[0].headers.Cookie, /sid=A/);
  assert.match(seen[1].headers.Cookie, /sid=B/);
  assert.doesNotMatch(seen[1].headers.Cookie, /A/, '两个 scanId 的 cookie 不得互相污染');
  releaseLiveCookies('lc-a');
  releaseLiveCookies('lc-b');
});

test('自证：没有登记时包装器不生效（防止空转判据）', async () => {
  resetLiveCookies();
  const seen = [];
  const client = withLiveCookies(fakeClient(seen), 'lc-none', {});
  await client.request({ url: 'http://example.com/a', headers: { Cookie: 'sid=X' } });
  assert.equal(seen[0].headers.Cookie, 'sid=X');
  assert.equal(liveCookiesActiveForScan('lc-none'), false);

  // 目录不可读也只是降级，不抛（chmod 在 Windows 无效，故仅作信息，不作为断言前提）
  try { chmodSync(tmp, 0o000); } catch { /* Windows 上忽略 */ }
  try { chmodSync(tmp, 0o700); } catch { /* ignore */ }
});
