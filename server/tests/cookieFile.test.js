// ============================================================================
// server/tests/cookieFile.test.js —— cookie 文件解析与主机过滤（[D198]）
//
// 危害同源（为什么这些断言长这样）：
//   · 会话类旗标最容易「看起来生效、实际裸跑」——文件解析成空、domain 不匹配、
//     条目过期，三种都表现为扫描照跑、报告写「未检出」。所以每个「过滤掉」都要有
//     **可观察的计数**（skippedHost/skippedExpired/skippedSecure），并由本文件钉死；
//   · 凭据只发给该给的主机：domain 匹配规则（含前导点、host-only）错了就是把会话
//     送给第三方主机，因此 host-only 与子域两条都测；
//   · 格式识别不了必须**抛错**而不是返回空（静默空 = 使用者以为加载成功）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseCookieFile,
  selectCookies,
  parseCookieHeader,
  mergeCookieStrings,
  domainMatches,
  hostOf,
} from '../src/core/cookieFile.js';

const NETS_CAPE = [
  '# Netscape HTTP Cookie File',
  '# 这一行是注释，不是 cookie',
  '.example.com\tTRUE\t/\tFALSE\t0\tsid\tSECRET',
  '.example.com\tTRUE\t/\tTRUE\t0\tsectok\tS1',
  'other.test\tTRUE\t/\tFALSE\t0\tnope\tX',
  '#HttpOnly_example.com\tTRUE\t/\tFALSE\t0\thttpOnlyTok\tH1',
  'expired.test\tTRUE\t/\tFALSE\t100\tsid\tOLD',
].join('\n');

test('Netscape 格式：注释/HttpOnly 前缀/字段切分', () => {
  const { format, entries } = parseCookieFile(NETS_CAPE);
  assert.equal(format, 'netscape');
  const names = entries.map((e) => e.name).sort();
  assert.deepEqual(names, ['httpOnlyTok', 'nope', 'sectok', 'sid', 'sid'], '注释行不得进条目（sid 出现两次是两份不同域的条目）');
  const sid = entries.find((e) => e.name === 'sid' && e.domain === 'example.com');
  assert.equal(sid.value, 'SECRET');
  assert.equal(sid.httpOnly, false);
  assert.equal(entries.find((e) => e.name === 'httpOnlyTok').httpOnly, true, '#HttpOnly_ 前缀必须被识别');
  assert.equal(entries.find((e) => e.name === 'sectok').secure, true);
});

test('JSON 格式：数组与 {cookies:[…]} 包装都吃；expires 秒/毫秒都归一', () => {
  const arr = parseCookieFile(JSON.stringify([{ name: 'a', value: '1', domain: '.example.com', secure: true, expirationDate: 4102444800 }]));
  assert.equal(arr.format, 'json');
  assert.equal(arr.entries[0].domain, 'example.com', '前导点必须归一');
  assert.equal(arr.entries[0].expires, 4102444800000, '秒必须按秒解释');
  const wrapped = parseCookieFile(JSON.stringify({ cookies: [{ name: 'b', value: '2' }] }));
  assert.equal(wrapped.entries[0].name, 'b');
  assert.equal(wrapped.entries[0].domain, '', '无 domain ⇒ 通用条目');
  const msForm = parseCookieFile(JSON.stringify([{ name: 'c', value: '3', expires: 4102444800000 }]));
  assert.equal(msForm.entries[0].expires, 4102444800000, '毫秒不再乘 1000');
});

test('Cookie 头文本格式：去掉 Cookie: 前缀，无 domain ⇒ 任意主机', () => {
  const { format, entries } = parseCookieFile('Cookie: a=1; b=2');
  assert.equal(format, 'header');
  assert.deepEqual(entries.map((e) => `${e.name}=${e.value}`), ['a=1', 'b=2']);
  assert.equal(entries[0].domain, '');
});

test('识别不了/空文件必须抛错（静默返回空 = 使用者以为加载成功）', () => {
  assert.throws(() => parseCookieFile(''), /空/);
  assert.throws(() => parseCookieFile('这不是 cookie 也不是 JSON'), /无法识别/);
  assert.throws(() => parseCookieFile('[{"name":"a"}]'), /没有任何/);
  assert.throws(() => parseCookieFile('{"cookies": 5}'), /必须是数组/);
  assert.throws(() => parseCookieFile('[broken'), /JSON/);
});

test('domainMatches：host-only 精确、前导点子域、空 domain 通用', () => {
  assert.equal(domainMatches('example.com', 'example.com'), true);
  assert.equal(domainMatches('.example.com', 'www.example.com'), true);
  assert.equal(domainMatches('example.com', 'www.example.com'), true);
  assert.equal(domainMatches('example.com', 'notexample.com'), false, '后缀匹配必须按 label 边界，不能吃 notexample.com');
  assert.equal(domainMatches('', 'anything.test'), true);
  assert.equal(domainMatches('a.example.com', 'b.example.com'), false);
  assert.equal(hostOf('http://WWW.Example.com:8080/x'), 'www.example.com');
  assert.equal(hostOf('not a url'), '');
});

test('selectCookies：按主机/过期/secure 过滤并给出可观察计数', () => {
  const { entries } = parseCookieFile(NETS_CAPE);
  const now = 1_700_000_000_000;
  const http = selectCookies(entries, 'http://www.example.com/api', now);
  assert.deepEqual(http.matched.map((e) => e.name).sort(), ['httpOnlyTok', 'sid'], 'http 目标不得带 secure 条目');
  assert.equal(http.skippedSecure, 1, 'secure 条目必须以计数形式体现，不能静默消失');
  assert.equal(http.skippedHost >= 1, true, 'other.test / expired.test 至少一条因主机不符被跳过');
  assert.match(http.header, /sid=SECRET/);
  const https = selectCookies(entries, 'https://www.example.com/api', now);
  assert.equal(https.skippedSecure, 0, 'https 目标应带上 secure 条目');
  assert.match(https.header, /sectok=S1/);
  const expired = selectCookies(entries, 'http://expired.test/', now);
  assert.equal(expired.skippedExpired, 1, '过期条目必须计入 skippedExpired 而不是静默带上');
  assert.doesNotMatch(expired.header, /OLD/);
});

test('parseCookieHeader / mergeCookieStrings：显式优先、文件补齐、保序', () => {
  assert.deepEqual(parseCookieHeader('a=1; b=2'), [{ name: 'a', value: '1' }, { name: 'b', value: '2' }]);
  assert.deepEqual(parseCookieHeader('a=1; a=2').map((p) => p.value), ['2'], '同名后者覆盖');
  assert.equal(mergeCookieStrings('sid=EXPLICIT', 'sid=FILE; extra=1'), 'sid=EXPLICIT; extra=1');
  assert.equal(mergeCookieStrings('', 'x=1'), 'x=1');
  assert.equal(mergeCookieStrings('a=1', ''), 'a=1');
});

test('自证：分母非零（判据不能空转）', () => {
  const { entries } = parseCookieFile(NETS_CAPE);
  assert.ok(entries.length >= 4, `netscape 样例解析出 ${entries.length} 条，样例本身坏了`);
  const json = parseCookieFile(JSON.stringify([{ name: 'x', value: 'y' }]));
  assert.ok(json.entries.length === 1);
});
