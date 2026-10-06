// 编码参数识别（paramEncoding）单测
// 判定必须保守：误标会让该注入点的所有请求带上错误编码，把正常可注入点变成"打不动"。
// 同时要覆盖「payload 按参数语义构造、发送时再编码」这条链路的正确性。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectParamEncoding, encodeForPoint } from '../src/engine/paramEncoding.js';
import { buildInjectionRequest } from '../src/engine/injection.js';
import { createTarget } from '../src/engine/models.js';

test('base64 参数：解码出更短的可打印明文 → 识别', () => {
  for (const [v, dec] of [['MQ==', '1'], ['MTIz', '123'], ['dXNlcg==', 'user'], ['YWJjZA==', 'abcd']]) {
    const r = detectParamEncoding(v);
    assert.ok(r, `${v} 应被识别为 base64`);
    assert.equal(r.encoding, 'base64');
    assert.equal(r.decoded, dec);
  }
});

test('反例：普通值不得被误识别（长度不足 / 解码非可打印 / 纯数字 / 含非法字符）', () => {
  for (const v of ['test', 'abcd', '1234', '12345678', 'order-1024', 'alice', '1', '', 'a b c']) {
    assert.equal(detectParamEncoding(v), null, `${v} 不应被识别为编码`);
  }
});

test('0x 前缀 hex 识别；裸长数字串不识别（避免把订单号当 hex）', () => {
  const r = detectParamEncoding('0x61626364');
  assert.ok(r);
  assert.equal(r.encoding, 'hex');
  assert.equal(r.decoded, 'abcd');
  assert.equal(detectParamEncoding('12345678901234'), null);
});

test('encodeForPoint：按注入点编码形态编码 payload，非编码点原样返回', () => {
  const p = "1' AND '1'='1";
  assert.equal(encodeForPoint(p, 'base64'), Buffer.from(p, 'utf8').toString('base64'));
  assert.equal(encodeForPoint(p, 'hex'), '0x' + Buffer.from(p, 'utf8').toString('hex'));
  assert.equal(encodeForPoint(p, undefined), p);
});

test('注入请求：payload 基于解码后的语义值构造，发送时整体编码（编码点真实生效链路）', () => {
  const target = createTarget({ url: 'http://lab/api?id=1', config: {} });
  // orig=解码值 '1'（TargetParser 会把 originalValue 换成语义值，rawValue 保留线上原值）
  const point = { location: 'url', param: 'id', originalValue: '1', rawValue: 'MQ==', encoding: 'base64' };
  const req = buildInjectionRequest(target, point, "1 UNION SELECT 1,2,3-- -");
  const sent = new URL(req.url).searchParams.get('id');
  // 线上形态必须是 base64，且解码回来正是语义 payload
  assert.equal(Buffer.from(sent, 'base64').toString('utf8'), "1 UNION SELECT 1,2,3-- -");
});

test('注入请求：非编码点行为不变（回归）', () => {
  const target = createTarget({ url: 'http://lab/api?id=1', config: {} });
  const point = { location: 'url', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(target, point, '1 AND 1=1');
  assert.equal(new URL(req.url).searchParams.get('id'), '1 AND 1=1');
});

test('--param-del：自定义分隔符下只替换目标参数，其余参数原样保留', () => {
  const target = createTarget({ url: 'http://lab/api?a=1;id=2;b=3', config: { paramDel: ';' } });
  const point = { location: 'url', param: 'id', originalValue: '2' };
  const req = buildInjectionRequest(target, point, '2 AND 1=1');
  const q = new URL(req.url).search.startsWith('?') ? new URL(req.url).search.slice(1) : '';
  assert.ok(q.includes('a=1'), '前序参数应保留');
  assert.ok(q.includes('b=3'), '后续参数应保留');
  assert.ok(q.includes('id=2%20AND%201%3D1') || q.includes('id=2 AND 1=1'), '目标参数应被替换为注入值');
  assert.ok(!q.includes('&'), '不应退化回 & 分隔');
});

// ———— base64url（[A2/D10] 真缺口：标准 base64 要求长度是 4 的倍数且字母表是 +/，
//      而 URL-safe 形态**常不带补齐**（`?id=dXNlcg`）、字母表是 -_（明文 `~~~` → 线上 `fn5-`）————

test('base64url 正例：无补齐的 URL-safe 值被识别，且解码到语义值', () => {
  for (const [v, dec] of [['dXNlcg', 'user'], ['dXNlciE', 'user!'], ['fn5-', '~~~'], ['Zm9vYmFy', 'foobar']]) {
    const r = detectParamEncoding(v);
    assert.ok(r, `${v} 应被识别`);
    assert.equal(r.decoded, dec, `${v} 解码结果`);
  }
});

test('base64url 反例：真实业务里带连字符/下划线的值一律不得误标（误标=该点打不动）', () => {
  for (const v of [
    'order-1024', 'test-1', 'user-name', 'hello-world', 'product-42',
    'session-abc123', '2024-01-15', 'my_file.txt', 'cafe-babe', '1234567', 'abc-', 'alice',
  ]) {
    assert.equal(detectParamEncoding(v), null, `${v} 不应被识别为编码`);
  }
});

test('字母表重叠护栏：像标准 base64 的值必须标 base64，不许被 base64url 抢走', () => {
  // `U0VDUkVULVRPS0VO`（明文 'SECRET-TOKEN'）长度是 4 的倍数、串内没有 +/ ⇒
  // 两条分支都能解出可打印明文。错标成 base64url 的后果：payload 发出去带 -_，
  // 严格 base64 解码的服务端直接解坏 ⇒ 一个正常可注入点被打不动（比漏识别贵）。
  for (const v of ['U0VDUkVULVRPS0VO', 'dXNlcg==', 'MQ==', 'aHR0cHM6Ly9leGFtcGxlLmNvbS9jYWxsYmFjaz9pZD0x']) {
    assert.equal(detectParamEncoding(v).encoding, 'base64', `${v} 应判 base64`);
  }
});

test('encodeForPoint base64url：与线上形态往返一致，且**不带补齐**、不含 +/', () => {
  assert.equal(encodeForPoint('user', 'base64url'), 'dXNlcg');
  assert.equal(encodeForPoint('~~~', 'base64url'), 'fn5-');
  const enc = encodeForPoint("1' AND '1'='1", 'base64url');
  assert.ok(!/=/.test(enc), `URL-safe 输出不该有补齐：${enc}`);
  assert.ok(!/[+/]/.test(enc), `URL-safe 输出不该有 + /：${enc}`);
  assert.equal(Buffer.from(enc, 'base64url').toString('utf8'), "1' AND '1'='1");
});

test('注入请求链路：base64url 点的线上值是 URL-safe 编码，解码回来正是语义 payload', () => {
  const target = createTarget({ url: 'http://lab/api?id=dXNlcg', config: {} });
  const point = { location: 'url', param: 'id', originalValue: 'user', rawValue: 'dXNlcg', encoding: 'base64url' };
  const req = buildInjectionRequest(target, point, "user' UNION SELECT 1,2,3-- -");
  const sent = new URL(req.url).searchParams.get('id');
  assert.ok(!/[+/]/.test(sent), `发出去不该含标准字母表字符：${sent}`);
  assert.equal(Buffer.from(sent, 'base64url').toString('utf8'), "user' UNION SELECT 1,2,3-- -");
});

test('刻意保守的下限留痕：短于 4 字符的值不识别（连 `MQ` = base64url 的 1 也不认）', () => {
  // 这不是漏做：长度 floor 降到 2 会把大量两三个字符的正常值（`a-`、`1_`、`MT`）
  // 卷进误标面，而误标的代价是"整点打不动"、漏标的代价只是"少一条通道"。
  // 用断言把这个取舍钉住 —— 要放宽必须先拿出反例集不被误标的证据。
  assert.equal(detectParamEncoding('MQ'), null);
  assert.equal(detectParamEncoding('MT'), null);
  assert.equal(detectParamEncoding('a-'), null);
});

