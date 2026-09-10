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
