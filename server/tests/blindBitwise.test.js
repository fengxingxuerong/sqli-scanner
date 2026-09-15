// blindBitwise 单测：mock 通道下位平面收敛正确性 + 默认关闭零回归
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractBoolean } from '../src/engine/blindExtractor.js';

// mock：支持 LENGTH 长度二分 + BIT_COUNT 位平面探测 + ASCII 等值验证 + false 基准
function makeMock(secret) {
  const state = { count: 0 };
  const httpClient = {
    async request(opts) {
      state.count++;
      const url = String(opts.url || '');
      const m = /id=1 AND (.+?)-- -/.exec(decodeURIComponent(url));
      if (!m) return { data: 'base', status: 200 };
      const cond = m[1];
      if (cond === '1=2') return { data: 'FALSEPAGE', status: 200 };
      // LENGTH 长度二分：(LENGTH((SELECT ...)))>N → true/false（宽松匹配 LENGTH...>N）
      const lm = /LENGTH\(\(SELECT username FROM users WHERE id = 2\)\)\)>(\d+)/.exec(cond);
      if (lm) {
        const n = Number(lm[1]);
        return { data: secret.length > n ? 'TRUEPAGE' : 'FALSEPAGE', status: 200 };
      }
      // BIT_COUNT 位平面探测
      const bc = /BIT_COUNT\(CONV\(HEX\(SUBSTRING\(\(?SELECT username FROM users WHERE id = 2\)?,(\d+),1\)\),16,10\) & (\d+)\)/.exec(cond);
      if (bc) {
        const pos = Number(bc[1]);
        const mask = Number(bc[2]);
        const byte = pos <= secret.length ? secret.charCodeAt(pos - 1) : 0;
        return { data: (byte & mask) !== 0 ? 'TRUEPAGE' : 'FALSEPAGE', status: 200 };
      }
      // ASCII 字符比较二分：ASCII(SUBSTRING((SELECT ...),pos,1))>N → true/false
      const gt = /ASCII\(SUBSTRING\(\(SELECT username FROM users WHERE id = 2\),(\d+),1\)\)>(\d+)/.exec(cond);
      if (gt) {
        const pos = Number(gt[1]);
        const n = Number(gt[2]);
        const byte = pos <= secret.length ? secret.charCodeAt(pos - 1) : 0;
        return { data: byte > n ? 'TRUEPAGE' : 'FALSEPAGE', status: 200 };
      }
      // ASCII 等值验证
      const eq = /ASCII\(SUBSTRING\(\(SELECT username FROM users WHERE id = 2\),(\d+),1\)\)=(\d+)/.exec(cond);
      if (eq) {
        const pos = Number(eq[1]);
        const val = Number(eq[2]);
        const byte = pos <= secret.length ? secret.charCodeAt(pos - 1) : 0;
        return { data: val === byte ? 'TRUEPAGE' : 'FALSEPAGE', status: 200 };
      }
      return { data: 'FALSEPAGE', status: 200 };
    },
  };
  return { httpClient, state };
}

test('blindBitwise：位平面提取收敛到真值', async () => {
  const secret = 'bob';
  const { httpClient, state } = makeMock(secret);
  const ctx = {
    httpClient,
    dbms: 'MySQL',
    scanId: 't1',
    config: { blindBitwise: true, predictOutput: false, blindRobust: { extractVerify: true } },
    point: { id: 'p', location: 'url', param: 'id', originalValue: '1', boundary: '' },
    target: { url: 'http://mock/num?id=1' },
  };
  const ex = {
    _extractCache: new Map(),
    // [P0-FIX] 对齐 Extractor._send 真实契约：值经 buildInjectionRequest 构造（mock 里
    // 直接把值当 query 参数拼进 URL）→ httpClient.request → 返回 { data, status }
    async _send(ctx, value, opts = {}) {
      const req = { method: 'GET', url: `http://mock/num?id=${encodeURIComponent(value)}` };
      return ctx.httpClient.request(req);
    },
  };
  const got = await extractBoolean(ex, ctx, 'SELECT username FROM users WHERE id = 2');
  assert.equal(got, secret);
  console.log(`  [bitwise] requests=${state.count}`);
});

test('blindBitwise 默认关闭：走原二分路径（mock 兼容 ASCII 二分）', async () => {
  const secret = 'bob';
  const { httpClient, state } = makeMock(secret);
  const ctx = {
    httpClient,
    dbms: 'MySQL',
    scanId: 't2',
    config: { predictOutput: false },
    point: { id: 'p', location: 'url', param: 'id', originalValue: '1', boundary: '' },
    target: { url: 'http://mock/num?id=1' },
  };
  const ex = {
    _extractCache: new Map(),
    // [P0-FIX] 对齐 Extractor._send 真实契约：值经 buildInjectionRequest 构造（mock 里
    // 直接把值当 query 参数拼进 URL）→ httpClient.request → 返回 { data, status }
    async _send(ctx, value, opts = {}) {
      const req = { method: 'GET', url: `http://mock/num?id=${encodeURIComponent(value)}` };
      return ctx.httpClient.request(req);
    },
  };
  const got = await extractBoolean(ex, ctx, 'SELECT username FROM users WHERE id = 2');
  assert.equal(got, secret);
  console.log(`  [default] requests=${state.count}`);
});
