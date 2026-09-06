// WAF tamper 链动态验证单测（[P1-FIX 2026-09-05] P1-6：从"猜链"到"验链"）
// mock 分流依据（关键坑，均为实测）：
//   1) buildInjectionRequest 经 URLSearchParams 序列化：空格→'+'、单引号不编码；
//      charencode payload 的 %27 会再被编码为 %2527（双重编码特征）。
//   2) decodeURIComponent 不解码 '+' → 断言前须 replace(/\+/g,' ')。
//   探针 `1' AND 1=1-- -` 各形态：
//   裸 → "AND 1=1"；链1 equaltolike → "LIKE"（= 替换必变形；注：space2comment/between 引号状态机/模式匹配
//   对未闭合引号 payload 空转，不适合做 mock 链）；链2 charencode → 原始 URL 含 %2527。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyTamperChains } from '../src/core/waf/chainVerify.js';

const target = { url: 'http://mock.test/?id=1', baseUrl: 'http://mock.test/?id=1', method: 'GET' };
const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };
const chains = [
  { vendor: 'cloudflare', plugins: ['equaltolike'] },
  { vendor: 'cloudflare', plugins: ['charencode'] },
];

const OK = () => ({ status: 200, data: 'ok page content ' + 'x'.repeat(200) });
const BLOCKED = () => ({ status: 403, data: 'blocked' });
const SHRUNK = () => ({ status: 200, data: 'x' }); // 软拦截：体缩水 >50%

function classify(opts) {
  const url = String(opts.url || '');
  const dec = decodeURIComponent(url).replace(/\+/g, ' ');
  if (dec.includes('LIKE')) return 'chain1';
  if (/%2527/.test(url)) return 'chain2';
  if (dec.includes('AND 1=1')) return 'raw';
  return 'baseline';
}

function makeClient(map) {
  return {
    async request(opts) {
      const r = map[classify(opts)] || OK;
      return typeof r === 'function' ? r() : r;
    },
  };
}

test('裸探针未被拦 → 保守返回首条链（对齐旧行为）', async () => {
  const out = await verifyTamperChains({
    httpClient: makeClient({ raw: OK }),
    target, point, chains,
  });
  assert.deepEqual(out.plugins, ['equaltolike']);
});

test('裸探针被拦 + 链1放行 → 返回链1', async () => {
  const out = await verifyTamperChains({
    httpClient: makeClient({ raw: BLOCKED }),
    target, point, chains,
  });
  assert.deepEqual(out.plugins, ['equaltolike']);
});

test('裸探针被拦 + 链1被拦 + 链2放行 → 返回链2', async () => {
  const out = await verifyTamperChains({
    httpClient: makeClient({ raw: BLOCKED, chain1: BLOCKED }),
    target, point, chains,
  });
  assert.deepEqual(out.plugins, ['charencode']);
});

test('全部链被拦 → 返回 null（跳过重跑，省掉注定失败的请求）', async () => {
  const out = await verifyTamperChains({
    httpClient: makeClient({ raw: BLOCKED, chain1: BLOCKED, chain2: BLOCKED }),
    target, point, chains,
  });
  assert.equal(out, null);
});

test('目标不可达 → 返回 null', async () => {
  const out = await verifyTamperChains({
    httpClient: { async request() { throw new Error('ECONNREFUSED'); } },
    target, point, chains,
  });
  assert.equal(out, null);
});

test('验证器内部异常 → 保守回退首条链', async () => {
  const bad = {
    async request(opts) {
      if (classify(opts) === 'raw') throw new Error('boom');
      return OK();
    },
  };
  const out = await verifyTamperChains({ httpClient: bad, target, point, chains });
  assert.deepEqual(out.plugins, ['equaltolike']);
});

test('响应体缩水 50% 判定拦截（无 403 状态码的软拦截）', async () => {
  let first = true;
  const client = {
    async request() {
      if (first) { first = false; return OK(); } // 首请求=基线
      return SHRUNK(); // 其后所有注入请求均缩水
    },
  };
  const out = await verifyTamperChains({ httpClient: client, target, point, chains });
  assert.equal(out, null);
});
