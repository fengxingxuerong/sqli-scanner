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
import { TOKEN_PROBES } from '../src/core/waf/blockProfile.js';

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
  if (/%41%4E%44/i.test(url)) return "chain2";
  // 探针族：带注释尾 与 引号闭合无注释，均属裸探针
  if (dec.includes('AND 1=1') || dec.includes("AND '1'='1")) return 'raw';
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

test('裸探针缩水判敏感；链验证阶段只认硬拦截（strict，2026-09-10 语义变更）', async () => {
  let first = true;
  const client = {
    async request() {
      if (first) { first = false; return OK(); } // 首请求=基线
      return SHRUNK(); // 其后所有注入请求均缩水
    },
  };
  const out = await verifyTamperChains({ httpClient: client, target, point, chains });
  // 变更理由：payload 一旦真正生效，结果集本就变空/变短（如恒空页的 /blind）；
  // 若链验证阶段沿用「缩水 = 被拦」，每条链都会被误判失败 → 重跑被整轮跳过（实测 CRS blind 场景）。
  // 链验证要回答的是「WAF 是否放行」，故只看状态码与拦截页文案。
  assert.deepEqual(out.plugins, ['equaltolike']);
});

test('链验证阶段命中拦截页文案 → 判被拦（硬拦截信号）', async () => {
  let first = true;
  const client = {
    async request(opts) {
      if (first) { first = false; return OK(); }
      const blocked = classify(opts) === 'raw'; // 裸探针被硬拦
      if (blocked) return { status: 200, data: 'Request blocked by OWASP CRS rule 942460' };
      return { status: 200, data: 'Request blocked by OWASP CRS rule 942100' }; // 链探针同样硬拦
    },
  };
  const out = await verifyTamperChains({ httpClient: client, target, point, chains });
  assert.equal(out, null);
});

// ══════════════════════════════════════════════════════════════════════════
// [A2-2026-09-21] 逐词画像 → 定向选链 的**接线**契约
// ══════════════════════════════════════════════════════════════════════════
// 为什么必须有这组用例：`rankChainsByProfile` 是纯函数、有它自己的单测，但"画像真的接到了
// 选链上吗"属于**调用链**问题 —— 本仓踩过「只测被调函数，入口是坏的」的坑。
// 这里的关键在于 **MAX_CHAINS=3 的截断**：候选多于 3 条时，只有进得了名额的链才会被验证，
// 所以"排序"才真正决定成败。
const chains4 = [
  { vendor: 'c1', plugins: ['equaltolike'] }, // 不覆盖任何被拦 token
  { vendor: 'c2', plugins: ['modsecversionedkeywords'] }, // 覆盖 union/select
  { vendor: 'c3', plugins: ['comment'] }, // 覆盖 comment/hash/space
  { vendor: 'c4', plugins: ['lowercase'] }, // 覆盖 union ← 本用例里**唯一**能放行的那条
];
const UNION_IDX = 6; // TOKEN_PROBES[6] = union
const lowersUnion = (opts) => {
  const dec = decodeURIComponent(String(opts.url || '')).replace(/\+/g, ' ');
  return /and 1=1/.test(dec) && !/AND 1=1/.test(dec); // lowercase 链生效后的特征
};

/** 请求时序：1 基线 → 2~3 裸探针 → 4~15 画像(12 条) → 16+ 链验证 */
function profileClient({ blockedTokens }) {
  let n = 0;
  return {
    async request(opts) {
      n++;
      if (n === 1) return OK(); // 基线
      if (n <= 3) return BLOCKED(); // 裸探针全被拦
      if (n <= 3 + TOKEN_PROBES.length) {
        const idx = n - 4;
        return blockedTokens.includes(idx) ? BLOCKED() : OK();
      }
      return lowersUnion(opts) ? OK() : BLOCKED(); // 链验证：只有 lowercase 放行
    },
  };
}

test('★接线：画像拦 union 时，可放行的那条链被挤进 MAX_CHAINS 名额 → 命中', async () => {
  const out = await verifyTamperChains({
    httpClient: profileClient({ blockedTokens: [UNION_IDX] }),
    target, point, chains: chains4,
  });
  assert.ok(out, '应命中（而不是"候选链均被拦截"）');
  assert.deepEqual(out.plugins, ['lowercase']);
});

test('对照：画像未拦任何词 → 仍按原序取前 3 条 → 唯一的可放行链落在名额之外 → 返回 null', async () => {
  const out = await verifyTamperChains({
    httpClient: profileClient({ blockedTokens: [] }),
    target, point, chains: chains4,
  });
  // 这一条正是"定向选链"的价值证明：同样的客户端、同样的 4 条候选，
  // 仅因画像为空而退回按序截断(c1/c2/c3)，唯一的可放行链 c4 就进不了验证名单。
  assert.equal(out, null);
});
