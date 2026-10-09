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
import { verifyTamperChains, pickChainsToVerify } from '../src/core/waf/chainVerify.js';
import { ENCODING_FALLBACK_VENDOR } from '../src/core/waf/wafRecommend.js';
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

// ── D20：编码兜底链必须**显式占**一个验证名额 ────────────────────────────────
// 真回归（CI acceptance 连续 3 个 run 同场景红，D19 修好）：`waf403`（关键字即拦）要靠
// 「候选中有一条能过 WAF」才换 boolean 通道重跑。那条链一直是 `chardoubleencode`（双重 URL 编码，
// 靶场只解一次码 ⇒ 能过）。D14 时它"恰好"排在静态链前 2 里 ⇒ 蒙对；D15 放行 41 件未分类弹药后
// 它掉到 codec 序列第 30+ ⇒ 被切片丢掉 ⇒ 漏检。
// ⇒ 结论：**兜底能力必须显式保底，不能靠排序争**（与 planChainsByProfile 同源纪律）。
// ⚠️ D18 试过用 `chain.isCodec` 识别 —— 无效，因为该字段只由**动态生成的链**携带，
//    静态链（来自静态候选表）没有它 ⇒ 保底分支恒不触发。现改为**显式 vendor 标记**。

test('★ D20：编码兜底链必须进验证名单（按显式标记识别，不靠排序）', () => {
  const V = ENCODING_FALLBACK_VENDOR;
  const merged = [
    { vendor: 'generic_block', plugins: ['modsecurityversionedkeywords'] },
    { vendor: 'generic_block', plugins: ['nonrecursivereplace'] },
    { vendor: V, plugins: ['chardoubleencode'] },
  ];
  const picked = pickChainsToVerify(merged, { maxChains: 3, generatedSlots: 1 });
  assert.ok(
    picked.some((c) => c.vendor === V),
    `兜底链被挤出验证名单 ⇒ 关键字即拦的场景会漏检：${JSON.stringify(picked)}`,
  );
  // 名额来自 slots（3-1=2）：本用例没有生成链 ⇒ 总数就是 2（不能凭空多出）。
  // 兜底链不在前 slots 内 ⇒ 走"替换末条"保底 ⇒ 仍是 2。
  assert.equal(picked.length, 2, `不得超预算：实得 ${picked.length}`);
});

test('D20 反向钉子：候选里没有兜底链时行为不变（仍是前 slots 条，不凭空造链）', () => {
  const merged = [
    { vendor: 'generic_block', plugins: ['a'] },
    { vendor: 'generic_block', plugins: ['b'] },
    { vendor: 'generic_block', plugins: ['c'] },
  ];
  const picked = pickChainsToVerify(merged, { maxChains: 3, generatedSlots: 1 });
  assert.deepEqual(picked.map((c) => c.plugins[0]), ['a', 'b']);
});

test('D20 兜底链已在名单内时**不改顺序**（先试最有希望的 ⇒ 省请求）', () => {
  const V = ENCODING_FALLBACK_VENDOR;
  const merged = [
    { vendor: V, plugins: ['chardoubleencode'] },
    { vendor: 'generic_block', plugins: ['a'] },
    { vendor: 'generic_block', plugins: ['b'] },
  ];
  const picked = pickChainsToVerify(merged, { maxChains: 3, generatedSlots: 1 });
  assert.deepEqual(picked.map((c) => c.plugins[0]), ['chardoubleencode', 'a'], '顺序不得被改动');
});

test('D20 生成链名额不被兜底保底挤占（总数仍等于预算）', () => {
  const V = ENCODING_FALLBACK_VENDOR;
  const merged = [
    { vendor: 'generic_block', plugins: ['a'] },
    { vendor: 'generic_block', plugins: ['b'] },
    { vendor: V, plugins: ['chardoubleencode'] },
    { vendor: 'bypass:auto', plugins: ['g1'] },
  ];
  const picked = pickChainsToVerify(merged, { maxChains: 3, generatedSlots: 1 });
  assert.equal(picked.length, 3, `名额总数应为 3：${JSON.stringify(picked.map((c) => c.plugins[0]))}`);
  assert.ok(picked.some((c) => c.vendor === V), '兜底链必须在名单里');
  assert.ok(picked.some((c) => c.vendor === 'bypass:auto'), '生成链名额必须保留');
});

// ── 不变式：输出**恒不超预算**（防下游二次截断静默吃掉保底）────────────────────
// [实测 2026-10-10] 曾把 pickChainsToVerify 改成"兜底追加在末尾"（返回 4 条）：
//   本文件的纯函数用例全绿，但 `verifyTamperChains` 第 194 行还有一道
//   `ranked.slice(0, MAX_CHAINS)` ⇒ 第 4 条（正是兜底链）被**静默切掉**，真机上保底彻底失效
//   ——比"替换末条"更糟（替换至少保证了兜底在预算内被验证）。
// ⇒ 教训：保底只能**占名额**，不能靠追加；且"返回值长度"这条不变式必须有测试守着，
//   否则纯函数测试绿、生产路径坏（本仓第三次栽在同一类"两层之间无守卫"上）。
test('★ 不变式：pickChainsToVerify 输出在任何入参下都不得超过 maxChains', () => {
  const V = ENCODING_FALLBACK_VENDOR;
  const pools = [
    [], // 空池
    [{ vendor: 'generic_block', plugins: ['a'] }],
    // 兜底在池尾 + 有生成链（最容易被"追加"实现撑爆的组合）
    [
      { vendor: 'generic_block', plugins: ['a'] },
      { vendor: 'generic_block', plugins: ['b'] },
      { vendor: 'generic_block', plugins: ['c'] },
      { vendor: V, plugins: ['chardoubleencode'] },
      { vendor: 'bypass:auto', plugins: ['g1'] },
      { vendor: 'bypass:auto', plugins: ['g2'] },
    ],
  ];
  for (const merged of pools) {
    for (const [maxChains, generatedSlots] of [[3, 1], [4, 1], [5, 2], [2, 1], [1, 1], [3, 0]]) {
      const picked = pickChainsToVerify(merged, { maxChains, generatedSlots });
      assert.ok(
        picked.length <= maxChains,
        `超预算 ⇒ 多出的条目会被 verifyTamperChains 的 slice 静默切掉：` +
          `maxChains=${maxChains} generatedSlots=${generatedSlots} 实得 ${picked.length} ` +
          JSON.stringify(picked.map((c) => c.plugins[0])),
      );
    }
  }
});

test('★ 兜底不在前 slots 时，保底必须落在预算**内**（追加式实现会让它在真机上被切掉）', () => {
  const V = ENCODING_FALLBACK_VENDOR;
  const merged = [
    { vendor: 'generic_block', plugins: ['a'] },
    { vendor: 'generic_block', plugins: ['b'] },
    { vendor: V, plugins: ['chardoubleencode'] }, // 静态链第 3 位 ⇒ slots=2 取不到
    { vendor: 'bypass:auto', plugins: ['g1'] },
  ];
  const picked = pickChainsToVerify(merged, { maxChains: 3, generatedSlots: 1 });
  assert.equal(picked.length, 3, `必须是 3（预算内），追加式实现会返回 4 然后被 slice 切掉：实得 ${picked.length}`);
  assert.ok(picked.some((c) => c.vendor === V), '兜底链必须在**会被真正验证**的那几条里');
  assert.ok(picked.some((c) => c.vendor === 'bypass:auto'), '生成链名额必须保留');
});

// ── 已知缺口（不是本文件能修的，见 TODO 15.1）────────────────────────────────
// `e2e/pentest-lab` 的 `waf403` 场景（关键字即拦，靶场服务端只解一次码）：
//   · 真实逐词画像被拦 = [comment, and, or, union, select, sleep]；
//   · `chardoubleencode` 因 D19 把它的 TAMPER_COVERS 补成"关键词全覆盖"，
//     hit 最高 ⇒ 排序后**稳居池子第 0**，是第一条被验证、也第一条放行的链 ⇒ 被选中重跑；
//   · 但它过了 WAF 之后落到 MySQL 是 `%61%6e%64` 这类碎片（服务端只解一次码）
//     ⇒ error 通道有信号，boolean 要的"真/假两侧同形且结果不同"物理不可达
//     ⇒ waf403 的 must:['boolean'] 确定性红（D29 三轮一致，非抖动）。
//   · 真正能用的是 `symboliclogical`（AND→&& / OR→||，语义等价），显式指定时
//     实测 842ms 拿到 boolean；但它是静态链**第 3** 位，而 slots = maxChains - generatedSlots = 2
//     ⇒ 它根本进不了验证名单（与保底逻辑无关，保底分支在真实池子下从未触发）。
// ⚠️ 由此得到的判据：**不是"能不能过 WAF"，而是"过了还能不能用"**。
//   任何"让兜底链排得更前"的改动都在加剧这个缺口；反过来要让语义等价链进得了 slots，
//   必须动 COVERS 口径（D19 的支点，有回归风险）⇒ 单独立项真机验证，不在此处顺手改。
