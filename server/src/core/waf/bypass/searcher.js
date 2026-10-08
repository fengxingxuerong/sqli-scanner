// ============================================================================
// searcher.js —— 定向变异：按「被拦词表」**组合生成**候选链（A2 的真缺口部分）
//
// ■ 先划清分工（核实于 2026-09-22，避免第三次重复造轮子）
//   A2 原计划五步，核实后前三步**已经存在**，且都写在 core/waf/ 里：
//     · 拦截画像（逐词探针 → 黑名单）  → blockProfile.profileBlockedTokens ✅
//     · 预算封顶（maxProbes / MAX_CHAINS） → blockProfile / chainVerify ✅
//     · 按画像排序（能消除被拦词的链优先）→ blockProfile.rankChainsByProfile ✅
//     · 逐链探针验证（strict 判据放行）  → chainVerify.verifyTamperChains ✅
//   → **本模块不重复以上任何一条。**
//
// ■ 本模块只补真正的缺口 ①：候选**只来自静态推荐表**（wafRecommend 的 3 条），
//   `rankChainsByProfile` 只是给这 3 条**重排** —— 搜索空间仍是"3 条里挑"，
//   而不是"按黑名单从 228 个插件里组合"。本例：目标拦 `union`+`select` 时，
//   静态表里可能根本没有"同时消除 union 与 select 且不引入新标点"的那条链。
//   → 本模块用 semantics 索引（T1）作为弹药库，组合出候选并排序。
//   [批次C 2026-10-03] 组合维度从「单/双」扩到「单/双/三 + 减标点补位」：
//   covers=0 的 reducesPunct 插件（dash2hash，CRS 标点预算方向唯一实证有效项）此前
//   进不了候选池，实证首选链 dash2hash×hexliterals（两序）不可能被生成；被拦词族 ≥3
//   时双链覆盖不满。两个缺口同日修（新增用例见 waf.bypassSearcher.test.js 的
//   「减标点补位」「三链组合」两条）。
//
// ■ 缺口 ②（链**有效性**验证）与 ③（交战记录入报告）不在本模块：②属 chainVerify 的
//   判据扩展（需真靶场验收），③属报告层。两者均已在待办卡里单列，勿在此处夹带实现。
//
// ■ 纯函数：不发请求、无 I/O。请求预算的消耗由调用方（chainVerify）决定 ——
//   本模块只保证"给出的顺序值得优先花预算"。
// ============================================================================

import { tamperRegistry } from '../../tamper/TamperRegistry.js';
import {
  selectByAvoiding,
  buildSemanticIndex,
  estimatePunctCost,
  isSemanticallyUnsafe,
  SEMANTIC_CATEGORIES,
} from './semantics.js';
// [接线 2026-09-23] 复用既有「按画像重排」判据 —— 不重写第二套排序。
// blockProfile.js 不反向 import 本模块，无循环依赖。
import { rankChainsByProfile } from '../blockProfile.js';

/**
 * 探针 id → 该探针实际引入的 token（小写，与 semantics 索引的 eliminates 口径对齐）。
 * ⚠️ 与 blockProfile.TOKEN_PROBES 的 id 集合必须一致 —— 由
 * waf.bypassSearcher.test.js 的「映射表不得腐烂」用例机械守卫。
 * @type {Record<string, string[]>}
 */
export const PROBE_TOKEN_MAP = {
  quote: ["'"],
  comment: ['--'],
  hash: ['#'],
  space: [' ', '\t'],
  and: ['and'],
  or: ['or'],
  union: ['union'],
  select: ['select'],
  sleep: ['sleep'],
  paren: ['('],
  comma: [','],
  cmp: ['='],
};

/**
 * 探针 id 列表 → 实际 token 列表（去重）。
 * @param {string[]} ids
 * @returns {string[]}
 */
export function probeTokensToTokens(ids = []) {
  const out = new Set();
  for (const id of ids) for (const t of PROBE_TOKEN_MAP[id] || []) out.add(t);
  return [...out];
}

/**
 * 一个插件"值不值得选"的打分：能消除的被拦 token 越多越优先，引入的标点代价越低越优先。
 *
 * `eliminatesAll`（编码族）= 整串编码后**全部明文关键词一起消失**，所以覆盖数记为被拦词总数。
 * 但它同时被标 `isCodec` —— 因为它要求目标做对应预解码才有意义，属**兜底弹药**：
 * 排序时必须整体排在"针对性消除"之后，否则会让候选池被编码类霸榜（等于退化成盲试）。
 * @param {object} meta 语义索引条目
 * @param {Set<string>} blocked 被拦 token 集合
 * @returns {{covers:number, punct:number, isCodec:boolean}}
 */
function scoreMeta(meta, blocked, fullBlocked) {
  let covers = 0;
  const isCodec = meta.eliminatesAll === true;
  if (isCodec) covers += fullBlocked.size; // 编码链覆盖整个 payload —— 与具体 token 无关，按全量计
  for (const t of meta.eliminates || []) if (blocked.has(t)) covers += 1;
  // 标点代价：把 introduces 里非词字符数当作增量的近似（精确值由 estimatePunctCost 实测）
  let punct = 0;
  for (const t of meta.introduces || []) punct += (String(t).match(/[^A-Za-z0-9_]/g) || []).length;
  return { covers, punct, isCodec };
}

/**
 * 定向生成候选链（纯函数）。
 *
 * 顺序按「覆盖被拦词数降序 → 标点代价升序 → 链长升序」：
 * 先给"能一次消掉最多被拦词"的链，同覆盖下优先不给目标添新标点（CRS 942460/942431 卡点）。
 *
 * @param {object} p
 * @param {string[]} [p.blockedTokens] 探针 id 列表（blockProfile.profileBlockedTokens 的输出）
 * @param {string} [p.dbms] 目标 DBMS（交由既有 registry 守卫复核 dbms 适用性）
 * @param {number} [p.maxChains] 最多返回多少条（默认 6；调用方通常再截到 MAX_CHAINS）
 * @param {number} [p.maxPairPool] 双插件组合的候选池上限（默认 8，防组合爆炸）
 * @param {string|null} [p.sample] 标点代价评估样本 payload（缺省 null = 不按样本收敛）
 * @returns {{chains: Array<{plugins:string[], covers:string[], punctDelta:number, source:'single'|'pair'|'pair+punct'|'punct+pair'|'triple', isCodec:boolean}>, blocked:string[], emptyReason?:string}}
 */
export function planChainsByProfile({
  blockedTokens = [],
  dbms,
  maxChains = 6,
  maxPairPool = 8,
  sample = null,
} = {}) {
  const blocked = probeTokensToTokens(blockedTokens);
  const blockedSet = new Set(blocked);
  if (blocked.length === 0) {
    return { chains: [], blocked: [], emptyReason: '无被拦词（未做画像或目标不敏感）' };
  }

  // 用 T1 的索引排除含被拦词的插件（boosted 的"加分"已由 scoreMeta 的 covers 体现，
  // 故此处不再单独持有 boosted —— 避免声明了却不用的死变量）
  const sel = selectByAvoiding(blocked, { dbms: dbms || undefined });
  const idx = buildSemanticIndex();

  // [批次 D3 2026-10-04] 覆盖率只统计**真的出现在样本里的被拦词**。
  //   画像说 WAF 拦 union/select，但验证探针（sample）里根本没有 select —— 为「消除
  //   select」的插件花候选名额就是浪费（channelPolicy 用例实测：它把原本能过的编码链
  //   挤出了唯一生成名额，整条链反而验证失败）。token 出现性按形态判：词形用  词边界，
  //   符号形用 indexOf。
  const tokenInSample = (t) => {
    if (!sample) return true; // 未给样本 ⇒ 保守地视为全部相关（既有行为）
    if (/^[a-z_]+$/.test(t)) {
      const re = new RegExp('(?:^|[^a-z0-9_])' + t + '(?:$|[^a-z0-9_])', 'i');
      return re.test(sample) || new RegExp('(^' + t + '$)', 'i').test(sample.trim());
    }
    return sample.includes(t);
  };
  const relevantBlocked = blocked.filter(tokenInSample);
  const relevantSet = new Set(relevantBlocked);
  // ⚠️ 不做「空相关早退」：编码兜底（eliminatesAll）的覆盖对象是**整个 payload**，
  //    不依赖某个具体 token —— 相关词为空时它恰恰是唯一合理的候选（channelPolicy 用例）。
  const punctSample = sample || "'1' UNION SELECT 1-- -";

  // ── 单插件候选 ──
  const singles = sel.usable
    .map((name) => {
      const meta = idx.get(name) || {};
      const s = scoreMeta(meta, relevantSet, blockedSet);
      return { name, ...s, category: meta.category };
    })
    .filter((x) => x.covers > 0) // 不消除任何被拦词的插件不进候选（那是盲试）
    .sort(
      (a, b) =>
        (Number(a.isCodec) - Number(b.isCodec)) || // 兜底弹药（全编码）整体靠后
        (b.covers - a.covers) ||
        (a.punct - b.punct) ||
        a.name.localeCompare(b.name),
    );

  const chains = [];
  const seen = new Set();
  const push = (plugins, source, isCodec = false) => {
    // [D15 2026-10-08] 链上任一插件命中「结构性破坏 SQL」不变量 ⇒ 不生成。
    //   selectByAvoiding 已经在单插件层过滤过一轮，这里是**链级**双保险：防止
    //   后续有人从别处（静态表合并、新来源）把这类插件带进来。
    //   ⚠️ 静态推荐表不走这条（真机对拍证据优先于结构判据，见 buildCandidateChains）。
    if (plugins.some(isSemanticallyUnsafe)) return;
    // [批次C 2026-10-03] 去重键改为**有序**拼接 —— 变换复合不可交换
    // （hexliterals∘dash2hash ≠ dash2hash∘hexliterals，wafRecommend 实证两种顺序都在案
    // 且都是首选链）。旧的「排序后集合键」会把两个顺序折叠成一条，静默丢掉另一序的候选。
    const key = plugins.join('+');
    if (seen.has(key)) return;
    // 交给既有守卫复核（terminal / 未注册 / dbms）—— 不自建第二套判据
    const v = tamperRegistry.validateChain(plugins, dbms ? { dbms } : {});
    if (!v.ok || v.plugins.length !== plugins.length) return;
    seen.add(key);
    const covers = new Set();
    for (const p of plugins) for (const t of (idx.get(p)?.eliminates) || []) if (relevantSet.has(t)) covers.add(t);
    chains.push({
      plugins: [...plugins],
      covers: [...covers],
      punctDelta: estimatePunctCost(plugins, punctSample).delta,
      source,
      isCodec,
    });
  };

  for (const s of singles) push([s.name], 'single', s.isCodec);

  // ── 双插件候选：只从「有覆盖」的池子里两两组合，且跳过同类别的（同类别互补性低） ──
  //    池子先排除编码类 —— 它们是 terminal 或被其截断，组合无意义（validateChain 也会挡）
  const pairPool = singles.filter((s) => !s.isCodec);
  const pool = pairPool.slice(0, Math.max(2, maxPairPool));
  for (let i = 0; i < pool.length; i++) {
    for (let j = i + 1; j < pool.length; j++) {
      if (pool[i].category === pool[j].category) continue;
      push([pool[i].name, pool[j].name], 'pair', false);
    }
  }

  // ── 减标点补位（2026-10-03 批次C）─────────────────────────────────────
  // covers=0 的 reducesPunct 插件（dash2hash）此前被 `.filter(covers > 0)` 挡在候选池外，
  // 而 CRS 系 WAF 真正卡人的是 942460/942431 的「标点预算」，wafRecommend 实测 dash2hash
  // 是该方向唯一有效项（tamper on 2/5 → 5/5），实证首选链 ['dash2hash','hexliterals'] 与
  // ['hexliterals','dash2hash'] **两个顺序都在案**（变换顺序影响输出形态，两种都赢过）。
  // ⇒ 生成器必须能把「定向消除者」与「减标点补位」组到同一条链上，两个顺序都生成。
  //    补位者单独不产生单插件链（covers=0 ⇒ 不进 singles，那是盲试）。
  const punctPool = sel.usable
    .filter((name) => (idx.get(name)?.reducesPunct) === true)
    .slice(0, 2);
  for (const s of pool.slice(0, 4)) {
    for (const pn of punctPool) {
      if ((idx.get(pn)?.category) === s.category) continue; // 同类别不互补（同上）
      push([s.name, pn], 'pair+punct', false);
      push([pn, s.name], 'punct+pair', false);
    }
  }

  // ── 三链组合：被拦词族 ≥3 时双链覆盖不满 ──
  // 典型 CRS 画像：quote + space + comment 同时被拦 —— 两个消除者 + 一个减标点补位
  // 才是一条「全覆盖」链。⚠️ 不能直接用 pool 前 3 名两两配：quote 被拦时前几名可能
  // 全是 LITERAL 类（hexliterals/quote2hex/…），同类别互相 skip ⇒ 三链恒空。
  // 正确形态：**每个类别取它的最优消除者**，再跨类别取前 2 名组合（有界：≤3 类别 ⇒
  // ≤3 个三元组；纯函数零请求，名额仍由调用方的 MAX_CHAINS 截断）。
  const bestByCat = new Map();
  for (const s of pairPool) {
    const cur = bestByCat.get(s.category);
    const better =
      !cur ||
      s.covers > cur.covers ||
      (s.covers === cur.covers && s.punct < cur.punct) ||
      (s.covers === cur.covers && s.punct === cur.punct && s.name.localeCompare(cur.name) < 0);
    if (better) bestByCat.set(s.category, s);
  }
  const catBest = [...bestByCat.values()]
    .sort((a, b) => (b.covers - a.covers) || (a.punct - b.punct) || a.name.localeCompare(b.name))
    .slice(0, 3);
  const pn0 = punctPool[0];
  const pnCat = pn0 ? (idx.get(pn0)?.category) : undefined;
  for (let i = 0; i < catBest.length; i++) {
    for (let j = i + 1; j < catBest.length; j++) {
      if (!pn0 || pnCat === catBest[i].category || pnCat === catBest[j].category) continue;
      push([catBest[i].name, catBest[j].name, pn0], 'triple', false);
    }
  }

  chains.sort(
    (a, b) =>
      (Number(a.isCodec) - Number(b.isCodec)) ||
      (b.covers.length - a.covers.length) ||
      (a.punctDelta - b.punctDelta) ||
      (a.plugins.length - b.plugins.length) ||
      a.plugins.join().localeCompare(b.plugins.join()),
  );

  // [D15] 兜底弹药**显式留一个名额**：候选池扩大后（实测派生把 48 件未分类弹药拉进来），
  //   非 codec 链轻易就能占满 maxChains，而编码兜底恰恰排在最后 ⇒ 会被静默挤出
  //   （用例「拦 and/or 时应有编码兜底链」当场抓到）。
  //   它的价值只在"针对性消除全都消不掉"时才兑现，名额必须留，不能靠排序争。
  //   （与既有纪律同源：A2 保守回退必须显式留名额，否则生成链永不验证。）
  const head = chains.filter((c) => !c.isCodec);
  const codecs = chains.filter((c) => c.isCodec);
  let out;
  if (head.length >= maxChains && codecs.length) {
    out = [...head.slice(0, Math.max(1, maxChains - 1)), codecs[0]];
  } else {
    out = [...head, ...codecs].slice(0, Math.max(1, maxChains));
  }
  return {
    chains: out,
    blocked,
    ...(out.length === 0
      ? { emptyReason: `被拦词 [${blocked.join(',')}] 无任何可用插件能消除（含未分类项已排除）` }
      : {}),
  };
}

/**
 * 把「定向生成的链」与「静态推荐链」合并成大候选池（静态链在前，保持既有行为为首选）。
 * 生成链只作**补充**，不改变静态链的相对顺序 —— 这样接线后即使新逻辑无效，
 * 行为也退化为改造前的样子（保守回退）。
 * @param {Array<{vendor?:string, plugins:string[]}>} staticChains
 * @param {Array<{vendor?:string, plugins:string[]}>} generatedChains
 * @returns {Array<{vendor:string, plugins:string[]}>}
 */
export function mergeCandidateChains(staticChains = [], generatedChains = []) {
  const out = [];
  const seen = new Set();
  for (const c of [...(staticChains || []), ...(generatedChains || [])]) {
    if (!c || !Array.isArray(c.plugins) || c.plugins.length === 0) continue;
    // [批次C 2026-10-03] 与 planChains 的 push 同口径：**有序**去重（变换复合不可交换）。
    // 旧的排序集合键会把静态表里实证过的两种顺序（OPERATOR_SWAP_CHAINS[0]/[3]）折叠成
    // 一条 —— 静态链自身就被吃掉一半，与「保守回退」的初衷相悖。
    const key = c.plugins.join('+');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ vendor: c.vendor || (c.plugins.length ? `bypass:${c.plugins.join('+')}` : 'unknown'), plugins: [...c.plugins] });
  }
  return out;
}

/**
 * 画像 → 候选池（`chainVerify` 的接线入口，也是本模块唯一被生产代码调用的函数）。
 *
 * 顺序约定（保守回退的核心）：
 *   ① 先走既有 `rankChainsByProfile` 重排静态推荐链 —— **静态链整体保持在前**；
 *   ② 再追加定向生成的补充链。
 *   ⇒ 生成链只在你"挪到后面"的位置生效：新逻辑无效时，前 MAX_CHAINS 条仍与改造前一致。
 *
 * 零额外请求：本函数只用已拿到的画像结果做纯计算，不发任何请求；
 * 请求数由调用方的 MAX_CHAINS 截断决定，与改造前相同。
 *
 * @param {Array<{vendor:string, plugins:string[]}>} staticChains wafRecommend 输出
 * @param {string[]} blockedTokens profileBlockedTokens 的输出（探针 id 列表）
 * @param {{dbms?:string, maxGenerated?:number, sample?:string|null}} [opts]
 * @returns {Array<{vendor:string, plugins:string[]}>}
 */
export function buildCandidateChains(staticChains, blockedTokens, opts = {}) {
  const list = Array.isArray(staticChains)
    ? staticChains.filter((c) => c && Array.isArray(c.plugins) && c.plugins.length)
    : [];
  // 无画像（目标不敏感 / 画像没拿到）→ 原样返回，与改造前逐字一致
  if (!Array.isArray(blockedTokens) || blockedTokens.length === 0) return list.slice();

  const ranked = rankChainsByProfile(list, blockedTokens);
  const { chains } = planChainsByProfile({
    blockedTokens,
    dbms: opts.dbms || undefined,
    maxChains: opts.maxGenerated ?? 3,
    sample: opts.sample ?? null,
  });
  return mergeCandidateChains(ranked, chains);
}

/** 供调用方判断某条链是否属于"定向生成"（报告里区分来源） */
export function isGeneratedChain(vendor) {
  return typeof vendor === 'string' && vendor.startsWith('bypass:');
}

/** 类别枚举再导出，便于调用方按上下文过滤（避免再从 semantics 深引） */
export { SEMANTIC_CATEGORIES };

export default { planChainsByProfile, mergeCandidateChains, probeTokensToTokens, PROBE_TOKEN_MAP };
