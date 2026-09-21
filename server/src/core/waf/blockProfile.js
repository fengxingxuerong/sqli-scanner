// ============================================================================
// blockProfile.js —— 拦截**逐词画像**与定向选链（A2 增量）
// ============================================================================
// 解决什么：`chainVerify` 原先只用两条**整串**探针（`' AND 1=1-- -` / `' AND '1'='1`）
// 判「WAF 敏不敏感」，然后 `list.slice(0, MAX_CHAINS)` **按序截断**候选链。
// 它自己注释里已写明痛点：「真实 WAF 普遍拦 `--`，探针①无论套什么链都恒 403」——
// 当时的解法是"再加一条探针"，而不是**诊断出到底拦了什么词**。
// 于是选链仍是盲选：可能把 3 个名额全花在「消除 comment 的链」上，而目标其实拦的是 `union`。
//
// 本模块做三件事：
//   ① `profileBlockedTokens`：对注入点发一组**单词级**探针，逐个判「是否被拦」→ 得到黑名单；
//   ② `TAMPER_COVERS`：tamper 插件 → 它能**消除**哪些 token 的映射（小表，覆盖常用插件）；
//   ③ `rankChainsByProfile`：按画像给候选链重排（能消除被拦词的链优先），替代按序截断。
//
// ★成本纪律★：画像要 N 个请求，所以**只在「裸探针全被拦」时才做**（见 chainVerify 的接线）。
// 目标不敏感时走原路径、零额外请求 —— 避免"为了诊断把请求数翻倍"。
//
// ⚠️ 已知局限（如实标注，不假装精确）：单词探针之间**共享分隔符**，无法完全解耦
// ——若目标连空格都拦，则所有含空格的探针都会"被拦"，画像会把 `and`/`union` 等一并
// 记为被拦。故画像的定位是**给候选链排序提供偏置**，不是"精确的规则还原"。
// ============================================================================
import { buildInjectionRequest } from '../../engine/injection.js';
import { logger } from '../logger.js';

const BLOCKED_STATUSES = new Set([403, 406, 429, 501, 503]);

/**
 * 拦截判定（与 chainVerify 同源，统一放此处以免两处口径漂移）。
 * @param {object|null} res 响应（null = 请求失败/超时）
 * @param {number} baseLen 干净基线响应体长度
 * @param {{strict?: boolean}} [opts] strict=true 只认硬拦截（状态码/拦截页文案），不看"响应体缩水"。
 *   ⚠️ 为何 strict 必须排除体缩水：[P0-FIX 2026-09-10] 实测 blind 场景（`/blind` 恒返回空页）
 *   下，payload 一旦真生效结果集本就变空/变短 → 每条链都被判"仍被拦" → 全部候选失败、
 *   重跑被跳过。**链验证要回答的是「WAF 是否放行」，不是「响应是否变短」。**
 */
export function looksBlocked(res, baseLen, { strict = false } = {}) {
  if (!res) return true;
  if (BLOCKED_STATUSES.has(res.status)) return true;
  if (strict) return /blocked by|request blocked|access denied|安全狗|拦截/i.test(String(res.data ?? ''));
  const len = String(res.data ?? '').length;
  if (baseLen > 0 && len < baseLen * 0.5) return true;
  return false;
}

/**
 * 单词级探针集。
 * 每个探针只引入**一个**可疑记号，且都以原始值为前缀（贴近真实注入位置）。
 * @type {Array<{id: string, value: (orig: string) => string, desc: string}>}
 */
export const TOKEN_PROBES = [
  { id: 'quote', value: (o) => `${o}'`, desc: '单引号（字符串闭合）' },
  { id: 'comment', value: (o) => `${o}-- -`, desc: '注释符 --' },
  { id: 'hash', value: (o) => `${o}#`, desc: '注释符 #' },
  { id: 'space', value: (o) => `${o} 1`, desc: '空格（分隔符）' },
  { id: 'and', value: (o) => `${o} AND 1`, desc: '逻辑关键字 AND' },
  { id: 'or', value: (o) => `${o} OR 1`, desc: '逻辑关键字 OR' },
  { id: 'union', value: (o) => `${o} UNION 1`, desc: '集合关键字 UNION' },
  { id: 'select', value: (o) => `${o} SELECT 1`, desc: '关键字 SELECT' },
  { id: 'sleep', value: (o) => `${o} SLEEP(1)`, desc: '时间函数 SLEEP' },
  { id: 'paren', value: (o) => `${o}(1)`, desc: '括号' },
  { id: 'comma', value: (o) => `${o},1`, desc: '逗号' },
  { id: 'cmp', value: (o) => `${o} 1=1`, desc: '比较运算符 =' },
];

/**
 * tamper 插件 → 它能消除的 token 集合。
 * 只覆盖**常用且语义明确**的插件；未列出的插件视为"不消除任何 token"
 * （排序时降权），避免给 228 个插件逐个补声明带来的维护面与误标风险。
 * @type {Record<string, string[]>}
 */
export const TAMPER_COVERS = {
  space2comment: ['space'],
  space2hash: ['space'],
  space2plus: ['space'],
  space2mysqlblank: ['space'],
  space2mssqlblank: ['space'],
  space2randomblank: ['space'],
  symboliclogical: ['and', 'or'],
  logical_operators: ['and', 'or'],
  comment: ['comment', 'hash', 'space'],
  versionedcomments: ['space'],
  versionedmorekeywords: ['union', 'select', 'and', 'or'],
  modsecversionedkeywords: ['union', 'select'],
  keywordinterleave: ['union', 'select', 'and', 'or'],
  dash2hash: ['comment'],
  charencode: ['quote', 'space', 'paren', 'comma', 'cmp'],
  charcode: ['quote', 'space', 'paren', 'comma', 'cmp'],
  chardoubleencode: ['quote', 'space', 'paren', 'comma', 'cmp'],
  percentage: ['quote', 'space', 'paren', 'comma'],
  unionalltounion: ['union'],
  lowercase: ['union', 'select', 'and', 'or', 'sleep'],
  uppercase: ['union', 'select', 'and', 'or', 'sleep'],
  randomcase: ['union', 'select', 'and', 'or', 'sleep'],
};

/** 某条链（插件数组）能消除的 token 并集 */
export function coveredTokens(plugins) {
  const out = new Set();
  for (const p of plugins || []) {
    for (const t of TAMPER_COVERS[p] || []) out.add(t);
  }
  return out;
}

/**
 * 逐词拦截画像：对每个 token 探针发一次请求，返回被拦 token 列表。
 *
 * @param {object} p
 * @param {object} p.httpClient 扫描作用域 httpClient
 * @param {object} p.target 扫描目标
 * @param {object} p.point 探测点
 * @param {object} [p.config] 扫描配置
 * @param {number} [p.baseLen] 干净基线响应体长度（不再重复发基线请求）
 * @param {number} [p.timeoutMs] 单请求超时
 * @param {number} [p.maxProbes] 预算封顶：最多发多少个探针（默认全部）
 * @returns {Promise<{blocked: string[], probed: number, error?: string}>}
 */
export async function profileBlockedTokens({
  httpClient,
  target,
  point,
  config = {},
  baseLen = 0,
  timeoutMs = 6000,
  maxProbes = TOKEN_PROBES.length,
}) {
  if (!httpClient || !target || !point) return { blocked: [], probed: 0, error: '缺少 httpClient/target/point' };
  const orig = point.originalValue || '1';
  const probes = TOKEN_PROBES.slice(0, Math.max(0, maxProbes));
  const blocked = [];
  let probed = 0;
  try {
    for (const probe of probes) {
      const req = buildInjectionRequest(target, point, probe.value(orig));
      let res = null;
      try {
        res = await httpClient.request({ ...req, timeoutMs, retry: 0, cookieJar: config.cookieJar !== false });
      } catch {
        res = null; // 失败/超时按"被拦"处理（保守，与 chainVerify 同口径）
      }
      probed++;
      // ★画像一律用 strict 判据（只看状态码 / 拦截页文案）★
      // 为什么不用"体缩水"：画像要回答的是「WAF 明确拦了哪个**词**」。而体缩水是"响应变了"
      // 而非"被拦"——一个单词探针（如 `1'`）本身就可能改变结果集。若把缩水算作被拦，
      // 一个缩水型目标会让**全部** 12 个探针都记成"被拦"，画像结论整体失真、选链被带偏
      // （此点由既有用例 waf.chainVerify 的 SHRUNK mock 暴露：它会让选链从 chain1 变成 chain2）。
      if (looksBlocked(res, baseLen, { strict: true })) blocked.push(probe.id);
    }
  } catch (e) {
    return { blocked, probed, error: e.message };
  }
  if (blocked.length) {
    logger.info(`WAF 逐词画像：${probed} 个探针中 ${blocked.length} 个被拦 → [${blocked.join(', ')}]`);
  }
  return { blocked, probed };
}

/**
 * 按画像给候选链重排：能消除被拦 token 的链优先（命中的被拦 token 越多越靠前）。
 * 纯函数，稳定排序（同分保持原顺序 —— 原顺序来自 wafRecommend 的置信度）。
 *
 * 注：`vendor` 标为**必填**，与上游契约一致（wafRecommend 的 61 厂商映射每条都带 vendor），
 * 也与 `verifyTamperChains` 的 `@returns {Promise<{vendor:string,plugins:string[]}|null>}` 对齐
 * —— 首版标成可选会让调用处 TS2322（CI 实测：lint job 的 "TypeScript check (server, checkJs)"）。
 *
 * @param {Array<{vendor: string, plugins: string[]}>} chains
 * @param {string[]} blockedTokens profileBlockedTokens 的输出
 * @returns {Array<{vendor: string, plugins: string[]}>} 重排后的新数组（不改原数组）
 */
export function rankChainsByProfile(chains, blockedTokens) {
  const list = Array.isArray(chains) ? chains.filter((c) => c && Array.isArray(c.plugins) && c.plugins.length) : [];
  if (!Array.isArray(blockedTokens) || blockedTokens.length === 0 || list.length === 0) return list.slice();
  const set = new Set(blockedTokens);
  return list
    .map((c, idx) => {
      const covered = coveredTokens(c.plugins);
      let hit = 0;
      for (const t of set) if (covered.has(t)) hit++;
      return { c, idx, hit };
    })
    .sort((a, b) => (b.hit - a.hit) || (a.idx - b.idx)) // 命中多者优先；同分按原序（稳定）
    .map((x) => x.c);
}

export default { profileBlockedTokens, rankChainsByProfile, looksBlocked, TAMPER_COVERS, TOKEN_PROBES };
