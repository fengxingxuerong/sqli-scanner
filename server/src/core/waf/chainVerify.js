// WAF tamper 链动态验证（[P1-FIX 2026-09-05] P1-6：从"猜链"到"验链"）
//
// 背景：wafRecommend 是纯静态表（61 厂商映射），scanRunner 自动重跑只盲取
// suggestions[0]——推荐链对当前目标可能已被拦截，整轮重跑注定失败（白费
// N×3+ 请求）。本模块对候选链逐条发轻量注入探针实测「是否被拦截」，
// 返回第一条放行的链；全部被拦则跳过重跑。
//
// 判定标准（保守，与 WafIdentifier.activeProbe 同款信号，不引入误报源）：
//   拦截 = 状态码 ∈ {403,406,429,501,503} 或 响应体缩水至干净基线的 50% 以下
//   探测请求失败/超时 → 该链「无法判定」→ 视为被拦（保守）
//   干净探针（无 tamper）本身未被拦 → 无法证明链价值 → 保守返回首条链（对齐旧行为）
import { buildInjectionRequest } from '../../engine/injection.js';
import { applyTampers } from '../tamper/applyTampers.js';
import { logger } from '../logger.js';
// [A2-2026-09-21] 拦截判定与逐词画像/定向选链统一收敛到 blockProfile：
// 原来 looksBlocked 定义在本文件，新模块若各写一份就会出现"两处口径漂移"（本仓高频病）。
import { looksBlocked, profileBlockedTokens } from './blockProfile.js';
// [接线 2026-09-23] T1/T2 的产出（语义索引 + 定向变异）正式接进验链流程。
// buildCandidateChains 内部先走既有 rankChainsByProfile 重排静态链、再追加生成链，
// 故**静态链整体保持在前** —— 新逻辑无效时前 MAX_CHAINS 条与改造前完全一致（保守回退）。
import { buildCandidateChains, isGeneratedChain } from './bypass/searcher.js';
import { rankChainsByProfile } from './blockProfile.js';

const MAX_CHAINS = 3; // 最多验证 3 条候选链（预算约束）
// [A2-ENDPOINT 2026-09-23] 定向生成的链占用几个验证名额。
// ⚠️ 为什么必须**显式留名额**：`list`（OPERATOR_SWAP_CHAINS）有 4 条静态链，
// 而 MAX_CHAINS=3 只取前三 —— 生成链被追加在静态链**之后**（保守回退的设计），
// 于是它永远落在第 5 位、**一次也不会被验证**，A2 等于接了线却从未生效。
// 留 1 个名额后：仍是「静态链优先」（前 2 条）+「生成链 1 条」，验证总条数不变（预算纪律）。
const GENERATED_SLOTS = 1;

/**
 * 对候选 tamper 链做探针验证。
 * @param {object} p
 * @param {object} p.httpClient 扫描作用域 httpClient（request(opts)）
 * @param {object} p.target 扫描目标
 * @param {object} p.point 探测点（取未命中点中的第一个）
 * @param {Array<{vendor:string, plugins:string[]}>} p.chains wafRecommend 输出（按置信度序）
 * @param {object} [p.config] 扫描配置（timeoutMs/cookieJar 等透传）
 * @param {number} [p.timeoutMs] 探针超时（默认 6000）
 * @param {null|((e:{plugins:string[], vendor:string, generated:boolean, probe:string, blocked:boolean}) => void)} [p.onChainProbe]
 *   [可观测性 2026-09-23] 每条候选链每发一次探针就回调一次。存在的理由：验链结果
 *   （返回哪条链）无法回答「哪些链被**试过**」——而 A2 的验收判据恰恰是「生成链有没有
 *   进入验证流程」，不是「它有没有赢」。没有这个回调就只能靠猜，与本项目「取数要能看见
 *   它声称在管的东西」的纪律相悖。生产路径不传即为 no-op，零成本。
 * @returns {Promise<{vendor:string, plugins:string[]}|null>} 首条验证通过的链；全被拦返回 null
 */
export async function verifyTamperChains({
  httpClient,
  target,
  point,
  chains,
  config = {},
  timeoutMs = 6000,
  onChainProbe = null,
}) {
  const list = Array.isArray(chains) ? chains.filter((c) => c && Array.isArray(c.plugins) && c.plugins.length) : [];
  if (!httpClient || !target || !point || list.length === 0) return null;
  const orig = point.originalValue || '1';
  // [P0-FIX 2026-09-10 实战实测] 探针族（原来是单探针，有致命盲区）：
  //   探针① `${orig}' AND 1=1-- -`  —— 带注释尾巴；
  //   探针② `${orig}' AND '1'='1`   —— 引号闭合，无 -- / # / 空格依赖。
  // 单探针的问题：真实 WAF（含本次实测靶场）普遍拦 `--`，探针①无论套什么链都恒 403 →
  // 所有链被误判「仍被拦」→ 自适应重跑直接跳过。探针②在拦注释的场景下仍能证明链价值。
  // 判据：裸探针需「全部被拦」才认定 WAF 敏感；链验证「任一探针放行」即通过。
  const probeValues = [`${orig}' AND 1=1-- -`, `${orig}' AND '1'='1`];
  const send = async (value, plugins) => {
    const t0 = Date.now();
    // [FIX] 用入参 value（基线发原值、探针发注入串）；plugins 才套 tamper
    const payload = plugins ? applyTampers(value, { config }, plugins) : value;
    const req = buildInjectionRequest(target, point, payload);
    try {
      const res = await httpClient.request({
        ...req,
        timeoutMs,
        retry: 0,
        cookieJar: config.cookieJar !== false,
      });
      return { res, elapsed: Date.now() - t0 };
    } catch {
      return { res: null, elapsed: Date.now() - t0 };
    }
  };

  try {
    // 1) 干净基线：原值请求（未注入）
    const base = await send(orig, null);
    const baseLen = base.res ? String(base.res.data ?? '').length : 0;
    if (!base.res) return null; // 目标不可达 → 无法验证

    // 2) 未套 tamper 的裸探针：**全部**被拦才认定 WAF 对该形态敏感；
    //    任一放行 → WAF 不敏感，保守返回首条链（对齐旧行为）
    let allRawBlocked = true;
    for (const pv of probeValues) {
      const raw = await send(pv, null);
      if (!looksBlocked(raw.res, baseLen)) { allRawBlocked = false; break; }
    }
    if (!allRawBlocked) return list[0];

    // 3) [A2-2026-09-21] 逐词画像 + 定向选链。
    //    走到这里说明「整串探针**全**被拦」。原先直接 `list.slice(0, MAX_CHAINS)` **按序**取前 3 条
    //    —— 那是盲选：3 个名额可能全花在「消除 `--` 的链」上，而目标实际拦的是 `union`。
    //    现在先花预算做逐词画像（哪些词被拦），再按「能消除被拦词」重排候选。
    //    成本纪律：**仅在此分支发生** —— 目标不敏感时（上面 allRawBlocked=false 已返回）零额外请求。
    const profile = await profileBlockedTokens({ httpClient, target, point, config, baseLen, timeoutMs });
    // [接线 2026-09-23] 画像 → 候选池。**零额外请求**：只用已拿到的画像做纯计算，
    // 请求数仍由下面的 MAX_CHAINS 截断决定，与改造前相同。
    // 生成链排在静态链之后，故静态链仍是首选（新逻辑无效 = 自动退化回改造前）。
    //
    // [A2-ENDPOINT 2026-09-23] 关键改动：**显式给生成链留 GENERATED_SLOTS 个名额**。
    // 不改这一处的话，`ranked` = [4 条静态链 ..., 生成链 ...]，而下面只验前 3 条 →
    // 生成链永远排在第 5 位、一次也不会被发请求验证（A2 接了线但从未生效）。
    // 现在池子 = 静态链前 (MAX_CHAINS - GENERATED_SLOTS) 条 + 生成链前 GENERATED_SLOTS 条，
    // **验证总条数仍是 MAX_CHAINS**（预算不变），静态链仍在前（回退语义不变）。
    const bypassSearch = config?.wafEvasion?.bypassSearch !== false;
    const merged = buildCandidateChains(list, profile.blocked, {
      dbms: point?.dbms || undefined,
      maxGenerated: MAX_CHAINS,
    });
    let ranked;
    if (bypassSearch) {
      const statics = merged.filter((c) => !isGeneratedChain(c.vendor));
      const generated = merged.filter((c) => isGeneratedChain(c.vendor));
      ranked = [...statics.slice(0, MAX_CHAINS - GENERATED_SLOTS), ...generated.slice(0, GENERATED_SLOTS)];
    } else {
      // 关闭档 = 只有静态链（既有 A2-1 的按画像重排），用于 A/B 对照与回归定位
      ranked = rankChainsByProfile(list, profile.blocked).slice(0, MAX_CHAINS);
    }

    // 4) 逐链验证：任一探针套链后未被拦截 → 该链有效（strict：只认硬拦截）
    for (const chain of ranked.slice(0, MAX_CHAINS)) {
      for (const pv of probeValues) {
        const t = await send(pv, chain.plugins);
        const blocked = looksBlocked(t.res, baseLen, { strict: true });
        if (onChainProbe) {
          try {
            onChainProbe({
              plugins: chain.plugins,
              vendor: chain.vendor,
              generated: isGeneratedChain(chain.vendor),
              probe: pv,
              blocked,
            });
          } catch { /* 观察者的异常不得影响验链 */ }
        }
        if (!blocked) {
          logger.info(
            `WAF 链验证：[${chain.plugins.join(',')}] 探针放行（${t.elapsed}ms），候选共 ${list.length} 条` +
              (profile.blocked.length ? `（画像被拦：${profile.blocked.join('/')}）` : '')
          );
          return chain;
        }
      }
    }
    logger.warn(
      `WAF 链验证：${Math.min(ranked.length, MAX_CHAINS)} 条候选链探针均被拦截，跳过自动重跑` +
        (profile.blocked.length ? `（画像被拦：${profile.blocked.join('/')}）` : '')
    );
    return null;
  } catch (e) {
    // 验证流程异常 → 保守回退首条链（不因验证器故障削弱旧行为）
    logger.warn(`WAF 链验证异常（${e.message}），回退首条推荐链`);
    return list[0] ?? null;
  }
}

export default verifyTamperChains;
