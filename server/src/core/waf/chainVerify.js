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

const BLOCKED_STATUSES = new Set([403, 406, 429, 501, 503]);
const MAX_CHAINS = 3; // 最多验证 3 条候选链（预算约束）

function looksBlocked(res, baseLen) {
  if (!res) return true;
  if (BLOCKED_STATUSES.has(res.status)) return true;
  const len = String(res.data ?? '').length;
  if (baseLen > 0 && len < baseLen * 0.5) return true;
  return false;
}

/**
 * 对候选 tamper 链做探针验证。
 * @param {object} p
 * @param {object} p.httpClient 扫描作用域 httpClient（request(opts)）
 * @param {object} p.target 扫描目标
 * @param {object} p.point 探测点（取未命中点中的第一个）
 * @param {Array<{vendor:string, plugins:string[]}>} p.chains wafRecommend 输出（按置信度序）
 * @param {object} p.config 扫描配置（timeoutMs/cookieJar 等透传）
 * @param {number} [p.timeoutMs] 探针超时（默认 6000）
 * @returns {Promise<{vendor:string, plugins:string[]}|null>} 首条验证通过的链；全被拦返回 null
 */
export async function verifyTamperChains({ httpClient, target, point, chains, config = {}, timeoutMs = 6000 }) {
  const list = Array.isArray(chains) ? chains.filter((c) => c && Array.isArray(c.plugins) && c.plugins.length) : [];
  if (!httpClient || !target || !point || list.length === 0) return null;
  const orig = point.originalValue || '1';
  // 探针：引号闭合 + 无引号布尔段。选它的原因：space2comment 引号状态机不替换
  // 引号内空格（`' AND '` 中空格在闭合外才能变换），无引号段保证各 tamper 均可改变形态，
  // 便于放行判定不被「链变换后与裸形态相同」干扰。
  const probeValue = `${orig}' AND 1=1-- -`;
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

    // 2) 未套 tamper 的裸探针：未被拦 → WAF 对该形态不敏感，保守返回首条链（对齐旧行为）
    const raw = await send(probeValue, null);
    if (!looksBlocked(raw.res, baseLen)) return list[0];

    // 3) 逐链验证：探针套链后未被拦截 → 该链有效
    for (const chain of list.slice(0, MAX_CHAINS)) {
      const t = await send(probeValue, chain.plugins);
      if (!looksBlocked(t.res, baseLen)) {
        logger.info(
          `WAF 链验证：[${chain.plugins.join(',')}] 探针放行（${t.elapsed}ms），候选共 ${list.length} 条`
        );
        return chain;
      }
    }
    logger.warn(`WAF 链验证：${Math.min(list.length, MAX_CHAINS)} 条候选链探针均被拦截，跳过自动重跑`);
    return null;
  } catch (e) {
    // 验证流程异常 → 保守回退首条链（不因验证器故障削弱旧行为）
    logger.warn(`WAF 链验证异常（${e.message}），回退首条推荐链`);
    return list[0] ?? null;
  }
}

export default verifyTamperChains;
