// ============================================================================
// sign-scheme.mjs —— signed-api-lab 的「官方签名方案」（靶站与脚本共用同一份定义）
//
// 为什么要抽这份：靶站验签用的算法，与 `sign-correct.mjs` 产签的算法**必须是同一份代码**。
// 两处各写一遍，改一处就会让「正确脚本」不再正确 —— 那时 A 场景红的原因与能力无关，
// 是靶场自己坏了（本仓 §D/§W 两次「靶场注释与实现不符」把排查带向错误方向的同一类错）。
//
// 方案刻意选最常见的形态：`sign = md5(按参数名排序拼 k=v，用 & 连接，再接密钥)`，
// 排除 `sign` 自身。真实项目里这类方案的名字千奇百怪（X-Sign / x-tumid / _sig / wxsign），
// 但**参与集与顺序**是共同的失效点 ⇒ 场景 B 打的正是「参与集算错了」这一类。
// ============================================================================
import crypto from 'node:crypto';

/** 靶站与正确脚本共用的密钥（故意入库：这是靶场，不是生产；真项目的密钥绝不该进仓库） */
export const KEY = 'lab-secret-key';

/**
 * 防重放接口（/api/tick）的密钥 —— 与业务接口分开，真实项目也是这么配的。
 * 放在这里而不是脚本里：靶站要验、`tick-fresh`/`tick-stale` 两个脚本要产，
 * 三处必须同一个值（同上一条纪律：算法与密钥只有一份定义）。
 */
export const TICK_KEY = 'lab-tick-key';

/** /api/tick 的时钟窗（毫秒）：窗外一律拒 —— 抓包重放几秒钟就死就是这个词 */
export const TICK_WINDOW_MS = 60000;

/**
 * 规范串：参数按名字典序排列，拼 `k=v` 用 `&` 连接，末尾接密钥。
 * @param {Iterable<[string, string]>} entries 参数对（含重复名时按出现顺序保留）
 * @param {string} key 密钥
 */
export function canonical(entries, key = KEY) {
  const pairs = [...entries]
    .filter(([k]) => k !== 'sign')
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `${pairs.map(([k, v]) => `${k}=${v}`).join('&')}${key}`;
}

/** 对参数集签名 */
export function buildSign(entries, key = KEY) {
  return crypto.createHash('md5').update(canonical(entries, key)).digest('hex');
}

/**
 * 从查询串取参数对（保留顺序，不去重）。
 * ⚠ 容忍相对路径：靶站侧 `req.url` 只有 path+query（Node http 的原始请求行），
 *   直接 new URL 会 ERR_INVALID_URL —— 第一版就栽在这里（整个进程被抛出未捕获异常打死）。
 *   签名算的是「参数集」，用一个固定的占位 origin 解析不影响结果，两侧（浏览器绝对 URL /
 *   靶站相对请求行）拿到的 entries 逐字相同。
 * @param {string} urlOrPath 绝对 URL 或 `/path?a=b`
 */
export function paramsOf(urlOrPath) {
  const raw = String(urlOrPath || '');
  const u = /^[a-z][a-z0-9+.-]*:/i.test(raw) ? new URL(raw) : new URL(raw, 'http://127.0.0.1');
  return [...u.searchParams.entries()];
}
