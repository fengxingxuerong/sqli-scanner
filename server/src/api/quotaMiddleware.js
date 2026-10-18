// ============================================================================
// api/quotaMiddleware.js —— 配额中间件：目标数 + 扇出（spec 5.2.1 规则 3/4）
//
// 解决什么：rateLimit 是请求速率限流（按 API key 限 N 次/分钟），不是目标维度配额。
// spec 5.2.1 规则 3 要求按凭据限制"时间窗内不同目标数"，规则 4 要求限制"活跃扫描扇出"。
//
// 两类配额（进程内 Map，单实例部署语义；多实例需引入 Redis，后续迭代）：
//   · 目标数配额：按凭据 + 时间窗维护目标集合，超限拒绝（QUOTA_TARGET_EXCEEDED）
//   · 扇出配额：按凭据维护活跃扫描数，超限拒绝（QUOTA_FANOUT_EXCEEDED），扫描结束 release
//
// 环境变量：
//   QUOTA_TARGET_MAX（默认 20）—— 时间窗内最多不同目标数
//   QUOTA_FANOUT_MAX（默认 5） —— 同时最多活跃扫描数
//   QUOTA_WINDOW_MS（默认 3600000）—— 时间窗长度
// ============================================================================
import { createHash } from 'node:crypto';

const TARGET_MAX = Math.max(1, parseInt(process.env.QUOTA_TARGET_MAX || '20', 10));
const FANOUT_MAX = Math.max(1, parseInt(process.env.QUOTA_FANOUT_MAX || '5', 10));
const WINDOW_MS = Math.max(60000, parseInt(process.env.QUOTA_WINDOW_MS || '3600000', 10));

// credentialKey → { targets: Map<target, timestamp>, windowStart }
const targetStore = new Map();
// credentialKey → active count
const fanoutStore = new Map();

/**
 * 从凭据字符串生成摘要键（与 rateLimit.tokenKeyOf 同语义，但不依赖 req）。
 * @param {string|undefined} token 原始凭据（空/缺省 ⇒ 'anonymous'）
 * @returns {string} `h:<sha256 前 16 位>` 摘要键
 */
export function credentialKeyOf(token) {
  const t = String(token || '').trim();
  if (!t) return 'anonymous';
  return 'h:' + createHash('sha256').update(t).digest('hex').slice(0, 16);
}

/**
 * 检查配额（目标数 + 扇出）。通过时记账，需调用方在扫描结束后调 release。
 * @param {{credentialKey:string, target:string, operation?:string}} param
 * @returns {{allowed:boolean, code?:string, message?:string, remaining?:object}}
 */
export function checkQuota({ credentialKey, target, operation = 'scan' }) {
  const now = Date.now();
  const key = credentialKey || 'anonymous';
  const targetStr = String(target || 'unknown');

  // ── 目标数配额 ──
  let ts = targetStore.get(key);
  if (!ts) { ts = { targets: new Map(), windowStart: now }; targetStore.set(key, ts); }
  if (now - ts.windowStart > WINDOW_MS) { ts.targets.clear(); ts.windowStart = now; }
  // 清理过期目标
  for (const [t, time] of ts.targets) {
    if (now - time > WINDOW_MS) ts.targets.delete(t);
  }
  if (!ts.targets.has(targetStr) && ts.targets.size >= TARGET_MAX) {
    return { allowed: false, code: 'QUOTA_TARGET_EXCEEDED', message: `目标数配额超限（${ts.targets.size}/${TARGET_MAX}，窗口 ${WINDOW_MS}ms）` };
  }

  // ── 扇出配额 ──
  const active = fanoutStore.get(key) || 0;
  if (active >= FANOUT_MAX) {
    return { allowed: false, code: 'QUOTA_FANOUT_EXCEEDED', message: `扇出配额超限（${active}/${FANOUT_MAX}）` };
  }

  // 通过：记账
  ts.targets.set(targetStr, now);
  fanoutStore.set(key, active + 1);
  return { allowed: true, remaining: { targets: TARGET_MAX - ts.targets.size, fanout: FANOUT_MAX - active - 1 } };
}

/**
 * 释放扇出配额（扫描结束/停止时调用）。
 * @param {{credentialKey?: string}} param 凭据键（缺省按 anonymous）
 * @returns {void}
 */
export function release({ credentialKey }) {
  const key = credentialKey || 'anonymous';
  const active = fanoutStore.get(key) || 0;
  if (active > 0) fanoutStore.set(key, active - 1);
}

/** 查询当前配额态（供测试/调试） */
export function getQuotaState(credentialKey) {
  const key = credentialKey || 'anonymous';
  const ts = targetStore.get(key);
  return {
    targets: ts ? ts.targets.size : 0,
    fanout: fanoutStore.get(key) || 0,
    limits: { targetMax: TARGET_MAX, fanoutMax: FANOUT_MAX, windowMs: WINDOW_MS },
  };
}

/** 重置所有配额（仅测试用） */
export function _resetForTest() {
  targetStore.clear();
  fanoutStore.clear();
}

export { TARGET_MAX, FANOUT_MAX, WINDOW_MS };