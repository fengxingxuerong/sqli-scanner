// ============================================================================
// e2e/bearer-lab/jwt-scheme.mjs —— 靶站与脚本共用的「真 JWT(HS256) + 刷新凭据」口径
//
// 为什么单独成文件：验签和签发必须**同一份实现**，否则靶站"接受"了引擎带来的东西
// 只是因为两边算法不一样恰好都放行 —— 那种靶站测不出任何事。与 signed-api-lab 的
// sign-scheme.mjs 同一条理由。
//
// ⚠ 时钟是**虚拟**的（state.nowMs 由靶站自己拨），不用真实时间：
//   "令牌在扫描中途过期"这件事如果靠 sleep 或短 TTL 实现，CI 上就是抛硬币 ——
//   扫描快一点整轮都在有效期内，慢一点第一条就 401，两种情况测的是完全不同的东西。
//   拨钟让它由**请求计数**决定，场景才可复现。exp/nbf 字段仍是真的 JWT 字段，
//   验签走 HMAC-SHA256，线上形态与真实目标一致（只有"时间从哪来"是假的）。
// ============================================================================
import crypto from 'node:crypto';

export const JWT_SECRET = 'lab-bearer-secret';
export const REFRESH_SECRET = 'lab-refresh-token-0123456789';
/** 令牌名义有效期（毫秒）—— 签发时写进 exp，是否"过期"由靶站的虚拟时钟拨动决定 */
export const TOKEN_TTL_MS = 60_000;

const b64u = (buf) => Buffer.from(buf).toString('base64url');

/**
 * 签发一枚 HS256 JWT（iat/exp 为秒级 JWT 标准字段）。
 * @param {number} nowMs 靶站的虚拟"当前时间"
 * @param {number} seq   令牌序号（写进 jti，靶站据此区分"换了新令牌"与"重放抓包那枚"）
 * @param {number} ttlMs 有效期：**初始那枚短、续期那枚长** —— 真实世界正是这个形状
 *   （从浏览器复制出来的 access token 通常已用掉大半有效期，而 /token 刚签发的是满期的）。
 *   两边都短会把扫描变成"每 3 条续一次期"的压力测试，A（没配续期）与 B（配了）的差别就测不出来。
 */
export function signToken(nowMs, seq = 0, ttlMs = TOKEN_TTL_MS) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    sub: 'lab-user',
    aud: 'lab-api',
    iat: Math.floor(nowMs / 1000),
    exp: Math.floor((nowMs + ttlMs) / 1000),
    jti: `t${seq}`,
  };
  const p1 = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(p1).digest('base64url');
  return `${p1}.${sig}`;
}

/** 续期换来的那枚：有效期足够长，让"是否续期成功"成为唯一变量 */
export const REFRESHED_TTL_MS = 365 * 24 * 3600 * 1000;

/**
 * 验签 + 校验 exp（对照靶站真实形态：签名不对与过期都是 401，但原因要分开计）。
 * @returns {{ok: boolean, why: string, payload?: object}}
 */
export function verifyToken(token, nowMs) {
  if (!token || typeof token !== 'string') return { ok: false, why: 'no-token' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, why: 'malformed' };
  const expect = crypto.createHmac('sha256', JWT_SECRET).update(`${parts[0]}.${parts[1]}`).digest('base64url');
  // 定长比较：本靶站是测试夹具，但沿用 constant-time 写法，免得养成"签名字符串直接 =="的习惯
  const a = Buffer.from(expect);
  const b = Buffer.from(parts[2]);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, why: 'bad-signature' };
  let payload;
  try {
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return { ok: false, why: 'bad-payload' };
  }
  if (typeof payload.exp === 'number' && Math.floor(nowMs / 1000) >= payload.exp) return { ok: false, why: 'expired', payload };
  return { ok: true, why: '', payload };
}

export default { signToken, verifyToken, JWT_SECRET, REFRESH_SECRET, TOKEN_TTL_MS };
