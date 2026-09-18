// ============================================================================
// core/sessionSecret.js —— 会话落盘敏感值的封存/解封（对称加密）
//
// 为什么需要：会话文件（sessions/*.json）里 `points[].originalValue` 是**注入点的原始参数值**。
// 当注入点是 Cookie / 自定义认证头时，这个值就是**会话凭据明文**落盘；而 compose 还把
// sessions 目录挂在 named volume 上（可被其它容器/备份读到）。审计把这条列为中危。
//
// 设计取向（为什么不直接打码）：
//   打码会破坏「断点续跑」——恢复会话时需要用原始值重建基线请求。所以选择**落盘加密**：
//   · 内存里始终是明文（扫描/续跑/报告语义完全不变）；
//   · 只有写进磁盘的那一份是密文（前缀 `enc:v1:`）；
//   · 密钥来源可配（`SCAN_SESSION_KEY` / 由 `SCAN_API_TOKEN` 派生 / 进程随机兜底）。
//
// 密钥来源优先级与后果：
//   ① `SCAN_SESSION_KEY`（推荐，能跨重启续跑）
//   ② `SCAN_API_TOKEN` 派生（容器部署通常已有；改了 token 则旧会话不可解 → 自动重扫该点）
//   ③ 进程随机（**仅本进程内可解**，重启后旧会话解不开 → 该点标记为待重扫，不会崩）
//
// 解密失败不抛异常：旧明文会话、换过 key 的会话都必须能继续被读入（降级为"该点待重扫"）。
// ============================================================================
import crypto from 'node:crypto';

const PREFIX = 'enc:v1:';
const SALT = 'sqli-scanner/session-secret/v1';

let cachedKey = null;
let cachedKeySource = null;

/** 当前生效的密钥来源（供日志/诊断用，不含密钥本身） */
export function secretKeySource() {
  if (process.env.SCAN_SESSION_KEY) return 'env:SCAN_SESSION_KEY';
  if (process.env.SCAN_API_TOKEN) return 'derived:SCAN_API_TOKEN';
  return 'process-random';
}

function deriveKey(material) {
  // scrypt 派生 32 字节；参数取足够稳的 N=16384（一次性派生，不构成性能问题）
  return crypto.scryptSync(String(material), SALT, 32, { N: 16384, r: 8, p: 1 });
}

function getKey() {
  const src = secretKeySource();
  if (cachedKey && cachedKeySource === src) return cachedKey;
  let key;
  if (src === 'env:SCAN_SESSION_KEY') key = deriveKey(process.env.SCAN_SESSION_KEY);
  else if (src === 'derived:SCAN_API_TOKEN') key = deriveKey(process.env.SCAN_API_TOKEN);
  else key = crypto.randomBytes(32); // 进程随机：本进程可解，重启即失效（降级为待重扫）
  cachedKey = key;
  cachedKeySource = src;
  return key;
}

/** 测试钩子：清除密钥缓存（切换 env 后重新派生） */
export function _resetSecretKeyForTest() {
  cachedKey = null;
  cachedKeySource = null;
}

/** @returns {boolean} 该值是否已是封存形态 */
export function isSealed(value) {
  return typeof value === 'string' && value.startsWith(PREFIX);
}

/**
 * 封存一个敏感字符串：`enc:v1:<iv>:<tag>:<ciphertext>`（各段 base64）。
 * · 非字符串 / 空值 → 原样返回（不制造无意义密文）
 * · 已封存 → 原样返回（幂等，避免重复加密后无法还原）
 * @param {unknown} plain
 * @returns {unknown}
 */
export function sealSecret(plain) {
  if (typeof plain !== 'string' || plain === '') return plain;
  if (isSealed(plain)) return plain;
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${PREFIX}${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
  } catch {
    // 加密不可用（极端环境）→ 返回原值：宁可留下明文也不要让会话写盘整体失败
    return plain;
  }
}

/**
 * 解封。返回 null 表示「有密文但解不开」（调用方据此把该点降级为待重扫）。
 * 明文入参原样返回（兼容加密上线前写下的旧会话文件）。
 * @param {unknown} value
 * @returns {string|null|unknown}
 */
export function openSecret(value) {
  if (!isSealed(value)) return value;
  try {
    const parts = String(value).slice(PREFIX.length).split(':');
    if (parts.length !== 3) return null;
    const [ivB64, tagB64, ctB64] = parts;
    const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), Buffer.from(ivB64, 'base64'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}
