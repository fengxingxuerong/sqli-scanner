// ============================================================================
// http/clientCert.js —— mTLS 客户端证书加载（对标 sqlmap --cert）
// ============================================================================
// 场景：目标站点要求 TLS 双向认证（企业内网/金融网关越来越常见），没有客户端证书
// 连 TCP 握手后的第一个请求都被拒 —— 扫描器在检测阶段之前就已出局。sqlmap 用
// --cert=<pem>（单文件同时含证书与私钥）解决；本模块是同一语义的加载层：
//   · 按 path+mtime 缓存（扫描期数千请求不得每次读盘）；
//   · 缺文件/形状不对**抛错**（配置错误要响，静默忽略等于全程 401 还说"目标不可达"）。
// ============================================================================
import { readFileSync, statSync } from 'node:fs';
import { AppError, ErrorCode } from '../errors.js';

const _cache = new Map(); // path → { mtimeMs, pem }
const CACHE_MAX = 16;

const CERT_BLOCK = /-----BEGIN ([A-Z0-9 ]+)?CERTIFICATE-----/;
const KEY_BLOCK = /-----BEGIN ([A-Z0-9 ]+)?PRIVATE KEY-----/;

/**
 * 加载客户端证书 PEM（证书+私钥同文件，sqlmap --cert 语义）。
 * @param {string} path PEM 文件路径
 * @returns {{ cert: Buffer, key: Buffer }} 同一份缓冲两用（PEM 内含两个块，TLS 库各自取用）
 * @throws {AppError} 文件不存在 / 不是「证书+私钥」的 PEM
 */
export function loadClientCert(path) {
  let st;
  try {
    st = statSync(path);
  } catch {
    throw new AppError(ErrorCode.INVALID_PARAM, `clientCert 文件不可读：${path}`);
  }
  const hit = _cache.get(path);
  if (hit && hit.mtimeMs === st.mtimeMs) return { cert: hit.pem, key: hit.pem };
  const pem = readFileSync(path);
  const text = pem.toString('utf8');
  if (!CERT_BLOCK.test(text) || !KEY_BLOCK.test(text)) {
    throw new AppError(
      ErrorCode.INVALID_PARAM,
      `clientCert 须为同时含 CERTIFICATE 与 PRIVATE KEY 块的 PEM 文件（sqlmap --cert 同语义）：${path}`
    );
  }
  if (_cache.size >= CACHE_MAX) {
    const oldest = _cache.keys().next().value;
    if (oldest !== undefined) _cache.delete(oldest);
  }
  _cache.set(path, { mtimeMs: st.mtimeMs, pem });
  return { cert: pem, key: pem };
}

export default loadClientCert;
