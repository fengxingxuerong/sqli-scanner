import winston from 'winston';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// ── 统一敏感信息打码工具（T1-A：redact）──────────────────────────
// 覆盖：① URL 内嵌凭据 https://user:pass@host ② 认证头 Authorization/Proxy-Authorization
//       ③ Cookie/Set-Cookie 头值 ④ password/token/api_key 等通用敏感键值
//       ⑤ 超长内容截断 + 打标（防 payload 证据/响应体刷屏、落盘爆炸）。
// 与既有 sanitizeLog 兼容：sanitizeLog 现委托 redact（不做截断），行为不变。

// 通用敏感键值对（password/token/api_key 等）
// [B-10a] 补全 private_key/access_key/secret_key/client_id/client_secret 等常见变体
const SENSITIVE_KEY_RE = /(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?id|client[_-]?secret)\s*[=:]\s*[^\s&;,]+/gi;
// [P0-SEC 2026-09-08] JSON 形态的敏感键（`"token":"<32hex>"`）：上面的正则要求 key 后紧跟 =/:，
// 而 JSON 里 key 后是先闭合引号再 `:` → 完全不匹配。实际泄漏路径：
//   • scanRoutes 启动失败日志把 e.stack 整段输出（栈里带调用方传入的 config 对象）；
//   • ReportAI 把 options 展开进请求体后报错回显。
// 只打码 value，保留 key 与引号结构（日志可读性）。
const SENSITIVE_JSON_KEY_RE =
  /("(?:[a-z0-9_-]*(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|access[_-]?key|client[_-]?id|client[_-]?secret))"\s*:\s*")[^"]*(")/gi;
// URL 内嵌凭据
const URL_CRED_RE = /(https?:\/\/)([^/@\s]+):([^/@\s]+)@/gi;
// 认证头（含 Bearer/Basic/Digest scheme，值整体打码）
// [B-10b] 补全 Token/JWT/Negotiate/ApiKey 等非标准 scheme
const AUTH_HEADER_RE = /(authorization|proxy-authorization)\s*[:=]\s*((?:bearer|basic|digest|token|jwt|negotiate|apikey)\s+)?[^\s,;]+/gi;
// Cookie 头（值可能含多个 k=v，整体打码到换行——不能只到第一个分号，
// 否则多 cookie 串 "a=1; b=secret" 中 a=1 之后的部分会泄露）
const COOKIE_HEADER_RE = /(set-?cookie|cookie)\s*[:=]\s*[^\r\n]+/gi;

// 请求头对象里视为敏感、需整体打码的头名（大小写不敏感）
// [B-10c] 补全 x-api-key/x-auth-token 等常见头名
const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-token',
  'x-scan-token',
  'x-api-key',
  'x-auth-token',
]);

/**
 * 对文本做敏感信息打码；可选超长截断。
 * @param {*} input 任意输入（非字符串会被 String() 化）
 * @param {{maxLength?:number}} [options] maxLength>0 时超长部分截断并打标
 * @returns {string}
 */
export function redact(input, options = {}) {
  const maxLength = Number(options.maxLength) || 0;
  let s = String(input ?? '');
  // ① URL 内嵌 user:pass@
  s = s.replace(URL_CRED_RE, '$1***:***@');
  // ② 认证头值（Authorization / Proxy-Authorization）
  s = s.replace(AUTH_HEADER_RE, '$1=***');
  // ③ Cookie / Set-Cookie 头值
  s = s.replace(COOKIE_HEADER_RE, '$1=***');
  // ④ 通用敏感键值（含 password/token/api_key 等）
  s = s.replace(SENSITIVE_KEY_RE, '$1=***');
  // ④b JSON 键值形态（"token":"xxx"）
  s = s.replace(SENSITIVE_JSON_KEY_RE, '$1***$2');
  // ⑤ 超长截断 + 打标（防 payload 证据/响应体刷屏）
  if (maxLength > 0 && s.length > maxLength) {
    s = `${s.slice(0, maxLength)}…[截断 ${s.length - maxLength} 字符]`;
  }
  return s;
}

/**
 * 对请求头对象打码：Authorization/Cookie/Proxy-Authorization 等敏感头的值整体替换为 ***。
 * @param {object} headers
 * @returns {object} 打码后的头副本（浅拷贝，不改入参）
 */
export function redactHeaders(headers) {
  if (!headers || typeof headers !== 'object') return headers;
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SENSITIVE_HEADER_NAMES.has(String(k).toLowerCase()) ? '***' : v;
  }
  return out;
}

/**
 * 仅做超长截断 + 打标（不打码），供报告导出等「用户主动索取数据」场景防止超长证据膨胀。
 * @param {*} input
 * @param {number} maxLength
 * @returns {string}
 */
export function truncateLong(input, maxLength) {
  const s = String(input ?? '');
  const n = Number(maxLength) || 0;
  if (n > 0 && s.length > n) {
    return `${s.slice(0, n)}…[截断 ${s.length - n} 字符]`;
  }
  return s;
}

// 向后兼容：sanitizeLog = redact 不打截断（既有测试 architecture.p1.test.js 依赖其行为）
export function sanitizeLog(msg) {
  return redact(msg);
}

// 解析可写日志路径：优先 <cwd>/logs/，失败回退系统临时目录。
// 引擎作为 Tauri sidecar / 在受限目录运行时 CWD 可能只读，相对路径 engine.log 会写失败，故动态探测。
function resolveLogPath() {
  const candidates = [
    path.join(process.cwd(), 'logs', 'engine.log'),
    path.join(os.tmpdir(), 'sqli-scanner', 'engine.log'),
  ];
  for (const p of candidates) {
    try {
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.accessSync(path.dirname(p), fs.constants.W_OK);
      return p;
    } catch {
      // 该候选路径不可写，尝试下一个
    }
  }
  return candidates[candidates.length - 1];
}

// 测试/受限环境可通过 SQLI_NO_FILE_LOG=1 关闭文件日志，避免写盘权限提示（向后兼容：不设则行为不变）
const NO_FILE_LOG = process.env.SQLI_NO_FILE_LOG === '1' || process.env.SQLI_NO_FILE_LOG === 'true';
const LOG_PATH = NO_FILE_LOG ? null : resolveLogPath();

// 日志器：控制台 + 文件（warn 级别以上落盘）
// [P0-FIX] 文件日志加轮转：maxsize 10MB × maxFiles 5，防止长驻进程日志无界增长
const transports = [new winston.transports.Console()];
if (LOG_PATH) {
  const fileTransport = new winston.transports.File({
    filename: LOG_PATH,
    level: 'warn',
    maxsize: 10 * 1024 * 1024, // 10MB 单文件上限
    maxFiles: 5,               // 最多保留 5 个轮转文件
    tailable: true,            // 写满自动轮转
  });
  // 文件不可写（如沙箱/只读目录）时静默降级，绝不影响引擎主流程
  fileTransport.on('error', () => {});
  transports.push(fileTransport);
}

// 单条日志最大长度：超长（如整段响应体/拖库证据被误打印）截断，防日志刷屏与落盘膨胀
const LOG_MAX_LENGTH = 4000;

export const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) => {
      // 统一在最终输出前脱敏 + 截断，覆盖控制台 + 文件两种 transport
      return `[${timestamp}] [${level}] ${redact(message, { maxLength: LOG_MAX_LENGTH })}`;
    })
  ),
  transports,
});

export default logger;
