// ============================================================================
// loginFlow.js — 登录编排最小版（opt-in config.login，实战分析 P1-6）
//
// 解决什么问题：认证此前只有「静态注入」（cookie/header 一次带上）+ 会话失效**检测**
// （scanValidityGuard 判 authLost 建议人工重取 cookie）。token 一小时过期的目标，
// 扫到一半全变 401 → 后半程全判「不可注入」。本模块提供标准表单登录的自动编排：
//   ① GET 登录页 → 解析表单字段（用户名/密码输入框名自动探测 + hidden 字段透传）
//   ② POST 凭据（urlencoded）→ CookieJar 承接会话
//   ③ 扫描请求遇 401/403/登录跳转 → 自动重登一次并重试原请求
//
// 诚实边界（刻意不做）：OAuth/JWT 刷新流、SAML、验证码、JS 加密提交（密码前端加密的
// 站点表单模拟无效）——这些交给「人工取 cookie + 静态注入」主路径。仅覆盖
// 「标准 HTML 表单登录」这一最大子集（实战分析 §1.2 的口径）。
//
// 安全语义：登录请求经同一个 per-scan client 发送 → SSRF 校验 / scope 逐请求校验 /
// 限速桶全部照常生效（与 csrfKeeper 的取页同一条链），无需在路由层另开校验面。
// 凭据不落日志（只打字段名与状态码）。
// ============================================================================
import { logger } from './logger.js';
import { isLoginRedirect } from './scanValidityGuard.js';

/** 用户名输入框候选名（找不到 type=text/email 时按名字猜） */
const USER_FIELD_RE = /^(user(name)?|login|log|email|account|acct|mail|uid|nick(name)?|phone|mobile)$/i;
/** hidden 字段透传上限（防恶意页面塞爆表单） */
const MAX_HIDDEN = 20;
/** hidden 字段值截断（csrf token 不会太长） */
const MAX_HIDDEN_VALUE = 512;

/** 解析 <input> 标签的属性（轻量正则：登录页表单结构远比整页解析简单） */
function parseInputs(html) {
  const inputs = [];
  const re = /<input\b([^>]*)>/gi;
  let m;
  while ((m = re.exec(html)) !== null && inputs.length < 100) {
    const attrs = {};
    const are = /([a-zA-Z-]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
    let a;
    while ((a = are.exec(m[1])) !== null) {
      attrs[a[1].toLowerCase()] = a[3] ?? a[4] ?? a[5] ?? '';
    }
    inputs.push(attrs);
  }
  return inputs;
}

/**
 * [纯函数] 从登录页 HTML 探测表单字段：
 * 密码框 = 第一个 type=password 的 input；用户名框 = 同表单里它之前最近的
 * type=text/email 输入框（名字符合候选集优先）；hidden 字段全量透传（CSRF 等）。
 * @param {string} html 登录页 HTML
 * @returns {{ usernameField: string|null, passwordField: string|null, hidden: Record<string,string> }|null}
 *   无密码框（非标准表单登录页）返回 null
 */
export function detectLoginFields(html) {
  const inputs = parseInputs(String(html ?? ''));
  const pwdIdx = inputs.findIndex((i) => String(i.type || '').toLowerCase() === 'password');
  if (pwdIdx < 0 || !inputs[pwdIdx].name) return null;
  let usernameField = null;
  for (let i = pwdIdx - 1; i >= 0; i -= 1) {
    const t = String(inputs[i].type || 'text').toLowerCase();
    if (t === 'hidden' || t === 'password' || t === 'submit' || t === 'checkbox' || t === 'radio') continue;
    if ((t === 'text' || t === 'email' || t === 'tel') && inputs[i].name) {
      usernameField = inputs[i].name;
      break;
    }
  }
  if (!usernameField) {
    // 候选名兜底：全表单找名字像用户名的输入框（非常规布局的用户名框可能在密码框之后）
    const byName = inputs.find((i, idx) => idx !== pwdIdx && i.name && USER_FIELD_RE.test(i.name));
    usernameField = byName ? byName.name : null;
  }
  /** @type {Record<string, string>} */
  const hidden = {};
  for (const i of inputs) {
    if (Object.keys(hidden).length >= MAX_HIDDEN) break;
    if (String(i.type || '').toLowerCase() === 'hidden' && i.name && i.value != null) {
      hidden[i.name] = String(i.value).slice(0, MAX_HIDDEN_VALUE);
    }
  }
  return {
    usernameField,
    passwordField: inputs[pwdIdx].name,
    hidden,
  };
}

/**
 * 请求是否为「会话过期」信号：401/403，或 302/303 跳登录页。
 * 403 带上是因为不少站过期后返回 403 登录页（body 有密码框也可佐证，但头部判定够用）。
 * @param {{status?: number, headers?: object}|null|undefined} res
 */
export function isLoginChallenge(res) {
  if (!res || typeof res !== 'object') return false;
  const status = Number(res.status);
  if (status === 401 || status === 403) return true;
  return isLoginRedirect(res);
}

/**
 * 执行一次登录：GET 登录页 → 探测字段 → POST 凭据（urlencoded，hidden 透传）。
 * @param {object} opts { client, login: {url, username, password, usernameField?, passwordField?} }
 * @returns {Promise<{ok: boolean, status: number, detail: string}>}
 */
export async function performLogin({ client, login }) {
  const url = String(login.url || '');
  // ① 取登录页（字段探测 + hidden/CSRF 透传）；取页失败也继续 POST（有的站登录页就是接口）
  let fields = null;
  try {
    const page = await client.request({ method: 'GET', url });
    fields = detectLoginFields(page?.data ?? '');
  } catch (e) {
    logger.warn(`[login] 登录页取页失败（继续按显式字段名尝试）：${e?.message || e}`);
  }
  const usernameField = login.usernameField || fields?.usernameField;
  const passwordField = login.passwordField || fields?.passwordField || 'password';
  if (!usernameField) {
    logger.warn('[login] 未探测到用户名输入框（可经 login.usernameField 显式指定）——登录可能无效');
  }
  const data = {
    ...(fields?.hidden || {}),
    ...(usernameField ? { [usernameField]: String(login.username ?? '') } : {}),
    [passwordField]: String(login.password ?? ''),
  };
  // ② 提交凭据（urlencoded 表单；302/303 视为登录流程正常推进）
  const res = await client.request({
    method: 'POST',
    url,
    data: new URLSearchParams(data).toString(),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  const status = Number(res?.status) || 0;
  const body = String(res?.data ?? '');
  // ③ 成功启发式：响应里不再有密码框（还在登录页 = 失败）且未被明确打回认证挑战
  // （302 重定向后的落点页状态码任意——仪表盘 200、目标不存在的跳转 404 都算登录成功）
  const stillOnLogin = /<input[^>]+type=(["']?)password\1/i.test(body);
  const challenged = status === 401 || status === 403 || isLoginRedirect(res);
  const ok = !stillOnLogin && !challenged;
  logger.info(`[login] 登录提交：status=${status} 字段=${usernameField || '?'}/${passwordField} 判定=${ok ? '成功' : '失败'}`);
  return { ok, status, detail: stillOnLogin ? '响应仍是登录页' : '' };
}

/**
 * 包装扫描级 httpClient 视图：会话过期自动重登一次并重试原请求。
 * 与 csrfKeeper.withCsrf 同一包装惯例（返回 {request} 视图，挂在 safeUrl/csrf 之后）。
 * 防抖：并发请求同时遇 401 时只做一次登录（in-flight 去重）；凭据错误时重登返回失败
 * → 直接放行原响应（由 scanValidityGuard 的 authLost 机制按既有口径收尾），不会死循环。
 * @param {object} client 原始 per-scan 视图
 * @param {{url:string, username?:string, password?:string, usernameField?:string, passwordField?:string}} login
 */
export function withLoginFlow(client, login) {
  let inFlight = null;
  async function loginOnce() {
    try {
      const r = await performLogin({ client, login });
      return r.ok === true;
    } catch (e) {
      logger.warn(`[login] 自动登录异常（放行原响应）：${e?.message || e}`);
      return false;
    }
  }
  return {
    request: async (opts = {}) => {
      const res = await client.request(opts);
      if (!isLoginChallenge(res)) return res;
      // 会话过期 → 重登（并发去重）→ 重试原请求一次
      if (!inFlight) inFlight = loginOnce().finally(() => { inFlight = null; });
      const ok = await inFlight;
      if (!ok) return res;
      return client.request(opts);
    },
  };
}

export default { detectLoginFields, isLoginChallenge, performLogin, withLoginFlow };
