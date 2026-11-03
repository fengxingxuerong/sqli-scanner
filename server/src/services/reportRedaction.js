// ============================================================================
// services/reportRedaction.js —— 统一脱敏管道（spec 5.3.1）
//
// 解决什么：脱敏逻辑此前分散在 ReportGenerator.sanitizeTargetForExport /
// reportPoC.pocRedactedForExport / hashAnalysis（不回显原文但 data.passwords 仍含原文），
// 无统一管道保证全格式一致。本模块收口：所有格式导出前必经 redactReport。
//
// 三层脱敏（按 opts 分层，缺省全 false ⇒ 零行为变化，向后兼容）：
//   · redactPasswords → data.passwords 中哈希原文打码（保留 identity，打码 hash）
//   · redactAuth      → PoC 凭据头（Authorization/Cookie/x-api-token）打码
//   · redactTarget    → target.config.auth/proxy/login/clientCert 置 null，
//                       cookieParams/headerParams 删除，URL 内嵌凭据打码
//
// 约束（spec 5.3.1 规则 4）：脱敏后风险标注（passwordAnalysis）仍可读且不可反推原文。
// ============================================================================
const REDACTED = '[REDACTED]';

// 落盘/持久化专用：这些键的值一律打码（键名保留，便于报告读者知道「曾配置过」）。
// 只作用于 target 与 PoC headers，不递归改写漏洞证据正文。
const SENSITIVE_KEY_RE =
  /^(password|passwd|pwd|secret|token|authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-api-token|x-scan-token|clientcert|privatekey|private_key|access_key|secret_key)$/i;

/** 打码单个 password 条目：保留 identity（最后一个 `:` 前），打码 hash */
function redactPasswordEntry(entry) {
  if (typeof entry !== 'string') return REDACTED;
  const colon = entry.lastIndexOf(':');
  if (colon <= 0) return REDACTED;
  return entry.slice(0, colon) + ':' + REDACTED;
}

/** 打码 PoC/文本中的凭据 */
export function redactPocText(s) {
  if (typeof s !== 'string') return s;
  return s
    // -H "Authorization: ..." / -H "Cookie: ..." / -H "x-api-token: ..."
    .replace(/(-H\s+['"])(?:Authorization|Proxy-Authorization|Cookie|x-api-token|x-scan-token)(:\s*[^'"]*)(['"])/gi, `$1${REDACTED}$3`)
    // 内联 Authorization: Bearer/Basic <token>
    .replace(/(Authorization:\s*)(?:Bearer|Basic)\s+[^\s,;'"&]+/gi, `$1${REDACTED}`)
    // 裸 Cookie/Set-Cookie 头行（HTML/Markdown 报告里的原始报文片段）
    .replace(/((?:set-)?cookie\s*:\s*)[^\r\n<]+/gi, `$1${REDACTED}`)
    // URL 内嵌凭据 user:pass@host
    .replace(/:\/\/([^:/@\s]+):([^/@\s]+)@/, `://$1:'${REDACTED}'@`);
}

/** 打码 PoC headers 对象中的凭据头（保留头名，值替换） */
function redactPocHeaders(headers) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return headers;
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SENSITIVE_KEY_RE.test(String(k)) ? REDACTED : v;
  }
  return out;
}

/** 打码 vuln 的 PoC 凭据 */
function redactVulnAuth(vuln) {
  if (!vuln || typeof vuln !== 'object') return vuln;
  const out = { ...vuln };
  if (out.poc && typeof out.poc === 'object' && !Array.isArray(out.poc)) {
    out.poc = { ...out.poc };
    for (const key of ['curl', 'command', 'request', 'raw', 'body']) {
      if (typeof out.poc[key] === 'string') out.poc[key] = redactPocText(out.poc[key]);
    }
    if (out.poc.headers) out.poc.headers = redactPocHeaders(out.poc.headers);
  } else if (typeof out.poc === 'string') {
    out.poc = redactPocText(out.poc);
  } else if (Array.isArray(out.poc)) {
    out.poc = out.poc.map((p) => (typeof p === 'string' ? redactPocText(p) : p));
  }
  return out;
}

/**
 * 递归打码 target 内的敏感键值（只改值，保留键名）。
 * 只用于落盘/持久化：报告正文里的漏洞证据与参数名不动。
 * @param {any} node
 * @param {number} [depth]
 * @returns {any}
 */
function redactSensitiveValues(node, depth = 0) {
  if (node == null || depth > 8) return node;
  if (Array.isArray(node)) return node.map((v) => redactSensitiveValues(v, depth + 1));
  if (typeof node !== 'object') return node;
  const out = {};
  for (const [k, v] of Object.entries(node)) {
    out[k] = SENSITIVE_KEY_RE.test(k) && v != null ? REDACTED : redactSensitiveValues(v, depth + 1);
  }
  return out;
}

/**
 * 落盘点位脱敏：cookie/header 注入点的 originalValue 本身就是会话凭据；
 * 参数名命中敏感词（token/password/authorization…）时同样打码。
 * 点位本身（id/location/param）保留，报告仍能说明「测过这个点」。
 * @param {Array<object>} points
 * @returns {Array<object>}
 */
export function redactPointsForDisk(points) {
  if (!Array.isArray(points)) return points;
  return points.map((p) => {
    if (!p || typeof p !== 'object') return p;
    const out = { ...p };
    const loc = String(out.location || out.in || '').toLowerCase();
    if (
      loc === 'cookie' || loc === 'header' || loc === 'headers'
      || SENSITIVE_KEY_RE.test(String(out.param || ''))
    ) {
      if (out.originalValue != null) out.originalValue = REDACTED;
    }
    if (out.formValues && typeof out.formValues === 'object') {
      out.formValues = redactSensitiveValues(out.formValues);
    }
    return out;
  });
}

/** 落盘 target 脱敏：auth/proxy/login/clientCert 置 null，cookie/header 参数删除，URL 内嵌凭据打码 */
function redactTargetForDisk(target) {
  if (!target || typeof target !== 'object') return target;
  const out = { ...target };
  for (const key of ['baseUrl', 'url']) {
    if (typeof out[key] === 'string') out[key] = redactPocText(out[key]);
  }
  if (out.config && typeof out.config === 'object') {
    const cfg = { ...out.config };
    for (const key of ['auth', 'proxy', 'login', 'clientCert', 'bearerRefresh']) {
      if (key in cfg) cfg[key] = null;
    }
    out.config = redactSensitiveValues(cfg);
  }
  if ('cookieParams' in out) delete out.cookieParams;
  if ('headerParams' in out) delete out.headerParams;
  if (out.db && typeof out.db === 'object') {
    out.db = { ...out.db };
    if (out.db.connectionString) out.db.connectionString = '***';
    if (out.db.password) out.db.password = '***';
  }
  return redactSensitiveValues(out);
}

/**
 * target 与点位凭据同属落盘面：抽成一处，避免 redactReport 的分支继续增长。
 * @param {object} out 已克隆的报告
 */
function redactTargetAndPointsForDisk(out) {
  if (out.target && typeof out.target === 'object') out.target = redactTargetForDisk(out.target);
  if (Array.isArray(out.points)) out.points = redactPointsForDisk(out.points);
}

/**
 * 落盘/持久化专用脱敏：强制打开三层，且额外清掉 target 的会话凭据。
 * 不修改入参（深拷贝）。
 * @param {object} report
 * @returns {object}
 */
export function redactPersistedReport(report) {
  if (!report || typeof report !== 'object') return report;
  return redactReport(report, { redactPasswords: true, redactAuth: true, redactTarget: true });
}

/**
 * 统一脱敏管道。返回**深拷贝**（不污染内存中的原 report）。
 * @param {object} report 原始报告
 * @param {{redactPasswords?:boolean, redactAuth?:boolean, redactTarget?:boolean}} opts
 * @returns {object} 脱敏后的报告
 */
export function redactReport(report, opts = {}) {
  if (!report || typeof report !== 'object') return report;
  const { redactPasswords = false, redactAuth = false, redactTarget = false } = opts;
  if (!redactPasswords && !redactAuth && !redactTarget) return report; // 零行为变化

  const out = structuredClone(report);

  // ① passwords 哈希原文打码
  if (redactPasswords && out.data && Array.isArray(out.data.passwords)) {
    out.data.passwords = out.data.passwords.map(redactPasswordEntry);
  }

  // ② PoC 凭据头打码
  if (redactAuth && Array.isArray(out.vulns)) {
    out.vulns = out.vulns.map(redactVulnAuth);
  }

  // ③ target 与点位凭据置 null / 删除（导出与落盘共用；导出路径随后还会过 sanitizeTargetForExport）
  if (redactTarget) redactTargetAndPointsForDisk(out);

  return out;
}

/** 解析脱敏配置：非法值按默认（不脱敏）处理并告警 */
export function parseRedactOpts(raw) {
  const opts = {};
  const warn = [];
  for (const key of ['redactPasswords', 'redactAuth', 'redactTarget']) {
    const v = raw?.[key];
    if (v === undefined || v === false || v === 'false' || v === 0) {
      opts[key] = false;
    } else if (v === true || v === 'true' || v === 1) {
      opts[key] = true;
    } else {
      opts[key] = false; // 非法值按默认处理
      warn.push(`${key}=${JSON.stringify(v)} 非法，按默认 false 处理`);
    }
  }
  return { opts, warn };
}