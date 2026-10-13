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
//   · redactTarget    → target.config.auth/proxy 置 null
//
// 约束（spec 5.3.1 规则 4）：脱敏后风险标注（passwordAnalysis）仍可读且不可反推原文。
// ============================================================================
const REDACTED = '[REDACTED]';

/** 打码单个 password 条目：保留 identity（最后一个 `:` 前），打码 hash */
function redactPasswordEntry(entry) {
  if (typeof entry !== 'string') return REDACTED;
  const colon = entry.lastIndexOf(':');
  if (colon <= 0) return REDACTED;
  return entry.slice(0, colon) + ':' + REDACTED;
}

/** 打码 PoC 字符串中的凭据头 */
function redactPocString(s) {
  if (typeof s !== 'string') return s;
  return s
    // -H "Authorization: ..." / -H "Cookie: ..." / -H "x-api-token: ..."
    .replace(/(-H\s+['"])(?:Authorization|Proxy-Authorization|Cookie|x-api-token|x-scan-token)(:\s*[^'"]*)(['"])/gi, `$1${REDACTED}$3`)
    // 内联 Authorization: Bearer/Basic <token>
    .replace(/(Authorization:\s*)(?:Bearer|Basic)\s+[^\s,;'"&]+/gi, `$1${REDACTED}`)
    // URL 内嵌凭据 user:pass@host
    .replace(/:\/\/([^:/@\s]+):([^/@\s]+)@/, `://$1:'${REDACTED}'@`);
}

/** 打码 vuln 的 PoC 凭据 */
function redactVulnAuth(vuln) {
  if (!vuln || typeof vuln !== 'object') return vuln;
  const out = { ...vuln };
  if (out.poc && typeof out.poc === 'object' && !Array.isArray(out.poc)) {
    out.poc = { ...out.poc };
    for (const key of ['curl', 'command', 'request', 'raw']) {
      if (typeof out.poc[key] === 'string') out.poc[key] = redactPocString(out.poc[key]);
    }
  } else if (typeof out.poc === 'string') {
    out.poc = redactPocString(out.poc);
  } else if (Array.isArray(out.poc)) {
    out.poc = out.poc.map((p) => (typeof p === 'string' ? redactPocString(p) : p));
  }
  return out;
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

  // ③ target.auth/proxy 置 null
  if (redactTarget && out.target && out.target.config && typeof out.target.config === 'object') {
    out.target.config = { ...out.target.config, auth: null, proxy: null };
  }

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