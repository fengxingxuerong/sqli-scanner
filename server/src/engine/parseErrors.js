// ============================================================================
// parseErrors.js —— [G4 对标 sqlmap --parse-errors]
//
// sqlmap `--parse-errors` 语义：从响应中解析数据库报错信息（原文 + SQL 上下文），
// 供证据链/AI 报告使用。本项目此前错误响应原文不进证据链（ErrorDetector 仅留
// hit.match 报错签名）。本模块提供纯函数：
//   · extractErrorContext(body)：报错签名匹配 + 报错附近原文片段截取
//   · extractSqlFragment(body)：报错中的 SQL 上下文片段（引号包裹的片段 / LINE n: 行）
// 默认 opt-in（config.parseErrors === true 才调用），零行为变化。
// ============================================================================
import { ERROR_SIG } from './payloads.js';

// 报错中的 SQL 上下文片段提取：
//   · PostgreSQL：LINE 1: SELECT ... FROM users WHERE ...
//   · MySQL：You have an error in your SQL syntax ... near 'xxx' at line 1
//   · SQL Server：Msg 207, Level 16, State 1, Line 1 / Incorrect syntax near 'xxx'
//   · Oracle：ORA-00933: SQL command not properly ended（无片段，仅签名）
const SQL_FRAGMENT_RES = [
  /LINE\s*\d+\s*:\s*([^\r\n]{1,160})/i,
  /(?:near|at)\s+["']((?:[^"']|['"]){1,80})/i,
  /(?:Query|Statement|SQL)[:：]\s*([^\r\n]{1,160})/i,
  /Incorrect\s+syntax\s+(?:near\s+)?["']?((?:[^"']|['"]){1,80})/i,
];

/**
 * 从响应体中提取「报错特征 + 报错附近原文片段」。
 * @param {string|object|undefined|null} body 响应体（res.data 原始值）
 * @param {{maxCtx?:number, maxBody?:number}} [opts] maxCtx=上下文截断长度；maxBody=留存原文上限
 * @returns {{match:string, context:string, bodyTruncated:string}|null} 无报错特征返回 null
 */
export function extractErrorContext(body, { maxCtx = 200, maxBody = 2000 } = {}) {
  const s = String(body ?? '');
  if (!s) return null;
  const m = s.match(ERROR_SIG);
  if (!m) return null;
  const idx = m.index ?? -1;
  // 截取报错签名前后上下文（整段 HTML 里定位到报错信息所在窗口）
  const start = Math.max(0, idx - 40);
  let context = idx >= 0
    ? s.slice(start, start + maxCtx)
    : s.slice(0, maxCtx);
  // 去除可能夹带的 HTML 标签残余（保留可读文本），并防上下文为空
  context = context.replace(/<[^>]*>/g, '').trim() || m[0].slice(0, maxCtx);
  return {
    match: m[0].slice(0, 200),
    context: context.slice(0, maxCtx),
    bodyTruncated: s.length > maxBody ? s.slice(0, maxBody) : s,
  };
}

/**
 * 从响应体中提取报错里的 SQL 上下文片段（报错常回显 SQL 附近的原始查询形态）。
 * @param {string|object|undefined|null} body 响应体
 * @param {{maxLen?:number}} [opts] 片段截断长度
 * @returns {string|null} 提取到的片段（去标签、单行截断）；无片段返回 null
 */
export function extractSqlFragment(body, { maxLen = 160 } = {}) {
  const s = String(body ?? '').replace(/<[^>]*>/g, ' ');
  if (!s) return null;
  for (const re of SQL_FRAGMENT_RES) {
    const m = s.match(re);
    if (m && m[1] && m[1].length >= 4) {
      const frag = m[1].replace(/\s+/g, ' ').trim();
      if (frag && /[A-Za-z0-9_]/i.test(frag)) return frag.slice(0, maxLen);
    }
  }
  return null;
}