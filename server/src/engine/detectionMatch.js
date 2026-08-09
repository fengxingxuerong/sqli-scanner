// 自定义检测判定锚点（对标 sqlmap --string / --not-string / --regexp / --code）
// 让操作员在布尔/时间盲注里给定「真/假响应」的内容或状态码指纹，作为确定性判定依据，
// 绕开纯统计判定（在动态内容/定制 404/特殊状态码目标上显著提升检出率与可控性）。
//
// 设计原则：纯函数、可单测、零副作用；仅当 config.detectMatch 至少含一个有效锚点时激活，
// 否则返回 null（调用方走原统计判定分支，保证默认路径零回归）。
import { AppError, ErrorCode } from '../core/errors.js';

/**
 * 归一化 detectMatch 配置。无任何有效锚点 → 返回 null（不激活）。
 * @param {object} config 引擎 config（target.config === ctx.config）
 * @returns {null | {string?:string, notString?:string, regexp?:RegExp, code?:number}}
 */
export function normalizeDetectMatch(config) {
  const c = config || {};
  const m = c.detectMatch;
  if (!m || typeof m !== 'object') return null;
  const anchors = {};
  if (m.string != null && String(m.string) !== '') anchors.string = String(m.string);
  if (m.notString != null && String(m.notString) !== '') anchors.notString = String(m.notString);
  if (m.regexp != null && String(m.regexp) !== '') {
    try {
      anchors.regexp = new RegExp(String(m.regexp));
    } catch {
      // 非法正则：忽略该锚点（不阻断其余锚点）
      anchors._badRegexp = true;
    }
  }
  if (m.code != null) {
    const n = Number(m.code);
    if (Number.isFinite(n)) anchors.code = n;
  }
  if (Object.keys(anchors).length === 0) return null;
  return anchors;
}

/**
 * 评估各锚点（AND 语义：所有给定锚点必须同时通过才判 vulnerable）。
 * 语义（对标 sqlmap）：
 *   - string：TRUE 响应应「含」该串、FALSE 响应应「不含」
 *   - notString：TRUE 响应应「不含」该串、FALSE 响应应「含」
 *   - regexp：该正则应「匹配」TRUE 响应、且「不匹配」FALSE 响应
 *   - code：TRUE 响应 HTTP 状态码应 === code、FALSE 响应应 !== code
 * @param {object} match normalizeDetectMatch 返回值
 * @param {{trueBody:string, falseBody:string, trueStatus:number, falseStatus:number}} resp
 * @returns {{vulnerable:boolean, evidence:string}}
 */
export function evaluateDetectMatch(match, resp) {
  const { trueBody = '', falseBody = '', trueStatus = 0, falseStatus = 0 } = resp || {};
  const results = [];
  if (match.string != null) {
    const tp = trueBody.includes(match.string);
    const fp = falseBody.includes(match.string);
    results.push({ name: `string(${match.string})`, pass: tp && !fp, detail: `true含=${tp} false含=${fp}` });
  }
  if (match.notString != null) {
    const tp = trueBody.includes(match.notString);
    const fp = falseBody.includes(match.notString);
    results.push({ name: `notString(${match.notString})`, pass: !tp && fp, detail: `true含=${tp} false含=${fp}` });
  }
  if (match.regexp != null) {
    const tp = match.regexp.test(trueBody);
    const fp = match.regexp.test(falseBody);
    results.push({ name: 'regexp', pass: tp && !fp, detail: `true匹配=${tp} false匹配=${fp}` });
  }
  if (match.code != null) {
    const tp = trueStatus === match.code;
    const fp = falseStatus === match.code;
    results.push({ name: `code(${match.code})`, pass: tp && !fp, detail: `trueStatus=${trueStatus} falseStatus=${falseStatus}` });
  }
  const allPass = results.length > 0 && results.every((r) => r.pass);
  const evidence = results.map((r) => `${r.name}:${r.pass ? 'PASS' : 'FAIL'}(${r.detail})`).join('; ');
  return { vulnerable: allPass, evidence };
}

// 兼容性校验：CLI/API 入口可调用，提前拦截非法正则，给出可读错误（而非运行时静默忽略）
export function validateDetectMatch(config) {
  const c = config || {};
  const m = c.detectMatch;
  if (!m || typeof m !== 'object') return true;
  if (m.regexp != null && String(m.regexp) !== '') {
    try {
      // eslint-disable-next-line no-new
      new RegExp(String(m.regexp));
    } catch (e) {
      throw new AppError(ErrorCode.INVALID_PARAM, `--regexp 非法正则：${e.message}`);
    }
  }
  if (m.code != null && !Number.isFinite(Number(m.code))) {
    throw new AppError(ErrorCode.INVALID_PARAM, `--code 必须是 HTTP 状态码数字（如 200），当前 ${m.code}`);
  }
  return true;
}
