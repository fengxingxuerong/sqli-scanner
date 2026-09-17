// ============================================================================
// vulnEnrich.js —— 漏洞条目上下文回填（「受影响参数」一等字段）
// ============================================================================
// 存在理由（实测缺陷）：vuln 对象只有 pointId，而 pointId 是
// `sha256(location:param:actionUrl)` 的前 8 位十六进制——一个内部 hash。
// 报告里漏洞表因此只印得出 `3f2a91bc`，客户拿着报告根本不知道是**哪个参数**出了问题，
// 必须回查 report.points 才能翻译，而报告一旦脱离原始 JSON 就断了这条线索。
// 交付物的「受影响参数」必须是漏洞条目的**自包含字段**。
//
// 本模块只做一件事：把 point/target 上已有的信息复制（而非重新推导）到漏洞条目上，
// 使每条 vuln 自带 { param, location, locationText, url, method, affectedParam, vulnType }。
//
// 设计约束：
//   - 只复制、不推导 URL：affected url 取 point.actionUrl（表单实际提交地址）优先，
//     否则取 target.baseUrl；绝不在此处拼查询串（拼接逻辑在 injection.js，重复实现必漂移）。
//   - 纯函数 + 浅拷贝：不写回调用方传入的 vuln/report 对象（既有测试锁定
//     「导出不得给输入 vuln 挂字段」，见 server/tests/poc.evidence.test.js）。
//   - 永不抛异常：字段缺失时降级为 null，报告生成不能因增强项失败。
// ============================================================================

import { vulnTypeOf, locationText } from '../services/vulnTaxonomy.js';

/**
 * 取该注入点的「受影响请求」地址。
 * 优先级：表单实际提交地址（actionUrl）→ 目标基准地址。
 * 不拼接查询串：URL 上的注入点其 baseUrl 已含该参数，拼接反而会产出与实发请求不符的地址。
 * @param {object|null} point
 * @param {object|null} target
 * @returns {string|null}
 */
export function affectedUrlOf(point, target) {
  const cand = (point && (point.actionUrl || point.crawledUrl)) || (target && (target.baseUrl || target.url)) || '';
  return cand ? String(cand) : null;
}

/**
 * 受影响请求方法：表单点的实际提交方法优先，否则目标方法（默认 GET）。
 * @param {object|null} point
 * @param {object|null} target
 * @returns {string}
 */
export function affectedMethodOf(point, target) {
  const m = (point && point.formMethod) || (target && target.method) || 'GET';
  return String(m).toUpperCase();
}

/**
 * 人读形式的受影响参数：「参数名 · 位置」。
 * 三个分支统一同一格式（`名称 · 位置`）——不一致会让报告里出现 `a · b` 与 `c· d` 两种排版，
 * 看起来像两个不同字段。直连模式无参数名时退化为 SQL 模板标识，避免空单元格。
 * @param {string|null} param
 * @param {string} location
 * @param {object|null} point
 * @returns {string}
 */
export function affectedParamLabel(param, location, point) {
  const loc = locationText(location);
  const name = param || (point && point.sqlTemplate ? '（直连 SQL 模板）' : '（未记录参数名）');
  return `${name} · ${loc}`;
}

/**
 * 给单条漏洞补上下文。已存在的非空字段不覆盖（幂等，可重复调用）。
 * @param {object} vuln
 * @param {object|null} point 该漏洞对应的注入点（可能为 null：历史快照/外部构造报告）
 * @param {object|null} target
 * @returns {object} 新的漏洞对象（浅拷贝）
 */
export function enrichVuln(vuln, point, target) {
  if (!vuln || typeof vuln !== 'object') return vuln;
  try {
    const param = point && point.param != null ? String(point.param) : null;
    const location = (point && point.location) || null;
    const out = { ...vuln, vulnType: vuln.vulnType || vulnTypeOf(vuln.technique) };

    // 只在「本条目尚无该字段」时写入：不覆盖外部显式给定的值，保证幂等
    if (param != null && out.param == null) out.param = param;
    if (location != null && out.location == null) out.location = location;
    if (out.locationText == null) out.locationText = locationText(location);
    if (out.url == null) {
      const url = affectedUrlOf(point, target);
      if (url) out.url = url;
    }
    if (out.method == null) out.method = affectedMethodOf(point, target);
    if (out.affectedParam == null) out.affectedParam = affectedParamLabel(out.param ?? param, location, point);
    return out;
  } catch {
    return vuln; // 增强是增益项：任何异常都不让报告生成失败
  }
}

/**
 * 给整份报告的漏洞列表补上下文（返回浅拷贝，不写回入参）。
 * report.points 是注入点的权威来源；pointId 找不到时仍给出 vulnType 与位置说明，
 * 只有参数名缺失（而非整条增强失败）。
 * @param {object} report
 * @returns {object} 新报告对象（vulns 已增强）
 */
export function attachVulnContext(report) {
  if (!report || typeof report !== 'object') return report;
  const vulns = Array.isArray(report.vulns) ? report.vulns : null;
  if (!vulns || !vulns.length) return report;
  const target = report.target || null;
  const byId = new Map();
  for (const p of Array.isArray(report.points) ? report.points : []) {
    if (p && p.id != null) byId.set(p.id, p);
  }
  let touched = false;
  const out = vulns.map((v) => {
    const enriched = enrichVuln(v, byId.get(v?.pointId) || null, target);
    if (enriched !== v) touched = true;
    return enriched;
  });
  return touched ? { ...report, vulns: out } : report;
}

export default attachVulnContext;
