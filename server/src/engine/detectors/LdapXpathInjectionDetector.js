import { NoSqlInjectionDetector } from './NoSqlInjectionDetector.js';
import { createDetectionResult } from '../models.js';
import { LDAP_FILTER_PROBES, XPATH_PROBES } from '../payloads.js';

// ============================================================================
// LdapXpathInjectionDetector.js —— [D203] LDAP / XPath 注入检测器
//
// 对标 sqlmap 1.10 的 --ldap / --xpath（底账此前记 P2 gap：无检测器、无 payload 面）。
// 复用非 SQL 补充趟的门控/并发/结果聚合（supplementalRuns._runNoSql），
// 按 ctx.noSqlKind ∈ 'ldap'|'xpath' 分派，与 nosql/graphql/ssti 并列为通道类别。
//
// 判定**不另起炉灶**：继承 NoSqlInjectionDetector，直接调用抽出来的
// `_detectBooleanProbes` —— 失败重发、真/假内容差异、与基线可区分、二次确认
// 四道误报防线与 NoSQL 通道逐字同源。只替换探测表与 payload 拼接方式。
//
// 不做「响应出现 XPath/LDAP 解析错误就算命中」：解析错误只证明后端吃了非法语法，
// 不证明攻击者能控制查询语义，会把「参数校验报错」大面积误报成注入。
// ============================================================================

const PROBES = {
  ldap: { probes: LDAP_FILTER_PROBES, label: 'LDAP 过滤器注入' },
  xpath: { probes: XPATH_PROBES, label: 'XPath 表达式注入' },
};

export class LdapXpathInjectionDetector extends NoSqlInjectionDetector {
  /**
   * @param {object} ctx { httpClient, target, point, config, noSqlKind: 'ldap'|'xpath' }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { httpClient, target, point, noSqlKind } = ctx;
    const entry = PROBES[noSqlKind];
    const result = createDetectionResult(point.id, 'nosql');
    result.noSqlKind = noSqlKind;
    if (!entry) return result; // 未知类别 → 不投，与父类同口径

    try {
      const baseResp = await this.send(httpClient, ctx, this.buildRequest(target, point, point.originalValue || '1'));
      const baseBody = String(baseResp?.data ?? '');
      return await this._detectBooleanProbes(
        ctx, point, baseBody, result,
        entry.probes, (orig, frag) => `${orig}${frag}`, entry.label, noSqlKind
      );
    } catch {
      // 单次失败不致命，标记未命中（与父类 detect 同口径）
      return result;
    }
  }
}

export default LdapXpathInjectionDetector;
