// ============================================================================
// summaryFingerprint.js —— [D202 对标 sqlmap --fingerprint] 报告级指纹汇总
//
// 与同目录 fingerprint.js（DBMS 指纹缓存）职责不同，勿合并。
// 诚实边界：**不做主动指纹探测**。本函数只把扫描期已经采集到的信号
// （DBMS/版本/证据等级 / WAF 厂商 / 用户显式 --os / 显式 --encoding）汇总成
// `summary.fingerprint` 一等字段，让交付报告与 SSE/前端拿到同一份事实。
// OS 在没有 --os 时一律为 null + source='unspecified'，不从 DBMS 猜、不编造。
// ============================================================================

/**
 * @param {object} input
 * @param {object} [input.report] 报告（读 summary.dbmsEvidence）
 * @param {Array<object>} [input.pointsToScan] 注入点（读 dbms / dbmsVersion）
 * @param {Map<string, object>|object} [input.wafAgg] WAF 识别聚合
 * @param {object} [input.config] 扫描配置（读 os / encoding）
 * @param {string|null} [input.dbms] 汇总 DBMS
 * @returns {object} 指纹对象
 */
export function buildFingerprint({ report, pointsToScan = [], wafAgg, config = {}, dbms } = {}) {
  const point = pointsToScan.find((p) => p && p.dbms) || {};
  const vendors = wafAgg instanceof Map
    ? [...wafAgg.keys()]
    : Object.keys(wafAgg || {});
  return {
    dbms: dbms || point.dbms || null,
    dbmsVersion: point.dbmsVersion || null,
    dbmsEvidenceLevel: report?.summary?.dbmsEvidence?.level ?? null,
    os: config.os || null,
    osSource: config.os ? 'explicit' : 'unspecified',
    encoding: config.encoding || null,
    wafVendors: vendors,
    basis: 'scan-signals-only',
    caveat: '仅汇总本次扫描已采集的信号；OS / Web 服务器未做主动指纹探测，未显式指定时 OS 不推断',
  };
}
