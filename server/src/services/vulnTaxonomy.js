// ============================================================================
// vulnTaxonomy.js —— 漏洞类型规范化词表（交付物级「漏洞类型」单一取数源）
// ============================================================================
// 存在理由：引擎内部只认 technique（union/error/boolean/…），这是**检测通道**口径，
// 不是**漏洞类型**口径。而甲方交付报告、漏洞管理平台、SARIF 消费者要的是
// 「这是什么漏洞 + CWE 编号 + OWASP 分类」，扫描器内部标识对它们没有意义。
// 此前报告里只印 technique，收报告的人得自己翻译成 CWE-89——翻译过程就是失真来源。
//
// 本模块把 technique → 规范化漏洞类型做成一维映射，供 ReportGenerator（md/html/csv）、
// vulnEnrich（JSON 报告字段）与 SARIF 导出共用。纯数据 + 纯函数，零副作用、零 IO。
//
// 口径声明（诚实边界）：
//   - CWE 按「注入通道」映射到 CWE-89（SQL 注入）/ CWE-943（NoSQL 注入）。
//     SQL 注入的六个子技术全部归 CWE-89——CWE 不细分 union/boolean/time，
//     细分体现在 nameZh/nameEn 与 technique 字段上，不要把差异塞进 CWE 编号。
//   - CVSS 不在本模块：评分口径在 reportDelivery.js（cvssFor），避免两处漂移。
// ============================================================================

/** 统一的 OWASP Top 10 分类（本项目命中的注入类漏洞全部落在此类） */
export const OWASP_INJECTION = 'A03:2021-Injection';

/** 注入位置 → 中文名（报告「受影响参数」列的位置说明） */
export const LOCATION_TEXT = {
  url: 'URL 查询参数（GET query）',
  body: '请求体参数（POST body / 表单 / JSON）',
  cookie: 'Cookie 参数',
  header: 'HTTP 请求头',
  path: 'URL 路径段（path segment）',
  direct: '直连模式（SQL 模板，无 HTTP 请求）',
};

/**
 * technique → 漏洞类型元数据。
 * 键必须与检测器 technique 标识完全一致（见 server/src/engine/detectors/）。
 */
export const VULN_TAXONOMY = {
  union: {
    key: 'union',
    nameZh: 'SQL 注入（联合查询注入）',
    nameEn: 'SQL Injection (UNION-based)',
    cwe: 'CWE-89',
    owasp: OWASP_INJECTION,
    descZh: '攻击者用 UNION SELECT 把自有查询的结果拼进原查询回显位，可直接读取任意表数据。',
  },
  error: {
    key: 'error',
    nameZh: 'SQL 注入（报错注入）',
    nameEn: 'SQL Injection (Error-based)',
    cwe: 'CWE-89',
    owasp: OWASP_INJECTION,
    descZh: '利用数据库报错信息把查询结果带回页面，同时泄露 SQL 上下文与数据库指纹。',
  },
  boolean: {
    key: 'boolean',
    nameZh: 'SQL 注入（布尔盲注）',
    nameEn: 'SQL Injection (Boolean-blind)',
    cwe: 'CWE-89',
    owasp: OWASP_INJECTION,
    descZh: '页面无回显无报错，靠「真/假条件导致的内容差异」逐位推断数据，不依赖回显特征。',
  },
  time: {
    key: 'time',
    nameZh: 'SQL 注入（时间盲注）',
    nameEn: 'SQL Injection (Time-blind)',
    cwe: 'CWE-89',
    owasp: OWASP_INJECTION,
    descZh: '页面在真假条件下完全一致时，用条件化延迟（SLEEP/WAITFOR/pg_sleep）逐位推断数据。',
  },
  stacked: {
    key: 'stacked',
    nameZh: 'SQL 注入（堆叠查询 / 多语句执行）',
    nameEn: 'SQL Injection (Stacked queries)',
    cwe: 'CWE-89',
    owasp: OWASP_INJECTION,
    descZh: '注入点支持多语句执行，可追加 INSERT/UPDATE/DELETE 或调用存储过程，直接改写数据库。',
  },
  oob: {
    key: 'oob',
    nameZh: 'SQL 注入（带外通道 / OOB）',
    nameEn: 'SQL Injection (Out-of-band)',
    cwe: 'CWE-89',
    owasp: OWASP_INJECTION,
    descZh: '回显与延迟均不可用时，驱动数据库进程主动向外发起 DNS/HTTP 请求把数据带出。',
  },
  second_order: {
    key: 'second_order',
    nameZh: 'SQL 注入（二阶注入）',
    nameEn: 'SQL Injection (Second-order)',
    cwe: 'CWE-89',
    owasp: OWASP_INJECTION,
    descZh: '注入载荷先被安全存储，随后在另一处查询中被拼接执行——写入点与触发点分离。',
  },
  inline: {
    key: 'inline',
    nameZh: 'SQL 注入（内联查询注入）',
    nameEn: 'SQL Injection (Inline query)',
    cwe: 'CWE-89',
    owasp: OWASP_INJECTION,
    descZh: '用户输入被拼进派生表/子查询等内联上下文，非典型 WHERE 位置的回显型注入。',
  },
  nosql: {
    key: 'nosql',
    nameZh: 'NoSQL 注入',
    nameEn: 'NoSQL Injection',
    cwe: 'CWE-943',
    owasp: OWASP_INJECTION,
    descZh: '把用户输入直接并入 NoSQL 查询对象（如 $where / 查询操作符），可绕过鉴权或读出数据。',
  },
};

/** 未收录技术通道的兜底类型：不编造 CWE，只标 SQL 注入类 */
export const VULN_TYPE_FALLBACK = {
  key: 'unknown',
  nameZh: 'SQL 注入（未分类通道）',
  nameEn: 'SQL Injection (unclassified)',
  cwe: 'CWE-89',
  owasp: OWASP_INJECTION,
  descZh: '检测通道未收录于规范化词表，按 SQL 注入类处置；CWE 按注入类给出，具体子类型待人工复核。',
};

/**
 * technique → 规范化漏洞类型。
 * @param {string} technique 检测器技术标识
 * @returns {{key:string,nameZh:string,nameEn:string,cwe:string,owasp:string,descZh:string}}
 */
export function vulnTypeOf(technique) {
  return VULN_TAXONOMY[technique] || { ...VULN_TYPE_FALLBACK, key: technique || 'unknown' };
}

/**
 * 注入位置 → 中文说明（未知位置原样返回，不编造）。
 * @param {string} location
 */
export function locationText(location) {
  return LOCATION_TEXT[location] || (location ? String(location) : '未知位置');
}

export default vulnTypeOf;
