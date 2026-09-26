import { createHash } from 'node:crypto';
import { nanoid } from 'nanoid'; // 仅 scanId / targetId 用（随机，不需稳定）
import { AppError, ErrorCode } from '../core/errors.js';
import { defaults } from '../config/defaults.js';

// 工厂与校验函数：构造 Target / InjectionPoint / DetectionResult /
// Vulnerability / ReportModel / ExtractedData，保证字段完整。

/**
 * 扫描目标（HTTP 模式或直连模式）。直连模式用 db/sqlTemplate，HTTP 模式用 baseUrl 等。
 * @typedef {object} Target
 * @property {string} id
 * @property {'http'|'direct'} mode
 * @property {string} [baseUrl]
 * @property {string} [method]
 * @property {Record<string, any>} [bodyParams]
 * @property {object|null} [jsonBody]
 * @property {Record<string, any>} [cookieParams]
 * @property {Record<string, any>} [headerParams]
 * @property {Record<string, any>} config
 * @property {object} [db] 直连模式：{ connectionString, driverType }
 * @property {string} [sqlTemplate] 直连模式：含 {INJECT} 标记的 SQL 模板
 * @property {string} [originalValue] 直连模式：注入标记的原始值
 */

/**
 * 注入点。工厂仅创建基础字段，运行期由探测阶段补充（encoding/rawValue 等）。
 * @typedef {object} InjectionPoint
 * @property {string} id
 * @property {string} location
 * @property {string} param
 * @property {string} originalValue
 * @property {boolean} confirmed
 * @property {string|null} technique
 * @property {string|null} dbms
 * @property {string|null} [formMethod]
 * @property {string|null} [actionUrl]
 * @property {Record<string, any>|null} [formValues]
 * @property {string|null} [csrfTokenName]
 * @property {boolean} [isStorePoint]
 * @property {string|null} [storeKind]
 * @property {string} [encoding] 运行期补充：编码方式（如 base64）
 * @property {string} [rawValue] 运行期补充：编码前的原始值
 * @property {string} [decodedValue] 运行期补充：解码后的值
 * @property {boolean} [precisionMarked] 运行期补充：精确标记点（跳静态探测）
 * @property {string} [_baselineTitle] 运行期补充：基线页 <title>
 */

/**
 * 单点单技术的检测结果。
 * @typedef {object} DetectionResult
 * @property {string} pointId
 * @property {string} technique
 * @property {boolean} vulnerable
 * @property {string|null} dbms
 * @property {string} evidence
 * @property {any[]} payloads
 * @property {any} trace 结构化判定轨迹（布尔/时间盲注统计用）
 * @property {number} [baseLen] 探测期使用：基线响应长度
 * @property {any} [errorDetail] error 技术专用：结构化报错上下文（signature/context/sqlFragment/body，部分可能为 null）
 * @property {string} [noSqlKind] NoSQL 技术专用：NoSQL 类型标记
 * @property {boolean} [inconclusive] time 技术专用：判定不可信（噪声过大/样本不足）
 * @property {string} [inconclusiveReason] time 技术专用：不可信原因说明
 * @property {number} [idxs] 探测期使用：回显列位
 * @property {string[]} [columns] 提取期使用：列名
 * @property {object} [extractedData] 提取期使用：数据
 */

// 构造扫描目标（校验 URL 与方法）
/**
 * @param {any} input
 * @returns {Target}
 */
export function createTarget(input) {
  const mode = (input && input.mode) || 'http';
  // 直连模式（对标 sqlmap -d）：绕过 HTTP，直接用原生驱动连库执行 SQL。
  if (mode === 'direct') {
    if (!input.db && !input.connectionString) {
      throw new AppError(ErrorCode.INVALID_TARGET, '直连模式需要提供 db 连接信息或 connectionString');
    }
    if (!input.sqlTemplate || !String(input.sqlTemplate).includes('{INJECT}')) {
      throw new AppError(ErrorCode.INVALID_TARGET, '直连模式需要提供含 {INJECT} 注入标记的 sqlTemplate');
    }
    return {
      id: nanoid(10),
      mode: 'direct',
      db: input.db || { connectionString: input.connectionString, driverType: input.driverType || 'memory' },
      sqlTemplate: input.sqlTemplate,
      originalValue: input.originalValue != null ? String(input.originalValue) : '1',
      config: { ...defaults, ...(input.config || {}) },
    };
  }
  // HTTP 模式（默认）
  if (!input || !input.url) {
    throw new AppError(ErrorCode.INVALID_TARGET, '目标 URL 不能为空');
  }
  const method = (input.method || 'GET').toUpperCase();
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    throw new AppError(ErrorCode.UNSUPPORTED_METHOD, `不支持的请求方法：${method}`);
  }
  return {
    id: nanoid(10),
    mode: 'http',
    baseUrl: input.url,
    method,
    bodyParams: input.bodyParams || {},
    // [P1 批次 2026-09-08] JSON body 注入通道：传入对象时 TargetParser 递归发现嵌套叶子
    // 注入点（param 用点路径如 user.id），injection.js 按路径替换叶子值后重序列化发送。
    // 不与 bodyParams 互斥：jsonBody 存在时优先走 JSON 语义。
    jsonBody: input.jsonBody || null,
    cookieParams: input.cookieParams || {},
    headerParams: input.headerParams || {},
    config: { ...defaults, ...(input.config || {}) },
  };
}

// 构造注入点
// id 用 location+param+actionUrl 的稳定 hash，确保 resume 跨扫描匹配同一注入点
/**
 * @param {string} location
 * @param {string} param
 * @param {string} originalValue
 * @param {Record<string, any>} [extra]
 * @returns {InjectionPoint}
 */
export function createInjectionPoint(location, param, originalValue, extra = {}) {
  const stableKey = `${location}:${param}:${extra.actionUrl || ''}`;
  return {
    id: createHash('sha256').update(stableKey).digest('hex').slice(0, 8),
    location,
    param,
    originalValue: originalValue ?? '', // P2-15: ?? 而非 || 避免 0 被当作 falsy 变空串
    confirmed: false,
    technique: null,
    dbms: null,
    // —— 以下为表单点新增字段（非表单点均为 null/{}，向后兼容）——
    formMethod: extra.formMethod != null ? extra.formMethod : null, // 表单提交方法
    actionUrl: extra.actionUrl != null ? extra.actionUrl : null, // 表单 action 解析后的绝对地址
    formValues: extra.formValues != null ? extra.formValues : null, // 表单全部字段原始值（含 CSRF token），{} 表示空表单
    csrfTokenName: extra.csrfTokenName != null ? extra.csrfTokenName : null, // 捕获到的反 CSRF 字段名
    // —— 二阶注入新增（非表单点保持 false/null，向后兼容）——
    isStorePoint: extra.isStorePoint != null ? extra.isStorePoint : false, // 是否为潜在"存储型参数点"（候选二阶存储端）
    storeKind: extra.storeKind != null ? extra.storeKind : null, // 启发式分类：'registration'|'profile'|'comment'|'unknown'|null
    ...extra, // 透传额外自定义字段（如直连模式的 sqlTemplate）
  };
}

// 构造检测结果（默认未命中）
/**
 * @param {string} pointId
 * @param {string} technique
 * @returns {DetectionResult}
 */
export function createDetectionResult(pointId, technique) {
  return {
    pointId,
    technique,
    vulnerable: false,
    dbms: null,
    evidence: '',
    payloads: [],
    trace: null, // 结构化判定轨迹（布尔/时间盲注统计判定用），其余技术为 null
  };
}

/**
 * 漏洞条目。工厂创建时 dbms 为 null，检出后由调用方回填。
 * @typedef {object} Vulnerability
 * @property {string} id
@property {string} pointId
@property {string} technique
 * @property {string|null} dbms
@property {string} riskLevel
@property {any[]} payloads
 * @property {string} description
@property {string} evidence
@property {any} trace
 * @property {any} [errorDetail] error 技术回填：结构化报错上下文
 * @property {string} [noSqlKind] NoSQL 技术回填：NoSQL 类型标记
 */

/**
 * 扫描执行上下文：由 ScanManager/Detector 组装，贯穿检测器、提取器与利用器。
 * 现有代码多标注为 any（消除 noImplicitAny 噪声）；需要精确类型的代码可直接引用本 typedef，
 * 未列出的新增字段请在本处补 @property（JSDoc 不支持对象索引签名）。
 * 现有代码多标注为 any（消除 noImplicitAny 噪声）；需要精确类型的新代码可直接引用本 typedef。
 * @typedef {object} Ctx
 * @property {any} [config] 生效配置
 * @property {string} [dbms] 已识别方言
 * @property {any} [dbmsVersion] 方言版本串
 * @property {InjectionPoint} [point] 当前注入点
 * @property {Target} [target] 当前目标
 * @property {any} [headers] 请求头
 * @property {any} [session] 会话（cookie/认证态）
 * @property {any} [httpClient] 发包客户端
 * @property {any} [oobReceiver] 带外接收器
 * @property {any} [guard] 健康守卫
 * @property {any} [extractor] 提取器
 * @property {any} [scanId] 扫描 ID
 */

// 构造漏洞
// description 与 evidence 语义分离（P1-U2）：description=可读说明，evidence=检测器原始证据串。
// 调用方（ScanManager）第 5 参传入的是检测器 evidence，故此处同时写入 description 与 evidence，
// 前端 VulnDetail 可单独展示 evidence，报告审计更完整。
/**
 * @param {string} pointId
 * @param {string} technique
 * @param {string} riskLevel
 * @param {any[]} payloads
 * @param {string} description
 * @param {any} [trace]
 * @returns {Vulnerability}
 */
export function createVulnerability(pointId, technique, riskLevel, payloads, description, trace = null) {
  return {
    id: nanoid(8),
    pointId,
    technique,
    dbms: null,
    riskLevel,
    payloads: payloads || [],
    description: description || '',
    evidence: description || '', // 检测器原始证据（与 description 同源，供前端单独展示）
    trace: trace || null, // 透传检测器的结构化判定轨迹，供前端时间线可视化
  };
}

// 空提取数据
export function emptyExtractedData() {
  return {
    databases: [],
    tables: {},
    columns: {},
    rows: {},
    // 枚举模式专有字段（--hostname / --is-dba / --schema / --privileges / --roles）
    hostname: undefined,
    isDba: undefined,
    schemas: {},
    userPrivs: undefined,
    roles: undefined,
    // 枚举模式字段（--current-db / --current-user / --users / --passwords / --count / --search）
    currentDb: undefined,
    currentUser: undefined,
    users: undefined,
    passwords: undefined,
    counts: {},
    search: /** @type {any} */ (undefined), // 枚举模式回填（--search 结果树）
  };
}

// 构造报告（扫描开始时调用）
export function createReport(scanId, target) {
  return {
    scanId,
    target,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    dbms: null,
    points: [],
    vulns: [],
    data: null,
    riskLevel: 'Low',
    summary: {},
  };
}

/**
 * 按字段计数（`summary.byRisk` / `summary.byTechnique` 的唯一实现）。
 *
 * 为什么放在 models.js 而不是各自内联：本仓出过一整类"同一件事两处实现、只补一处"的缺陷，
 * 而这两个计数此前只存在于 `ReportGenerator.build()` 那条**并行**路径里 —— 产品实际走的
 * `createReport` + `finalize` 从来没算过，于是 `manifest.summary.byRisk/byTechnique`
 * 恒为 null（实测产物：findings 里明明有 High/Medium，清单里两个键却是 null）。
 * @param {Array<object>} arr
 * @param {string} key
 * @returns {Record<string, number>}
 */
export function countBy(arr, key) {
  /** @type {Record<string, number>} */
  const m = {};
  for (const x of arr || []) {
    const k = x[key];
    m[k] = (m[k] || 0) + 1;
  }
  return m;
}
