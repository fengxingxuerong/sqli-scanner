import { createHash } from 'node:crypto';
import { nanoid } from 'nanoid'; // 仅 scanId / targetId 用（随机，不需稳定）
import { AppError, ErrorCode } from '../core/errors.js';
import { defaults } from '../config/defaults.js';

// 工厂与校验函数：构造 Target / InjectionPoint / DetectionResult /
// Vulnerability / ReportModel / ExtractedData，保证字段完整。

// 构造扫描目标（校验 URL 与方法）
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
    cookieParams: input.cookieParams || {},
    headerParams: input.headerParams || {},
    config: { ...defaults, ...(input.config || {}) },
  };
}

// 构造注入点
// id 用 location+param+actionUrl 的稳定 hash，确保 resume 跨扫描匹配同一注入点
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

// 构造漏洞
// description 与 evidence 语义分离（P1-U2）：description=可读说明，evidence=检测器原始证据串。
// 调用方（ScanManager）第 5 参传入的是检测器 evidence，故此处同时写入 description 与 evidence，
// 前端 VulnDetail 可单独展示 evidence，报告审计更完整。
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
    search: undefined,
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
