import { nanoid } from 'nanoid';
import { AppError, ErrorCode } from '../core/errors.js';
import { defaults } from '../config/defaults.js';

// 工厂与校验函数：构造 Target / InjectionPoint / DetectionResult /
// Vulnerability / ReportModel / ExtractedData，保证字段完整。

// 构造扫描目标（校验 URL 与方法）
export function createTarget(input) {
  if (!input || !input.url) {
    throw new AppError(ErrorCode.INVALID_TARGET, '目标 URL 不能为空');
  }
  const method = (input.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'POST') {
    throw new AppError(ErrorCode.UNSUPPORTED_METHOD, `不支持的请求方法：${method}`);
  }
  return {
    id: nanoid(10),
    baseUrl: input.url,
    method,
    bodyParams: input.bodyParams || {},
    cookieParams: input.cookieParams || {},
    headerParams: input.headerParams || {},
    config: { ...defaults, ...(input.config || {}) },
  };
}

// 构造注入点
// extra 用于表单点扩展字段（非表单点保持 null/{}，向后兼容）
export function createInjectionPoint(location, param, originalValue, extra = {}) {
  return {
    id: nanoid(8),
    location,
    param,
    originalValue: originalValue || '',
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
export function createVulnerability(pointId, technique, riskLevel, payloads, description, trace = null) {
  return {
    id: nanoid(8),
    pointId,
    technique,
    dbms: null,
    riskLevel,
    payloads: payloads || [],
    description: description || '',
    trace: trace || null, // 透传检测器的结构化判定轨迹，供前端时间线可视化
  };
}

// 空提取数据
export function emptyExtractedData() {
  return { databases: [], tables: {}, columns: {}, rows: {} };
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
