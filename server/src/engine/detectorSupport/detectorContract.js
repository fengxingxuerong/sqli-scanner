// ============================================================================
// detectorSupport/detectorContract.js —— [D257] 检测器统一「插头」
// ----------------------------------------------------------------------------
// 为什么要有它：本仓有 13 个检测器（9 个编排总图条目 + 3 个键名/元素名验证器 +
// LDAP/XPath 子类），它们此前只共享「detect(ctx) 返回一个对象」这一个口头约定：
//   · 返回对象缺字段（vulnerable 为 undefined / payloads 不是数组）没人拦；
//   · 「未结论」与「测过且无洞」在结果形态上无法区分 —— InlineQueryDetector 两条
//     网络失败路径把「未结论」写进 evidence，却没置 inconclusive，该点会被记成
//     「已测阴性」（D257 实测抓到的真实缺陷，见 docs/检测器统一契约-D257.md）；
//   · 每个检测器「靠什么判、能提取什么」只活在注释里，新加检测器没有可核的声明。
//
// 本模块把三件事收敛成**可执行**的契约（对标 nuclei 的 Executer + Operators）：
//   ① 判定/提取算子声明：match / extract 只能取枚举里的值，未知值在**构造期**就抛；
//   ② 结果不变量：vulnerable 与 inconclusive 互斥、命中必须带证据与载荷、
//      未结论必须带原因、pointId/technique 必须与检测器一致；
//   ③ 统一执行器：executeDetector() 是唯一入口，返回归一化的 outcome，
//      调度层不再各自解释 result 字段。
//
// 诚实边界：算子声明是**能力声明**，不是判定算法的实现。它保证「每个检测器都说清了
// 自己靠哪类证据下结论」，不保证该类证据一定足够强（检出率仍以靶场为准）。
// ============================================================================
import { AppError, ErrorCode } from '../../core/errors.js';

/**
 * 判定算子类别。值即契约：新增类别必须同步这里与文档，不得在检测器里写自由文本。
 * @type {Readonly<Record<string, string>>}
 */
export const MATCH_KINDS = Object.freeze({
  signature: '响应中出现可归因于载荷的数据库/引擎签名（报错回显）',
  echo: '响应中出现注入标记（回显列 / 子查询求值结果）',
  'bool-diff': '真/假探针对的响应可复现地分化',
  timing: '注入响应耗时显著且稳定地高于基线',
  oob: '带外接收端收到目标回连（无回显通道）',
  stored: '存储型探针经触发页读回注入证据（二阶）',
  marker: '非 SQL 引擎语法标记/求值结果回显（NoSQL/GraphQL/SSTI/LDAP/XPath）',
  unspecified: '未声明（仅基类占位；生产检测器由 detectorContract.guard 拦住）',
});

/**
 * 提取算子类别：检测器命中后能交给下游（报告/提取阶段）的结构化产物。
 * @type {Readonly<Record<string, string>>}
 */
export const EXTRACT_KINDS = Object.freeze({
  dbms: '从证据推断/确认数据库类型',
  'echo-columns': '记录可回显列与列数（供 UNION 提取复用）',
  'error-context': '留存报错原文与 SQL 片段（--parse-errors 消费）',
  'nosql-kind': '标注非 SQL 注入类别（nosql/graphql/ssti/ldap/xpath）',
});

const UNSPECIFIED = 'unspecified';

/**
 * 校验一个类别是否在枚举内。
 * @param {Readonly<Record<string, string>>} table 枚举表
 * @param {string} kind 待校验类别
 * @param {string} field 字段名（match / extract，用于报错定位）
 * @param {string} technique 技术位（用于报错定位）
 * @returns {void}
 */
function assertKind(table, kind, field, technique) {
  if (typeof kind !== 'string' || !Object.prototype.hasOwnProperty.call(table, kind)) {
    throw new AppError(
      ErrorCode.DETECTOR_CONTRACT_INVALID,
      `检测器 ${technique} 的 ${field} 声明了未知类别 ${JSON.stringify(kind)}；` +
        `合法值：${Object.keys(table).join(' / ')}`
    );
  }
}

/**
 * 归一化并冻结一个检测器契约。
 *
 * @param {object} spec 契约声明
 * @param {string} spec.technique 技术位（必须与实例 technique 一致）
 * @param {string|string[]} [spec.match] 判定算子类别（单个或多个）
 * @param {string[]} [spec.extract] 提取算子类别
 * @param {string} [spec.note] 人类可读补充（进文档/报错，不参与判定）
 * @returns {{technique: string, match: readonly string[], extract: readonly string[], note: string}} 冻结后的契约
 */
export function defineDetectorContract(spec) {
  const technique = String((spec && spec.technique) || '').trim();
  if (!technique) {
    throw new AppError(ErrorCode.DETECTOR_CONTRACT_INVALID, '检测器契约缺少 technique');
  }
  const matchIn = spec.match == null ? [] : Array.isArray(spec.match) ? spec.match : [spec.match];
  const extractIn = spec.extract == null ? [] : Array.isArray(spec.extract) ? spec.extract : [spec.extract];
  if (!matchIn.length) {
    throw new AppError(ErrorCode.DETECTOR_CONTRACT_INVALID, `检测器 ${technique} 未声明判定算子（match）`);
  }
  for (const kind of matchIn) assertKind(MATCH_KINDS, kind, 'match', technique);
  for (const kind of extractIn) assertKind(EXTRACT_KINDS, kind, 'extract', technique);
  return Object.freeze({
    technique,
    match: Object.freeze([...new Set(matchIn)]),
    extract: Object.freeze([...new Set(extractIn)]),
    note: String((spec && spec.note) || ''),
  });
}

/**
 * 结果不变量校验：把「检测器返回了什么」从口头约定变成可执行判据。
 *
 * 规则（全部为**结构**判据，不评价判定算法强弱）：
 *   ① result 必须是对象，pointId / technique 必须与执行上下文一致（防复制粘贴串台）；
 *   ② vulnerable 必须是布尔、evidence 必须是字符串、payloads 必须是数组；
 *   ③ 命中（vulnerable=true）必须带非空 evidence 与至少一条 payload —— 否则报告里
 *      会出现「有洞但无证据」的条目；
 *   ④ 未结论（inconclusive=true）必须与命中互斥，且带非空原因 —— 否则调度层无法
 *      把它记入「未验证面」，会被误读成「测过且无洞」。
 *
 * @param {any} result 检测器返回值
 * @param {{technique: string, pointId: string}} meta 期望的技术位与注入点
 * @returns {any} 原对象（便于链式返回）
 */
export function assertDetectionResult(result, meta) {
  const where = `${meta && meta.technique ? meta.technique : '?'}@${meta && meta.pointId ? meta.pointId : '?'}`;
  if (!result || typeof result !== 'object') {
    throw new AppError(ErrorCode.DETECTOR_CONTRACT_INVALID, `检测器 ${where} 未返回结果对象`);
  }
  if (result.pointId !== meta.pointId) {
    throw new AppError(
      ErrorCode.DETECTOR_CONTRACT_INVALID,
      `检测器 ${where} 返回的 pointId=${JSON.stringify(result.pointId)} 与当前注入点不一致`
    );
  }
  if (result.technique !== meta.technique) {
    throw new AppError(
      ErrorCode.DETECTOR_CONTRACT_INVALID,
      `检测器 ${where} 返回的 technique=${JSON.stringify(result.technique)} 与实例技术位不一致`
    );
  }
  if (typeof result.vulnerable !== 'boolean') {
    throw new AppError(ErrorCode.DETECTOR_CONTRACT_INVALID, `检测器 ${where} 的 vulnerable 不是布尔值`);
  }
  if (typeof result.evidence !== 'string') {
    throw new AppError(ErrorCode.DETECTOR_CONTRACT_INVALID, `检测器 ${where} 的 evidence 不是字符串`);
  }
  if (!Array.isArray(result.payloads)) {
    throw new AppError(ErrorCode.DETECTOR_CONTRACT_INVALID, `检测器 ${where} 的 payloads 不是数组`);
  }
  if (result.vulnerable) {
    if (!result.evidence.trim()) {
      throw new AppError(ErrorCode.DETECTOR_CONTRACT_INVALID, `检测器 ${where} 判命中但 evidence 为空`);
    }
    if (result.payloads.length === 0) {
      throw new AppError(ErrorCode.DETECTOR_CONTRACT_INVALID, `检测器 ${where} 判命中但 payloads 为空`);
    }
  }
  if (result.inconclusive === true) {
    if (result.vulnerable) {
      throw new AppError(ErrorCode.DETECTOR_CONTRACT_INVALID, `检测器 ${where} 同时标记命中与未结论（互斥）`);
    }
    if (typeof result.inconclusiveReason !== 'string' || !result.inconclusiveReason.trim()) {
      throw new AppError(ErrorCode.DETECTOR_CONTRACT_INVALID, `检测器 ${where} 标记未结论但缺少 inconclusiveReason`);
    }
  }
  return result;
}

/**
 * 把「检测器返回值」归一化成调度层消费的 outcome（单源，避免两处字面量漂移）。
 * @param {string} technique 技术位
 * @param {any} result 检测器返回值（可能来自未继承 Detector 的鸭子类型对象）
 * @returns {{technique: string, result: any, vulnerable: boolean, unverified: boolean, reason: string}} 归一化结论
 */
function buildOutcome(technique, result) {
  const unverified = !!result && result.inconclusive === true;
  return {
    technique,
    result,
    vulnerable: !!result && result.vulnerable === true,
    unverified,
    reason: unverified ? String(result.inconclusiveReason || '') : '',
  };
}

/**
 * 统一执行器（对标 nuclei Executer.Execute）：调用检测器 → 校验结果 → 归一化 outcome。
 *
 * 与直接调 detect() 的差别：所有调度点拿到的都是同一形状，且**不会**出现
 * 「result 为 undefined 却被当成未命中」这种静默失败 —— 契约违规会抛出
 * DETECTOR_CONTRACT_INVALID。它是**编程错误**（不是目标行为），正常扫描不应出现；
 * 调度层按「该检测器本次未命中」记录告警，并由守卫测试保证它不会溜进发布。
 *
 * @param {{technique: string, detect: (ctx: any) => Promise<any>}} detector 检测器实例
 * @param {any} ctx 检测上下文（需含 point.id）
 * @returns {Promise<{technique: string, result: any, vulnerable: boolean, unverified: boolean, reason: string}>} 归一化结论
 */
export async function executeDetector(detector, ctx) {
  const pointId = ctx && ctx.point ? ctx.point.id : undefined;
  const result = await detector.detect(ctx);
  assertDetectionResult(result, { technique: detector.technique, pointId });
  return buildOutcome(detector.technique, result);
}

/**
 * 调度层唯一入口：生产检测器（继承 Detector、带 run）走 `run()`，由契约校验兜底；
 * 鸭子类型对象（测试替身，只有 detect）退回 `detect()`，**不做**契约校验。
 *
 * 为什么保留这条退路：本仓大量调度测试用 `{ technique, detect }` 桩驱动真实
 * detectPhase（见 detect.orchestration.test.js）。把测试桩也绑进契约，等于要求
 * 每个桩复制一份完整 DetectionResult，测试会从「验证调度」退化成「验证桩」。
 * 生产侧由守卫钉住「编排总图里的每个类都继承 Detector」，不靠这条退路放水。
 *
 * @param {{technique: string, detect: (ctx: any) => Promise<any>, run?: (ctx: any) => Promise<any>}} detector 检测器实例或测试替身
 * @param {any} ctx 检测上下文
 * @returns {Promise<{technique: string, result: any, vulnerable: boolean, unverified: boolean, reason: string}>} 归一化结论
 */
export async function runDetector(detector, ctx) {
  if (typeof detector.run === 'function') return detector.run(ctx);
  return buildOutcome(detector.technique, await detector.detect(ctx));
}

/**
 * 契约的机器可读摘要（测试/文档共用，避免两处各写一份枚举）。
 * @param {{technique?: string, contract?: {technique: string, match: readonly string[], extract: readonly string[], note: string}}} detector 检测器实例
 * @returns {{technique: string, match: string[], extract: string[], note: string, declared: boolean}} 摘要
 */
export function contractSummary(detector) {
  const c = detector && detector.contract;
  if (!c) return { technique: String(detector && detector.technique), match: [], extract: [], note: '', declared: false };
  return {
    technique: c.technique,
    match: [...c.match],
    extract: [...c.extract],
    note: c.note,
    declared: !(c.match.length === 1 && c.match[0] === UNSPECIFIED),
  };
}

export default { MATCH_KINDS, EXTRACT_KINDS, defineDetectorContract, assertDetectionResult, executeDetector, runDetector };
