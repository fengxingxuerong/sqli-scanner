// ============================================================================
// findingTriage.js —— [D125 2026-10-22] 渗透交付的人工裁决（confirmed / 误报 / 接受风险）
//
// 为什么需要：扫描器只能回答「引擎认为有没有」，交付前还要回答「人是否认可」。此前
// 报告里只有引擎命中，没有地方记录「这条已人工复现」「这条是误报」「客户接受风险」——
// 顾问只能在外部的表格里另记一份，复扫后两份记录必然漂移。
//
// 设计要点：
//   · **稳定指纹**：pointId / vuln.id 每次扫描都会重新生成（scanDiff.js 已踩过这个坑），
//     裁决按「方法 + 目标 origin+path + 位置 + 参数 + 技术」匹配 ⇒ 同一目标复扫后仍生效。
//   · **独立存储**：裁决是人的判断，不属于某一次扫描快照；存在 <ledger>/triage.json，
//     台账保留策略删扫描目录时不连带删除裁决。
//   · **只读合并**：报告读取时把裁决合并进副本，不改内存里的 s.report；导出/MCP/HTML
//     因此走同一条「attachTriage」路径，不会出现「界面有、导出没有」的两套口径。
//   · 裁决**不改变** verdict、exit code、风险等级或漏洞条数 —— 它是标注，不是重新检测。
// ============================================================================
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve as pathResolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError, ErrorCode } from '../core/errors.js';
import { logger } from '../core/logger.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_LEDGER_DIR = pathResolve(HERE, '../../data/ledger');
const STORE_VERSION = 1;
const NOTE_MAX = 2000;

/** @typedef {'open'|'confirmed'|'false_positive'|'accepted_risk'} TriageStatus */
/** @typedef {{status: TriageStatus, note: string, updatedAt: string|null}} TriageView */

const TRIAGE_STATUSES = /** @type {TriageStatus[]} */ (['open', 'confirmed', 'false_positive', 'accepted_risk']);

const STATUS_LABEL = {
  open: '待确认',
  confirmed: '已确认',
  false_positive: '误报',
  accepted_risk: '接受风险',
};

/**
 * 裁决状态的中文展示文本（报告/CSV/Markdown/HTML 共用，避免三种格式各写一套）。
 * @param {unknown} status
 * @returns {string}
 */
export function triageStatusText(status) {
  return STATUS_LABEL[/** @type {TriageStatus} */ (status)] || STATUS_LABEL.open;
}

/**
 * 裁决备注的纯文本形态（缺省空串；截断交给报告层已有的长度控制）。
 * @param {object|null|undefined} vuln
 * @returns {string}
 */
export function triageNoteText(vuln) {
  return String((vuln && vuln.triage && vuln.triage.note) || '');
}

/**
 * 裁决存储文件：默认 <ledger>/triage.json；SQLI_TRIAGE_FILE 可显式覆盖（测试隔离用）。
 * @returns {string}
 */
function storePath() {
  if (process.env.SQLI_TRIAGE_FILE) return pathResolve(process.env.SQLI_TRIAGE_FILE);
  const dir = process.env.SQLI_LEDGER_DIR ? pathResolve(process.env.SQLI_LEDGER_DIR) : DEFAULT_LEDGER_DIR;
  return join(dir, 'triage.json');
}

/**
 * 读裁决存储；文件缺失/损坏时返回空存储（裁决是增强数据，不能把报告读取带崩）。
 * @returns {{version: number, findings: Record<string, object>}}
 */
function readStore() {
  const empty = { version: STORE_VERSION, findings: {} };
  try {
    const raw = readFileSync(storePath(), 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || !parsed.findings || typeof parsed.findings !== 'object') return empty;
    return { version: STORE_VERSION, findings: parsed.findings };
  } catch (e) {
    if (e && /** @type {NodeJS.ErrnoException} */ (e).code !== 'ENOENT') {
      logger.warn(`[triage] 读取裁决存储失败，按空存储继续（${e?.message || e}）`);
    }
    return empty;
  }
}

/**
 * 原子写裁决存储（同目录临时文件 + rename），避免进程中断留下半份 JSON。
 * @param {{version: number, findings: Record<string, object>}} store
 * @returns {void}
 */
function writeStore(store) {
  const file = storePath();
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(store, null, 2), 'utf8');
  renameSync(tmp, file);
}

/**
 * 目标 URL 收敛到 origin + pathname：去掉 query/hash，避免复扫换了参数原值就换指纹。
 * @param {unknown} url
 * @returns {string}
 */
function normalizeUrl(url) {
  const text = String(url || '');
  try {
    const u = new URL(text);
    return `${u.origin}${u.pathname}`;
  } catch {
    return text.split('?')[0].split('#')[0];
  }
}

/**
 * 取第一个非空值；全空时返回最后一个（用作默认值）。
 * @param {unknown[]} values
 * @returns {unknown}
 */
function firstNonEmpty(values) {
  for (const v of values) if (v != null && v !== '') return v;
  return values[values.length - 1];
}

/**
 * 稳定 finding 指纹：方法 + 目标 + 位置 + 参数 + 技术。
 * 与 scanDiff.js 的 location:param:technique 同源，额外带目标与方法，避免跨站/跨动词串味。
 * @param {object} report
 * @param {object} vuln
 * @param {object} [point]
 * @returns {string}
 */
export function findingKeyOf(report, vuln, point) {
  const p = point || ((report && report.points) || []).find((x) => x.id === vuln.pointId) || {};
  const target = (report && report.target) || {};
  const url = firstNonEmpty([p.actionUrl, p.url, vuln.url, target.baseUrl, target.url, '?']);
  const method = String(firstNonEmpty([p.method, target.method, 'GET'])).toUpperCase();
  const location = firstNonEmpty([p.location, vuln.location, '?']);
  const param = firstNonEmpty([p.param, vuln.param, '?']);
  return `${method} ${normalizeUrl(url)}|${location}|${param}|${vuln.technique || '?'}`;
}

/**
 * 统计各裁决状态（报告 summary.triage）。
 * @param {Array<object>} vulns
 * @returns {{total:number, open:number, confirmed:number, falsePositive:number, acceptedRisk:number}}
 */
function countTriage(vulns) {
  const out = { total: 0, open: 0, confirmed: 0, falsePositive: 0, acceptedRisk: 0 };
  for (const v of vulns || []) {
    const status = (v && v.triage && v.triage.status) || 'open';
    out.total += 1;
    if (status === 'confirmed') out.confirmed += 1;
    else if (status === 'false_positive') out.falsePositive += 1;
    else if (status === 'accepted_risk') out.acceptedRisk += 1;
    else out.open += 1;
  }
  return out;
}

/**
 * 把存储里的裁决合并进报告副本：每条 vuln 带 findingKey + triage，summary 带计数。
 * 纯只读；返回新报告对象，不修改调用方持有的内存报告。
 * @param {object|null} report
 * @returns {object|null}
 */
export function attachTriage(report) {
  if (!report || typeof report !== 'object') return report;
  const store = readStore();
  const pointsById = new Map(((report.points) || []).map((p) => [p.id, p]));
  const vulns = (report.vulns || []).map((v) => {
    const key = findingKeyOf(report, v, pointsById.get(v.pointId));
    const rec = Object.prototype.hasOwnProperty.call(store.findings, key) ? store.findings[key] : null;
    const triage = rec
      ? { status: rec.status, note: String(rec.note || ''), updatedAt: rec.updatedAt || null }
      : { status: 'open', note: '', updatedAt: null };
    return { ...v, findingKey: key, triage };
  });
  return {
    ...report,
    vulns,
    summary: { ...(report.summary || {}), triage: countTriage(vulns) },
  };
}

/**
 * 校验裁决状态（未知状态直接 400，不做静默降级）。
 * @param {unknown} status
 * @returns {TriageStatus}
 */
function validateStatus(status) {
  if (typeof status !== 'string' || !TRIAGE_STATUSES.includes(/** @type {TriageStatus} */ (status))) {
    throw new AppError(ErrorCode.INVALID_PARAM, `无效的裁决状态：${String(status)}`);
  }
  return /** @type {TriageStatus} */ (status);
}

/**
 * 校验并归一化备注（trim + 长度上限）。
 * @param {unknown} note
 * @returns {string}
 */
function validateNote(note) {
  if (note != null && typeof note !== 'string') throw new AppError(ErrorCode.INVALID_PARAM, '备注必须是字符串');
  const text = String(note == null ? '' : note).trim();
  if (text.length > NOTE_MAX) throw new AppError(ErrorCode.INVALID_PARAM, `备注过长（上限 ${NOTE_MAX} 字符）`);
  return text;
}

/**
 * 在报告里定位 finding（id 或稳定 findingKey 二者皆可）。
 * @param {object} report
 * @param {string} findingId
 * @returns {{vuln: object, point: object|undefined, key: string}}
 */
function locateFinding(report, findingId) {
  const pointsById = new Map(((report.points) || []).map((p) => [p.id, p]));
  const vuln = (report.vulns || []).find((v) => v.id === findingId || v.findingKey === findingId);
  if (!vuln) throw new AppError(ErrorCode.SCAN_NOT_FOUND, '未找到该漏洞（findingId 不存在或已过期）');
  const point = pointsById.get(vuln.pointId);
  return { vuln, point, key: vuln.findingKey || findingKeyOf(report, vuln, point) };
}

/**
 * 构造落盘记录（只存最后状态与定位信息，便于排查）。
 * @param {object} p
 * @param {TriageStatus} p.status
 * @param {string} p.note
 * @param {string} p.updatedAt
 * @param {string} p.scanId
 * @param {object} p.report
 * @param {object|undefined} p.point
 * @param {object} p.vuln
 * @returns {object}
 */
function triageRecord({ status, note, updatedAt, scanId, report, point, vuln }) {
  const target = (report && report.target) || {};
  return {
    status,
    note,
    updatedAt,
    lastScanId: String(scanId || ''),
    target: firstNonEmpty([target.url, target.baseUrl, null]),
    method: String(firstNonEmpty([point && point.method, target.method, 'GET'])).toUpperCase(),
    location: firstNonEmpty([point && point.location, vuln.location, null]),
    param: firstNonEmpty([point && point.param, vuln.param, null]),
    technique: vuln.technique || null,
  };
}

/**
 * 写入一条人工裁决（按稳定指纹 upsert；status=open 且备注为空 ⇒ 删除该条）。
 * @param {object} p
 * @param {object} p.report 报告（可用 attachTriage 后的形态）
 * @param {string} p.scanId
 * @param {string} p.findingId vuln.id 或 findingKey
 * @param {unknown} p.status
 * @param {unknown} [p.note]
 * @returns {{findingKey: string, triage: TriageView}}
 */
export function setFindingTriage({ report, scanId, findingId, status, note }) {
  if (!report || typeof report !== 'object') throw new AppError(ErrorCode.SCAN_NOT_FOUND, '扫描不存在或已结束');
  const triageStatus = validateStatus(status);
  const text = validateNote(note);
  const { vuln, point, key } = locateFinding(report, findingId);
  const store = readStore();
  const updatedAt = new Date().toISOString();
  if (triageStatus === 'open' && !text) {
    delete store.findings[key];
  } else {
    store.findings[key] = triageRecord({ status: triageStatus, note: text, updatedAt, scanId, report, point, vuln });
  }
  writeStore(store);
  return { findingKey: key, triage: { status: triageStatus, note: text, updatedAt } };
}
