// ============================================================================
// sideEffectLedger.js —— [D90 2026-10-18] 写副作用登记与自动清理
//
// ── 为什么必须补（TODO 2026-10-10 盘点的 P2-5）──────────────────────────────
// 「写副作用无自动清理/回滚（只有 docs/pentest-handover/05 的人工条款 R5/R6）」。
// 人工条款原文要求「记录全部副作用并清理」，但**没有任何机制保证它被执行** ——
// 这正是本仓反复治理的那类形状：**承诺写在文档里，代码里没有对应物**。
//
// 真实授权测试里的后果很具体：
//   · fileWrite 往目标落一个 webshell/标记文件，测试结束**留在客户服务器上**
//   · osShell 起过进程、udf 装过 DLL、stacked 写过表 —— 全无登记，事后翻不出来
//   客户拿到的报告只有「我们写了什么」的正文描述，**没有可复核的清单，也没有收尾动作**。
//
// ── 本模块做什么 ────────────────────────────────────────────────────────────
// ① **写前登记**（record）：每次写操作前把「写了什么/写到哪里/如何撤销」记成一条结构化
//    记录，落 `ledger/<scanId>/side-effects.json`（与扫描台账同目录，便于一并归档）。
// ② **自动清理**（buildCleanupPlan / cleanup）：按记录生成撤销动作并执行，
//    逐条回报成功/失败/skipped，**失败不得静默**（客户要知道哪个残留没清掉）。
//
// ── 与既有护栏的关系（不得绕过）─────────────────────────────────────────────
// 本模块**不新增任何写能力**，只登记与撤销既有能力已产生的副作用：
//   · 写操作本身仍受 productionMode / EXPLOIT_ENABLED / allowWrites / confirmDestructive 门控
//   · cleanup 是**对目标发起的额外请求**，因此同样需要 EXPLOIT_ENABLED 门（见 route 侧调用）
//   · 默认**不自动执行**清理：cleanup 需显式调用（CLI `--cleanup-side-effects <scanId>` /
//     REST 端点），避免「扫描器自作主张再动一次目标」——那是比不清理更糟的行为。
//
// ── 诚实边界 ────────────────────────────────────────────────────────────────
// · 只登记**本模块被显式调用**的那些写操作；不调用即无记录（不是「全自动兜底」）。
// · 撤销能力按操作类型分档：fileWrite 可删文件、stacked 可逆 DML 可反向、os-shell 起的
//   进程**无法保证收回**（同类工具一致）——不可撤销者登记为 `irreversible` 并在报告显式提示。
// · 不做「回滚整个业务事务」（那需要目标侧配合）；只做**本工具自己留下的痕迹**的清理。
// ============================================================================

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { logger } from '../core/logger.js';
import { AppError, ErrorCode } from '../core/errors.js';
import { ledgerRoot } from './scanLedger.js';

/** 副作用类型（决定撤销语义） */
export const SIDE_EFFECT_KINDS = Object.freeze({
  FILE_WRITE: 'file_write', // 目标文件系统落盘 → 可删
  UDF_INSTALL: 'udf_install', // 自定义函数/驱动 → 可尝试卸载
  STACKED_DML: 'stacked_dml', // 数据被改（INSERT/UPDATE/DELETE）→ 可反向（若记了原值）
  OS_SHELL: 'os_shell', // 命令执行（可能有进程/临时文件）→ 不可保证收回
  REG_WRITE: 'reg_write', // 注册表写入 → 可尝试删键
});

/**
 * [D132 2026-10-23] 校验 scanId 只作**单层目录名**——`join(ledgerRoot(), scanId, ...)` 之前
 * 完全没校验，而 scanId 来自 REST 查询串/请求体（`/api/exploit/side-effects?scanId=...`
 * 与 cleanup 的 body），攻击者（或本机任意进程，回环无鉴权时）可用 `../../x` 越界读写
 * `side-effects.json` 并在任意可写位置递归建目录。
 *
 * 与 `scanLedger.js` 的 safeScanId 同一口径（同一类缺陷，两处各写一份是它复发的根源，
 * 因此判据保持逐字对齐；之所以不抽公共函数：两个模块的目录语义独立演进，
 * 抽出来反而要把「ledger 根相同」这个巧合固化）。
 * @param {unknown} scanId 调用方给的扫描 id
 * @returns {string} 安全的单层目录名
 * @throws {AppError} scanId 含路径分隔符 / `..` / 绝对路径 / NUL 时
 */
function safeScanId(scanId) {
  const s = String(scanId ?? '');
  if (!s || s === '.' || s === '..' || /[\\/]/.test(s) || isAbsolute(s) || s.includes('\0')) {
    throw new AppError(
      ErrorCode.SCAN_ID_INVALID,
      `sideEffectLedger: 非法 scanId（不得包含路径分隔符或 ..）：${s.slice(0, 80)}`
    );
  }
  return s;
}

/**
 * 副作用登记表（按 scanId 分文件）。
 * 结构：{ scanId, createdAt, effects: [ {id, kind, target, detail, reversible, undo, recordedAt, cleanedAt, cleanResult} ] }
 * @param {unknown} scanId 扫描 id（经 safeScanId 校验）
 * @returns {string} 登记表绝对路径
 */
function sideEffectsPath(scanId) {
  return join(ledgerRoot(), safeScanId(scanId), 'side-effects.json');
}

/**
 * 读取登记表（不存在返回空壳，不抛）。
 * @dynamic CLI(bin/cli.js) 与 REST 路由(exploitRoutes) 均经动态 import 调用，静态扫描不可见
 */
export function readSideEffects(scanId) {
  const p = sideEffectsPath(scanId);
  if (!existsSync(p)) return { scanId, createdAt: null, effects: [] };
  try {
    const j = JSON.parse(readFileSync(p, 'utf8'));
    if (!j || !Array.isArray(j.effects)) return { scanId, createdAt: null, effects: [] };
    return j;
  } catch (e) {
    // 损坏不让调用方崩：返回空壳并在日志显式说明（不静默）
    logger.warn(`[side-effects] 登记表解析失败（${p}）：${e.message} —— 按空处理，但请人工核查该文件`);
    return { scanId, createdAt: null, effects: [], corrupt: true };
  }
}

/**
 * 登记一条写副作用。**在任何写操作之前调用**（写成功与否都留痕：失败也说明「试过」）。
 *
 * @param {string} scanId 扫描/会话 id
 * @param {object} effect
 * @param {string} effect.kind SIDE_EFFECT_KINDS 之一
 * @param {string} effect.target 目标（URL / 库表 / 主机路径）
 * @param {string} [effect.detail] 人类可读说明（写了什么内容/值）
 * @param {string} [effect.undo] 撤销配方（如 `rm -f -- <path>`）；缺省时按类型给默认形态
 * @param {string} [error] 写操作失败时的错误信息（登记「尝试过但失败」）
 * @returns {{id:string, path:string, recorded?:boolean}}
 */
export function recordSideEffect(scanId, effect, error = '') {
  const p = sideEffectsPath(scanId);
  const store = readSideEffects(scanId);
  if (!store.createdAt) store.createdAt = new Date().toISOString();

  const kind = String(effect?.kind || 'unknown');
  const id = `${kind}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  const reversible = inferReversible(kind);
  const entry = {
    id,
    kind,
    target: String(effect?.target || '').slice(0, 500),
    detail: String(effect?.detail || '').slice(0, 1000),
    // 撤销配方（由调用方给出；无法撤销时为 null 并靠 kind 的默认可逆性判断）
    undo: effect?.undo ? String(effect.undo).slice(0, 2000) : null,
    reversible,
    recordedAt: new Date().toISOString(),
    status: error ? 'failed' : 'applied', // applied=已施加, failed=尝试失败（也可能已部分生效）
    error: error ? String(error).slice(0, 500) : '',
    cleanedAt: null,
    cleanResult: null,
  };
  store.effects.push(entry);

  try {
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify(store, null, 2) + '\n', 'utf8');
  } catch (e) {
    // 登记失败必须显式告警：不能出现「写了但没记」的静默状态（那等于本模块不存在）
    logger.error(`[side-effects] 登记失败（${p}）：${e.message} —— 该次写操作无痕迹，请人工记录`);
    return { id, path: p, recorded: false };
  }
  logger.info(`[side-effects] 已登记 ${kind} → ${entry.target}（可逆=${reversible}${error ? '，失败' : ''}）`);
  return { id, path: p, recorded: true };
}

/**
 * 类型的默认可逆性（无显式 undo 配方时的判定）。
 * 注意返回三态：true（可逆）/ 'undo-only'（仅有反向语句时可逆）/ false（不可逆）。
 * @param {string} kind
 * @returns {boolean|string}
 */
function inferReversible(kind) {
  if (kind === SIDE_EFFECT_KINDS.FILE_WRITE) return true; // 删文件即可
  if (kind === SIDE_EFFECT_KINDS.UDF_INSTALL) return true; // 可尝试 DROP FUNCTION
  if (kind === SIDE_EFFECT_KINDS.REG_WRITE) return true; // 可尝试删键
  if (kind === SIDE_EFFECT_KINDS.STACKED_DML) return 'undo-only'; // 仅有反向语句时可逆
  // os_shell：起的进程/创建的临时文件无法保证收回 —— 如实标不可逆
  return false;
}

/**
 * 生成清理计划（不执行）。
 * @dynamic CLI 与 REST 路由经动态 import 调用，静态扫描不可见
 * @param {string} scanId
 * @returns {{scanId, items:Array, irreversible:Array, summary:object}}
 */
export function buildCleanupPlan(scanId) {
  const store = readSideEffects(scanId);
  const items = [];
  const irreversible = [];
  for (const e of store.effects) {
    if (e.cleanedAt) continue; // 已清理，不再入计划（幂等）
    const canUndo = e.reversible === true || (e.reversible === 'undo-only' && !!e.undo);
    if (!canUndo) {
      irreversible.push(e);
      continue;
    }
    items.push({
      id: e.id,
      kind: e.kind,
      target: e.target,
      // 撤销语句：优先用调用方给的具体配方（如 `rm -f <path>` / `DROP FUNCTION x`）
      undo: e.undo || defaultUndo(e),
    });
  }
  return {
    scanId,
    items,
    irreversible,
    summary: {
      应清理: items.length,
      不可逆: irreversible.length,
      总计: store.effects.length,
      已清理: store.effects.filter((e) => e.cleanedAt).length,
    },
  };
}

/** 无显式配方时的默认撤销语句（按类型给最保守形态） */
function defaultUndo(e) {
  if (e.kind === SIDE_EFFECT_KINDS.FILE_WRITE) return `rm -f -- ${e.target}`;
  if (e.kind === SIDE_EFFECT_KINDS.UDF_INSTALL) return `DROP FUNCTION ${e.target}`;
  if (e.kind === SIDE_EFFECT_KINDS.REG_WRITE) return `reg delete "${e.target}" /f`;
  return null;
}

/**
 * 执行清理计划。**调用方负责先过 EXPLOIT_ENABLED 门**（本函数只做登记与调度）。
 *
 * @param {string} scanId
 * @param {(cmd:string) => Promise<{ok:boolean, output?:string, error?:string}>} executor
 *        实际执行器（由调用方注入：CLI 走 os-shell 通道、REST 走 exploit 通道）。
 *        注入而非内置，是为了让「清理」与「利用」共用同一套门控与 HTTP 客户端，
 *        避免出现「绕过门控的第二条写链路」。
 * @returns {Promise<{scanId, results:Array, summary:object}>}
 */
/**
 * 执行单条撤销（[D90] 从 cleanupSideEffects 拆出：那里圈复杂度 17 超软上限 15）。
 * 职责单一 —— 把「执行一条撤销、把结果正负两面都记下来」收在一处。
 * @param {object} item 计划项
 * @param {object|undefined} rec 对应的登记记录（用于回写清理状态）
 * @param {(cmd:string) => Promise<{ok:boolean,output?:string,error?:string}>} executor
 * @returns {Promise<object>} result 行
 */
async function runOneCleanup(item, rec, executor) {
  if (!item.undo) {
    return { id: item.id, kind: item.kind, target: item.target, status: 'skipped', reason: '无可用的撤销配方' };
  }
  try {
    const r = await executor(item.undo);
    const ok = !!(r && r.ok);
    if (rec) {
      rec.cleanedAt = ok ? new Date().toISOString() : null;
      rec.cleanResult = ok ? 'cleaned' : `failed: ${(r && r.error) || 'unknown'}`;
    }
    return {
      id: item.id, kind: item.kind, target: item.target,
      undo: item.undo, status: ok ? 'cleaned' : 'failed',
      output: r && r.output ? String(r.output).slice(0, 300) : '',
      error: ok ? '' : String((r && r.error) || '执行器返回失败'),
    };
  } catch (e) {
    // 抛异常同样计入失败：不能中断整个清理流程（一条炸掉不该让其余残留无人处理）
    if (rec) rec.cleanResult = `failed: ${e.message}`;
    return { id: item.id, kind: item.kind, target: item.target, undo: item.undo, status: 'failed', error: e.message };
  }
}

/** 不可逆项单独成行（不清、但必须让报告看得见，不能混进「已清理」计数） */
function irreversibleRows(irreversible) {
  return irreversible.map((e) => ({
    id: e.id, kind: e.kind, target: e.target,
    status: 'irreversible',
    reason: '该类型副作用无法自动收回（如 os-shell 起的进程），需人工确认并记录在测试报告',
  }));
}

/** 汇总计数（从结果行派生，不另行维护状态） */
function summarizeResults(results) {
  return {
    已清理: results.filter((r) => r.status === 'cleaned').length,
    失败: results.filter((r) => r.status === 'failed').length,
    跳过: results.filter((r) => r.status === 'skipped').length,
    不可逆: results.filter((r) => r.status === 'irreversible').length,
  };
}

/**
 * 执行清理计划。**调用方负责先过 EXPLOIT_ENABLED 门**（本函数只做登记与调度）。
 *
 * @param {string} scanId
 * @param {(cmd:string) => Promise<{ok:boolean, output?:string, error?:string}>} executor
 *        实际执行器（由调用方注入：CLI 走 os-shell 通道、REST 走 exploit 通道）。
 *        注入而非内置，是为了让「清理」与「利用」共用同一套门控与 HTTP 客户端，
 *        避免出现「绕过门控的第二条写链路」。
 * @dynamic REST 路由经动态 import 调用（走与利用同一套门控），静态扫描不可见
 * @returns {Promise<{scanId, results:Array, summary:object}>}
 */
export async function cleanupSideEffects(scanId, executor) {
  const plan = buildCleanupPlan(scanId);
  const store = readSideEffects(scanId);
  const results = [];

  for (const item of plan.items) {
    const rec = store.effects.find((e) => e.id === item.id);
    results.push(await runOneCleanup(item, rec, executor));
  }
  results.push(...irreversibleRows(plan.irreversible));

  try {
    mkdirSync(dirname(sideEffectsPath(scanId)), { recursive: true });
    writeFileSync(sideEffectsPath(scanId), JSON.stringify(store, null, 2) + '\n', 'utf8');
  } catch (e) {
    logger.warn(`[side-effects] 清理结果回写失败：${e.message}（清理已执行，但痕迹未落盘）`);
  }

  const summary = summarizeResults(results);
  logger.info(`[side-effects] 清理完成：${JSON.stringify(summary)}`);
  return { scanId, results, summary };
}

/**
 * 给报告用的摘要（供 ReportGenerator 消费：让客户看到「写了什么、清没清」）。
 * @dynamic REST 路由经动态 import 调用，静态扫描不可见
 * @param {string} scanId
 * @returns {object|null} null = 本次扫描无写副作用
 */
export function sideEffectSummaryForReport(scanId) {
  const store = readSideEffects(scanId);
  if (!store.effects.length) return null;
  const plan = buildCleanupPlan(scanId);
  return {
    总数: store.effects.length,
    已施加: store.effects.filter((e) => e.status === 'applied').length,
    尝试失败: store.effects.filter((e) => e.status === 'failed').length,
    已清理: store.effects.filter((e) => e.cleanedAt).length,
    待清理: plan.items.length,
    不可逆: plan.irreversible.length,
    明细: store.effects.map((e) => ({
      kind: e.kind, target: e.target, status: e.status, cleaned: !!e.cleanedAt,
    })),
  };
}

export default {
  SIDE_EFFECT_KINDS,
  recordSideEffect,
  readSideEffects,
  buildCleanupPlan,
  cleanupSideEffects,
  sideEffectSummaryForReport,
};
