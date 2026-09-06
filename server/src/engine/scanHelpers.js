// =====================================================================
// scanHelpers.js — ScanManager 使用的纯函数工具集（从 ScanManager.js 拆分）
// 包含：urlHash / SYS_DBS / publicTarget / publicReport
//       mergeExtracted / mergeExtractedForResume / hasData / mapPool
// 这些函数不依赖 ScanManager 实例状态，可独立测试和复用。
// =====================================================================
import crypto from 'node:crypto';
import { logger } from '../core/logger.js';

// 目标 URL -> 8 字符 hex 哈希，用于派生默认会话文件名。同一 URL 始终生成相同哈希，
// 不同 URL 哈希碰撞概率极低（16^8 ~ 43 亿分一），避免 sessionDefault 并发扫描互踩文件。
export function urlHash(url) {
  return crypto.createHash('md5').update(String(url)).digest('hex').slice(0, 8);
}

// 系统数据库名集合（对标 sqlmap --exclude-sysdbs 的默认排除；小写比对）。
// 全面拖库（_extract 的 dumpAllDatabases）与枚举模式（_extractByScope）共用；
// 由 config.excludeSysdbs（默认 true）门控，设为 false 时不过滤。
export const SYS_DBS = new Set([
  'information_schema', 'mysql', 'performance_schema', 'sys', // MySQL/MariaDB/TiDB
  'pg_catalog', 'pg_toast', 'template0', 'template1', // PostgreSQL（template 库存档库；postgres 是默认用户库，不应排除）
  'master', 'tempdb', 'model', 'msdb', 'resource', 'distribution', // SQL Server
  'sys', 'system', 'auxsys', // Oracle all_users 中的系统 schema（SYS/SYSTEM）
  'sysibm', 'syscat', 'sysstat', 'systools', // DB2 系统 schema
  'system', // ClickHouse
]);

// [MERGED: security] 事件/报告对外载荷脱敏：剥离 target 中的认证凭据与代理配置
// （SSE 事件流、报告接口均会携带 target；凭据只在引擎内部扫描时使用，不外泄）。
export function publicTarget(target) {
  if (!target || typeof target !== 'object') return target;
  const out = { ...target };
  if (out.config && typeof out.config === 'object') {
    const { auth, proxy, ...rest } = out.config;
    out.config = { ...rest, auth: null, proxy: null };
  }
  delete out.cookieParams;
  delete out.headerParams;
  if (out.db && typeof out.db === 'object' && out.db.connectionString) {
    out.db = { ...out.db, connectionString: '***' };
  }
  return out;
}

export function publicReport(report) {
  if (!report || typeof report !== 'object') return report;
  return { ...report, target: publicTarget(report.target) };
}

// 合并提取数据：将 src 的字段合并到 target（原 ScanManager._mergeExtracted）
// 防御：提取返回结构残缺（如桩/部分失败）时不抛错，仅合并已有字段
export function mergeExtracted(target, src) {
  if (!src) return;
  for (const db of (src.databases || [])) {
    if (!target.databases.includes(db)) target.databases.push(db);
  }
  for (const [k, v] of Object.entries(src.tables || {})) target.tables[k] = v;
  for (const [k, v] of Object.entries(src.columns || {})) target.columns[k] = v;
  for (const [k, v] of Object.entries(src.rows || {})) target.rows[k] = v;
  // 枚举模式专有字段（--current-db / --current-user / --count）
  if (src.currentDb !== undefined) target.currentDb = src.currentDb;
  if (src.currentUser !== undefined) target.currentUser = src.currentUser;
  if (src.users !== undefined) target.users = src.users;
  if (src.passwords !== undefined) target.passwords = src.passwords;
  if (src.counts) target.counts = { ...(target.counts || {}), ...src.counts };
  // 枚举模式专有字段（--hostname / --is-dba / --schema / --privileges / --roles）
  if (src.hostname !== undefined) target.hostname = src.hostname;
  if (src.isDba !== undefined) target.isDba = src.isDba;
  if (src.userPrivs !== undefined) target.userPrivs = src.userPrivs;
  if (src.roles !== undefined) target.roles = src.roles;
  if (src.schemas) target.schemas = { ...(target.schemas || {}), ...src.schemas };
}

// [P0-FIX] resume 合并提取数据：将历史会话的 extracted 合并到当前提取结果。
// 历史库/表/列/行检查已存在则不覆盖（当前扫描已提取到的新数据优先）。
export function mergeExtractedForResume(current, restored) {
  if (!restored) return current;
  if (!current) return structuredClone(restored);
  const out = structuredClone(current);
  for (const db of (restored.databases || [])) {
    if (!out.databases.includes(db)) out.databases.push(db);
  }
  for (const [k, v] of Object.entries(restored.tables || {})) {
    if (!out.tables[k]) out.tables[k] = v;
  }
  for (const [k, v] of Object.entries(restored.columns || {})) {
    if (!out.columns[k]) out.columns[k] = v;
  }
  for (const [k, v] of Object.entries(restored.rows || {})) {
    if (!out.rows[k]) out.rows[k] = v;
  }
  if (restored.currentDb !== undefined && out.currentDb === undefined) out.currentDb = restored.currentDb;
  if (restored.currentUser !== undefined && out.currentUser === undefined) out.currentUser = restored.currentUser;
  if (restored.users !== undefined && out.users === undefined) out.users = restored.users;
  if (restored.passwords !== undefined && out.passwords === undefined) out.passwords = restored.passwords;
  if (restored.counts) out.counts = { ...(restored.counts || {}), ...(out.counts || {}) };
  if (restored.hostname !== undefined && out.hostname === undefined) out.hostname = restored.hostname;
  if (restored.isDba !== undefined && out.isDba === undefined) out.isDba = restored.isDba;
  if (restored.userPrivs !== undefined && out.userPrivs === undefined) out.userPrivs = restored.userPrivs;
  if (restored.roles !== undefined && out.roles === undefined) out.roles = restored.roles;
  if (restored.schemas) out.schemas = { ...(restored.schemas || {}), ...(out.schemas || {}) };
  return out;
}

// 检查提取数据是否含任何有效内容
export function hasData(data) {
  return !!(
    (data.databases && data.databases.length) ||
    (data.tables && Object.keys(data.tables).length) ||
    (data.rows && Object.keys(data.rows).length) ||
    data.currentDb ||
    data.currentUser ||
    data.users ||
    data.passwords ||
    data.hostname ||
    data.isDba ||
    data.userPrivs ||
    data.roles ||
    (data.schemas && Object.keys(data.schemas).length) ||
    (data.counts && Object.values(data.counts).some((v) => v != null))
  );
}

// 受控并发池：最多 concurrency 个任务并行，任务顺序无关；单任务异常被吞不中断其他任务
// （提取阶段点间并行用，与 Extractor._concurrentMap 同语义，独立实现避免跨模块耦合）。
export async function mapPool(items, fn, concurrency) {
  const queue = items.slice();
  let cursor = 0;
  const worker = async () => {
    while (cursor < queue.length) {
      const i = cursor++;
      try {
        await fn(queue[i], i);
      } catch (e) {
        logger.warn(`[extract] 单点提取失败: ${e?.message || e}`);
      }
    }
  };
  const n = Math.max(1, Math.min(concurrency, queue.length));
  await Promise.all(Array.from({ length: n }, () => worker()));
}
