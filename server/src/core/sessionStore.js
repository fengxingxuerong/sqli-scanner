// ============================================================================
// patch/sessionStore.js —— 安全加固版会话持久化
// 基于 server/src/core/sessionStore.js 修改，修复项：
//   [P1-1] 落盘前剥离 config 中的认证/代理等敏感配置（config.auth / cookieParams /
//          headerParams），避免 session JSON 明文存放目标站凭据
//   [P2-10] 同文件路径写盘互斥（进程内按 filePath 串行化），防 sessionDefault
//           固定文件名（sqli-session-latest.json）并发扫描相互覆盖
// 其余逻辑（路径白名单等）与原文件一致。
// ============================================================================

import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { logger } from './logger.js';
import { sealSecret, openSecret, secretKeySource } from './sessionSecret.js';

// ── 会话落盘路径白名单（原逻辑不变）──
const SESSION_NAME_RE = /^[A-Za-z0-9._-]+$/;

export function isSafeSessionPath(filePath) {
  if (typeof filePath !== 'string' || filePath.length === 0) return false;
  if (filePath === '.' || filePath === '..') return false;
  if (!filePath.includes('/') && !filePath.includes('\\')) {
    // 拒绝裸文件名含 .. 或 . 开头的隐藏文件（如 .env、index.js 等非会话文件）
    return !filePath.includes('..') && !filePath.startsWith('.') && SESSION_NAME_RE.test(filePath);
  }
  const resolved = path.resolve(filePath);
  const rel = path.relative(path.resolve(os.tmpdir()), resolved);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

// [P1-1] 落盘前脱敏 config：剥离认证凭据与代理配置，保留其余扫描配置
// [P0-FIX] 补全剥离集合：原实现只剥 auth/proxy，但注释声称也剥离 cookieParams/headerParams
// （含会话 Cookie / 自定义认证头）。为对齐声明并防御未来 config 混入 params 字段，一并置 null。
function sanitizeConfigForDisk(config) {
  if (!config || typeof config !== 'object') return config;
  const { auth, proxy, cookieParams, headerParams, ...rest } = config;
  return { ...rest, auth: null, proxy: null, cookieParams: null, headerParams: null };
}

// [P2-10] 按文件路径的进程内写盘互斥队列：同一路径的写盘严格串行
// [⑰] 修复锁泄漏：原实现 next.catch(() => {}) 每次创建新 Promise，
// === 比较永远 false → fileLocks.delete 永不执行 → Map 无界增长。
// 修复：存入变量复用同一引用，settled 后比较成功即清理。
const fileLocks = new Map();
function withFileLock(filePath, task) {
  const prev = fileLocks.get(filePath) || Promise.resolve();
  const next = prev.then(task, task); // 前序失败不阻断后续（与既有容错一致）
  const stored = next.catch(() => {}); // 同一引用存入 Map 和清理条件
  fileLocks.set(filePath, stored);
  // 写完成后清理已 settled 的锁条目（stored 已 resolved，不再阻塞后续）
  stored.then(() => { if (fileLocks.get(filePath) === stored) fileLocks.delete(filePath); }, () => {});
  return next;
}

export class ScanSession {
  constructor(scanId, meta = {}, filePath = null) {
    this.scanId = scanId;
    this.url = meta.url || null;
    this.config = meta.config || {};
    this.filePath = filePath && isSafeSessionPath(filePath) ? filePath : null;
    this.points = [];
    this.perPoint = {};
    this.vulns = [];
    this.extracted = null; // [P0-FIX] 增量保存提取数据（report.data），断点续跑时合并
    this.dumpCheckpoints = {}; // [Feature 4] 行级断点：{ "db\x00table": { database, table, lastCompletedRowIndex } }
    this.createdAt = new Date().toISOString();
    this._writeQueue = Promise.resolve();
  }

  // [P1-FIX] 写合并：同一事件循环内的多次 enqueue 只触发一次 _flush（写最新快照）。
  // 原实现每次调用都向 _writeQueue 链追加一次全量 JSON.stringify + fs.writeFile，
  // dumpData 大表拖库（每 checkpointInterval=100 行一次 setDumpCheckpoint，fire-and-forget）
  // 时队列可堆积上千次全量写（内存 + 写放大）。合并后连续写入折叠为 1 次，
  // _flush 在落盘时读取 this 最新状态（_snapshot() 惰性取值），写入的永远是最新快照。
  _enqueueWrite() {
    if (!this.filePath) return Promise.resolve();
    if (!this._writeScheduled) {
      this._writeScheduled = true;
      const task = this._writeQueue.then(() => {
        this._writeScheduled = false;
        return this._flush();
      });
      this._writeQueue = task.catch(() => {}); // 防断链：写失败（_flush 内部已吞错）不影响后续调度
      return task;
    }
    return this._writeQueue;
  }

  setPoints(points) {
    this.points = points.map((p) => ({ id: p.id, location: p.location, param: p.param, originalValue: p.originalValue }));
    for (const p of this.points) {
      if (!this.perPoint[p.id]) this.perPoint[p.id] = { status: 'pending', found: [], extracted: false };
    }
    return this._enqueueWrite();
  }

  savePointResult(pointId, { found = [], extracted = false } = {}) {
    this.perPoint[pointId] = { status: 'done', found, extracted };
    for (const f of found) {
      const exists = this.vulns.some((v) => v.pointId === pointId && v.technique === f.technique);
      if (!exists) this.vulns.push({ pointId, technique: f.technique, dbms: f.result?.dbms || null });
    }
    return this._enqueueWrite();
  }

  // [P0-FIX] 保存提取数据（report.data），断点续跑时合并回报告。
  // 独立方法避免污染 perPoint 点集合（不产生伪注入点）。
  setExtracted(data) {
    this.extracted = data || null;
    return this._enqueueWrite();
  }

  // [Feature 4] 行级断点续传：保存/读取 dumpData 的行级进度
  getDumpCheckpoint(db, table) {
    const key = `${db}\x00${table}`;
    return this.dumpCheckpoints[key] || null;
  }

  setDumpCheckpoint(db, table, lastCompletedRowIndex) {
    const key = `${db}\x00${table}`;
    this.dumpCheckpoints[key] = { database: db, table, lastCompletedRowIndex };
    return this._enqueueWrite();
  }

  markPointError(pointId, error) {
    if (this.perPoint[pointId]) this.perPoint[pointId].status = 'error';
    else this.perPoint[pointId] = { status: 'error', found: [], extracted: false, error: String(error) };
    if (this.filePath) this._enqueueWrite();
  }

  pendingPointIds() {
    return Object.keys(this.perPoint).filter((id) => this.perPoint[id].status !== 'done');
  }

  isComplete() {
    return Object.keys(this.perPoint).length > 0 && this.pendingPointIds().length === 0;
  }

  finalize(report) {
    this.finalReport = report ? { riskLevel: report.riskLevel, finishedAt: report.finishedAt } : null;
    this.completedAt = new Date().toISOString();
    return this._enqueueWrite();
  }

  _snapshot() {
    return {
      scanId: this.scanId,
      url: this.url,
      // [P1-1] 脱敏：config.auth/proxy 置 null，不落盘明文凭据
      config: sanitizeConfigForDisk(this.config),
      createdAt: this.createdAt,
      completedAt: this.completedAt || null,
      // [P0-SEC 2026-09-18 / A5] 注入点原始值（可能是 Cookie/认证头 → 会话凭据）落盘前封存。
      // 内存语义不变（this.points 仍是明文），只有磁盘这一份是密文；load() 会解封回来。
      points: this.points.map((p) => (p && typeof p === 'object'
        ? { ...p, originalValue: sealSecret(p.originalValue) }
        : p)),
      perPoint: this.perPoint,
      vulns: this.vulns,
      // [P0-FIX] 持久化提取数据，断点续跑时合并回 report.data
      extracted: this.extracted || null,
      // [Feature 4] 持久化行级断点，断点续跑时恢复 dumpData 进度
      dumpCheckpoints: this.dumpCheckpoints || {},
      finalReport: this.finalReport || null,
    };
  }

  async _flush() {
    if (!this.filePath) return;
    if (!isSafeSessionPath(this.filePath)) return;
    try {
      await fs.mkdir(path.dirname(this.filePath), { recursive: true });
      const data = JSON.stringify(this._snapshot());
      // [P2-FIX] 原子写：先写同目录临时文件再 rename 覆盖（崩溃/进程被杀不会留下半写文件，
      // 原实现直接 writeFile 目标路径，半写会导致 ScanSession.load 解析失败返回 null → 会话丢失）。
      // 仅当目标文件已存在或同目录可写时走 temp+rename；失败回退直接写（保持既有容错语义）。
      const tmpPath = `${this.filePath}.${process.pid}.${Date.now()}.tmp`;
      try {
        await withFileLock(this.filePath, async () => {
          await fs.writeFile(tmpPath, data, 'utf-8');
          await fs.rename(tmpPath, this.filePath).catch(() => fs.writeFile(this.filePath, data, 'utf-8'));
        });
        // 清理残留 tmp（rename 成功时 tmp 已消失；回退直写路径可能残留）
        await fs.unlink(tmpPath).catch(() => {});
      } catch {
        // temp+rename 不可用（权限/跨设备）→ 回退直接写（与旧行为一致，不改变容错语义）
        await withFileLock(this.filePath, () => fs.writeFile(this.filePath, data, 'utf-8'));
      }
    } catch (e) {
      // 落盘失败不阻断扫描主流程（与 sqlmap session 容错一致）
    }
  }

  static async load(filePath) {
    if (!isSafeSessionPath(filePath)) return null;
    try {
      const raw = await fs.readFile(filePath, 'utf-8');
      const data = JSON.parse(raw);
      const s = new ScanSession(data.scanId, { url: data.url, config: data.config }, filePath);
      // [A5] 解封注入点原始值。解不开（换过 key / 旧随机 key）→ 该点降级为待重扫，
      // 而不是把密文当参数值发出去（那会发出一个毫无意义的请求并污染结果）。
      const unsealed = [];
      const failedPointIds = [];
      for (const p of Array.isArray(data.points) ? data.points : []) {
        if (!p || typeof p !== 'object') { unsealed.push(p); continue; }
        const opened = openSecret(p.originalValue);
        if (opened === null) {
          failedPointIds.push(String(p.id));
          unsealed.push({ ...p, originalValue: undefined });
        } else {
          unsealed.push({ ...p, originalValue: opened });
        }
      }
      if (failedPointIds.length) {
        logger.warn(
          `会话 ${data.scanId} 有 ${failedPointIds.length} 个注入点原始值无法解封` +
            `（密钥来源 ${secretKeySource()}）——这些点将作为未完成重新扫描：${failedPointIds.slice(0, 5).join(', ')}`
        );
      }
      s.points = unsealed;
      s.perPoint = data.perPoint || {};
      for (const id of failedPointIds) {
        s.perPoint[id] = { status: 'pending', found: [], extracted: false };
      }
      s.vulns = data.vulns || [];
      s.extracted = data.extracted || null; // [P0-FIX] 恢复提取数据
      s.dumpCheckpoints = data.dumpCheckpoints || {}; // [Feature 4] 恢复行级断点
      s.createdAt = data.createdAt || s.createdAt;
      s.completedAt = data.completedAt || null;
      s.finalReport = data.finalReport || null;
      return s;
    } catch {
      return null;
    }
  }
}

export default ScanSession;
