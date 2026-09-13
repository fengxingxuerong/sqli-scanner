// ============================================================================
// core/dbHealthGuard.js —— 目标数据库健康守卫（熔断）
//
// 背景（实战事故）：并发 4 反复扫同一 PostgreSQL 目标时，检测器投放的多层嵌套
// 子查询会在并发叠加下触发 PG 的 `stack depth limit exceeded`，此后该库连接
// 进入不可用状态——所有查询 500，连原始业务请求都失败。
// 危害等级：等同把客户生产库打挂。扫描器必须先保证「不伤害目标」，再谈检出率。
//
// 为什么既有自适应并发没兜住：Scheduler 的自适应只看「网络层错误」与「延迟」，
// 而 DB 致命错误表现为 **HTTP 500 + 错误体**（请求在 HTTP 层是成功的），
// 错误率恒为 0 → 自适应完全无感，并发一路维持 4 直到打挂。
//
// 本模块职责：
//   1) 从响应体识别「目标库已进入不可恢复状态」的致命特征；
//   2) 首次命中即熔断（trip）：通知调度器把并发打到 1，并让检测器跳过重型 payload；
//   3) 连续命中达阈值 → 请求中止本次扫描（库已损坏，继续测全是脏数据 + 持续伤害）。
//
// 设计约束：
//   - 只识别「目标已受损」的信号，不识别普通 SQL 报错（普通报错是检测器的正常输入，
//     误熔断会让 error 技术整体失效）。
//   - 无状态泄漏：Guard 生命周期跟随单次扫描（由 scanRunner 创建并持有）。
// ============================================================================

// 目标库致命错误特征表。命中即代表「继续请求有害且无意义」，不是普通注入报错。
// 每条均附 hint，便于在报告/日志里给出可操作的处置建议。
export const FATAL_DB_SIGS = [
  {
    id: 'stack_depth',
    sig: /stack depth limit exceeded/i,
    hint: '数据库已达 max_stack_depth 上限，连接不可用；需降低并发并避免深层嵌套子查询',
  },
  {
    id: 'too_many_connections',
    sig: /too many (clients|connections)( already)?/i,
    hint: '数据库连接池耗尽；需降低并发',
  },
  {
    id: 'connection_terminated',
    sig: /(server closed the connection unexpectedly|connection terminated unexpectedly|connection reset by peer|terminating connection due to)/i,
    hint: '数据库连接被服务端中断',
  },
  {
    id: 'out_of_memory',
    sig: /(out of memory|cannot allocate memory|out of shared memory)/i,
    hint: '数据库内存耗尽',
  },
  {
    id: 'too_many_prepared',
    sig: /(too many prepared statements|prepared statement .* already exists)/i,
    hint: '预编译语句句柄耗尽；需降低并发',
  },
  {
    id: 'db_readonly',
    sig: /(cannot execute .* in a read-only transaction|database is in recovery|the database system is (starting up|shutting down|in recovery))/i,
    hint: '数据库处于只读/恢复中状态，已无法承载扫描',
  },
];

/**
 * 从响应体识别致命 DB 错误。
 * 仅当 HTTP 状态码为 5xx（或无法判定但文本强特征）时才判定，避免把页面里
 * 恰好出现的报错文案（如帮助中心文档）误判为目标受损。
 * @param {{status?: number, data?: any}} res 响应对象
 * @returns {{id: string, hint: string}|null} 命中返回特征对象，否则 null
 */
export function detectFatalDbError(res) {
  if (!res) return null;
  const status = Number(res.status);
  const text = String(res.data ?? '');
  if (!text) return null;
  // 5xx 才是「服务端炸了」；2xx/3xx 页面即使含类似文案也不是目标受损
  if (!Number.isFinite(status) || status < 500 || status > 599) return null;
  for (const s of FATAL_DB_SIGS) {
    if (s.sig.test(text)) return { id: s.id, hint: s.hint };
  }
  return null;
}

/**
 * 「重型」payload 判定：多层嵌套子查询。
 * 这类语句正是触发 PG stack depth 的主因（每条都带 3 层左右子查询，
 * 并发叠加时栈深度成倍增长）。熔断后应当跳过，只保留扁平 payload。
 * 判据（保守，只拦确实深嵌套的）：`(SELECT` 出现 ≥3 次，或 `FROM (` 出现 ≥2 次。
 * @param {string} payload 待投放的注入串
 * @returns {boolean}
 */
export function isHeavyPayload(payload) {
  const s = String(payload ?? '');
  if (!s) return false;
  const sub = (s.match(/\(\s*SELECT/gi) || []).length;
  if (sub >= 3) return true;
  const fromParen = (s.match(/FROM\s*\(/gi) || []).length;
  return fromParen >= 2;
}

/**
 * 单次扫描的健康守卫。
 * 用法：scanRunner 创建 → 挂到 ctx.guard → Detector.send / sendInjection 回流 observe。
 */
export class DbHealthGuard {
  /**
   * @param {object} [opts]
   * @param {(info: {id: string, hint: string, fatalHits: number}) => void} [opts.onTrip]
   *        首次熔断回调（用于调度器降并发）。
   * @param {number} [opts.abortAfter] 连续致命命中达到该次数后请求中止扫描（默认 3）。
   */
  constructor({ onTrip, abortAfter } = {}) {
    this.onTrip = typeof onTrip === 'function' ? onTrip : null;
    const abortAfterN = Number(abortAfter);
    this.abortAfter = Number.isFinite(abortAfterN) && abortAfterN > 0 ? abortAfterN : 3;
    this.tripped = false;
    this.fatalHits = 0;
    this.lastFatal = null;
    this.skippedHeavy = 0;
  }

  /**
   * 回流观察一次响应。命中致命特征即累计；首次命中触发 onTrip。
   * @param {{status?: number, data?: any}} res 响应
   * @returns {boolean} 本次是否命中致命错误
   */
  observe(res) {
    const hit = detectFatalDbError(res);
    if (!hit) return false;
    this.fatalHits += 1;
    this.lastFatal = hit;
    if (!this.tripped) {
      this.tripped = true;
      if (this.onTrip) {
        try {
          this.onTrip({ ...hit, fatalHits: this.fatalHits });
        } catch {
          /* 回调失败不影响熔断状态 */
        }
      }
    }
    return true;
  }

  /**
   * 熔断后是否应跳过该 payload（重型嵌套子查询）。
   * 未熔断时恒为 false —— 默认路径零行为变化，不影响既有检出率与请求数。
   * @param {string} payload
   * @returns {boolean}
   */
  shouldSkip(payload) {
    if (!this.tripped) return false;
    if (!isHeavyPayload(payload)) return false;
    this.skippedHeavy += 1;
    return true;
  }

  /** 是否已达到中止阈值（库基本已废，继续扫描只产出脏数据） */
  get shouldAbort() {
    return this.fatalHits >= this.abortAfter;
  }

  /** 报告/日志用的状态摘要 */
  summary() {
    if (!this.tripped) return null;
    return {
      fatalId: this.lastFatal?.id ?? null,
      hint: this.lastFatal?.hint ?? null,
      fatalHits: this.fatalHits,
      skippedHeavy: this.skippedHeavy,
      aborted: this.shouldAbort,
    };
  }
}

export default DbHealthGuard;
