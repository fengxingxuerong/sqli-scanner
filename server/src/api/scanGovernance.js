// =====================================================================
// scanGovernance.js —— 扫描并发额度 + 扫描终结副作用回收
//
// [大文件拆分 2026-09-21] 从 api/scanRoutes.js 抽出（原 719–768 行）。
//
// 为什么这簇能安全外移：
//   · 唯一的模块级状态是 `activeScanCount`（本模块自持，不与被拆文件共享）；
//   · `trackScanTerminal` 的 bus / sm 都是**参数传入**，不闭包捕获外部变量；
//   · 外部依赖仅 `releaseScanScope`（core/scopeGuard.js，叶子模块）。
//
// 这簇管的是「资源不泄漏」两件事：
//   ① 并发额度：超过 MAX_SCAN_API_CONCURRENT 直接拒绝（acquireScanSlot 返回 null）；
//   ② 终结回收：扫描完成/出错/停止三种终结事件都要**幂等地**释放额度 + 注销 scope。
//      漏一处就会额度只增不减（跑满后 API 永久 429）或 scope Map 无界增长。
//
// ⚠ `_scanGovernance` 是**测试钩子**（tests/securityGovernance.test.js 从
// scanRoutes.js import 它）。搬走后由 scanRoutes.js re-export，导出的是**同一个
// 对象引用**，故测试读写的仍是本模块这份状态 —— 语义不变。
// =====================================================================
import { releaseScanScope } from '../core/scopeGuard.js';
import { recordScan } from '../services/scanLedger.js';
import { logger } from '../core/logger.js';

// 并发扫描上限（环境变量可覆盖；非法值回落 8）
const MAX_SCAN_API_CONCURRENT = (() => {
  const n = Number(process.env.MAX_SCAN_API_CONCURRENT);
  return Number.isInteger(n) && n >= 1 ? n : 8;
})();

// 当前活跃扫描数。只在本模块内被 acquireSlot / release / resetForTest 修改。
let activeScanCount = 0;

/**
 * 申请一个扫描并发额度。
 *
 * @returns {(() => void)|null} 释放函数（幂等，重复调用无副作用）；
 *   额度已满返回 null —— 调用方应据此拒绝请求（429 一类）。
 */
export function acquireScanSlot() {
  if (activeScanCount >= MAX_SCAN_API_CONCURRENT) return null;
  activeScanCount++;
  let released = false;
  return () => {
    if (!released) {
      released = true;
      activeScanCount = Math.max(0, activeScanCount - 1);
    }
  };
}

/**
 * 监听扫描终结事件，触发「回收 scope + 释放额度」。
 *
 * 三种终结事件都要覆盖：scan_completed / scan_error / scan_stopped。
 * 另外处理「订阅前就已终结」的竞态：订阅完成的瞬间去查一次状态，已终结则立即收尾
 * （否则该扫描的额度永远不释放）。
 *
 * `finish()` 用 done 标志保证幂等 —— 事件可能重复到达（bus 重放/多订阅），
 * 重复释放会把 activeScanCount 减成负数（额度凭空多出来）。
 *
 * @param {object} sm ScanManager（读 scans.get(scanId).status）
 * @param {object} bus eventBus（bus.create(scanId) 拿发射器）
 * @param {string} scanId 扫描 id
 * @param {() => void} release acquireScanSlot 返回的释放函数
 * @returns {void}
 */
export function trackScanTerminal(sm, bus, scanId, release) {
  const em = bus.create(scanId);
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    em.off('event', onEvent);
    // [P0-SEC 2026-09-08] 扫描终结即回收 scope 登记（避免同 id 复用、也防 Map 无界增长）
    releaseScanScope(scanId);
    release();
  };
  const onEvent = (evt) => {
    if (evt && (evt.type === 'scan_completed' || evt.type === 'scan_error' || evt.type === 'scan_stopped')) {
      persistScan(sm, scanId, evt.type);
      finish();
    }
  };
  em.on('event', onEvent);
  // 竞态：订阅前就已终结的扫描不会再来事件，这里补一次状态检查
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) finish();
}

/**
 * 扫描终结 → 落台账（server/data/ledger/<scanId>/）。
 *
 * 为什么挂在终结事件上：`ScanManager` 在扫描完成后 30s 就回收上下文（_retire），
 * 而台账是**唯一**能把"我到底扫了什么、结果如何"留在服务端的东西。
 * 此前它只有 CLI 与一键扫描在写，REST/桌面侧一条都不落 ⇒ Web 的历史页其实是浏览器
 * localStorage（换机器/清缓存/服务重启即丢），`GET /api/scan/:id/report` 过 30 秒必失败。
 * scanLedger.recordScan 的既有口径在此复用，不另起一套落盘格式。
 *
 * 失败处理：台账写不进（只读盘/权限）不能影响扫描本身与终结回收 —— 只 warn 一条。
 * 关闭方式：SCAN_LEDGER=0（默认开；写盘是同步的，用 setImmediate 挪出事件推送路径）。
 */
function persistScan(sm, scanId, kind) {
  if (process.env.SCAN_LEDGER === '0') return;
  if (kind === 'scan_error') return; // 出错扫描没有可交付结论，不污染台账
  setImmediate(() => {
    try {
      const live = sm.getReport(scanId);
      if (!live) return;
      const rg = sm.reportGen;
      // recordScan 明确要求传 attachPoc 之后的形态（poc 是惰性挂载且不改原对象），
      // 直接把原始 report 传进去会得到 0 个 poc 文件 —— 这条口径见 scanLedger 头注释。
      const withPoc = typeof rg?.attachPoc === 'function' ? rg.attachPoc(live) : live;
      // 不传 docs.json：让 recordScan 落**原始报告**（与 CLI 的口径一致，见 bin/cli.js:569）。
      // rg.toJSON() 是导出形态（_forExport 会截断 + 脱敏 target），存它会导致
      // "台账回读的报告"与"内存里的报告"两种形状 —— 同一条 /scan/:id/report
      // 会因扫描新旧程度返回不同结构，客户端必然踩到。
      recordScan(withPoc, {
        html: typeof rg?.toHTML === 'function' ? rg.toHTML(withPoc) : undefined,
        markdown: typeof rg?.toMarkdown === 'function' ? rg.toMarkdown(withPoc) : undefined,
      });
    } catch (e) {
      logger.warn(`扫描 ${scanId} 台账登记失败（不影响扫描结果）：${e.message}`);
    }
  });
}

/**
 * 测试钩子：暴露并发上限与当前活跃数，并提供 reset。
 *
 * `activeScanCount` 用 getter 暴露 —— 不能用常量快照，否则测试读到的永远是 0。
 */
export const _scanGovernance = {
  maxConcurrent: MAX_SCAN_API_CONCURRENT,
  get activeScanCount() {
    return activeScanCount;
  },
  resetForTest() {
    activeScanCount = 0;
  },
};
