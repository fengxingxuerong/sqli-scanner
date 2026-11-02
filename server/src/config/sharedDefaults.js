// ============================================================================
// sharedDefaults.js —— 跨端默认值的**单一真源**（[P1-CFG 2026-11-02]）
//
// 背景：此前「默认并发/速率/超时/crawlDepth/enableExtract」在四个地方各写一遍：
//   server/src/config/defaults.js（引擎）、bin/cli/args.js（CLI）、
//   src/shared/constants.ts（Web UI）、scanGuard/scalarsCore.js（REST 缺省）。
// 实测漂移：UI 6/5/10s/1、引擎 4/10/30s/0、CLI 4/50、REST 在缺省时把 enableExtract
// 写成 false —— 同一句「默认扫描」从不同入口进去行为不同，且没有任何判据。
//
// 本文件只放**跨端共享**的标量默认值；引擎内部调优项（盲注采样数、并发上限等）
// 仍留在 defaults.js，因为 CLI/UI 不直接建模它们。
// 派生方式：引擎直接 import；前端由 scripts/sync-scan-defaults.mjs 生成
// src/shared/scanDefaults.generated.json（`npm run defaults:check` 守卫）。
// ============================================================================

/**
 * @type {Readonly<{
 *   timeoutMs:number, retry:number, ratePerSec:number, concurrency:number,
 *   timeThresholdMs:number, crawlDepth:number, crawlForms:boolean,
 *   enableExtract:boolean, pocRedactAuth:boolean, confirmFormWrites:boolean
 * }>}
 */
export const SHARED_SCAN_DEFAULTS = Object.freeze({
  // 网络
  timeoutMs: 30000,
  retry: 3,
  // 调度/限速
  ratePerSec: 10,
  concurrency: 4,
  // 时间盲注判定阈值（ms）
  timeThresholdMs: 1500,
  // 爬虫/表单
  crawlDepth: 0,
  crawlForms: false,
  // 数据提取：默认关闭（仅 --dump / 枚举 / UI 显式开启；避免「扫一下就拖库」）
  enableExtract: false,
  // 报告 PoC 凭据脱敏：默认开启
  pocRedactAuth: true,
  // 自动发现表单的写请求：默认关闭
  confirmFormWrites: false,
});

export default SHARED_SCAN_DEFAULTS;
