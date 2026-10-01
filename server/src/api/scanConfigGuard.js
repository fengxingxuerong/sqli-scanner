// ====================================================================================
// api/scanConfigGuard.js —— 扫描配置的【唯一】入参守卫（clamp / 形状校验 / 白名单键落地）
//
// 为什么单独成文件（2026-09-25 从 scanRoutes.sanitizeStart 整段平移，行为不变）：
//   这 500+ 行守卫原先长在 HTTP 分支里，于是"第二条入口"（直连模式 mode:direct）完全绕过它
//   —— buildDirectTarget 当时只做了 scope 判定就把 {...defaults, ...cfg} 原样交给引擎，
//   实测越界值 concurrency:9999 / timeoutMs:99999999 / 带分号的 dumpWhere 直接进引擎。
//   本仓对这类缺陷的口径是【两条入口走同一个守卫函数】，而不是"在第二条入口里手挑几个键 clamp"
//   （手挑等于两张清单各自漂移，而那正是它当初被漏掉的机制原因）。
//
// 整段平移能成立的前提（改本文件前先核）：
//   ① 块内只依赖 cfg / config / scopeRules 与模块级导入 —— HTTP 专有的 url/method/params
//      处理全在块外，所以没有夹带目标解析；
//   ② 兜底透传 BACKFILL_SCALAR_KEYS 已含在块末（在调用方播报"被丢弃的键"**之前**完成），
//      否则 18 个"靠兜底才落地"的键会被误报成"设置不会生效"。
// ====================================================================================

// [六期拆分 2026-10-01] 550 行线性 clamp 序列按域切到 ./scanGuard/*（每段整块平移为
// 独立函数、config 原地写，调用顺序即原书写顺序）：标量主序列（scalarsCore）→ 出口与
// 护栏（scalarsEgress，含 applyTuningKnobs 唯一调用点）→ 五个对象组（objectGroups）→
// bespoke 真校验键（bespokeKeys）→ 白名单标量兜底（backfill，必须最后）。
// 本文件只剩编排与两个既有导出（buildGuardedConfig / sanitizeExtractScope re-export）
// —— scanRoutes.js 与 directTarget.js 的导入路径不变。

import {
  guardScalarsCore,
} from './scanGuard/scalarsCore.js';
import { guardScalarsEgress } from './scanGuard/scalarsEgress.js';
import {
  guardSecondOrder, guardWafEvasion, guardOob, guardNoSql, guardBlindRobust,
} from './scanGuard/objectGroups.js';
import { guardBespokeKeys } from './scanGuard/bespokeKeys.js';
import { applyBackfill } from './scanGuard/backfill.js';
export { sanitizeExtractScope } from './scanGuard/extractScope.js';

/**
 * 把调用方传来的 cfg 规范化成引擎实际使用的 config。
 * @param {object} cfg 请求体里的 config（未净化）
 * @param {object} scopeRules parseScope(cfg.scope) 的结果（HTTP 与直连共用同一判据）
 * @returns {object} 只含白名单键、且全部经过 clamp / 形状校验的配置
 */
export function buildGuardedConfig(cfg, scopeRules) {
  const config = {};
  // scope 原文进 config（可序列化：数组形态），供路由层登记与 HttpClient 逐跳重定向校验复用
  if (scopeRules.enabled) config.scope = scopeRules.raw;
  guardScalarsCore(config, cfg, scopeRules);
  guardScalarsEgress(config, cfg);
  guardSecondOrder(config, cfg);
  guardWafEvasion(config, cfg);
  guardOob(config, cfg);
  guardNoSql(config, cfg);
  guardBlindRobust(config, cfg);
  guardBespokeKeys(config, cfg);

  // hex / flushSession 两个严格布尔位已随本批调优旋钮一起挪到 api/scanConfigTuning.js
  // （同一形状："REST 收下、引擎按 === true 判定"的那类键，宁可拒掉并说明）；
  // 统一在上方 compactErrorTemplates 之后那一次 applyTuningKnobs 调用里落地，
  // **不要再调第二遍** —— 它是幂等的，但两处调用会让"哪个键在哪被写"重新变成读代码才能知道的事。

  // 未知字段：忽略，但**必须喊出来**（原来是 debug 级，默认 info 日志下等于静默）。
  // [CFG-REACH 2026-09-20] 为什么从 debug 提到 warn：本函数的返回 config 只由白名单键构成，
  // 所以「传了未知键」= 「你以为设置了的开关根本没进引擎」。调用方拿到的是 200 + scanId，
  // 报告里是一句「未检出」——静默丢弃把一个配置笔误变成了看起来完全正常的假阴性。
  // 这正是本仓库反复手工补过的坑（注释里已有 6 处「此前不在白名单被静默丢弃」）。
  // 前端不会因此刷屏：它发的是 SCAN_CONFIG_KEYS 推导出来的键集，实测不含未知键。
  // 两类静默丢弃都**必须喊出来**（判据在 scanConfigUtils.diffDroppedConfigKeys，纯函数可单测）：
  // · unknown —— 键名不在白名单：本函数返回的 config 只由白名单键构成，"传了未知键"
  //   等于"你以为设置的开关根本没进引擎"（[CFG-REACH 2026-09-20] 从 debug 提到 warn）。
  // · shapeDropped —— 键名**在**白名单、值也确实发了，却因形状/clamp 校验被丢
  //   （matchCode:200、skipParams:"a,b"、paramDel 取了窄集合外的字符…）。
  //   后果与上一类完全相同：200 + scanId + 报告里一句「未检出」，而那项设置没生效。
  //   原先只有 hex/flushSession 一处按这个口径在喊（现于 scanConfigTuning），这一类却是整个入口的通病。
  // 未知键 / 值形态不合的丢弃 → 播报壳在 scanConfigTuning.warnDroppedConfigKeys
  // （判据本身是纯函数 scanConfigUtils.diffDroppedConfigKeys）。⚠ **必须在 return 前**调用：
  // 放早了会算在下方兜底透传之前，把 18 个"靠兜底才落地"的键误报成"设置不会生效"。
  applyBackfill(config, cfg);
  return config;
}
