// =====================================================================
// backfill.js — 白名单标量键兜底透传（显式名单，不是「所有未处理的白名单键」）。
// 自 scanConfigGuard.js 拆出（纯搬移）。⚠ 必须在 return 前、其余守卫之后调用：
//   ① 只落地 config 里还没有的键（k in config 跳过）；
//   ② 在调用方 warnDroppedConfigKeys 播报「被丢弃的键」之前完成，
//     否则 18 个「靠兜底才落地」的键会被误报成「设置不会生效」。
// =====================================================================

export function applyBackfill(config, cfg) {
  // [P0-FIX 2026-09-09] 白名单标量键兜底透传（**显式名单**，不是“所有未处理的白名单键”）。
  // 发现原因：configWhitelist.passthrough 守卫抱出 13 个「进了 KNOWN_CFG_KEYS 但 sanitizeStart
  // 根本没透传」的键——delay / reqRate / maxReq（限速与请求预算治理）、excludeSysdbs /
  // nullConnection / testFilter / testSkip / useRegistry / hpp / forceSsl / ignoreRedirects /
  // activeWafProbe / prefilter 均在内。表现为「REST 传了但引擎收不到」：sqlmap 对标能力在
  // API/CLI 层不可达，而「降低扫描风险」的治理键默认被当成已生效。
  // 为什么用显式名单而不是反向遍历：clampStr/pickInt 系列对「空串/非法值」的契约是**丢弃**
  // （有既有测试锁定），反向遍历会把 `''` 这类值当合法透传，改变现有语义。
  const BACKFILL_SCALAR_KEYS = new Set([
    'prefilter', 'testFilter', 'testSkip', 'useRegistry', 'excludeSysdbs', 'nullConnection',
    'delay', 'reqRate', 'maxReq', 'forceSsl', 'ignoreRedirects', 'hpp', 'activeWafProbe',
    // freshQueries：纯布尔开关，无需单独校验分支，走统一标量透传
    'freshQueries',
    // [CFG-REACH 2026-09-20] 进白名单只解决「不报错」，不透传就仍然收不到——这正是上面
    // 注释里那 13 个键的老病。这几个都是引擎按 truthy 判定的开关，走统一透传即可：
    // testPath/testHeaders（TargetParser）· noCast（DBFingerprinter/Extractor）
    // · unionFrom（引擎侧 resolveFromClause 已再过 sanitizeUnionFrom）
    // 刻意不进这里的三个，各自都有会坏事的理由：
    //   dumpWhere    —— 拼进提取 SQL 的原始片段，走下方 bespoke 分支拒分号
    //   hex          —— 引擎按 `config.hex === true` **严格**判定（Extractor.js:618,697），
    //                    通用透传会放过 1/"true"，于是又变成「API 收了、引擎不生效」
    //   flushSession —— 与 hex 同口径收严格布尔，避免同一批键里两种真值语义并存
    'testPath', 'testHeaders', 'noCast', 'unionFrom',
  ]);
  for (const k of BACKFILL_SCALAR_KEYS) {
    if (!(k in cfg) || k in config) continue;
    const v = cfg[k];
    if (v === undefined || v === null) continue;
    if (typeof v === 'boolean') { config[k] = v; continue; }
    if (typeof v === 'number' && Number.isFinite(v)) { config[k] = v; continue; }
    if (typeof v === 'string' && v !== '') { config[k] = v.slice(0, 2000); continue; }
    // 其余形态（对象/数组/空串）不兜底：交由逐项 clamp 处理，不绕过现有校验
  }
}
