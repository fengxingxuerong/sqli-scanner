// =====================================================================
// backfill.js — 白名单标量键兜底透传（显式名单，不是「所有未处理的白名单键」）。
// 自 scanConfigGuard.js 拆出（纯搬移）。⚠ 必须在 return 前、其余守卫之后调用：
//   ① 只落地 config 里还没有的键（k in config 跳过）；
//   ② 在调用方 warnDroppedConfigKeys 播报「被丢弃的键」之前完成，
//     否则 18 个「靠兜底才落地」的键会被误报成「设置不会生效」。
// =====================================================================

export function applyBackfill(config, cfg) {
  // [P0-FIX 2026-10-05] 限速三键必须夹取到与 exploitRoutes **完全相同**的区间。
  //
  // 缺陷：同一语义（--delay / --reqrate / --max-requests），两个 REST 入口两套契约 ——
  //   exploitRoutes.js:211-213   numOpt(v, 0, { min:0, max:60/1000/1e6 })  ← 有夹取
  //   本文件下方通用分支         Number.isFinite(v) 即原样透传             ← 无夹取
  //
  // 实测（直接调用 applyBackfill）：
  //   delay=-5     → -5       负延时，行为等同 0 ⇒ 用户设的延时静默失效
  //   delay=99999  → 99999    实际被 retry.js 的 Math.min(…, MAX_DELAY_SEC) 夹到 60
  //   reqRate=50000→ 50000    实际被 TokenBucket 的 Math.min(…, 10000) 夹到 10000
  //
  // 注意危害的准确定性：这三键**不会**造成限速绕过 —— 消费端 retry.js 与
  // TokenBucket 各自都有上限兜底（防御纵深，所以现在还没出事）。真正的危害是
  // **静默失真**：用户设的值与实际生效的值不一致，且没有任何提示。
  // 而"当前靠下游三处兜底才没出事"本身就是契约该写在入口的证据：
  // 任何一层重构时都可能悄悄丢掉一层，届时就成了真绕过。
  //
  // 为什么夹取而不是丢弃：clampStr/pickInt 对"非法值"的契约是丢弃，但用户填
  // delay=120 的本意是"慢一点"，夹到 60 保留了意图；丢弃则退化成"不延时"，
  // 限速反而凭空消失 —— 比夹取更危险。
  //
  // ⚠️ 两处区间必须同步维护。改动任一侧都要改另一侧，
  //    由 tests/configRateLimitClamp.test.js + tests/configReachability.guard.test.js 钉住。
  const RATE_LIMIT_BOUNDS = {
    delay: [0, 60],
    reqRate: [0, 1000],
    maxReq: [0, 1_000_000],
  };

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
    if (typeof v === 'number' && Number.isFinite(v)) {
      // 限速三键夹取；其余键保持原样透传（夹取只对有明确上下界的键做，不外溢）
      const bounds = RATE_LIMIT_BOUNDS[k];
      config[k] = bounds ? Math.min(Math.max(v, bounds[0]), bounds[1]) : v;
      continue;
    }
    if (typeof v === 'string' && v !== '') { config[k] = v.slice(0, 2000); continue; }
    // 其余形态（对象/数组/空串）不兜底：交由逐项 clamp 处理，不绕过现有校验
  }
}
