// =====================================================================
// scalarsCore.js — buildGuardedConfig 的标量主序列（网络/调度/提取/响应锚点族）。
// 自 scanConfigGuard.js 拆出（纯搬移）：逐键 clamp 序列整段平移为函数，config 原地写。
// 依赖入参 scopeRules（safeUrl/csrf 的授权范围约束）——调用方保证顺序：
//   本函数先于 bespokeKeys（extractScope 隐含开 enableExtract 依赖此处已落的 enableExtract）。
// =====================================================================
import { clampInt, clampStr, pickInt, pickBool } from '../scanConfigUtils.js';
import { defaults } from '../../config/defaults.js';
import { logger } from '../../core/logger.js';
import { filterInScope } from '../../core/scopeGuard.js';

export function guardScalarsCore(config, cfg, scopeRules) {
  // —— 网络/调度 ——
  // [REVERTED P2-3] ratePerSec 不 clamp（既有契约「原样透传 P0-P1③」），限速治理归
  // httpClient/defaults。但不 clamp ≠ 不管类型：下游用 Number.isFinite 严格判定而它**不转
  // 类型** ⇒ 数字字符串 "20" 被判成 0，而 0 的语义是「不限速」（tokenBucket.js:23）——
  // 刚设的闸门被静默关掉，且"键在值也在"所以 dropped 告警不响。这里只做类型归一：
  // 数字字符串→数字；非数字形态不写入 config（按 defaults 治理）并喊出来，绝不降级成不限速。
  if (cfg.ratePerSec !== undefined && cfg.ratePerSec !== null) {
    const raw = cfg.ratePerSec;
    const n = typeof raw === 'string' ? Number(raw.trim()) : raw;
    if (typeof n === 'number' && Number.isFinite(n)) config.ratePerSec = n;
    else logger.warn(`ratePerSec 值不可用作速率（${JSON.stringify(raw)}），已忽略并按默认限速治理；要不限速请显式传数字 0`);
  }
  const concurrency = pickInt(cfg, 'concurrency', defaults.concurrency, 1, 10);
  if (concurrency !== undefined) config.concurrency = concurrency;
  const retry = pickInt(cfg, 'retry', defaults.retry, 0, 5);
  if (retry !== undefined) config.retry = retry;
  const timeoutMs = pickInt(cfg, 'timeoutMs', defaults.timeoutMs, 1000, 60000);
  if (timeoutMs !== undefined) config.timeoutMs = timeoutMs;
  const timeThresholdMs = pickInt(cfg, 'timeThresholdMs', defaults.timeThresholdMs, 100, 60000);
  if (timeThresholdMs !== undefined) config.timeThresholdMs = timeThresholdMs;
  const level = pickInt(cfg, 'level', defaults.level, 1, 5);
  if (level !== undefined) config.level = level;
  const risk = pickInt(cfg, 'risk', defaults.risk, 1, 3);
  if (risk !== undefined) config.risk = risk;
  const prefix = clampStr(cfg.prefix, '', 200);
  if (prefix !== undefined) config.prefix = prefix;
  const suffix = clampStr(cfg.suffix, '', 200);
  if (suffix !== undefined) config.suffix = suffix;
  config.enableExtract = !!cfg.enableExtract;

  // —— P0-S3 新增显式收编字段（原逻辑不变）——
  const extractConcurrency = pickInt(cfg, 'extractConcurrency', defaults.extractConcurrency, 1, 16);
  if (extractConcurrency !== undefined) config.extractConcurrency = extractConcurrency;
  const dumpMaxRows = pickInt(cfg, 'dumpMaxRows', 50000, 1, 50000);
  if (dumpMaxRows !== undefined) config.dumpMaxRows = dumpMaxRows;
  const timeBlindSamples = pickInt(cfg, 'timeBlindSamples', defaults.timeBlindSamples, 3, 10);
  if (timeBlindSamples !== undefined) config.timeBlindSamples = timeBlindSamples;
  // [T4 标定] 时间盲注自适应标定（--time-sec 自适应）+ 探测/提取 sleep 参数化透传
  const timeBlindCalibrate = pickBool(cfg, 'timeBlindCalibrate');
  if (timeBlindCalibrate !== undefined) config.timeBlindCalibrate = timeBlindCalibrate;
  const timeBlindCalibrateMin = pickInt(cfg, 'timeBlindCalibrateMin', defaults.timeBlindCalibrateMin, 1, 30);
  if (timeBlindCalibrateMin !== undefined) config.timeBlindCalibrateMin = timeBlindCalibrateMin;
  const timeBlindSleepSec = pickInt(cfg, 'timeBlindSleepSec', defaults.timeBlindSleepSec, 1, 60);
  if (timeBlindSleepSec !== undefined) config.timeBlindSleepSec = timeBlindSleepSec;
  const timeProbeSleepSec = pickInt(cfg, 'timeProbeSleepSec', undefined, 1, 60);
  if (timeProbeSleepSec !== undefined) config.timeProbeSleepSec = timeProbeSleepSec;
  const timeExtractSleepSec = pickInt(cfg, 'timeExtractSleepSec', undefined, 1, 60);
  if (timeExtractSleepSec !== undefined) config.timeExtractSleepSec = timeExtractSleepSec;
  const maxColumnsGuess = pickInt(cfg, 'maxColumnsGuess', defaults.maxColumnsGuess, 1, 100);
  if (maxColumnsGuess !== undefined) config.maxColumnsGuess = maxColumnsGuess;
  const dumpRowLimit = pickInt(cfg, 'dumpRowLimit', defaults.dumpRowLimit, 1, 1000);
  if (dumpRowLimit !== undefined) config.dumpRowLimit = dumpRowLimit;
  // [sqlmap 对标] 行范围导出：--start/--stop → dumpStart/dumpStop（绝对行号，clamp 0~1000000）
  const dumpStart = pickInt(cfg, 'dumpStart', defaults.dumpStart, 0, 1000000);
  if (dumpStart !== undefined) config.dumpStart = dumpStart;
  const dumpStop = pickInt(cfg, 'dumpStop', defaults.dumpStop, 0, 1000000);
  if (dumpStop !== undefined) config.dumpStop = dumpStop;
  // [sqlmap 对标] 保活探测：--safe-url 仅放行 http(s)（SSRF 在 client.request 内逐请求校验）；
  // safeFreq clamp 1~10000。非法协议静默丢弃（不阻断启动）。
  if (typeof cfg.safeUrl === 'string' && /^https?:\/\//i.test(cfg.safeUrl.trim())) {
    // [P0-SEC 2026-09-08] safeUrl 也受授权范围约束：保活探测页常是另一个主机（/health 走网关），
    // 不校就等于开了一个「扫描器自己往圈外发请求」的旁路，而且会携带 Cookie/Authorization。
    const safeUrlInScope = !scopeRules.enabled || filterInScope([cfg.safeUrl.trim()], scopeRules).allowed.length > 0;
    if (!safeUrlInScope) {
      logger.warn(`safeUrl ${cfg.safeUrl.trim()} 越出授权范围（scope），已丢弃该配置`);
    } else {
      config.safeUrl = clampStr(cfg.safeUrl.trim(), '', 2000);
      const safeFreq = pickInt(cfg, 'safeFreq', defaults.safeFreq, 1, 10000);
      if (safeFreq !== undefined) config.safeFreq = safeFreq;
    }
  }
  // [批次 5 补遗 2026-09-14] CSRF 会话层透传（KNOWN_CFG_KEYS 守卫要求：白名单键必须在
  // sanitizeStart 落地，否则 REST/API 路径收不到——CLI 单独走自己的映射不受影响）。
  // csrfUrl 与 safeUrl 同款：仅放行 http(s) + 受授权范围约束。
  // [位置修复 2026-09-14] 原插入落在 safeUrl 的 else 分支内 → 单独配置 csrfUrl（不带
  // safeUrl）时透传不执行，契约守卫 FAIL（5 键全 miss）。移出到顶层平级。
  if (typeof cfg.csrfUrl === 'string' && cfg.csrfUrl.trim()) {
    const csrfUrl = cfg.csrfUrl.trim();
    if (!/^https?:\/\//i.test(csrfUrl)) {
      logger.warn(`csrfUrl ${csrfUrl} 非法协议，已丢弃该配置`);
    } else if (scopeRules.enabled && filterInScope([csrfUrl], scopeRules).allowed.length === 0) {
      logger.warn(`csrfUrl ${csrfUrl} 越出授权范围（scope），已丢弃该配置`);
    } else {
      config.csrfUrl = clampStr(csrfUrl, '', 2048);
      if (typeof cfg.csrfTokenName === 'string' && cfg.csrfTokenName.trim()) {
        config.csrfTokenName = clampStr(cfg.csrfTokenName.trim(), '', 128);
      }
      if (typeof cfg.csrfMethod === 'string' && cfg.csrfMethod.trim()) {
        const m = cfg.csrfMethod.trim().toUpperCase();
        if (['GET', 'POST'].includes(m)) config.csrfMethod = m;
      }
      const csrfFreq = pickInt(cfg, 'csrfRefreshFreq', defaults.csrfRefreshFreq, 1, 10000);
      if (csrfFreq !== undefined) config.csrfRefreshFreq = csrfFreq;
    }
  }
  // --skip：参数名数组（去重、去空、clamp 64，字符串化校验）
  if (Array.isArray(cfg.skipParams)) {
    const sp = [...new Set(cfg.skipParams.map((s) => String(s).trim()).filter(Boolean))].slice(0, 64);
    if (sp.length) config.skipParams = sp;
  }
  const dumpConcurrency = pickInt(cfg, 'dumpConcurrency', defaults.dumpConcurrency, 1, 16);
  if (dumpConcurrency !== undefined) config.dumpConcurrency = dumpConcurrency;
  const dumpDatabaseConcurrency = pickInt(cfg, 'dumpDatabaseConcurrency', defaults.dumpDatabaseConcurrency, 1, 16);
  if (dumpDatabaseConcurrency !== undefined) config.dumpDatabaseConcurrency = dumpDatabaseConcurrency;
  const crawlForms = pickBool(cfg, 'crawlForms');
  if (crawlForms !== undefined) config.crawlForms = crawlForms;
  // [B-perf] skip-static 参数预筛选（对标 --skip-static）：boolean 化透传，默认关（opt-in）
  const skipStatic = pickBool(cfg, 'skipStatic');
  if (skipStatic !== undefined) config.skipStatic = skipStatic;
  // [P1-PERF 2026-09-08] 输入校验跳过的开关（默认 true，需能透传 false 才能关）
  const validationSkip = pickBool(cfg, 'validationSkip');
  if (validationSkip !== undefined) config.validationSkip = validationSkip;
  // [P0-SEC 2026-09-08] PoC 凭据脱敏开关（交付型报告建议开）
  const pocRedactAuth = pickBool(cfg, 'pocRedactAuth');
  if (pocRedactAuth !== undefined) config.pocRedactAuth = pocRedactAuth;
  // [perf-FIX 2026-09-07] 单点目标 opt-in 预筛选：默认关闭（不配置时单点不预筛，行为与历史一致）
  const prefilterSinglePoint = pickBool(cfg, 'prefilterSinglePoint');
  if (prefilterSinglePoint !== undefined) config.prefilterSinglePoint = prefilterSinglePoint;
  // [B-perf] 响应相似度锚点（对标 --string / --not-string）：Detector.matchAnchors / _boundarySimilar
  // 消费 config.matchString / config.notString（此前不在白名单被静默丢弃）。字符串截断到 500。
  const matchString = clampStr(cfg.matchString, undefined, 500);
  if (matchString !== undefined) config.matchString = matchString;
  const notString = clampStr(cfg.notString, undefined, 500);
  if (notString !== undefined) config.notString = notString;
  // [主代理收尾] 盲注响应匹配多指标（二轮增强已实现，Detector.matchText/_matchByCode/
  // _matchByRegexp/_matchByTitle 消费，此前不在白名单被静默丢弃）：
  //   matchText/matchTitle = 布尔开关（严格 === true 才启用）；
  //   matchCode = true（弱信号：真假状态码不同）或 { true, false } 期望状态码（100-599）；
  //   matchRegexp/trueRegexp/falseRegexp = 正则源文本（500 截断，非法正则引擎侧回落）。
  const matchText = pickBool(cfg, 'matchText');
  if (matchText !== undefined) config.matchText = matchText;
  const matchTitle = pickBool(cfg, 'matchTitle');
  if (matchTitle !== undefined) config.matchTitle = matchTitle;
  if (cfg.matchCode !== undefined && cfg.matchCode !== null) {
    const mc = cfg.matchCode;
    if (mc === true) {
      config.matchCode = true;
    } else if (typeof mc === 'object' && !Array.isArray(mc)) {
      const expected = {};
      const mcTrue = clampInt(mc.true, undefined, 100, 599);
      if (mcTrue !== undefined) expected.true = mcTrue;
      const mcFalse = clampInt(mc.false, undefined, 100, 599);
      if (mcFalse !== undefined) expected.false = mcFalse;
      if (Object.keys(expected).length) config.matchCode = expected;
    }
  }
  const matchRegexp = clampStr(cfg.matchRegexp, undefined, 500);
  if (matchRegexp !== undefined) config.matchRegexp = matchRegexp;
  const trueRegexp = clampStr(cfg.trueRegexp, undefined, 500);
  if (trueRegexp !== undefined) config.trueRegexp = trueRegexp;
  const falseRegexp = clampStr(cfg.falseRegexp, undefined, 500);
  if (falseRegexp !== undefined) config.falseRegexp = falseRegexp;
  // [sqlmap 对标] 动态内容块自动排除 + 提取常见值缓存：此前未透传 → ctx.config 永远缺此字段，
  // 检测器/提取器一律走 null/默认路径，对标能力形同虚设。透传 + 用 defaults 作默认值落地。
  const autoDynamicBlock = pickBool(cfg, 'autoDynamicBlock');
  config.autoDynamicBlock = autoDynamicBlock !== undefined ? autoDynamicBlock : defaults.autoDynamicBlock;
  // [P0-FIX 2026-09-10] 布尔盲注二级判据（组间稳定差异）开关 + 采样数：透传 + 用 defaults 作默认值落地
  const boolStableDiff = pickBool(cfg, 'boolStableDiff');
  config.boolStableDiff = boolStableDiff !== undefined ? boolStableDiff : defaults.boolStableDiff;
  const boolStableDiffSamples = pickInt(cfg, 'boolStableDiffSamples', defaults.boolStableDiffSamples, 2, 4);
  if (boolStableDiffSamples !== undefined) config.boolStableDiffSamples = boolStableDiffSamples;
  const predictOutput = pickBool(cfg, 'predictOutput');
  if (predictOutput !== undefined) config.predictOutput = predictOutput;
  const crawlDepth = pickInt(cfg, 'crawlDepth', defaults.crawlDepth, 0, 3);
  if (crawlDepth !== undefined) config.crawlDepth = crawlDepth;
}
