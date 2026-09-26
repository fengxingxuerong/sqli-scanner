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
import { ErrorCode, AppError } from '../core/errors.js';
import { TECHNIQUE_TYPES } from '../engine/payloads.js';
import { defaults } from '../config/defaults.js';
import { logger } from '../core/logger.js';
import { applyTuningKnobs } from './scanConfigTuning.js';
import { isSafeSessionPath } from '../core/sessionStore.js';
import { filterInScope } from '../core/scopeGuard.js';
import { clampInt, clampNum, boolOf, clampStr, pickInt, pickBool, sanitizeCookieMap } from './scanConfigUtils.js';


// ── 以下两段随守卫一起搬来（原在 scanRoutes.js）：它们只被本文件的配置校验用到 ──
// [CFG-REACH 2026-09-20] --param-del 合法字符集。该值会直接参与请求 URL 的 split/join
// （engine/injection.js:145,155），所以不能只照抄 CLI 的「截到 1 字符」：CLI 的输入是
// 操作者自己打的，REST 的输入来自网络调用方。
// 取「实战确实见到的那几个分隔符」这个窄集合，而不是「排除危险字符」的宽集合——
// 因为要排除的实在太多：# 截断片段、? 与 / 动路径、= 破坏 k=v 切分、& 与默认分隔符歧义、
// % 是百分号编码前缀（拿它当分隔符会和编码值互相打架）、空白与控制符直接非法。
// 窄集合写错只会误拒（调用方看得见 warn），宽集合写错是静默改请求形状 —— 后者贵得多。
const PARAM_DEL_ALLOWED = /^[;,|^~]$/;

// ── [2026-09-23 E2] extractScope（枚举 / 拖库动作族）的形状校验 ──────────────
//
// 为什么补这一支：CLI 侧 `--dbs/--tables/--columns/--dump/--dump-all/--users/...` 一直是
// 「把参数解析成 config.extractScope 交给引擎」（bin/cli/config.js:314 buildExtractScope
// → ScanManager._extractByScope → engine/extractScope.js），而 REST 白名单**从未收录该键**
// → Web / 桌面 / API 三端完全没有枚举与拖库能力：传了会被当「未知字段」静默丢弃（仅一条 warn），
// 调用方拿到 200 + scanId，报告里是一句「未检出」——又一个静默假阴性。
//
// 为什么这里**不做字符集白名单**（与 paramDel / dumpWhere 的处理方式不同）：
//   库名/表名/列名会被**原样拼进 SQL**，但引擎侧所有拼接点都已经过了 `escSql()`
//   （extractionMaps.js 全文一致，形如 `WHERE table_schema='${escSql(db)}'`）。
//   在 REST 层再加一套字符集，只会与引擎的口径并存成两份真相：引擎放宽一次、这里就得跟一次，
//   而且真实的库表名可能含中文/空格/连字符 → 窄集合会**误拒合法输入**。
//   所以此处只校验**形状**：类型、非空、长度、元素数量、无控制字符。
//   （判据与危害同源：这里能造成的危害是「形状不对导致引擎 throw / 无界枚举」，不是注入。）
const EXTRACT_SCOPE_MODES = new Set([
  'dbs', 'tables', 'columns', 'dump', 'dumpAll', 'commonTables', 'commonColumns', 'search',
  'currentDb', 'currentUser', 'hostname', 'isDba', 'users', 'passwords',
  'schema', 'privileges', 'roles', 'count',
]);

/** 字符串数组：去空、去重、拒控制字符、限长、限数量（超限截断而非整体丢弃） */
function sanitizeIdentList(v, maxItems) {
  if (!Array.isArray(v)) return undefined;
  const out = [];
  for (const raw of v) {
    if (typeof raw !== 'string') continue;
    const s = raw.trim();
    if (!s || s.length > 256) continue;
    if (/[\u0000-\u001f\u007f]/.test(s)) continue; // 控制字符：任何合法标识符都不含
    if (!out.includes(s)) out.push(s);
    if (out.length >= maxItems) break;
  }
  return out.length ? out : undefined;
}

/**
 * 校验 /scan/start 的 config.extractScope。返回 undefined = 不启用枚举（保持既有全量行为）。
 * mode 必须在白名单内：它是引擎 switch 的判据，传错会直接 throw（extractScope.js:436）。
 */
export function sanitizeExtractScope(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const mode = typeof raw.mode === 'string' ? raw.mode.trim() : '';
  if (!EXTRACT_SCOPE_MODES.has(mode)) return undefined;
  const out = { mode };
  const dbs = sanitizeIdentList(raw.dbs, 100);
  if (dbs) out.dbs = dbs;
  const tables = sanitizeIdentList(raw.tables, 500);
  if (tables) out.tables = tables;
  const cols = sanitizeIdentList(raw.cols, 500);
  if (cols) out.cols = cols;
  // search 模式的匹配关键字（进 LIKE 模式，已由 escSql 转义）
  if (typeof raw.keyword === 'string') {
    const kw = raw.keyword.trim();
    if (kw && kw.length <= 128 && !/[\u0000-\u001f\u007f]/.test(kw)) out.keyword = kw;
  }
  // 系统库过滤开关：默认 true（与 CLI buildExtractScope 的 ex() 一致）
  if (typeof raw.excludeSysdbs === 'boolean') out.excludeSysdbs = raw.excludeSysdbs;
  return out;
}

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
  // 认证配置透传（httpClient.mergeAuthHeaders 消费：basic/cookie/自定义头）
  // 注：凭据仅在引擎内存/报告/会话中使用，服务端导出侧已脱敏（见 ReportGenerator/ScanManager patch）。
  if (cfg.auth && typeof cfg.auth === 'object') config.auth = cfg.auth;

  if (cfg.techniques) {
    if (!Array.isArray(cfg.techniques) || cfg.techniques.some((tech) => !TECHNIQUE_TYPES.includes(tech))) {
      throw new AppError(ErrorCode.INVALID_PARAM, 'techniques 含非法技术类型');
    }
    config.techniques = cfg.techniques;
  }
  // [P1-FIX 2026-09-08 接线补齐] proxy scheme 与 httpClient.PROXY_SCHEMES 对齐（补 socks4/socks4a）：
  // 原正则只认 https?|socks5?，引擎已支持的 socks4 在 API 层就被拒（功能可达性与实现不一致）。
  if (cfg.proxy) {
    if (typeof cfg.proxy !== 'string' || !/^(?:https?|socks5h?|socks4a?):\/\//i.test(cfg.proxy)) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        'proxy 格式非法（支持 http:// https:// socks5:// socks5h:// socks4:// socks4a://；需强制直连请设 trustProxyEnv=false）'
      );
    }
    config.proxy = cfg.proxy;
  }
  // [P1-FIX 2026-09-08] 出口层三键透传：此前只进了 defaults/env，per-scan config 到不了
  // HttpClient（engine 侧靠 opts 逐层透传），导致 UI 勾了「忽略自签证书」对检测请求无效。
  const insecureTls = pickBool(cfg, 'insecureTls');
  if (insecureTls !== undefined) config.insecureTls = insecureTls;
  const trustProxyEnv = pickBool(cfg, 'trustProxyEnv');
  if (trustProxyEnv !== undefined) config.trustProxyEnv = trustProxyEnv;
  // [P0-FIX 2026-09-09] 生产护栏透传：productionMode 默认 true（按生产环境对待遇），
  // 关掉它（false）是显式脱离护栏——只应出现在靶场/自建演练环境。
  const productionMode = pickBool(cfg, 'productionMode');
  if (productionMode !== undefined) config.productionMode = productionMode;
  const confirmDestructive = pickBool(cfg, 'confirmDestructive');
  if (confirmDestructive !== undefined) config.confirmDestructive = confirmDestructive;
  // [2026-09-23] 报错模板按机制族裁剪：引擎侧按 `config.compactErrorTemplates === true`
  // **严格**判定（ErrorDetector._resolveErrorTemplates），与 hex 同口径 —— 走 pickBool 而不是
  // 通用标量透传，否则 `1`/`"true"` 会被 REST 收下却在引擎侧不生效（白名单有、引擎收不到）。
  const compactErrorTemplates = pickBool(cfg, 'compactErrorTemplates');
  if (compactErrorTemplates !== undefined) config.compactErrorTemplates = compactErrorTemplates;
  // [2026-09-24 接入口] 提取/统计层的 11 个旋钮（引擎一直在读、注释一直写着"可经 config.X
  // 调整"，而 defaults / 本白名单 / CLI / 面板四处都没接）。逐键区间与理由抽到
  // api/scanConfigTuning.js —— 一是让 scanRoutes 回到 arch:guard 的 1200 行预算内
  // （**拆分而不是加进基线**：基线是"承认既有债"，不该用来收自己刚造的债），
  // 二是这批键形状一致（单值严格透传 + 一个带底阈值组），单独成模块能逐键穷举测试。
  // 默认值逐个等于引擎内部兜底 ⇒ 不发等于零行为变化。
  applyTuningKnobs(config, cfg);
  if (typeof cfg.ssrfViaProxy === 'string') {
    const v = cfg.ssrfViaProxy.trim().toLowerCase();
    // [P1-FIX 2026-09-09] 新增 strict-dns：本地能解析就先按严格层判（解不出才下放给代理）。
    // 为什么需要：auto 语义下，内网 DNS 把域名指到 169.254.169.254 时代理解析会照打，
    // 边界完全转移到代理配置上；挂 Burp/企业代理扫内网时至少要有一个选项能把门要回来。
    if (v === 'auto' || v === 'off' || v === 'strict-dns') config.ssrfViaProxy = v;
    else if (v === 'true' || v === '1') config.ssrfViaProxy = 'auto';
    else if (v === 'false' || v === '0') config.ssrfViaProxy = 'off';
    else throw new AppError(ErrorCode.INVALID_PARAM, 'ssrfViaProxy 仅支持 "auto" | "off" | "strict-dns"');
  }
  // [P0-FIX 2026-09-09] proxyBypassLocal：默认 true（本地/私网不吃环境变量代理）；
  // 显式传 false 可恢复「连本地也走代理」的旧行为。
  const proxyBypassLocal = pickBool(cfg, 'proxyBypassLocal');
  if (proxyBypassLocal !== undefined) config.proxyBypassLocal = proxyBypassLocal;
  // [2026-09-24] HTTP 传输形态两键：defaults.js 的注释早在 2026-09-09 就写着
  // 「本键与 http2 此前只存在于 defaults，未进 KNOWN_CFG_KEYS → 已补白名单+透传」，
  // 但白名单里**从来没有它们**（本轮实测：sanitizeStart 对 config.http2 / 
  // config.disableKeepAlive 都不落地，还会回一条「未知字段」warn）。后果不是"不好看"：
  //   · http2 —— crawler.js:169 / TargetParser.js:288 的判据是 `config?.http2 === true`，
  //     收不到就永远走 axios HTTP/1.1，而调用方以为换了协议形态（WAF 侧指纹也不同）；
  //   · disableKeepAlive —— httpClient.js:322 只看构造参数，REST 传了等于没传。
  // CLI 侧这两个键连旋钮都没有 ⇒ 此前没有任何入口能让引擎读到非默认值。
  // 走严格布尔（同 compactErrorTemplates）：`1`/`"true"` 在 REST 收下却不被引擎生效，
  // 是一种更难的查法，不如在入口就拒掉。
  const http2 = pickBool(cfg, 'http2');
  if (http2 !== undefined) config.http2 = http2;
  const disableKeepAlive = pickBool(cfg, 'disableKeepAlive');
  if (disableKeepAlive !== undefined) config.disableKeepAlive = disableKeepAlive;
  // [2026-09-24] xpAutoEnable：**不可逆动作的拒绝位**。Exploiter.js:450 的判据是
  // `ctx.config?.xpAutoEnable !== false`，命中就发
  // `EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE`（实例级永久配置变更，MSSQL 侧
  // 对标 sqlmap 的自动开启行为）。原实现该键在任何入口都不存在 ⇒ 使用者**无法拒绝**
  // 一次改服务器配置的写操作——这与本仓「高危动作必须显式确认」（productionMode /
  // confirmDestructive / secondOrder.allowWrites）的口径不一致。
  // 默认仍为 true（零行为变化，避免把既有 MSSQL 利用链打断了还没人知道），
  // 但从本轮起 `config.xpAutoEnable=false` 真的能把这一步关掉。
  const xpAutoEnable = pickBool(cfg, 'xpAutoEnable');
  if (xpAutoEnable !== undefined) config.xpAutoEnable = xpAutoEnable;
  if (cfg.secondOrder) {
    const so = cfg.secondOrder;
    config.secondOrder = {
      enabled: !!so.enabled,
      // [P0-1 配套] triggerUrls 的 SSRF 校验在路由处理器 async 层执行（见 /scan/start
      // handler：对 sanitized.config.secondOrder.triggerUrls 逐个 assertSafeHttpTarget），
      // 此处仅做协议白名单过滤（同步函数不能 await）。
      triggerUrls: Array.isArray(so.triggerUrls)
        ? so.triggerUrls.filter((x) => typeof x === 'string' && /^https?:\/\//i.test(x))
        : [],
      refreshCsrf: so.refreshCsrf !== false,
      // [P0-FIX 2026-09-09] 二阶写请求确认位：productionMode=true 时，非幂等 method
      // （POST/PUT/PATCH/DELETE）与触发页写请求必须 allowWrites===true 才放行。
      // 实战后果：二阶检测天然要「写一次」才能触发存储型路径，而对 /order/create 这类
      // GET 写端点，“只读复核”的说法从一开始就不成立——必须把“我在写”这件事显式开关化。
      allowWrites: so.allowWrites === true,
      triggerMethod: typeof so.triggerMethod === 'string'
        ? so.triggerMethod.slice(0, 16)
        : defaults.secondOrder.triggerMethod,
      negativeControl: so.negativeControl !== false,
      oobTrigger: !!so.oobTrigger,
      // [P0-REACH 2026-09-23] 读写分离二阶注入（对标 sqlmap --second-url/--second-method/--second-data）：
      // 引擎在 SecondOrderDetector._trigger 里**真读**这三个字段（`so.secondUrl || url`、
      // resolveSecondOrderMethod(so.secondMethod, …)、`so.secondData`），但本 clamp 此前不保留它们、
      // CLI 也没有可设入口 → 该能力**三条路径全不可达**（CLI 不能设 / REST 传了被丢弃 / UI 更无入口）。
      // 与 extractScope 那次是同一病灶：能力在，入口不在，而报告只会写「未检出」。
      // ⚠️ 形状只做协议白名单 + 长度上限；**SSRF/授权范围校验在路由 handler 的 async 层**执行
      // （与 triggerUrls 同一条链，见下方 secondUrl 校验段）—— 不能在这里放行未校验的 URL。
      // 方法白名单刻意不在此重复：单一真相在引擎的 resolveSecondOrderMethod（含幂等门）。
      // 未传时回落 defaults 而非 undefined：浅合并下 undefined 会让「引擎读到 undefined」
      // 与「用户没配」在现场无法区分，报告/审计取 config.secondOrder.secondMethod 时也是空的。
      secondUrl: typeof so.secondUrl === 'string' && /^https?:\/\//i.test(so.secondUrl)
        ? so.secondUrl.slice(0, 2048)
        : defaults.secondOrder.secondUrl,
      secondMethod: typeof so.secondMethod === 'string'
        ? so.secondMethod.slice(0, 16)
        : defaults.secondOrder.secondMethod,
      secondData: typeof so.secondData === 'string'
        ? so.secondData.slice(0, 8192)
        : (so.secondData && typeof so.secondData === 'object' ? so.secondData : defaults.secondOrder.secondData),
      // [todo#39 2026-09-11] 跨角色触发（读写分离身份）：存储与触发页可分属不同会话身份
      // （低权账号写入、高权账号读出是存储型注入的实战高发形态）。键值均须为字符串，
      // 过滤 __proto__/constructor/prototype 等危险键（对象字面量展开会沿原型链污染）。
      storeCookies: sanitizeCookieMap(so.storeCookies),
      triggerCookies: sanitizeCookieMap(so.triggerCookies),
    };
  }
  if (cfg.wafEvasion && typeof cfg.wafEvasion === 'object') {
    const we = cfg.wafEvasion;
    // [2026-09-24] 必须**带底重建**（对照下面的 oob 分支）：models.js:113 的 config 合并是
    // 浅合并（{...defaults, ...input.config}），wafEvasion 一旦整体替换，未转发的子键就成了
    // undefined。而引擎侧 filterAdaptive 的判据是 `=== true`（defaults.js 里默认开、且实测
    // 把关键词过滤靶场从 [error] 提到 [error,boolean]）—— 于是「只带 tamper 的请求」
    // （UI 的 tamper 编辑器、CLI 的 --tamper 都发这种）会**静默关掉自适应过滤重跑**：
    // 扫描照常跑完、照常报绿，只是少了一整轮绕过。实测 sanitizeStart 旧写法对
    // {wafEvasion:{tamper:{...}}} 只转发回 tamper 一个键，9 个子键丢 8 个。
    const waf = { ...defaults.wafEvasion };
    const randomUA = pickBool(we, 'randomUA');
    if (randomUA !== undefined) waf.randomUA = randomUA;
    const obfuscate = pickBool(we, 'obfuscate');
    if (obfuscate !== undefined) waf.obfuscate = obfuscate;
    const jitterMs = pickInt(we, 'jitterMs', defaults.wafEvasion.jitterMs, 0, 5000);
    if (jitterMs !== undefined) waf.jitterMs = jitterMs;
    // 其余四个布尔位：引擎判据有 `=== true` 与 `!== false` 两种，两种都要求键**存在**
    // 才是用户真正表达的意图，故逐个显式转发（非法/未传则保持 defaults）。
    for (const k of ['adaptiveOnBlock', 'bypassSearch', 'filterAdaptive', 'autoRetry', 'channelDegrade']) {
      const v = pickBool(we, k);
      if (v !== undefined) waf[k] = v;
    }
    if (we.tamper && typeof we.tamper === 'object') {
      const t = we.tamper;
      const intensity = ['low', 'medium', 'high'].includes(t.intensity) ? t.intensity : defaults.wafEvasion.tamper.intensity;
      const plugins = Array.isArray(t.plugins) ? t.plugins.filter((p) => typeof p === 'string') : defaults.wafEvasion.tamper.plugins;
      waf.tamper = { ...defaults.wafEvasion.tamper, enabled: !!t.enabled, plugins, intensity };
    }
    config.wafEvasion = { ...config.wafEvasion, ...waf };
  }
  if (cfg.oob && typeof cfg.oob === 'object') {
    const o = cfg.oob;
    config.oob = {
      enabled: !!o.enabled,
      callbackBase: typeof o.callbackBase === 'string' ? o.callbackBase : defaults.oob.callbackBase,
      httpPort: clampInt(o.httpPort, defaults.oob.httpPort, 1, 65535),
      timeoutMs: clampInt(o.timeoutMs, defaults.oob.timeoutMs, 1000, 60000),
      // [B-perf] DNS OOB 接收端参数（oobReceiver._startDns 消费 cfg.dnsPort / cfg.dnsDomain，
      // 此前不在白名单被丢弃，REST 层只能靠环境变量 DNS_PORT/DNS_DOMAIN 兜底）。
      // dnsDomain 截断到 253（RFC 域名长度上限）；dnsPort clamp 到 [1,65535]。
      // [主代理收尾] dnsOob 开关透传：OobDetector DNS 轮消费（生成 <token>.<dnsDomain> 触发查询）。
      dnsOob: !!o.dnsOob,
      dnsDomain: typeof o.dnsDomain === 'string' ? o.dnsDomain.slice(0, 253) : defaults.oob.dnsDomain,
      dnsPort: clampInt(o.dnsPort, defaults.oob.dnsPort, 1, 65535),
    };
  }
  if (cfg.noSql && typeof cfg.noSql === 'object') {
    const ns = cfg.noSql;
    config.noSql = {
      enabled: !!ns.enabled,
      kinds: Array.isArray(ns.kinds)
        ? ns.kinds.filter((k) => typeof k === 'string' && ['nosql', 'graphql', 'ssti'].includes(k))
        : defaults.noSql.kinds,
      // [2026-09-24] 本组此前整键漏转发 concurrency：ScanManager.js:633 读
      // `Number(noSql.concurrency) || 2`，而 sanitizeStart 只重建 {enabled, kinds} ⇒
      // 传 concurrency:8 静默回到 2（非 SQL 补充趟的并发上不去，大点集扫描白等）。
      concurrency: clampInt(ns.concurrency, defaults.noSql.concurrency, 1, 16),
    };
  }
  if (cfg.blindRobust && typeof cfg.blindRobust === 'object') {
    const br = cfg.blindRobust;
    const d = defaults.blindRobust;
    config.blindRobust = {
      enabled: boolOf(br.enabled, d.enabled),
      booleanSamples: clampInt(br.booleanSamples, d.booleanSamples, 1, 10),
      baselineSamples: clampInt(br.baselineSamples, d.baselineSamples, 1, 20),
      timeConfidenceZ: clampNum(br.timeConfidenceZ, d.timeConfidenceZ, 1, 5),
      minStableRatio: clampNum(br.minStableRatio, d.minStableRatio, 0.5, 1),
      booleanSignificanceZ: clampNum(br.booleanSignificanceZ, d.booleanSignificanceZ, 1, 5),
      adaptive: boolOf(br.adaptive, d.adaptive),
      adaptiveHeadroom: clampNum(br.adaptiveHeadroom, d.adaptiveHeadroom, 0, 1),
      // [P0-FIX 2026-09-08] 统计判定的「关掉护栏」下限：原 clamp 允许 floor=0 / z=0，
      // 而 adaptive=true 时门槛 = clamp(噪声 + headroom, floor, cap)，floor=0 会把噪声目标的
      // 一致率门槛拉到 0 → 任何抖动都算「稳定」；booleanSignificanceZ=0 则「false 组与基线
      // 完全相同也判阳」——两个都是误报放大器。盲注误报的代价（往报告里写假漏洞）远大于漏报，
      // 故给硬下限：一致率门槛不低于 0.5、显著性 z 不低于 1.0（单侧≈84% 置信）。
      minStableRatioFloor: clampNum(br.minStableRatioFloor, d.minStableRatioFloor, 0.5, 1),
      minStableRatioCap: clampNum(br.minStableRatioCap, d.minStableRatioCap, 0.5, 1),
      adaptiveTimeFloorScale: clampNum(br.adaptiveTimeFloorScale, d.adaptiveTimeFloorScale, 0, 10),
      concurrency: clampInt(br.concurrency, d.concurrency, 1, 16),
      // [2026-09-24] 本组此前**整键漏转发**：blindExtractor 读 `config.blindRobust.extractVerify`
      // （`!== false` 判据），而 defaults.blindRobust 有 13 键、这里只重建 12 键 ——
      // 于是带 blindRobust 的请求会把 defaults 里的 `extractVerify: true` 替换成 undefined，
      // 表面上"看起来还是 true"（undefined !== false 为真），实际后果是**关不掉**：
      // 调用方显式传 `extractVerify:false` 被丢弃，提取阶段的逐字节等值验证 + 整体投票复验
      // （每字符 1 次 + 收尾 1 次请求）照跑不误。CLI/面板都没有这个旋钮 ⇒ REST 是**唯一**入口，
      // 而这个唯一入口是断的。
      extractVerify: boolOf(br.extractVerify, d.extractVerify),
    };
  }
  // sessionFile 白名单（原逻辑不变）
  if (cfg.sessionFile !== undefined && cfg.sessionFile !== null && cfg.sessionFile !== '') {
    if (!isSafeSessionPath(cfg.sessionFile)) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        'sessionFile 非法：仅允许工作目录下的文件名或系统临时目录内路径，拒绝绝对路径/..逃逸'
      );
    }
    config.sessionFile = cfg.sessionFile;
  }
  const sessionDefault = pickBool(cfg, 'sessionDefault');
  if (sessionDefault !== undefined) config.sessionDefault = sessionDefault;
  // [对标 sqlmap --dbms] 强制指定 DBMS：白名单校验 + 透传（scanRunner 消费跳过指纹）
  if (cfg.dbms !== undefined && cfg.dbms !== null && String(cfg.dbms).trim() !== '') {
    config.dbms = clampStr(String(cfg.dbms).trim(), '', 64);
  }

  // [P1-FIX 2026-09-05] Cookie Jar 开关：cookieJar 默认开（undefined 不写入，引擎默认 true）；
  // dropSetCookie=true 对标 sqlmap --drop-set-cookie（请求不吸收服务端 Set-Cookie）
  const cookieJarFlag = pickBool(cfg, 'cookieJar');
  if (cookieJarFlag !== undefined) config.cookieJar = cookieJarFlag;
  const dropSetCookieFlag = pickBool(cfg, 'dropSetCookie');
  if (dropSetCookieFlag !== undefined) config.dropSetCookie = dropSetCookieFlag;
  // [G4 对标 sqlmap --parse-errors] 错误响应原文/上下文进证据链（opt-in，默认 false）
  const parseErrorsFlag = pickBool(cfg, 'parseErrors');
  if (parseErrorsFlag !== undefined) config.parseErrors = parseErrorsFlag;

  // [P0 2026-09-09 实战批次] 失效值替换（对标 sqlmap --invalid-*）：仅接受三种合法模式，
  // 非法值静默丢弃（引擎侧 invalidValue.js 同样对非法模式零行为变化，双保险）。
  if (cfg.invalidValue !== undefined && cfg.invalidValue !== null) {
    const m = String(cfg.invalidValue).trim().toLowerCase();
    if (['bignum', 'logical', 'string'].includes(m)) config.invalidValue = m;
  }
  // [P0 2026-09-09 实战批次] 已知注入点直通：{ param 必填, quote?, paren?, techniques? }。
  // quote/paren 为闭合形态原文（如 quote="'" paren="))"），techniques 为技术位白名单。
  if (cfg.knownPoint !== undefined && cfg.knownPoint !== null && typeof cfg.knownPoint === 'object') {
    const kp = cfg.knownPoint;
    const out = {};
    if (kp.param != null && String(kp.param).trim() !== '') out.param = String(kp.param).trim().slice(0, 256);
    if (kp.quote != null) out.quote = String(kp.quote).slice(0, 16);
    if (kp.paren != null) out.paren = String(kp.paren).slice(0, 16);
    if (Array.isArray(kp.techniques) && kp.techniques.length) {
      const TECHS_OK = ['union', 'error', 'boolean', 'time', 'stacked', 'oob', 'inline', 'second_order'];
      const techs = kp.techniques.map(String).filter((t) => TECHS_OK.includes(t));
      if (techs.length) out.techniques = [...new Set(techs)];
    }
    if (out.param) config.knownPoint = out;
  }

  // ── [2026-09-23 E2] 枚举 / 拖库动作族（对标 sqlmap --dbs/--tables/--dump-all/--users/…）──
  // 校验器见 sanitizeExtractScope（含「为何不做字符集白名单」的口径说明）。
  // 非法/形状不对时**丢弃并 warn**，而不是抛错：与其它配置键口径一致（配置片段不该让整次扫描失败），
  // 但必须喊出来——静默丢弃正是本仓库反复踩的那类假阴性。
  if ('extractScope' in cfg) {
    const scope = sanitizeExtractScope(cfg.extractScope);
    if (scope) config.extractScope = scope;
    else {
      logger.warn(
        `extractScope 形状非法已丢弃（不会执行任何枚举/拖库）：${JSON.stringify(cfg.extractScope).slice(0, 200)}` +
        `（mode 需为 ${[...EXTRACT_SCOPE_MODES].join('|')} 之一）`
      );
    }
  }

  // ── [CFG-REACH 2026-09-20] 两个不能走「通用标量透传」的键，各自需要真校验 ──
  // unionCols：引擎按 Number() 用（UnionDetector.js:119）并当作「固定列数」直接喂进二分。
  // 通用透传会把 "abc" 原样带下去 → NaN 参与列数判定；"99999" 则会以固定列数名义
  // 构造超宽 UNION。这里收敛成 1..200 的整数，非法值丢弃并说明（不静默）。
  if ('unionCols' in cfg) {
    const n = Number(String(cfg.unionCols).trim());
    if (Number.isInteger(n) && n >= 1 && n <= 200) config.unionCols = String(n);
    else logger.warn(`unionCols ${JSON.stringify(cfg.unionCols)} 非 1..200 整数，已丢弃（保留自动列数二分）`);
  }
  // paramDel：见 PARAM_DEL_ALLOWED 注释——该值会进请求 URL，必须单字符 + 白名单。
  if ('paramDel' in cfg) {
    const d = String(cfg.paramDel ?? '');
    if (d.length === 1 && PARAM_DEL_ALLOWED.test(d)) config.paramDel = d;
    else if (d !== '') logger.warn(`paramDel ${JSON.stringify(d)} 需为 ; , | ^ ~ 中的单个字符，已丢弃`);
  }
  // dumpWhere：extractScope 把它原样拼进提取 SQL 的 WHERE 位（extractScope.js:160,219）。
  // 拒分号是因为分号是把「一个条件」变成「第二条语句」的那一步（堆叠查询）——本键只在
  // 已确认注入点之后用于收窄导出范围，没有任何合法场景需要带分号，所以这不是取舍是净收益。
  // 长度与 CLI 的 clampStr 同档（2000），空串按「不配置」处理（与其它字符串键口径一致）。
  if ('dumpWhere' in cfg) {
    const w = String(cfg.dumpWhere ?? '').trim();
    if (!w) {
      // 空 = 显式不配，与 defaults 语义一致，不告警
    } else if (w.includes(';')) {
      logger.warn('dumpWhere 含分号（堆叠查询形态），已丢弃该配置');
    } else {
      config.dumpWhere = w.slice(0, 2000);
    }
  }
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
  return config;
}
