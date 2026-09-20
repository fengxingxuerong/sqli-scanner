// ============================================================================
// scanRoutes.js —— 扫描 API 路由
// 功能：
//   sanitizeStart 目标 URL SSRF 校验 + method 白名单 + headerParams/bodyParams/cookieParams 校验
//   ratePerSec clamp + 报告守卫 token 恒时比较 + requireReport 挂在所有 :id 端点
//   /scan/:id/report/export 导出 JSON/HTML/CSV/Markdown
//   直连模式（-d）+ 枚举模式（extractScope）+ AI 报告
// ============================================================================

import { Router } from 'express';
import crypto from 'node:crypto';
import { ScanManager } from '../engine/ScanManager.js';
import * as eventBus from '../core/eventBus.js';
import { ErrorCode, AppError } from '../core/errors.js';
import { PAYLOADS, FINGERPRINT, TECHNIQUE_TYPES } from '../engine/payloads.js';
import { defaults } from '../config/defaults.js';
import { logger } from '../core/logger.js';
import { isSafeSessionPath } from '../core/sessionStore.js';
import { assertSafeHttpTarget } from '../core/httpClient.js';
// [交付场景] 两次扫描差异对比（纯函数，便于单测；见 tests/scanDiff.test.js）
import { diffReports } from '../engine/scanDiff.js';
// [P0-SEC 2026-09-08] 授权范围（scope）硬约束 + 逐跳登记
import { parseScope, assertInScope, filterInScope, registerScanScope, releaseScanScope } from '../core/scopeGuard.js';

// ── 配置白名单 clamp 工具（原逻辑不变）──
const clampInt = (v, def, min, max) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(Math.min(max, Math.max(min, n))) : def;
};
const clampNum = (v, def, min, max) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def;
};
const boolOf = (v, def = false) => (v === undefined || v === null ? def : !!v);
const clampStr = (v, def, maxLen) => {
  if (v === undefined || v === null) return undefined;
  const s = String(v);
  if (s === '') return undefined;
  return s.length > maxLen ? s.slice(0, maxLen) : s;
};
const pickInt = (cfg, key, def, min, max) => {
  const v = cfg[key];
  return v === undefined || v === null ? undefined : clampInt(v, def, min, max);
};
const pickBool = (cfg, key) => {
  const v = cfg[key];
  return v === undefined || v === null ? undefined : boolOf(v);
};
// [todo#39 2026-09-11] 二阶跨角色触发：Cookie 映射消毒（storeCookies/triggerCookies 共用）。
// 仅保留字符串键值对；过滤原型污染键（__proto__/constructor/prototype）；上限 32 键防滥用。
const sanitizeCookieMap = (v) => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return undefined;
  const out = {};
  let n = 0;
  for (const [k, val] of Object.entries(v)) {
    if (n >= 32) break;
    if (typeof k !== 'string' || typeof val !== 'string') continue;
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (!k.trim() || k.length > 256 || val.length > 4096) continue;
    out[k] = val;
    n++;
  }
  return n ? out : undefined;
};

// 白名单字段全集（原逻辑不变）
const KNOWN_CFG_KEYS = new Set([
  'ratePerSec', 'concurrency', 'retry', 'timeoutMs', 'timeThresholdMs', 'enableExtract',
  'extractConcurrency', 'dumpMaxRows', 'timeBlindSamples', 'maxColumnsGuess', 'dumpRowLimit',
  'dumpConcurrency', 'dumpDatabaseConcurrency', 'crawlForms', 'crawlDepth', 'auth', 'proxy', 'techniques',
  // [sqlmap 对标] 行范围导出 + 保活探测（--start/--stop/--safe-url/--safe-freq）
  'dumpStart', 'dumpStop', 'safeUrl', 'safeFreq',
  // [sqlmap 对标 2026-09-14] --csrf-url/--csrf-token/--csrf-method（CSRF 会话层）
  'csrfUrl', 'csrfTokenName', 'csrfMethod', 'csrfRefreshFreq',
  'skipParams',
  'secondOrder', 'wafEvasion', 'oob', 'noSql', 'blindRobust', 'sessionFile',
  // [P0-FIX 2026-09-10] 布尔盲注二级判据：组间稳定差异（boolStableDiff 总开关 + 采样数）
  'boolStableDiff', 'boolStableDiffSamples',
  'sessionDefault',
  'level', 'risk', 'prefix', 'suffix',
  // [对标 sqlmap --dbms] 强制指定 DBMS（scanRunner 消费：跳过指纹直接按指定库检测）
  'dbms',
  // [B-perf] skip-static 参数预筛选 / 响应相似度锚点（--string/--not-string）
  'skipStatic', 'matchString', 'notString',
  // [perf-FIX 2026-09-07] 单点目标 opt-in 预筛选（--prefilter-single-point）
  'prefilterSinglePoint',
  // [P0 2026-09-09 实战批次] 失效值替换（--invalid-bignum/--invalid-logical/--invalid-string）
  // + 已知注入点直通（手工确认的可注入参数跳过预筛选/闭合探测）
  'invalidValue', 'knownPoint',
  // [P1 批次 2026-09-08] 白名单漂移补齐（configWhitelist.guard.test 守卫检出）：
  // 以下键均为引擎实际消费的用户扫描配置（defaults.js 顶层），此前不在白名单导致
  // REST 传入被静默忽略（配置语义漂移）。
  'prefilter', // 参数预筛选总开关（scanRunner 消费）
  'testFilter', 'testSkip', 'useRegistry', // 声明式注册表筛选（payloadRegistry 消费）
  'excludeSysdbs', 'nullConnection', // --exclude-sysdbs / --null-connection
  // [P0-SEC 2026-09-08] 授权范围硬约束（数组或逗号串，条目形如 example.com / *.example.com /
  // 10.0.0.0/8 / https://a.example.com/portal）；非空即强制，越界直接拒绝启动。
  'scope',
  // [P1-FIX 2026-09-08 实战批次] HTTP 层实战能力：自签证书目标 / 环境变量代理 / 代理下目标校验下放
  'insecureTls', 'trustProxyEnv', 'ssrfViaProxy',
  // [P0-FIX 2026-09-09] 本地/私网目标绕过环境变量代理（默认 true）
  'proxyBypassLocal',
  // [P1-PERF 2026-09-08] 输入校验型目标的可证安全跳过开关 + PoC 凭据脱敏开关
  'validationSkip', 'pocRedactAuth',
  // [P0-FIX 2026-09-09] 生产护栏：高危池（RCE/写文件/DoS 类）投放必须显式确认。
  // 这两个键必须可达 REST：否则「引擎实现了、API 收不到」会重演——使用者以为 risk=3 就真能控住风险。
  'productionMode', 'confirmDestructive',
  'delay', 'reqRate', 'maxReq', // --delay/--reqrate/--max-requests 限速治理
  'forceSsl', 'ignoreRedirects', // HTTPS 强制 / 重定向跟随开关
  'hpp', 'activeWafProbe', // HTTP 参数污染 / WAF 主动探测（opt-in）
  // [主代理收尾] 盲注响应匹配多指标（--text-only/--code/--regexp/--titles）
  'matchText', 'matchCode', 'matchRegexp', 'trueRegexp', 'falseRegexp', 'matchTitle',
  // [sqlmap 对标] 动态内容块自动排除（对标 sqlmap 默认动态内容感知）
  'autoDynamicBlock', 'predictOutput',
  // [T4 标定] 时间盲注自适应标定（--time-sec 自适应）+ 探测/提取 sleep 参数化
  'timeBlindCalibrate', 'timeBlindCalibrateMin',
  'timeBlindSleepSec', 'timeProbeSleepSec', 'timeExtractSleepSec',
  // [P1-FIX 2026-09-05] Cookie Jar（自动会话保持）+ --drop-set-cookie 对标
  'cookieJar', 'dropSetCookie',
  // [G4 对标 sqlmap --parse-errors] 错误响应原文/上下文进证据链（opt-in boolean）
  'parseErrors',
  // [P1-FIX 2026-09-09] freshQueries：面板（SqlmapOptions）有开关、scanRunner 也读 cfg.freshQueries，
  // 但白名单里没有这个键 → 勾了等于没勾（本批前端契约测试抱出来的活例）。
  'freshQueries',
  // [CFG-REACH 2026-09-20] 一批「CLI 能设、引擎真读、REST 收不到」的键。判据不是 grep 猜测，
  // 而是把两端交叉：CLI 往 config 上写的键 ∩ engine 用 config.X / ctx.config?.X 读的键，
  // 再减去 KNOWN_CFG_KEYS —— 第一轮剩下这 9 个。后果与普通 bug 不同：调用方传了 testPath=true
  // 会得到 200 + 一个正常 scanId，只是引擎**根本没开路径注入点探测**，报告写「未检出」。
  // 那是管道造成的假阴性，而假阴性对扫描器是最贵的一类错。
  // 由 server/tests/configReachability.guard.test.js 逐键真调 sanitizeStart 钉住（含反向：
  // 以后再加 CLI 可设键忘了进白名单，测试当场红，不必再靠人一轮轮手工补）。
  'testPath', 'testHeaders', // --test-path / --test-headers（TargetParser 消费）
  'noCast', 'flushSession', // --no-cast（DBFingerprinter/Extractor）/ --flush-session（sqlmapBridge）
  'dumpWhere', // --where：提取阶段的 WHERE 片段（extractScope 消费；会拼进 SQL，故下方拒分号）
  'unionCols', // --union-cols：固定列数、跳过 ORDER BY 二分（UnionDetector 消费）
  'paramDel', // --param-del：自定义参数分隔符（injection/TargetParser 消费，会进 URL，故下方强校验）
  // hex / unionFrom 是这支守卫测试第一次跑就自己抱出来的——我先前手工 triage 时把 `hex`
  // 当成 grep 噪声丢了（`hex` 这个词在 server/src 有上百处无关命中）。教训：判据要能跑，
  // 不能靠人眼看 grep。unionFrom 无需在此再加校验——引擎侧 resolveFromClause 已经过
  // sanitizeUnionFrom（仅 [A-Za-z0-9_ .$] 与括号），REST 再校一遍只会多一处会漂移的口径。
  'hex', // --hex：字符常量十六进制化（Extractor.searchColumnData → buildLikePattern）
  'unionFrom', // --union-from：强制 UNION FROM 子句（blindExtractor/Extractor/injection 四处消费）
]);

// [CFG-REACH 2026-09-20] --param-del 合法字符集。该值会直接参与请求 URL 的 split/join
// （engine/injection.js:145,155），所以不能只照抄 CLI 的「截到 1 字符」：CLI 的输入是
// 操作者自己打的，REST 的输入来自网络调用方。
// 取「实战确实见到的那几个分隔符」这个窄集合，而不是「排除危险字符」的宽集合——
// 因为要排除的实在太多：# 截断片段、? 与 / 动路径、= 破坏 k=v 切分、& 与默认分隔符歧义、
// % 是百分号编码前缀（拿它当分隔符会和编码值互相打架）、空白与控制符直接非法。
// 窄集合写错只会误拒（调用方看得见 warn），宽集合写错是静默改请求形状 —— 后者贵得多。
const PARAM_DEL_ALLOWED = /^[;,|^~]$/;

// 禁止由调用者覆写的头名（P2-8，与 httpClient 侧 FORBIDDEN_HEADERS 保持一致）
const FORBIDDEN_HEADER_NAMES = new Set([
  'host', 'content-length', 'transfer-encoding', 'connection', 'upgrade',
  'proxy-connection', 'keep-alive', 'te', 'trailer', 'expect',
]);

// 校验并收敛 /scan/start 入参，防止非法目标 / 越界配置进入引擎。
// 兼容两种入参形态（原逻辑），新增：headerParams 头名过滤。
// 注意：保持同步函数（测试契约同步调用）；SSRF 校验在路由处理器 async 层执行
// （见 /scan/start handler 中的 assertSafeHttpTarget 调用）。
export function sanitizeStart(body) {
  const b = body || {};
  const cfg = b.config || {};

  // ── 直连模式（对标 sqlmap -d）：不走 HTTP，直接连库执行 SQL 模板 ──
  // 原实现 sanitizeStart 只认 http:// 目标，mode/db/connectionString 全被丢弃 → 直连能力
  // 在 API 层不可达（DirectConnector/getDriver 是死代码）。此处放行并做最小校验：
  //   mode='direct'（或携带 db/connectionString）→ 必须提供 db 连接信息 + 含 {INJECT} 的 sqlTemplate。
  const isDirect = b.mode === 'direct' || !!(b.db || b.connectionString);
  if (isDirect) {
    if (!b.db && !b.connectionString) {
      throw new AppError(ErrorCode.INVALID_TARGET, '直连模式需要提供 db 连接信息或 connectionString');
    }
    if (!b.sqlTemplate || !String(b.sqlTemplate).includes('{INJECT}')) {
      throw new AppError(ErrorCode.INVALID_TARGET, '直连模式需要提供含 {INJECT} 注入标记的 sqlTemplate');
    }
    return {
      mode: 'direct',
      db: b.db || {
        connectionString: String(b.connectionString),
        driverType: String(b.driverType || 'memory'),
      },
      sqlTemplate: b.sqlTemplate,
      originalValue: b.originalValue != null ? String(b.originalValue) : '1',
      config: { ...defaults, ...(cfg || {}) },
    };
  }

  const src = b.target && typeof b.target === 'object' ? b.target : b;
  const rawUrl = typeof src.url === 'string' ? src.url : '';
  if (!rawUrl.trim()) {
    throw new AppError(ErrorCode.INVALID_PARAM, '缺少目标 URL');
  }
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new AppError(ErrorCode.INVALID_PARAM, '目标 URL 格式非法');
  }
  if (!/^https?:$/i.test(u.protocol)) {
    throw new AppError(ErrorCode.INVALID_PARAM, '仅支持 http/https 目标');
  }

  // [P0-SEC 2026-09-08] 授权范围（scope）硬约束——渗透作战第一红线：
  //   SSRF 防护管的是「别打自己人」，scope 管的是「别打没授权的人」。真实事故往往是手滑把同 C 段
  //   的预发系统 / 第三方 SaaS（支付、短信网关、客服）当授权目标打了进去。配置了就是硬约束
  //   （不提供「只告警」模式——告警模式等于没有）；未配置时行为与历史一致。
  //   重定向跳的校验由 HttpClient 按 scanId 登记的 scope 执行（见 scopeGuard.registerScanScope）。
  const scopeRules = parseScope(cfg.scope);
  if (scopeRules.enabled) assertInScope(u.toString(), scopeRules);

  const config = {};
  // scope 原文进 config（可序列化：数组形态），供路由层登记与 HttpClient 逐跳重定向校验复用
  if (scopeRules.enabled) config.scope = scopeRules.raw;

  // —— 网络/调度 ——
  // [REVERTED P2-3] ratePerSec 保持原样透传（不 clamp）：既有测试契约
  // 「ratePerSec 不再 clamp：原样透传（P0-P1③）」。限速治理由 httpClient/defaults 负责。
  if (cfg.ratePerSec !== undefined && cfg.ratePerSec !== null) config.ratePerSec = cfg.ratePerSec;
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
      triggerMethod: so.triggerMethod,
      negativeControl: so.negativeControl !== false,
      oobTrigger: !!so.oobTrigger,
      // [todo#39 2026-09-11] 跨角色触发（读写分离身份）：存储与触发页可分属不同会话身份
      // （低权账号写入、高权账号读出是存储型注入的实战高发形态）。键值均须为字符串，
      // 过滤 __proto__/constructor/prototype 等危险键（对象字面量展开会沿原型链污染）。
      storeCookies: sanitizeCookieMap(so.storeCookies),
      triggerCookies: sanitizeCookieMap(so.triggerCookies),
    };
  }
  if (cfg.wafEvasion && typeof cfg.wafEvasion === 'object') {
    const we = cfg.wafEvasion;
    const waf = {};
    const randomUA = pickBool(we, 'randomUA');
    if (randomUA !== undefined) waf.randomUA = randomUA;
    const obfuscate = pickBool(we, 'obfuscate');
    if (obfuscate !== undefined) waf.obfuscate = obfuscate;
    const jitterMs = pickInt(we, 'jitterMs', defaults.wafEvasion.jitterMs, 0, 5000);
    if (jitterMs !== undefined) waf.jitterMs = jitterMs;
    if (we.tamper && typeof we.tamper === 'object') {
      const t = we.tamper;
      const intensity = ['low', 'medium', 'high'].includes(t.intensity) ? t.intensity : 'medium';
      const plugins = Array.isArray(t.plugins) ? t.plugins.filter((p) => typeof p === 'string') : [];
      waf.tamper = { enabled: !!t.enabled, plugins, intensity };
    }
    if (Object.keys(waf).length) config.wafEvasion = { ...config.wafEvasion, ...waf };
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
        : [],
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
  // hex / flushSession：必须是**真布尔**。
  // 通用标量透传会把 1 / "true" / {} 这类 truthy 值原样收下，而引擎按 `config.hex === true`
  // 判定（Extractor.js:618,697）—— 结果就是"API 收了、引擎不生效"，与本批要消灭的
  // 「白名单有、透传没有」是同一个 bug 形状，只是换了触发条件。宁可拒掉并说明。
  for (const boolKey of ['hex', 'flushSession']) {
    if (!(boolKey in cfg)) continue;
    const v = cfg[boolKey];
    if (typeof v === 'boolean') config[boolKey] = v;
    else logger.warn(`${boolKey} 需为布尔值（收到 ${JSON.stringify(v)}），已丢弃——该开关按严格 true 判定，传 truthy 非布尔值不会生效`);
  }

  // 未知字段：忽略，但**必须喊出来**（原来是 debug 级，默认 info 日志下等于静默）。
  // [CFG-REACH 2026-09-20] 为什么从 debug 提到 warn：本函数的返回 config 只由白名单键构成，
  // 所以「传了未知键」= 「你以为设置了的开关根本没进引擎」。调用方拿到的是 200 + scanId，
  // 报告里是一句「未检出」——静默丢弃把一个配置笔误变成了看起来完全正常的假阴性。
  // 这正是本仓库反复手工补过的坑（注释里已有 6 处「此前不在白名单被静默丢弃」）。
  // 前端不会因此刷屏：它发的是 SCAN_CONFIG_KEYS 推导出来的键集，实测不含未知键。
  const ignored = Object.keys(cfg).filter((k) => !KNOWN_CFG_KEYS.has(k));
  if (ignored.length) {
    logger.warn(
      `扫描配置含 ${ignored.length} 个未知字段，已忽略（这些设置**不会生效**，请核对键名或改用 CLI）：${ignored.join(', ')}`
    );
  }

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
  const method = (src.method || 'GET').toUpperCase();
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    throw new AppError(ErrorCode.INVALID_PARAM, `不支持的请求方法：${method}`);
  }
  // [P2-8] headerParams 头名黑名单过滤：禁止调用者覆写 Host/Content-Length 等，
  // 防止对目标发起请求走私式探测 / 虚拟主机绕过。
  const headerParams = { ...(src.headerParams || {}) };
  for (const key of Object.keys(headerParams)) {
    if (FORBIDDEN_HEADER_NAMES.has(String(key).toLowerCase())) {
      logger.warn(`headerParams 忽略禁止覆写的头：${key}`);
      delete headerParams[key];
    }
  }
  // [P1 批次 2026-09-08] JSON body 注入通道透传：JSON 对象（POST application/json 目标）。
  // 安全校验：仅接受纯 JSON 对象（无函数/undefined 等非法值——REST 入参经 JSON 解析天然满足）；
  // 体积限制与 clampParams 同级（序列化后 10KB），防超大 JSON body 注入 DoS。
  // null/undefined/非对象 → null（不启用 JSON 语义，走 bodyParams 表单）。
  let jsonBody = null;
  if (src.jsonBody != null && typeof src.jsonBody === 'object' && !Array.isArray(src.jsonBody)) {
    try {
      const s = JSON.stringify(src.jsonBody);
      if (s && s.length <= 10000) jsonBody = JSON.parse(s);
      else logger.warn('jsonBody 序列化超 10KB 上限，忽略（防超大 body DoS）');
    } catch {
      logger.warn('jsonBody 非法 JSON 对象，忽略');
    }
  }
  return {
    url: u.toString(),
    method,
    bodyParams: clampParams(src.bodyParams),
    jsonBody,
    cookieParams: clampParams(src.cookieParams),
    headerParams,
    config,
  };
}

// [安全审计 P1] bodyParams/cookieParams 长度+数量限制
// 防超大 body 注入 / 超多参数 DoS（对标 headerParams 黑名单过滤的安全级别）
function clampParams(params, maxKeys = 50, maxValLen = 10000, maxKeyLen = 100) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) return {};
  const out = {};
  let count = 0;
  for (const [k, v] of Object.entries(params)) {
    if (count >= maxKeys) break;
    const key = String(k).slice(0, maxKeyLen);
    const val = typeof v === 'string' ? v.slice(0, maxValLen) : String(v ?? '').slice(0, maxValLen);
    out[key] = val;
    count++;
  }
  return out;
}

// ── 并发扫描上限（原逻辑不变）──
let activeScanCount = 0;
const MAX_SCAN_API_CONCURRENT = (() => {
  const n = Number(process.env.MAX_SCAN_API_CONCURRENT);
  return Number.isInteger(n) && n >= 1 ? n : 8;
})();

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

function trackScanTerminal(sm, bus, scanId, release) {
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
      finish();
    }
  };
  em.on('event', onEvent);
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) finish();
}

// 测试钩子
export const _scanGovernance = {
  maxConcurrent: MAX_SCAN_API_CONCURRENT,
  get activeScanCount() {
    return activeScanCount;
  },
  resetForTest() {
    activeScanCount = 0;
  },
};

// ── 报告访问护栏（P2-1：恒时比较）───────────────────────────────────────────
function createReportGuard(tokenOverride) {
  const resolveToken = () =>
    tokenOverride !== undefined ? tokenOverride : process.env.SCAN_API_TOKEN || '';
  const safeEqual = (a, b) => {
    const ha = crypto.createHash('sha256').update(String(a ?? '')).digest();
    const hb = crypto.createHash('sha256').update(String(b ?? '')).digest();
    return crypto.timingSafeEqual(ha, hb);
  };
  return (req, res, next) => {
    const token = resolveToken();
    if (!token) return next();
    // [P0-FIX] query token 兜底：EventSource 无法设置自定义头，前端 SSE 只能以
    // ?token=... 携带（与全局 token 中间件 index.js 的 req.query.token 语义对齐）。
    const provided =
      String(req.headers['x-scan-token'] || '') ||
      String(req.headers['x-api-token'] || '') ||
      String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '') ||
      String((req.query && req.query.token) || '').trim();
    if (provided && safeEqual(provided, token)) return next();
    return res.status(401).json({ code: 401, data: null, message: '需要有效的 API Token' });
  };
}

/**
 * 创建扫描相关路由。
 * @param {object} [opts]
 * @param {import('../engine/ScanManager.js').ScanManager} [opts.scanManager] 不传则内部自建
 * @param {any} [opts.eventBus] 事件总线（默认取模块级 eventBus 单例）
 * @param {string} [opts.reportToken] 报告导出接口的访问令牌
 */
export function createRoutes({ scanManager, eventBus: bus = eventBus, reportToken } = {}) {
  const sm = scanManager || new ScanManager();
  const router = Router();
  const requireReport = createReportGuard(reportToken);

  // [P0-SEC 2026-09-08] scanId 形状校验：scanId 会被拼进导出响应的 Content-Disposition 文件名，
  // 且出现在日志里。引擎自身用 nanoid(10) 生成，但路由不得假定调用方传得对：
  // 带 CR/LF 的 id 可试响应头注入，带 ../ 的 id 会被任何后续“落盘/拉取”型逻辑当路径用。
  // 统一用 router.param 拦住所有 :id 端点（比逐路由判更不容易漏）。
  router.param('id', (req, res, next, id) => {
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(id)) {
      return res.status(400).json({ code: ErrorCode.SCAN_ID_INVALID, data: null, message: 'scanId 格式非法' });
    }
    next();
  });

  router.post('/scan/start', async (req, res) => {
    const release = acquireScanSlot();
    if (!release) {
      return res.json({
        code: ErrorCode.ENGINE_BUSY,
        data: null,
        message: '引擎忙：并发扫描已达上限，请稍后再试',
      });
    }
    try {
      const sanitized = sanitizeStart(req.body); // 同步（测试契约）
      // [P0-1] SSRF 校验在路由层执行（DNS 解析需 async）：拒绝内网/回环/链路本地/云元数据地址
      // （策略见 httpClient.js；SSRF_ALLOW_PRIVATE=1 / SSRF_ALLOW_CIDRS=... 显式放行内部授权目标）
      // 直连模式（mode=direct）不发起 HTTP 请求，跳过 SSRF 校验（无 SSRF 面）。
      if (sanitized.mode !== 'direct') {
        await assertSafeHttpTarget(/** @type {string} */ (sanitized.url)).catch((e) => {
          throw e instanceof AppError ? e : new AppError(ErrorCode.INVALID_PARAM, e.message || '目标 URL 校验失败');
        });
      }
      // 二阶触发页逐个 SSRF 校验（剔除非法项）
      const soTrigger = sanitized.config?.secondOrder?.triggerUrls;
      if (Array.isArray(soTrigger) && soTrigger.length) {
        // [P0-SEC 2026-09-08] 二阶触发页同步受 scope 约束：存储点在圈内不代表回显页在圈内
        // （“写入 admin 后台、回显在另一个域”很常见），而触发页会携带会话 Cookie。
        const scopeRules = parseScope(sanitized.config?.scope);
        const checked = [];
        for (const u2 of soTrigger) {
          try {
            await assertSafeHttpTarget(u2);
            if (scopeRules.enabled) assertInScope(u2, scopeRules);
            checked.push(u2);
          } catch (e) {
            logger.warn(`二阶触发页 ${u2} 未通过 SSRF/授权范围校验，已剔除：${e.message}`);
          }
        }
        sanitized.config.secondOrder.triggerUrls = checked;
      }
      const scanId = await sm.start(sanitized);
      // [P0-SEC] 把本次扫描的授权范围登记到 scopeGuard：HttpClient 在「每一跳重定向」前取用，
      // 防止目标 302 到未授权主机（统一登录/CDN 回源/灰度切流）后，后续全部注入请求默默跑出圈。
      try {
        registerScanScope(scanId, parseScope(sanitized.config?.scope));
      } catch { /* 登记失败不影响扫描启动（启动前已做过入口校验） */ }
      trackScanTerminal(sm, bus, scanId, release);
      res.json({ code: 0, data: { scanId }, message: 'ok' });
    } catch (e) {
      release();
      const err = e instanceof AppError ? e : new AppError(ErrorCode.UNKNOWN, e.message);
      // [P2-SEC 2026-09-08] 不把整段 e.stack 写进日志：本仓日志级别是 warn（不是 debug），
      // 且会落到 logs/engine.log（任本机用户可读）。框架层堆栈会带入调用方传入的
      // config/headers 片段（旧版 redact 不盖 JSON 形态的 key），现在只留栈顶一帧定位，
      // 完整堆栈降到 debug（需要时手动开）。
      const topFrame = String(e.stack || '').split('\n').slice(1, 3).join(' | ').trim();
      logger.warn(`启动扫描失败：${err.message}${topFrame ? `（${topFrame}）` : ''}`);
      logger.debug(`启动扫描失败堆栈：${e.stack || ''}`);
      res.json({ code: err.code, data: null, message: err.message });
    }
  });

  // [P2-11] 实时报告快照同样挂报告守卫（token 未设置时为 no-op，行为不变）
  router.get('/scan/:id', requireReport, (req, res) => {
    const report = sm.getReport(req.params.id);
    if (!report) {
      return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
    }
    res.json({ code: 0, data: report, message: 'ok' });
  });

  // [P2-11] SSE 进度流挂报告守卫（事件内容含扫描目标与完整报告，见 ScanManager 脱敏 patch）
  router.get('/scan/:id/events', requireReport, (req, res) => {
    bus.toSSE(req.params.id, req, res);
  });

  router.post('/scan/:id/stop', requireReport, (req, res) => {
    const ok = sm.stop(req.params.id);
    res.json({ code: 0, data: { stopped: ok }, message: 'ok' });
  });

  // [实战最高频动作] 单点重测：调完参（level/risk/tamper/technique…）只重跑某个注入点。
  // POST /api/scan/:id/point/:pointId/retest   body: { config?: {...覆盖项} }
  // 旧实现只能整站重扫——调参验证一次要等几分钟。这里复用原扫描的 target + 新 config，
  // 通过 config.onlyPoint 把注入点收敛到目标点，请求量从数百降到几十，且对检测主流程零侵入。
  // 返回新的 scanId（与 /scan/start 一致，异步扫描，用 /scan/:id/report 取结果）。
  router.post('/scan/:id/point/:pointId/retest', requireReport, async (req, res) => {
    const release = acquireScanSlot();
    if (!release) {
      return res.json({ code: ErrorCode.ENGINE_BUSY, data: null, message: '引擎忙：并发扫描已达上限，请稍后再试' });
    }
    try {
      const base = sm.getReport(req.params.id);
      if (!base) {
        release();
        return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '基线扫描不存在' });
      }
      const point = (base.points || []).find((p) => p.id === req.params.pointId);
      if (!point) {
        release();
        return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '注入点不存在（pointId 需来自同一份报告）' });
      }
      const target = base.target || {};
      if (!target.baseUrl) {
        release();
        return res.json({ code: ErrorCode.INVALID_PARAM, data: null, message: '基线报告缺少目标信息，无法重测' });
      }
      const override = (req.body && req.body.config) || {};
      const merged = {
        ...(target.config || {}),
        ...override,
        onlyPoint: { location: point.location, param: point.param },
      };
      // 重测只做检测：带上原 extractScope 会重复枚举，既慢又可能误触发写入
      delete merged.extractScope;
      const payload = {
        url: target.baseUrl,
        method: target.method || 'GET',
        bodyParams: target.bodyParams || {},
        jsonBody: target.jsonBody || null,
        cookieParams: target.cookieParams || {},
        headerParams: target.headerParams || {},
        config: merged,
      };
      await assertSafeHttpTarget(payload.url).catch((e) => {
        throw e instanceof AppError ? e : new AppError(ErrorCode.INVALID_PARAM, e.message || '目标 URL 校验失败');
      });
      const scanId = await sm.start(payload);
      try {
        registerScanScope(scanId, parseScope(merged.scope));
      } catch { /* 登记失败不影响已启动的扫描 */ }
      trackScanTerminal(sm, bus, scanId, release);
      res.json({
        code: 0,
        data: {
          scanId,
          point: { id: point.id, location: point.location, param: point.param, encoding: point.encoding || null },
          configApplied: { level: merged.level ?? null, risk: merged.risk ?? null, tamper: merged.tamper ?? null, techniques: merged.techniques ?? null },
        },
        message: 'ok',
      });
    } catch (e) {
      release();
      const err = e instanceof AppError ? e : new AppError(ErrorCode.UNKNOWN, e.message);
      logger.warn(`单点重测启动失败：${err.message}`);
      res.json({ code: err.code, data: null, message: err.message });
    }
  });

  // [P0-FIX] 暂停/续跑扫描（对标 sqlmap Ctrl+C 暂停语义；仅 running 可暂停、paused 可恢复）
  router.post('/scan/:id/pause', requireReport, (req, res) => {
    const ok = sm.pause(req.params.id);
    res.json({ code: ok ? 0 : ErrorCode.SCAN_NOT_FOUND, data: { paused: ok }, message: ok ? 'ok' : '扫描不在运行中，无法暂停' });
  });

  router.post('/scan/:id/resume', requireReport, (req, res) => {
    const ok = sm.resume(req.params.id);
    res.json({ code: ok ? 0 : ErrorCode.SCAN_NOT_FOUND, data: { resumed: ok }, message: ok ? 'ok' : '扫描未处于暂停状态' });
  });

  router.get('/scan/:id/report', requireReport, (req, res) => {
    const report = sm.getReport(req.params.id);
    if (!report) {
      return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
    }
    // [P1-UX 2026-09-08] 查看报告同样带 PoC 证据（与导出同源、纯函数浅拷贝）：
    // 实战里「在界面上看到可复制的 curl」是开完台本后立刻要用的东西，不该为了一条命令再导一次报告。
    let data = report;
    try {
      if (typeof sm.reportGen?.attachPoc === 'function') data = sm.reportGen.attachPoc(report);
    } catch { /* PoC 是增强项，失败不影响报告主体 */ }
    res.json({ code: 0, data, message: 'ok' });
  });

  // [交付场景] 两次扫描差异对比：修完漏洞后要能证明「确实修好了」。
  // GET /api/scan/:id/diff?base=<scanId>
  //   比对键 = location:param:technique（不用 pointId——每次扫描的 pointId 都是新生成的，
  //   用它比对会把「同一个注入点」算成新增+已修复各一条，结果毫无意义）。
  //   输出三组：fixed（基线有、本次无）/ new（本次有、基线无）/ remaining（两次都有）。
  router.get('/scan/:id/diff', requireReport, (req, res) => {
    const baseId = String(req.query.base || '').trim();
    if (!baseId) {
      return res.json({ code: ErrorCode.INVALID_ARGUMENT ?? 1, data: null, message: '缺少 base 参数（基线扫描 id）：/api/scan/<id>/diff?base=<scanId>' });
    }
    const cur = sm.getReport(req.params.id);
    const base = sm.getReport(baseId);
    if (!cur) return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '当前扫描不存在' });
    if (!base) return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '基线扫描不存在' });

    res.json({ code: 0, data: diffReports(base, cur), message: 'ok' });
  });

  router.get('/scan/:id/report/export', requireReport, (req, res) => {
    const rawFormat = (req.query.format || 'json').toString().toLowerCase();
    // [P0-SEC 2026-09-08] format 白名单：它既进 Content-Type 又拼进 Content-Disposition 文件名，
    // 原实现直接透传 `req.query.format` → 带 `"` / CR / LF 的取值可闭合头字段或注入额外响应头。
    const FORMAT_EXT = { json: 'json', html: 'html', csv: 'csv', markdown: 'markdown', md: 'markdown', 'db-json': 'db.json', sarif: 'sarif' };
    if (!Object.prototype.hasOwnProperty.call(FORMAT_EXT, rawFormat)) {
      return res.status(400).json({ code: ErrorCode.INVALID_PARAM, data: null, message: 'format 非法，仅支持 json/html/csv/markdown/md/db-json/sarif' });
    }
    const format = rawFormat;
    const out = sm.exportReport(req.params.id, format);
    if (out == null) {
      return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
    }
    const contentTypes = {
      html: 'text/html; charset=utf-8',
      csv: 'text/csv; charset=utf-8',
      markdown: 'text/markdown; charset=utf-8',
      sarif: 'application/sarif+json; charset=utf-8',
      md: 'text/markdown; charset=utf-8',
      json: 'application/json; charset=utf-8',
      'db-json': 'application/json; charset=utf-8',
    };
    res.setHeader('Content-Type', contentTypes[format] || contentTypes.json);
    const ext = FORMAT_EXT[format];
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="report_${req.params.id}.${ext}"`
    );
    return res.send(out);
  });

  // GET /api/payloads?dbms=&technique= —— 只读查看 Payload 模板
  router.get('/payloads', (req, res) => {
    const dbms = req.query.dbms?.toString();
    const technique = req.query.technique?.toString();
    let data;
    if (dbms && technique) {
      data = (PAYLOADS[dbms] && PAYLOADS[dbms][technique]) || [];
    } else if (dbms) {
      data = PAYLOADS[dbms] || {};
    } else {
      data = { ...PAYLOADS, fingerprint: FINGERPRINT };
    }
    res.json({ code: 0, data, message: 'ok' });
  });

  return router;
}

// 默认单例扫描管理器（供 index.js 优雅关闭时访问在途扫描状态）
export const defaultScanManager = new ScanManager();

// 默认单例路由
export const scanRoutes = createRoutes({ scanManager: defaultScanManager });
