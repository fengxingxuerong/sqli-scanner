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

// 白名单字段全集（原逻辑不变）
const KNOWN_CFG_KEYS = new Set([
  'ratePerSec', 'concurrency', 'retry', 'timeoutMs', 'timeThresholdMs', 'enableExtract',
  'extractConcurrency', 'dumpMaxRows', 'timeBlindSamples', 'maxColumnsGuess', 'dumpRowLimit',
  'dumpConcurrency', 'dumpDatabaseConcurrency', 'crawlForms', 'crawlDepth', 'auth', 'proxy', 'techniques',
  // [sqlmap 对标] 行范围导出 + 保活探测（--start/--stop/--safe-url/--safe-freq）
  'dumpStart', 'dumpStop', 'safeUrl', 'safeFreq',
  'secondOrder', 'wafEvasion', 'oob', 'noSql', 'blindRobust', 'sessionFile',
  'sessionDefault',
  'level', 'risk', 'prefix', 'suffix',
  // [对标 sqlmap --dbms] 强制指定 DBMS（scanRunner 消费：跳过指纹直接按指定库检测）
  'dbms',
  // [B-perf] skip-static 参数预筛选 / 响应相似度锚点（--string/--not-string）
  'skipStatic', 'matchString', 'notString',
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
]);

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

  const config = {};

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
    config.safeUrl = clampStr(cfg.safeUrl.trim(), '', 2000);
    const safeFreq = pickInt(cfg, 'safeFreq', defaults.safeFreq, 1, 10000);
    if (safeFreq !== undefined) config.safeFreq = safeFreq;
  }
  const dumpConcurrency = pickInt(cfg, 'dumpConcurrency', defaults.dumpConcurrency, 1, 16);
  if (dumpConcurrency !== undefined) config.dumpConcurrency = dumpConcurrency;
  const dumpDatabaseConcurrency = pickInt(cfg, 'dumpDatabaseConcurrency', defaults.dumpDatabaseConcurrency, 1, 16);
  if (dumpDatabaseConcurrency !== undefined) config.dumpDatabaseConcurrency = dumpDatabaseConcurrency;
  const crawlForms = pickBool(cfg, 'crawlForms');
  if (crawlForms !== undefined) config.crawlForms = crawlForms;
  // [B-perf] skip-static 参数预筛选（对标 sqlmap --skip-static）：boolean 化透传，默认关（opt-in）
  const skipStatic = pickBool(cfg, 'skipStatic');
  if (skipStatic !== undefined) config.skipStatic = skipStatic;
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
  if (cfg.proxy) {
    if (typeof cfg.proxy !== 'string' || !/^(https?|socks5?):\/\//i.test(cfg.proxy)) {
      throw new AppError(ErrorCode.INVALID_PARAM, 'proxy 格式非法');
    }
    config.proxy = cfg.proxy;
  }
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
      negativeControl: so.negativeControl !== false,
      oobTrigger: !!so.oobTrigger,
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
      timeConfidenceZ: clampNum(br.timeConfidenceZ, d.timeConfidenceZ, 0, 5),
      minStableRatio: clampNum(br.minStableRatio, d.minStableRatio, 0, 1),
      booleanSignificanceZ: clampNum(br.booleanSignificanceZ, d.booleanSignificanceZ, 0, 5),
      adaptive: boolOf(br.adaptive, d.adaptive),
      adaptiveHeadroom: clampNum(br.adaptiveHeadroom, d.adaptiveHeadroom, 0, 1),
      minStableRatioFloor: clampNum(br.minStableRatioFloor, d.minStableRatioFloor, 0, 1),
      minStableRatioCap: clampNum(br.minStableRatioCap, d.minStableRatioCap, 0, 1),
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

  // 未知字段忽略（debug 级单行提示，不打日志刷屏）
  const ignored = Object.keys(cfg).filter((k) => !KNOWN_CFG_KEYS.has(k));
  if (ignored.length) logger.debug(`扫描配置忽略未知字段：${ignored.join(', ')}`);
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
  return {
    url: u.toString(),
    method,
    bodyParams: clampParams(src.bodyParams),
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

export function createRoutes({ scanManager, eventBus: bus = eventBus, reportToken } = {}) {
  const sm = scanManager || new ScanManager();
  const router = Router();
  const requireReport = createReportGuard(reportToken);

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
        await assertSafeHttpTarget(sanitized.url).catch((e) => {
          throw e instanceof AppError ? e : new AppError(ErrorCode.INVALID_PARAM, e.message || '目标 URL 校验失败');
        });
      }
      // 二阶触发页逐个 SSRF 校验（剔除非法项）
      const soTrigger = sanitized.config?.secondOrder?.triggerUrls;
      if (Array.isArray(soTrigger) && soTrigger.length) {
        const checked = [];
        for (const u2 of soTrigger) {
          try {
            await assertSafeHttpTarget(u2);
            checked.push(u2);
          } catch {
            logger.warn(`二阶触发页 ${u2} 未通过 SSRF 校验，已剔除`);
          }
        }
        sanitized.config.secondOrder.triggerUrls = checked;
      }
      const scanId = await sm.start(sanitized);
      trackScanTerminal(sm, bus, scanId, release);
      res.json({ code: 0, data: { scanId }, message: 'ok' });
    } catch (e) {
      release();
      const err = e instanceof AppError ? e : new AppError(ErrorCode.UNKNOWN, e.message);
      logger.warn(`启动扫描失败：${err.message}\n${e.stack || ''}`);
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
    res.json({ code: 0, data: report, message: 'ok' });
  });

  router.get('/scan/:id/report/export', requireReport, (req, res) => {
    const format = (req.query.format || 'json').toString().toLowerCase();
    const out = sm.exportReport(req.params.id, format);
    if (out == null) {
      return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
    }
    const contentTypes = {
      html: 'text/html; charset=utf-8',
      csv: 'text/csv; charset=utf-8',
      markdown: 'text/markdown; charset=utf-8',
      md: 'text/markdown; charset=utf-8',
      json: 'application/json; charset=utf-8',
      'db-json': 'application/json; charset=utf-8',
    };
    res.setHeader('Content-Type', contentTypes[format] || contentTypes.json);
    const ext = format === 'md' ? 'markdown' : format === 'db-json' ? 'db.json' : format;
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
