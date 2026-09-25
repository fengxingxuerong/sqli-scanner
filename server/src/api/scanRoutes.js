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
import { PAYLOADS, FINGERPRINT } from '../engine/payloads.js';
import { logger } from '../core/logger.js';
// [2026-09-24] 提取/统计层调优旋钮的入口收敛（11 键），见 api/scanConfigTuning.js。
import { warnDroppedConfigKeys } from './scanConfigTuning.js';
import { assertSafeHttpTarget } from '../core/httpClient.js';
// [交付场景] 两次扫描差异对比（纯函数，便于单测；见 tests/scanDiff.test.js）
import { diffReports } from '../engine/scanDiff.js';
// [P0-SEC 2026-09-08] 授权范围（scope）硬约束 + 逐跳登记
// [大文件拆分 2026-09-21] releaseScanScope 随 trackScanTerminal 一并移至 scanGovernance.js
// （本文件的唯一调用点就在那簇里），故此处不再 import。
import { parseScope, assertInScope, registerScanScope } from '../core/scopeGuard.js';
// [大文件拆分 2026-09-21] 两簇外移后的引用（下方同时 re-export 保路径）
import { clampParams } from './scanConfigUtils.js';
import { acquireScanSlot, trackScanTerminal, _scanGovernance } from './scanGovernance.js';
import { buildDirectTarget } from './directTarget.js';
// 配置守卫（两条入口共用；为何单独成文件见其文件头）
import { buildGuardedConfig } from './scanConfigGuard.js';
// 抽到守卫模块后仍从本文件 re-export，保住既有引用路径（与 acquireScanSlot 同一做法）
export { sanitizeExtractScope } from './scanConfigGuard.js';

export { acquireScanSlot, _scanGovernance };

// [大文件拆分 2026-09-21] clamp 家族（clampInt / clampNum / boolOf / clampStr /
// pickInt / pickBool / sanitizeCookieMap）已外移至 api/scanConfigUtils.js（纯函数、零依赖）。
// 它们是配置入口的第一道闸门（数值区间 / 长度上限 / 原型污染键过滤），
// 抽出来后每条闸门都能单独穷举测试。

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
  // [2026-09-24] 引擎真读、此前**任何入口都设不了**的三键（见 sanitizeStart 内注释）：
  // http2 / disableKeepAlive（传输形态）+ xpAutoEnable（不可逆动作的拒绝位）
  'http2', 'disableKeepAlive', 'xpAutoEnable',
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
  // [2026-09-23] 报错模板按机制族裁剪（默认 false：见 defaults.js 里写明的实测代价）
  'compactErrorTemplates',
  // [2026-09-24 接入口] 引擎读取点一直在、注释也一直写着"可经 config.X 调整"，
  // 但 X 在 defaults / 本白名单 / CLI / 面板**四处都没有** ⇒ 那承诺只有写单测的人能兑现。
  // 默认值逐个等于引擎内部兜底，故零行为变化；细节见 defaults.js 同批注释。
  'blindBitwise', 'blindMaxLen', 'booleanOrFallback', 'unionSkipGate',
  'deepDumpPageSize', 'dumpCheckpointInterval', 'fingerprintSleepSec', 'fingerprintTimeThresholdMs',
  // 预筛选时间预算（prefilter.js 明写"手动 cfg.prefilterBudgetMs 仍最高优先"）与
  // 提取响应上限（Extractor.js:121 回落 EXTRACT_MAX_BODY_BYTES，env 之外的 per-scan 覆盖）
  'prefilterBudgetMs', 'maxExtractBodyBytes',
  // 结论可信度守卫的阈值组（scanValidityGuard.VALIDITY_DEFAULTS 的 7 个阈值 + enabled 逃生口）
  'scanValidity',
  // [2026-09-23 E2] 枚举 / 拖库动作族：--dbs/--tables/--columns/--dump/--dump-all/--users/
  // --passwords/--current-db/--current-user/--hostname/--is-dba/--schema/--privileges/--roles/
  // --count/--search/--common-tables/--common-columns。CLI 一路把参数解析成 config.extractScope
  // 交给引擎（bin/cli/config.js:314 → ScanManager._extractByScope），而**此白名单从未收录它**
  // → Web / 桌面 / API 三端完全没有枚举与拖库能力（传了被当未知字段静默丢弃）。
  // 形状校验见下方 sanitizeExtractScope。
  'extractScope',
]);


// 禁止由调用者覆写的头名（P2-8，与 httpClient 侧 FORBIDDEN_HEADERS 保持一致）
const FORBIDDEN_HEADER_NAMES = new Set([
  'host', 'content-length', 'transfer-encoding', 'connection', 'upgrade',
  'proxy-connection', 'keep-alive', 'te', 'trailer', 'expect',
]);

// 直连模式专用键：HTTP 模式下 sanitizeStart 不会把它们写进 config（走 isDirect 早退分支），
// 所以"发了却没落地"在这里**不是**丢弃 —— 差分时必须排除，否则每个直连配置混进 HTTP 请求体
// 都会误报一条"设置不会生效"。
const DIRECT_ONLY_CFG_KEYS = new Set(['db', 'connectionString', 'sqlTemplate', 'mode']);


// 校验并收敛 /scan/start 入参，防止非法目标 / 越界配置进入引擎。
// 兼容两种入参形态（原逻辑），新增：headerParams 头名过滤。
// 注意：保持同步函数（测试契约同步调用）；SSRF 校验在路由处理器 async 层执行
// （见 /scan/start handler 中的 assertSafeHttpTarget 调用）。
export function sanitizeStart(body) {
  const b = body || {};
  const cfg = b.config || {};

  // ── 直连模式（对标 sqlmap -d）：不走 HTTP，直接连库执行 SQL 模板 ──
  // 校验、规范化、以及**对数据库主机的 scope 判定**都在 api/directTarget.js（纯函数）。
  // 原实现只认 http:// 目标，mode/db/connectionString 全被丢弃 ⇒ 直连能力在 API 层不可达。
  if (b.mode === 'direct' || b.db || b.connectionString) {
    const direct = buildDirectTarget(b, cfg);
    // 「传了但不会生效」的播报同样要覆盖这条入口 —— 原先只有 HTTP 分支喊，直连是静默的。
    // 位置与 HTTP 分支同规则：必须在全部分支（含兜底透传）之后，否则会把兜底落地的键误报成丢弃。
    warnDroppedConfigKeys(cfg, KNOWN_CFG_KEYS, direct.config, DIRECT_ONLY_CFG_KEYS);
    return direct;
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

  // —— 配置守卫：整段 clamp / 形状校验 / 白名单键落地已抽出到 api/scanConfigGuard.js ——
  // 抽出去不是为了好看：直连分支（buildDirectTarget）此前**完全绕过**这段，越界值原样进引擎。
  // 现在两条入口共用同一个函数 ⇒ 新增键只需改一处，不会再出现"一边 clamp 了、另一边漏掉"。
  const config = buildGuardedConfig(cfg, scopeRules);

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
  // [JSON-BODY-FIX 2026-09-20] bodyParams 里放嵌套对象 = 得到一个不可能注入的畸形点。
  // clampParams 对非字符串值做 String(v)（:696），于是 {user:{id:1}} 变成 body 参数
  // `user=[object Object]`，扫描照常跑完、报告写「未检出」—— 与同批修的「CLI 嵌套 body
  // 摊平」「白名单静默丢键」是同一类：能力在引擎（jsonBody + _discoverJsonLeaves）齐备，
  // 用错字段的那一方什么提示都收不到。这里不改行为（改成自动路由到 jsonBody 会让两个
  // 字段的语义纠缠不清），只把提示打出来：该走 jsonBody 的人一眼就知道自己走错了门。
  const nestedBodyKeys = Object.entries(src.bodyParams || {})
    .filter(([, v]) => v !== null && typeof v === 'object')
    .map(([k]) => String(k).slice(0, 100));
  if (nestedBodyKeys.length) {
    logger.warn(
      `bodyParams 含 ${nestedBodyKeys.length} 个对象/数组值（${nestedBodyKeys.slice(0, 5).join(', ')}），`
      + '会被 String() 成不可注入的畸形值——嵌套 body 请改用 jsonBody（引擎按叶子路径如发现 user.id 注入点）'
    );
  }
  warnDroppedConfigKeys(cfg, KNOWN_CFG_KEYS, config, DIRECT_ONLY_CFG_KEYS);
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

// ── 并发扫描上限（原逻辑不变）──
// [大文件拆分 2026-09-21] 并发额度与扫描终结回收已外移至 api/scanGovernance.js。
// 下方 re-export 保住既有 import 路径：tests/securityGovernance.test.js 从本文件
// import 了 acquireScanSlot / _scanGovernance。导出的是**同一对象引用**，
// 故测试读写的仍是 scanGovernance.js 里那份 activeScanCount 状态 —— 语义不变。

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
      // ⚠ 但**只跳过 SSRF 这一条**：scope 是另一条红线（"别打没授权的人"），它在
      //   sanitizeStart 的直连分支里对数据库主机单独判定 —— 过去这句注释把两条一起
      //   免掉了，读起来像"直连不受任何范围约束"是既定设计，其实不是。
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
      // [P0-REACH 2026-09-23] 读写分离的 secondUrl 与触发页**同级**：它同样会携带会话 Cookie
      // 发出真实请求，故适用同一条 SSRF + 授权范围判据。校验不过就清空 —— 引擎侧
      // `so.secondUrl || url` 恰好把空串当「回退触发页」，语义天然安全，不会带病进引擎。
      const secondUrl = sanitized.config?.secondOrder?.secondUrl;
      if (typeof secondUrl === 'string' && secondUrl) {
        try {
          await assertSafeHttpTarget(secondUrl);
          const readScopeRules = parseScope(sanitized.config?.scope);
          if (readScopeRules.enabled) assertInScope(secondUrl, readScopeRules);
        } catch (e) {
          logger.warn(`二阶读取页 ${secondUrl} 未通过 SSRF/授权范围校验，已清空（回退触发页）：${e.message}`);
          sanitized.config.secondOrder.secondUrl = '';
        }
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
      // 走与 /scan/start 同一套 config 守卫（白名单 / clamp / 类型归一 / dumpWhere 拒分号 /
      // techniques 白名单 / scope 断言）—— 历史上这里 merged 直送 sm.start，整条被绕开。
      // 参数形状仍取自 base 报告：它们在原扫描启动时已经过同一条守卫，不必二次加工。
      const merged = sanitizeStart({
        url: target.baseUrl,
        method: target.method || 'GET',
        config: { ...(target.config || {}), ...override },
      }).config;
      // 重测只做检测：带上原 extractScope 会重复枚举，既慢又可能误触发写入
      delete merged.extractScope;
      // onlyPoint 是服务端从报告真实点位算出的内部字段，刻意不在 KNOWN_CFG_KEYS 里
      // （见 configOrphanKeys.guard.test.js）⇒ 必须净化**之后**贴回：既不被白名单丢掉
      // （那样重测静默退化成整站重扫），也让 override 伪造的 onlyPoint 进不来。
      merged.onlyPoint = { location: point.location, param: point.param };
      const payload = {
        url: target.baseUrl, method: target.method || 'GET',
        bodyParams: target.bodyParams || {}, jsonBody: target.jsonBody || null,
        cookieParams: target.cookieParams || {}, headerParams: target.headerParams || {},
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
          // 自报字段必须指向**引擎真正读的那个键**。内置引擎的 tamper 在
          // `config.wafEvasion.tamper`（见 scanConfigTuning / Detector），顶层 `tamper` 只有
          // sqlmap 桥接层用（input.config.sqlmap.tamper）。原来回显 `merged.tamper ?? null` ⇒
          // 用户设了 tamper 复测，接口报 "tamper: null"（说了没做）；而若有人从 sqlmap 面板
          // 串过来一个顶层 tamper，它会被报成"已应用"，实际内置引擎根本没看它（做了没说反过
          // 来更糟：报了一个不存在的效果）。
          configApplied: {
            level: merged.level ?? null,
            risk: merged.risk ?? null,
            tamper: merged.wafEvasion?.tamper ?? null, // 引擎真正读的键（顶层 tamper 只有 sqlmap 桥接层用）
            techniques: merged.techniques ?? null,
          },
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
      // 必须是 4xx：这是一条**文件下载**端点。历史上它返回 200 + `application/json` 且不带
      // Content-Disposition，而前端只判 `res.ok` 就把响应体另存盘 ⇒ 用户拿到一个装着
      // {"code":2001,"message":"扫描不存在或已结束"} 的 "report_xxx.csv"，看起来像报告坏了，
      // 实际是扫描早已被回收。实测复现过（2026-09-25）。
      // 只改这一条端点的状态码：`/scan/:id/diff` 那类 JSON 接口按 200+code 契约被前端正常解包。
      return res.status(404).json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
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
