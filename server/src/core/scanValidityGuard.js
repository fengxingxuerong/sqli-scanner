// ============================================================================
// core/scanValidityGuard.js —— 扫描结论可信度守卫（假安心防护）
//
// 背景（渗透实战第一优先级缺陷）：目标中途宕机 / 被 WAF 封 IP / 会话过期时，
// 引擎把「测不出来」当成「没有漏洞」输出 0 漏洞报告。httpClient 的网络错误被
// 吞成 null（core/httpClient.js catch → return null），调用方 `String(res?.data ?? '')`
// 又把「请求失败」变成「200 空页」——于是所有检测器一致地返回「无差异 → 不可注入」，
// 报告写着「未发现漏洞」，使用者据此收工。这是危险的假安心（false reassurance）。
//
// 与 dbHealthGuard 的分工：
//   · dbHealthGuard  关心「我们是否把目标打坏了」（自伤熔断）；
//   · 本守卫         关心「目标还能不能给出可信答案」（结论有效性判定）。
//   两者同构：observe 回流 → 阈值判定 → shouldAbort 熔断 → summary 落报告。
//
// 设计约束（照 dbHealthGuard 的成熟范式）：
//   - 保守判定：宁可不判也不误判。拦截文案只在 status>=400 时生效，避免把业务页面
//     里恰好出现的「防火墙/安全验证」字样误判为被拦（正常目标零行为变化）。
//   - 只有「目标彻底不可达」才 abort（继续发包既无意义又可能加重封禁）；
//     blocked / session_expired / target_error 只标注不中止，把判断权交还使用者。
//   - 无状态泄漏：Guard 生命周期跟随单次扫描（由 scanRunner 创建并持有）。
//   - 结论一旦成立即「粘滞」（sticky）：目标中途挂掉后又恢复，早先那批失败请求造成的
//     「未检出」依然不可信，所以报告必须始终保留非 ok 状态。
// ============================================================================

// 判定阈值默认值（常量，非 defaults.js 配置项）。
// 允许通过 ctx/构造参数覆盖（opts 同名键），便于按目标调优而不引入新配置面。
export const VALIDITY_DEFAULTS = {
  windowSize: 40, // 统计窗口：只看最近 N 个请求，保证「中途变坏」能盖过早期干净样本
  abortAfterFails: 10, // 连续失败达此数 → 判定目标不可达并中止剩余检测
  blockRatio: 0.6, // 窗口内拦截占比阈值
  blockMinHits: 8, // 拦截绝对次数下限（防小样本误判：3/3 不算被封）
  authStreak: 3, // 注入请求连续 401/登录跳转次数阈值
  // [D36 实战 P0-3] 「从来没进去过」与「进去过之后整段出不去」两条判据的样本下限。
  // 为什么不是 3（与 authStreak 同值）：这两条**不分注入与否**，而一次自动登录/自动续期的
  // 正常形态就是「1 条 401 + 若干条重试成功」交替出现；下限 3 会把这类目标误判成失效。
  // 实测出处 e2e/bearer-lab：CLI 的 --auth/--header 到出口的请求**一个认证头都没带**
  // （createTarget 丢掉了顶层 auth），整轮 70 条全 401，verdict 却是 no_vulnerability_detected + 可信。
  unauthMinRequests: 8,
  authStreakAll: 8,
  serverErrRatio: 0.8, // 窗口内 5xx 占比阈值
  minSamples: 10, // 比例类判定的最小样本数
  // [D32 实战 P0-1] 自定义请求变换（签名/加密）生效时的两条显形阈值。
  // ⚠ 全部只在 transformActive 时参与判定 ⇒ 未用扩展点的扫描一个计数都不动。
  transformBaselineRejects: 2, // 基线（未注入）请求连续被拒达此数且从未成功 → 脚本与目标不匹配
  transformInjectRejects: 8, // 注入请求被拒绝对次数下限（防小样本误判，与 blockMinHits 同构）
};

// 明确的拦截状态码：403 Forbidden / 406 不可接受（ModSecurity 常用）/
// 429 限速封禁 / 503 服务不可用（WAF 过载拦截常以此返回）。
export const BLOCK_STATUSES = new Set([403, 406, 429, 503]);

// [D32 实战 P0-1] 「请求本身被目标判非法」的状态码（签名/加密参数被破坏后的典型回包）。
export const REQUEST_REJECT_STATUSES = new Set([400, 415, 422]);

// 通用拦截页文案（保守正则，仅在 status>=400 时才参与判定）。
// 不追求识别厂商，只求「这次请求被中间设备拒了」——厂商指纹由 waf/WafIdentifier 负责。
export const GENERIC_BLOCK_SIG =
  /waf|blocked|forbidden|access denied|请求非法|拦截|防火墙|安全狗|云锁|安全验证|challenge|cf-ray/i;

// 会话失效特征：302/303 跳登录页（含 CAS/SSO 网关）。
export const LOGIN_REDIRECT_SIG = /\/login|\/signin|\/logon|\/auth|\/cas\/|\/sso/i;

// 「注入请求」识别：请求里带 payload 特征。用于区分基线请求与注入请求——
// 只有「注入请求被打回认证页而基线请求没有」才是会话过期语义（整站 401 属凭据问题，
// 由 baselineAuthHits 反证排除）。判据宽松无妨：漏判成注入只会让 authLost 更难成立。
export const INJECTION_SIGS = [
  /union[\s+%20]+[\s\S]{0,40}?select/i,
  /select[\s+%20]+[\s\S]{0,60}?[\s+%20]from[\s+%20]/i,
  /(%27|')/i,
  /(%22|")\s*(or|and)/i,
  /(sleep|benchmark|pg_sleep|dbms_pipe\.receive_message|waitfor[\s+%20]+delay)[\s(]/i,
  /information_schema|xp_cmdshell|load_file|extractvalue|updatexml|sleep\(/i,
  /(--|%2d%2d|\/\*!|#)\s*$|(--)|(\/\*)/,
  /;\s*(drop|insert|update|delete|select|create)\b/i,
  /\bor\b[\s%20+]+1[\s%20+]*=[\s%20+]*1|\band\b[\s%20+]+1[\s%20+]*=[\s%20+]*1/i,
];

// [P1-FIX 2026-09-08] 「自己把目标准确地弄报错」与「目标本身在报错」必须区分。
// 背景：error 技术的工作方式就是让 DB 抛语法错，真实靶场（sqli-labs 风）里太半 payload
// 都回 500；若把这些 5xx 计入 serverErrRatio，则「扫到了洞但满屏 500」会被误判成 target_error，
// 于是每次正常扫描都弹「结论不可信」——告警疲劳一旦形成，真被封时有谁会看。
// 判据：注入形态请求 + 响应体带 SQL 报错签名 → 归为 selfInflicted（计入报告但不参与状态裁定）。
//
// [P1-B 2026-10-03] 与 engine 侧 `ERROR_SIG`（`engine/payloads/index.js`，2026-10-01 收紧）对齐。
// 上一版只有 9 条形态，漏掉 MySQL `extractvalue`/`updatexml` 的「XPATH syntax error」、
// SQLite 原生 `near "x": syntax error`、DB2 `SQL0104N` 等**真实报错**形态。
// 后果是一条静默的误判链：error-based 用 extractvalue 打有洞目标 → 500 里全是 XPATH 报错
// → 本签名不命中 → 未归 selfInflicted → 计入 serverErrRatio → 被判 target_error /「结论不可信」
// —— 正是本 Fix 要防的那件事，却在 payload 收紧了签名之后从这里漏了回来。
//
// 两侧是**同一个语义需求**（「响应体在说这是数据库报错」），故此处补齐为 ERROR_SIG 的同集；
// 由 `tests/errorSig.specificity.test.js` 的漂移守卫钉死：同一 REAL_ERRORS 语料两侧必须一致命中、
// 同一 GENERIC_PAGES 语料两侧必须一致不命中。改一侧不改另一侧 → 该测试立刻红。
export const SQL_ERROR_SIG =
  /(SQL syntax|syntax error at or near|near\s+["'][^\n]{0,80}?["']\s*:\s*syntax error|XPATH syntax error|extractvalue|updatexml|mysql_fetch|ORA-\d{5}|PG::|PostgreSQL.*ERROR|sqlite3\.|SQLSTATE\s*\[|unclosed quotation|incorrect syntax near|unrecognized token|Microsoft SQL Server|conversion failed|unknown column|Division by zero|SQL\d{4}[NRT]|DB2 SQL Error|Adaptive Server|Sybase\s*(?:error|message)|SQL error code|Firebird.*(?:error|exception)|isc_\d+|Informix\s+SQL|JdbcSQLException|org\.h2\.jdbc|org\.hsqldb|org\.apache\.derby|Syntax error in SQL statement|Syntax error: Encountered|Cannot parse|Microsoft Access|Jet.*Database|ODBC|MonetDB.*(?:error|exception)|MonetDB\s+\d{5})/i;

// 状态严重度排序（越大越严重）：判定与粘滞共用同一优先级。
// [D32] transform_rejected 排在 blocked 之上：blocked 是「对面有 WAF 挡着」（至少请求合法、
// 判定素材真实存在，只是被中间设备吃掉）；transform_rejected 是「我们自己发出的东西不合法」
// ⇒ 整轮一个注入都没抵达业务逻辑，阴性结论的失效程度更彻底，必须盖过其它标签显示出来。
const SEVERITY = {
  ok: 0,
  target_error: 1,
  session_expired: 2,
  blocked: 3,
  unreachable: 4,
  transform_rejected: 5,
};

// [2026-09-29 收敛] getHeader 全仓唯一实现在 core/getHeader.js（此前本文件、blockPolicy、
// WafIdentifier 三处各持一份且已漂移）。这里导入供本模块自用，并原样再导出保住既有引用路径。
import { getHeader } from './getHeader.js';
export { getHeader };

/**
 * 取响应状态码：无响应/无 status 一律视为 0（「请求失败」而非「某个 HTTP 结论」）。
 * @param {{status?: number}|null|undefined} res
 * @returns {number}
 */
export function pickStatus(res) {
  const n = Number(res?.status);
  return Number.isFinite(n) ? n : 0;
}

/**
 * 是否为「被拦截」响应：状态码命中拦截集合，或 4xx/5xx 且响应体含通用拦截特征。
 * 关键防误判：文案匹配只在 status>=400 时生效——200 页面里出现「安全验证/防火墙」
 * （帮助文档、产品名、验证码组件）不得判为拦截。
 * @param {{status?: number, data?: any, body?: any, headers?: object}|null} res
 * @returns {boolean}
 */
export function isBlockedResponse(res) {
  if (!res) return false;
  const status = pickStatus(res);
  if (status === 0) return false; // 请求失败不是拦截，属 unreachable 语义
  if (BLOCK_STATUSES.has(status)) return true;
  if (status < 400) return false;
  const text = String(res.data ?? res.body ?? '');
  if (!text) return false;
  return GENERIC_BLOCK_SIG.test(text);
}

/**
 * [D32 实战 P0-1] 是否为「这个请求本身被目标判为非法」：400 / 415 / 422。
 *
 * 为什么单列一族（而不是并进 isBlockedResponse）：签名/加密型接口拒绝被改过的请求时，
 * 回的是**应用层**的「请求非法 / 签名错误」（400 系），不是中间设备的拦截页（403/406/429/503）。
 * 两者含义完全不同：后者要人去对付 WAF，前者要人去修自己的签名脚本。
 * 故意不收 401/403（认证与拦截各有各的既有判定）、不收 404（path 段的 404 是正常产物，
 * 收进来会把大量真实扫描判成签名被拒）。
 * @param {{status?: number}|null} res
 * @returns {boolean}
 */
export function isRequestReject(res) {
  if (!res) return false;
  return REQUEST_REJECT_STATUSES.has(pickStatus(res));
}

/**
 * 是否为「会话失效」跳转：302/303 且 Location 命中登录页/CAS/SSO 特征。
 * @param {{status?: number, headers?: object}|null} res
 * @returns {boolean}
 */
export function isLoginRedirect(res) {
  if (!res) return false;
  const status = pickStatus(res);
  if (status !== 302 && status !== 303) return false;
  const loc = getHeader(res.headers, 'location');
  return !!loc && LOGIN_REDIRECT_SIG.test(loc);
}

/**
 * 请求是否为「注入请求」（携带 payload 特征）。
 * @param {{url?: string, method?: string, data?: any, body?: any, params?: any}|string|null} req
 * @returns {boolean}
 */
export function looksLikeInjection(req) {
  if (!req) return false;
  const raw = typeof req === 'string' ? req : req.url;
  let hay = String(raw ?? '');
  if (typeof req !== 'string') {
    const body = req.data ?? req.body ?? req.params;
    if (body != null) {
      try {
        hay += ' ' + (typeof body === 'string' ? body : JSON.stringify(body));
      } catch {
        /* 循环引用等：忽略 body，仅按 URL 判定 */
      }
    }
  }
  if (!hay.trim()) return false;
  return INJECTION_SIGS.some((re) => re.test(hay));
}

/**
 * 解析 Retry-After（秒数或 HTTP-date）为毫秒。
 * @param {string|number|null|undefined} value
 * @param {number} [nowMs] 解析 HTTP-date 时的「现在」（便于单测注入）
 * @returns {number|null} 无法解析返回 null
 */
export function parseRetryAfterMs(value, nowMs = Date.now()) {
  if (value == null || value === '') return null;
  const secs = Number(value);
  if (Number.isFinite(secs)) return secs >= 0 ? Math.round(secs * 1000) : null;
  const at = Date.parse(String(value));
  if (!Number.isFinite(at)) return null;
  return Math.max(0, Math.round(at - nowMs));
}

/**
 * 是否为用户/框架触发的请求取消（stop() 打断在途请求）。
 * 这类失败与目标健康无关，计入会把「用户点了停止」误判成「目标不可达」。
 * @param {any} error
 * @returns {boolean}
 */
export function isCanceledError(error) {
  if (!error) return false;
  return (
    error.name === 'AbortError' ||
    error.name === 'CanceledError' ||
    error.code === 'ERR_CANCELED' ||
    error.code === 'ABORT_ERR'
  );
}

/**
 * [P0-FIX 2026-09-09] 判断是否「网络层失败」——失败发生在传输环节，而非目标返回了响应。
 * 这类失败**不能**被解释为「目标没有注入」：请求根本没到（或没回来）。
 * 覆盖 HttpClient 抛出的 AppError(HTTP_TIMEOUT=3001 / HTTP_ERROR=3002)、axios/undici 底层
 * errno，以及代理通道特有的 socket hang up 等文案。
 * @param {any} e
 * @returns {boolean}
 */
export function isNetworkFailureError(e) {
  if (!e) return false;
  if (isCanceledError(e)) return false; // 用户主动 stop 不算目标故障
  if (typeof e.code === 'number' && (e.code === 3001 || e.code === 3002)) return true;
  if (e.code && NET_ERRNO.has(String(e.code))) return true;
  const msg = String(e.message || '');
  return /socket hang up|ECONN|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|connection refused|timeout of/i.test(msg);
}

const NET_ERRNO = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'ECONNABORTED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH',
  'ENETUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPIPE', 'ERR_BAD_RESPONSE', 'UND_ERR_SOCKET',
  'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT',
]);

/**
 * 由窗口样本聚合出当前判定状态（纯函数，便于单测）。
 * @param {{failStreak:number, blockRatio:number, blockHits:number, serverErrRatio:number, samples:number,
 *          authLost:boolean, neverAuthenticated?: boolean, expiredMidScan?: boolean, cfg:object}} m
 * @returns {'ok'|'blocked'|'unreachable'|'session_expired'|'target_error'}
 */
export function evaluateStatus(m) {
  const cfg = { ...VALIDITY_DEFAULTS, ...(m.cfg || {}) };
  if (m.failStreak >= cfg.abortAfterFails) return 'unreachable';
  if (m.blockRatio >= cfg.blockRatio && m.blockHits >= cfg.blockMinHits) return 'blocked';
  // [D36] neverAuthenticated / expiredMidScan 与 authLost 落成同一个状态（session_expired）：
  // 三者处置同为"把凭据带对再复扫"，区别在**成因文案**——分支在 summary() 里按计数选。
  // 刻意排在 blocked 之后：满屏 403 的目标已有 blocked family 负责，而 403 不算认证挑战。
  if (m.neverAuthenticated || m.expiredMidScan || m.authLost) return 'session_expired';
  if (m.serverErrRatio >= cfg.serverErrRatio && m.samples >= cfg.minSamples) return 'target_error';
  return 'ok';
}

/**
 * [D32 实战 P0-1] 由变换计数判出签名被拒状态（纯函数，便于单测）。
 *
 * 两种成因必须分开（处置完全不同，reason 文案也分开）：
 *   'baseline'  —— 连**未注入**的基线请求都被拒 ⇒ 脚本本身与目标不匹配（密钥/字段集/编码顺序错了），
 *                  这一轮所有请求都是废的，继续扫只是白烧预算。
 *   'injection' —— 基线正常、只有注入了 payload 的请求被拒 ⇒ 脚本没覆盖被改的那个字段
 *                  （常见于只对内层明文签名、或签名串里漏了注入的那个参数）⇒ 注入值从未抵达 SQL。
 * @param {{baselineRejects:number, baselineRejectStreak:number, baselineOk:number,
 *          injectRejects:number, injectOk:number}} t
 * @param {{transformBaselineRejects:number, transformInjectRejects:number}} cfg
 * @returns {null|'baseline'|'injection'}
 */
export function evaluateTransformStatus(t, cfg) {
  if (t.baselineRejectStreak >= cfg.transformBaselineRejects && t.baselineOk === 0) return 'baseline';
  if (t.injectRejects >= cfg.transformInjectRejects && t.injectOk === 0) return 'injection';
  return null;
}

/**
 * 单次扫描的可信度守卫。
 * 用法：scanRunner 创建 → ctxBase.httpClient.request/headRequest 包装里 observe 回流。
 */
export class ScanValidityGuard {
  /**
   * @param {object} [opts] 覆盖阈值（windowSize/abortAfterFails/blockRatio/blockMinHits/
   *                        authStreak/serverErrRatio/minSamples）
   */
  constructor(opts = {}) {
    // [D32] transformActive / [D36] refreshActive 是布尔开关而不是阈值：必须在下面的 Number
    // 循环之前摘出来，否则 `Number(true) === 1 > 0` 会把它当成一个阈值塞进 cfg
    //（cfg 会被当可调参数读，且会随 counts 一起进报告）。
    this.transformActive = opts?.transformActive === true;
    this.refreshActive = opts?.refreshActive === true;
    const thresholds = { ...(opts || {}) };
    delete thresholds.transformActive;
    delete thresholds.refreshActive;
    this.cfg = { ...VALIDITY_DEFAULTS };
    for (const k of Object.keys(VALIDITY_DEFAULTS)) {
      const v = Number(thresholds?.[k]);
      if (Number.isFinite(v) && v > 0) this.cfg[k] = v;
    }
    this.total = 0; // 累计观察数（含窗口外），供报告展示「本次扫描共发多少请求」
    this.samples = []; // 滑动窗口样本：{ fail, blocked, serverErr, auth }
    this.failStreak = 0; // 连续失败（res==null 或 status===0）
    this.maxFailStreak = 0; // 最长连续失败（粘滞展示用：目标恢复后 failStreak 会归零，但结论需保留真实峰值）
    this._abortLogged = false; // 已因连续失败/命中熔断而记录过一次中止事件（避免重复打日志）
    this.blockHits = 0; // 累计拦截命中
    this.serverErr = 0; // 累计 5xx（已排除「自己触发的 SQL 报错」）
    this.injection5xx = 0; // 注入请求引发的 5xx 总数：不参与状态裁定，但必须进报告（我们确实把目标打报错了几次）
    this.authLostHits = 0; // 累计「注入请求 401/登录跳转」命中
    this.baselineAuthHits = 0; // 基线（非注入）请求也 401/跳登录 的次数 → 反证「整站要认证」
    // [D36 实战 P0-3] 「有没有一次请求真的进到业务逻辑」的证据位点：
    //   authChallengeHits = 401 或跳登录页的次数（不分注入/基线）
    //   nonChallengeHits  = 有响应且不是认证挑战的次数（2xx/3xx/4xx 非 401/5xx 都算——
    //                       目标是「应用层在回应我们」，哪怕回 404 也证明过了认证这道门）
    // 两者一起把「整站要凭据而我们没有」与「扫描中途会话过期」分开：前者 baselineAuthHits>0
    // 会把既有 authLost 判据的反证挡掉（那是刻意如此，避免把"缺凭据"写成"会话过期"），
    // 但挡掉反证之后**没有第二条判据接住它** —— 实测就落成 ok + 可信 + 未检出。
    this.authChallengeHits = 0;
    this.nonChallengeHits = 0;
    this.authChallengeStreak = 0; // **不分注入与否**的连续认证挑战次数（中途失效的判据素材）
    this.neverAuthenticated = false; // 整轮零业务响应（缺凭据）
    this.expiredMidScan = false; // 有过业务响应，但此后连续 N 次都是认证挑战（中途失效）
    this._authStreak = 0; // 注入请求连续认证失败次数
    this.lastRetryAfterMs = null; // 最近一次拦截响应的 Retry-After（毫秒）
    this.stickyStatus = 'ok'; // 已成立的最严重状态（粘滞，恢复不回滚）
    this.stickySnapshot = null; // 该状态成立时的计数快照（reason 文案取用，保证数字与结论同源）
    this.inconclusive = []; // 因守卫中止而未完成有效检测的点 id
    this.inconclusiveSeen = new Set();
    // [P0-FIX 2026-09-09] 因网络层失败（连接失败/超时/代理不可用）而未完成有效检测的点。
    // 与「守卫熔断导致未决」区分开：熔断已经把状态推到 unreachable/blocked，而零星网络失败
    // 不会触发任何阈值——过去它们被 runLayer 的 catch 吞成「已检测、无漏洞」，是假阴性主因。
    this.netErrPoints = [];
    this.netErrSeen = new Set();
    // [D32 实战 P0-1] 自定义请求变换（签名/加密参数）生效时才启用的一族计数。
    // transformActive=false（未用扩展点）⇒ observeTransform 直接返回，存量判定路径零改动。
    this.transform = {
      baselineRejects: 0, // 基线（未注入）请求被判非法的次数
      baselineRejectStreak: 0, // 连续次数（用连续而非总数：脚本配错是系统性故障，2 条足以定性）
      baselineOk: 0, // 基线请求成功过 → 反证「脚本没配错」，此时只有注入被拒才是签名覆盖不全
      injectRejects: 0,
      injectOk: 0,
      netErr: 0, // 传输层失败单独记账：不得算进「被拒」（连不上 ≠ 签名错）
      /** @type {'baseline'|'injection'|null} 成因（两种处置不同，文案也分开） */
      kind: null,
    };
    // [D36 实战 P0-2] Bearer 续期的结果计数（只有配了 bearerRefresh 才会被喂）。
    // 存在的意义：配错续期端点 = 后半程全 401，而 session_expired 的默认建议是
    // "重新登录并携带有效 Cookie" —— 那会把人支到手工抓包上去，而真正该修的是这个端点。
    this.refresh = { attempts: 0, successes: 0, failures: 0, lastWhy: '' };
  }

  /** 窗口内聚合比例 */
  _ratios() {
    const n = this.samples.length;
    if (!n) return { blockRatio: 0, serverErrRatio: 0, samples: 0 };
    let blocked = 0;
    let serverErr = 0;
    for (const s of this.samples) {
      if (s.blocked) blocked += 1;
      if (s.serverErr) serverErr += 1;
    }
    return { blockRatio: blocked / n, serverErrRatio: serverErr / n, samples: n };
  }

  /**
   * 回流观察一次请求结果。成功传 res；抛错/返回 null 传 error（或 res=null）。
   * 永不抛异常——守卫故障绝不能影响检测主流程。
   * @param {{req?: object, res?: object|null, error?: any}} ev
   * @returns {void}
   */
  observe(ev = {}) {
    const { req = null, res = null, error = null } = ev || {};
    if (error && isCanceledError(error)) return; // 用户 stop() 取消，不计入目标健康
    this.total += 1;
    const status = pickStatus(res);
    const failed = !res || status === 0 || !!error;
    const blocked = !failed && isBlockedResponse(res);
    const serverErr = !failed && status >= 500 && status <= 599;
    const authHit = !failed && (status === 401 || isLoginRedirect(res));
    const injection = looksLikeInjection(req);
    // 自己触发的 SQL 报错（error 技术的正常产物）不计入「目标处于错误状态」
    const selfInflicted =
      serverErr && injection === true && SQL_ERROR_SIG.test(String(res?.data ?? ''));
    // 只统计「被我们排除掉的那部分」：与 serverErr 互斥，不重复计数（两者相加 = 全部 5xx）
    this.injection5xx += selfInflicted ? 1 : 0;

    if (failed) this.failStreak += 1;
    else this.failStreak = 0; // 任一成功响应即清零
    if (this.failStreak > this.maxFailStreak) this.maxFailStreak = this.failStreak;

    if (blocked) {
      this.blockHits += 1;
      const ra = parseRetryAfterMs(getHeader(res?.headers, 'retry-after'));
      if (ra != null) this.lastRetryAfterMs = ra;
    }
    if (serverErr && !selfInflicted) this.serverErr += 1;
    // [D36] 认证挑战/业务响应分账（不分注入与否）—— 与上面 authHit 的三本账各自独立：
    //   authLostHits/baselineAuthHits 服务既有的"注入请求中途过期"判据；
    //   这三本服务另外两种形态：从来没进去过 / 进去过之后整段出不去了。
    if (authHit) {
      this.authChallengeHits += 1;
      this.authChallengeStreak += 1;
    } else if (!failed) {
      // 403/404/5xx 都算"应用在回应"，不是认证问题 ⇒ 连续挑战段清零
      this.nonChallengeHits += 1;
      this.authChallengeStreak = 0;
    }
    if (authHit) {
      if (injection) {
        this._authStreak += 1;
        this.authLostHits += 1;
      } else {
        // 基线请求也掉进认证页 → 不是「扫描会话过期」，是目标整体要求认证
        this.baselineAuthHits += 1;
      }
    } else if (injection && !failed) {
      this._authStreak = 0; // 注入请求恢复正常 → 连续段清零
    }

    this.samples.push({ fail: failed, blocked, serverErr: serverErr && !selfInflicted, auth: authHit });
    while (this.samples.length > this.cfg.windowSize) this.samples.shift();

    const r = this._ratios();
    const authLost = this._authStreak >= this.cfg.authStreak && this.baselineAuthHits === 0;
    // [D36 实战 P0-3] 既有 authLost 只覆盖「注入请求被打回而基线请求没有」这一种形态，
    // 而 bearer-lab 实测到的两种更常见失效都从它手底漏过去，且都落成「未检出 + 结论可信」：
    //   ① neverAuthenticated：整轮没有一次业务响应（全 401/跳登录）。baselineAuthHits>0 把旧判据
    //      的反证挡住是对的（那是缺凭据，不是会话过期），但挡住之后没人接手。
    //   ② expiredMidScan：进去过，此后**连续** N 次出不去（不分注入与否）。旧判据要求"基线不 401"，
    //      而令牌一旦过期，基线请求同样吃 401 ⇒ 反证恒成立 ⇒ 那条判据在这类目标上**永不可达**。
    // 两条的失效方向都只会把"没测到"说成"不可信"，不会反向。
    this.neverAuthenticated =
      this.nonChallengeHits === 0 && this.authChallengeHits >= this.cfg.unauthMinRequests;
    this.expiredMidScan =
      this.nonChallengeHits > 0 && this.authChallengeStreak >= this.cfg.authStreakAll;
    const nextStatus = evaluateStatus({
      failStreak: this.failStreak,
      blockRatio: r.blockRatio,
      blockHits: this.blockHits,
      serverErrRatio: r.serverErrRatio,
      samples: r.samples,
      authLost,
      neverAuthenticated: this.neverAuthenticated,
      expiredMidScan: this.expiredMidScan,
      cfg: this.cfg,
    });
    // 粘滞：取历史最严重状态；新状态更严重时冻结其计数快照
    this._stick(nextStatus, r);
  }

  /**
   * 粘滞登记（observe 与 observeTransform 共用同一条优先级规则，避免两处各写一份而漂移）。
   * @param {string} nextStatus
   * @param {{blockRatio:number, serverErrRatio:number, samples:number}} r
   */
  _stick(nextStatus, r) {
    if (SEVERITY[nextStatus] > SEVERITY[this.stickyStatus]) {
      this.stickyStatus = nextStatus;
      this.stickySnapshot = this._counters(r);
    }
  }

  _counters(r) {
    return {
      total: this.total,
      failStreak: this.failStreak,
      blockHits: this.blockHits,
      serverErr: this.serverErr,
      injection5xx: this.injection5xx,
      authLostHits: this.authLostHits,
      // [D36] 「从来没进去过」的两本账 + 判定位点（跟着快照冻结，理由同 failStreak 峰值）
      authChallengeHits: this.authChallengeHits,
      nonChallengeHits: this.nonChallengeHits,
      authChallengeStreak: this.authChallengeStreak,
      neverAuthenticated: this.neverAuthenticated === true,
      expiredMidScan: this.expiredMidScan === true,
      blockRatio: r ? r.blockRatio : 0,
      serverErrRatio: r ? r.serverErrRatio : 0,
      samples: r ? r.samples : 0,
      windowSize: this.cfg.windowSize,
      // [D32] 变换计数随快照一起冻结：结论与数字同源（事后恢复不会把「连基线都被拒」洗白）
      transform: { ...this.transform },
      // [D36] 续期计数（未启用时全 0，字段恒存在 —— 报告契约不随配置漂移）
      refresh: { ...this.refresh },
    };
  }

  /**
   * [D36 实战 P0-2] 观察一次 Bearer 续期的结果（由 bearerKeeper 回传）。
   * 只记账、不改状态：会话失效本身仍由既有 authLost 机制判（续期失败后 401 会照常积累），
   * 本计数的作用是让 `session_expired` 的文案指准 —— "配了续期端点却没拿到 token"
   * 和"没人配续期、会话过期了"是两种完全不同的处置。
   * @param {{ok?: boolean, why?: string, status?: number}} ev
   */
  observeRefresh(ev = {}) {
    if (!this.refreshActive) return;
    this.refresh.attempts += 1;
    if (ev.ok === true) {
      this.refresh.successes += 1;
      return;
    }
    this.refresh.failures += 1;
    this.refresh.lastWhy = String(ev.why || '未知原因');
  }

  /**
   * [D32 实战 P0-1] 观察一条「已经过自定义请求变换」的请求结果。
   *
   * 素材由变换层在**加密/签名之前**打标（`injected`）—— 整包加密后 looksLikeInjection
   * 在密文上恒为 false，靠请求内容已经分不出基线与注入，而那正是本判据的核心区分。
   *
   * 这条通道只更新 transform 一族计数，不写入共享滑动窗口 samples ⇒
   * 同一条请求被 ctxBase 的 observe() 与本方法各看一次，两次职责不重叠，
   * 既有 blocked/target_error/session_expired 的阈值语义完全不受影响。
   * @param {{injected?: boolean, res?: object|null, error?: any}} ev
   */
  observeTransform(ev = {}) {
    if (!this.transformActive) return;
    const { res = null, error = null } = ev || {};
    if (error && isCanceledError(error)) return; // 用户 stop() 取消，与签名无关
    const status = pickStatus(res);
    if (!res || status === 0 || error) {
      this.transform.netErr += 1;
      return; // 传输失败不是「被目标判非法」，两件事不许混
    }
    const t = this.transform;
    const rejected = isRequestReject(res);
    if (ev.injected === true) {
      if (rejected) {
        t.injectRejects += 1;
      } else {
        t.injectOk += 1;
      }
      // 基线一旦成功过，说明脚本本身能用 ⇒ 基线连续段清零，改由 injection 成因判定
    } else {
      if (rejected) {
        t.baselineRejects += 1;
        t.baselineRejectStreak += 1;
      } else {
        t.baselineOk += 1;
        t.baselineRejectStreak = 0;
      }
    }
    const kind = evaluateTransformStatus(t, this.cfg);
    if (!kind) return;
    t.kind = kind;
    this._stick('transform_rejected', this._ratios());
  }

  /**
   * 记录一个「因守卫中止而未完成有效检测」的注入点 id。
   * @param {string} pointId
   */
  addInconclusive(pointId) {
    const id = String(pointId ?? '');
    if (!id || this.inconclusiveSeen.has(id)) return;
    this.inconclusiveSeen.add(id);
    this.inconclusive.push(id);
  }

/**
 * [P0-FIX 2026-09-09] 记录一个「因网络层失败未完成有效检测」的注入点。
   * 语义：该点的阴性结论不成立——失败的是传输，不是「目标没有注入」。
   * @param {string} pointId
   */
  addNetworkErrorPoint(pointId) {
    const id = String(pointId ?? '');
    if (!id) return;
    if (!this.netErrSeen.has(id)) {
      this.netErrSeen.add(id);
      this.netErrPoints.push(id);
    }
    this.addInconclusive(id);
  }
  /**
   * 是否应中止剩余注入点检测。
   * [D32] transform_rejected 也中止：签名/加密不匹配时后面每一条请求都必然同样被拒，
   * 继续跑只是白烧预算，而且会把「一个合法注入都没送达」的扫描写成满屏「未检出」。
   * @returns {boolean}
   */
  get shouldAbort() {
    return this.stickyStatus === 'unreachable' || this.stickyStatus === 'transform_rejected';
  }

  /**
   * 取走并清空「目标要求的退避时长」（Retry-After）。
   * 为什么需要 consume：调度循环在每个注入点开始前取一次，若不取同一段时长会被每个点重复
   * 触发（多点位目标上相等于把整次扫描拖成 N × Retry-After）。取完即清，一次 429 只退避一次。
   * @param {number} [maxMs] 上限（默认 30s，防目标准成意用大 Retry-After 把扫描卡住）
   * @returns {number} 毫秒；0 表示无需等待
   */
  consumeBackoffMs(maxMs = 30000) {
    const v = Number(this.lastRetryAfterMs) || 0;
    this.lastRetryAfterMs = null;
    if (v <= 0) return 0;
    return Math.min(v, maxMs);
  }

  /**
   * 报告/前端消费的固定契约（字段名不得改）。
   * @returns {{status:string, reliable:boolean, reason:string, counts:object, blockRatio:number,
   *            suggestBackoffMs:number|null, inconclusivePoints:string[], advice:string}}
   */
  summary() {
    const r = this._ratios();
    const status = this.stickyStatus;
    // 计数优先取「状态成立那一刻」的快照（结论与数字同源，事后恢复不会把数字洗白），
    // 但 total/inconclusivePoints 始终反映整次扫描。
    const base = this.stickySnapshot || this._counters(r);
    // unreachable 的连续失败次数取「历史峰值」：目标稍后恢复不会把「挂了 40 次」洗成「挂了 10 次」
    const failStreak = status === 'unreachable' ? Math.max(base.failStreak | 0, this.maxFailStreak) : base.failStreak;
    const counts = {
      total: this.total,
      failStreak,
      blockHits: base.blockHits,
      serverErr: base.serverErr,
      // 自身触发的 5xx 单独透出来：不拉高可信度告警，但让使用者看见「本次让目标报错了多少次」
      injection5xx: this.injection5xx,
      authLostHits: base.authLostHits,
      // [D36] 认证挑战与业务响应的账（summary 的 session_expired 分支据此选文案）
      authChallengeHits: base.authChallengeHits ?? this.authChallengeHits,
      nonChallengeHits: base.nonChallengeHits ?? this.nonChallengeHits,
      authChallengeStreak: base.authChallengeStreak ?? this.authChallengeStreak,
      neverAuthenticated: base.neverAuthenticated === true,
      expiredMidScan: base.expiredMidScan === true,
      // 「网络失败导致未测」的点数：哪怕整体状态 ok，这几个点的阴性结论也不成立
      netErrPoints: this.netErrPoints.length,
      // [D32] 自定义请求变换的计数（未启用时全 0，字段仍固定存在 —— 报告契约不随配置漂移）
      transform: base.transform || { ...this.transform },
      // [D36] Bearer 续期计数
      refresh: base.refresh || { ...this.refresh },
    };
    const netErrCount = this.netErrPoints.length;
    const blockRatio = round2(base.blockRatio ?? r.blockRatio);
    const win = base.windowSize || this.cfg.windowSize;
    let reason;
    let advice;
    switch (status) {
      case 'unreachable':
        reason = `目标连续 ${counts.failStreak} 次请求无有效响应（连接失败/超时/空响应），累计 ${counts.total} 次请求中无任何成功回包`;
        advice = '先确认目标存活与网络可达（浏览器直开、curl 同 URL）再复扫；复扫时降并发（concurrency=1）与速率（ratePerSec≤2）并加大超时；本次「未检出」不可作为无漏洞结论';
        break;
      case 'blocked':
        reason = `近 ${win} 次请求中拦截特征 ${counts.blockHits} 次（403/406/429/503 或拦截页文案），窗口拦截占比 ${blockRatio}`;
        // ⚠ 与 bearerKeeper 的判据差异在这里必须说清，否则会把人支到错误方向：
        //   本守卫的 session_expired 只认 401/跳转登录页（403 归 blocked 族，两者不可混），
        //   而**很多 Bearer 目标用 403 表达"令牌过期"** ⇒ 那类目标续期失败后落点是 blocked 而不是 session_expired。
        //   所以配了续期又失败时，这里必须提一句"先看续期链路"，让人知道 403 未必是 WAF。
        advice = (counts.refresh && counts.refresh.attempts > 0 && counts.refresh.failures > 0)
          ? `本次配了 Bearer 自动续期但失败 ${counts.refresh.failures} 次（最后一次：${counts.refresh.lastWhy || '原因未记录'}）——`
            + '目标用 403 表达令牌过期时，上面的拦截特征其实是会话失效，先修 bearerRefresh.url/tokenField 再谈 WAF 规避；'
            + '确属 WAF 时：降速并加抖动（ratePerSec≤1、jitterMs>0）、套用 tamper 规避链，申请把扫描源 IP 加白或换时段复扫；被拦请求对应的点应视为未测'
          : '疑似 WAF/封 IP：降速并加抖动（ratePerSec≤1、jitterMs>0）、套用 tamper 规避链；申请把扫描源 IP 加入 WAF 白名单或换时段复扫；被拦请求对应的点应视为未测';
        break;
      case 'session_expired': {
        const rf = counts.refresh || {};
        // 三种形态（都归 session_expired，因为处置同为"把凭据带对再复扫"），但必须说清是哪一种：
        //   ① neverAuthenticated —— 整轮没有一次业务响应：这扫描从头到尾不在已认证状态下；
        //   ② expiredMidScan —— 进去过、此后连续出不去：这才是"中途过期"，也是续期该救的场景；
        //   ③ 既有 authLost —— 注入被打回而基线没有（旧口径，一条字都不改，防既有报告漂移）。
        if (counts.neverAuthenticated) {
          reason =
            `本次 ${counts.total} 次请求里 ${counts.authChallengeHits} 次被认证层挡回（401 或跳转登录页），` +
            `而**没有任何一次得到过业务响应** —— 不是扫描中途过期，是这次扫描从头到尾都不在已认证状态下，` +
            `检测逻辑一次都没被执行到` +
            (rf.attempts > 0
              ? `；本次已配 Bearer 自动续期，但续期尝试 ${rf.attempts} 次里失败 ${rf.failures} 次`
                + `（最后一次：${rf.lastWhy || '原因未记录'}）`
              : '');
          advice = rf.attempts > 0
            ? '先修续期链路：核对 bearerRefresh.url 是否可达、要不要额外凭据（refreshToken 未配时目标常从 Cookie 取，'
              + '确认会话 jar 带得到）、以及 tokenField 是否指向响应里真有的字段（本条 reason 已给出响应顶层键）；'
              + '修好前本次「未检出」不成立 —— 所有请求根本没被当成已认证流量'
            : '这次扫描从未带上目标认得的凭据：改用 --auth / --header（抓包里的 Authorization）/ --cookie，'
              + '或直接用 requestFile 原始请求包（-r）复扫；目标是 Bearer+refresh 形态则配 config.bearerRefresh / '
              + '--refresh-url 让工具自动续期。补上凭据前本次「未检出」不构成任何结论 —— 全部请求都被挡在业务逻辑之外';
        } else if (counts.expiredMidScan) {
          reason =
            `前 ${counts.nonChallengeHits} 次请求得到过业务响应，此后**连续 ${counts.authChallengeStreak} 次**`
            + `被认证层挡回（401 或跳转登录页，不分注入与基线请求）—— 会话/令牌在扫描进行中失效，`
            + `后半程的检测全部发生在未认证状态下` +
            (rf.attempts > 0
              ? `；本次已配 Bearer 自动续期，但续期尝试 ${rf.attempts} 次里失败 ${rf.failures} 次`
                + `（最后一次：${rf.lastWhy || '原因未记录'}）`
              : '');
          advice = rf.attempts > 0
            ? '先修续期链路：核对 bearerRefresh.url 是否可达、要不要额外凭据（refreshToken 未配时目标常从 Cookie 取，'
              + '确认会话 jar 带得到）、以及 tokenField 是否指向响应里真有的字段（本条 reason 已给出响应顶层键）；'
              + '修好前本次「未检出」不成立 —— 后半程请求根本没被当成已认证流量'
            : '令牌/会话在扫描中途过期：Bearer+refresh 形态配 config.bearerRefresh / --refresh-url 让工具自动续期，'
              + '表单登录配 config.login / --login-url 让工具自动重登；否则请缩短单次扫描规模或换有效期更长的凭据复扫。'
              + '后半程的阴性结论不成立（那些请求根本没进业务逻辑）';
        } else {
          reason = rf.attempts > 0
            ? `注入请求连续 ${this.cfg.authStreak}+ 次返回 401 或跳转登录页（累计 ${counts.authLostHits} 次）；`
              + `本次已配 Bearer 自动续期，但续期尝试 ${rf.attempts} 次里失败 ${rf.failures} 次`
              + `（最后一次：${rf.lastWhy || '原因未记录'}）—— 会话维持没有真正建立`
            : `注入请求连续 ${this.cfg.authStreak}+ 次返回 401 或跳转登录页（累计 ${counts.authLostHits} 次），而基线请求未出现该特征，判定会话已失效`;
          advice = rf.attempts > 0
            ? '先修续期链路：核对 bearerRefresh.url 是否可达、要不要额外凭据（refreshToken 未配时目标常从 Cookie 取，'
              + '确认会话 jar 带得到）、以及 tokenField 是否指向响应里真有的字段（本条 reason 已给出响应顶层键）；'
              + '修好前本次「未检出」不成立 —— 后半程请求根本没被当成已认证流量'
            : '重新登录并携带有效 Cookie/Authorization（config.cookie 或 requestFile 原始包）后复扫；未认证状态下的「未检出」不成立，需带外验证登录态（若目标是 Bearer+refresh 形态，可配 config.bearerRefresh / --refresh-url 让工具自动续期）';
        }
        break;
      }
      case 'target_error':
        reason = `近 ${win} 次请求中 5xx 共 ${counts.serverErr} 次（占比 ${round2(base.serverErrRatio)}），目标自身处于错误状态`;
        advice = '先看目标应用日志/DB 连接池，确认服务健康后复扫；5xx 期间的响应差异无判定意义（若同时命中 dbHealth 熔断，先降并发避免持续伤害）';
        break;
      case 'transform_rejected': {
        const t = counts.transform || {};
        reason = t.kind === 'baseline'
          ? `自定义请求变换（签名/加密）产出的请求中，连**未注入的基线请求**都连续 ${t.baselineRejectStreak} 次被目标判非法` +
            `（400/415/422，累计 ${t.baselineRejects} 次且从未成功）—— 脚本与目标不匹配，本次一个合法请求都没送达业务逻辑`
          : `自定义请求变换生效下，基线请求正常而注入请求 ${t.injectRejects} 次全部被目标判非法` +
            '（400/415/422）—— 注入值破坏了签名/加密，payload 从未抵达 SQL 拼接点';
        advice = t.kind === 'baseline'
          ? '核对变换脚本的密钥、参与签名的字段集合与拼接顺序（拿一次真实抓包逐字节对：脚本产出的报文必须与浏览器/客户端发出的等价）；' +
            '修好前本次「未检出」不成立，不得写进交付结论'
          : '把被注入的参数纳入签名范围（或在明文层注入、由脚本重新加密整包后重算签名）；' +
            '本次「未检出」不等于「无漏洞」——这些请求在目标校验层就被拒了，检测从未开始';
        break;
      }
      default:
        reason = `目标可达性与会话状态正常：累计 ${counts.total} 次请求，无连续失败/拦截/会话失效/持续 5xx 迹象`;
        advice = '无需处置';
        break;
    }
    // [P0-FIX 2026-09-09] 零星网络失败不改变 status（阈值体系不动），但可靠度必须降级：
    // 有 N 个点「没测成」却报「无漏洞」，是把传输故障写成安全结论。
    if (status === 'ok' && netErrCount > 0) {
      reason =
        `${netErrCount} 个注入点因网络层失败（连接被拒/超时/代理不可用/空响应）未完成有效检测，` +
        `累计 ${counts.total} 次请求；这些点的「未检出」不等于「无漏洞」`;
      advice =
        '确认目标可达与出口路径（本机代理/NO_PROXY、VPN、DNS）后对未决点复扫；' +
        '复扫时可降并发（concurrency=1）、加大超时（timeoutMs）；报告里 netErrPoints 列出了具体点';
    }
    return {
      status,
      reliable: status === 'ok' && netErrCount === 0,
      reason,
      counts,
      blockRatio,
      // 观察到过 Retry-After 就原样透出（不仅限 blocked：ok 状态下的 429 同样值得提示降速）
      suggestBackoffMs: this.lastRetryAfterMs,
      inconclusivePoints: [...this.inconclusive],
      advice,
    };
  }
}

function round2(n) {
  return Math.round((Number(n) || 0) * 100) / 100;
}

export default ScanValidityGuard;
