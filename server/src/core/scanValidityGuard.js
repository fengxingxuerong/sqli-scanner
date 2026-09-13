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
  serverErrRatio: 0.8, // 窗口内 5xx 占比阈值
  minSamples: 10, // 比例类判定的最小样本数
};

// 明确的拦截状态码：403 Forbidden / 406 不可接受（ModSecurity 常用）/
// 429 限速封禁 / 503 服务不可用（WAF 过载拦截常以此返回）。
export const BLOCK_STATUSES = new Set([403, 406, 429, 503]);

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
export const SQL_ERROR_SIG =
  /(SQL syntax|syntax error at or near|ORA-\d{5}|PG::|sqlite3\.|SQLSTATE|unclosed quotation|incorrect syntax near|unrecognized token)/i;

// 状态严重度排序（越大越严重）：判定与粘滞共用同一优先级。
const SEVERITY = { ok: 0, target_error: 1, session_expired: 2, blocked: 3, unreachable: 4 };

/**
 * 大小写不敏感取响应头（axios headers 可能是 AxiosHeaders / 普通对象 / Map 样对象）。
 * @param {object} headers
 * @param {string} key
 * @returns {string|undefined}
 */
export function getHeader(headers, key) {
  if (!headers || typeof headers !== 'object') return undefined;
  const target = String(key).toLowerCase();
  if (typeof headers.get === 'function') {
    const v = headers.get(target);
    if (v != null) return String(v);
  }
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === target) return v == null ? undefined : String(v);
  }
  return undefined;
}

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
 * @param {{failStreak:number, blockRatio:number, blockHits:number, serverErrRatio:number, samples:number, authLost:boolean, cfg:object}} m
 * @returns {'ok'|'blocked'|'unreachable'|'session_expired'|'target_error'}
 */
export function evaluateStatus(m) {
  const cfg = { ...VALIDITY_DEFAULTS, ...(m.cfg || {}) };
  if (m.failStreak >= cfg.abortAfterFails) return 'unreachable';
  if (m.blockRatio >= cfg.blockRatio && m.blockHits >= cfg.blockMinHits) return 'blocked';
  if (m.authLost) return 'session_expired';
  if (m.serverErrRatio >= cfg.serverErrRatio && m.samples >= cfg.minSamples) return 'target_error';
  return 'ok';
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
    this.cfg = { ...VALIDITY_DEFAULTS };
    for (const k of Object.keys(VALIDITY_DEFAULTS)) {
      const v = Number(opts?.[k]);
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
    const nextStatus = evaluateStatus({
      failStreak: this.failStreak,
      blockRatio: r.blockRatio,
      blockHits: this.blockHits,
      serverErrRatio: r.serverErrRatio,
      samples: r.samples,
      authLost,
      cfg: this.cfg,
    });
    // 粘滞：取历史最严重状态；新状态更严重时冻结其计数快照
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
      blockRatio: r ? r.blockRatio : 0,
      serverErrRatio: r ? r.serverErrRatio : 0,
      samples: r ? r.samples : 0,
      windowSize: this.cfg.windowSize,
    };
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
  /** 是否应中止剩余注入点检测（仅「目标彻底不可达」才中止，其余状态只标注） */
  get shouldAbort() {
    return this.stickyStatus === 'unreachable';
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
      // 「网络失败导致未测」的点数：哪怕整体状态 ok，这几个点的阴性结论也不成立
      netErrPoints: this.netErrPoints.length,
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
        advice = '疑似 WAF/封 IP：降速并加抖动（ratePerSec≤1、jitterMs>0）、套用 tamper 规避链；申请把扫描源 IP 加入 WAF 白名单或换时段复扫；被拦请求对应的点应视为未测';
        break;
      case 'session_expired':
        reason = `注入请求连续 ${this.cfg.authStreak}+ 次返回 401 或跳转登录页（累计 ${counts.authLostHits} 次），而基线请求未出现该特征，判定会话已失效`;
        advice = '重新登录并携带有效 Cookie/Authorization（config.cookie 或 requestFile 原始包）后复扫；未认证状态下的「未检出」不成立，需带外验证登录态';
        break;
      case 'target_error':
        reason = `近 ${win} 次请求中 5xx 共 ${counts.serverErr} 次（占比 ${round2(base.serverErrRatio)}），目标自身处于错误状态`;
        advice = '先看目标应用日志/DB 连接池，确认服务健康后复扫；5xx 期间的响应差异无判定意义（若同时命中 dbHealth 熔断，先降并发避免持续伤害）';
        break;
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
