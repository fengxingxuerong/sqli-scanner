// ============================================================================
// engine/egressOpts.js —— 发包出口选项 / 出口结果可用性 的唯一真源
// [P0-FIX 2026-09-09]
//
// 为什么必须存在这个文件（本项目第三次同类事故，别再写第四遍）
// ----------------------------------------------------------------------------
// 同一个「把 config 翻成 HttpClient.request(opts)」的动作，历史上被手抄了三份：
//   ① Detector.send      —— 检测阶段（布尔/时间/联合/报错/堆叠全部走它）
//   ② Detector.sendHead  —— --null-connection 的 HEAD 快速判定
//   ③ sendInjection       —— 指纹 / 预筛选 / 静态跳过 / 盲注提取 / 二阶触发页（13+ 调用点共用）
// 每次新增一个出口类开关，都要同时改三处；漏一处的后果**不是崩溃，而是静默的结论污染**：
//   事故 1：`--delay` / `--reqrate` / `--max-requests` 只在 Detector.send 透传 →
//           请求量最大的指纹/预筛/提取阶段全速裸奔（客户系统被打挂、出口 IP 被 WAF 拉黑，
//           而使用者以为限速生效了）。
//   事故 2：forceSsl / ignoreRedirects 同因漂移 → 同一注入点「检测看到的响应」与
//           「提取看到的响应」不是同一个响应（提取阶段被 302 弹走后拖库结果为空，
//           被读成「该列无数据」）。
//   事故 3（本次）：sendInjection 缺 proxyBypassLocal → 挂了环境变量代理（Burp/Clash）扫
//           127.0.0.1 靶场时，**检测阶段绕过代理、指纹/预筛/提取阶段却把流量塞进 Burp**：
//           Burp 对部分请求掐线 → 那些点被判「无差异 → 不可注入」（实测 19/19 ↔ 18/19 的
//           假阴性差就是这个）。sendInjection 同时缺 cookieJar / dropSetCookie →
//           `--drop-set-cookie` 在提取阶段失效，同一注入点两阶段的会话状态不同（检测时靠
//           自动吸收 Set-Cookie 保持登录，提取时又被服务端认成另一个会话 → 提取全线 401，
//           而报告写的是「未提取到数据」）。
// 结论：**新增任何出口类配置，只需在 buildEgressOpts 里加一行**，三条通路自动同源。
// tests/injection.governance.test.js 会把「调用点必须调用 buildEgressOpts」与「键集合覆盖
// 受治清单」钉成测试，手抄第四份会在 CI 里直接失败。
//
// 与 ScanManager.getScanClient 的 egressPatch 的关系（冗余是故意的，别删）
// ----------------------------------------------------------------------------
// ScanManager.getScanClient（ScanManager.js:246-280）在扫描级客户端上再包一层，注入
// forceSsl / ignoreRedirects / insecureTls / trustProxyEnv / ssrfViaProxy。因此：
//   - 凡**经由扫描级客户端**发出的请求（Detector.send / sendInjection / Extractor / 二阶 /
//     NoSQL / WAF 重试），即使调用点忘了透传 forceSsl，egressPatch 也会补上 —— 这一层是兜底。
//   - 但 egressPatch 的边界很清楚：① 只对扫描级客户端生效，任何绕过它的通道（如
//     HttpClient.forScan 自带的 headRequest，或直连 connector 的其它方法）拿不到这些键；
//     ② 它只覆盖「egressPatch 里那五个键」，delay/reqRate/maxReq/cookieJar/dropSetCookie/
//     proxyBypassLocal 一概不在其中。
//   - 两处同时给出同名键时值必然相同（同源于 target.config），因此本文件把 forceSsl/
//     ignoreRedirects 也收进 buildEgressOpts **不构成行为变化**，只是让「不依赖客户端怎么包」
//     成为性质：换一个 httpClient（单测桩、直连连接器、未来新的通道）也不掉键。
// ============================================================================

/**
 * 受治出口键清单（治理/协议/网络三类）。新增出口类配置时：
 * ① 加进这个数组；② 在 buildEgressOpts 里给一行默认值。二者不一致会被治理测试判失败。
 * @type {readonly string[]}
 */
export const EGRESS_KEYS = Object.freeze([
  'timeoutMs',
  'retry',
  'proxy',
  'auth',
  'wafEvasion',
  'proxyBypassLocal',
  'delay',
  'reqRate',
  'maxReq',
  'cookieJar',
  'dropSetCookie',
  'forceSsl',
  'ignoreRedirects',
]);

/**
 * 由扫描/检测配置构造「出口选项对象」。语义与默认值与历史三处手写实现逐一等价：
 *   - `timeoutMs` / `retry`：取 config 值；调用点若要 per-request 覆盖（如时间盲注放宽超时、
 *     预筛零重试），用 `overrides` 传入 `opts.timeoutMs ?? config.timeoutMs`（优先级保持原样）。
 *   - `proxy: false`：HttpClient 把 false 视为「未显式配置」，仍会按 trustProxyEnv 回退环境变量代理。
 *   - `proxyBypassLocal`：**原样透传（不加 ?? true）**，把「未配置」的判定留给 HttpClient 的
 *     `opts.proxyBypassLocal ?? defaults.proxyBypassLocal !== false`——在此处替它补默认值会让
 *     defaults.proxyBypassLocal=false 的逃生口失效。
 *   - `cookieJar: !== false`（默认开）/ `dropSetCookie: === true`（默认关，对标 --drop-set-cookie）。
 *   - `forceSsl` / `ignoreRedirects`：严格 `=== true`（未配置即 false）。
 * @param {object} [config] 扫描配置（target.config / ctx.config）
 * @param {object} [overrides] 调用点专有键（per-request 覆盖、networkTiming、headers 等）
 * @returns {object} 可直接展开进 httpClient.request(cfg) / httpClient.headRequest(url, cfg)
 */
export function buildEgressOpts(config, overrides = {}) {
  const cfg = config && typeof config === 'object' ? config : {};
  const o = {
    timeoutMs: cfg.timeoutMs,
    retry: cfg.retry,
    proxy: cfg.proxy ?? false,
    auth: cfg.auth ?? null,
    wafEvasion: cfg.wafEvasion ?? null,
    // [P0-FIX 2026-09-09] 本地/私网豁免环境变量代理（事故 3 的正主；false 可恢复旧行为）
    proxyBypassLocal: cfg.proxyBypassLocal,
    // [sqlmap 对标] --delay / --reqrate / --max-requests：限速与请求上限
    delay: cfg.delay ?? 0,
    reqRate: cfg.reqRate ?? 0,
    maxReq: cfg.maxReq ?? 0,
    // [P1-FIX 2026-09-05] Cookie Jar 会话保持 / --drop-set-cookie
    cookieJar: cfg.cookieJar !== false,
    dropSetCookie: cfg.dropSetCookie === true,
    // [sqlmap 对标] --force-ssl / --ignore-redirects
    forceSsl: cfg.forceSsl === true,
    ignoreRedirects: cfg.ignoreRedirects === true,
  };
  if (overrides && typeof overrides === 'object') Object.assign(o, overrides);
  return o;
}

// ============================================================================
// 出口结果可用性：把「请求失败」与「目标返回空页面」分开
// ----------------------------------------------------------------------------
// 实战后果：httpClient 失败会抛 AppError(HTTP_TIMEOUT/HTTP_ERROR)，sendInjection 历史上把它
// 吞成 null，而全项目 60+ 处调用方写的是 `String(res?.data ?? '')` —— 于是
// 「连接被拒 / 超时 / 证书失败 / 响应超限」在判定层与「目标返回空页」完全同形：
//   · 布尔盲注：真假两侧都是空串 → 「无差异」→ 判「不可注入」；
//   · 时间盲注：失败样本记为「无延迟」→ 稳定率被失败样本拉低 → 判「不可注入」；
//   · UNION：标记探测失败 → 判「无回显列」→ confirmed 仍为 false。
// 三条都是**假安心**（false reassurance）：报告写着「未检出」，使用者据此收工。
// 本段提供统一判据：失败必须携带 __netErr，判定层先过 isUnusableResponse 再谈差异。
// ============================================================================

// 传输层错误的归类靠「errno 字符串 + 文案」双路匹配（HttpClient 会把底层 errno 包成
// AppError(HTTP_ERROR)，原始 code 丢失、但 message 保留），见 classifyNetError。

/**
 * 归类一次发送失败：{ code, message, kind }，kind ∈ timeout|refused|dns|tls|oversize|aborted|other。
 * kind 的用途是「让使用者知道该去查什么」：
 *   timeout → 加大 timeoutMs / 目标在慢速通道上；refused → 端口/服务存活；dns → 解析与出口；
 *   tls → 自签证书（insecureTls 或补根证书）；oversize → 响应体/请求数上限；aborted → 人为停止。
 * @param {any} err httpClient/axios/undici 抛出的错误（可为 AppError）
 * @returns {{code:string, message:string, kind:string}}
 */
export function classifyNetError(err) {
  const rawCode = err?.code;
  const code = rawCode == null ? '' : String(rawCode);
  const message = String(err?.message ?? err ?? '').slice(0, 300);
  const name = String(err?.name ?? '');
  const hay = `${code} ${message}`;
  const has = (re) => re.test(hay);
  let kind = 'other';
  if (name === 'AbortError' || name === 'CanceledError' || code === 'ERR_CANCELED' || code === 'ABORT_ERR') kind = 'aborted';
  // 超限：响应体过大（axios maxContentLength / HttpClient 快速失败文案）或 --max-requests 命中
  else if (has(/maxContentLength|max[- ]body|响应体超过上限|请求上限已达|maxReq\b|EMAXCONTENT/i)) kind = 'oversize';
  // 证书/TLS：必须在 timeout 之前——undici 的证书错误 message 里也可能带 read timeout 之类字样
  else if (has(/CERT|self[- ]signed|certificate|SSL|TLS_HANDSHAKE|UNABLE_GET_IMAGE|DEPTH_ZERO/i)) kind = 'tls';
  else if (has(/ENOTFOUND|EAI_AGAIN|getaddrinfo|DNS/i)) kind = 'dns';
  else if (has(/ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE|UND_ERR_SOCKET|socket hang up|connection refused|connection is closed/i)) kind = 'refused';
  else if (has(/ETIMEDOUT|ECONNABORTED|ESOCKETTIMEDOUT|UND_ERR_.*TIMEOUT|timeout|超时/i) || code === '3001') kind = 'timeout';
  return { code, message, kind };
}

// HttpClient 对「传输层失败」的统一错误码：3001 HTTP_TIMEOUT / 3002 HTTP_ERROR。
// 只有这两类可以被降级成失败响应对象（它们语义上确实是「这次请求没拿到可用响应」）。
const DEGRADABLE_APP_CODES = new Set([3001, 3002]);

/**
 * 是否为「用户/框架主动取消」或「安全/参数硬拒绝」（SSRF、scope 越界、URL 非法）——
 * 这两类**必须继续抛出**，不得降级成空响应：
 *   · 取消：不是目标的结论，也不该被记成任何未决点（stop() 后不该再多算一次未决）；
 *   · SSRF/scope：越界是事故，不是「这个点没洞」；把它吞成空页等于把硬停变成静默放行——
 *     实战后果是「授权范围外的主机被打了，而报告只写着未检出」。
 * 其余异常（含裸 Error/errno）沿用「不中断整条流水线」的既有语义，降级为失败响应对象。
 * @param {any} err
 * @returns {boolean} true = 调用方应当 rethrow
 */
export function mustRethrowSendError(err) {
  if (!err) return false;
  const name = String(err?.name ?? '');
  const code = err?.code;
  if (name === 'AbortError' || name === 'CanceledError' || code === 'ERR_CANCELED' || code === 'ABORT_ERR') return true;
  if (name === 'AppError' || (err instanceof Error && typeof code === 'number')) {
    return !DEGRADABLE_APP_CODES.has(code);
  }
  return false;
}

/**
 * 构造「网络失败响应」：保持 res 是对象（status 0 / data 空串 / headers 空对象），
 * 调用方 `res?.status` / `res?.data` 语义不变，同时携带 __netErr 供判定层显式拦截。
 * @param {any} err classifyNetError 的输入
 * @param {object} [extra] 附加字段（如 url，便于日志定位）
 * @returns {{status:number, statusText:string, headers:object, data:string, __netErr:object}}
 */
export function netFailureResponse(err, extra = {}) {
  return {
    status: 0,
    statusText: '',
    headers: {},
    data: '',
    __netErr: classifyNetError(err),
    ...extra,
  };
}

/**
 * 响应是否为「网络层失败」（含历史契约的 null/undefined：调用方拿到 null 也是失败）。
 * @param {{__netErr?: object}|null|undefined} res
 * @returns {boolean}
 */
export function isNetFailure(res) {
  if (res == null) return true;
  return !!res.__netErr;
}

/**
 * 取失败类别（timeout/refused/dns/tls/oversize/aborted/other）；非失败响应返回 ''。
 * @param {{__netErr?: {kind?: string}}|null|undefined} res
 * @returns {string}
 */
export function netErrKind(res) {
  if (res == null) return 'other';
  return String(res?.__netErr?.kind ?? '');
}

/**
 * 响应体是否被出口层截断（HttpClient 超限走截断通道时挂 `__meta.truncated = true`）。
 * 截断页参与 diff/相似度比对 = 拿「半张页面」当证据：长度差可能纯粹来自截断点，
 * 相似度分块数不同 → 真假判定全部失真，因此它与网络失败同属「不可用作判定输入」。
 * @param {{__meta?: {truncated?: boolean}}|null|undefined} res
 * @returns {boolean}
 */
export function isTruncatedResponse(res) {
  if (!res || typeof res !== 'object') return false;
  return res.__meta?.truncated === true;
}

/**
 * 统一「不可用作判定输入的响应」判据：网络失败 或 被截断。
 * 检测器在算差异之前必须先过这一关（Task 2/3 的公共前置）。
 * @param {object|null|undefined} res
 * @returns {boolean}
 */
export function isUnusableResponse(res) {
  return isNetFailure(res) || isTruncatedResponse(res);
}

/**
 * 不可用原因的可读文案（写进 point.unverifiedReason / 报告，供使用者知道去查什么）。
 * @param {object|null|undefined} res
 * @returns {string} 空串表示响应可用
 */
export function unusableReason(res) {
  if (isTruncatedResponse(res) && !res?.__netErr) {
    const bytes = Number(res?.__meta?.bodyBytes) || 0;
    return `响应体超限被截断${bytes ? `（${Math.round(bytes / 1024)}KB）` : ''}，差异比对不可用`;
  }
  if (!isNetFailure(res)) return '';
  if (res == null) return '请求未返回响应（连接失败/超时）';
  const kind = netErrKind(res) || 'other';
  const msg = String(res?.__netErr?.message ?? '').slice(0, 120);
  const zh =
    {
      timeout: '请求超时',
      refused: '连接被拒/被掐断',
      dns: 'DNS 解析失败',
      tls: 'TLS 证书握手失败',
      oversize: '响应体或请求数超上限',
      aborted: '请求被取消',
      other: '网络层失败',
    }[kind] || '网络层失败';
  return `网络层失败（${zh}${msg ? `：${msg}` : ''}）`;
}

export default {
  EGRESS_KEYS,
  buildEgressOpts,
  classifyNetError,
  mustRethrowSendError,
  netFailureResponse,
  isNetFailure,
  netErrKind,
  isTruncatedResponse,
  isUnusableResponse,
  unusableReason,
};
