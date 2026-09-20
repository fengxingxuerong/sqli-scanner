// ============================================================================
// redirectPolicy.js —— 重定向的**纯决策**逻辑（无 I/O、无 this、无状态）
//
// [大文件二期拆分 2026-09-20] 从 httpClient.js 的两条重定向跟随路径
// （_followRedirects / _followRedirectsH2）抽出其中**不含 I/O 的判定**。
//
// 为什么值得单独成模块：
//   · 这三条判定都是**安全语义**（凭据会不会泄露到第三方域、POST 会不会被重放成 GET），
//     但此前埋在两条各自 100+ 行的循环里，只能靠端到端测试间接覆盖；
//   · 抽成纯函数后可直接单测边界（同域 vs 跨域、端口变化、303 vs 301/302 vs 307/308）；
//   · 两条通道共用同一份判定 → 消除「H2 路径与 H1 路径行为漂移」这类历史隐患。
//
// 职责边界：只回答「这一跳该怎么发」，不负责「发出去」——DNS 钉死、SSRF 校验、
// 授权范围校验仍在调用方（它们需要 I/O 且顺序敏感）。
// ============================================================================

/** 跨域跳转时必须剥离的凭据头（防凭据泄露到第三方域）。统一小写，比对时对键名取小写。 */
export const CREDENTIAL_HEADERS = ['authorization', 'cookie', 'cookie2', 'proxy-authorization'];

/**
 * 判定重定向是否属于「跨域」，跨域则需剥离凭据头。
 *
 * 跨域定义：**hostname 或 protocol 变化**即视为跨域。
 * 刻意**不把端口变化算作跨域** —— 同站多端口（如 :8080 → :8443）很常见，
 * 按端口剥离会让正常的多端口应用在跳转后丢失会话，属误伤。
 * @param {string} fromUrl 当前 URL
 * @param {string} toUrl 跳转目标 URL
 * @returns {boolean} true=跨域（需剥离凭据）
 */
export function isCrossOriginRedirect(fromUrl, toUrl) {
  const u1 = new URL(fromUrl);
  const u2 = new URL(toUrl);
  return u1.hostname !== u2.hostname || u1.protocol !== u2.protocol;
}

/**
 * 计算重定向后应当使用的方法。
 *
 * 与浏览器一致（RFC 7231 §6.4 的工程实践）：
 *   · 303 See Other → 无条件降级为 GET（语义就是「去 GET 那个资源」）；
 *   · 301/302 且原方法非 GET/HEAD → 也降级为 GET —— 这两个状态码在历史实现中
 *     被广泛用于 POST 后跳转（PRG 模式），若原样重放 POST 会造成：
 *     ① 重复提交（表单被提交两次）；② 请求体透传到意料外的端点。
 *   · 307/308 → **保持不变**（这两个码的语义就是「原样重发」，含方法与 body）。
 * @param {number} status 重定向响应状态码
 * @param {string} [originalMethod] 原请求方法（缺省 GET）
 * @returns {string} 本跳应使用的方法（大写）
 */
export function resolveRedirectMethod(status, originalMethod) {
  const method = String(originalMethod || 'GET').toUpperCase();
  if (status === 303) return 'GET';
  if ((status === 301 || status === 302) && method !== 'GET' && method !== 'HEAD') return 'GET';
  return method;
}

/**
 * 依据是否跨域，产出本跳实际使用的请求头。
 *
 * 不变量：**不修改传入的 headers 对象**。同域跳转直接复用原对象（零拷贝）；
 * 首次跨域时才克隆一层，从副本删除凭据头 —— 这样「同域 → 跨域 → 再同域」的
 * 多跳链里，后续同域跳转仍能带上凭据（原实现若就地删除会造成凭据永久丢失）。
 *
 * [2026-09-20 统一两通道语义] 凭据头按**大小写不敏感**匹配删除（本模块的
 * `CREDENTIAL_HEADERS` 全小写，比对时对键名 `toLowerCase()`）。
 * 合并前 H1 路径用精确键名 `delete headers['Authorization']`，H2 路径用
 * `Object.keys` + 小写比对。显式构造大小写变体（如 `authorization`，HTTP/2 层面
 * 头名本就必须小写）时，H1 路径会**漏删** → 凭据泄露到第三方域。
 * 现统一采用大小写不敏感版本（即原先 H2 的行为，属收紧而非放宽）。
 *
 * ⚠️ 该不敏感比对本身踩过一次坑：`CREDENTIAL_HEADERS` 若写成首字母大写的
 * `['Authorization', …]` 而比对时又取 `k.toLowerCase()`，两边永不相等 →
 * **剥离静默失效**。`tests/redirectPolicy.test.js` 已钉死此行为，勿改回大写。
 *
 * @param {object} headers 当前生效的请求头
 * @param {object} originalHeaders 最初传入的请求头（用**引用相等**判断是否已克隆过）
 * @param {boolean} crossOrigin 本跳是否跨域
 * @returns {object} 本跳应使用的请求头（可能是同一引用，也可能是克隆副本）
 */
export function applyRedirectHeaders(headers, originalHeaders, crossOrigin) {
  if (!crossOrigin) return headers;
  const next = headers === originalHeaders ? { ...headers } : headers;
  for (const k of Object.keys(next)) {
    if (CREDENTIAL_HEADERS.includes(k.toLowerCase())) delete next[k];
  }
  return next;
}
