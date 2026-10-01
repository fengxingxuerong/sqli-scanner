// =====================================================================
// egress.js — 出口发送基座：send（统一 egress 选项 + 健康回流）/ sendHead
// （--null-connection）/ matchNullConnection（元数据判定）/ sendConcurrent（限并发批量）。
// 自 Detector.js 拆出（纯搬移）：由 Detector.prototype 挂载（this 语义不变）。
// =====================================================================
import { buildEgressOpts } from '../egressOpts.js';

  // 经统一 HttpClient 发送请求。
  // [P0-FIX 2026-09-09] 选项改为调 buildEgressOpts：历史上这里手拄一份、sendInjection 手拄一份，
  // 已经漂过三次（delay/reqRate/maxReq 只在检测阶段生效、forceSsl 只在提取阶段生效、
  // proxyBypassLocal/cookieJar 在提取阶段丢失）。漂一次的代价不是报错，是静默的结论污染。
export async function send(httpClient, ctx, req, opts = {}) {
    const config = (ctx && ctx.config) || {};
    const resp = await httpClient.request(
      buildEgressOpts(config, {
        method: req.method,
        url: req.url,
        params: req.params,
        data: req.data,
        headers: req.headers,
        sql: req.sql,
        timeoutMs: opts.timeoutMs ?? config.timeoutMs,
        retry: opts.retry ?? config.retry,
        // 网络耗时测量（时间盲注判定用）：HttpClient 在令牌获取完成后计 __networkMs
        networkTiming: opts.networkTiming,
      })
    );
    // 目标库健康回流：DB 致命错误（如 PG stack depth）在 HTTP 层是 500 成功响应，
    // Scheduler 的自适应（只看网络错误/延迟）感知不到，必须在此显式回流。
    try {
      ctx?.guard?.observe(resp);
    } catch {
      /* 守卫异常不影响检测主流程 */
    }
    return resp;
  }

  /**
   * [sqlmap 对标] --null-connection：发送 HEAD 请求（无响应体传输），用于布尔盲注快速判定。
   * config.nullConnection === true 时，boolean/time 检测器应调用此方法替代 send。
   * @param {object} httpClient 统一 HttpClient（需支持 headRequest 方法）
   * @param {object} ctx 检测上下文（含 config）
   * @param {object} req 请求对象（含 url / params / headers 等）
   * @param {object} [opts] 额外选项
   * @returns {Promise<{status:number, headers:object, data:string}>}
   */
export async function sendHead(httpClient, ctx, req, opts = {}) {
    const config = (ctx && ctx.config) || {};
    if (typeof httpClient.headRequest !== 'function') {
      // 兜底：httpClient 不支持 headRequest 时回退到 send（保持兼容性）
      return this.send(httpClient, ctx, req, opts);
    }
    return httpClient.headRequest(
      req.url,
      // [P0-FIX 2026-09-09] HEAD 快速判定与主路同源：此前这里少 cookieJar/dropSetCookie，
      // --null-connection 与 GET 路径看到的会话不是同一个（同一注入点两路结论相反）。
      buildEgressOpts(config, {
        headers: req.headers,
        timeoutMs: opts.timeoutMs ?? config.timeoutMs,
        retry: opts.retry ?? config.retry,
      })
    );
  }

  /**
   * [sqlmap 对标] --null-connection：基于状态码 + Content-Length 头的真假判定。
   * 不依赖响应体相似度比对，仅比较 HTTP 元数据。
   * 判定逻辑：
   *   - 状态码不同 → 信号（true，真假可区分）
   *   - 状态码相同但 Content-Length 不同 → 信号
   *   - 两者均相同 → 无差异（false）
   * @param {{status:number, headers:object}} response 待判定响应
   * @param {{status:number, headers:object}} baselineResponse 基线响应
   * @returns {boolean} true=可区分（注入信号），false=无差异
   */
export function matchNullConnection(response, baselineResponse) {
    // `|| {}` 会让推断类型并上空对象 → 显式标注，保留原兜底语义
    const r = /** @type {{ status?: number, headers?: any }} */ (response || {});
    const b = /** @type {{ status?: number, headers?: any }} */ (baselineResponse || {});
    // 状态码不同即信号
    const rStatus = r.status ?? 0;
    const bStatus = b.status ?? 0;
    if (rStatus !== bStatus) return true;
    // Content-Length 头比对
    const rLen = this._contentLength(r.headers);
    const bLen = this._contentLength(b.headers);
    if (rLen != null && bLen != null && rLen !== bLen) return true;
    return false;
  }

  // 从响应头取 Content-Length 数值（大小写不敏感），无则返回 null
export function _contentLength(headers) {
    if (!headers || typeof headers !== 'object') return null;
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === 'content-length') {
        const n = Number(v);
        return Number.isFinite(n) ? n : null;
      }
    }
    return null;
  }

  /**
   * 限并发发送一批请求：保持入参顺序返回结果数组，单个失败不中断整体。
   * 用于盲注基线与真假对重复采样，抵消串行 await 带来的 ~2.8× 开销。
   * 每个返回元素结构：{ resp, __elapsed(ms), __totalMs(ms), __error? }；发送失败仅置 __error，不抛。
   * —— 计时语义（本版）——
   * __elapsed 优先取 HttpClient 的纯网络耗时（__networkMs，不含令牌桶排队等待）：
   * 旧实现从 send 前计时，限速低时并发采样的排队时间被计入，基线 μ/σ 与注入耗时虚高
   * （见 docs/vs-sqlmap-analysis/01-detection.md 的已知风险）。mock 客户端无 __networkMs 时
   * 回退总耗时（与旧行为一致，零回归）；__totalMs 始终为总耗时（含排队）。
   * @param {object} httpClient
   * @param {object} ctx
   * @param {object[]} requests buildRequest 结果数组
   * @param {object} opts 透传给 send 的 opts（如 timeoutMs / networkTiming）
   * @param {number} limit 并发上限（默认 4，盲注用 rb.concurrency）
   */
export async function sendConcurrent(httpClient, ctx, requests, opts = {}, limit = 4) {
    const out = new Array(requests.length);
    let cursor = 0;
    const worker = async () => {
      while (cursor < requests.length) {
        const i = cursor++;
        const t0 = Date.now();
        try {
          const resp = await this.send(httpClient, ctx, requests[i], opts);
          const totalMs = Date.now() - t0;
          const networkMs = resp && typeof resp.__networkMs === 'number' ? resp.__networkMs : null;
          out[i] = { resp, __elapsed: networkMs ?? totalMs, __totalMs: totalMs };
        } catch (e) {
          out[i] = { __error: e, __elapsed: Date.now() - t0, __totalMs: Date.now() - t0 };
        }
      }
    };
    const n = Math.max(1, Math.min(limit || 1, requests.length));
    await Promise.all(Array.from({ length: n }, () => worker()));
    return out;
  }
