import { URL } from 'url';
import { obfuscatePayload } from './payloads.js';
import { obfuscateWithConfig } from '../core/tamper/applyTampers.js';
import { applyBoundary } from './injection.js';

// 检测器接口/基类（策略模式）
// 子类需实现 detect(ctx)，返回 DetectionResult。
// ctx 约定：{ httpClient, target, point, dbms, config }
export class Detector {
  /**
   * @param {string} technique 检测技术名（union/error/boolean/time）
   */
  constructor(technique) {
    this.technique = technique;
  }

  // 由子类实现具体检测逻辑
  async detect(ctx) {
    throw new Error('Detector.detect 必须由子类实现');
  }

  /**
   * 按注入点位置构造请求对象（注入位置：url/body/cookie/header）
   * @param {object} target 目标
   * @param {object} point 注入点
   * @param {string} injectedValue 注入后的参数值
   */
  buildRequest(target, point, injectedValue) {
    // 注入边界（--prefix/--suffix）：统一在基类施加，覆盖全部检测技术，与 sqlmap 对基线+探针一致。
    const boundary = target && target.config && target.config.injectionBoundary;
    const value = applyBoundary(injectedValue, point, boundary);
    // 表单点回退：优先用表单自身的提交方法与 action 地址；否则回退到 target 默认。
    const req = {
      method: point.formMethod || target.method,
      url: point.actionUrl || target.baseUrl,
      params: {},
      data: {},
      headers: { ...(target.headerParams || {}) },
    };
    const cookies = { ...(target.cookieParams || {}) };

    if (point.location === 'url') {
      const u = new URL(req.url);
      const hpp = target && target.config && target.config.hpp;
      if (hpp) {
        // HTTP 参数污染（对标 sqlmap --hpp）：同名多值（原始值在前、注入值在后）。
        // 与 injection.js buildInjectionRequest 保持同构：绕过只查首值的 WAF。
        const origParam = u.searchParams.get(point.param) || point.originalValue || '1';
        const others = new URL(req.url).searchParams;
        u.search = '';
        for (const [k, v] of others.entries()) {
          if (k !== point.param) u.searchParams.append(k, v);
        }
        u.searchParams.append(point.param, origParam);
        u.searchParams.append(point.param, value);
        req.url = u.toString();
      } else {
        u.searchParams.set(point.param, value);
        req.url = u.toString();
      }
    } else if (point.location === 'body') {
      // 表单点：将表单全部字段并入 data（含 CSRF token），再把当前注入参数覆盖为注入值
      const formValues = point.formValues || {};
      req.data = { ...formValues };
      req.data[point.param] = value;
    } else if (point.location === 'cookie') {
      cookies[point.param] = value;
      req.headers['Cookie'] = Object.entries(cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ');
    } else if (point.location === 'header') {
      req.headers[point.param] = value;
    }
    return req;
  }

  /**
   * 按 WAF 规避配置包裹混淆（tamper 链式优先，否则 legacy obfuscate，否则原样）。
   * 统一改调 obfuscateWithConfig，向后兼容：tamper 关且 obfuscate 关时返回原样。
   * @param {object} ctx 检测上下文（含 config.wafEvasion）
   * @param {string} value 已填充的注入值
   * @returns {string} 混淆后（或原样）的注入值
   */
  obfuscateValue(ctx, value) {
    return obfuscateWithConfig(value, ctx);
  }

  // 经统一 HttpClient 发送请求，并透传 proxy/auth/wafEvasion
  async send(httpClient, ctx, req, opts = {}) {
    const config = (ctx && ctx.config) || {};
    return httpClient.request({
      method: req.method,
      url: req.url,
      params: req.params,
      data: req.data,
      headers: req.headers,
      timeoutMs: opts.timeoutMs ?? config.timeoutMs,
      retry: opts.retry ?? config.retry,
      proxy: config.proxy ?? false,
      auth: config.auth ?? null,
      wafEvasion: config.wafEvasion ?? null,
      requestDelayMs: config.requestDelayMs ?? 0,
    });
  }

  /**
   * 限并发发送一批请求：保持入参顺序返回结果数组，单个失败不中断整体。
   * 用于盲注基线与真假对重复采样，抵消串行 await 带来的 ~2.8× 开销。
   * 每个返回元素结构：{ resp, __elapsed(ms), __error? }；发送失败仅置 __error，不抛。
   * @param {object} httpClient
   * @param {object} ctx
   * @param {object[]} requests buildRequest 结果数组
   * @param {object} opts 透传给 send 的 opts（如 timeoutMs）
   * @param {number} limit 并发上限（默认 4，盲注用 rb.concurrency）
   */
  async sendConcurrent(httpClient, ctx, requests, opts = {}, limit = 4) {
    const out = new Array(requests.length);
    let cursor = 0;
    const worker = async () => {
      while (cursor < requests.length) {
        const i = cursor++;
        const t0 = Date.now();
        try {
          const resp = await this.send(httpClient, ctx, requests[i], opts);
          out[i] = { resp, __elapsed: Date.now() - t0 };
        } catch (e) {
          out[i] = { __error: e, __elapsed: Date.now() - t0 };
        }
      }
    };
    const n = Math.max(1, Math.min(limit || 1, requests.length));
    await Promise.all(Array.from({ length: n }, () => worker()));
    return out;
  }
}

export default Detector;
