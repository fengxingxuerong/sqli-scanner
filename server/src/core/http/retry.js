// =====================================================================
// retry.js — 重试与闸门：每次尝试前闸门（_beforeAttempt：abort 检查 / --max-requests /
// --delay）/ 失败分类（_onRequestError：终态直接抛 / 可重试退避）/ 可中断延时（_sleep）。
// 自 httpClient.js 拆出（纯搬移）：由 HttpClient.prototype 挂载（this 语义不变）。
// =====================================================================
import { ErrorCode, AppError } from '../errors.js';
import { logger } from '../logger.js';
import { IP_FAIL_CODES, noteEgressIpFailure, dnsCache, clearHostPin } from './egressGuard.js';
import { TLS_CERT_CODES, isMaxContentLengthError } from './agentPool.js';
import { logSafeUrl } from './requestContext.js';
import {
  MAX_BODY_BYTES, NON_RETRYABLE_CODES, BACKOFF_BASE_MS, BACKOFF_MAX_MS, MAX_DELAY_SEC, newAbortError,
} from './limits.js';

  // 可中断延时：delay 期间若扫描被停止（signal aborted）立即返回，不必等完整个周期
export function _sleep(ms, signal) {
    if (!ms || ms <= 0) return Promise.resolve();
    return new Promise(/** @param {(value?: any) => void} resolve */ (resolve) => {
      const timer = setTimeout(() => {
        if (signal) signal.removeEventListener?.('abort', onAbort);
        resolve();
      }, ms);
      function onAbort() {
        clearTimeout(timer);
        resolve();
      }
      if (signal) {
        if (signal.aborted) { clearTimeout(timer); return resolve(); }
        signal.addEventListener?.('abort', onAbort, { once: true });
      }
    });
  }

  /**
   * 每次尝试前的闸门：① [⑮] signal 已取消时不再发新请求（重试循环防漏）；
   * ② [sqlmap 对标] --max-requests 计数检查，达上限后拒绝新请求；③ [sqlmap 对标] --delay
   * 固定延时（延时期间响应 abort signal，返回前复查取消）。
   */
export async function _beforeAttempt(opts) {
    // [⑮] abort 检查：signal 已取消时不再发新请求（重试循环防漏）
    if (opts.signal?.aborted) throw newAbortError();
    // [sqlmap 对标] --max-requests：请求计数检查，达上限后拒绝新请求。
    // 仅对归属明确（带 scanId）的请求计数：无 scanId 的请求无法在扫描结束时回收计数，
    // 用统一 key 会导致 ① Map 无界增长 ② 达到上限后全局永久拒绝新请求（不可恢复）。
    if (opts.maxReq && opts.maxReq > 0 && opts.scanId) {
      const count = this._requestCounts.get(opts.scanId) || 0;
      if (count >= opts.maxReq) {
        throw new AppError(ErrorCode.HTTP_ERROR, `请求上限已达（maxReq=${opts.maxReq}），拒绝新请求`);
      }
      this._requestCounts.set(opts.scanId, count + 1);
      this._evictRequestCounts(); // 兜底：防止异常退出残留的 scanId 条目累积
    }
    // [sqlmap 对标] --delay：每次请求前固定延时（秒），降低请求速率。
    // 上限 60s 防误配（如把毫秒当秒传入导致请求挂起）；延时期间响应 abort signal，
    // 避免「点了停止却要等完一个 delay 周期才生效」。
    if (opts.delay > 0) {
      await this._sleep(Math.min(Number(opts.delay) || 0, MAX_DELAY_SEC) * 1000, opts.signal);
      // [P2-FIX] delay 期间可能被 abort（_sleep 响应 signal 提前返回），
      // 复查 signal：已取消则不再发请求（原实现 sleep 后直接继续，浪费一次请求）
      if (opts.signal?.aborted) throw newAbortError();
    }
  }

  /**
   * 请求失败分类（原 request() catch 体迁移）：终态错误直接抛出；可重试错误完成退避
   * 等待后正常返回（调用方进入下一轮 attempt）——返回（不抛出）即代表「将重试」。
   */
export async function _onRequestError(err, opts, attempt, retry) {
    // [P0-FIX] AppError（SSRF 拦截 / 参数校验失败）是确定性的安全拒绝，重试多少次结果都一样，
    // 且每次重试都会重放整条重定向链（放大对禁止目标的探测）。必须立即抛出，不进入重试循环。
    if (err instanceof AppError) throw err;
    // [P0-FIX 2026-09-09] 连接层失败 → 拉黑刚用的出口 IP 并前移索引，使**本次重试**就打到另一个节点
    // （CDN/多 A 记录目标里单节点宕机时，不必等整段扫描超时）。超时不计：目标被重载荷拖慢 ≠ 节点死。
    if (err && err.code && IP_FAIL_CODES.has(err.code)) noteEgressIpFailure(opts.url, err.code);
    // [⑮] AbortError/CanceledError：扫描停止触发的请求取消，不重试直接抛出
    if (err.name === 'AbortError' || err.name === 'CanceledError' || err.code === 'ERR_CANCELED' || err.code === 'ABORT_ERR') {
      throw err;
    }
    // [P1-FIX ①] 证书类错误此前只是「快速失败 → 扫不出」，用户无从知道是证书问题；
    // 保留 NON_RETRYABLE 语义（重试无意义），但把逃生口与后果写进日志。
    if (err && err.code && TLS_CERT_CODES.has(err.code)) {
      logger.warn(
        `TLS 证书校验失败（${err.code}）：目标可能使用自签/内网 CA 证书。` +
          '如需扫描此类目标，设 insecureTls=true（关闭证书校验，报告须注明）；' +
          '更推荐把内网根证书加入系统信任链。'
      );
    }
    // [P1-FIX ④] axios 通道超限是「抛错」而非截断：明确记一条，避免被当成普通网络错误
    // 重试耗尽后无痕（提取路径已按 opts.maxContentLength 放大，此处针对扫描主链路）。
    if (isMaxContentLengthError(err)) {
      const limit = opts.maxContentLength ?? MAX_BODY_BYTES;
      logger.warn(
        `响应体超过上限（SSRF_MAX_BODY_MB 当前 ${Math.round(limit / 1048576)}MB）：` +
          `${logSafeUrl(opts.url || '')} 本次请求失败（未截断返回），差异比对在该点上不可用。`
      );
      // [P1-FIX 2026-09-09] 超限不重试：响应体积与重试无关，重试必然得到同一个错误，
      // 但每次都要把响应缓冲到上限再丢弃——在文件下载/大列表页这类目标上，
      // 相当于每个请求白烧 (retry+1) × 上限的内存与带宽（默认 4 × 15MB × 并发），
      // 还会把「目标页面太大」的真因埋进「HTTP 请求失败」。立即失败后，上层（预筛/守卫）
      // 能看到确定性的原因，而不是 4 次同构失败。
      throw new AppError(
        ErrorCode.HTTP_ERROR,
        `响应体超过上限（${Math.round(limit / 1048576)}MB），已快速失败（不重试）：${logSafeUrl(opts.url || '')}`
      );
    }
    const isTimeout = err.code === 'ECONNABORTED' || /timeout/i.test(err.message || '');
    if (err && err.code && NON_RETRYABLE_CODES.has(err.code)) {
      // [P0-FIX 2026-09-09] 区分「整个域名解析不出来」与「某个 IP 拒连」：
      //   • ENOTFOUND/EAI_AGAIN：已校验的 IP 列表来自旧解析结果，可能已整体变更 → 清空缓存 + 清钉死状态；
      //   • ECONNREFUSED：只可能是那一个节点的问题，上面 noteEgressIpFailure 已经拉黑该 IP 并前移索引。
      //     原实现这里直接 dnsCache.delete(hostname) 会把**已校验通过**的 IP 列表一起丢掉，下次请求
      //     重新解析又可能先拿到同一个死 IP，并在 60s 里反复重放整条 SSRF 校验 —— 死循环式浪费。
      if (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN') {
        const hostname = opts.url ? new URL(opts.url).hostname : null;
        if (hostname) {
          dnsCache.delete(hostname);
          clearHostPin(hostname);
        }
      }
      logger.warn(`HTTP 不可重试错误（快速失败）：${err.code} ${err.message}`);
      throw new AppError(ErrorCode.HTTP_ERROR, err.message || 'HTTP 请求失败');
    }
    if (isTimeout) {
      // P2-5：日志 URL 打码（剥离 query 中的注入 payload/敏感参数）
      // 文案区分「还会重试」与「最后一次尝试」（retry=0 时旧文案"第 1 次重试"误导）：
      logger.warn(
        attempt < retry
          ? `HTTP 超时（第 ${attempt + 1}/${retry + 1} 次尝试，将重试）：${logSafeUrl(opts.url || '')}`
          : `HTTP 超时（已达重试上限，放弃）：${logSafeUrl(opts.url || '')}`
      );
    } else {
      logger.warn(
        attempt < retry
          ? `HTTP 错误（第 ${attempt + 1}/${retry + 1} 次尝试，将重试）：${logSafeUrl(opts.url || '')} ${err.message}`
          : `HTTP 错误（已达重试上限，放弃）：${logSafeUrl(opts.url || '')} ${err.message}`
      );
    }
    if (attempt < retry) {
      const backoffMs = Math.min(BACKOFF_BASE_MS * 2 ** attempt, BACKOFF_MAX_MS);
      // [P2-FIX] 退避期间响应 abort signal（_sleep 可中断）：点了停止不必等完 backoff
      await this._sleep(backoffMs, opts.signal);
      if (opts.signal?.aborted) throw newAbortError();
      return;
    }
    if (isTimeout) throw new AppError(ErrorCode.HTTP_TIMEOUT, '请求超时');
  }
