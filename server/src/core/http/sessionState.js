// =====================================================================
// sessionState.js — per-scan 会话态：限速桶（createBucket/bucketForRate/
// _resolveRateBucket）/ 请求计数（--max-requests）/ Cookie Jar（jarFor/clearJar/
// _captureCookies）。
// 自 httpClient.js 拆出（纯搬移）：由 HttpClient.prototype 挂载（this 语义不变）。
// =====================================================================
import { defaults } from '../../config/defaults.js';
import { CookieJar } from '../cookieJar.js';
import { TokenBucket } from './tokenBucket.js';
import { MAX_TRACKED_SCANS } from './limits.js';

export function createBucket(scanId, ratePerSec) {
    // [P0-FIX 2026-09-14] ratePerSec<=0 = 不限速：建 UNLIMITED 桶（TokenBucket 内部处理），
    // 保持 per-scan 桶注册表结构不变（removeBucket/桶查询路径零改动）。原实现把 <=0 换成
    // defaults —— 显式 0 的调用方（本地靶场「不限速」意图）被暗中按保守默认限速。
    const rps = Number.isFinite(ratePerSec) && ratePerSec > 0 ? ratePerSec : 0;
    const bucket = new TokenBucket(rps);
    this.buckets.set(scanId, bucket);
    return bucket;
  }

export function removeBucket(scanId) {
  this.buckets.delete(scanId);
}

  // [sqlmap 对标] --max-requests：清理 scanId 的请求计数（扫描结束时调用）
export function removeRequestCount(scanId) {
    this._requestCounts.delete(scanId);
  }

  // [P1-FIX 2026-09-05] Cookie Jar：按 scanId 惰性创建；clearJar 随扫描退役调用
export function jarFor(scanId) {
    if (!this._jars.has(scanId)) this._jars.set(scanId, new CookieJar());
    return this._jars.get(scanId);
  }

export function clearJar(scanId) {
    this._jars.delete(scanId);
  }

  // 捕获响应 Set-Cookie 入 jar（幂等；cookieJar=false / dropSetCookie=true 时跳过，
  // 后者对标 --drop-set-cookie）
export function _captureCookies(url, res, opts) {
    if (!opts || !opts.scanId || opts.cookieJar === false || opts.dropSetCookie === true) return;
    const setCookies = res && res.headers && res.headers['set-cookie'];
    if (!setCookies) return;
    try {
      this.jarFor(opts.scanId).setFromResponse(url, setCookies);
    } catch { /* cookie 解析失败不影响请求主流程 */ }
  }

  // 计数表兜底清理：条目超上限时按 Map 插入顺序（最早写入）淘汰。
  // 正常路径由 removeRequestCount 回收；异常退出/未挂 scanId 的路径才依赖此处。
export function _evictRequestCounts() {
    if (this._requestCounts.size <= MAX_TRACKED_SCANS) return;
    const overflow = this._requestCounts.size - MAX_TRACKED_SCANS;
    let n = 0;
    for (const key of this._requestCounts.keys()) {
      if (n++ >= overflow) break;
      this._requestCounts.delete(key);
    }
  }

export function bucketForRate(ratePerSec) {
    // [P0-FIX 2026-09-14] 调用方保证只在 effectiveRate>0 时进入本方法；<=0 守卫为直通语义
    // 由上层处理（主选择点已短路），这里保留 >0 归一防误用。
    const rps = Number.isFinite(ratePerSec) && ratePerSec > 0 ? ratePerSec : defaults.ratePerSec;
    if (!this.rateBuckets.has(rps)) {
      // [P0-FIX] 兜底淘汰：rate 值由调用方控制（ratePerSec 透传），恶意/异常值可撑爆 Map。
      // 正常路径下 per-scan 限速走 createBucket/removeBucket；此处仅服务无 scanId 的请求。
      if (this.rateBuckets.size >= MAX_TRACKED_SCANS) {
        this.rateBuckets.delete(this.rateBuckets.keys().next().value);
      }
      this.rateBuckets.set(rps, new TokenBucket(rps));
    }
    return this.rateBuckets.get(rps);
  }

  /**
   * [P0-FIX 2026-09-14] 限速语义对齐 TokenBucket：effectiveRate<=0 = 不限速（直通，不落桶）。
   * 原实现把 <=0 交给 this.bucket（defaults 单例桶），显式 0 会被暗中按默认值限速——
   * defaults 保守化后该错位直接打崩以 0 表达「不限速」的调用方（pentest-lab 实测 0/10）。
   */
export function _resolveRateBucket(opts, effectiveRate) {
    // [2026-10-03] rateKey 优先：批量共享组桶挂在组 id 上，scanId 桶查不到它。
    //   顺序不能反 —— scanId 桶是**每扫描必有**的，反过来的话组桶永远拿不到。
    return (opts.rateKey && this.buckets.get(opts.rateKey))
      || (opts.scanId && this.buckets.get(opts.scanId)) ||
      (Number.isFinite(effectiveRate) && effectiveRate > 0
        ? this.bucketForRate(effectiveRate)
        : Number.isFinite(effectiveRate) && effectiveRate <= 0
          ? null // 不限速：跳过令牌桶
          : this.bucket); // 未配置 → 默认单例桶（defaults.ratePerSec）
  }
