// =====================================================================
// lifecycle.js — 扫描生命周期：暂停/信号下沉（_wrapWithSignal/_waitWhilePaused）
// 与上下文回收（_retire TTL / _disposeScan 立即清理 / _evictIfOverLimit 超限淘汰）。
// 自 ScanManager.js 拆出（纯搬移）：由 ScanManager.prototype 挂载（this 语义不变）。
// =====================================================================
import * as eventBus from '../../core/eventBus.js';
import { releaseScanScope } from '../../core/scopeGuard.js';

// 暂停轮询间隔：与 scan/detect.js 的点边界等待同量级，忙等与迟钝之间取个折中
const PAUSE_POLL_MS = 100;

  // [⑮] 包装 httpClient：自动将扫描级 signal 注入到每次 request 调用
  // [P0-FIX 2026-09-28 接口靶场] 顺带把**暂停**下沉到请求边界：
  //   暂停此前只在 scan/detect.js 的「点边界」生效，而一个点的检测是几十上百个包
  //   （布尔/时间盲注尤甚）。单参数目标按暂停键后靶站仍继续被打满，实测 2.6s 内又发了
  //   5 个包 —— "暂停"在实战里的用途恰恰是"目标开始报警了先停手"，那一步必须真的停手。
  //   挂在唯一一个所有探测请求都会经过的出口上（而不是去改每个检测器），
  //   暂停期间不占用连接、不产生请求，resume 后原样继续。
export function _wrapWithSignal(scanId, client) {
    const signal = this.getSignal(scanId);
    if (!signal || !client || typeof client.request !== 'function') return client;
    return {
      ...client,
      request: async (opts) => {
        await this._waitWhilePaused(scanId);
        return client.request({ ...opts, signal });
      },
    };
  }

  /**
   * 暂停时阻塞到 resume/stop（与点边界等待同一语义：不终止在途请求、不回收上下文）。
   * @param {string} scanId
   */
export async function _waitWhilePaused(scanId) {
    for (;;) {
      const s = this.scans.get(scanId);
      if (!s || !s.paused || s.cancelled) return;
      await new Promise((resolve) => setTimeout(resolve, PAUSE_POLL_MS));
    }
  }

  // 扫描上下文回收：completed/stopped/error 后置 retiredAt，TTL 到期清 scans 条目 + eventBus + 限速桶
export function _retire(scanId) {
    const s = this.scans.get(scanId);
    if (!s || s._retired) return;
    s._retired = true;
    s.retiredAt = new Date().toISOString();
    const timer = setTimeout(() => {
      this._disposeScan(scanId);
    }, this.retireTtlMs);
    if (typeof timer.unref === 'function') timer.unref(); // 不阻塞进程退出
    s._retireTimer = timer;
  }

  // 立即清理某次扫描的全部上下文（TTL 到期 / 超限淘汰）
export function _disposeScan(scanId) {
    // [P0-SEC] 同步回收 scope 登记（防同 id 复用旧范围，也防 Map 无界增长）
    releaseScanScope(scanId);
    const rec = this.scans.get(scanId);
    this.scans.delete(scanId);
    eventBus.dispose(scanId);
    if (this._scanClients.has(scanId)) {
      if (typeof this.httpClient.removeBucket === 'function') this.httpClient.removeBucket(scanId);
      // [sqlmap 对标] --max-requests：清理请求计数（防 Map 无界增长）
      if (typeof this.httpClient.removeRequestCount === 'function') this.httpClient.removeRequestCount(scanId);
      // [P1-FIX 2026-09-05] Cookie Jar 随扫描退役清理（防跨扫描会话泄漏 + Map 无界增长）
      if (typeof this.httpClient.clearJar === 'function') this.httpClient.clearJar(scanId);
      this._scanClients.delete(scanId);
    }
    if (rec && rec._retireTimer) clearTimeout(rec._retireTimer);
  }

  // scans Map 容量上限：超限淘汰最旧扫描
  // [MERGED: engine ★FIX-2] 只淘汰「非 running」的扫描：运行中的扫描若被淘汰，报告会立即
  // 从 getReport 中消失（用户拿不到结果），而 _run 的请求仍在继续（脱离治理）。
  // 全部 running 时宁可暂时超限也不淘汰在途扫描。
export function _evictIfOverLimit() {
    if (this.scans.size <= this.maxScans) return;
    let victim = null;
    let oldestTs = Infinity;
    for (const [id, rec] of this.scans) {
      if (rec.status === 'running') continue; // 不淘汰运行中的扫描
      const ts = rec.createdAt || 0;
      if (ts < oldestTs) {
        oldestTs = ts;
        victim = id;
      }
    }
    if (victim) this._disposeScan(victim);
  }
