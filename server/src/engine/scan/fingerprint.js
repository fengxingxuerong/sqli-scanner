// =====================================================================
// fingerprint.js — 指纹结果按「目标|点类别」分桶缓存（_fingerprintCached）：
// in-flight Promise 共享 + 未定库不缓存 + FP_RETRY_MAX 重跑预算。
// 自 ScanManager.js 拆出（纯搬移）：由 ScanManager.prototype 挂载（this 语义不变）。
// =====================================================================
import { logger } from '../../core/logger.js';

  // 指纹结果按目标缓存（同目标多注入点不重复跑 8-9 请求指纹）。
  // fpCache 存 Promise：并发 worker 同时命中 miss 时共享同一 in-flight 指纹，杜绝重复请求。
  // [CTX-FIX 2026-09-18] **判不出的结果不共享**：整轮指纹是用「触发它的那一个注入点」的上下文跑的
  //   （闭合前缀与点位置直接决定探针能否执行）。开 --test-headers/--test-path 后排在最前的常常是
  //   path/header 点，其上下文会把整轮指纹跑废，而 null 一旦被缓存就被后面每个点继承：
  //   实测 blackbox-lab C2-blindtime（真 MySQL 时间盲注点）r2 档因此 dbms=null → time 通道按
  //   未知方言投放 → 漏检；同一目标关掉 header/path 点单跑则 dbms=MySQL 正常命中。
  //   现给「重跑」留预算：最多 FP_RETRY_MAX+1 次尝试，成功定库的目标零额外请求（行为与原来一致）。
export async function _fingerprintCached(fpCache, ctxBase, target, point) {
    // [CTX-FIX 2026-09-18] 缓存键按「点类别」分桶，不再整台目标共享一份：
    // path / header 点的探针上下文与 query/body 点往往完全不同（实测 /api/sleep 的 path 点
    // 探针全部 404 → 整轮指纹 null），而检测是多点**并发**跑的（detect.js 里 Promise.all），
    // 谁先跑谁定调 → 真能出结果的 query 点只能继承那份 null。
    // 分桶后最多每类各跑一次指纹（query/body/cookie 仍共用 'main'，与原行为等价）。
    const cls = point?.location === 'path' || point?.location === 'header' ? point.location : 'main';
    const key = `${target.baseUrl || target.url || (target.mode === 'direct' ? 'direct' : 'target')}|${cls}`;
    const FP_RETRY_MAX = 2;
    let slot = fpCache.get(key);
    if (!slot) {
      slot = { promise: null, attempts: 0 };
      fpCache.set(key, slot);
    }
    if (!slot.promise) {
      slot.attempts++;
      const allowRetry = slot.attempts <= FP_RETRY_MAX;
      slot.promise = this.fp
        .fingerprint({ ...ctxBase, target, point })
        .catch((e) => {
          logger.warn(`指纹识别失败：${e.message}`);
          return null;
        })
        .then((res) => {
          // 未定出库 → 撤下这条 in-flight 记录，让下一个注入点用自己的上下文再试
          if (allowRetry && (!res || !res.dbms)) slot.promise = null;
          return res;
        });
    }
    return await slot.promise;
  }
