// ============================================================================
// bin/cli/batchPool.js —— 批量编排：并发池 + 故障隔离 + 汇总（对标 sqlmap -m / -l）
// ============================================================================
// 为什么抽出来（原实现的两处 pool 是粘贴复制，且带同一个缺陷）：
//   `-m`（URL 列表）与 `-l`（请求日志）各写了一份并发池，worker 里直接 `await worker(item)`，
//   **任何一个目标抛错 ⇒ Promise.all 立刻 reject ⇒ 整批中断**：
//     · 死目标（连接被拒）会让排在后面的正常目标一个都不跑；
//     · 已跑完的那些报告也一并丢掉（results 只存在于内存里，池一 reject 就没人写盘了）；
//     · 顶层没有 catch ⇒ 表现是 unhandled rejection，退出码 1，且**看不出是哪个目标坏的**。
//   ghauri 的批量同样有这个短板，实战后果是「100 个目标里第 3 个不通 ⇒ 97 个白等」。
//
// 修法（本模块的两条硬语义）：
//   ① **故障隔离**：单个目标的失败只记进 failures，不打断其它目标（池跑完才算完）；
//   ② **结果不丢**：成功目标的报告照常进 results，由调用方落盘；失败目标在摘要里**点名**。
// 退出码语义保持不变（有 High/Critical → 2）；新增：全批失败 → 1（与"扫了但没高危"区分开）。
// ============================================================================

/**
 * 并发池：按 concurrency 并行消费 items，单个 worker 抛错**不中断整批**。
 *
 * @param {any[]} items 待处理项
 * @param {(item:any)=>Promise<any>} worker 处理函数
 * @param {number} [concurrency] 并发度（<1 时按 1 处理）
 * @param {{ onError?:(item:any, err:any)=>void }} [opts]
 * @returns {Promise<{ errors: Array<{item:any, message:string}> }>} 逐条错误（供摘要点名）
 */
export async function runPool(items, worker, concurrency = 1, opts = {}) {
  const queue = Array.isArray(items) ? items.slice() : [];
  const errors = [];
  let cursor = 0;
  const lanes = Math.max(1, Math.min(Math.floor(concurrency) || 1, queue.length));
  const next = async () => {
    while (cursor < queue.length) {
      const item = queue[cursor++];
      try {
        await worker(item);
      } catch (e) {
        const rec = { item, message: String(e?.message || e) };
        errors.push(rec);
        if (typeof opts.onError === 'function') opts.onError(item, e);
      }
    }
  };
  await Promise.all(Array.from({ length: lanes }, () => next()));
  return { errors };
}

/**
 * 批量扫描编排（与具体"怎么扫一个目标"解耦，便于单测注入失败）。
 *
 * @param {object} p
 * @param {any[]} p.urls 目标列表
 * @param {number} [p.concurrency] 并发度
 * @param {(url:any)=>Promise<any>} p.scanOne 扫描单个目标（抛错 = 该目标失败）
 * @param {(msg:string)=>void} [p.log] 进度输出（默认 stderr）
 * @param {(report:any)=>string|null} [p.audit] 额外复核钩子：返回非空字符串 ⇒ 该目标进
 *   needsReview（**扫完了但可能什么都没测**，如 0 注入点）。与 failures 区分：
 *   failures = 进程/编排层异常；needsReview = 报告产出了但结论不可信。
 * @param {(item:any)=>string} [p.labelOf] 目标的**人类可读**名字（默认 String(item)）。
 *   集合条目是对象（带 method/headers/body），打印出来会是 `[object Object]` ——
 *   而「点名」正是本模块存在的理由，所以名字必须由调用方给准。
 * @returns {Promise<{results:Array, failures:Array, needsReview:Array<{url:any,why:string}>, summary:object}>}
 */
// ⚠ 默认值必须 cast：`= {}` 会被 TS 按解构出的必填字段（urls/scanOne）判定为缺属性（TS2739），
//    而运行期 `urls` 缺省是**合法的**（空列表，见 summarizeBatch 的 `|| []` 兜底）。
export async function runBatch({ urls, concurrency = 1, scanOne, log, audit, labelOf } = /** @type {any} */ ({})) {
  const out = (m) => (typeof log === 'function' ? log(m) : console.error(m));
  const name = (item) => (typeof labelOf === 'function' ? labelOf(item) : String(item));
  const results = [];
  const failures = [];
  const needsReview = [];
  const list = Array.isArray(urls) ? urls.slice() : [];
  await runPool(
    list,
    async (url) => {
      try {
        const report = await scanOne(url);
        const rec = {
          url,
          report,
          riskLevel: report?.riskLevel || 'error',
          vulns: report?.vulns?.length || 0,
        };
        results.push(rec);
        let why = '';
        if (typeof audit === 'function') {
          try { why = audit(report) || ''; } catch { why = ''; }
        }
        if (why) needsReview.push({ url, why });
        out(`[${results.length + failures.length}/${list.length}] ${name(url)} → ${rec.riskLevel}${why ? '（需复核）' : ''}`);
      } catch (e) {
        failures.push({ url, message: String(e?.message || e) });
        out(`[${results.length + failures.length}/${list.length}] ${name(url)} → 失败：${String(e?.message || e).slice(0, 160)}`);
      }
    },
    concurrency,
  );
  return { results, failures, needsReview, summary: summarizeBatch(results, failures, needsReview) };
}

/**
 * 批量汇总（纯函数）：风险分布 + 失败计数 + 是否有高危。
 * @param {Array<{riskLevel?:string}>} results
 * @param {Array<any>} failures
 */
export function summarizeBatch(results, failures, needsReview = []) {
  const byRisk = {};
  for (const r of results || []) {
    const k = r?.riskLevel || 'error';
    byRisk[k] = (byRisk[k] || 0) + 1;
  }
  const hasHigh = (results || []).some((r) => r?.riskLevel === 'Critical' || r?.riskLevel === 'High');
  return {
    total: (results || []).length + (failures || []).length,
    ok: (results || []).length,
    failed: (failures || []).length,
    needsReview: (needsReview || []).length,
    byRisk,
    hasHigh,
    // 全批失败与"扫了但没洞"必须能区分：前者是编排/目标问题，后者是结论
    allFailed: (results || []).length === 0 && (failures || []).length > 0,
  };
}

export default { runPool, runBatch, summarizeBatch };
