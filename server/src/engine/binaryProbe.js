// ============================================================================
// binaryProbe.js —— 二分探测的统一判据（列数 / 长度 / 字符 / 任意单调量）
//
// 由来（2026-09-17）：同一个病根在本项目出现了三次，见 docs/统一探测判据-设计.md
//   ① columnGuess：列数收敛到上限 50 → UNION 必败
//   ② blindExtractor._extendLength：长度扩展到上限 65531 → "提取 alice" 变成提 6.5 万字符
//   ③ _timeBinarySearch：疑似同类（未验证）
//   共同形态：二分判据只有真/假两态，真假来自"响应差异"；目标恒 200 + 错误页回显时
//   差异被抹平 → 失去方向 → 一路判真 → **顶到上限** → 下游拿着荒谬值继续跑且不报错。
//
// 本模块提供的判据组合：
//   · **主判据** judge(res) —— 调用方原有逻辑（真=偏大 / 假=偏小）；
//   · **备份判据** shape(res) === failShape —— 用于主判据失效的目标；
//   · **两段式**：先只用主判据跑完整二分；**没顶到上限就直接返回**（既有目标零额外请求）；
//     **仅当顶到上限**才取两端点响应骨架做自检，可区分才用备份判据重跑；
//   · **capped 标记**：结果顶到上限时明确告知调用方 —— 由调用方决定"放弃"而非"照用"。
//
// 调用方约定（重要）：拿到 `capped: true` 时**不得把该值当作正常结果使用**。
//   列数 capped → 返回 null 让 UNION 放弃；长度 capped → 判该字段探测失败。
//   今天三次事故里，判据失效只是起因，**拿错误值继续跑才是伤害**。
// ============================================================================

/**
 * 二分探测（含备份判据与上限自检）。
 *
 * @param {(n: number) => Promise<any>} probe 发探测请求（返回 {status, data} 或 null）
 * @param {object} opts
 * @param {number} opts.lo 下界（含）
 * @param {number} opts.hi 上界（含）；结果等于 hi 即视为「顶到上限」
 * @param {(res: any) => boolean} opts.judge 主判据：true=偏大 → 收缩上界
 * @param {(res: any) => string} [opts.shape] 响应骨架提取（配合备份判据用）
 * @param {boolean} [opts.trackReliable] 是否统计「是否拿到过 2xx/3xx」（原 columnGuess 语义）
 * @param {number} [opts.shapeTrueAt] 取基准时用于「判据**已知为真**」的探测点（默认 `lo`）。
 *   ⚠️ 默认值只对「`lo` 端必真」的调用方成立 —— `columnGuess` 的 `lo=1`（`ORDER BY 1` 必成功）
 *   满足；但 `_binarySearch` 的延伸段 `lo=256` **不满足**（真实长度 5 时 `x > 256` 为假）。
 *   那种场景要显式给一个必真点（长度二分传 `0`：`x > 0` 对非空值必真）。
 * @param {number} [opts.shapeFalseAt] 取基准时用于「判据**已知为假**」的探测点（默认 `hi`）。
 * @param {'gt'|'lt'} [opts.direction] **判据方向**（关键，迁移时最容易搞反）：
 *   · `'gt'`（默认）：`judge` 为真表示「**结果偏大**」→ 收缩上界。语义同 `columnGuess`
 *     的「`ORDER BY n` 报错 ⇒ 列数比 n 少」。此时 `n` = 最大的「未偏大」值。
 *   · `'lt'`：`judge` 为真表示「**mid 偏小**」→ 抬高下界。语义同 `_binarySearch` 的
 *     「`x > mid` 为真 ⇒ 真实值比 mid 大」。此时 `n` = 最大的「判据为真」值。
 *   ⚠️ 这两个方向在代码上只差一个分支，但搞反会让二分倒着跑（实测一次挂掉 21 个用例）。
 * @returns {Promise<{n:number, reliable:boolean, capped:boolean}>}
 */
export async function binaryProbe(probe, {
  lo, hi, judge, shape, trackReliable = false, direction = 'gt',
  shapeTrueAt, shapeFalseAt,
}) {
  const runOnce = async (backupShape) => {
    let a = lo;
    let b = hi;
    let ans = lo - 1;
    let reliable = false;
    while (a <= b) {
      const mid = Math.floor((a + b) / 2);
      const res = await probe(mid);
      if (trackReliable) {
        const st = Number(res?.status ?? 0);
        if (st >= 200 && st < 400) reliable = true;
      }
      // 偏大 = 主判据成立，或（启用备份时）响应与「必然失败」端点同形
      let over = false;
      try {
        over = Boolean(judge(res));
      } catch {
        over = false;
      }
      if (!over && backupShape != null && typeof shape === 'function') {
        try {
          over = shape(res) === backupShape;
        } catch {
          over = false;
        }
      }
      if (direction === 'lt') {
        // judge 为真 = mid 偏小 ⇒ 抬高下界；为假 = mid 偏大 ⇒ 收缩上界
        if (over) {
          ans = mid;
          a = mid + 1;
        } else {
          b = mid - 1;
        }
      } else {
        // judge 为真 = 结果偏大 ⇒ 收缩上界
        if (over) b = mid - 1;
        else {
          ans = mid;
          a = mid + 1;
        }
      }
    }
    // 不钳制：让调用方按自己的语义处理（列数要 >=1，长度二分允许 -1 表示"全假"）。
    // 原实现（columnGuess）用 `ans <= 0 ? 1 : ans`，那是列数的语义，不该固化在通用 helper 里。
    return { n: ans, reliable };
  };

  // ── 第 1 段：只用主判据（既有目标行为完全不变）──
  let r = await runOnce(null);
  if (r.n < hi) return { ...r, capped: false };

  // ── 第 2 段：仅当顶到上限 → 形态自检 ──
  // 先显式判一次 shape 是否存在：endShape 内部虽有同样的运行时检查，
  // 但 TS 无法从字符串比较里收窄 `shape` 的类型，这里判一次更清晰。
  // 基准必须来自「判据已知相反」的两点：默认取区间端点，但 `_binarySearch` 那类
  // 「lo 端未必为真」的调用方需显式指定真点（见 shapeTrueAt 的说明）。
  const failShape = typeof shape === 'function'
    ? await endShape(probe, shapeTrueAt ?? lo, shapeFalseAt ?? hi, shape)
    : null;
  if (failShape == null) return { ...r, capped: true }; // 不可区分 → 明确标记，别硬猜

  const r2 = await runOnce(failShape);
  return { ...r2, capped: r2.n >= hi };
}

/**
 * 取两端点响应骨架：hi 端（应「偏大」）与 lo 端（应「偏小」）。
 * 两者同形（无法区分）或过短 → 返回 null，表示**备份判据不可用**。
 * @param {(n:number)=>Promise<any>} probe
 * @param {number} lo
 * @param {number} hi
 * @param {(res:any)=>string} shape
 * @returns {Promise<string|null>}
 */
async function endShape(probe, lo, hi, shape) {
  if (typeof shape !== 'function') return null;
  try {
    const loRes = await probe(lo);
    const hiRes = await probe(hi);
    const loShape = String(shape(loRes) || '');
    const hiShape = String(shape(hiRes) || '');
    if (!loShape || !hiShape || loShape === hiShape || hiShape.length < 8) return null;
    return hiShape;
  } catch {
    return null;
  }
}

export default binaryProbe;
