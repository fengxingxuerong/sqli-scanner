// ============================================================================
// scripts/lib/failureDetail.mjs —— [D243] 从 TAP 输出里取「失败用例 + 断言消息」
//
// 为什么需要它（D242 的实测教训）：
//   D242 收口时 `facts:refresh` 首轮红了一个用例，复跑绿。facts-sync 的 D225 取证只打
//   `not ok` 行 —— 那一行**只有用例名**，看不到判据的输入量。修那条用例的归因需要三个数：
//   `maxGap` / `elapsed` / `reqs`（它们决定「环境慢」还是「逻辑失控」）。
//   拿不到数 ⇒ 只能盲调阈值 ⇒ 那不是修复，是赌。
//
// TAP 里断言消息在 `error:` 行（node:test 的 tap reporter 把 YAML 块跟在 not ok 之后）：
//
//   not ok 1398 - ★修复①★ …
//     ---
//     duration_ms: 8613.65
//     error: 'AssertionError: …（maxGap=52ms ≤ 150ms、elapsed=8000ms ≤ 20000ms …）'
//
// 所以这里把「用例名 + 断言消息」配对取出，作为取证输出。
// ⚠ 只做**取证**，不改变任何判定：取不到就返回空，调用方按原样处理。
// ============================================================================

/**
 * 从 TAP 输出中提取失败用例及其断言消息。
 * @param {string} tapOutput 完整 TAP 文本
 * @param {number} [limit] 最多取几条（默认 10）
 * @returns {Array<{title:string, detail:string}>} title=not ok 行（截断 160 字），detail=error 行（截断 400 字）
 */
export function extractFailureDetails(tapOutput, limit = 10) {
  const lines = String(tapOutput ?? '').split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length && out.length < limit; i++) {
    if (!/^\s*not ok /.test(lines[i])) continue;
    const title = lines[i].trim();
    let detail = '';
    // error 行紧跟在 not ok 之后的 YAML 块里；窗口给 20 行足够宽松，又不至于串到下一个用例
    for (let j = i + 1; j < Math.min(i + 20, lines.length); j++) {
      const m = lines[j].match(/^\s*error:\s*(.*)$/);
      if (m) { detail = m[1].trim(); break; }
    }
    out.push({ title: title.slice(0, 160), detail: detail.slice(0, 400) });
  }
  return out;
}
