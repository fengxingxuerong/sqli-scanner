// ============================================================================
// redteamVerdict.mjs —— [D134 2026-10-23] 红队套件输出 → 判定（可单测，不靠门禁自报）
//
// 为什么抽出来：验收门禁的纪律是「只吃事实数字」，而红队套件的输出有四种形态，
// 混起来判会把**环境缺失记成能力退化**。2026-10-23 实测到的那次：
//   宿主 3306 没起 → env.mjs 自己拉起一个 root 口令未知的 mysqld → 靶场 19 个端点
//   全部查库失败 → `vuln=19 hit=0 rate=0%` → 套件报 **0/19 检出率 0% FAIL**，
//   而真实性质是「靶场库不可用」= 缺依赖（本仓 D126 已立法：环境缺失不得伪装成能力退化）。
//
// 四种形态与判定：
//   · `[SKIP]`（没跑，且没有 round 行）      → skip（环境常态，不计通过也不算失败）
//   · `[BLOCKED]`（跑了但依赖坏，无 round） → blocked（**必须显形**：靶场库/口令不可用）
//   · 有 round 行但数字缺失                 → fail（判据取不到 = 门禁自己坏了，不许当通过）
//   · 有 round 行                           → 只认事实：必须全中且安全点零误报（D92）
// ============================================================================

/** 从文本里取一行标记后的说明（`[SKIP] xxx` / `[BLOCKED] xxx`） */
function tailOf(text, marker) {
  const re = new RegExp(`\\${marker}\\s*(.+)`);
  const m = re.exec(text);
  return (m ? m[1] : '原因未写明').trim().slice(0, 300);
}

/**
 * 判定红队套件输出。
 * @param {unknown} out 套件合并后的 stdout/stderr 文本
 * @returns {{ status: 'pass'|'fail'|'skip'|'blocked', facts: Record<string, unknown>, reason: string|null }} 判定结果
 */
export function classifyRedteamOutput(out) {
  const text = String(out ?? '');
  const hasRound = /\[redteam\] round=r2/.test(text);

  // 环境类：必须「没有 round 行」才算没跑过 —— 否则会把跑完后的旁支日志误判成跳过
  if (!hasRound && /\[BLOCKED\]/.test(text)) {
    const reason = tailOf(text, '[BLOCKED]');
    return { status: 'blocked', facts: { 原因: reason, 靶场库: '不可用' }, reason };
  }
  if (!hasRound && /\[SKIP\]/.test(text)) {
    const reason = tailOf(text, '[SKIP]');
    return { status: 'skip', facts: { 原因: reason }, reason };
  }

  const m = /\[redteam\] round=r2 vuln=(\d+) hit=(\d+) rate=(\d+)% safe=(\d+) fp=(\d+)/.exec(text);
  if (!m) {
    return { status: 'fail', facts: {}, reason: '未取到 gate-check 判据（输出格式变了？）' };
  }
  const [, total, hit, pct, safeN, fp] = m;
  const facts = { 检出: `${hit}/${total}`, 检出率: `${pct}%`, 安全点: safeN, 误报: fp };
  const bad = Number(fp) > 0;
  const missed = Number(hit) !== Number(total);
  const pass = Number(total) > 0 && !bad && !missed;
  const reason = bad
    ? `安全点误报 ${fp} 个`
    : Number(total) === 0
      ? '真值分母为 0（真值表为空 = 判据失效）'
      : missed
        ? `漏检 ${Number(total) - Number(hit)}/${total}（判据 D92：红队必须全中）`
        : null;
  return { status: pass ? 'pass' : 'fail', facts, reason };
}