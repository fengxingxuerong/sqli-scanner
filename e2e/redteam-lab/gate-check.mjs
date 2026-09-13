// ============================================================================
// e2e/redteam-lab/gate-check.mjs —— 红队评测门禁判据（直接读结果文件算准确率）
// ============================================================================
// 为什么单独一个脚本：门禁若去解析 run-scan 的人类可读输出（"r2 done: 19/26 hit"），
// 分母含安全点，且文本格式一变就误判。这里**直接读 ground-truth 与 results 文件**算真值：
//   - 检出率 = 真值 vuln 中被命中的比例（分母只含 vuln）
//   - 误报数 = 真值 safe 中被误报为命中的数量（分母只含 safe）
// 输出一行标准化结果供门禁解析，退出码即结论。
//
// 用法：node e2e/redteam-lab/gate-check.mjs [r1|r2]
// ============================================================================
import { readFileSync } from 'node:fs';

const round = process.argv[2] || 'r2';
const gt = JSON.parse(readFileSync(new URL('./ground-truth.json', import.meta.url), 'utf8'));
const res = JSON.parse(readFileSync(new URL(`./results-${round}.json`, import.meta.url), 'utf8'));
const byId = Object.fromEntries(res.map((r) => [r.id, r]));

const vulns = gt.filter((g) => g.kind === 'vuln');
const safes = gt.filter((g) => g.kind === 'safe');

// 真值守卫：地面真值必须已确认（truth=true 才计入分母），否则靶场没起来时
// 会把「全部未命中」算成「全部正确」，出现假绿。
const verifiedVulns = vulns.filter((v) => v.truth === true);
const hit = verifiedVulns.filter((v) => byId[v.id]?.hit).length;
const fp = safes.filter((s) => byId[s.id]?.hit).length;
const rate = verifiedVulns.length ? Math.round((hit / verifiedVulns.length) * 100) : 0;

if (verifiedVulns.length !== vulns.length) {
  console.log(
    `[redteam] ⚠️ 真值表有 ${vulns.length - verifiedVulns.length} 个 vuln 点未通过 selftest 确认` +
      `（truth=false）——分母只计已确认项，请先跑 npm run redteam:truth 重建真值`
  );
}

console.log(
  `[redteam] round=${round} vuln=${verifiedVulns.length} hit=${hit} rate=${rate}% safe=${safes.length} fp=${fp}`
);

// 判据：调参口径 ≥90% 且零误报；安全点一个都不能被误报
const pass = rate >= 90 && fp === 0 && verifiedVulns.length > 0;
console.log(pass ? '[PASS] 红队实战评测' : `[FAIL] 红队实战评测（rate=${rate}% fp=${fp}）`);
process.exit(pass ? 0 : 1);
