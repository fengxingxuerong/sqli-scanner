// ============================================================================
// e2e/extract-proof/run.mjs —— [D118 2026-10-20] 「数据泄露实证」验收
//
// ── 为什么需要它 ────────────────────────────────────────────────────────────
// 「给一个目标直接出可提交的漏洞报告」，最硬的证据不是「命中了某个通道」，而是
// **证明能读出对方的数据**（库名 / 表名 / 行）。这块原先在报告里是**坏的**：
//
//   实测 DVWA low（外部裁判 3 号）：
//     node server/bin/cli.js -u ".../sqli/?id=1&Submit=Submit" ... --dbs
//     ⇒ data.databases = ["'", "CAST((SELECT GROUP_CONCAT(schema_name SEPARATOR '", "') ..."]
//   即提取到的不是库名，而是 **payload 自身的残片**。
//
// 根因：响应把用户输入原样回显（DVWA low 的 `<pre>ID: {$id}`），于是
// `body.match(/__S__(.*?)__E__/)` 命中的第一处是 **payload 文本里的标记**，不是 SQL 结果。
// 修复：匹配前先 `stripEchoedPayload(body, payload)`（该工具 ErrorDetector /
// DBFingerprinter / blindExtractor 早已在用，唯独提取主路径没接）。
// 修复后实测：`--dbs` → `["dvwa","test"]`；`--dump -D dvwa -T users` → 5 行真实数据。
//
// 本套件把这条钉在真靶场上：**拿到的是真库名，而不是 payload 残片**。
//
// ── 依赖与门控（按需 SKIP，不伪装通过）──────────────────────────────────────
// 需要 DVWA 在跑（见 e2e/dvwa-lab/README.md）。未就绪时输出 [SKIP] 且 exit 0；
// acceptance 读**文本判据**而非退出码。
// ============================================================================

import { ScanManager } from '../../server/src/engine/ScanManager.js';

const DVWA = process.env.DVWA_EXTRACT_BASE || 'http://127.0.0.1:8099/vulnerabilities/sqli/';
const TIMEOUT_MS = Number(process.env.EXTRACT_PROOF_TIMEOUT_MS) || 120000;
const COOKIE = { security: 'low', PHPSESSID: 'extract-proof' };

const CONFIG = {
  concurrency: 1,
  ratePerSec: 0,
  retry: 1,
  timeoutMs: 12000,
  techniques: ['union', 'error', 'boolean', 'time'],
  level: 2,
  risk: 2,
  productionMode: false,
  testParameter: ['id'],
  enableExtract: true,
  // 只枚举库名：证明「读得到」即可，不拖表（拖表是 --dump 的事，且请求量更大）
  extractDbs: true,
};

// payload 残片特征：命中即说明提取拿到的是 payload 文本而非 SQL 结果
const RESIDUE_RE = /__S__|__E__|CAST\(|GROUP_CONCAT|information_schema\.schemata|SEPARATOR/i;

async function reachable() {
  try {
    const r = await fetch(`${DVWA}?id=1&Submit=Submit`, {
      headers: { cookie: 'security=low; PHPSESSID=proof' },
      signal: AbortSignal.timeout(8000),
    });
    return r.status === 200;
  } catch {
    return false;
  }
}

if (!(await reachable())) {
  console.log(`[SKIP] DVWA 不可达（${DVWA}）—— 数据泄露实证验收需要 DVWA 在跑，跳过（不计通过亦不计失败）`);
  console.log('       起法见 e2e/dvwa-lab/README.md（PHP 8.3 + MariaDB）；就绪后：');
  console.log('       node e2e/extract-proof/run.mjs');
  process.exit(0);
}

console.log(`[proof] 目标就绪：${DVWA}（DVWA low，官方真漏洞端点）`);
console.log('[proof] 断言：--dbs 必须拿到**真库名**，不得是 payload 残片');

const sm = new ScanManager({});
const id = await sm.start({
  url: `${DVWA}?id=1&Submit=Submit`,
  cookieParams: COOKIE,
  config: CONFIG,
});

const t0 = Date.now();
for (;;) {
  const st = sm.scans.get(id);
  if (st && (st.status === 'completed' || st.status === 'error')) break;
  if (Date.now() - t0 > TIMEOUT_MS) {
    sm.stop(id);
    console.log('❌ 扫描超时（见 timeoutMs）');
    process.exit(1);
  }
  await new Promise((r) => setTimeout(r, 200));
}

const rep = sm.getReport(id) || {};
const dbs = Array.isArray(rep?.data?.databases) ? rep.data.databases : [];
const requests = rep?.summary?.validity?.counts?.total || 0;
const vulns = (rep.vulns || []).length;

console.log(`\n检出漏洞：${vulns} 条 · 请求 ${requests} · data.databases = ${JSON.stringify(dbs)}`);

const residue = dbs.filter((d) => RESIDUE_RE.test(String(d)));
const realDbs = dbs.filter((d) => !RESIDUE_RE.test(String(d)) && String(d).trim());

console.log(`真库名：${realDbs.length ? realDbs.join(', ') : '（无）'}`);
if (residue.length) console.log(`❌ payload 残片：${residue.length} 条 —— ${JSON.stringify(residue)}`);

// 判据：① 必须先检出漏洞（否则提取无从谈起）② 拿到 ≥1 个真库名 ③ 无 payload 残片
// ④ 必须真的发了请求（防「没扫就通过」）
const pass = vulns > 0 && realDbs.length > 0 && residue.length === 0 && requests > 20;
console.log(
  pass
    ? '✅ 数据泄露实证成立：提取到的是真库名（非 payload 残片），报告可引用该实证'
    : `❌ 数据泄露实证不成立（漏洞=${vulns} 真库名=${realDbs.length} 残片=${residue.length} 请求=${requests}）`
);
process.exit(pass ? 0 : 1);
