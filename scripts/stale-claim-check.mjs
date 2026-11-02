#!/usr/bin/env node
// ============================================================================
// scripts/stale-claim-check.mjs —— [D234] 「已被推翻的口径又写回当前文档」检测
//
// 为什么需要它（本仓真实的复发史，不是假想）：
//   · D115（2026-10-20）用 testParamNames 推翻 D114 的「Benchmark 4/12 漏检缺口」，
//     D117 扩到 178/178；`acceptance.mjs` 早已把 benchmark 接成门禁套件。
//   · D130（2026-10-23）只改了主 `README.md` 的两处口径，**e2e/ 下的 README 没扫到**。
//   · 2026-10-22 的会话记录里已写「Benchmark README 三处口径互不相等」，**记了没修**。
//   · 直到 D234（2026-11-02）才发现 `e2e/README.md`（两处重复行）与
//     `e2e/benchmark-lab/README.md` 仍在说「参考靶场、不接门禁、真值 4/12」——腐烂 13 天。
//
// 结论：**光靠"记得改"不行**，被推翻的数字会以「顺口提一句」的形式爬回文档。
// 本门禁只做一件事：当前状态文档（README 类）里**不得复述已作废的口径**，
// 除非同一行明确标注了「作废 / 已被推翻 / 历史」。
//
// 口径边界（别把判据写松）：
//   · 只扫 **README 类当前文档**（`README*.md` / `AGENTS.md`），排除 `docs/archive/`；
//     `CHANGELOG.md`、`docs/*-2026-*.md`、`e2e/**/results/` 是**历史留痕**，刻意不扫。
//   · 规则是**显式清单**（不是"自动从台账推断"）：宁可少抓，也不要用脆弱的启发式
//     把正常叙述判成错。新增一条被推翻的口径时，往 RULES 里加一行并写 why。
//
// 用法：
//   node scripts/stale-claim-check.mjs              # 退出码即结论
//   node scripts/stale-claim-check.mjs --selftest   # 判据自证（构造样本必须红）
//
// 退出码：0 = 无残留 / 1 = 检出残留（或自证失败）
// ============================================================================
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * 规则表：每条 = 一个「已作废口径」的识别式 + 允许出现的上下文词 + 适用范围。
 * `scope` 存在时只对路径匹配的文档生效 —— 同一句话在别的靶场文档里可能是**正确**的
 *（dvga 确实仍为参考证据不接门禁），不加 scope 会把正确表述判成错。
 * ⚠️ 加规则时同步在 CHANGELOG 记录「哪条结论被推翻、谁推翻的」——否则判据会变成无源之水。
 */
const RULES = [
  {
    id: 'benchmark-stale-in-lab',
    // benchmark 自己的 README：句子里不一定出现 "Benchmark"（如「当前真值 4/12」单独成行），所以 re 放宽带
    scope: /benchmark-lab[\\/]README\.md$/i,
    re: /4\/12|20\/504|参考靶场|参考\/已知缺口|已知漏检缺口|不接\s*acceptance|修缺口前不接/,
    // allow 只放「这行在说历史 / 在否认旧说法 / 在讲边界」的显式标记。
    // 误报会让门禁被关掉，所以宁可漏报：**没有标记的断言才报**。
    allow: /作废|已被推翻|历史|原结论|D114|D115|D234|已接|没测成|不是参考|与实际相反|不外推|只证明/,
    why: 'D115/D117 已把口径改为全量 178/178、门禁基线 43/43；acceptance.mjs 早已接 benchmark 套件，referenceOnly 名单里从未有它。4/12 是 D114「没测成」的历史快照',
  },
  {
    id: 'benchmark-stale-in-overview',
    // e2e 总览里混着多个靶场（DVGA 说「参考靶场不接门禁」是**正确**的），
    // 因此要求同一行先出现 benchmark 主语，才判旧状态词。
    scope: /e2e[\\/]README\.md$/i,
    re: /benchmark[^\n]{0,140}(4\/12|20\/504|参考靶场|参考\/已知缺口|已知漏检缺口|不接\s*acceptance|修缺口前不接)/i,
    allow: /作废|已被推翻|历史|原结论|D114|D115|D234|已接|没测成|不是参考|与实际相反|不外推|只证明/,
    why: '同 benchmark-stale-in-lab：该靶场早已接 acceptance，旧的「参考/已知缺口、不接门禁」定性作废',
  },
];

/** 只扫这些文件（README 类当前文档） */
function targetFiles() {
  const out = [join(ROOT, 'README.md'), join(ROOT, 'AGENTS.md')];
  const en = join(ROOT, 'README.en.md');
  out.push(en);
  // e2e/**/README.md 与 docs/**/README.md
  const walk = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const ent of entries) {
      const p = join(dir, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === 'node_modules' || ent.name === 'archive' || ent.name === 'results') continue;
        walk(p);
      } else if (/^README(\.en)?\.md$/i.test(ent.name)) {
        out.push(p);
      }
    }
  };
  walk(join(ROOT, 'e2e'));
  walk(join(ROOT, 'docs'));
  return [...new Set(out)].filter((p) => {
    try { return statSync(p).isFile(); } catch { return false; }
  });
}

/**
 * 扫一个文本，返回命中（行号 + 规则）。
 * @param {string} text 文档正文
 * @param {string} [filePath] 文档路径（用于 scope 判定；不传 = 全部规则生效）
 * @returns {Array<{line:number, rule:string, text:string}>}
 */
function scanText(text, filePath = '') {
  const hits = [];
  const lines = text.split(/\r?\n/);
  const active = RULES.filter((r) => !r.scope || r.scope.test(filePath));
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    for (const r of active) {
      if (!r.re.test(l)) continue;
      if (r.allow.test(l)) continue;
      hits.push({ line: i + 1, rule: r.id, text: l.trim().slice(0, 160) });
    }
  }
  return hits;
}

function selftest() {
  const LAB = 'e2e/benchmark-lab/README.md';
  const OVERVIEW = 'e2e/README.md';
  const bad = [
    // 靶场自带 README：单独一行的断言必须抓
    [LAB, '| Benchmark | 20/504 子集真值 4/12、安全 0/8 |'],
    [LAB, '当前真值 4/12，修缺口前不接门禁'],
    [LAB, '按 DVGA 同口径登记为参考靶场，不接 acceptance，未就绪时 SKIP'],
    [LAB, '**外部裁判 4 号（参考/已知缺口）**：OWASP Benchmark'],
    // e2e 总览：同一行必须带 benchmark 主语才判（DVGA 行不算）
    [OVERVIEW, '| `benchmark-lab` | **外部裁判 4 号（参考/已知缺口）**：子集 query 真值 10 + query 安全 8 |'],
  ];
  const good = [
    [LAB, '原「20/504 子集 4/12」被 D115 推翻，旧数字作废'],
    [LAB, 'D114 的 4/12 是「没测成」不是「检不出」'],
    [LAB, 'Benchmark 已接 acceptance（cases.json 74 条 → 43/43 + 0/24）'],
    [LAB, '**不在 referenceOnly 名单里**，即它是门禁靶场，不是参考靶场'],
    [OVERVIEW, '五个外部裁判都在本机起了真靶场，其中 Benchmark 三清单全跑（187/187）'],
  ];
  let fail = 0;
  for (const [f, s] of bad) {
    if (!scanText(s, f).length) { console.log(`✖ 漏报 [${f}]：${s}`); fail++; }
  }
  for (const [f, s] of good) {
    if (scanText(s, f).length) { console.log(`✖ 误报 [${f}]：${s}`); fail++; }
  }
  // scope 自证：同一句「参考靶场不接门禁」在非 benchmark 文档里必须**不**命中
  // （dvga 的这类表述是正确的，判据不许误伤）
  const dvgaLines = [
    ['e2e/dvga-lab/README.md', '仍为单端点参考证据，不接门禁'],
    [OVERVIEW, '| **DVGA（GraphQL 面参考靶场）** | 见 `e2e/dvga-lab/README.md` | 仍为单端点参考证据，不接门禁 |'],
  ];
  for (const [f, s] of dvgaLines) {
    if (scanText(s, f).length) { console.log(`✖ 误报 [${f}]：${s}（scope 失效，误伤其他靶场）`); fail++; }
  }
  console.log(fail
    ? `✖ 自证失败 ${fail} 例`
    : `✔ 自证通过（漏报 ${bad.length} 例全抓、误报 ${good.length + dvgaLines.length} 例全放过）`);
  process.exit(fail ? 1 : 0);
}

function main() {
  if (process.argv.includes('--selftest')) return selftest();
  const files = targetFiles();
  const all = [];
  for (const f of files) {
    let text;
    try { text = readFileSync(f, 'utf-8'); } catch { continue; }
    // ⚠️ 必须把相对路径传进去：规则带 scope，缺路径会让 active 规则集为空 ⇒ 判据恒绿（本批自证抓过）
    const rel = relative(ROOT, f);
    for (const h of scanText(text, rel)) all.push({ file: rel, ...h });
  }
  if (all.length) {
    console.error(`✖ 检出 ${all.length} 处已作废口径的复述（当前文档不得引用被推翻的数字）：`);
    for (const h of all) {
      const rule = RULES.find((r) => r.id === h.rule);
      console.error(`  ${h.file}:${h.line}  [${h.rule}]  ${h.text}`);
      if (rule) console.error(`      为什么错：${rule.why}`);
    }
    console.error('\n修法：改成本轮口径；若确实是在记历史，同一行要写「作废/已被推翻/历史」。');
    return process.exit(1);
  }
  console.log(`✔ 未检出已作废口径的复述（扫描 ${files.length} 个 README 类文档，${RULES.length} 条规则）`);
}

main();
