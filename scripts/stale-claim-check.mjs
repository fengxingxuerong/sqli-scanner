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
//   · 扫 **README 类当前文档**（`README*.md` / `AGENTS.md`）+ **根目录交付/审计报告**
//     （[D285] `<主题>-YYYY-MM-DD.md` 家族，DELIVERY_REPORT_RE），排除 `docs/archive/`；
//     `CHANGELOG.md`、`docs/*-2026-*.md`、`e2e/**/results/` 是**历史留痕**，刻意不扫。
//     [D285] 为什么根目录交付报告必须扫：它们是「过期结论被上游顺口引用」的重灾区 ——
//     11-01《交付状态报告》的「27/27 全断言」过期结论存活 11 天才被人工停用
//     （2026-11-12 结项报告 §6-7/§9 实证缺口）。带 ⛔ 作废横幅的整份按历史留痕豁免
//     （bannerExempt 规则），与「正文一字未删」的既定口径一致。
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

// [D285] 根目录交付/审计报告的命名惯例：`<主题>-YYYY-MM-DD.md`，主题以「交付」或「全方面」开头。
// 新的根目录交付报告沿用该命名即自动进扫描集合，无需改本文件。
const DELIVERY_REPORT_RE = /(?:^|[\\/])(?:交付|全方面)[^\\/]*\d{4}-\d{2}-\d{2}\.md$/i;
// [D285] 作废横幅：只认文档头部的显式声明（前 15 行内出现即整份按历史留痕豁免 bannerExempt 规则）。
// 正文里的行级 allow 词不受横幅影响，照常生效。
const BANNER_RE = /口径作废|已作废|时点快照|被取代|⛔/;
const BANNER_SCAN_LINES = 15;

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
  {
    id: 'delivery-acceptance-2727',
    // [D285] 「27/27 全断言」是 D269 后的已作废口径：SKIP/BLOCKED 也算跑过 ⇒ 27 套件 ≠ 全绿；
    // README:776 实测没有任何一次运行达到 27/27 全断言；现行口径 25/27 跑出断言 + 2 SKIP。
    // 只限根目录交付报告家族 —— README 类文档用「25/27」等现行口径叙述不受影响。
    scope: DELIVERY_REPORT_RE,
    re: /27\s*\/\s*27|27\s*PASS\s*\/\s*0\s*SKIP|27\s*套件\s*全断言/,
    allow: /作废|推翻|历史|不再成立|时点快照|过期|取代|现行|D269|没有任何一次|没有一次|未达成|≠\s*全绿|不对应/,
    bannerExempt: true,
    why: 'D269 验收覆盖口径修正：SKIP/BLOCKED 也算跑过 ⇒ 27 套件 ≠ 全绿；README:776「没有任何一次运行达到 27/27 全断言」；2026-11-12 结项报告 §9 已将 11-01《交付状态报告》的「27 PASS / 0 SKIP（27/27 全断言）」作废，现行口径 25/27 + 2 SKIP。将来若真出现 27/27 全断言的运行，须在本批同口径下更新本规则并留推翻链',
  },
  {
    id: 'delivery-gate-count-stale',
    // [D285] 收口清单条目自 D71 起随批次只增不减（37→49→51/52→55）；把旧条目数写成
    // 「现行全绿」即过期口径。同数分母才判（54/55 这类「部分红」叙述不命中）。
    scope: DELIVERY_REPORT_RE,
    re: /gate[-:\s]?close[^0-9\n]{0,12}\b(37|39|41|43|49|51|52)\s*\/\s*\1\b/,
    allow: /作废|推翻|历史|不再成立|时点快照|过期|取代|现行|D269|没有任何一次|没有一次|未达成/,
    bannerExempt: true,
    why: '收口清单条目只增不减：37（D145）→ 49（D251）→ 51/52（D252/D260）→ 55（D280 起，AGENTS.md 收口段落为现行真源）；把 37/39/41/43/49/51/52 写成现行全绿 = 过期口径（2026-11-12 结项报告 §9）',
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
  // [D285] 根目录交付/审计报告（`<主题>-YYYY-MM-DD.md` 命名惯例）也进扫描集合。
  let rootEntries;
  try { rootEntries = readdirSync(ROOT, { withFileTypes: true }); } catch { rootEntries = []; }
  for (const ent of rootEntries) {
    if (ent.isFile() && DELIVERY_REPORT_RE.test(ent.name)) out.push(join(ROOT, ent.name));
  }
  return [...new Set(out)].filter((p) => {
    try { return statSync(p).isFile(); } catch { return false; }
  });
}

/**
 * [D285] 文档头部是否带作废横幅（前 BANNER_SCAN_LINES 行内命中 BANNER_RE）。
 * 带横幅的时点文档整份按历史留痕处理：bannerExempt 规则全部豁免（与 §9「原文一字未删」一致）。
 * @param {string} text 文档正文
 * @returns {boolean}
 */
function hasInvalidationBanner(text) {
  return text.split(/\r?\n/).slice(0, BANNER_SCAN_LINES).some((l) => BANNER_RE.test(l));
}

/**
 * 扫一个文本，返回命中（行号 + 规则）。
 * @param {string} text 文档正文
 * @param {string} [filePath] 文档路径（用于 scope 判定；不传 = 全部规则生效）
 * @param {{docInvalidated?: boolean}} [opts] docInvalidated=true 时豁免 bannerExempt 规则
 * @returns {Array<{line:number, rule:string, text:string}>}
 */
function scanText(text, filePath = '', opts = {}) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  const active = RULES.filter(
    (r) => (!r.scope || r.scope.test(filePath)) && !(opts.docInvalidated && r.bannerExempt)
  );
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
  // ── [D285] 根目录交付/审计报告家族 ──────────────────────────────────────────
  const DELIVERY_OLD = '交付状态报告-2026-11-01.md';
  const DELIVERY_NEW = '交付结项报告-2026-11-12.md';
  const d285Bad = [
    // 11-01 报告正文的两条死口径（无横幅上下文时必须红）
    [DELIVERY_OLD, '| 判定 | **27 PASS / 0 BLOCKED / 0 FAIL / 0 SKIP**（27/27 跑出断言，EXIT=0） |'],
    [DELIVERY_OLD, '| 收口清单 | `gate:close` **37/37**（含 typecheck/lint/wiring 71 文件/facts/refs/readme 双向核对） |'],
    // 新报告同样在扫描集合内：把死口径当本轮结论复述（无 allow 词）必须红
    [DELIVERY_NEW, '本轮全量验收 27/27 全断言，交付判定达成'],
    [DELIVERY_NEW, '本轮收口 gate:close 39/39 全绿'],
  ];
  const d285Good = [
    // 横幅豁免：同一行死口径，文档头部带 ⛔ 口径作废横幅 ⇒ 整份按历史留痕放过
    [DELIVERY_OLD, '| 判定 | **27 PASS / 0 BLOCKED / 0 FAIL / 0 SKIP**（27/27 跑出断言，EXIT=0） |', { docInvalidated: true }],
    [DELIVERY_OLD, '| 收口清单 | `gate:close` **37/37**（含 typecheck/lint/wiring 71 文件） |', { docInvalidated: true }],
    // 行级 allow：引用旧口径的同时声明作废 / 现行口径
    [DELIVERY_NEW, '「交付判定 ✅ 达成」「27 PASS / 0 SKIP（27/27 全断言）」不再成立'],
    [DELIVERY_NEW, '✅ 已把「2026-11-01 全量验收 27/27 全 PASS」替换为现行 25/27 口径'],
    [DELIVERY_NEW, '当前收口门禁 55 项，最近验收 25/27（2 SKIP 如实披露）'],
    // scope 自证：同一死口径在非交付报告文档里不判（显式清单，宁可少抓）
    ['docs/质量台账.md', '历史台账：2026-11-01 曾记录 27/27 全断言'],
    ['TODO.md', 'D-old 批次曾用 27/27 全断言口径（后被 D269 推翻）'],
  ];
  for (const [f, s, o] of d285Bad) {
    if (!scanText(s, f, o).length) { console.log(`✖ 漏报 [${f}]：${s}`); fail++; }
  }
  for (const [f, s, o] of d285Good) {
    if (scanText(s, f, o).length) { console.log(`✖ 误报 [${f}]：${s}`); fail++; }
  }
  console.log(fail
    ? `✖ 自证失败 ${fail} 例`
    : `✔ 自证通过（漏报 ${bad.length + d285Bad.length} 例全抓、误报 ${good.length + dvgaLines.length + d285Good.length} 例全放过）`);
  process.exit(fail ? 1 : 0);
}

function main() {
  if (process.argv.includes('--selftest')) return selftest();
  const files = targetFiles();
  const all = [];
  let bannerDocs = 0;
  for (const f of files) {
    let text;
    try { text = readFileSync(f, 'utf-8'); } catch { continue; }
    // [D285] 头部作废横幅 ⇒ 整份按历史留痕豁免 bannerExempt 规则（11-01 报告口径）。
    // 计数只统计真正适用 bannerExempt 规则的文档（现行只有根目录交付报告家族），
    // README 家族的横幅不计数——否则日志会虚报豁免面。
    const docInvalidated = hasInvalidationBanner(text);
    // ⚠️ 必须把相对路径传进去：规则带 scope，缺路径会让 active 规则集为空 ⇒ 判据恒绿（本批自证抓过）
    const rel = relative(ROOT, f);
    if (docInvalidated && RULES.some((r) => r.bannerExempt && (!r.scope || r.scope.test(rel)))) bannerDocs++;
    for (const h of scanText(text, rel, { docInvalidated })) all.push({ file: rel, ...h });
  }
  if (all.length) {
    console.error(`✖ 检出 ${all.length} 处已作废口径的复述（当前文档不得引用被推翻的数字）：`);
    for (const h of all) {
      const rule = RULES.find((r) => r.id === h.rule);
      console.error(`  ${h.file}:${h.line}  [${h.rule}]  ${h.text}`);
      if (rule) console.error(`      为什么错：${rule.why}`);
    }
    console.error('\n修法：改成本轮口径；若确实是在记历史，同一行要写「作废/已被推翻/历史」，或给时点文档加 ⛔ 作废横幅。');
    return process.exit(1);
  }
  console.log(
    `✔ 未检出已作废口径的复述（扫描 ${files.length} 个 README 类文档 + 根目录交付报告，${RULES.length} 条规则` +
      (bannerDocs ? `；${bannerDocs} 份带作废横幅按历史留痕豁免` : '') +
      '）'
  );
}

main();
