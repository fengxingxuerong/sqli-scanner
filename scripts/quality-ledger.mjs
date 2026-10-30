#!/usr/bin/env node
// ============================================================================
// quality-ledger.mjs —— 对外质量台账（D178）
//
// 为什么要有它：本仓最厚的一层资产是「门禁 + 结论台账 + 验收套件」，但它们只存在于
// 脚本输出与内部文档里，外部完全看不见。竞品普遍在喊 high fidelity / evidence-bound，
// 却没有一家给出**可核查**的台账（见 docs/竞品对标-2026W44.md §二）。
//
// 三条纪律：
//   1. **只汇总既有判据的产出**，不新增任何能力声明（本页不做「检出率」这类断言）；
//   2. 数字全部从真源读：`docs/_facts.json`、`docs/_claims-ledger.json`、
//      `scripts/lib/gate-list.mjs`、`e2e/acceptance.mjs`、`e2e-wiring-check.mjs`；
//   3. 手改页面即红：`--check` 重算并与磁盘逐字比对（已进收口清单）。
//
// 用法：
//   node scripts/quality-ledger.mjs           # 重新生成 docs/质量台账.md
//   node scripts/quality-ledger.mjs --check   # 只校验（CI / 收口清单用）
//   node scripts/quality-ledger.mjs --selftest# 自证判据不空转
// ============================================================================
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { closeGateList, wiringTestFiles } from './lib/gate-list.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const OUT_REL = join('docs', '质量台账.md');

/**
 * @typedef {object} LedgerSources 台账数据源
 * @property {object} facts docs/_facts.json 内容
 * @property {Array<{id:string, claim:string, status:string}>} claims 结论台账条目
 * @property {number} gateCount 收口门禁项数
 * @property {number} wiringCount wiring 测试文件数
 * @property {{suites: number, labs: number, wired: number, reference: number}} suites 验收套件与靶场
 */

/** 从 e2e/acceptance.mjs 的 SUITES 数组里数套件（源码扫描；该文件有副作用，不能 import） */
function countAcceptanceSuites(root) {
  const src = readFileSync(join(root, 'e2e', 'acceptance.mjs'), 'utf8');
  const start = src.indexOf('const SUITES = [');
  if (start < 0) return 0;
  const end = src.indexOf('\n];', start);
  const block = end < 0 ? src.slice(start) : src.slice(start, end);
  // 套件条目形如 `<4 空格>id: 'xxx'`（首版正则要求 `{` 与 `id` 相邻，漏掉带注释的条目 ⇒ 少算一半）
  return (block.match(/\n {4}id: '[a-z0-9-]+'/g) || []).length;
}

/** 从 e2e-wiring-check.mjs 的汇总行里取靶场数（它没有 JSON 出口，读稳定文案） */
function readLabCounts(root) {
  try {
    const out = execFileSync(process.execPath, ['scripts/e2e-wiring-check.mjs'], { cwd: root, encoding: 'utf8' });
    const m = out.match(/靶场 (\d+) 个：已接线 (\d+) · 参考靶场（已登记）(\d+)/);
    if (!m) return { labs: 0, wired: 0, reference: 0 };
    return { labs: Number(m[1]), wired: Number(m[2]), reference: Number(m[3]) };
  } catch {
    // 读不到就如实报 0，让台账出现明显异常（而不是编一个数字）
    return { labs: 0, wired: 0, reference: 0 };
  }
}

/**
 * 采集台账数据源。
 * @param {string} [root] 仓库根（默认本仓；selftest 用夹具）
 * @returns {LedgerSources} 数据源
 */
function readSources(root = ROOT) {
  const facts = JSON.parse(readFileSync(join(root, 'docs', '_facts.json'), 'utf8'));
  const ledger = JSON.parse(readFileSync(join(root, 'docs', '_claims-ledger.json'), 'utf8'));
  const claims = Array.isArray(ledger?.claims) ? ledger.claims : [];
  const lc = readLabCounts(root);
  return {
    facts,
    claims,
    gateCount: closeGateList({ root }).length,
    wiringCount: wiringTestFiles(root).length,
    suites: { suites: countAcceptanceSuites(root), ...lc },
  };
}

/** 覆盖率与阈值比较（低于阈值一律标红字，不粉饰） */
function coverageRows(cov, thr) {
  const mark = (k) => (cov[k] >= thr[k] ? '✅' : '❌ 低于阈值');
  return `| lines | ${cov.lines}% | ${thr.lines}% | ${mark('lines')} |
| branches | ${cov.branches}% | ${thr.branches}% | ${mark('branches')} |
| functions | ${cov.functions}% | ${thr.functions}% | ${mark('functions')} |`;
}

/** 按 status 分组计数 */
function byStatus(claims) {
  /** @type {Record<string,number>} */
  const out = {};
  for (const c of claims) out[c.status] = (out[c.status] || 0) + 1;
  return out;
}

/**
 * 渲染台账 Markdown（纯函数：同一份数据必然渲染出同一份文本）。
 * @param {LedgerSources} src 数据源
 * @returns {string} Markdown 正文
 */
function buildLedger(src) {
  const { facts, claims, gateCount, wiringCount, suites } = src;
  const srv = facts.server || {};
  const fe = facts.frontend || {};
  const cov = srv.coverage || {};
  const thr = srv.thresholds || {};
  const counts = byStatus(claims);
  const statusKeys = ['verified', 'refuted', 'unverified'];
  const refuted = claims.filter((c) => c.status === 'refuted');
  const unverified = claims.filter((c) => c.status === 'unverified');
  return [
    '# 质量台账（自动生成）',
    '',
    `> 由 \`node scripts/quality-ledger.mjs\` 生成，手改会被 \`--check\` 判红（已进收口清单）。`,
    `> 数据快照：${facts.generatedAt || '未记录'}（\`docs/_facts.json\` 采集时间）。`,
    '> 本页**只汇总既有判据的产出**，不做任何能力声明——检出率/覆盖率口径请回到对应文档。',
    '',
    '## 一、门禁与测试',
    '',
    '| 项 | 值 |',
    '|---|---|',
    `| 收口门禁项数（\`npm run gate:close\`） | ${gateCount} |`,
    `| 其中 wiring/guard 测试文件 | ${wiringCount} |`,
    `| 前端用例（vitest） | ${fe.tests ?? '未采集'} |`,
    `| 服务端用例 | ${srv.tests ?? '未采集'}（pass ${srv.pass ?? '-'} / fail ${srv.fail ?? '-'} / skip ${srv.skip ?? '-'}） |`,
    `| 验收套件（\`npm run acceptance\`） | ${suites.suites} |`,
    `| e2e 靶场 | ${suites.labs}（已接线 ${suites.wired} · 参考靶场 ${suites.reference}） |`,
    '',
    '### 服务端覆盖率 vs 阈值',
    '',
    '| 指标 | 实测 | 阈值 | 判定 |',
    '|---|---|---|---|',
    coverageRows(cov, thr),
    '',
    '## 二、结论台账（`docs/_claims-ledger.json`）',
    '',
    '| 状态 | 条数 | 含义 |',
    '|---|---|---|',
    ...statusKeys.map((k) => `| ${k} | ${counts[k] || 0} | ${k === 'verified' ? '有可复现命令 + 落盘产物' : k === 'refuted' ? '已被实测推翻（保留旧数字）' : '尚无证据，禁止对外引用'} |`),
    `| **合计** | **${claims.length}** | — |`,
    '',
    ...(refuted.length
      ? ['### 已推翻（旧数字保留，不删历史）', '', ...refuted.map((c) => `- \`${c.id}\` — ${c.claim}`), '']
      : []),
    ...(unverified.length
      ? ['### 未验证（禁止当结论引用）', '', ...unverified.map((c) => `- \`${c.id}\` — ${c.claim}`), '']
      : []),
    '## 三、怎么复核这一页',
    '',
    '```bash',
    'node scripts/quality-ledger.mjs --check   # 页面与数据源逐字一致（手改即红）',
    'npm run gate:close                        # 门禁本身跑一遍',
    'npm run acceptance                        # 验收套件（缺环境会如实 BLOCKED/SKIP）',
    'node scripts/e2e-wiring-check.mjs         # 靶场接线状态',
    '```',
    '',
    '> 门禁绿 ≠ 判据对：这些数字只说明「此刻没有退化」，判据本身是否成立请看',
    '> `docs/_claims-ledger.json` 的 `refute_cmd` 与各批次 CHANGELOG。',
    '',
  ].join('\n');
}

function run(root, checkOnly) {
  const md = buildLedger(readSources(root));
  const abs = join(root, OUT_REL);
  if (checkOnly) {
    let current = '';
    try {
      current = readFileSync(abs, 'utf8');
    } catch {
      console.error(`[quality-ledger] ✗ 缺 ${OUT_REL}：请运行 node scripts/quality-ledger.mjs 生成`);
      process.exitCode = 1;
      return;
    }
    if (current.replace(/\r\n/g, '\n') !== md) {
      console.error(`[quality-ledger] ✗ ${OUT_REL} 与数据源不一致（手改或数据过期）：`);
      console.error('    修法：node scripts/quality-ledger.mjs（重新生成后再提交）');
      process.exitCode = 1;
      return;
    }
    console.log(`[quality-ledger] ✓ 台账与数据源一致（门禁 ${readSources(root).gateCount} 项、结论 ${md.length} 字符）`);
    process.exitCode = 0;
    return;
  }
  writeFileSync(abs, md, 'utf8');
  console.log(`[quality-ledger] 已生成 ${OUT_REL}（${md.length} 字符）`);
  process.exitCode = 0;
}

// ── 自证：判据必须能红 ────────────────────────────────────────────────────────
function selftest() {
  const fixture = {
    facts: {
      generatedAt: '2026-01-01T00:00:00+00:00',
      server: { tests: 10, pass: 9, fail: 0, skip: 1, coverage: { lines: 90, branches: 80, functions: 85 }, thresholds: { lines: 85, branches: 74, functions: 77 } },
      frontend: { tests: 5 },
    },
    claims: [
      { id: 'a', claim: 'claim A', status: 'verified' },
      { id: 'b', claim: 'claim B', status: 'refuted' },
      { id: 'c', claim: 'claim C', status: 'unverified' },
    ],
    gateCount: 31,
    wiringCount: 68,
    suites: { suites: 26, labs: 42, wired: 35, reference: 7 },
  };
  const md = buildLedger(fixture);
  const failures = [];
  const must = [
    ['门禁项数', md.includes('| 收口门禁项数（`npm run gate:close`） | 31 |')],
    ['服务端用例', md.includes('（pass 9 / fail 0 / skip 1）')],
    ['覆盖率判定为过', md.includes('| lines | 90% | 85% | ✅ |')],
    ['refuted 明细', md.includes('已推翻（旧数字保留，不删历史）') && md.includes('claim B')],
    ['unverified 明细', md.includes('未验证（禁止当结论引用）') && md.includes('claim C')],
    ['不做能力声明', md.includes('不做任何能力声明')],
  ];
  for (const [name, ok] of must) if (!ok) failures.push(`「${name}」未出现在台账里（判据空转）`);
  // 低于阈值必须标红（不能因为「看着差不多」而放过）
  const low = buildLedger({ ...fixture, facts: { ...fixture.facts, server: { ...fixture.facts.server, coverage: { lines: 80, branches: 80, functions: 85 } } } });
  if (!low.includes('| lines | 80% | 85% | ❌ 低于阈值 |')) failures.push('覆盖率低于阈值未被标红');
  // 同一数据必须渲染同一文本（否则 --check 会天天假红）
  if (buildLedger(fixture) !== md) failures.push('同一份数据两次渲染结果不同（非确定性）');
  if (failures.length) {
    console.error('[quality-ledger] ✗ selftest 失败：');
    for (const f of failures) console.error('  · ' + f);
    process.exitCode = 1;
    return;
  }
  console.log('[quality-ledger] ✓ selftest 通过（计数/明细/覆盖率标红/确定性 6 条判据均有效）');
  process.exitCode = 0;
}

const argv = process.argv.slice(2);
if (argv.includes('--selftest')) selftest();
else run(ROOT, argv.includes('--check'));
