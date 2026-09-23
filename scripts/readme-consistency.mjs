#!/usr/bin/env node
// ============================================================================
// readme-consistency.mjs —— README 声称的事实必须**可机械核对**
//
// 一个共同病根：**同一事实在手写文本里被说成了几个版本，而没有任何判据**。
//
// 【A 类：README 内部自洽】方言分层在 README 里被写了三处 —— 功能表概览行（三数 + 方言清单）、
//   分层详表（三行，各自方言名）、给客户的话（「共 N 种」）。Oracle / SQL Server 在
//   2026-09-14/15 从「模板适配」升级为「真实引擎验证」时，详表与客户段改了，
//   **概览行的「4 种真实 + 3 部分 + 11 模板」没改**。危害不是"数字错"这么轻：
//   4+3+11=18 与 6+3+9=18 都自洽，读者看不出破绽 → 对外**低估自己**，且随每次升级继续累积。
//
// 【B 类：README 声称 ↔ 代码单一取数源】README 的规模数字（检测通道清单、tamper 数、
//   payload 分项）此前**全部无判据**。真危害是"加了能力忘改 README，或反之"——
//   现有门禁都看不见：`tamper:parity` 管的是"对齐 sqlmap 官方清单 84/84"（不是总数）、
//   `facts:check` 管的是测试数与覆盖率。故此处直接对**运行期取数源**核对（不数文件、不抄注释）：
//     · 检测通道 → `VULN_TAXONOMY` 的键（该文件自称"漏洞类型单一取数源"，报告/SARIF 都走它）
//     · tamper   → `tamperRegistry.list().length`（运行期真实注册数）
//     · payload  → `PAYLOADS` / `CLAUSE_PAYLOADS` / `OOB_PAYLOADS` 的**递归条目数（含重复）**
//                  + `PAYLOAD_REGISTRY.length`（声明式注册表）
//
//   2026-09-23 实测到的漂移：`672 → 681`、`1779 → 1769`、`82 → 137`（OOB 14 未变）。
//   该行自 2026-08-23 快照后没再更新过 —— 典型「对外门面随代码演进静默过期」。
//   ⚠️ 口径说明（改动这些数字前必须读）：payload 计数有**两种口径**，差异极大 ——
//   同一模板在不同库/技术下会重复出现，「含重复递归计数」主库 1769 条，**去重后仅 959 条**。
//   README 用的是前者（与历史表述同口径）。本守卫钉住的是**含重复口径**；换口径等于改语义，
//   必须先改 README 的措辞再加判据。
//
// **刻意不纳入的两项**（写在这里，免得后来者以为是漏了）：
//   · 「62 WAF 指纹」：`WAF_RECOMMEND_MAP` 有 64 个键，其中 `generic_block` / `_default` 不是
//     厂商指纹。取数口径有两解 → 加守卫会造出脆弱判据（假红风险大于收益）。
//   · 「6 种真实引擎 / 3 部分 / 9 模板」以外的证据等级描述：属自然语言，不可机械核对。
//
// 判据设计原则（本项目纪律）：**判据要与危害同源**，且**不依赖行号**（README 结构会变）。
// 工具：`--selftest` 用构造样本自证每条判据都不空转、且对正确样本不误报。
//
// 用法：
//   node scripts/readme-consistency.mjs            # 校验
//   node scripts/readme-consistency.mjs --selftest # 自证判据
// ============================================================================

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { VULN_TAXONOMY } from '../server/src/services/vulnTaxonomy.js';
import { tamperRegistry } from '../server/src/core/tamper/index.js';
import { PAYLOADS, CLAUSE_PAYLOADS, OOB_PAYLOADS } from '../server/src/engine/payloads.js';
import { PAYLOAD_REGISTRY } from '../server/src/engine/payloadRegistry.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const README_PATH = resolve(ROOT, 'README.md');

const TIER_KEYS = [
  { id: 'verified', label: '真实引擎验证', desc: '真实引擎验证' },
  { id: 'partial', label: '部分通道验证', desc: '部分通道验证' },
  { id: 'template', label: '模板适配', desc: '模板适配' },
];

/** 递归数出「字符串数组」的条目总数（含跨库/技术重复）—— payload 计数口径见文件头 */
export function countTemplates(v) {
  let n = 0;
  const walk = (x) => {
    if (Array.isArray(x)) {
      if (x.every((e) => typeof e === 'string')) n += x.length;
      else x.forEach(walk);
    } else if (x && typeof x === 'object') Object.values(x).forEach(walk);
  };
  walk(v);
  return n;
}

// ── 解析 ─────────────────────────────────────────────────────────────────────
const cellsOf = (line) => line.split('|').slice(1, -1).map((c) => c.trim());

/** 剥离「名字（备注）」里的备注，并拆出名字清单。分隔符：概览行用 `/`，详表用 `、` */
const namesOf = (text, sep) =>
  text
    .split(sep)
    .map((s) => s.replace(/（[^）]*）/g, '').replace(/\*\*/g, '').replace(/`/g, '').trim())
    .filter(Boolean);

/** 概览行：`| **18 种数据库** | MySQL / … | **4 种真实引擎全链路验证 + 3 种部分通道验证 + 11 种模板适配**（分层见下） |` */
function parseOverview(lines) {
  const idx = lines.findIndex((l) => /^\|\s*\*\*\d+\s*种数据库\*\*\s*\|/.test(l));
  if (idx < 0) return { error: '未找到「N 种数据库」概览行（README 结构可能已改）' };
  const cells = cellsOf(lines[idx]);
  if (cells.length < 3) return { error: '概览行列数不足 3（方言清单 / 分层说明缺失）' };
  const declared = Number(lines[idx].match(/\*\*(\d+)\s*种数据库\*\*/)[1]);
  const names = namesOf(cells[1], '/');
  const triple = cells[2].match(
    /(\d+)\s*种真实引擎全链路验证\s*\+\s*(\d+)\s*种部分通道验证\s*\+\s*(\d+)\s*种模板适配/,
  );
  if (!triple) return { error: '概览行未找到「a 种真实引擎全链路验证 + b 种部分通道验证 + c 种模板适配」三数表述' };
  return { line: idx + 1, declared, names, triple: triple.slice(1, 4).map(Number) };
}

/** 分层详表：三行，第 2 单元格为方言名清单 */
function parseTiers(lines) {
  const out = {};
  for (const key of TIER_KEYS) {
    const idx = lines.findIndex((l) => l.includes(`**${key.label}`) && l.startsWith('|'));
    if (idx < 0) return { error: `未找到分层详表行「${key.label}」（README 结构可能已改）` };
    const cells = cellsOf(lines[idx]);
    if (cells.length < 2) return { error: `分层行「${key.label}」列数不足` };
    out[key.id] = { line: idx + 1, names: namesOf(cells[1], '、') };
  }
  return out;
}

/** 客户段：`…上表 ⛔ 等级（TiDB / … 共 9 种）仅有模板适配…` */
function parseCustomerCount(lines) {
  const idx = lines.findIndex((l) => /上表\s*⛔\s*等级（/.test(l) && /共\s*\d+\s*种/.test(l));
  if (idx < 0) return { error: '未找到客户段「上表 ⛔ 等级（… 共 N 种）」表述' };
  return { line: idx + 1, count: Number(lines[idx].match(/共\s*(\d+)\s*种/)[1]) };
}

/** 检测技术行：`| **9 种检测技术** | union / error / … |` */
function parseTechLine(lines) {
  const idx = lines.findIndex((l) => /^\|\s*\*\*\d+\s*种检测技术\*\*\s*\|/.test(l));
  if (idx < 0) return { error: '未找到「N 种检测技术」行' };
  const cells = cellsOf(lines[idx]);
  if (cells.length < 2) return { error: '检测技术行列数不足 2' };
  return {
    line: idx + 1,
    declared: Number(lines[idx].match(/\*\*(\d+)\s*种检测技术\*\*/)[1]),
    names: namesOf(cells[1], '/'),
  };
}

/** tamper 数量的**所有**表述处（功能表 + 项目状态），必须全部与运行期注册数一致 */
function parseTamperCounts(lines) {
  const out = [];
  lines.forEach((l, i) => {
    const m = l.match(/\*\*(\d+)\s*个 tamper 插件\*\*/) || l.match(/^- Tamper 插件: (\d+) 个/);
    if (m) out.push({ line: i + 1, count: Number(m[1]) });
  });
  if (out.length < 2) return { error: `tamper 数量表述只找到 ${out.length} 处（预期 ≥2：功能表 + 项目状态）` };
  return out;
}

/** payload 行：`| **1920 条 payload 模板** | …：主库 1769 + 子句 137 + OOB 14（口径：…）+ 681 条声明式注册表（…） |` */
function parsePayloadLine(lines) {
  const idx = lines.findIndex((l) => /^\|\s*\*\*\d+\s*条 payload 模板\*\*\s*\|/.test(l));
  if (idx < 0) return { error: '未找到「N 条 payload 模板」行' };
  const l = lines[idx];
  const total = l.match(/\*\*(\d+)\s*条 payload 模板\*\*/);
  const parts = l.match(/主库\s*(\d+)\s*\+\s*子句\s*(\d+)\s*\+\s*OOB\s*(\d+)/);
  const registry = l.match(/(\d+)\s*条声明式注册表/);
  if (!parts) return { error: 'payload 行未找到「主库 N + 子句 N + OOB N」分项表述' };
  if (!registry) return { error: 'payload 行未找到「N 条声明式注册表」表述' };
  return {
    line: idx + 1,
    total: Number(total[1]),
    main: Number(parts[1]),
    clause: Number(parts[2]),
    oob: Number(parts[3]),
    registry: Number(registry[1]),
  };
}

// ── 判据（纯函数，便于自证） ──────────────────────────────────────────────────
/** @param code 代码侧取数源 */
export function checkConsistency(input) {
  const { overview, tiers, customer, tech, tamperCounts, payload, code } = input;
  const fails = [];
  const tierCounts = TIER_KEYS.map((k) => tiers[k.id].names.length);
  const [a, b, c] = overview.triple;
  const tierSet = new Set();
  const dupAcross = [];

  for (const k of TIER_KEYS) {
    for (const n of tiers[k.id].names) {
      if (tierSet.has(n)) dupAcross.push(n);
      tierSet.add(n);
    }
  }

  // ── A 类：README 内部自洽 ──
  if (overview.declared !== overview.names.length) {
    fails.push(
      `① 概览行声明「${overview.declared} 种数据库」，但它自己列出 ${overview.names.length} 个方言名` +
      `（README.md:${overview.line}）`,
    );
  }

  const sum = a + b + c;
  const tierTotal = tierCounts.reduce((x, y) => x + y, 0);
  if (sum !== tierTotal) {
    fails.push(
      `② 概览行三数之和 ${a}+${b}+${c}=${sum}，与分层详表名称总数 ${tierTotal} 不一致` +
      `（README.md:${overview.line} vs :${tiers.verified.line}/${tiers.partial.line}/${tiers.template.line}）`,
    );
  }
  if (sum !== overview.names.length) {
    fails.push(`② 概览行三数之和 ${sum} ≠ 概览行方言名数 ${overview.names.length}（README.md:${overview.line}）`);
  }

  TIER_KEYS.forEach((k, i) => {
    if (overview.triple[i] !== tierCounts[i]) {
      fails.push(
        `③ 概览行称「${overview.triple[i]} 种${k.desc}」，分层详表里「${k.label}」实有 ${tierCounts[i]} 个` +
        `（README.md:${overview.line} vs :${tiers[k.id].line}）— 升级/降级某方言后，两处必须同步`,
      );
    }
  });

  if (dupAcross.length) {
    fails.push(`④ 方言跨层重复登记：${[...new Set(dupAcross)].join('、')} — 升级后未从旧层删除`);
  }

  const missing = [...tierSet].filter((n) => !overview.names.includes(n));
  const extra = overview.names.filter((n) => !tierSet.has(n));
  if (missing.length) fails.push(`⑤ 分层详表里有、概览行漏写的方言：${missing.join('、')}`);
  if (extra.length) fails.push(`⑤ 概览行有、分层详表未归类的方言：${extra.join('、')}`);

  if (customer.count !== tierCounts[2]) {
    fails.push(
      `⑥ 客户段称⛔模板适配「共 ${customer.count} 种」，详表实有 ${tierCounts[2]} 个（README.md:${customer.line}）`,
    );
  }

  // ── B 类：README 声称 ↔ 代码取数源 ──
  if (tech.declared !== tech.names.length) {
    fails.push(
      `⑦ 功能表称「${tech.declared} 种检测技术」，但自己列出 ${tech.names.length} 个（README.md:${tech.line}）`,
    );
  }
  if (tech.names.length !== code.techniques.length) {
    fails.push(
      `⑧ README 列出 ${tech.names.length} 个检测通道，代码取数源 VULN_TAXONOMY 有 ${code.techniques.length} 个` +
      `（README.md:${tech.line}）— 加了通道忘改 README，或反之`,
    );
  } else {
    const missTech = code.techniques.filter((n) => !tech.names.includes(n));
    const extraTech = tech.names.filter((n) => !code.techniques.includes(n));
    if (missTech.length) fails.push(`⑧ README 漏写的检测通道：${missTech.join('、')}（代码里有）`);
    if (extraTech.length) fails.push(`⑧ README 多写的检测通道：${extraTech.join('、')}（代码里没有）`);
  }

  for (const t of tamperCounts) {
    if (t.count !== code.tamperCount) {
      fails.push(
        `⑨ README.md:${t.line} 称「${t.count} 个 tamper 插件」，运行期 tamperRegistry 实注册 ${code.tamperCount} 个` +
        ` — 增删插件后必须同步 README（含项目状态那处）`,
      );
    }
  }

  if (payload.total !== payload.main + payload.clause + payload.oob) {
    fails.push(
      `⑩ payload 合计 ${payload.total} ≠ 分项之和 ${payload.main}+${payload.clause}+${payload.oob}=` +
      `${payload.main + payload.clause + payload.oob}（README.md:${payload.line}）`,
    );
  }
  const payloadPairs = [
    ['主库', payload.main, code.payloadMain],
    ['子句', payload.clause, code.payloadClause],
    ['OOB', payload.oob, code.payloadOob],
    ['声明式注册表', payload.registry, code.payloadRegistry],
  ];
  for (const [label, claimed, actual] of payloadPairs) {
    if (claimed !== actual) {
      fails.push(
        `⑩ README.md:${payload.line} 称${label} ${claimed} 条，代码实测 ${actual} 条` +
        ` — 模板增删后必须同步（口径：含跨库/技术重复的递归条目数）`,
      );
    }
  }

  return fails;
}

// ── 自证：判据必须能抓住每一类漂移，且对正确样本不误报 ──────────────────────────
const SAMPLE = () => ({
  overview: { line: 1, declared: 3, names: ['A', 'B', 'C'], triple: [1, 1, 1] },
  tiers: {
    verified: { line: 2, names: ['A'] },
    partial: { line: 3, names: ['B'] },
    template: { line: 4, names: ['C'] },
  },
  customer: { line: 5, count: 1 },
  tech: { line: 6, declared: 2, names: ['union', 'error'] },
  tamperCounts: [{ line: 7, count: 228 }, { line: 8, count: 228 }],
  payload: { line: 9, total: 3, main: 2, clause: 1, oob: 0, registry: 681 },
  code: {
    techniques: ['union', 'error'], tamperCount: 228,
    payloadMain: 2, payloadClause: 1, payloadOob: 0, payloadRegistry: 681,
  },
});

function selftest() {
  const bad = [];
  const expectOk = (name, mut) => {
    const s = SAMPLE();
    mut(s);
    const f = checkConsistency(s);
    if (f.length) bad.push(`样本「${name}」本应全绿，却报：${f[0]}`);
  };
  const expectFail = (name, mut, mustMatch) => {
    const s = SAMPLE();
    mut(s);
    const f = checkConsistency(s);
    if (!f.length) bad.push(`样本「${name}」本应报错，却全绿 —— 该判据在空转`);
    else if (mustMatch && !f.some((x) => mustMatch.test(x))) {
      bad.push(`样本「${name}」报错了但不是预期判据：${f.join(' | ')}`);
    }
  };

  expectOk('原样正确样本', () => {});
  expectOk('三数全为 0 的空分层（合法边界）', (s) => {
    s.overview = { line: 1, declared: 0, names: [], triple: [0, 0, 0] };
    s.tiers = {
      verified: { line: 2, names: [] }, partial: { line: 3, names: [] }, template: { line: 4, names: [] },
    };
    s.customer = { line: 5, count: 0 };
  });
  expectOk('payload 三项全 0（合法边界）', (s) => {
    s.payload = { line: 9, total: 0, main: 0, clause: 0, oob: 0, registry: 0 };
    s.code.payloadMain = 0; s.code.payloadClause = 0; s.code.payloadOob = 0; s.code.payloadRegistry = 0;
  });

  expectFail('概览声明总数与清单不符', (s) => { s.overview.declared = 4; }, /①/);
  expectFail('三数之和与详表总数不符', (s) => { s.overview.triple = [1, 1, 2]; }, /②/);
  expectFail('三数之和与概览清单不符', (s) => {
    s.overview.names.push('D'); s.tiers.template.names.push('D'); s.overview.declared = 4;
  }, /②/);
  expectFail('单项数与所属层不符（本次真缺陷的形态）', (s) => { s.overview.triple = [2, 1, 1]; }, /③/);
  expectFail('同方言跨层重复', (s) => { s.tiers.partial.names = ['B', 'A']; s.overview.triple = [1, 2, 1]; }, /④/);
  expectFail('详表有而概览漏写', (s) => { s.overview.names = ['A', 'B']; s.overview.declared = 3; }, /⑤/);
  expectFail('概览有而详表漏归类', (s) => {
    s.overview.names = ['A', 'B', 'C', 'D']; s.overview.declared = 4;
  }, /⑤/);
  expectFail('客户段共 N 种与模板层不符', (s) => { s.customer.count = 5; }, /⑥/);

  expectFail('检测技术声明数与清单不符', (s) => { s.tech.declared = 3; }, /⑦/);
  expectFail('README 通道数 ≠ 代码 taxonomy（加了通道忘改 README）', (s) => {
    s.code.techniques = ['union', 'error', 'time'];
  }, /⑧/);
  expectFail('README 有代码没有的通道（写了个不存在的通道）', (s) => {
    s.tech.names = ['union', 'nosql2']; s.tech.declared = 2;
  }, /⑧/);
  expectFail('tamper 数 ≠ 运行期注册数（含只改一处的情况）', (s) => {
    s.tamperCounts = [{ line: 7, count: 233 }, { line: 8, count: 228 }];
  }, /⑨/);
  expectFail('payload 合计 ≠ 分项之和', (s) => { s.payload.total = 9; }, /⑩/);
  expectFail('payload 主库数与代码不符', (s) => { s.payload.main = 5; s.payload.total = 6; }, /⑩/);
  expectFail('payload 注册表条数与代码不符（本次真缺陷 672→681 的形态）', (s) => {
    s.payload.registry = 672;
  }, /⑩/);

  if (bad.length) {
    console.error('[readme] ✗ 自证失败 —— 判据存在空转或误报：');
    for (const b of bad) console.error('    · ' + b);
    return 1;
  }
  console.log('[readme] ✓ 自证通过：16 类漂移样本全部被点名，3 类正确样本无误报（判据不空转）');
  return 0;
}

// ── 主流程 ───────────────────────────────────────────────────────────────────
function main() {
  if (process.argv.includes('--selftest')) return selftest();

  const lines = readFileSync(README_PATH, 'utf8').split(/\r?\n/);
  const overview = parseOverview(lines);
  const tiers = parseTiers(lines);
  const customer = parseCustomerCount(lines);
  const tech = parseTechLine(lines);
  const tamperCounts = parseTamperCounts(lines);
  const payload = parsePayloadLine(lines);

  const parseErrors = [overview, tiers, customer, tech, tamperCounts, payload]
    .map((r) => r && r.error)
    .filter(Boolean);
  if (parseErrors.length) {
    console.error('[readme] ✗ 解析失败（README 结构可能已改，判据已失效 —— 必须修判据，不能静默跳过）：');
    for (const e of parseErrors) console.error('    · ' + e);
    return 1;
  }

  const code = {
    techniques: Object.keys(VULN_TAXONOMY),
    tamperCount: tamperRegistry.list().length,
    payloadMain: countTemplates(PAYLOADS),
    payloadClause: countTemplates(CLAUSE_PAYLOADS),
    payloadOob: countTemplates(OOB_PAYLOADS),
    payloadRegistry: PAYLOAD_REGISTRY.length,
  };

  const fails = checkConsistency({ overview, tiers, customer, tech, tamperCounts, payload, code });
  if (fails.length) {
    console.error(`[readme] ✗ README 声称与事实不符（${fails.length} 处）：`);
    for (const f of fails) console.error('    · ' + f);
    console.error('[readme] 修法：方言分层以「分层详表」为唯一事实源；检测通道 / tamper / payload 以代码取数源为准。');
    return 1;
  }

  const [a, b, c] = overview.triple;
  console.log(
    `[readme] ✓ 口径自洽：方言分层 ${a}+${b}+${c}=${overview.declared} 种（三处一致）· ` +
    `检测通道 ${tech.names.length} 条（= VULN_TAXONOMY）· tamper ${code.tamperCount} 个（= 运行期注册数，${tamperCounts.length} 处一致）· ` +
    `payload 主库 ${code.payloadMain} + 子句 ${code.payloadClause} + OOB ${code.payloadOob} + 注册表 ${code.payloadRegistry}（= 代码实测）`,
  );
  return 0;
}

process.exit(main());
