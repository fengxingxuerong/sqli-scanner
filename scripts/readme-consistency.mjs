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

import { readFileSync, existsSync } from 'node:fs';
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

// ── 外部真值取数：验收套件数 / sqlmap 官方 tamper 分母 ──────────────────────────
/**
 * 验收门禁的套件数：数 e2e/acceptance.mjs 里 SUITES 数组的 `title:`。
 * 口径注意：**必须同时接受单引号与反引号** —— 数组里有 2 条 title 是模板字面量
 * （如 \`CRS 人工挂链 A/B（PL${WAF_GATE_PL} 档基线）\`），只匹配 ' 会把 15 数成 13。
 * 数组边界取首个顶层 `\n];`，避免把文件其它位置的 title: 混进来。
 */
function countAcceptanceSuites() {
  const src = readFileSync(resolve(ROOT, 'e2e/acceptance.mjs'), 'utf8');
  const start = src.indexOf('const SUITES');
  const end = src.indexOf('\n];', start);
  if (start < 0 || end < 0) {
    throw new Error('e2e/acceptance.mjs 里找不到 const SUITES 数组 —— 判据取数源已失效，必须修判据');
  }
  return (src.slice(start, end).match(/title:\s*['"`]/g) || []).length;
}

/** 上游 tamper 官方清单：分母与「本仓缺几条」都从这里算，README 不许手写。 */
function readUpstreamTamper(registeredNames) {
  const j = JSON.parse(
    readFileSync(resolve(ROOT, 'server/src/core/tamper/upstream-sqlmap-tamper.json'), 'utf8')
  );
  // 数据源自洽：count 字段必须与 names 长度一致，否则 README 的分母会跟着生成器一起错。
  if (j.count !== j.names.length) {
    throw new Error(`upstream-sqlmap-tamper.json 自相矛盾：count=${j.count} names=${j.names.length}`);
  }
  const missing = j.names.filter((n) => !registeredNames.has(n));
  return { total: j.names.length, missing, tag: j.tag };
}

/**
 * README 里「能力口径」的套件数声称。
 * 刻意只认两种固定措辞：`（N 套件，…）`（命令表）与 `N 套件一次跑完`（门禁小节）。
 * 带日期标题的「N 套件全绿」是**某一轮的运行记录**（历史事实），不是当前口径 ——
 * 把这类也纳入就等于要求"每次改文档都重跑 20 分钟门禁"，那是假红来源。
 */
function parseSuiteClaims(lines) {
  const out = [];
  lines.forEach((l, i) => {
    for (const m of l.matchAll(/（(\d+) 套件，|(?<![\d.])(\d+) 套件一次跑完/g)) {
      out.push({ line: i + 1, count: Number(m[1] ?? m[2]) });
    }
  });
  return out;
}

/** README 的 tamper 覆盖声称「覆盖 sqlmap 官方 tamper 全集（N/M）」。 */
function parseTamperUniverse(lines) {
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/官方 tamper 全集（(\d+)\/(\d+)[^）]*）/);
    if (m) return { line: i + 1, covered: Number(m[1]), declared: Number(m[2]) };
  }
  return {
    error:
      'README 里找不到「官方 tamper 全集（N/M）」这一行 —— 措辞改了要同步改判据，不能静默跳过这条对外数字',
  };
}

/**
 * 二级文档里不许再抄一份"会随代码变的计数"（SECURITY.md / CONTRIBUTING.md）。
 * 危害实测：README 的数字有 facts-sync 与本脚本守，而这两份各抄了一份 ⇒ 每加一批测试要改 4 个文件，
 * 漏改就长期说假数（本轮实测最狠的一处：SECURITY.md 写 1249，真值 2483，差了近一倍）。
 * 判据形态刻意做成**"禁止出现这种写法"**而不是"数值相等"：
 * 前者不随事实漂移，不会造成"改代码必须同时改文档"的假红；后者会把二级文档拖进同一套同步机器里。
 */
function parseDocNumberTaboos(docs) {
  const hits = [];
  const RE = /(\d{3,})\s*(?:个\s*)?(?:测试|用例)|tamper\s*(\d{3,})\s*个/;
  for (const d of docs) {
    d.lines.forEach((l, i) => {
      const m = l.match(RE);
      if (m) hits.push({ file: d.name, line: i + 1, text: l.trim().slice(0, 80) });
    });
  }
  return hits;
}

/**
 * 实注册的 REST 端点集合：server/index.js 的挂载点 + 各 router 的注册行。
 * 只取 /api 前缀那一份（同一 router 会双挂载到 / 供 Tauri 用，数两遍会虚增）。
 * 返回 `METHOD /api/path` 字符串集合，与 README 表格的写法同形。
 */
function collectRegisteredEndpoints() {
  const idx = readFileSync(resolve(ROOT, 'server/index.js'), 'utf8');
  const mounts = [...idx.matchAll(/app\.use\('([^']+)',\s*(\w+Routes)\)/g)]
    .map(([, prefix, name]) => [prefix, name])
    .filter(([prefix]) => prefix.startsWith('/api'));
  if (!mounts.length) throw new Error('server/index.js 里找不到 app.use("/api", xxxRoutes) —— 判据取数源失效');
  const out = new Set();
  for (const [prefix, name] of mounts) {
    const file = resolve(ROOT, 'server/src/api', `${name}.js`);
    const src = readFileSync(file, 'utf8');
    for (const m of src.matchAll(/(?:router|\w+Routes)\.(get|post|put|delete|patch)\(\s*'([^']*)'/g)) {
      const p = m[2] === '/' ? '' : m[2];
      out.add(`${m[1].toUpperCase()} ${prefix}${p}`);
    }
  }
  if (!out.size) throw new Error('挂载点找到了但一个端点都没解析出来 —— 判据取数源失效');
  return out;
}

/** README「## 后端 API」小节里的表格行：`| \`/api/xxx\` | METHOD | 说明 |` */
function parseApiTable(lines) {
  const start = lines.findIndex((l) => /^##\s+后端 API/.test(l));
  if (start < 0) return { error: 'README 里找不到「## 后端 API」小节 —— 措辞改了要同步改判据，不能静默跳过' };
  const rows = [];
  for (let i = start + 1; i < lines.length && !/^##\s/.test(lines[i]); i++) {
    const m = lines[i].match(/^\|\s*`(\/[^`]*)`\s*\|\s*(GET|POST|PUT|DELETE|PATCH)\s*\|/i);
    if (m) rows.push({ line: i + 1, key: `${m[2].toUpperCase()} ${m[1]}` });
  }
  return { rows };
}

/**
 * README 里教人执行的 `node <仓库内路径>.js|mjs|cjs` —— 路径必须真的存在。
 * 实测触发过一次：README 两处教 `node bin/cli.js --help`，而 CLI 真身在 `server/bin/cli.js`，
 * 从仓库根照抄就是 MODULE_NOT_FOUND。
 * 判据形态是"文件在不在"，不随口径漂移；目前 12 处引用全部命中真实文件（零假阳）。
 * 若将来要写构建产物路径（如 server/dist-engine/*），把它加进 ALLOW_MISSING 并注明理由，
 * 别把整条判据放宽成不检查。
 */
function parseNodePathClaims(lines) {
  const out = [];
  lines.forEach((l, i) => {
    for (const m of l.matchAll(/node\s+((?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.(?:js|mjs|cjs))/g)) {
      out.push({ line: i + 1, path: m[1] });
    }
  });
  return out;
}

// ── 判据（纯函数，便于自证） ──────────────────────────────────────────────────
/** @param code 代码侧取数源 */
export function checkConsistency(input) {
  const { overview, tiers, customer, tech, tamperCounts, payload, suiteClaims, tamperUniverse, code } = input;
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

  // ── C 类：对外能力口径与外部真值分母（此前完全无判据的两处数字） ──
  if (!suiteClaims.length) {
    fails.push('⑪ README 里没找到任何「（N 套件，」/「N 套件一次跑完」措辞 —— 判据取数点漂移，必须同步改判据');
  }
  for (const s of suiteClaims) {
    if (s.count !== code.acceptanceSuites) {
      fails.push(
        `⑪ README.md:${s.line} 称「${s.count} 套件」，e2e/acceptance.mjs 的 SUITES 实为 ${code.acceptanceSuites} 个` +
        ` — 增删套件后必须同步（README 里那条流水线列举的套件名也要一起补）`,
      );
    }
  }

  if (tamperUniverse.declared !== code.upstreamTotal) {
    fails.push(
      `⑫ README.md:${tamperUniverse.line} 的分母写「${tamperUniverse.declared}」，` +
      `上游清单 upstream-sqlmap-tamper.json（tag ${code.upstreamTag}）实为 ${code.upstreamTotal} 条` +
      ` — 分母是外部真值，不能手写；刷新用 npm run tamper:parity:refresh`,
    );
  }
  const expectedCovered = code.upstreamTotal - code.upstreamMissing.length;
  if (tamperUniverse.covered !== expectedCovered) {
    fails.push(
      `⑫ README.md:${tamperUniverse.line} 的分子写「${tamperUniverse.covered}」，实际覆盖 ` +
      `${expectedCovered}/${code.upstreamTotal}` +
      (code.upstreamMissing.length ? `（缺：${code.upstreamMissing.join('、')}）` : '（官方条目全覆盖）'),
    );
  }

  const docTaboos = parseDocNumberTaboos(input.docs || []);
  for (const t of docTaboos) {
    fails.push(
      `⑬ ${t.file}:${t.line} 抄了一份会随代码变的计数（用例数 / tamper 插件数）：「${t.text}」` +
      ` — 请改成指向 docs/_facts.json 或 README 的说法，别在二级文档里留副本`,
    );
  }

  // ⑭ 后端 API 表双向核对：表里写的必须真存在，真存在的必须写进表
  const apiRows = input.apiTable?.rows || [];
  const registered = new Set(code.endpoints);
  if (!apiRows.length) {
    fails.push('⑭ README 的「后端 API」表一行都没解析出来 —— 表格格式或小节标题改了，判据已失效');
  }
  const ghost = apiRows.filter((r) => !registered.has(r.key));
  if (ghost.length) {
    fails.push(
      `⑭ README 的 API 表写了 ${ghost.length} 个**不存在**的端点：${ghost.map((r) => `${r.key}（:${r.line}）`).join('、')}` +
      ` — 路径或方法名与代码注册不符，照文档调用必然 404`,
    );
  }
  const listed = new Set(apiRows.map((r) => r.key));
  const undocumented = [...registered].filter((k) => !listed.has(k)).sort();
  if (undocumented.length) {
    fails.push(
      `⑭ 代码注册了 ${registered.size} 个端点，README 表漏写 ${undocumented.length} 个：${undocumented.join('、')}`,
    );
  }

  const missingPaths = (input.nodePaths || []).filter((p) => !code.existingPaths.has(p.path));
  if (missingPaths.length) {
    fails.push(
      `⑮ README 教了 ${missingPaths.length} 个跑不通的命令行路径：` +
      missingPaths.map((p) => `${p.path}（:${p.line}）`).join('、') +
      ` — 照抄的人只会拿到 MODULE_NOT_FOUND`,
    );
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
  suiteClaims: [{ line: 10, count: 15 }],
  tamperUniverse: { line: 11, covered: 70, declared: 70 },
  docs: [
    { name: 'SECURITY.md', lines: ['- CI 强制：TypeScript、ESLint、前端覆盖率阈值、服务端测试（用例数见 docs/_facts.json）'] },
    { name: 'CONTRIBUTING.md', lines: ['   - 前端：`npm test`（vitest，用例数见 _facts.json）'] },
  ],
  apiTable: {
    rows: [{ line: 12, key: 'GET /api/health' }, { line: 13, key: 'POST /api/scan/start' }],
  },
  nodePaths: [{ line: 14, path: 'server/bin/cli.js' }],
  code: {
    techniques: ['union', 'error'], tamperCount: 228,
    payloadMain: 2, payloadClause: 1, payloadOob: 0, payloadRegistry: 681,
    acceptanceSuites: 15, upstreamTotal: 70, upstreamMissing: [], upstreamTag: '1.9.11',
    endpoints: ['GET /api/health', 'POST /api/scan/start'],
    existingPaths: new Set(['server/bin/cli.js']),
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
  // C 类：本轮实测到的两处裸奔数字（README 写 12 套件 / 84 分母，真值 15 / 70）
  expectFail('验收套件数与 SUITES 不符', (s) => {
    s.suiteClaims = [{ line: 10, count: 12 }];
  }, /⑪/);
  expectFail('套件声称整段消失（措辞漂移＝判据会静默空转）', (s) => {
    s.suiteClaims = [];
  }, /⑪/);
  expectFail('tamper 官方分母与上游清单不符', (s) => {
    s.tamperUniverse = { line: 11, covered: 84, declared: 84 };
  }, /⑫.*分母/);
  expectFail('分母对了但分子虚高（缺条目未点名）', (s) => {
    s.tamperUniverse = { line: 11, covered: 70, declared: 70 };
    s.code.upstreamMissing = ['between'];
  }, /⑫.*分子/);
  expectOk('有缺失时分子如实写差值（合法形态）', (s) => {
    s.code.upstreamMissing = ['between'];
    s.tamperUniverse = { line: 11, covered: 69, declared: 70 };
  });
  // ⑬ 二级文档抄数字（本轮实测：SECURITY.md 的 1249 与真值差近一倍，且无人守）
  expectFail('二级文档抄了用例数', (s) => {
    s.docs[0].lines = ['- CI 强制：服务端 1249 测试'];
  }, /⑬/);
  expectFail('二级文档抄了 tamper 数', (s) => {
    s.docs[1].lines = ['  ├── src/core/ 核心模块（tamper 225 个）'];
  }, /⑬/);
  expectOk('二级文档写小数字的场景数（不该被 ⑬ 误伤）', (s) => {
    s.docs[0].lines = ['- recall-lab 18 场景、Rust fmt/clippy'];
  });
  // ⑭ API 表双向核对（本轮实测：README 写了不存在的 /api/scan/stop，且漏写 14 个真端点）
  expectFail('API 表写了代码里不存在的端点', (s) => {
    s.apiTable.rows.push({ line: 14, key: 'POST /api/scan/stop' });
  }, /⑭.*不存在/);
  expectFail('代码新增端点而 API 表漏写', (s) => {
    s.code.endpoints.push('GET /api/scan/:id/diff');
  }, /⑭.*漏写/);
  expectFail('API 表整段解析不出来（格式漂移）', (s) => {
    s.apiTable = { rows: [] };
  }, /⑭.*一行都没解析/);
  // ⑮ 教了跑不通的命令行路径（本轮实测：README 两处写 node bin/cli.js，真身在 server/bin/cli.js）
  expectFail('README 教的脚本路径不存在', (s) => {
    s.nodePaths = [{ line: 14, path: 'bin/cli.js' }];
  }, /⑮/);

  if (bad.length) {
    console.error('[readme] ✗ 自证失败 —— 判据存在空转或误报：');
    for (const b of bad) console.error('    · ' + b);
    return 1;
  }
  console.log('[readme] ✓ 自证通过：26 类漂移样本全部被点名，5 类正确样本无误报（判据不空转）');
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
  const suiteClaims = parseSuiteClaims(lines);
  const tamperUniverse = parseTamperUniverse(lines);
  const apiTable = parseApiTable(lines);
  const nodePaths = parseNodePathClaims(lines);

  const parseErrors = [overview, tiers, customer, tech, tamperCounts, payload, tamperUniverse, apiTable]
    .map((r) => r && r.error)
    .filter(Boolean);
  if (parseErrors.length) {
    console.error('[readme] ✗ 解析失败（README 结构可能已改，判据已失效 —— 必须修判据，不能静默跳过）：');
    for (const e of parseErrors) console.error('    · ' + e);
    return 1;
  }

  const upstream = readUpstreamTamper(new Set(tamperRegistry.list().map((t) => t.name)));
  // 二级文档：只读来判"有没有抄数字"，不参与任何数值比对
  const docs = ['SECURITY.md', 'CONTRIBUTING.md'].map((name) => ({
    name,
    lines: readFileSync(resolve(ROOT, name), 'utf8').split(/\r?\n/),
  }));
  const code = {
    techniques: Object.keys(VULN_TAXONOMY),
    tamperCount: tamperRegistry.list().length,
    payloadMain: countTemplates(PAYLOADS),
    payloadClause: countTemplates(CLAUSE_PAYLOADS),
    payloadOob: countTemplates(OOB_PAYLOADS),
    payloadRegistry: PAYLOAD_REGISTRY.length,
    acceptanceSuites: countAcceptanceSuites(),
    upstreamTotal: upstream.total,
    upstreamMissing: upstream.missing,
    upstreamTag: upstream.tag,
    endpoints: [...collectRegisteredEndpoints()],
    existingPaths: new Set(nodePaths.map((p) => p.path).filter((p) => existsSync(resolve(ROOT, p)))),
  };

  const fails = checkConsistency({
    overview, tiers, customer, tech, tamperCounts, payload, suiteClaims, tamperUniverse, docs, apiTable, nodePaths, code,
  });
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
    `payload 主库 ${code.payloadMain} + 子句 ${code.payloadClause} + OOB ${code.payloadOob} + 注册表 ${code.payloadRegistry}（= 代码实测）· ` +
    `API 表 ${apiTable.rows.length} 行（= 代码注册端点 ${code.endpoints.length} 条，双向已核）· ` +
    `验收 ${code.acceptanceSuites} 套件 · tamper 官方分母 ${code.upstreamTotal}（外部真值）· ` +
    `README 教的 ${nodePaths.length} 条 node <路径> 全部真实存在`,
  );
  return 0;
}

process.exit(main());
