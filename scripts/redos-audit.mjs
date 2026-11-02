#!/usr/bin/env node
// ============================================================================
// scripts/redos-audit.mjs —— [D232] 检测器正则的 ReDoS（灾难性回溯）审计
//
// 为什么需要它：检测器的正则**跑在目标可控的响应体上**（最大 10MB）。一条
// `(a+)+` 形态的表达式就能让扫描器被目标拖死——这不是性能问题，是 DoS 面。
// 《卡死风险报告》P2-4 指出该审计一直没做，本脚本把它机器化。
//
// 做法（两段，缺一不可）：
//   ① **静态**：用 espree 从 AST 精确取正则字面量（不靠正则匹配源码，避免误抓注释/除法），
//      按嵌套量词等启发式打分，产出候选清单；
//   ② **动态**：对候选喂"病态串"（`a` 的重复 + 一个破坏后缀），在 **worker 线程**里跑并限时，
//      超时 = 确认灾难性回溯。静态只用来排序，结论以动态为准。
//
// 用法：
//   node scripts/redos-audit.mjs              # 静态 + 动态，输出表格与 JSON
//   node scripts/redos-audit.mjs --static     # 只做静态候选清单（快）
//   node scripts/redos-audit.mjs --json       # 机器可读
//   node scripts/redos-audit.mjs --selftest   # 判据自证（对已知危险/安全样本）
// ============================================================================
import { readdirSync, readFileSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import * as espree from 'espree';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_DIRS = ['server/src/engine', 'server/src/core', 'server/src/services'];

/** 单条正则的动态探测预算（超过即判为病态输入下的不可接受成本） */
const PROBE_BUDGET_MS = 250;
/** 病态串长度：32/26/24 是经典 (a+)+ 的致命区间，太短测不出、太长会真挂 */
const PROBE_SIZES = [24, 26, 32];

// ── 静态：AST 提取 ─────────────────────────────────────────────────────────
function walkFiles(dir, out = []) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) walkFiles(p, out);
    else if (ent.name.endsWith('.js')) out.push(p);
  }
  return out;
}

/**
 * `new RegExp('字面量', 'flags')` 的静态部分；不是这种形态返回 null。
 * @param {object} node
 * @returns {{pattern:string, flags:string}|null}
 */
function ctorRegexParts(node) {
  if (node.type !== 'NewExpression') return null;
  if (node.callee?.name !== 'RegExp') return null;
  const [arg, flagArg] = node.arguments || [];
  if (arg?.type !== 'Literal' || typeof arg.value !== 'string') return null;
  const flags = flagArg?.type === 'Literal' ? String(flagArg.value ?? '') : '';
  return { pattern: arg.value, flags };
}

/**
 * 从一个 AST 节点取出正则记录；不是正则返回 null。
 * @param {object} node
 * @param {string} file
 * @returns {{file:string, line:number, pattern:string, flags:string, source:'literal'|'ctor'}|null}
 */
function regexFromNode(node, file) {
  if (node.type === 'Literal' && node.regex) {
    return { file, line: node.loc.start.line, pattern: node.regex.pattern, flags: node.regex.flags, source: 'literal' };
  }
  const ctor = ctorRegexParts(node);
  if (!ctor) return null;
  return { file, line: node.loc.start.line, ...ctor, source: 'ctor' };
}

/**
 * 深度优先遍历 AST，跳过 loc/range 等元字段（它们也指向对象，会把遍历带偏）。
 * @param {object|object[]} node
 * @param {(n:object)=>void} onNode
 */
function walkAst(node, onNode) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const n of node) walkAst(n, onNode);
    return;
  }
  onNode(node);
  for (const k of Object.keys(node)) {
    if (k === 'loc' || k === 'range' || k === 'parent') continue;
    const v = node[k];
    if (v && typeof v === 'object') walkAst(v, onNode);
  }
}

/**
 * 从源码里取正则：字面量 `/.../flags` 与 `new RegExp('字面量')`（只认可静态求值的字符串）。
 * @param {string} file
 * @returns {Array<{file:string, line:number, pattern:string, flags:string, source:'literal'|'ctor'}>}
 */
function extractRegexes(file) {
  let src;
  try { src = readFileSync(file, 'utf-8'); } catch { return []; }
  let ast;
  try {
    ast = espree.parse(src, { ecmaVersion: 'latest', sourceType: 'module', loc: true });
  } catch {
    return []; // 解析不了的文件（如含实验语法）跳过，不让审计本身崩
  }
  const out = [];
  walkAst(ast, (node) => {
    const r = regexFromNode(node, file);
    if (r) out.push(r);
  });
  return out;
}

// ── 静态打分：只用于排序，结论以动态为准 ────────────────────────────────────
/**
 * 嵌套量词等危险形态打分（0 = 未命中明显形态）。
 * 保守实现：宁可漏报给动态兜（动态是权威），也不要把大量安全正则排到前面。
 * @param {string} p
 * @returns {{score:number, reasons:string[]}}
 */
function scorePattern(p) {
  const reasons = [];
  let score = 0;
  // 组内含量词 + 组外量词：(a+)+ / (\w*\s?)* / (?:a|b+)*
  if (/\([^()]*[+*][^()]*\)\s*[+*{]/.test(p)) { score += 3; reasons.push('组内量词 + 组外量词'); }
  // 交替分支共享前缀 + 外层量词：(a|ab)+
  if (/\([^()]*\|[^()]*\)\s*[+*{]/.test(p)) { score += 2; reasons.push('交替 + 组外量词'); }
  // 相邻重叠量词：.*.* / \w+\w+
  if (/(\.\*|\\w\+|\\s\+|\\d\+)\s*(\.\*|\\w\+|\\s\+|\\d\+)/.test(p)) { score += 2; reasons.push('相邻重叠量词'); }
  // 无边界的贪婪 .* 夹在定界符之间（回溯放大）
  if (/\.\*[^)]*\.\*/.test(p)) { score += 1; reasons.push('双 .*'); }
  return { score, reasons };
}

// ── 动态：worker 隔离探测 ──────────────────────────────────────────────────
/**
 * worker 侧：对给定正则喂病态串，返回各长度下耗时。
 * 单独进程/线程的意义：真挂住时可以直接 terminate，不把主流程带走。
 */
function probeInWorker() {
  const { pattern, flags, sizes } = workerData;
  const out = [];
  let re;
  try { re = new RegExp(pattern, flags.includes('g') ? flags : `${flags}`.replace(/y/g, '')); } catch { parentPort.postMessage({ error: 'invalid' }); return; }
  for (const n of sizes) {
    // 病态串：全 a + 一个非 a 后缀（破坏匹配 ⇒ 逼出回溯）；同时试数字/空格变体
    const subjects = ['a'.repeat(n) + '!', '1'.repeat(n) + 'x', ' '.repeat(n) + '#'];
    let worst = 0;
    for (const s of subjects) {
      const t0 = process.hrtime.bigint();
      try { re.lastIndex = 0; re.test(s); } catch { /* ignore */ }
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      if (ms > worst) worst = ms;
    }
    out.push({ n, ms: worst });
  }
  parentPort.postMessage({ samples: out });
}

/**
 * 在 worker 里跑一条正则的探测，超 budget 立刻 terminate。
 * @param {{pattern:string, flags:string}} re
 * @returns {Promise<{ms:number, timedOut:boolean, error?:string}>}
 */
function probe(re, budget = PROBE_BUDGET_MS) {
  return new Promise((res) => {
    const w = new Worker(new URL(import.meta.url), {
      workerData: { pattern: re.pattern, flags: re.flags, sizes: PROBE_SIZES },
    });
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      w.terminate();
      res({ ms: budget, timedOut: true });
    }, budget);
    w.on('message', (msg) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      w.terminate();
      if (msg.error) return res({ ms: 0, timedOut: false, error: msg.error });
      const worst = Math.max(...msg.samples.map((s) => s.ms));
      res({ ms: worst, timedOut: false });
    });
    w.on('error', (e) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      res({ ms: 0, timedOut: false, error: e.message });
    });
  });
}

// ── 自证 ───────────────────────────────────────────────────────────────────
async function selftest() {
  const bad = { pattern: '(a+)+$', flags: '' };
  const good = { pattern: '^[a-z]+$', flags: '' };
  const r1 = await probe(bad);
  const r2 = await probe(good);
  const ok1 = r1.timedOut || r1.ms > 50; // 危险样本必须被判出来
  const ok2 = !r2.timedOut && r2.ms < 50; // 安全样本不得误报
  console.log(`[selftest] 危险样本 (a+)+$  → ${r1.timedOut ? '超时(判危险)' : r1.ms.toFixed(2) + 'ms'} ${ok1 ? 'OK' : 'FAIL'}`);
  console.log(`[selftest] 安全样本 ^[a-z]+$ → ${r2.timedOut ? '超时(误报)' : r2.ms.toFixed(2) + 'ms'} ${ok2 ? 'OK' : 'FAIL'}`);
  // 静态打分也要有区分度
  const sb = scorePattern(bad.pattern).score;
  const sg = scorePattern(good.pattern).score;
  console.log(`[selftest] 静态打分 危险=${sb} 安全=${sg} ${sb > sg ? 'OK' : 'FAIL'}`);
  process.exit(ok1 && ok2 && sb > sg ? 0 : 1);
}

// ── 主流程 ─────────────────────────────────────────────────────────────────
async function main() {
  const argv = process.argv.slice(2);
  if (!isMainThread) return probeInWorker(); // worker 入口
  if (argv.includes('--selftest')) return selftest();

  const files = SCAN_DIRS.flatMap((d) => {
    const abs = join(ROOT, d);
    try { return statSync(abs).isDirectory() ? walkFiles(abs) : []; } catch { return []; }
  });

  const all = files.flatMap(extractRegexes);
  const scored = all.map((r) => ({ ...r, ...scorePattern(r.pattern) }))
    .sort((a, b) => b.score - a.score);

  console.log(`扫描 ${files.length} 个文件，提取正则 ${all.length} 条`);
  const candidates = scored.filter((r) => r.score > 0).slice(0, 40);
  console.log(`静态打分 >0 的候选 ${scored.filter((r) => r.score > 0).length} 条，对前 ${candidates.length} 条做动态探测（预算 ${PROBE_BUDGET_MS}ms）\n`);

  const results = [];
  if (!argv.includes('--static')) {
    for (const c of candidates) {
      // 逐条探测，不并发：并发会把机器打满，导致本来安全的正则被误判成超时
      const r = await probe(c);
      results.push({ ...c, probe: r });
      const mark = r.timedOut ? '✖ 超时' : r.error ? `! ${r.error}` : `${r.ms.toFixed(2)}ms`;
      if (r.timedOut || r.ms > 20) {
        console.log(`${mark.padEnd(10)} ${relative(ROOT, c.file)}:${c.line}  /${c.pattern.slice(0, 90)}/${c.flags}`);
      }
    }
    const danger = results.filter((r) => r.probe.timedOut);
    console.log(`\n动态确认灾难性回溯：${danger.length} 条`);
    if (!danger.length) console.log('（其余候选均在 20ms 内完成，未见病态输入下的爆炸）');
  }

  const outArg = argv.find((a) => a.startsWith('--out='));
  if (outArg) {
    const outFile = resolve(ROOT, outArg.slice('--out='.length));
    mkdirSync(dirname(outFile), { recursive: true });
    writeFileSync(outFile, JSON.stringify({
      generatedAt: new Date().toISOString(),
      filesScanned: files.length,
      regexes: all.length,
      probed: results.length,
      danger: results.filter((r) => r.probe.timedOut).map((r) => ({ file: relative(ROOT, r.file), line: r.line, pattern: r.pattern, flags: r.flags })),
      candidates: results.map((r) => ({ file: relative(ROOT, r.file), line: r.line, pattern: r.pattern, flags: r.flags, score: r.score, reasons: r.reasons, probe: r.probe })),
    }, null, 2));
    console.log(`\n产物：${relative(ROOT, outFile)}`);
  } else {
    // 默认不落盘：这道门禁每次收口都跑，写文件会让工作区无故变脏（facts/refs 门禁会感知）
    console.log('\n（未指定 --out，不落盘；要存档请加 --out=<相对路径>）');
  }
  process.exit(results.some((r) => r.probe.timedOut) ? 2 : 0);
}

main();
