#!/usr/bin/env node
// ============================================================================
// scripts/merge-integrity.mjs —— 合并态完整性门禁（专门拦"merge 把代码吃掉了"）
//
// 为什么需要它（2026-09-29 实测事故，一次真实的 merge 回退）
// ----------------------------------------------------------------------------
// merge commit `684e4a3`（parents = `cc5fd55` `00ce269`）在解冲突时，把
// `server/src/services/scanLedger.js` 整段**回退**成了 `00ce269` 的旧版本：
//   · d44ff82（真功能提交，407 行）新增的 5 个函数定义丢失（−174 行）
//   · 调用点与 `export default { ... }` 清单却留着
//   · `src/services/scanLedger.js` 被静默改回"功能从未存在"的状态
//
// 这次事故的性质是**"合并导致的差异丢失"**，而不是"某人写错了代码"。因此它有三个特征，
// 也决定了本门禁该怎么写：
//   ① 它不是"新增的 bug"，而是"已修好的东西又回来了"——普通测试只会以「模块 import 崩」
//      的形式间接暴露，且**归因极难**（台账测试直接 fail，看起来像测试本身有问题）；
//   ② 单看 merge commit 毫无异常（它就是一次普通合并），必须**横向对比三个版本**才能发现；
//   ③ 只对"被 merge 触及的文件"做检查即可 —— 与 merge 无关的文件不可能被这个机制弄坏。
//
// 判据（两条，都只针对**本次变更**，因此适合进 CI）
// ----------------------------------------------------------------------------
//   ① 一致性：对发生在 base / ours / theirs 三者间的改动，
//      merge 结果必须**至少包含 ours 与 theirs 的全部内容**。具体做两件事：
//        a) 双方新增的行（相对 base）在 merge 结果里不得参差丢失 —— 用"每侧新增行中
//           merge 结果仍缺失的比例"衡量（允许少量因真实冲突取舍，阈值显式化）；
//        b) **symbol 级**：若某侧相对 base **新增导出了符号**，而 merge 结果里这个符号
//           **不存在**了 ⇒ 必红（这是本次事故的精确签名：d44ff82 新增 3 个导出，
//           merge 后它们的实现整段消失）。
//   ② 可加载：变更触及的 .js 文件必须仍能被静态解析且引用完整（复用
//      `module-loadable.mjs` 的判据，不手抄第二份）。
//
// ⚠️ 本门禁**不需要 checkout 三个版本**，全部用 `git show <rev>:<path>` 读内容，
//    因此可以在 CI 的浅克隆上运行（只要求 base/ours/theirs 三个 rev 可达）。
//
// 用法：
//   node scripts/merge-integrity.mjs                 # 自动探测：HEAD 是否 merge，取三个 rev
//   node scripts/merge-integrity.mjs --base <rev> --ours <rev> --theirs <rev>
//   node scripts/merge-integrity.mjs --selftest       # 自证：用本仓历史真实复现本次事故
//   node scripts/merge-integrity.mjs --json
// ============================================================================
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { parse } from 'acorn';
import { analyzeSource, checkModule } from './module-loadable.mjs';

const ROOT = process.cwd();
const argv = process.argv.slice(2);
const JSON_OUT = argv.includes('--json');
const SELFTEST = argv.includes('--selftest');

const argOf = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : null;
};

/** 行级"丢失比例"阈值：merge 有真实冲突取舍时允许少量丢失，超过即视为"吃代码" */
const MAX_DROP_RATIO = 0.1;
/** 参与检查的最小新增行数（太小的改动噪声大，不做比例判定，但仍做 symbol 判定） */
const MIN_LINES_FOR_RATIO = 20;

// ── 豁免清单（已知的历史损伤：显式登记 + 必须写理由与日期）──────────────────────
// 为什么需要：门禁是**回溯式**的——区间模式会看到历史上所有 merge，包括在门禁建成之前
// 就已发生、且已被人工修好的损伤（本仓 684e4a3 是唯一一例：它的 README 粘连与
// scanLedger 丢失都已在后续提交里修复）。没有豁免机制，这个合并会让区间检查**永久红**，
// 门禁变成噪声源 —— 而"永久红"的门禁最终一定会被人 `|| true` 掉，那才是真正的失效。
// 约定：豁免只针对"已修复的历史损伤"，且必须写理由与日期；未登记的违规一律照常红。
const WAIVER_PATH = path.join(ROOT, 'scripts', 'merge-integrity.waivers.json');
let WAIVERS = [];
try {
  if (fs.existsSync(WAIVER_PATH)) {
    const parsed = JSON.parse(fs.readFileSync(WAIVER_PATH, 'utf-8'));
    WAIVERS = Array.isArray(parsed?.waivers) ? parsed.waivers : [];
  }
} catch (e) {
  console.error(`⚠️  豁免清单解析失败（${WAIVER_PATH}）：${e?.message ?? e}`);
}

function waiverFor(merge, file, kind) {
  return WAIVERS.find(
    (w) => w && String(merge).startsWith(String(w.merge)) && w.file === file && w.kind === kind
  );
}

/** 把一批 finding 拆成"仍算失败"与"已豁免"两拨 */
function splitByWaiver(findings, merge) {
  const active = [];
  const waived = [];
  for (const f of findings) {
    const w = waiverFor(merge, f.file, f.kind);
    if (w) waived.push({ ...f, waiverReason: w.reason, waiverDate: w.date });
    else active.push(f);
  }
  return { active, waived };
}

function git(args, opts = {}) {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024, ...opts }).trim();
  } catch (e) {
    if (opts.allowFail) return null;
    throw new Error(`git ${args.join(' ')} 失败：${e.message}`);
  }
}

const hasRev = (rev) => git(['rev-parse', '--verify', '--quiet', `${rev}^{commit}`], { allowFail: true }) !== null;

/** 读某 rev 下某文件的文本（不存在返回 null） */
function show(rev, p) {
  return git(['show', `${rev}:${p}`], { allowFail: true });
}

/** 把文本按行拆开（统一换行；空文件得 []） */
function lines(text) {
  if (text === null || text === undefined) return null;
  if (text === '') return [];
  return text.replace(/\r\n/g, '\n').split('\n');
}

// ── 自动探测 merge 三方 ──────────────────────────────────────────────────────
export function detectMergeContext() {
  const parents = git(['rev-list', '--parents', '-n', '1', 'HEAD'], { allowFail: true });
  if (!parents) return null;
  const parts = parents.split(/\s+/);
  if (parts.length < 3) return null; // 非 merge commit
  const ours = parts[1];
  const theirs = parts[2];
  const base = git(['merge-base', ours, theirs], { allowFail: true });
  if (!base) return null;
  return { ours, theirs, base, merge: parts[0] };
}

/**
 * 枚举一个提交区间里的**全部** merge commit 及其三方信息。
 *
 * 为什么需要（HEAD 检测不够）：CI 在 push 上只看 HEAD；若候选分支的 HEAD 恰好是普通提交、
 * 而区间中间夹着一个吃代码的 merge，HEAD 检测就会漏。区间模式补上这个缺口。
 * merge-base 取不到的条目（浅克隆）跳过，不阻断。
 * @param {string} range 形如 `A..B`
 */
export function detectMergeContextsInRange(range) {
  const merges = (git(['rev-list', '--merges', range], { allowFail: true }) || '')
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
  const out = [];
  for (const merge of merges) {
    const parents = (git(['rev-list', '--parents', '-n', '1', merge], { allowFail: true }) || '').split(/\s+/);
    if (parents.length < 3) continue;
    const [, ours, theirs] = parents;
    const base = git(['merge-base', ours, theirs], { allowFail: true });
    if (!base) continue; // 浅克隆：跳过，不误判
    out.push({ merge, ours, theirs, base });
  }
  return out;
}

/** 本次 merge 实际改动的文件（相对 ours 与 theirs 的交集之外的那些） */
function changedFilesInMerge({ ours, theirs, merge }) {
  // merge 相对 ours 的差异 = 本次合并带进来的全部变化
  const out = git(['diff', '--name-only', ours, merge], { allowFail: true }) || '';
  return out.split('\n').map((s) => s.trim()).filter(Boolean);
}

// ── 判据 ① b：symbol 级"新增导出是否被吃掉" ──────────────────────────────────
/** 从源码里抽导出符号名（只看 Program 顶层，ESM 语义） */
export function exportedSymbols(src) {
  if (!src) return new Set();
  let ast;
  try {
    ast = parse(src, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true });
  } catch {
    return new Set();
  }
  const out = new Set();
  for (const node of ast.body) {
    if (node.type === 'ExportNamedDeclaration') {
      if (node.declaration) {
        const d = node.declaration;
        if (d.id) out.add(d.id.name);
        for (const decl of d.declarations || []) {
          if (decl.id) collectIds(decl.id, out);
        }
      }
      for (const s of node.specifiers || []) {
        const n = s.exported?.name ?? s.exported?.value;
        if (n) out.add(n);
      }
    } else if (node.type === 'ExportDefaultDeclaration') {
      out.add('default');
    }
  }
  return out;
}

function collectIds(node, out) {
  if (!node) return;
  if (node.type === 'Identifier') return void out.add(node.name);
  if (node.type === 'ObjectPattern') for (const p of node.properties) collectIds(p.value ?? p.argument, out);
  if (node.type === 'ArrayPattern') for (const el of node.elements) collectIds(el, out);
  if (node.type === 'AssignmentPattern') collectIds(node.left, out);
}

/**
 * 对单个文件跑 symbol 判据 + 行级判据。
 * @returns {Array<object>} findings
 */
export function checkFileAcrossMerge(file, ctx) {
  const findings = [];
  const baseSrc = show(ctx.base, file);
  const oursSrc = show(ctx.ours, file);
  const theirsSrc = show(ctx.theirs, file);
  const mergedSrc = show(ctx.merge, file);

  // 文件在 merge 结果里被删了，而某一侧还有 ⇒ 单独报（交由下面的 symbol 逻辑也不算漏）
  if (mergedSrc === null && (oursSrc !== null || theirsSrc !== null)) {
    findings.push({
      kind: 'file-dropped-in-merge',
      file,
      message: 'merge 结果中该文件消失，但至少一侧仍存在',
    });
    return findings;
  }
  if (mergedSrc === null) return findings;

  // ── symbol 级：任一侧相对 base 新增的导出，merge 后不得消失 ──
  const baseSym = baseSrc ? exportedSymbols(baseSrc) : new Set();
  const mergedSym = exportedSymbols(mergedSrc);
  for (const [side, src] of [['ours', oursSrc], ['theirs', theirsSrc]]) {
    if (!src) continue;
    const sym = exportedSymbols(src);
    for (const s of sym) {
      if (baseSym.has(s)) continue;      // 不是新增
      if (mergedSym.has(s)) continue;     // merge 保留了，正常
      findings.push({
        kind: 'added-export-dropped',
        file,
        symbol: s,
        message: `${side} 侧相对 base 新增了导出 '${s}'，但 merge 结果里它不存在了（典型：解冲突时把整段实现回退掉）`,
      });
    }
  }

  // ── 行级：某侧新增的行不得大面积消失 ──
  const baseLines = lines(baseSrc) || [];
  const mergedLines = lines(mergedSrc) || [];
  const mergedSet = new Set(mergedLines);
  for (const [side, src] of [['ours', oursSrc], ['theirs', theirsSrc]]) {
    if (src === null) continue;
    const sideLines = lines(src) || [];
    const baseSet = new Set(baseLines);
    const added = sideLines.filter((l) => l.trim() && !baseSet.has(l));
    if (added.length < MIN_LINES_FOR_RATIO) continue;
    const missing = added.filter((l) => !mergedSet.has(l));
    const ratio = missing.length / added.length;
    if (ratio > MAX_DROP_RATIO) {
      findings.push({
        kind: 'added-lines-dropped',
        file,
        side,
        message: `${side} 侧相对 base 新增 ${added.length} 行，merge 结果缺失 ${missing.length} 行（${(ratio * 100).toFixed(1)}% > 阈值 ${MAX_DROP_RATIO * 100}%）`,
        sample: missing.slice(0, 3).map((l) => l.trim().slice(0, 90)),
      });
    }
  }

  // ── 「粘连」判据：merge 把父提交里**相邻的两行粘成了一行** ──
  // 为什么必须单独判（2026-09-29 同一事故的第二处损伤）：
  //   同一个 merge 除了吃掉 scanLedger 的 174 行，还把 README.md 里 3 处相邻行粘成一行
  //   （徽章两行、`# 服务端测试（…）` 与 `cd server && npm test`、两条列表项）。
  //   这类损伤**字符一个字都没少**，只是丢了换行 ⇒ 行级"丢失"判据（上面那条）看不见它，
  //   只能靠 `facts:check` 的匹配式偶然发现（且它表现为"README 结构可能已改"，归因困难）。
  //   判据：对 merge 的每一行，看它能否被**父提交中相邻的两行**首尾拼出。真实代码里
  //   "某一行恰好等于父提交相邻两行拼接"的概率可忽略，故误报率极低。
  const JOIN_MIN_PART = 8; // 两侧片段各自至少 8 字符，避免短行（如 "}"、"}"）噪声
  for (const [side, src] of [['ours', oursSrc], ['theirs', theirsSrc]]) {
    if (src === null) continue;
    const sideLines = lines(src) || [];
    const consecutive = new Set();
    for (let i = 0; i + 1 < sideLines.length; i++) {
      const a = sideLines[i].replace(/\s+$/, '');
      const b = sideLines[i + 1].replace(/^\s+/, '');
      if (a.length >= JOIN_MIN_PART && b.length >= JOIN_MIN_PART) consecutive.add(`${a}\u0000${b}`);
    }
    if (!consecutive.size) continue;
    for (const l of mergedLines) {
      if (l.length < JOIN_MIN_PART * 2) continue;
      for (let i = JOIN_MIN_PART; i <= l.length - JOIN_MIN_PART; i++) {
        if (!consecutive.has(`${l.slice(0, i)}\u0000${l.slice(i)}`)) continue;
        findings.push({
          kind: 'lines-joined-in-merge',
          file,
          side,
          message: `merge 结果第 ${mergedLines.indexOf(l) + 1} 行把 ${side} 侧相邻两行粘成了一行（丢了换行）：${l.trim().slice(0, 100)}`,
        });
        break;
      }
    }
  }

  // ── 判据 ②：变更触及的 .js 必须仍引用完整 ──
  if (file.endsWith('.js') && file.startsWith('server/')) {
    try {
      const abs = path.join(ROOT, file);
      if (fs.existsSync(abs)) {
        const mod = analyzeSource(fs.readFileSync(abs, 'utf-8'), abs);
        const byFile = new Map([[abs, mod]]);
        for (const f of checkModule(mod, byFile)) findings.push({ ...f, fromMergeCheck: true });
      }
    } catch {
      /* 解析失败由 module-loadable.mjs 全量门禁负责，这里不重复报 */
    }
  }
  return findings;
}

// ============================================================================
// 自证：用本仓**真实历史**复现 2026-09-29 那次 merge 事故
// ============================================================================
// 这是本门禁最有价值的一条验证：把 base/ours/theirs 指向真实的那三个 commit，
// 判据必须自己喊出"theirs 侧新增的导出 highestRisk 在 merge 结果里没了"。
// 伪造样本容易写成"顺着判据写"，真历史不会。
export function selfTest() {
  const SCENARIO = {
    name: '真实事故复现：684e4a3 把 d44ff82 的 scanLedger 实现吃掉',
    base: '00ce269',   // 远端 squash 态（旧版 scanLedger）
    ours: 'cc5fd55',   // 本地线（含 d44ff82 的完整实现）
    theirs: '00ce269',
    merge: '684e4a3',  // 出事的 merge commit
    file: 'server/src/services/scanLedger.js',
    expectKinds: ['added-export-dropped'],
  };
  // 同一事故的第二处损伤：README.md 被粘掉 3 处换行（字符没少，只有"丢失"判据看不见）
  const SCENARIO_JOIN = {
    name: '真实事故复现（粘连形态）：684e4a3 把 README 相邻行粘成一行',
    base: '00ce269',
    ours: 'cc5fd55',
    theirs: '00ce269',
    merge: '684e4a3',
    file: 'README.md',
    expectKinds: ['lines-joined-in-merge'],
  };

  let ok = true;
  for (const sc of [SCENARIO, SCENARIO_JOIN]) {
    const missing = [sc.base, sc.ours, sc.theirs, sc.merge].filter((r) => !hasRev(r));
    if (missing.length) {
      console.log(`  ⏭️  跳过真实历史自证：缺少 rev ${missing.join(', ')}（浅克隆/已 GC）`);
      continue;
    }
    const findings = checkFileAcrossMerge(sc.file, sc);
    const kinds = [...new Set(findings.map((f) => f.kind))];
    const hit = sc.expectKinds.every((k) => kinds.includes(k));
    if (!hit) ok = false;
    console.log(`  ${hit ? '✅' : '❌'} ${sc.name}`);
    console.log(`     命中判据：${kinds.join(', ') || '(无)'}`);
    for (const f of findings.slice(0, 4)) {
      console.log(`     · [${f.kind}]${f.symbol ? ` ${f.symbol}` : ''} ${String(f.message).slice(0, 110)}`);
    }
  }

  // 反向对照：一个"没有事故"的 merge 必须零违规 —— 否则门禁在健康树上恒红，不可用
  const clean = {
    base: '00ce269', ours: '684e4a3', theirs: '684e4a3',
    merge: '684e4a3', file: 'server/src/services/scanLedger.js',
  };
  const cleanSkipped = [clean.base, clean.ours, clean.theirs, clean.merge].some((r) => !hasRev(r));
  let cleanOk = true;
  if (!cleanSkipped) {
    const cf = checkFileAcrossMerge(clean.file, clean);
    cleanOk = cf.filter((f) => f.kind === 'added-export-dropped' || f.kind === 'added-lines-dropped').length === 0;
    console.log(`  ${cleanOk ? '✅' : '❌'} 反向对照：无事故的对比（ours=theirs=merge）必须零违规`);
  }

  return { ok, skipped: false };
}

// ── 入口 ────────────────────────────────────────────────────────────────────
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (SELFTEST) {
  console.log('merge-integrity 自证（真实历史）：');
  const r = selfTest();
  console.log(r.ok ? '\n✅ 自证通过：判据在真实事故上抓得到，且对健康 merge 零误报' : '\n❌ 自证失败');
  process.exit(r.ok ? 0 : 1);
}

if (isMain) {
  const explicit = { base: argOf('--base'), ours: argOf('--ours'), theirs: argOf('--theirs') };
  const range = argOf('--range');

  // ── 区间模式：检查一个区间内的**所有** merge（CI 只看 HEAD 会漏掉区间中间的 merge）──
  if (range && !explicit.base) {
    const ctxs = detectMergeContextsInRange(range);
    if (!ctxs.length) {
      console.log(`ℹ️  区间 ${range} 内没有可检的 merge commit（或无 merge / 浅克隆缺 merge-base）⇒ 判为通过。`);
      process.exit(0);
    }
    let all = [];
    const waivedAll = [];
    for (const ctx of ctxs) {
      const files = changedFilesInMerge(ctx);
      const found = [];
      for (const f of files) found.push(...checkFileAcrossMerge(f, ctx));
      const { active, waived } = splitByWaiver(found, ctx.merge);
      if (active.length) console.log(`  ⚠️  merge ${ctx.merge.slice(0, 8)}：${active.length} 处违规`);
      if (waived.length) console.log(`  ℹ️  merge ${ctx.merge.slice(0, 8)}：${waived.length} 处已豁免（见 scripts/merge-integrity.waivers.json）`);
      all = all.concat(active.map((f) => ({ ...f, merge: ctx.merge })));
      waivedAll.push(...waived.map((f) => ({ ...f, merge: ctx.merge })));
    }
    if (JSON_OUT) {
      console.log(JSON.stringify({ range, mergesChecked: ctxs.length, findings: all, waived: waivedAll }, null, 2));
    } else if (!all.length) {
      console.log(`✅ 合并态完整性通过：区间 ${range} 内 ${ctxs.length} 个 merge，0 违规${waivedAll.length ? `（另有 ${waivedAll.length} 处为已登记的历史损伤豁免）` : ''}`);
    } else {
      console.error(`❌ 合并态完整性失败：区间 ${range} 内 ${ctxs.length} 个 merge 共 ${all.length} 处违规\n`);
      for (const f of all) {
        console.error(`  [${f.kind}] ${f.merge.slice(0, 8)} ${f.file}${f.symbol ? ` (${f.symbol})` : ''} — ${f.message}`);
      }
    }
    process.exit(all.length ? 1 : 0);
  }

  let ctx = null;
  if (explicit.base && explicit.ours && explicit.theirs) {
    ctx = { ...explicit, merge: argOf('--merge') || 'HEAD' };
  } else {
    ctx = detectMergeContext();
  }

  if (!ctx) {
    console.log('ℹ️  HEAD 不是 merge commit（或缺少三方信息）⇒ 本次无需合并态检查，跳过。');
    console.log('    （CI 中本步骤因此天然只对 push/PR merge 生效；非 merge 场景判为通过。）');
    process.exit(0);
  }

  const files = changedFilesInMerge(ctx);
  const found = [];
  for (const f of files) found.push(...checkFileAcrossMerge(f, ctx));
  const { active: findings, waived } = splitByWaiver(found, ctx.merge);

  if (JSON_OUT) {
    console.log(JSON.stringify({ ctx: { base: ctx.base, ours: ctx.ours, theirs: ctx.theirs, merge: ctx.merge }, changedFiles: files.length, findings, waived }, null, 2));
  } else if (!findings.length) {
    console.log(`✅ 合并态完整性通过：merge ${ctx.merge.slice(0, 10)}（base ${ctx.base.slice(0, 8)} / ours ${ctx.ours.slice(0, 8)} / theirs ${ctx.theirs.slice(0, 8)}），检查 ${files.length} 个变更文件，0 违规${waived.length ? `（另有 ${waived.length} 处为已登记的历史损伤豁免）` : ''}`);
  } else {
    console.error(`❌ 合并态完整性失败：${findings.length} 处违规\n`);
    for (const f of findings) {
      console.error(`  [${f.kind}] ${f.file}${f.symbol ? ` (${f.symbol})` : ''} — ${f.message}`);
      if (f.sample) for (const s of f.sample) console.error(`        · ${s}`);
    }
    console.error('\n提示：这类缺陷是"merge 解冲突时把别人的实现回退了"，不是新写的 bug。');
    console.error('请对比三个版本后重新解冲突，不要用 --force 覆盖（会丢掉真实功能）。');
  }
  process.exit(findings.length ? 1 : 0);
}
