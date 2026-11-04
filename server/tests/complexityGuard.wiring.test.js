// ============================================================================
// tests/complexityGuard.wiring.test.js —— 函数级复杂度门禁必须真的接上（D53）
//
// 与 nestingGuard.wiring.test.js 同族：每加一道门禁，必须同时加接线守卫，
// 断言它出现在 CI / pre-commit / ci-local / check:all / package.json 里。
// 缺了就等于没加 —— 本仓已两次栽在"判据写好了但没人执行"上。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readCode } from './_srcScan.mjs';
import { readFileSync } from 'node:fs';

const repo = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

// parseRunBodies：抽出 CI yaml 里每个 `- run:` 的命令体（与 nestingGuard.wiring 同款）。
const RUN_RE = /^([ \t]*)(?:-[ \t]+)*run:[ \t]*(\|[-+]?)?[ \t]*(.*)$/;
function parseRunBodies(yaml) {
  const out = [];
  const lines = yaml.split(/\r?\n/);
  let base = -1, body = [];
  for (const raw of lines) {
    const line = raw.replace(/\s+#.*$/, '');
    if (/^\s*#/.test(line) || !line.trim()) continue;
    const m = line.match(RUN_RE);
    if (m) {
      if (base >= 0) out.push(body.join('\n'));
      base = m[1].length;
      body = [m[3]];
      if (!m[2]) out.push(body.join('\n')), (base = -1), (body = []);
      continue;
    }
    if (base >= 0 && line.length > base && /^\s+\S/.test(line)) body.push(line.slice(base));
  }
  if (base >= 0) out.push(body.join('\n'));
  return out;
}

test('接线-1) CI workflow 必须执行 complexity-guard（检查 + 自证各一步）', () => {
  const yaml = repo('.github/workflows/ci.yml');
  const runs = parseRunBodies(yaml);
  assert.ok(runs.length > 0, '解析不到任何 run 步骤 —— 解析器本身有问题，先自证');

  const check = runs.filter((r) => /complexity-guard\.mjs\s*$/.test(r.trim()));
  const self = runs.filter((r) => /complexity-guard\.mjs\s+--selftest\s*$/.test(r.trim()));
  assert.equal(check.length, 1, `CI 应恰好有 1 步执行 complexity-guard 检查，实际 ${check.length} 步`);
  assert.equal(self.length, 1, 'CI 必须同时跑 --selftest（钉住"判据不空转"）');
});

test('接线-2) pre-commit 必须包含函数级复杂度门禁', () => {
  const hook = repo('.husky/pre-commit');
  assert.match(hook, /run_gate\s+"函数级复杂度[^"]*"\s+node\s+scripts\/complexity-guard\.mjs/,
    'pre-commit 里应有一条 run_gate 调用 complexity-guard');
});

test('接线-3) ci-local 清单必须包含函数级复杂度门禁（自证 + 检查）', () => {
  const src = repo('scripts/ci-local.mjs');
  assert.match(src, /complexity-guard\.mjs\s+--selftest/, 'ci-local 应含 selftest 项');
  assert.match(src, /cmd:\s*'node scripts\/complexity-guard\.mjs'/, 'ci-local 应含检查项');
});

test('接线-4) package.json 提供可单独调用的脚本，且 check:all 串入检查', () => {
  const pkg = JSON.parse(repo('package.json'));
  assert.equal(pkg.scripts['complexity:guard'], 'node scripts/complexity-guard.mjs');
  assert.equal(pkg.scripts['complexity:guard:selftest'], 'node scripts/complexity-guard.mjs --selftest');
  assert.equal(pkg.scripts['complexity:baseline'], 'node scripts/complexity-guard.mjs --fix-baseline');
  assert.ok(pkg.scripts['check:all'].includes('complexity:guard'),
    'check:all 必须串入 complexity:guard');
  assert.ok(pkg.scripts['check:all'].includes('complexity:guard:selftest'),
    'check:all 也应含 selftest（与 nesting:selftest 的既有做法一致）');
});

// ── 门禁脚本本身的形态守卫 ─────────────────────────────────────────────────
test('形态-5) 脚本不得在 import 时执行 CLI（否则 measureFunctions/judge 无法被测试导入）', () => {
  const code = readCode(new URL('../../scripts/complexity-guard.mjs', import.meta.url));
  assert.ok(
    /isMain[\s\S]*if\s*\(\s*isMain\s*\)/.test(code),
    '应先判断是否被直接执行再跑 CLI —— 无条件执行会让 import 杀掉测试进程'
  );
  assert.ok(
    !/^process\.exit\(main\(\)\);/m.test(code),
    '存在无条件的顶层 process.exit(main())，模块无法被安全 import'
  );
});

test('形态-6) 基线文件存在且结构合法（门禁不得因基线缺失而空转）', () => {
  const b = JSON.parse(repo('docs/_complexity-baseline.json'));
  assert.ok(b && typeof b === 'object', '基线应为对象');
  assert.ok(b.functions && typeof b.functions === 'object', '基线应含 functions 字段');
  const entries = Object.entries(b.functions);
  assert.ok(entries.length > 0, '基线不应为空（存量确有超软上限的函数）');
  for (const [k, d] of entries) {
    assert.equal(typeof d.lines, 'number', `${k} 的 lines 应为数字`);
    assert.equal(typeof d.complexity, 'number', `${k} 的 complexity 应为数字`);
    assert.ok(d.lines > 100 || d.complexity > 15,
      `${k} 既不超行数软上限也不超复杂度软上限，收进基线无意义`);
  }
});

test('形态-7) 基线里的每项都应被当前仓库"测到"（防基线虚高）', async () => {
  const b = JSON.parse(repo('docs/_complexity-baseline.json'));
  const { measureFunctions, remapArrowKeys } = await import('../../scripts/complexity-guard.mjs');
  // [D244] 匿名函数的键带行号（`<arrow@N>`），**在其前面插入任何注释/空行都会漂移**。
  // guard 内部用 remapArrowKeys 处理这件事（D217），但本测试此前直接按基线键精确匹配
  // ⇒ guard 绿、测试红，把「行号漂移」误报成「基线腐烂」（D243 实测：插 17 行触发 3 个键）。
  // 现在测试与 guard 同口径：先全量度量，再用同一份重映射把基线键解析到当前实测键。
  const files = [...new Set(Object.keys(b.functions).map((k) => k.slice(0, k.lastIndexOf('::'))))];
  const measuredAll = measureFunctions(files);
  const remap = remapArrowKeys(measuredAll, b.functions);
  // remap 的方向是「实测键 → 基线键」，这里反过来查
  const actualKeyOf = new Map(Object.entries(remap).map(([m, bk]) => [bk, m]));
  let checked = 0;
  let remapped = 0;
  for (const [key, d] of Object.entries(b.functions)) {
    const actualKey = actualKeyOf.get(key) || key;
    const m = measuredAll[actualKey];
    assert.ok(m, `${key}：基线里有但当前代码测不到 —— 函数可能已改名或删除（基线腐烂）`);
    if (actualKey !== key) remapped++;
    assert.ok(m.lines <= d.lines,
      `${key}：基线记 ${d.lines} 行，实际 ${m.lines} 行 —— 基线虚高（可下调）`);
    assert.ok(m.complexity <= d.complexity,
      `${key}：基线记复杂度 ${d.complexity}，实际 ${m.complexity} —— 基线虚高（可下调）`);
    checked++;
  }
  assert.ok(checked > 0, '应至少校验一项');
  // 重映射是「按 (行数, 圈复杂度) 唯一匹配」，正常仓库里应当能解析掉那些漂移的匿名键。
  // 不断言 remapped > 0（某次重构后行号可能恰好没漂），只在它非零时留痕便于排查。
  if (remapped > 0) console.log(`[形态-7] 匿名函数键重映射 ${remapped} 个（行号漂移免疫）`);
});
// [D244] 形态-7 依赖 remapArrowKeys 才能免疫行号漂移。这里独立钉住它的三条边界，
// 防止 guard 侧把它改坏（比如放宽成「按序号对齐」）而测试跟着错。
test('形态-7b) remapArrowKeys：唯一特征匹配才映射，歧义/变差都不映射', async () => {
  const { remapArrowKeys } = await import('../../scripts/complexity-guard.mjs');
  const base = { 'a.js::<arrow@10>': { lines: 120, complexity: 18 } };
  // 特征一致 ⇒ 映射（行号漂移可解析）
  assert.deepEqual(
    remapArrowKeys({ 'a.js::<arrow@20>': { lines: 120, complexity: 18 } }, base),
    { 'a.js::<arrow@20>': 'a.js::<arrow@10>' }
  );
  // 特征变了（变差）⇒ 不映射：不能因为「都是同一个箭头」就放行
  assert.deepEqual(
    remapArrowKeys({ 'a.js::<arrow@20>': { lines: 121, complexity: 18 } }, base),
    {}
  );
  // 歧义（同文件两个同特征匿名函数）⇒ 不映射：宁可误报，不静默错配
  assert.deepEqual(
    remapArrowKeys({
      'a.js::<arrow@20>': { lines: 120, complexity: 18 },
      'a.js::<arrow@30>': { lines: 120, complexity: 18 },
    }, base),
    {}
  );
});
