// ============================================================================
// server/tests/castBudget.guard.test.js —— 测试/生产代码里「主动关掉类型检查」的行数只减不增
//
// 背景（2026-10-09，批次 D26/D27）：
//   D26 把 `src/tests` 纳入类型检查（此前 64 个测试文件 0 静态检查），打开就暴 45 处漂移。
//   但"进了检查范围"和"真在被检查"是两件事 —— 每一处 `as never` / `as any` / `as unknown as`
//   都是**在原地把刚建起来的检查关掉**。所以这条守卫是一个棘轮：
//   只许往下走，往上加必须先说明为什么这里非关不可。
//
// 为什么按「行」而不是「处」计数：一行里写两个 cast（`f(a as never, b as never)`）在本仓确实存在，
//   但判据要的是**趋势**而不是精确语法树；行数可由一条 grep 复现，任何人都能自己核对基线。
//
// 三类关法里的差别（本仓的取向）：
//   · `@ts-expect-error` **不计入预算** —— 它是自反的：那行要是没错了，指令本身会报错，
//     所以它不会静默失效。D27 就是把一批 `as never` 换成它（见 scanConfig.scope/contract）。
//   · `as never` 是最坏的：它把"这个实参到底该是什么类型"整个关掉，签名以后再变也不会报。
//   · `as unknown as T` 至少指名了目标类型，是"知道自己在绕过"的写法 —— 但仍属预算内。
//
// 三个方向：
//   ① 预算：两个 scope（src/tests 与 src 生产码）各自 ≤ 基线；
//   ② 自证：计数函数在合成样本上必须给出预期数字（正则写坏 ⇒ 恒 0 ⇒ 基线永远不破）；
//   ③ 分母：每个 scope 扫到的文件数必须成规模，且基线本身不许被写成 0 以外的退化值。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const NUL = String.fromCharCode(0);

// 基线：2026-10-09 D27 收完三批（scope / contract / store）后，**由判据自己现算**得到。
// ⚠️ 这里踩过一次：先用 `grep -nE ... | wc -l` 量到 102 当基线，注入一条 cast 却不红 ——
//    因为 grep 把"注释里讨论 as never"的行也算进去了，而判据剥注释后只有 91。
//    基线必须由判据本身产出（临时把基线设 0 读失败消息即可），不能由旁边的探针代劳。
const BASELINE = {
  tests: 91, // 同一判据口径下：本轮开工前（HEAD）117 行 → D27 摘到 91 行（−26）
  production: 11, // 本批未动，钉住不许增长
};

const SUPPRESSIVE = [/as never/g, /as any/g, /as unknown as/g];

/**
 * 单行判定（注释里讨论 cast 不算关掉检查）。
 * ⚠️ 自证必须调**这一个**函数：本守卫第一版的自证写了个本地副本、漏掉剥注释那步，
 *    于是它验的是"我以为判据长什么样"而不是判据本身 —— 这类 paraphrase 自证是假安全。
 */
function lineHasSuppression(raw) {
  const line = raw.replace(/\/\/.*$/, '');
  return SUPPRESSIVE.some((re) => new RegExp(re.source).test(line));
}

const countLines = (src) => src.split('\n').filter(lineHasSuppression).length;

/** 按"含任一形态的行数"计，一行最多贡献 1。 */
function countSuppressiveLines(files) {
  let lines = 0;
  const perFile = new Map();
  for (const f of files) {
    const abs = path.join(REPO, f);
    let st;
    try {
      st = statSync(abs);
    } catch {
      continue;
    }
    if (!st.isFile()) continue;
    const n = countLines(readFileSync(abs, 'utf8'));
    if (n) perFile.set(f, n);
    lines += n;
  }
  return { lines, perFile };
}

let tracked = [];
let gitSkip = false;
try {
  tracked = execFileSync('git', ['-C', REPO, 'ls-files', '-z'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
    .split(NUL)
    .filter((f) => /\.(ts|tsx)$/.test(f));
} catch (e) {
  gitSkip = 'git ls-files 不可用：' + (e && e.message ? e.message : String(e));
}

const TESTS_SCOPE = (f) => f.startsWith('src/tests/');
const PROD_SCOPE = (f) => f.startsWith('src/') && !TESTS_SCOPE(f);

test('自证：计数在合成样本上给出预期数字（正则一坏就恒 0，基线再也破不了）', () => {
  assert.equal(
    countLines(['const a = x as never;', 'const b = y as any;', 'const c = z as unknown as T;'].join('\n')),
    3
  );
  assert.equal(countLines('// 这里原本写 as never，已摘掉'), 0, '注释行不该被算成一次关闭');
  assert.equal(countLines('expect(1).toBe(1);'), 0);
  assert.equal(countLines('f(a as never, b as never);'), 1, '单位是行，不是处');
});

test('① 两个 scope 的行数都不得超过基线（只减不增）', { skip: gitSkip }, () => {
  const t = countSuppressiveLines(tracked.filter(TESTS_SCOPE));
  const p = countSuppressiveLines(tracked.filter(PROD_SCOPE));
  const top = (m) =>
    [...m.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([f, n]) => `  ${n}  ${f}`)
      .join('\n');

  assert.ok(
    t.lines <= BASELINE.tests,
    `src/tests 的 cast 行数 ${t.lines} > 基线 ${BASELINE.tests}。` +
      `要往测试里加 as never / as any，先问"这层关闭掩盖了什么"：` +
      `入参本来就合法就直接摘；故意喂非法值改用 @ts-expect-error（它自反，写错会报）。` +
      `确实非关不可才调基线，并在 CHANGELOG 里写明理由。\n当前最多的文件：\n${top(t.perFile)}`
  );
  assert.ok(
    p.lines <= BASELINE.production,
    `src 生产码的 cast 行数 ${p.lines} > 基线 ${BASELINE.production}。\n当前最多的文件：\n${top(p.perFile)}`
  );
});

test('② 分母：扫到的文件规模必须对得上（文件集一旦算错，0 行就是恒绿）', { skip: gitSkip }, () => {
  const tFiles = tracked.filter(TESTS_SCOPE);
  const pFiles = tracked.filter(PROD_SCOPE);
  assert.ok(tFiles.length >= 60, `src/tests 只扫到 ${tFiles.length} 个 TS 文件（应 60+）`);
  assert.ok(pFiles.length >= 60, `生产码只扫到 ${pFiles.length} 个 TS 文件（应 60+）`);
  // 计数必须真的看见过东西：全为 0 说明判据或路径坏了
  const { lines } = countSuppressiveLines([...tFiles, ...pFiles]);
  assert.ok(lines > 0, '一个 cast 都没扫到 ⇒ 判据已经瞎了，不要把它当"清零"');
});
