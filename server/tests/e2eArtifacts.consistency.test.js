// ============================================================================
// tests/e2eArtifacts.consistency.test.js —— 入库 e2e 报告的"结论列"必须与同行数据同向
// ============================================================================
// 起因（2026-09-25 实测）：`e2e/multi-engine-lab/results/multi-engine-report.md` 与
// `.no-waf.md` 两份**入库基线**的 9 行"说明"列全部印「检出」，而同一行的
// tamper off / tamper on 两列都是 `-`（空）。根因在生成端：
//     `${on ? '检出' : '未检出'}` —— `on` 是**拼接后的字符串**，空的时候是 '-' ⇒ 恒 truthy。
// 读的人因此拿到与数据完全相反的结论，而且这个状态已经躺了五天（产物生成于 09-20）。
//
// 为什么查"内部自洽"而不是"重跑再比对"：
//   产物带时间戳，逐字节比对必然天天红；而这次事故的性质是
//   **同一行里结论与数据矛盾** —— 不需要重跑任何 e2e 就能判，对新产物同样有效。
//   （另有一条相关事实：CI 里并没有"跑完测试后工作区必须干净"的门禁，实测
//    `grep git diff .github/workflows/ci.yml` 无命中 —— 那是另一个议题。）
// 判据自己不许多空转：文件数低于阈值直接红（第一版目录过滤写成恒假，就是被这条抓住的）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const MEASURE_RE = /tamper|off|on\b|命中|检出数|检出率|请求/i; // 表头里"这列是测量值"的写法
const VERDICT_HEAD_RE = /说明|结论/; // 结论列的两种写法（multi-engine 用"说明"，waf-real 用"结论"）
const BEFORE_RE = /关|off/i; // A/B 表的"前一列"
const AFTER_RE = /开|on\b/i; // A/B 表的"后一列"

/**
 * 单元格里的技术位集合：空与 '-' 都算空集。
 * ⚠ 还要认得**手写在表里的"没有"**：历史报告里写的是 `**- 全拦**`、`无`、`null`，
 *   直接按逗号切会得到一个名叫 `**- 全拦**` 的"技术位"，于是守卫反过来诬告一行诚实的
 *   「↑ 绕过生效」（off 其实是空集）。先把 markdown 强调剥掉、把"表示没有"的写法归一。
 */
function setOf(cell) {
  if (!cell) return [];
  const s = String(cell).replace(/[*_`]/g, '').trim();
  if (s === '' || s === '-' || s === '—') return [];
  // 判"这一格其实表示没有"的唯一安全做法：先把**明确表示没有**的词删掉，再看剩下
  //   是不是只有标点。反过来（"含 全拦 就返回空集"）会误伤 —— 真实历史行
  //   `| str | **- 全拦** | **boolean** | ↑ 绕过生效 |` 里前一格是占位符，
  //   而后一格/结论里可能带着同样的字样，宽判据会把诚实的行判成缺陷（我第一版就踩了，
  //   守卫当场造出三条假缺陷，被自己的合成用例抓住）。
  const nothingish = /^(?:[-—–.\s,、/（）()]*|全拦|未检出|无|none|null|n\/a|no data)$/i;
  const tokens = s.split(/[,，]/).map((x) => x.trim()).filter(Boolean);
  const set = tokens.filter((t) => t && !nothingish.test(t))
    // 一格写成 `- 全拦` / `（无）` 这种"占位符 + 说明"的，逐 token 清干净后也算空
    .filter((t) => !/^[\s\-—–.·（）()/]*$/i.test(t.replace(/全拦|未检出|无绕过|无|none|null|no data/gi, '')));
  return set;
}

/**
 * 找出一份 markdown 里"结论列与同一行测量列矛盾"的行。
 *
 * ⚠ 测量列**按表头文字选**。第一版按位置 `cells.slice(1, verdictIdx)` 取，
 *   于是「场景」这类标签列也被当成数据 —— `| h2 | num | - | - | 检出 |` 里的 'num'
 *   让"有信号"成立，把那份撒谎的产物放回工作区都不会红（变异验证当场抓到）。
 *
 * 两类判据：
 *   A「光说检出而测量列全空」—— 09-20 那份连印五天的基线的形状。
 *   B「A/B 两列与结论句方向相反」—— 结论句声称有收益/持平/全拦，就必须与同行两列的
 *     **集合差**一致。`e2e/waf-real/results/` 长期被 .gitignore 排除，这些表在 CI 的
 *     checkout 里根本不存在、守卫对它们从未生效；2026-09-25 放开 md 之后必须补上这条，
 *     否则"入库"只是把没人看的文件搬进仓库。
 */
function contradictoryTableRows(md, file) {
  const problems = [];
  let table = null; // 当前表的 { verdictIdx, measureIdx, beforeIdx, afterIdx, size }；遇到非表格行即失效
  for (const raw of String(md).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line.startsWith('|')) { table = null; continue; }
    if (/^[\s|:-]+$/.test(line)) continue; // 分隔行：既不是表头也不是数据
    const cells = line.split('|').slice(1, -1).map((c) => c.trim());
    const verdictIdx = cells.findIndex((c) => VERDICT_HEAD_RE.test(c));
    if (verdictIdx >= 0 && !table) {
      // 表头行：记下结论列与测量列的位置
      table = {
        verdictIdx,
        size: cells.length,
        measureIdx: cells
          .map((c, i) => (i !== verdictIdx && MEASURE_RE.test(c) ? i : -1))
          .filter((i) => i >= 0),
        beforeIdx: cells.findIndex((c, i) => i !== verdictIdx && BEFORE_RE.test(c)),
        afterIdx: cells.findIndex((c, i) => i !== verdictIdx && AFTER_RE.test(c)),
      };
      continue;
    }
    if (!table || cells.length !== table.size) continue;
    const verdict = cells[table.verdictIdx];
    // 表头没标出测量列时不下判据（宁可漏报一条形状未知的表，也不误报）
    if (!table.measureIdx.length) continue;

    // ── A 类：只说"检出"，同行测量列却全空 ──
    if (/^\s*(✅\s*)?检出\s*$/.test(verdict)) {
      const hasSignal = table.measureIdx.some((i) => cells[i] && cells[i] !== '-');
      if (!hasSignal) problems.push(`${file}: 「${cells.join(' | ')}」结论列写「${verdict}」，同行测量列却全是空`);
    }

    // ── B 类：A/B 两列的集合差必须与结论句同向 ──
    if (table.beforeIdx >= 0 && table.afterIdx >= 0 && table.beforeIdx !== table.afterIdx) {
      const off = setOf(cells[table.beforeIdx]);
      const on = setOf(cells[table.afterIdx]);
      const lost = off.filter((t) => !on.includes(t));
      const gained = on.filter((t) => !off.includes(t));
      const say = (re) => re.test(verdict);
      const row = `${file}: 「${cells.join(' | ')}」`;
      if (say(/绕过生效|新增/) && !gained.length) {
        // ⚠ 例外：`绕过生效（新增 …）` 这种写法已经把**新增的技术位点名**了，
        //   而点名名单与前一列相同（例如 `boolean` 在前一列已存在）时集合差为空 ——
        //   那不是"没新增"，是生成端自己写了一句与数据不符的话。这种情况同样要报，
        //   但要说清是"括号里点名的技术位并不新"，否则下一个读日志的人会以为是解析坏了。
        problems.push(`${row} 结论说"有新增/绕过生效"，而后一列没有前一列之外的技术位（前=[${off}] 后=[${on}]）`);
      }
      if (say(/绕过生效|新增/) && lost.length && !say(/丢失|反而/)) {
        problems.push(`${row} 结论只说"生效"，但同行显示 tamper 还**丢掉了** [${lost}] —— 报喜不报忧的结论句`);
      }
      const nothingClaim = /全拦|均未检出|无检出|两侧均未检出/.test(verdict);
      if (nothingClaim && (off.length || on.length)) {
        problems.push(`${row} 结论说"全拦/未检出"，同行却有技术位（前=[${off}] 后=[${on}]）`);
      }
      if (say(/持平|一致/) && (lost.length || gained.length)) {
        problems.push(`${row} 结论说"持平/一致"，同行两列的集合却不同（丢失 [${lost}] 新增 [${gained}]）`);
      }
      if (say(/丢失|反而/) && !lost.length) {
        problems.push(`${row} 结论说"丢失"，而后一列并没有少掉任何技术位（前=[${off}] 后=[${on}]）`);
      }
    }
  }
  return problems;
}

function listMarkdown(dir) {
  const root = join(REPO, dir);
  if (!existsSync(root)) return [];
  const out = [];
  for (const e of readdirSync(root, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = join(root, e.name);
    if (e.isDirectory()) out.push(...listMarkdown(relative(REPO, p)));
    else if (e.name.endsWith('.md')) out.push(p);
  }
  return out;
}

test('multi-engine-lab 三份入库基线：说明列不得与同行数据反向', () => {
  const files = [
    'e2e/multi-engine-lab/results/multi-engine-report.md',
    'e2e/multi-engine-lab/results/multi-engine-report.no-waf.md',
    'e2e/multi-engine-lab/results/multi-engine-report.pl1.md',
  ];
  const problems = [];
  for (const f of files) {
    const abs = join(REPO, f);
    assert.ok(existsSync(abs), `基线产物缺失：${f}`);
    problems.push(...contradictoryTableRows(readFileSync(abs, 'utf8'), f));
  }
  assert.deepEqual(problems, [], `报告在给自己的数据反着下结论：\n  ${problems.join('\n  ')}`);
});

// ── B 类判据自身的变异验证：撒谎写法必须全部被点名，诚实写法必须一条不报 ──
const AB_HEAD = ['| 场景 | tamper 关 | tamper 开 | 结论 |', '|---|---|---|---|'].join('\n');
const abRow = (off, on, verdict) => `${AB_HEAD}\n| num | ${off} | ${on} | ${verdict} |`;

test('B 类判据不空转：撒谎的结论句都要被点名，诚实的那条不许报', () => {
  const cases = [
    [abRow('boolean', 'boolean', '绕过生效'), '没有前一列之外的技术位'],
    [abRow('union,error', 'union', '绕过生效'), '还**丢掉了**'],
    [abRow('boolean', 'boolean,error', '技术位持平'), '集合却不同'],
    [abRow('-', '-', '技术位持平'), null], // 诚实行：不应报
    [abRow('boolean', '-', '全拦'), '却有技术位'],
    [abRow('boolean', 'boolean', '反而丢失 union'), '并没有少掉任何技术位'],
  ];
  for (const [md, fragment] of cases) {
    const problems = contradictoryTableRows(md, 'synthetic.md');
    if (fragment === null) {
      assert.deepEqual(problems, [], `诚实的行被误报了：\n  ${problems.join('\n  ')}`);
      continue;
    }
    assert.ok(problems.length >= 1, `撒谎的行没被点名：${md.split('\n').pop()}`);
    assert.ok(problems.some((p) => p.includes(fragment)),
      `报出来了但原因不对（期望含「${fragment}」）：\n  ${problems.join('\n  ')}`);
  }
});

test('入库的 CRS A/B 报告必须真在仓库里，且守卫对它那张表真的生效', () => {
  const f = 'e2e/waf-real/results/waf-real-report.md';
  const abs = join(REPO, f);
  assert.ok(existsSync(abs),
    `${f} 不在仓库里 —— README 引的"对外唯一口径"没有可查产物，守卫对它永远不生效`);
  const lines = readFileSync(abs, 'utf8').split(/\r?\n/);
  // 往**真实产物**里注入一句撒谎结论。只测合成分支是不够的：表头写法（"tamper 关/开"）、
  //   列序、分隔行只要与本机不一致，判据就会静默跳过整张表 —— 那种失效只有真文件能暴露。
  const dataRow = lines.findIndex((l) => /^\|\s*(num|str|like|orderby|blind)\s*\|/.test(l));
  assert.ok(dataRow >= 0, `${f} 里找不到注入点（数据行格式变了？守卫的表头识别也该跟着改）`);
  const cells = lines[dataRow].split('|');
  cells[cells.length - 2] = ' 绕过生效（新增 nothing） ';
  const injected = [
    ...lines.slice(0, dataRow),
    cells.join('|'),
    ...lines.slice(dataRow + 1),
  ].join('\n');
  const problems = contradictoryTableRows(injected, f);
  assert.ok(problems.length >= 1,
    `往真实产物注入撒谎结论都没被点名 ⇒ 守卫对这张表失效：\n  ${lines[dataRow]}`);
});

test('全仓 e2e 报告扫一遍：判据不得空转，且任何"说检出而测量列为空"的行都要报出来', () => {
  const files = listMarkdown('e2e');
  assert.ok(files.length >= 10, `只扫到 ${files.length} 份 e2e 报告 —— 遍历规则失效了，本守卫不得空转`);
  const problems = [];
  for (const p of files) {
    try {
      problems.push(...contradictoryTableRows(readFileSync(p, 'utf8'), relative(REPO, p).replace(/\\/g, '/')));
    } catch { /* 读不动的文件不在本判据范围内 */ }
  }
  assert.deepEqual(problems, [], `以下报告的结论与自己的数据矛盾：\n  ${problems.join('\n  ')}`);
});
