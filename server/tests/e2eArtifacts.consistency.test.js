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

/**
 * 找出一份 markdown 里"结论列与同一行测量列矛盾"的行。
 *
 * ⚠ 测量列**按表头文字选**。第一版按位置 `cells.slice(1, verdictIdx)` 取，
 *   于是「场景」这类标签列也被当成数据 —— `| h2 | num | - | - | 检出 |` 里的 'num'
 *   让"有信号"成立，把那份撒谎的产物放回工作区都不会红（变异验证当场抓到）。
 */
function contradictoryTableRows(md, file) {
  const problems = [];
  let table = null; // 当前表的 { verdictIdx, measureIdx, size }；遇到非表格行即失效
  for (const raw of String(md).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line.startsWith('|')) { table = null; continue; }
    if (/^[\s|:-]+$/.test(line)) continue; // 分隔行：既不是表头也不是数据
    const cells = line.split('|').slice(1, -1).map((c) => c.trim());
    const verdictIdx = cells.findIndex((c) => c.includes('说明'));
    if (verdictIdx >= 0 && !table) {
      // 表头行：记下结论列与测量列的位置
      table = {
        verdictIdx,
        size: cells.length,
        measureIdx: cells
          .map((c, i) => (i !== verdictIdx && MEASURE_RE.test(c) ? i : -1))
          .filter((i) => i >= 0),
      };
      continue;
    }
    if (!table || cells.length !== table.size) continue;
    const verdict = cells[table.verdictIdx];
    if (!/^\s*(✅\s*)?检出\s*$/.test(verdict)) continue; // 只管"光说检出"这种断言
    // 表头没标出测量列时不下判据（宁可漏报一条形状未知的表，也不误报）
    if (!table.measureIdx.length) continue;
    const hasSignal = table.measureIdx.some((i) => cells[i] && cells[i] !== '-');
    if (!hasSignal) {
      problems.push(`${file}: 「${cells.join(' | ')}」结论列写「${verdict}」，同行测量列却全是空`);
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

test('multi-engine-lab 两份入库基线：说明列不得与同行数据反向', () => {
  const files = [
    'e2e/multi-engine-lab/results/multi-engine-report.md',
    'e2e/multi-engine-lab/results/multi-engine-report.no-waf.md',
  ];
  const problems = [];
  for (const f of files) {
    const abs = join(REPO, f);
    assert.ok(existsSync(abs), `基线产物缺失：${f}`);
    problems.push(...contradictoryTableRows(readFileSync(abs, 'utf8'), f));
  }
  assert.deepEqual(problems, [], `报告在给自己的数据反着下结论：\n  ${problems.join('\n  ')}`);
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
