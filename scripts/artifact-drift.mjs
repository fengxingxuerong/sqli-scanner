// ============================================================================
// scripts/artifact-drift.mjs —— 入库的 e2e 基线产物必须与"当前代码跑出来的"一致
// ============================================================================
// 起因（本仓栽过两次，都是同一形状）：
//   · `e2e/multi-engine-lab/results/*.md` 的结论列连印五天「tamper 后检出」，
//     而同一行的两列全是 `-` —— 生成端写的是 `${on ? '检出' : '未检出'}`，`on` 是拼接串。
//   · `mariadb-report.md` 里 `num | boolean | boolean | 绕过生效`，前后完全相同也说"生效"。
// 这两条都是**产物在说谎**，而且仓库里没有任何东西会因为它变红：
//   守卫测的是"结论与同行数据自不自洽"（内部一致性），
//   本脚本测的是"这份产物还是不是当前代码生成的那份"（外部一致性）。两回事，都要有。
//
// 为什么不能直接 `git diff --exit-code`：产物带 `> 生成：<ISO 时间>`，逐字节比必然天天红。
//   所以归一化只剥掉**时间戳**，其余一行不改 —— 表格、聚合值、有效性声明全部进比对。
//
// 判据不许多空转（本仓同类守卫第一版就被恒假过滤器骗过）：
//   ① 每个文件必须至少留下 1 行表格行，否则报错（说明归一化把内容全丢了）；
//   ② 清单里的路径必须是 git 跟踪的（否则 HEAD 侧永远是"文件不存在"）；
//   ③ 没有任何文件被检查 ⇒ 直接红，不返回"通过"。
//
// 用法：
//   node scripts/artifact-drift.mjs                 # 检查默认清单（CI 真跑的档）
//   node scripts/artifact-drift.mjs --list
//   node scripts/artifact-drift.mjs <path>...       # 只查指定产物
//   node scripts/artifact-drift.mjs --verbose       # 打印每档保留/丢弃了多少行
// 退出码：0 = 无漂移；1 = 有漂移或前提失效（缺文件 / 未跟踪 / 归一化后为空）。
// ============================================================================
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');

// 默认清单：**CI 每次 push 真的会重跑**的那些档的产物。
// 故意不含 `waf-real-report.md` / `.pl2.md` / `.pl4.md`：那几份要真 MySQL / 真 MariaDB，
// 只在 acceptance job 与本机跑，服务端小版本一变（error 通道文本指纹跟着变）就会假红。
// 等哪天 CI 里那两个 job 也重跑同一档，再逐份加进来 —— 加之前先测三次稳定度。
const DEFAULT_PATHS = [
  'e2e/multi-engine-lab/results/multi-engine-report.md',
  'e2e/multi-engine-lab/results/multi-engine-report.no-waf.md',
  'e2e/multi-engine-lab/results/multi-engine-report.pl1.md',
];

const argv = process.argv.slice(2);
const verbose = argv.includes('--verbose');
if (argv.includes('--list')) {
  console.log(DEFAULT_PATHS.join('\n'));
  process.exit(0);
}
const positional = argv.filter((a) => !a.startsWith('--'));
const PATHS = positional.length ? positional : DEFAULT_PATHS;

const TS_RE = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?/;

/**
 * 归一化：**只**剥时间戳。一行都不许多丢 —— 多丢一行就多一处不会被发现的说谎。
 * @param {string} text
 * @returns {{ kept: string[], tableRows: number, dropped: number }}
 */
function normalize(text) {
  const kept = [];
  let dropped = 0;
  let tableRows = 0;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, '');
    if (!line) continue;
    if (TS_RE.test(line)) { dropped++; continue; }
    if (line.startsWith('|')) tableRows++;
    kept.push(line);
  }
  return { kept, tableRows, dropped };
}

function headVersion(path) {
  const r = spawnSync('git', ['show', `HEAD:${path}`], { cwd: ROOT, maxBuffer: 32e6 });
  if (r.status !== 0) return null;
  return r.stdout.toString('utf8');
}

function isTracked(path) {
  const r = spawnSync('git', ['ls-files', '--error-unmatch', path], { cwd: ROOT, encoding: 'utf8' });
  return r.status === 0;
}

const problems = [];
let checked = 0;

for (const p of PATHS) {
  if (!isTracked(p)) {
    problems.push(`${p}：未被 git 跟踪 —— HEAD 侧没有"入库那份"可比，漂移检查对它不成立`);
    continue;
  }
  const headRaw = headVersion(p);
  if (headRaw === null) {
    problems.push(`${p}：git show HEAD:${p} 失败（仓库状态异常？）`);
    continue;
  }
  const diskPath = resolve(ROOT, p);
  if (!existsSync(diskPath)) {
    problems.push(`${p}：工作区里没有这份产物（被谁删了？HEAD 里还有）`);
    continue;
  }
  const diskRaw = readFileSync(diskPath, 'utf8');
  const a = normalize(headRaw);
  const b = normalize(diskRaw);
  // 反空转：归一化后没有表格行 ⇒ 要么这份产物本身不含表格，要么归一化把内容吞了
  if (a.tableRows === 0 || b.tableRows === 0) {
    problems.push(
      `${p}：归一化后表格行为 0（HEAD=${a.tableRows} 工作区=${b.tableRows}）` +
        ' —— 判据会因"没内容可比"而恒真，不许这样通过'
    );
    continue;
  }
  checked++;
  const diffs = [];
  const max = Math.max(a.kept.length, b.kept.length);
  for (let i = 0; i < max; i++) {
    if (a.kept[i] !== b.kept[i]) diffs.push([i, a.kept[i] ?? '（HEAD 侧已无此行）', b.kept[i] ?? '（工作区已无此行）']);
  }
  if (verbose) console.log(`  ${p}：比对 ${max} 行（剥时间戳 HEAD ${a.dropped} / 工作区 ${b.dropped}），表格行 ${b.tableRows}`);
  if (diffs.length) {
    const sample = diffs.slice(0, 6)
      .map(([i, l, r]) => `      第 ${i + 1} 行\n        - ${l}\n        + ${r}`)
      .join('\n');
    problems.push(
      `${p}：与 HEAD 那份不一致（${diffs.length} 行差异）—— ` +
        '要么代码/靶场行为真的变了（那就更新基线并在提交信息里写明差异），要么这份产物是手工改的\n' + sample +
        (diffs.length > 6 ? `\n      …另有 ${diffs.length - 6} 行` : '')
    );
  }
}

if (!PATHS.length || checked === 0) {
  console.error('[artifact-drift] 一个文件都没检查 ⇒ 不返回"通过"');
  process.exit(1);
}
if (problems.length) {
  console.error(`[artifact-drift] ❌ ${problems.length} 份产物与 HEAD 漂移：\n  ${problems.join('\n  ')}`);
  process.exit(1);
}
console.log(`[artifact-drift] ✅ ${checked} 份入库基线与当前代码产物一致（只忽略时间戳）`);
