#!/usr/bin/env node
// ============================================================================
// scripts/lab-targets-check.mjs —— 靶场「靶点清单」一致性门禁（多靶场）
// ============================================================================
// 为什么需要它：评测结论（检出率 / 误报）建立在一条**真值链**上 ——
//
//   selftest.mjs ──生成──▶ ground-truth.json ──被读──▶ 评测判据（gate-check 等）
//        ▲                                     ▲
//        │（真值标定＝"这靶场有哪些点"的权威）   │
//   run-scan.mjs（决定"实际扫哪些"）────────────┘
//
// 「标定哪些」与「实际扫哪些」是**两份各自手写**的清单，加上真值表与若干子集清单，
// 彼此之间原本没有任何判据。不同步时后果**不对称**：
//   · 标定有、扫描无 → 该点不进扫描统计（检出的分母少一项，**静默**）
//   · 标定无、扫描有 → 评测拿到一个没有真值的点，无从判定（这个方向至少会红）
// 前者正是本仓反复出现的那类「静默缺口」（见 TODO §J/§Q/§R/§U/§V），故固化成判据。
//
// 口径（每个靶场都按这套查）：
//   1. **权威集合 = selftest 的真值标定**（"这个靶场有哪些点"由它说了算）；
//   2. `ground-truth.json`（派生物）必须**等于**权威 —— 不能少（漏项静默偏乐观）、
//      不能多（幽灵条目）；
//   3. **扫描清单 ⊆ 权威**，且**差集必须显式登记**在 `scanGaps` 里并写清理由
//      （不留"默认跳过"的口子；反向也查：登记的 id 必须真的在差集里，否则是清单腐烂）；
//   4. 子集清单（对标 sqlmap / 定向复核）⊆ 权威，**显式登记"为什么是子集"**，
//      规模走「只减不增」基线（悄悄删几项会让对标结论的分母变小而无人察觉）；
//   5. 任一文件解析不到靶点 id → 直接报错退出（判据失效必须显形，
//      静默返回空集合会让"一致"变成假绿）。
//
// 用法：node scripts/lab-targets-check.mjs   （退出码即结论）
// ============================================================================
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => readFileSync(resolve(ROOT, rel), 'utf8');

// 靶点 id 的形状（各靶场一致：字母+数字(+可选小写字母) + 若干 `-词`）
const ID_SHAPE = /^[A-Z]\d+[a-z]?(-[a-z0-9]+)+$/;

const LABS = [
  {
    name: 'redteam-lab',
    dir: 'e2e/redteam-lab/',
    // 权威：真值标定
    authority: { file: 'selftest.mjs', label: '真值标定', re: /\{\s*id:\s*'([^']+)'/g },
    // 派生物：必须等于权威
    derived: { file: 'ground-truth.json', label: '真值表', pick: (j) => j.map((x) => x.id) },
    // 扫描清单：⊆ 权威，差集必须登记在 scanGaps
    scan: { file: 'run-scan.mjs', label: '扫描目标', re: /T\('([^']+)'/g },
    scanGaps: [], // 全覆盖
    subsets: [
      {
        file: 'sqlmap-bench.mjs', baseline: 18, re: /\{\s*id:\s*'([^']+)'/g,
        why: '只取 sqlmap 能跑通的形态；README「sqlmap 同题对照」已注明分母不同、比率不可直接类比',
      },
      {
        file: 'verify-fix.mjs', baseline: 10, re: /\{\s*id:\s*'([^']+)'/g,
        why: '针对布尔/时间通道修复的复核：3 个命中点（C7/C8/A1）+ 7 个安全点全量，不覆盖其它通道',
      },
    ],
  },
  {
    name: 'blackbox-lab',
    dir: 'e2e/blackbox-lab/',
    authority: { file: 'selftest.mjs', label: '真值标定', re: /\bid:\s*'([^']+)'/g },
    derived: { file: 'ground-truth.json', label: '真值表', pick: (j) => j.points.map((x) => x.id) },
    scan: { file: 'run-scan.mjs', label: '扫描目标', re: /\{\s*id:\s*'([^']+)'/g },
    // [2026-09-20] 原先这两个点从未被扫描（run-scan 的 POINTS 只有 20 项，而注释声称
    // 「由 run-scenario.mjs 单独处理」—— 该文件全仓不存在，out/ 里也没有它们的产物）。
    // 现已按 TODO §W 补进扫描，差集清零。**注意**：差集清零只代表"不再有未覆盖的点"，
    // 不代表它们都能被检出 —— E1b 当前实测 MISS（引擎二阶只覆盖 error 型回显，
    // 而该靶点是 boolean 型差异），那是**评测结果**，记在 TODO §W 与 README，不归本门禁管。
    scanGaps: [],
    subsets: [
      {
        file: 'sqlmap-bench.mjs', baseline: 20, re: /\{\s*id:\s*'([^']+)'/g,
        why: '与 run-scan 对照的 sqlmap 同题命令（20 点）：比扫描覆盖少 D1-postform / E1b-admin-query '
          + '（两者原先都不在扫描范围内，sqlmap 侧也无对应命令），故比率不可直接类比',
      },
    ],
  },
];

function extractIds(file, re, who) {
  const src = read(file);
  const raw = [...src.matchAll(re)].map((m) => m[1]);
  const ids = raw.filter((x) => ID_SHAPE.test(x));
  const junk = raw.filter((x) => !ID_SHAPE.test(x));
  if (!ids.length) {
    console.error(`❌ 从 ${file} 里一条靶点 id 都没解析到（${who}）—— 结构变了，本门禁需要跟着改。`);
    console.error('   判据失效必须显形：静默返回空集合会让下面的"一致"变成假绿。');
    process.exit(2);
  }
  if (junk.length) console.error(`⚠️ ${file}（${who}）里有 ${junk.length} 个不像靶点 id 的匹配，已忽略：${junk.slice(0, 5).join('、')}`);
  const dup = [...new Set(ids.filter((x, i) => ids.indexOf(x) !== i))];
  return { ids, dup };
}

const problems = [];
const info = [];

for (const lab of LABS) {
  const D = lab.dir;
  info.push(`【${lab.name}】`);

  const auth = extractIds(D + lab.authority.file, lab.authority.re, lab.authority.label);
  const authority = new Set(auth.ids);
  if (auth.dup.length) problems.push(`${lab.name}: ${lab.authority.file} 有重复 id：${auth.dup.join('、')}`);
  info.push(`  权威（${lab.authority.label}）${authority.size} 个靶点`);

  // ② 派生物必须等于权威
  try {
    const json = JSON.parse(read(D + lab.derived.file));
    const dIds = lab.derived.pick(json);
    precheck(dIds);
    const miss = [...authority].filter((i) => !dIds.includes(i));
    const ghost = dIds.filter((i) => !authority.has(i));
    if (miss.length) {
      problems.push(`${lab.name}: ${lab.derived.file} 缺 ${miss.length} 个靶点（会被**静默排除出统计分母**）：${miss.join('、')}`);
    }
    if (ghost.length) problems.push(`${lab.name}: ${lab.derived.file} 里有权威集合之外的"幽灵靶点"：${ghost.join('、')}`);
    info.push(`  ${lab.derived.label} ${dIds.length} 条${miss.length || ghost.length ? '（见下方问题）' : ' ✅'}`);
  } catch (e) {
    problems.push(`${lab.name}: 读 ${lab.derived.file} 失败：${e.message}`);
  }

  // ③ 扫描清单 ⊆ 权威，差集必须登记
  const scan = extractIds(D + lab.scan.file, lab.scan.re, lab.scan.label);
  if (scan.dup.length) problems.push(`${lab.name}: ${lab.scan.file} 有重复 id：${scan.dup.join('、')}`);
  const scanGhost = scan.ids.filter((i) => !authority.has(i));
  if (scanGhost.length) problems.push(`${lab.name}: ${lab.scan.file} 扫了权威集合之外的靶点：${scanGhost.join('、')}`);
  const gap = [...authority].filter((i) => !scan.ids.includes(i));
  const declared = new Set(lab.scanGaps.map((g) => g.id));
  const undeclared = gap.filter((i) => !declared.has(i));
  const staleGap = [...declared].filter((i) => !gap.includes(i));
  if (undeclared.length) {
    problems.push(
      `${lab.name}: 有 ${undeclared.length} 个靶点**真值已标定、但扫描没有覆盖**，且未登记理由：${undeclared.join('、')}\n` +
        '     → 这些点的检出能力从未被评测过，而统计里看不出来。补扫 或 在 scanGaps 里登记'
    );
  }
  if (staleGap.length) problems.push(`${lab.name}: scanGaps 登记了实际已被覆盖的靶点（清单腐烂）：${staleGap.join('、')}`);
  info.push(`  ${lab.scan.label} ${scan.ids.length}/${authority.size}${gap.length ? `（差集 ${gap.length} 个，已登记）` : ' ✅ 全覆盖'}`);

  // ④ 子集
  if (lab.subsets) {
    for (const s of lab.subsets) {
      const sub = extractIds(D + s.file, s.re, s.file);
      if (sub.dup.length) problems.push(`${lab.name}: ${s.file} 有重复 id：${sub.dup.join('、')}`);
      const ghost2 = sub.ids.filter((i) => !authority.has(i));
      if (ghost2.length) problems.push(`${lab.name}: ${s.file} 引用了权威集合之外的靶点 id：${ghost2.join('、')}`);
      if (sub.ids.length < s.baseline) {
        problems.push(
          `${lab.name}: ${s.file} 只有 ${sub.ids.length} 条，低于基线 ${s.baseline}（只减不增）——` +
            '分母悄悄变小会让对标/复核结论失真；确认是有意缩减就同步下调基线'
        );
      }
      info.push(`  子集 ${s.file} ${sub.ids.length}/${authority.size} ⊆ 权威（基线 ${s.baseline}｜${s.why}）`);
    }
  }
}

function precheck(ids) {
  if (!Array.isArray(ids) || !ids.length) {
    console.error('❌ 派生物里一条靶点 id 都没取到 —— 结构变了，本门禁需要跟着改。');
    process.exit(2);
  }
}

console.log('靶点清单一致性门禁：');
for (const line of info) console.log(line.startsWith('  ') || line.startsWith('【') ? line : `  · ${line}`);

if (problems.length) {
  console.error(`\n❌ 检出 ${problems.length} 处不一致：\n`);
  for (const p of problems) console.error(`  · ${p}`);
  console.error('\n为什么这不是小事：真值链断了以后，评测结论看起来照常（甚至更好看），');
  console.error('但分母已经和靶场实际不一致 —— 没有人会因此去查。');
  process.exit(1);
}

console.log('\n✅ 所有靶场的清单一致（权威 = 真值表；扫描差集与子集均已登记）。');
process.exit(0);
