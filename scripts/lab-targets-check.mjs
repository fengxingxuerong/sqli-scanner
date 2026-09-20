#!/usr/bin/env node
// ============================================================================
// scripts/lab-targets-check.mjs —— 红队靶场「靶点清单」一致性门禁
// ============================================================================
// 为什么需要它：redteam-lab 的评测结论（检出率 / 误报）建立在一条**真值链**上：
//
//   selftest.mjs ──生成──▶ ground-truth.json ──被读──▶ gate-check.mjs ◀── results-r2.json
//        ▲                                                    ▲                    ▲
//        └── id 集合必须一致 ──┐                               │                    │
//                             │                               └── 分母只含 truth=true 的 vuln
//        run-scan.mjs ────────┘（决定"扫哪些"）────────────────────────────────────────┘
//
// 三份清单（run-scan / selftest / ground-truth）是**各自手写**的，彼此之间没有任何判据。
// 一旦不同步，后果**不对称**：
//   · run-scan 多一个点、selftest 少一个 → 该点不进真值表 → **完全不计入分母** → 静默，
//     而且结论看起来更漂亮（检出率不受影响）。
//   · selftest 多一个点、run-scan 少一个 → 那个不可观测的 id 恒判未命中 → 检出率被拉低，
//     这个方向会红，至少有人会去查。
// 前者正是本仓反复出现的那类「静默缺口」（见 TODO §J/§Q/§R/§U），故固化成可跑判据。
//
// 口径：
//   · **权威集合** = run-scan 的 TARGETS 与 selftest 的 TARGETS，且两者必须**逐 id 相等**
//     （「要扫哪些」与「要标定哪些」是同一件事的两面，不允许差集）
//   · `ground-truth.json` 的 id 集合必须**等于**权威集合（它是 selftest 的派生物）
//   · 子集清单（sqlmap-bench / verify-fix）必须 ⊆ 权威，且**显式登记"为什么是子集"**；
//     规模受「只减不增」基线保护 —— 悄悄删几个会让对标结论的分母变小而无人察觉
//     （与 `scripts/.arch-baseline.json`、tamper 缺失集合基线同一模式）
//
// 用法：node scripts/lab-targets-check.mjs   （退出码即结论）
// ============================================================================
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => readFileSync(resolve(ROOT, rel), 'utf8');

const LAB = 'e2e/redteam-lab/';

// 权威清单：两份必须逐 id 相等
const AUTHORITATIVE = [
  { key: 'run-scan.mjs', label: '扫描目标', re: /T\('([^']+)'/g },
  { key: 'selftest.mjs', label: '真值标定', re: /\{\s*id:\s*'([^']+)'/g },
];

// 子集清单：显式登记"为什么不是全集"，并用基线锁住规模（只减不增）
const SUBSETS = [
  {
    key: 'sqlmap-bench.mjs',
    label: 'sqlmap 同题对照',
    re: /\{\s*id:\s*'([^']+)'/g,
    baseline: 18,
    why: '只取 sqlmap 能跑通的形态；README「sqlmap 同题对照」已注明分母不同、比率不可直接类比',
  },
  {
    key: 'verify-fix.mjs',
    label: '修复后独立复核',
    re: /\{\s*id:\s*'([^']+)'/g,
    baseline: 10,
    why: '针对布尔/时间通道修复的复核：3 个命中点（C7/C8/A1）+ 7 个安全点全量，不覆盖其它通道',
  },
];

function extractIds(rel, re, who) {
  const src = read(rel);
  const ids = [...src.matchAll(re)].map((m) => m[1]);
  if (!ids.length) {
    console.error(`❌ 从 ${rel} 里一条 id 都没解析到（${who}）—— 该文件结构变了，本门禁需要跟着改。`);
    console.error('   判据失效必须显形：静默返回空集合会让下面的"一致"变成假绿。');
    process.exit(2);
  }
  const dup = [...new Set(ids.filter((x, i) => ids.indexOf(x) !== i))];
  return { ids, dup };
}

const problems = [];
const info = [];

// ── 权威清单：两份必须相等 ────────────────────────────────────────────────────
const auth = AUTHORITATIVE.map((a) => {
  const { ids, dup } = extractIds(LAB + a.key, a.re, a.label);
  if (dup.length) problems.push(`${a.key} 里有重复 id：${dup.join('、')}`);
  return { ...a, ids };
});
const [first, ...rest] = auth;
for (const other of rest) {
  const onlyA = first.ids.filter((i) => !other.ids.includes(i));
  const onlyB = other.ids.filter((i) => !first.ids.includes(i));
  if (onlyA.length || onlyB.length) {
    problems.push(
      `权威清单不一致：${first.key}(${first.ids.length}) ↔ ${other.key}(${other.ids.length})\n` +
        (onlyA.length ? `     只在 ${first.key}：${onlyA.join('、')}\n` : '') +
        (onlyB.length ? `     只在 ${other.key}：${onlyB.join('、')}` : '')
    );
  }
}
const authority = new Set(first.ids);
info.push(`权威集合 ${authority.size} 个靶点（${auth.map((a) => a.key).join(' / ')}）`);

// ── 真值表：必须等于权威集合（它是 selftest 的派生物）──────────────────────────
try {
  const gt = JSON.parse(read(LAB + 'ground-truth.json'));
  const gtIds = gt.map((g) => g.id);
  if (!gtIds.length) {
    problems.push('ground-truth.json 是空的（没有条目）—— 它应由 selftest 生成，先跑 npm run redteam:truth');
  }
  const missInGt = [...authority].filter((i) => !gtIds.includes(i));
  const ghostInGt = gtIds.filter((i) => !authority.has(i));
  if (missInGt.length) {
    problems.push(
      `真值表缺 ${missInGt.length} 个靶点（会被**静默排除出检出率分母**）：${missInGt.join('、')}\n` +
        '     先跑 npm run redteam:truth 重建真值表'
    );
  }
  if (ghostInGt.length) problems.push(`真值表里有权威集合之外的"幽灵靶点"：${ghostInGt.join('、')}`);
  const unsafe = gt.filter((g) => g.kind === 'vuln' && g.truth !== true).map((g) => g.id);
  if (unsafe.length) {
    problems.push(`真值表里有 ${unsafe.length} 个 vuln 未通过标定（truth≠true）：${unsafe.join('、')}`);
  }
  info.push(`真值表 ${gtIds.length} 条（vuln ${gt.filter((g) => g.kind === 'vuln').length} / safe ${gt.filter((g) => g.kind === 'safe').length}）`);
} catch (e) {
  problems.push(`读 ground-truth.json 失败：${e.message}`);
}

// ── 子集清单：⊆ 权威 + 规模只减不增 ──────────────────────────────────────────
for (const s of SUBSETS) {
  const { ids, dup } = extractIds(LAB + s.key, s.re, s.label);
  if (dup.length) problems.push(`${s.key} 里有重复 id：${dup.join('、')}`);
  const ghost = ids.filter((i) => !authority.has(i));
  if (ghost.length) problems.push(`${s.key} 引用了权威集合之外的靶点 id：${ghost.join('、')}`);
  if (ids.length < s.baseline) {
    problems.push(
      `${s.key} 只有 ${ids.length} 条，低于基线 ${s.baseline}（只减不增）——` +
        '分母悄悄变小会让对标/复核结论失真；确认是有意缩减就同步下调基线'
    );
  }
  info.push(`子集 ${s.key} ${ids.length}/${authority.size} ⊆ 权威（基线 ${s.baseline}｜${s.label}：${s.why}）`);
}

// ── 输出 ──────────────────────────────────────────────────────────────────────
console.log('靶点清单一致性门禁：');
for (const line of info) console.log(`  · ${line}`);

if (problems.length) {
  console.error(`\n❌ 检出 ${problems.length} 处不一致：\n`);
  for (const p of problems) console.error(`  · ${p}`);
  console.error('\n为什么这不是小事：真值链断了以后，评测结论看起来照常（甚至更好看），');
  console.error('但分母已经和靶场实际不一致 —— 没有人会因此去查。');
  process.exit(1);
}

console.log('\n✅ 五份清单一致：权威 %d 个靶点，真值表与子集均已核对。', authority.size);
process.exit(0);
