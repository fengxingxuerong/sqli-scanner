// ============================================================================
// tests/auditExceptions.wiring.test.js —— 已接受的审计例外必须显式登记
// ============================================================================
// 本仓栽过的那一格：**没人记录"为什么这条还在"**，于是它静静躺着直到某天
// 有人以为"audit 已经清零了"。本仓的硬门禁是 `npm audit --audit-level=high`
// （见 scripts/ci-local.mjs 的 audit job 两条），确实会绿——但绿的原因是
// **阈值只拦 high/critical**，不是问题不存在。
//
// 这份清单把 medium 级的例外与其理由写死在仓库里，并要求：
//   · 例外条目必须能对应到真实的 audit 现状（版本范围仍命中），
//     否则是"过期例外"——问题已修或版本已升，条目应删；
//   · 一旦例外所依赖的前提变化（生产依赖也中危 / 修复不再需要大版本跨越），
//     条目就变成谎言，须由人复核。
//
// 判据不联网、不跑 audit（audit 需 registry 且极慢），只核**清单与依赖声明的自洽**。
// 真实漏洞状态请以 `npm audit` 的当次输出为准。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const pkg = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8'));

// ── 已接受的例外清单（唯一真源；改这里，不要散落到别处） ────────────────────
// 字段：包 / 当前声明版本 / 严重级 / 修法 / 理由 / 复核条件
const ACCEPTED = [
  {
    pkg: 'vitest',
    severity: 'moderate',
    advisory: 'GHSA-82fw-gwwq-j7x9（@vitest/mocker 重定向 mock 的路径穿越/任意文件读）',
    declared: '^3.2.7',
    why:
      '① 仅开发依赖，不进任何交付产物：生产依赖 `npm audit --omit=dev` 实测 **0 漏洞**，' +
      '且桌面壳（SEA/sidecar）打包的是 dist 与 engine，不含 vitest。' +
      '② 利用前提在本仓不成立：该缺陷要求测试代码里存在**攻击者可控的** mocker 重定向 mock。' +
      '本仓 vitest 用例是自有的固定测试集，mock 目标由测试作者写死，不接受外部输入。' +
      '③ 官方修复线为 vitest >=4.1.11，而 npm 给出的可达修复是 **4.x → 5.0.3 的破坏性大版本跨越**：' +
      '会连带要求 vite / @vitest/coverage-v8 / @vitejs/plugin-react 一起升，' +
      '而本仓前端测试 503 条、覆盖率门禁有数值阈值——这类变更必须单独做一轮' +
      '「升级 + 全量回归 + 覆盖率基线复核」，不能夹带在一次常规优化里。',
    revisitWhen:
      '任一成立即须重新评估并移除本条目：' +
      '(a) vitest 发布 >=4.1.11 且可在不跨大版本的前提下升到；' +
      '(b) 前端测试需要用 mocker redirect 接收外部可控输入；' +
      '(c) npm audit 的门槛被下调到 medium（即例外不再被阈值掩盖）。',
  },
];

test('例外-1) 已接受清单非空且每条都写明了理由与复核条件', () => {
  assert.ok(ACCEPTED.length > 0, '例外清单为空 —— 若中危已全部修复，请连同本文件一起删');
  for (const e of ACCEPTED) {
    for (const f of ['pkg', 'severity', 'advisory', 'declared']) {
      assert.ok(e[f], `例外条目 ${e.pkg || '(未命名)'} 缺少字段 ${f}`);
    }
    // 理由/复核条件才是「防止无声遗忘」的主体，必须实质成文。
    // ⚠️ 长度阈值只对这两个字段生效：declared 是版本号（'^3.2.7' 仅 6 字符），
    //   一开始把它也套进同一阈值，导致守卫对合法条目误红——判据自己先犯了
    //   「一刀切」的错。判据一旦误报，人就会开始忽略它，那比没有判据更糟。
    for (const f of ['why', 'revisitWhen']) {
      assert.ok(e[f] && String(e[f]).length > 30,
        `例外条目 ${e.pkg || '(未命名)'} 的 ${f} 未实质成文（≤30 字符）—— 未写清理由的例外等于没有登记`);
    }
  }
});

test('例外-2) 每条例外对应的包确实是 devDependency（不得放宽到生产依赖）', () => {
  for (const e of ACCEPTED) {
    assert.ok(pkg.devDependencies?.[e.pkg], `${e.pkg} 不在 devDependencies —— 例外前提「不进交付产物」已失效`);
    assert.ok(!pkg.dependencies?.[e.pkg],
      `${e.pkg} 同时出现在 dependencies —— 它会进交付产物，例外理由必须重写`);
  }
});

test('例外-3) 例外声明的版本范围与 package.json 当前声明一致（防止条目过期失真）', () => {
  for (const e of ACCEPTED) {
    assert.equal(pkg.devDependencies[e.pkg], e.declared,
      `${e.pkg} 当前声明 ${pkg.devDependencies[e.pkg]}，但例外清单写的是 ${e.declared}。\n` +
      '若版本已升：若已升到修复线以上 ⇒ 删掉本例外；若仍在修复线以下 ⇒ 更新 declared 与理由。');
  }
});

test('例外-4) 声明范围仍落在 advisory 的易感区间内（范围外则条目是废话）', () => {
  // GHSA-82fw-gwwq-j7x9 的易感范围：>=2.1.0 <4.1.11
  const VULN_RANGE = /^\^?3\./; // 3.x 全系在易感范围内
  for (const e of ACCEPTED) {
    if (e.pkg === 'vitest') {
      assert.match(e.declared, VULN_RANGE,
        `vitest 已声明为 ${e.declared}，若已不在 <4.1.11 易感区间，本例外应删除`);
    }
  }
});

test('例外-5) 生产依赖门禁仍以 high 为阈值且清单只登记 medium（口径不得悄悄放宽）', () => {
  const ciLocal = readFileSync(join(REPO, 'scripts', 'ci-local.mjs'), 'utf8');
  assert.ok(/npm audit --omit=dev --audit-level=high/.test(ciLocal),
    '生产依赖 audit 门禁缺失或阈值被改动');
  for (const e of ACCEPTED) {
    assert.equal(e.severity, 'moderate',
      `${e.pkg} 的例外严重级为 ${e.severity}：high/critical 必须立刻修，不得登记为例外`);
  }
});
