// ============================================================================
// boundaryCandidates.guard.test.js —— [D88 2026-10-18] 闭合候选表的结构不变量
//
// ── 为什么有这个文件 ────────────────────────────────────────────────────────
// 候选表此前是 `probeBoundary` 内的**局部数组字面量**，没有任何测试能引用它。
// 后果不是「少一个候选」这么轻——它被真实第三方靶场（OWASP Juice Shop）抓出了一条
// **静默假阴性**：
//   · 目标模板 `... AND (name LIKE '%{v}%' OR description LIKE '%{v}%')`（LIKE + 双层括号）
//   · 表里只有 `%'` / `%')` 两档，**缺 `%'))` 档** ⇒ 13 个候选全部落空
//   · 落空 ⇒ `point.boundary=''` ⇒ 门控探针退化成 `apple AND 1=1-- -`（谓词整条落在
//     字符串字面量内）⇒ 真假响应恒等 ⇒ 门控判「不是注入」⇒ UNION/布尔通道从未启动
//   · 报告写「未检出」——与「这个站没有注入」完全同形
//   · 同目标 sqlmap 1.10.7 **检出成功**（boolean-based blind，确认 SQLite）⇒ 外部裁判判我方漏检
//
// 所以本文件钉的不是「某个字符串在表里」，而是**两条结构不变量**——
// 补一个字符串只能治一处，不变量才防得住同族缺口再出现。
//
// 判据性质：静态断言（读导出常量），秒级、零网络、可进 CI 常驻。
// 真机侧由 e2e/juice-shop-lab（外部裁判靶场）承担。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BOUNDARY_CANDIDATES } from '../src/engine/detectorSupport/boundary.js';

const has = (p) => BOUNDARY_CANDIDATES.includes(p);

test('不变量①：LIKE 上下文的括号层级必须成阶梯（%\' / %\') / %\'))）', () => {
  // 缺任一档 ⇒ 对应括号层级的标准搜索框上，闭合探测全落空（Juice Shop 就是缺 %')) 这档）
  for (const p of ["%'", "%')", "%'))"]) {
    assert.ok(has(p), `LIKE 族缺 ${JSON.stringify(p)} —— 该括号层级的搜索框将整点漏检`);
  }
});

test('不变量②：双引号族的 LIKE 形态同样成阶梯（%" / %") / %"))', () => {
  for (const p of ['%"', '%")', '%"))']) {
    assert.ok(has(p), `LIKE 双引号族缺 ${JSON.stringify(p)} —— 双引号 + LIKE 目标将漏检`);
  }
});

test('不变量③：括号层级在「普通族」与「LIKE 族」之间对称', () => {
  // 普通族有 '))/")) 两档，LIKE 族就必须有 %'))/%")) 两档；
  // 单边缺档 = 同一模板形状换了 LIKE 前缀就失明（静默假阴性），这是最隐蔽的一类漂移。
  const pairs = [["'", "%'"], ["')", "%')"], ["'))", "%'))"], ['"', '%"'], ['")', '%")'], ['"))', '%"))']];
  for (const [plain, like] of pairs) {
    assert.equal(
      has(plain),
      has(like),
      `括号层级不对称：${JSON.stringify(plain)} ${has(plain) ? '在' : '不在'}表里，` +
        `但 ${JSON.stringify(like)} ${has(like) ? '在' : '不在'}表里 —— 同模板形状换 LIKE 前缀即失明`
    );
  }
});

test('不变量④：基础族齐全（空串/单引号/双引号/反引号 + 反斜杠转义）', () => {
  for (const p of ['', "'", '"', '`']) {
    assert.ok(has(p), `基础闭合族缺 ${JSON.stringify(p)}`);
  }
  // 反斜杠转义形态（addslashes 目标）：用码点比较，避免字面量转义歧义
  assert.ok(
    BOUNDARY_CANDIDATES.includes(String.fromCharCode(92)),
    '缺反斜杠转义形态（addslashes 目标上闭合探测会全落空）'
  );
});

test('不变量⑤：表内无重复项（重复只会白烧请求）', () => {
  const seen = new Set();
  const dups = [];
  for (const p of BOUNDARY_CANDIDATES) {
    if (seen.has(p)) dups.push(p);
    seen.add(p);
  }
  assert.deepEqual(dups, [], `候选表有重复项：${JSON.stringify(dups)}`);
});

test('不变量⑥：高频候选在前（空串/单引号族必须先于长尾，保证正常路径短路）', () => {
  // 顺序即探测顺序：常见场景靠前几个候选短路命中，长尾（LIKE 族/转义族）在后。
  // 这条不是审美——错序会让每个注入点多发若干无用探针（本仓对请求预算敏感）。
  assert.equal(BOUNDARY_CANDIDATES[0], '', '空串（无包裹）必须首位：多数注入点无需闭合前缀');
  assert.ok(
    BOUNDARY_CANDIDATES.indexOf("'") < BOUNDARY_CANDIDATES.indexOf("%'"),
    '单引号族应排在 LIKE 族之前（LIKE 属长尾）'
  );
});
