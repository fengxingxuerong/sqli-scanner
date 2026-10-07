// server/tests/tamper.upstreamAlign.test.js
//
// [批次 D12 2026-10-07] 竞品吸收 T-1…T-10 里"本地可判"的那几条：
//   T-1 binary / T-2 bluecoat / T-3 charunicodeencode / T-5 concat2concatws /
//   T-7 htmlencode / T-8 ifnull2casewhenisnull / T-9 overlongutf8 / T-10 randomcomments
//
// 判据口径（与仓内既有纪律同源）：
//   ① **期望不自己写** —— 逐条从上游快照 `upstream-sqlmap-doctests.json` 取
//      （那份是 tag 1.10.10 的官方 docstring，外部出的卷子）；
//   ② **采集面下限** —— 目标插件必须在快照里真的有示例，否则"0 条要判"会让判据静默变绿；
//   ③ 除比对之外，每条再钉一条**结构性不变量**（能杀掉"照着期望硬编码"的实现）；
//   ④ 随机性插件走 `ctx.rng` 注入 ⇒ 确定性断言，不用 Math.random 碰运气。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import '../src/core/tamper/applyTampers.js'; // 触发内置插件注册

const HERE = dirname(fileURLToPath(import.meta.url));
const SNAPSHOT = JSON.parse(
  readFileSync(resolve(HERE, '../src/core/tamper/upstream-sqlmap-doctests.json'), 'utf8'),
);

/** 本批要求"与上游字面一致"的插件（charunicodeencode / randomcomments 为有意变体，不在内） */
const ALIGNED = ['binary', 'bluecoat', 'concat2concatws', 'htmlencode', 'ifnull2casewhenisnull', 'overlongutf8'];

function getPlugin(name) {
  const p = tamperRegistry.get(name);
  assert.ok(p, `插件 ${name} 应已注册`);
  return p;
}

// ── ① 采集面下限：快照里必须真的有这 6 个插件的示例 ────────────────────────────
test('① 采集面：上游快照必须覆盖本批 6 个插件（防判据空转）', () => {
  for (const name of ALIGNED) {
    const pairs = SNAPSHOT.perPlugin?.[name];
    assert.ok(Array.isArray(pairs) && pairs.length > 0,
      `上游快照里没有 ${name} 的示例 —— 判据会变成"0 条要判"的假绿，先检查 --refresh`);
  }
  assert.equal(SNAPSHOT.tag, '1.10.10', '快照 tag 应为 1.10.10');
});

// ── ② 逐条与上游官方示例字面比对（期望来自外部快照，不是本仓写的） ──────────────
test('② 本批 6 个插件与上游官方示例字面一致', () => {
  let checked = 0;
  for (const name of ALIGNED) {
    const p = getPlugin(name);
    for (const [idx, { input, output }] of SNAPSHOT.perPlugin[name].entries()) {
      const got = String(p.transform(input, {}));
      assert.equal(got, output,
        `${name}#${idx} 与上游不一致\n  输入: ${JSON.stringify(input)}\n  上游: ${JSON.stringify(output)}\n  本仓: ${JSON.stringify(got)}`);
      checked++;
    }
  }
  assert.ok(checked >= 9, `本批应比对至少 9 条上游示例，实际 ${checked}`);
});

// ── ③ T-7 htmlencode：幂等（旧实现把已编码实体的 & / ; 再编一次） ───────────────
test('③ htmlencode：f(f(x)) === f(x)，且声明 idempotent 由通用守卫复验', () => {
  const p = getPlugin('htmlencode');
  assert.equal(p.idempotent, true, 'htmlencode 应显式声明幂等（幂等守卫只管声明过的插件）');
  const samples = [
    "1' AND SLEEP(5)#",
    '1&#39;&#32;AND&#32;SLEEP&#40;5&#41;&#35;',
    "1 AND '1'='1",
    '__S__x__E__',
    'a b_c-d',
  ];
  for (const s of samples) {
    const once = String(p.transform(s, {}));
    const twice = String(p.transform(once, {}));
    assert.equal(twice, once, `htmlencode 非幂等：${JSON.stringify(s)} → ${JSON.stringify(once)} → ${JSON.stringify(twice)}`);
  }
  // ③b 结构性：编码集是 [^a-zA-Z0-9]（**刻意比上游的 [^\w] 多编一个 `_`**）——
  //     离线 12 类规则 A/B 实测：改成 [^\w] 后 information_schema 那一类绕过率
  //     100% → 0%（下划线留在明文里 ⇒ 整词规则直接命中）。标记安全不靠本件让路：
  //     `__S__` / `__E__` 由 applyTampers 的占位保护层在进链前换掉。
  assert.equal(p.transform('information_schema', {}), 'information&#95;schema');
  assert.equal(p.transform('a_b', {}), 'a&#95;b');
});

// ── ④ T-9 overlongutf8：产出必须是**合法**超长 UTF-8（旧实现是 %C0%27） ─────────
test('④ overlongutf8：两字节形态合法且可逆解回原码点', () => {
  const p = getPlugin('overlongutf8');
  assert.equal(p.transform("'", {}), '%C0%A7', '单引号的超长式是 %C0%A7，不是 %C0%27');
  assert.equal(p.transform('"', {}), '%C0%A2');
  assert.equal(p.transform(' ', {}), '%C0%A0');
  assert.equal(p.transform('>', {}), '%C0%BE');

  // 结构性不变量：每个产出的 %XX%YY 对，首字节在 C0–DF、次字节在 80–BF（续字节），
  // 且能按超长式解回原码点 —— 旧公式（把原码点直接接在 C0 后）在这里必红。
  const sample = "'\" >= (,)#";
  const out = String(p.transform(sample, {}));
  const pairs = [...out.matchAll(/%([0-9A-Fa-f]{2})%([0-9A-Fa-f]{2})/g)];
  assert.equal(pairs.length, sample.length, `每个非字母数字字符都应产出一对 %XX%YY，实际 ${pairs.length}/${sample.length}`);
  const decoded = pairs.map(([, hi, lo]) => {
    const b1 = parseInt(hi, 16);
    const b2 = parseInt(lo, 16);
    assert.ok(b1 >= 0xc0 && b1 <= 0xdf, `首字节 ${hi} 不在 C0–DF（不是两字节超长式的首字节）`);
    assert.ok(b2 >= 0x80 && b2 <= 0xbf, `次字节 ${lo} 不在 80–BF（不是续字节 ⇒ 非法 UTF-8）`);
    return ((b1 - 0xc0) << 6) | (b2 - 0x80);
  });
  assert.equal(decoded.join('|'), [...sample].map((c) => c.charCodeAt(0)).join('|'),
    '超长式必须能可逆解回原码点（编码公式错了就解不回去）');
});

// ── ⑤ T-5 concat2concatws：GROUP_CONCAT 不得被切开 ──────────────────────────────
test('⑤ concat2concatws：分隔符为 MID(CHAR(0),0,0) 且跳过 GROUP_CONCAT', () => {
  const p = getPlugin('concat2concatws');
  assert.equal(p.transform('CONCAT(1,2)', {}), 'CONCAT_WS(MID(CHAR(0),0,0),1,2)');
  // 切开即产出 MySQL 不存在的 GROUP_CONCAT_WS ⇒ 非法 SQL
  for (const s of ['GROUP_CONCAT(a)', 'group_concat(a)', 'GROUP_CONCAT(a SEPARATOR \',\')']) {
    assert.equal(p.transform(s, {}), s, `GROUP_CONCAT 形态不得被改写：${s}`);
  }
});

// ── ⑥ T-2 bluecoat：不得叠出双空白 ─────────────────────────────────────────────
test('⑥ bluecoat：%09 与空格永不相邻（双空白本身是规则特征）', () => {
  const p = getPlugin('bluecoat');
  const samples = [
    'SELECT id FROM users WHERE id = 1',
    '1 UNION ALL SELECT NULL, NULL, NULL WHERE id=1',
    'WHERE id >= 1 AND x <= 2 AND y != 3',
  ];
  for (const s of samples) {
    const out = String(p.transform(s, {}));
    assert.ok(!/%09[ \t]/.test(out), `出现 %09 紧跟空白（双空白）：${out}`);
    assert.ok(!/[ \t]{2}/.test(out), `出现连续空白：${out}`);
    assert.ok(!/[ \t]%09/.test(out), `出现空白紧跟 %09（双空白）：${out}`);
  }
  // 复合运算符不被拆坏（与 equaltolike 同锚点）
  assert.equal(p.transform('WHERE id>=1', {}), 'WHERE%09id>=1');
  assert.equal(p.transform('WHERE id = 1', {}), 'WHERE%09id LIKE 1');
});

// ── ⑦ T-1 binary：值前缀注入，且**不改写字符串字面量**（旧实现语义损失） ──────────
test('⑦ binary：注入 binary 关键字，但不得改写字面量取值', () => {
  const p = getPlugin('binary');
  assert.equal(p.transform('1 UNION ALL SELECT NULL, NULL, NULL', {}),
    '1 UNION ALL SELECT binary NULL, binary NULL, binary NULL');
  assert.equal(p.transform('1 AND 2>1', {}), '1 AND binary 2>binary 1');
  assert.equal(p.transform('CASE WHEN (1=1) THEN 1 ELSE 0x28 END', {}),
    'CASE WHEN (binary 1=binary 1) THEN binary 1 ELSE binary 0x28 END');
  // 语义不损失：字面量内容必须逐字符原样保留（旧实现会把 'admin' 换成另一个值 ⇒ 比较恒假）
  for (const s of ["1 AND 'admin'='admin'", '1 AND "a b"="a b"', "WHERE u='x' AND p='y'"]) {
    assert.equal(p.transform(s, {}), s, `binary 不得改写字符串字面量：${s}`);
  }
});

// ── ⑧ T-8 ifnull2casewhenisnull：分支括号 + 深度/引号感知 ────────────────────────
test('⑧ ifnull2casewhenisnull：分支加括号，嵌套与字面量内逗号不切错', () => {
  const p = getPlugin('ifnull2casewhenisnull');
  assert.equal(p.transform('IFNULL(1, 2)', {}), 'CASE WHEN ISNULL(1) THEN (2) ELSE (1) END');
  // 括号是这条的核心：分支为复合表达式时不加括号会被优先级吞掉
  assert.match(p.transform('IFNULL(a, b AND c)', {}), /THEN \(b AND c\) ELSE \(a\) END$/);
  // 深度感知：逗号取 depth==1 的那个（旧实现在第一个 ')' 就收尾 ⇒ 畸形 SQL）
  assert.equal(p.transform('IFNULL(IFNULL(a,b),c)', {}),
    'CASE WHEN ISNULL(CASE WHEN ISNULL(a) THEN (b) ELSE (a) END) THEN (c) ELSE (CASE WHEN ISNULL(a) THEN (b) ELSE (a) END) END');
  // 引号感知：字面量内的逗号不参与切分
  assert.equal(p.transform("IFNULL('a,b',c)", {}), "CASE WHEN ISNULL('a,b') THEN (c) ELSE ('a,b') END");
  // 不配对 ⇒ 放弃，绝不猜
  assert.equal(p.transform('IFNULL(a,b', {}), 'IFNULL(a,b');
});

// ── ⑨ T-3 charunicodeencode：十六进制大写（%u 按字面匹配 ⇒ 大小写是绕过面） ──────
test('⑨ charunicodeencode：%u 后跟大写十六进制', () => {
  const p = getPlugin('charunicodeencode');
  assert.equal(p.transform('L', {}), '%u004C');
  assert.equal(p.transform('abcd', {}), '%u0061%u0062%u0063%u0064');
  const hexes = [...String(p.transform('Select From Where', {})).matchAll(/%u([0-9A-Fa-f]{4})/g)]
    .map((m) => m[1]);
  assert.ok(hexes.length > 0);
  for (const h of hexes) {
    assert.equal(h, h.toUpperCase(), `十六进制应为大写，实际 ${h}`);
  }
  // 有意保留的护栏：已编码的 %XX 不被二次编码
  assert.equal(p.transform('a%20b', {}), '%u0061%20%u0062');
});

// ── ⑪ equaltolike / equaltorlike：字面量保护**试过并撤回**（留痕，勿再顺手加） ──
//    上一版给这两件加了"字面量内的 = 不替换"（比上游严），缺陷注入阶段被
//    `waf.bypassWiring.test.js` 3 条红拦下：注入 payload 自身带**未闭合的开引号**
//    （`1' AND '1'='1`），`splitByLiteral` 的成对假设会把 ` AND ` 当成字面量内容、
//    把真正的 `=` 吞进"字面量" ⇒ 变换整体失效（连正经的运算符都不换了）。
//    ⇒ 结论不是"没做"，而是**做了会更糟**，且有红灯为证。故维持上游口径。
test('⑪ equaltolike / equaltorlike：维持上游口径，字面量内的 = 仍被替换（有证撤回）', () => {
  const like = getPlugin('equaltolike');
  const rlike = getPlugin('equaltorlike');
  assert.equal(like.transform('SELECT * FROM users WHERE id=1', {}), 'SELECT * FROM users WHERE id LIKE 1');
  assert.equal(rlike.transform('SELECT * FROM users WHERE id=1', {}), 'SELECT * FROM users WHERE id RLIKE 1');
  // 注入形态（开引号未闭合）必须照常换 —— 这正是"加了字面量保护会坏"的场景
  assert.equal(like.transform("1' AND '1'='1", {}), "1' AND '1' LIKE '1");
  assert.equal(rlike.transform("1' AND '1'='1", {}), "1' AND '1' RLIKE '1");
  assert.equal(like.transform('a<=1', {}), 'a<=1');
  assert.equal(rlike.transform('a!=1', {}), 'a!=1');
});

// ── ⑩ T-10 randomcomments：词内拆分（ctx.rng 注入 ⇒ 确定性） ────────────────────
test('⑩ randomcomments：在关键字**词内**插 /**/（随机性走 ctx.rng）', () => {
  const p = getPlugin('randomcomments');
  const always = () => 0;      // rng() < 0.5 恒真 ⇒ 每个内部位置都插
  const never = () => 0.9;     // 恒假 ⇒ 走"至少切一刀"兜底
  // 与上游同一循环边界（内部位置 1..len-2），末字符前不插 ⇒ 末两字母恒相邻
  assert.equal(p.transform('INSERT', { rng: always }), 'I/**/N/**/S/**/E/**/RT');
  const fallback = String(p.transform('INSERT', { rng: never }));
  assert.ok(fallback.includes('/**/'), `兜底分支必须保证形态改变，实际 ${fallback}`);
  // 结构性：/**/ 必须落在词内（旧实现只在词后追加 ⇒ 结尾一定是 /**/）
  assert.ok(!/\/\*\*\/$/.test(fallback), `注释不能只在词尾（那是旧行为）：${fallback}`);
  assert.ok(/^[A-Za-z]/.test(fallback) && /[A-Za-z]$/.test(fallback),
    `词内拆分应保留首尾字母：${fallback}`);
  // 非关键字不受影响
  assert.equal(p.transform('foo bar', { rng: always }), 'foo bar');
});
