// ============================================================================
// server/tests/tamper.tokenBoundary.test.js
//
// 拦的是这一类缺陷：**运算符替换把操作数粘进关键词**，产出的不是"被绕过的 SQL"，
// 而是"比较整个消失了"。
//   equaltorlike 曾把 `id=1` 变成 `idRLIKE1` —— 三个 token 融成一个标识符，注入语义被摧毁；
//   而静态规则型 WAF 恰好不再匹配 `=` ⇒ 在绕过矩阵里记作"绕过成功"。
//   这是一类**最坏的假绕过**：它让一个废插件在测量报表里看起来有效。
// 兄弟件 equaltolike 在 [T4] 已修（替换串两侧补空格），本条把这类形态钉成判据。
//
// 判据形态：不检"输出里出现了什么词"（`NULLIF`/`LEAST(` 这类合法形态会误报），
//   只检"输入里的操作数在输出里是否还是独立 token" —— 粘连必然破坏操作数边界。
// 变异自证（改坏看是否真的红，别信"看起来会红"）：
//   · plugins/equaltorlike.js 替换串改回 'RLIKE'（去掉两侧空格）⇒ ① 红（id 被粘）；
//   · plugins/between.js 的 ` NOT BETWEEN 0 AND ` 改成 'NOT BETWEEN 0 AND' ⇒ ① 红；
//   · plugins/least.js 去掉 > 分支 ⇒ ④ 红。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import '../src/core/tamper/applyTampers.js'; // 导入即注册

/** 独立 token 判据：两侧不得紧邻标识符字符 */
const standalone = (tok, s) => new RegExp(`(?<![A-Za-z0-9_])${tok.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9_])`).test(s);

// 输入 → 必须在输出里仍为独立 token 的操作数
const CASES = [
  { input: 'id=1', operands: ['id', '1'] },
  { input: '1=1', operands: ['1'] },
  { input: '1 AND 2>1', operands: ['2', '1'] },
  { input: '1 AND A = B--', operands: ['A', 'B'] },
  { input: 'SELECT * FROM users WHERE id=1', operands: ['id', '1', 'users'] },
  { input: 'IFNULL(1, 2)', operands: ['1', '2'] },
  { input: "1 AND '1'='1", operands: ['1'] },
  { input: 'a<1', operands: ['a', '1'] },
];

const OPERATOR_TAMPERS = [
  'equaltolike', 'equaltorlike', 'between', 'least', 'greatest',
  'ifnull2ifisnull', 'ifnull2casewhenisnull', 'if2case', 'symboliclogical', 'concat2concatws',
];

test('① 运算符替换型 tamper：改写后操作数必须仍是独立 token（不许粘连）', () => {
  const failures = [];
  for (const name of OPERATOR_TAMPERS) {
    const p = tamperRegistry.get(name);
    assert.ok(p, `插件 ${name} 未注册`);
    for (const { input, operands } of CASES) {
      let out;
      try { out = String(p.transform(input, {})); } catch (e) { failures.push(`${name}(${input}) 抛错 ${e.message}`); continue; }
      if (out === input) continue; // 未改写 ⇒ 无新 token，不参与本判据
      for (const tok of operands) {
        if (!standalone(tok, out)) failures.push(`${name}: ${JSON.stringify(input)} → ${JSON.stringify(out)} ｜ 操作数 ${tok} 被粘进相邻 token`);
      }
    }
  }
  assert.deepEqual(failures, [], `token 粘连 ${failures.length} 条：\n${failures.join('\n')}`);
});

test('② 反向对照：粘连形态必须被本判据判红（防恒真判据）', () => {
  const broken = (p) => p.replace(/=/g, 'RLIKE'); // equaltorlike 的历史形态
  assert.equal(broken('id=1'), 'idRLIKE1');
  assert.equal(standalone('id', broken('id=1')), false, '坏形态必须被抓住');
  assert.equal(standalone('id', 'id RLIKE 1'), true, '修好的形态必须放行');
});

test('③ 真实缺陷回归：equaltorlike 不再产出 idRLIKE1（与兄弟件 equaltolike 同口径）', () => {
  const p = tamperRegistry.get('equaltorlike');
  assert.equal(p.transform('id=1'), 'id RLIKE 1');
  assert.equal(p.transform('SELECT * FROM users WHERE id=1'), 'SELECT * FROM users WHERE id RLIKE 1'); // 上游官方 doctest
  assert.equal(p.transform('a>=1'), 'a>=1');
  assert.equal(p.transform('a!=1'), 'a!=1');
});

test('④ 真实缺口回归：between 覆盖 = 分支、least 覆盖 > 分支（上游有、本仓此前没有）', () => {
  const b = tamperRegistry.get('between');
  assert.equal(b.transform('1 AND A = B--'), '1 AND A BETWEEN B AND B--');
  assert.equal(b.transform('1 AND A > B--'), '1 AND A NOT BETWEEN 0 AND B--');
  assert.ok(!/  /.test(b.transform('1 AND A > B--')), '> 两侧空白应被消费，不叠出双空格');
  const l = tamperRegistry.get('least');
  assert.equal(l.transform('1 AND A > B'), '1 AND LEAST(A,B+1)=B+1');
  assert.equal(l.transform('a<1'), 'LEAST(a,1-1)=a'); // 本仓既有分支不回退
});

test('⑤ informationschemacomment 保留原大小写（Oracle/PG 的引用标识符区分大小写）', () => {
  const p = tamperRegistry.get('informationschemacomment');
  assert.equal(p.transform('SELECT table_name FROM INFORMATION_SCHEMA.TABLES'), 'SELECT table_name FROM INFORMATION_SCHEMA/**/.TABLES');
  assert.equal(p.transform('select 1 from information_schema.tables'), 'select 1 from information_schema/**/.tables');
});
