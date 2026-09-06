// tamper.doctest.test.js —— 插件语义契约快照回归
// ============================================================================
// 背景：tamper 插件层曾出现「语义漂移被绕过率掩盖」的系统性问题（equaltolike
// 产出 idLIKE1 非法 SQL、between 破坏 >= 语义等），且绕过率矩阵不做 SQL 语义校验，
// 只靠逻辑零散断言无法根治。
//
// 本测试建立「doctest」机制：插件对象可声明 doctests: [{ input, output?|match? }]，
// 断言插件 transform 的确定性语义契约（对齐 sqlmap 官方脚本 docstring 示例的思路）：
//   - output：精确等于
//   - match：正则匹配（用于随机类插件，如 space2dash 的随机 hex）
// 任何插件改动若违反各自声明的契约，本测试即失败 —— 从源头阻断漂移。
//
// 新增插件约定：带确定性语义的插件请在对象上声明 doctests；随机/依赖 ctx 的
// 插件可只提供 match 形式或省略（filter 只执行声明了 doctests 的插件）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
// 导入即触发内置插件注册（applyTampers.js 内部 registerMany）
import '../src/core/tamper/applyTampers.js';

test('tamper doctest：所有声明契约的插件通过（防语义漂移）', async () => {
  const plugins = tamperRegistry
    .all()
    .filter((p) => Array.isArray(p.doctests) && p.doctests.length);
  assert.ok(
    plugins.length >= 14,
    `当前 205 个插件中至少 14 个应带 doctests（本轮已加），实际 ${plugins.length}`
  );

  const failures = [];
  let total = 0;
  for (const p of plugins) {
    for (const [i, dt] of p.doctests.entries()) {
      total += 1;
      let out;
      try {
        out = String(p.transform(dt.input ?? ''));
      } catch (e) {
        failures.push(`${p.name}#${i} 抛异常: ${e.message}`);
        continue;
      }
      if (dt.output !== undefined) {
        if (out !== dt.output) {
          failures.push(
            `${p.name}#${i} 输出漂移: ${JSON.stringify(dt.input)} → ${JSON.stringify(out)}，期望 ${JSON.stringify(dt.output)}`
          );
        }
      } else if (dt.match) {
        if (!new RegExp(dt.match).test(out)) {
          failures.push(
            `${p.name}#${i} 未匹配: ${JSON.stringify(dt.input)} → ${JSON.stringify(out)}，正则 ${JSON.stringify(dt.match)}`
          );
        }
      } else {
        failures.push(`${p.name}#${i} doctest 缺少 output/match`);
      }
    }
  }

  assert.equal(
    failures.length,
    0,
    `doctest 契约违反 ${failures.length} 条（共执行 ${total} 条）：\n${failures.join('\n')}`
  );
});

// 注册表契约：带 doctests 的插件必须有 name 且可被 resolve（防注册表兜底跳过）
test('tamper doctest：带契约的插件均可在注册表中按名解析', () => {
  const withContract = tamperRegistry.all().filter((p) => Array.isArray(p.doctests) && p.doctests.length);
  for (const p of withContract) {
    const resolved = tamperRegistry.resolve([p.name]);
    assert.equal(resolved.length, 1, `插件 ${p.name} 应能按名解析`);
  }
});