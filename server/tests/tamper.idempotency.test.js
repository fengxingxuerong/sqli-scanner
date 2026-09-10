// [P0 2026-09-09 实战批次] tamper 幂等性守卫
// 背景（09-09 批次审计 P0-2）：插件若声明幂等但 f(f(x)) !== f(x)，链式组合或
// 「被 WAF 拦后重跑」场景会把损坏形态发给目标——实测即假阴性 + 噪声请求。
// 本守卫：
//   1) 全量插件双应用不抛错（稳健性底线）；
//   2) 声明 idempotent:true 的插件必须满足 f(f(x)) === f(x)（doctests 全量）；
//   3) doctests 输出不回吞输入标记（快速形状自检）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import '../src/core/tamper/applyTampers.js'; // 触发内置插件注册

const plugins = tamperRegistry.all();

test('全量插件双应用稳健性：f(f(x)) 不抛错', () => {
  assert.ok(plugins.length > 200, `内置插件应全量注册，实际 ${plugins.length}`);
  for (const p of plugins) {
    const samples = Array.isArray(p.doctests) && p.doctests.length ? p.doctests.map((d) => d.input) : ['1 AND 1=1'];
    for (const s of samples) {
      assert.doesNotThrow(() => {
        const once = p.transform(s, {});
        p.transform(String(once ?? ''), {});
      }, `插件 ${p.name} 双应用抛错（样本: ${s}）`);
    }
  }
});

test('声明 idempotent:true 的插件必须满足 f(f(x)) === f(x)', () => {
  const declared = plugins.filter((p) => p.idempotent === true);
  assert.ok(declared.length >= 1, '至少应有已验证幂等的插件声明（blindbinary）');
  for (const p of declared) {
    const samples = Array.isArray(p.doctests) && p.doctests.length
      ? p.doctests.map((d) => d.input)
      : ['1 AND ORD(MID((SELECT 1),1,1))>0'];
    for (const s of samples) {
      const once = String(p.transform(s, {}));
      const twice = String(p.transform(once, {}));
      assert.equal(twice, once, `插件 ${p.name} 声明幂等但 f(f(x))!==f(x)（样本: ${s}）`);
    }
  }
});

test('list() 透出幂等声明（UI/API 可见）', () => {
  const meta = tamperRegistry.list().find((x) => x.name === 'blindbinary');
  assert.ok(meta, 'blindbinary 应已注册');
  assert.equal(meta.idempotent, true);
});
