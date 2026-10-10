// ============================================================================
// tests/requestScript.guard.test.js —— requestScript 入口形状校验的空值语义
//
// 来历（D35 由 e2e/api-range-lab 实测抓到，不是推演）：D32 把这条键写成
//   "非空字符串，否则 1003"，而 `defaults.requestScript = ''` —— **关闭态本身就是空串**。
//   平时看不出来：单目标扫描不会把空串再喂回入口。但「单点重测」这类接口会把
//   **整份基线配置原样回放**进 /scan/start，于是每一次重测都在启动阶段就被拒：
//   retest 启动失败：{"code":1003,"message":"requestScript 须为非空脚本路径…"}
//   —— api-range-lab 从 49/49 掉到 48/49 才把它暴露出来。
//
// 这条缺陷的形状与本仓反复出现的那一类同源：**默认值与入口校验互相不认**。
// 所以本文件的重点不是"合法路径能透传"（passthrough 守卫已覆盖），而是
// 「**回放默认配置必须通过**」—— 那才是真正炸掉的路径。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defaults } from '../src/config/defaults.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const URL0 = 'http://example.com/?id=1';
const start = (config) => sanitizeStart({ url: URL0, config });

test('空串是「未启用」而不是非法：不抛错，且产出的 config 里没有这个键', () => {
  for (const blank of ['', '   ', '\t\n']) {
    const out = start({ requestScript: blank });
    assert.ok(
      out.config.requestScript === undefined || out.config.requestScript === '',
      `空白串被落成了生效值：${JSON.stringify(out.config.requestScript)}`,
    );
  }
});

test('⭐ 回放整份默认配置必须通过（api-range-lab「单点重测」炸的就是这条路径）', () => {
  // 真实形态：重测接口拿基线报告里的 target.config（由 defaults 展开而来）整份回放。
  // 这里不手写 ''，而是**从 defaults 取**，这样以后有人改默认值为非空串时本用例会说话。
  assert.equal(typeof defaults.requestScript, 'string', '默认值形态变了，需同步入口空值语义');
  const replayed = start({ ...structuredClone(defaults), requestScript: defaults.requestScript });
  assert.ok(replayed, '默认配置回放被入口拒了 ⇒ 重测/续跑这类"配置回放"路径全废');
  assert.equal(replayed.config.requestScript, undefined);
});

test('合法路径：透传且 trim（不 trim 会把带空格的路径交给加载层，报错文案里看不出是空格问题）', () => {
  assert.equal(start({ requestScript: '/opt/signers/sign.mjs' }).config.requestScript, '/opt/signers/sign.mjs');
  assert.equal(start({ requestScript: '  D:\\signers\\a.mjs  ' }).config.requestScript, 'D:\\signers\\a.mjs');
});

test('非字符串与超长 ⇒ 明确拒绝（收了不生效比报错难查得多）', () => {
  for (const bad of [123, {}, [], true]) {
    assert.throws(() => start({ requestScript: bad }), /requestScript/, `收到 ${JSON.stringify(bad)} 却放行`);
  }
  assert.throws(() => start({ requestScript: `/${'a'.repeat(1100)}` }), /过长/);
});

test('undefined / null ⇒ 视为未设置（不得落键，也不得抛）', () => {
  assert.equal(start({ requestScript: undefined }).config.requestScript, undefined);
  assert.equal(start({ requestScript: null }).config.requestScript, undefined);
});
