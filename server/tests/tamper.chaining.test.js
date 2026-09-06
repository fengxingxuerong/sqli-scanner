// applyTampers 链式执行测试：验证 tamper 插件按序串联、前后传递
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyTampers, obfuscateWithConfig } from '../src/core/tamper/applyTampers.js';
import '../src/core/tamper/applyTampers.js'; // 触发内置插件注册

test('applyTampers: 空插件列表返回原样', () => {
  assert.equal(applyTampers("SELECT 1 FROM dual", {}, []), "SELECT 1 FROM dual");
  assert.equal(applyTampers("' OR 1=1-- -", {}, []), "' OR 1=1-- -");
});

test('applyTampers: 空字符串 payload', () => {
  assert.equal(applyTampers('', {}, ['space2comment']), '');
});

test('applyTampers: 单插件', () => {
  const out = applyTampers('a AND b', {}, ['space2plus']);
  assert.equal(out, 'a+AND+b');
});

test('applyTampers: 双插件链式(a→b) 输出为下一个输入', () => {
  // space2plus: 'a AND b' → 'a+AND+b'
  // randomcase 把 'a+AND+b' 随机化——验证输出被传递
  // 注意：randomcase 随机化，结果每次不同，但不应包含空格（space2plus 已转 +）
  const out = applyTampers('a AND b', {}, ['space2plus', 'randomcase']);
  assert.ok(!out.includes(' '), '空格已被 space2plus 转 +，randomcase 不应还原');
  assert.ok(out.includes('+'), 'space2plus 的 + 应保留');
});

test('applyTampers: 三插件链式', () => {
  // space2comment: 'SELECT 1' → 'SELECT/**/1'
  // multiplespaces: 'SELECT/**/1' → 关键字后追加空格 → 'SELECT  /**/1'
  // randomcase: 'SELECT  /**/1' → 随机化大小写
  const out = applyTampers('SELECT 1', {}, ['space2comment', 'multiplespaces', 'randomcase']);
  assert.ok(out.includes('/**/'), 'space2comment 注释保留');
  assert.ok(out.length > 'SELECT 1'.length, '经过多重转换变长');
});

test('applyTampers: ctx 透传给插件', () => {
  // 某些插件读 ctx 上下文（如 xforwardedfor 读 ctx.target）
  // space2comment 不依赖 ctx，但验证不会抛
  const ctx = { target: { baseUrl: 'http://x' }, point: { id: 'p1' }, dbms: 'MySQL' };
  assert.doesNotThrow(() => applyTampers("' UNION SELECT 1-- -", ctx, ['space2comment']));
});

test('applyTampers: 未知插件名被忽略（resolve 跳过未注册名）', () => {
  // tamperRegistry.resolve 会跳过未注册名
  const out = applyTampers('a AND b', {}, ['space2plus', 'nonexistent_plugin', 'randomcase']);
  assert.ok(out.includes('+'), 'space2plus 生效');
  // randomcase 也生效，说明 nonexistent_plugin 被跳过
  assert.ok(out.toUpperCase() !== out.toLowerCase(), 'randomcase 应改变大小写');
});

test('obfuscateWithConfig: tamper.enabled=false 时不走 chain', () => {
  const ctx = { config: { wafEvasion: { tamper: { enabled: false } } } };
  assert.equal(obfuscateWithConfig("' OR 1=1-- -", ctx), "' OR 1=1-- -");
});

test('obfuscateWithConfig: tamper 缺省时不走 chain', () => {
  assert.equal(obfuscateWithConfig("' OR 1=1-- -", {}), "' OR 1=1-- -");
});

test('obfuscateWithConfig: tamper.enabled=true 走 chain', () => {
  const ctx = { config: { wafEvasion: { tamper: { enabled: true, plugins: ['space2plus'] } } } };
  const out = obfuscateWithConfig('a AND b', ctx);
  assert.equal(out, 'a+AND+b');
});

test('obfuscateWithConfig: legacy obfuscate=true 走旧路径', () => {
  const ctx = { config: { wafEvasion: { obfuscate: true } } };
  const out = obfuscateWithConfig("' OR 1=1-- -", ctx);
  // obfuscatePayload 加内联注释但不改变语义
  assert.ok(out.includes('OR'), 'OR 关键字保留');
  assert.ok(out.includes('1=1'), '数字表达式保留');
});

test('obfuscateWithConfig: tamper 优先于 legacy obfuscate', () => {
  const ctx = {
    config: {
      wafEvasion: {
        tamper: { enabled: true, plugins: ['space2plus'] },
        obfuscate: true, // 应被忽略
      },
    },
  };
  const out = obfuscateWithConfig('a AND b', ctx);
  assert.equal(out, 'a+AND+b', 'tamper 路径应优先于 legacy obfuscate');
});