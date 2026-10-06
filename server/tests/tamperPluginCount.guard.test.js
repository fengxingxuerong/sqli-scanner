// ============================================================================
// tests/tamperPluginCount.guard.test.js —— 插件总数与注册完整性
//
// ── 发现的缺陷（失实文档）────────────────────────────────────────────────────
// applyTampers.js 的注释里有一条逐版追加的"内置总数"演进链：
//   28→62  62→76  76→88  90→102  102→114  …  186→200
// 末端声称 **200**，而运行时实际注册 **229** 个（已用 tamperRegistry.list() 实测）。
//
// 更麻烦的是**这份注释出现了两份**：
//   第一份在 import 块（第 37–206 行），走 76→88
//   第二份在 registerMany 列表（第 342–461 行），直接从 76→90，**没有 76→88 这一环**
// 即：同一个注册列表被割成两块，两块各自维护一份已经失真的总数。
// 于是"这个项目有多少个内置插件"从注释里**根本读不出来** —— 两处都不是 229，
// 而且互相矛盾。新增插件的人也无从知道该改哪一处。
//
// ── 为什么不用"把注释数字改对"了事 ──────────────────────────────────────────
// 那只是把一个装饰性断言暂时对齐。真正的病根是**总数被写在 24 个地方、没有任何东西
// 校验它**：下次有人加插件，数字照样漂移。本仓反复吃亏于此（keyword2hexall 的
// "覆盖全部关键字"、swapcase 的"大小写混淆"），故改成由测试钉死运行时真值。
//
// ── 三条断言各自的作用 ──────────────────────────────────────────────────────
//  ① 每个 plugins/*.js 都已注册 —— 挡住"文件写了但没 import/run"的假能力
//  ② 注册项与目录文件**一一对应**（双向）—— 挡住 import 了却漏注册、以及目录空文件
//  ③ 自证：判据本身有效 —— 否则守卫只是装饰品
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import '../src/core/tamper/applyTampers.js';   // 副作用：注册内置插件

const PLUGIN_DIR = new URL('../src/core/tamper/plugins/', import.meta.url);
const dirFiles = readdirSync(PLUGIN_DIR).filter((f) => f.endsWith('.js'))
  .map((f) => f.replace(/\.js$/, ''));

test('① plugins/ 目录里的每个文件都出现在运行时注册表里', () => {
  // 方向一：文件 → 注册。漏掉就是"能写不能用"，对扫描器等于能力缺失。
  const registered = new Set(tamperRegistry.list().map((p) => p.name));
  const missing = dirFiles.filter((n) => !registered.has(n));
  assert.deepEqual(missing, [],
    `以下插件文件存在但未注册到 tamperRegistry（能写不能用 = 能力缺失）：\n  ${missing.join('\n  ')}`);
});

test('② 注册表与目录一一对应（反向：注册了但目录里没文件 = 引用错路径）', () => {
  const dir = new Set(dirFiles);
  const extra = tamperRegistry.list().map((p) => p.name).filter((n) => !dir.has(n));
  assert.deepEqual(extra, [],
    `以下已注册的插件在 plugins/ 目录里找不到同名文件（import 路径写错？）：\n  ${extra.join('\n  ')}`);
});

test('③ 插件总数一致（目录 = 注册表）', () => {
  // 注释里"内置总数 200"已失实（实际 229）。这里不重复断言一个硬编码数字 ——
  // 那样下一次加插件又会红，而是断言两个**真源**彼此相等。
  // 数字本身由 tests/tamperPluginCount.snapshot.test.js 之类的快照承担（可选）。
  assert.equal(tamperRegistry.list().length, dirFiles.length,
    `运行时注册 ${tamperRegistry.list().length} 个，目录里有 ${dirFiles.length} 个文件`);
});

test('④ 原始插件对象都实现了 transform（用 all()，不是 list()）', () => {
  // ⚠️ 初版误用 list()，导致 229 个全红 —— list() 按设计**只返回元信息**
  //   （TamperRegistry.js:50 "不含 transform，便于序列化展示"），
  //   拿它断言 transform 必然全挂。这是"判据比被测对象更笨"的又一次实例，
  //   只不过方向相反：这次是判据要求了 API 根本不存在的东西。
  // 正确做法：list() 校验元信息完整性，all() 校验可执行性。
  const bad = tamperRegistry.all()
    .filter((p) => !p || typeof p.transform !== 'function' || typeof p.name !== 'string' || !p.name);
  assert.deepEqual(bad.map((p) => p && p.name), [], '存在缺少 name/transform 的原始插件对象');

  // list() 的元信息完整性（元信息是 REST 展示层的输入，缺字段会让界面空行）
  const badMeta = tamperRegistry.list()
    .filter((p) => typeof p.name !== 'string' || !p.name || typeof p.description !== 'string');
  assert.deepEqual(badMeta.map((p) => p && p.name), [], 'list() 元信息缺 name/description');
});

test('自证-5) 判据本身有效（dirFiles 非空且与运行时确实有交集）', () => {
  // 若 readdirSync 路径写错返回空数组，上面 ①② 会**恒绿**（空集没有反例）。
  // 这是本会话多次踩到的坑：判据过弱 ⇒ 假绿 ⇒ 守卫形同虚设。
  assert.ok(dirFiles.length > 100, `plugins/ 应有上百个插件，实读 ${dirFiles.length} —— 路径可能写错`);
  assert.ok(tamperRegistry.list().length > 100, `注册表应非空，实读 ${tamperRegistry.list().length}`);
  assert.ok(dirFiles.includes('rot13'), '已知插件 rot13 应在目录里 —— 若不在说明读错了目录');
});

test('诊断-6) 记录当前真值，便于发现异常漂移（非断言，仅信息）', () => {
  const src = readFileSync(new URL('../src/core/tamper/applyTampers.js', import.meta.url), 'utf8');
  const claims = [...src.matchAll(/内置总数\s*(\d+)\s*→\s*(\d+)/g)].map((m) => +m[2]);
  const actual = tamperRegistry.list().length;
  // 不断言，但把失真暴露出来：注释里的最大"末端总数"应等于实际值。
  // 当前实测 claims 最大 200 ≠ actual 229 —— 这是已知失实文档，
  // 已由本次提交在注释里加注说明，不再靠数字对齐（数字会再次漂移）。
  console.log(`  [诊断] 注释声称的末端总数：${claims.length ? Math.max(...claims) : '(无)'}；实际注册：${actual}；断言条数：${claims.length}`);
  assert.ok(claims.length > 0 || actual > 0, '诊断信息本身可计算');
});
