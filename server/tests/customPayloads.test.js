// ==================== tests/customPayloads.test.js —— 用户自定义检测条目 ====================
// 覆盖三条硬约束（见 customPayloads.js 文件头）：只追加不覆盖 / 同样受高危池硬门管辖 /
// 校验失败硬失败。外加「默认零变化」这条最要紧的不变式 —— 不传 --payload-file 时，
// 注册表必须是**同一个数组引用**，指纹测试与 facts 数字才不会漂。
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  validateCustomEntries,
  mergeCustomEntries,
  CUSTOM_REQUIRED_FIELDS,
} from '../src/engine/payloads/customPayloads.js';
import {
  PAYLOAD_REGISTRY,
  selectPayloads,
  countDestructiveCandidates,
  runWithCustomPayloads,
  isDestructivePayload,
} from '../src/engine/payloadRegistry.js';
import { DESTRUCTIVE_PAYLOADS } from '../src/engine/payloads/destructive.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads/index.js';

const okEntry = (over = {}) => ({
  id: 'custom-test-1',
  dbms: ['MySQL'],
  technique: 'boolean',
  template: '{ORIG} AND 1=1',
  falseTemplate: '{ORIG} AND 1=2',
  ...over,
});

describe('validateCustomEntries —— 校验与规范化', () => {
  test('① 顶层非数组 ⇒ 报错', () => {
    const { entries, errors } = validateCustomEntries({ entries: [] });
    assert.equal(entries.length, 0);
    assert.match(errors[0], /顶层必须是数组/);
  });

  test('② 缺必填字段 ⇒ 逐字段点名', () => {
    for (const f of CUSTOM_REQUIRED_FIELDS) {
      const bad = okEntry();
      delete bad[f];
      const { errors } = validateCustomEntries([bad]);
      assert.equal(errors.length, 1, `删掉 ${f} 应恰好报 1 条`);
      assert.match(errors[0], new RegExp(`缺必填字段 ${f}`));
    }
  });

  test('③ technique 越界 ⇒ 报出合法取值', () => {
    const { errors } = validateCustomEntries([okEntry({ technique: 'nosqlmagic' })]);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /technique 必须是/);
    // 合法值来自 TECHNIQUE_TYPES（单源，不手抄）
    for (const t of TECHNIQUE_TYPES) {
      assert.equal(validateCustomEntries([okEntry({ id: `x-${t}`, technique: t })]).errors.length, 0);
    }
  });

  test('④ 文件内 id 重复 ⇒ 拒收（防止后一条静默吞掉前一条）', () => {
    const { entries, errors } = validateCustomEntries([okEntry(), okEntry()]);
    assert.equal(entries.length, 1);
    assert.match(errors[0], /id 重复 custom-test-1/);
  });

  test('⑤ where 非法 ⇒ 报出合法取值', () => {
    const { errors } = validateCustomEntries([okEntry({ where: 'anywhere' })]);
    assert.match(errors[0], /where 必须是 value\/position/);
  });

  test('⑥ 缺 level/risk ⇒ 按最低档补全，不是"不过滤"', () => {
    const { entries, errors } = validateCustomEntries([okEntry({ level: undefined, risk: undefined })]);
    assert.equal(errors.length, 0);
    assert.equal(entries[0].level, 1);
    assert.equal(entries[0].risk, 1);
    assert.deepEqual(entries[0].clause, []);
    assert.deepEqual(entries[0].boundary, []);
    assert.equal(entries[0].where, 'value');
    assert.equal(entries[0].custom, true);
  });
});

describe('mergeCustomEntries —— 追加语义', () => {
  test('⑦ 空数组 ⇒ 返回**同一个引用**（默认路径零变化的最硬钉子）', () => {
    assert.equal(mergeCustomEntries(PAYLOAD_REGISTRY, []), PAYLOAD_REGISTRY);
    assert.equal(mergeCustomEntries(PAYLOAD_REGISTRY, null), PAYLOAD_REGISTRY);
  });

  test('⑧ 追加而非替换：内置条目一条不少', () => {
    const { entries } = validateCustomEntries([okEntry()]);
    const merged = mergeCustomEntries(PAYLOAD_REGISTRY, entries);
    assert.equal(merged.length, PAYLOAD_REGISTRY.length + 1);
    assert.equal(merged[merged.length - 1].id, 'custom-test-1');
    // 内置数组本身不被改动
    assert.equal(PAYLOAD_REGISTRY.length, merged.length - 1);
  });

  test('⑨ id 与内置冲突 ⇒ 抛错拒绝（不允许覆盖内置条目）', () => {
    const clash = okEntry({ id: PAYLOAD_REGISTRY[0].id });
    const { entries } = validateCustomEntries([clash]);
    assert.throws(() => mergeCustomEntries(PAYLOAD_REGISTRY, entries), /不允许覆盖内置/);
  });
});

describe('安全口径 —— 自定义条目同样受高危池硬门管辖', () => {
  test('⑩ 模板命中 destructive 池 ⇒ isDestructivePayload 为真（判定按模板串，不靠 id 命名）', () => {
    const evil = Object.values(DESTRUCTIVE_PAYLOADS).flatMap((byTech) => Object.values(byTech).flat())[0];
    assert.ok(typeof evil === 'string' && evil.length > 0);
    // 故意不给 id 加 -dest- 标记：证明判定不靠命名
    const { entries } = validateCustomEntries([okEntry({ id: 'innocent-looking', template: evil })]);
    assert.equal(isDestructivePayload(entries[0]), true);
  });

  test('⑪ 高危自定义条目在 productionMode 未确认时不投放，且计入 countDestructiveCandidates', () => {
    const evil = Object.values(DESTRUCTIVE_PAYLOADS).flatMap((byTech) => Object.values(byTech).flat())[0];
    const { entries } = validateCustomEntries([
      okEntry({ id: 'custom-dest-1', dbms: ['MySQL'], technique: 'boolean', template: evil, level: 1, risk: 1 }),
    ]);
    runWithCustomPayloads(entries, () => {
      const picked = selectPayloads({ dbms: 'MySQL', technique: 'boolean', level: 1, risk: 1, productionMode: true });
      assert.equal(picked.some((p) => p.id === 'custom-dest-1'), false, '未确认高危 ⇒ 不得投放');
      const allowed = selectPayloads({
        dbms: 'MySQL', technique: 'boolean', level: 1, risk: 1, productionMode: true, confirmDestructive: true,
      });
      assert.equal(allowed.some((p) => p.id === 'custom-dest-1'), true, '已确认 ⇒ 投放');
      assert.ok(countDestructiveCandidates({ level: 1, risk: 1 }) >= 1);
    });
  });
});

// ==================== 接线守卫 ====================
// 为什么单独钉：本仓吃过「解析了参数但没人消费」「函数写了但没接进主链」的亏（同类守卫见
// modsecLive.wiring.test.js ⑯）。扩展点是新能力，最容易死在最后一米 —— CLI 帮助里写了、
// 参数解析了，但 runSingleScan 没包裹 ⇒ 用户传了文件却毫无效果。
// ⚠️ 判据文本源必须**先剥单行注释、后剥块注释**（顺序反了会把注释里的示例当成真接线，
// 本仓已栽四次），且断言绑到**调用形态**而不只是名字出现。
describe('接线守卫 —— CLI 参数必须真接到扫描主链', () => {
  const readSrc = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
  const stripComments = (s) => s.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

  test('⑭ args.js 真解析 --payload-file', () => {
    const src = stripComments(readSrc('../bin/cli/args.js'));
    assert.ok(src.length > 1000, '分母守卫：源码不该是空的');
    assert.match(src, /'--payload-file'/, 'args.js 必须解析 --payload-file');
  });

  test('⑮ cli.js 真加载并真注入（绑调用形态，不是绑 import 名）', () => {
    const src = stripComments(readSrc('../bin/cli.js'));
    assert.ok(src.length > 1000, '分母守卫：源码不该是空的');
    assert.match(src, /validateCustomEntries\(/, '必须调用校验');
    assert.match(src, /mergeCustomEntries\(/, '必须做冲突检查');
    assert.match(src, /runWithCustomPayloads\(/, '必须把条目注入扫描上下文');
  });

  test('⑯ payloadRegistry 的筛选入口真走 activeRegistry', () => {
    const src = stripComments(readSrc('../src/engine/payloadRegistry.js'));
    assert.match(src, /activeRegistry\(\)\.filter\(/, 'selectPayloads 必须消费生效注册表');
    assert.match(src, /of activeRegistry\(\)/, 'countDestructiveCandidates 必须同源');
  });
});

describe('作用域 —— 只在本次扫描可见，默认路径逐位零变化', () => {
  test('⑫ 上下文内可见自定义条目；出了上下文立刻不可见', () => {
    const { entries } = validateCustomEntries([okEntry({ dbms: ['MySQL'], technique: 'boolean' })]);
    runWithCustomPayloads(entries, () => {
      const picked = selectPayloads({ dbms: 'MySQL', technique: 'boolean', level: 1, risk: 1 });
      assert.equal(picked.some((p) => p.id === 'custom-test-1'), true);
    });
    const after = selectPayloads({ dbms: 'MySQL', technique: 'boolean', level: 1, risk: 1 });
    assert.equal(after.some((p) => p.id === 'custom-test-1'), false);
  });

  test('⑬ 不注入时 selectPayloads 结果与内置基线完全一致（同一引用语义）', () => {
    const baseline = selectPayloads({ dbms: 'MySQL', technique: 'boolean', level: 1, risk: 1 });
    runWithCustomPayloads([], () => {
      const inside = selectPayloads({ dbms: 'MySQL', technique: 'boolean', level: 1, risk: 1 });
      assert.deepEqual(inside.map((p) => p.id), baseline.map((p) => p.id));
    });
  });
});
