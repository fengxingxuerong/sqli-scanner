// ============================================================================
// server/tests/sqlmapParity.guard.test.js —— sqlmap 对标底账的守卫（[D197] 2026-10-30）
//
// 为什么必须有：底账这种东西的价值全在「它不会自己漂」。历史上本仓做过 5 轮 sqlmap 对标，
// 每一轮都是散文：分母手写、状态靠眼看、下一轮没人知道哪条已经闭环。本守卫把底账钉在
// 三件事上（缺一件它就退化成又一份散文）：
//   ① **产物即判据**：docs/_sqlmap-parity.json 与 docs/sqlmap-对标底账.md 必须逐字等于脚本重算结果；
//   ② **覆盖不许虚报**：底账里 `同名同义`/`等价异构`/`部分覆盖` 引用的旗标，必须真的在
//      server/bin/cli/args.js / cli.js 里存在（用与 readme-flag-coverage **同源**的口径独立取一次）；
//   ③ **缺口不许乐观漂**：`缺口` 项一旦被实现（同名旗标出现），本测试立刻红 —— 逼着改状态。
//
// 与本批（D197）的关系：本轮把五项 sqlmap 能力面接上 CLI（--http2 / --no-keep-alive /
// --null-connection / --drop-set-cookie / --list-tampers），其中前四项**引擎早就实现**、
// 只有 CLI 摸不到（「能力有 ≠ 装得上」）。本文件同时验证「接线真的通到了 config」
// 与「--list-tampers 列出的名字真的能用来挑链」——否则接线只是改了文档。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DOC_REL,
  INVENTORY,
  JSON_REL,
  NOTES,
  PLAN,
  SQLMAP_VERSION,
  STATUS,
  STATUS_LABEL,
  cliFlags,
  judgeParity,
  parseCode,
  renderJson,
  renderMarkdown,
} from '../../scripts/sqlmap-parity.mjs';
import { parseArgs } from '../bin/cli/args.js';
import { buildConfig } from '../bin/cli/config.js';
import { buildEgressOpts } from '../src/engine/egressOpts.js';
import { tamperCatalogLines } from '../bin/cli/tamperCatalog.js';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const readRepo = (rel) => readFileSync(join(REPO, rel), 'utf8');

/** 独立取一次旗标（不复用底账里的 flags 入参）：口径与 readme-flag-coverage 同源 + 入口拦截 + 表驱动。 */
function sourceFlags() {
  const argsSrc = readRepo('server/bin/cli/args.js');
  const cliSrc = readRepo('server/bin/cli.js');
  return new Set(cliFlags(argsSrc, cliSrc));
}

test('① 产物即判据：JSON 与 Markdown 必须逐字等于脚本重算结果', () => {
  assert.equal(readRepo(JSON_REL), renderJson(), `${JSON_REL} 与脚本产出不一致（手改或忘了跑 --write）`);
  assert.equal(readRepo(DOC_REL), renderMarkdown(), `${DOC_REL} 与脚本产出不一致（手改或忘了跑 --write）`);
});

test('② 覆盖不许虚报：被判「有落点」的旗标必须在 CLI 源码里真实存在', () => {
  const flags = sourceFlags();
  const bad = [];
  for (const [opt, code] of Object.entries(STATUS)) {
    const p = parseCode(code);
    if (p.kind === 'ok' && !flags.has(opt)) bad.push(`${opt} 记同名同义，但源码里没有`);
    if ((p.kind === 'alias' || p.kind === 'part') && !flags.has(p.flag)) bad.push(`${opt} 记为 ${p.flag} 覆盖，但源码里没有 ${p.flag}`);
  }
  assert.deepEqual(bad, [], `底账虚报覆盖：\n  ${bad.join('\n  ')}`);
});

test('③ 缺口不许乐观漂：被判「缺口」的项不得已在本方 CLI 里实现', () => {
  const flags = sourceFlags();
  const stale = Object.entries(STATUS)
    .filter(([, code]) => parseCode(code).kind === 'gap')
    .map(([opt]) => opt)
    .filter((opt) => flags.has(opt));
  assert.deepEqual(stale, [], `以下项已实现却仍记「缺口」（底账只许朝事实方向改）：${stale.join('、')}`);
});

test('④ 判据自身有牙（四个反例）：并把真实底账跑一遍', () => {
  const inv = [{ group: 'g', opts: ['--a', '--b', '--c', '--d', '--e'] }];
  // 刻意不给 `--e` 状态：它同时充当「未分类」反例的样本（其余反例也会带上这条噪声，不影响断言）
  const legal = { '--a': 'ok', '--c': 'out:理由足够长的一段话，说明这是有意识不做', '--d': 'auto:默认行为就是它，无需开关的说明' };
  const cases = [
    [{ inventory: inv, flags: ['--a'], status: { ...legal, '--b': 'gap:P3' }, notes: { '--b': 'x' } }, '没有状态', '未分类'],
    [{ inventory: inv, flags: ['--a', '--b'], status: { ...legal, '--b': 'gap:P3' }, notes: { '--b': '还差 x' } }, '仍记 gap', 'gap 但已实现'],
    [{ inventory: inv, flags: ['--a'], status: { ...legal, '--b': 'ok:--nope' }, notes: {} }, '没有 --nope', '引用不存在的旗标'],
    [{ inventory: inv, flags: ['--a'], status: { ...legal, '--b': 'gap:P3' }, notes: {} }, '没写「还差什么」', '缺口无说明'],
  ];
  for (const [input, expect, name] of cases) {
    const r = judgeParity(input);
    assert.ok(r.fails.some((f) => f.includes(expect)), `反例「${name}」没被抓住（实际失败：${r.fails.join(' / ') || '(无)'}）`);
  }
  const real = judgeParity();
  assert.deepEqual(real.fails, [], `真实底账自身不干净：\n  ${real.fails.join('\n  ')}`);
});

test('⑤ 分母下限与哨兵项：INVENTORY 被删空/截断时必须红', () => {
  const total = judgeParity().stats.total;
  assert.ok(total >= 200, `分母只剩 ${total} 项（sqlmap 1.10.7 实测 222）—— INVENTORY 可能被截断`);
  // 哨兵：横跨各分组的真实能力面，任一缺失都说明快照不是「完整选项面」
  const flat = new Set(INVENTORY.flatMap((g) => g.opts));
  for (const s of ['--url', '--tamper', '--dump-all', '--os-shell', '--reg-read', '--graphql', '--list-tampers', '-t']) {
    assert.ok(flat.has(s), `INVENTORY 缺哨兵项 ${s} —— 分母不是完整选项面`);
  }
  // gap 的优先级只能 P1/P2/P3（防止有人写 P0 绕开计划）
  for (const [opt, code] of Object.entries(STATUS)) {
    const p = parseCode(code);
    if (p.kind === 'gap') assert.match(p.priority, /^P[123]$/, `${opt} 的优先级非法：${p.priority}`);
  }
});

test('⑥ D197 接线真的通到 config 与**出口选项**（不是只改了文档）', () => {
  const cases = [
    [['-u', 'http://t.test/?id=1', '--no-keep-alive'], 'disableKeepAlive'],
    [['-u', 'http://t.test/?id=1', '--drop-set-cookie'], 'dropSetCookie'],
  ];
  for (const [argv, key] of cases) {
    const args = parseArgs(argv);
    assert.equal(args[key], true, `parseArgs 未认出 ${argv[argv.length - 1]}`);
    const config = buildConfig(args);
    assert.equal(config[key], true, `${argv[argv.length - 1]} 没有落到 config.${key}（引擎拿不到）`);
    // 关键一步：出口选项必须**真的带上它**。历史三次事故（egressOpts.js 顶部）都是
    // 「config 里有、opts 里没有」⇒ 使用者以为生效、实际只有一部分通路生效。
    const opts = buildEgressOpts(config);
    assert.equal(opts[key], true, `config.${key} 没进 buildEgressOpts ⇒ 检测/提取通路看不到它（收参数不生效）`);
  }
  // 默认必须仍是关：两项都是 opt-in（否则等于给所有用户换出口形态）
  const off = buildConfig(parseArgs(['-u', 'http://t.test/?id=1']));
  const offOpts = buildEgressOpts(off);
  for (const key of ['disableKeepAlive', 'dropSetCookie']) {
    assert.ok(!off[key], `config.${key} 在未传旗标时必须为 falsy，实际 ${off[key]}`);
    assert.ok(!offOpts[key], `egressOpts.${key} 在未传旗标时必须为 falsy，实际 ${offOpts[key]}`);
  }
});

test('⑥b 同批刻意没接的两项必须仍是缺口（防「只做了一半就宣称支持」）', () => {
  // --null-connection / --http2 复核结论：引擎侧只做了一半（前者零调用点、后者仅取页面），
  // 收成 CLI 旗标就是「收参数不生效」。本测试把「不许悄悄接上」写成判据：
  // 一旦谁把它们接完（含检测链路），下面这条会红，逼着他把底账状态一并改对。
  const flags = sourceFlags();
  for (const f of ['--null-connection', '--http2']) {
    assert.equal(flags.has(f), false, `${f} 已被接上：请同时把 docs/_sqlmap-parity.json 的状态改成 ok/part 并说明覆盖范围`);
    assert.equal(parseCode(STATUS[f]).kind, 'gap', `${f} 在底账里必须是 gap（当前 ${STATUS[f]}）`);
  }
});

test('⑧ 底账的元数据不许自相矛盾：版本、状态译名、计划覆盖、说明表', () => {
  // 版本：JSON 里记的上游基准必须与脚本常量一致（否则「对标的是哪一版」就说不清了）
  const ledger = JSON.parse(readRepo(JSON_REL));
  assert.equal(ledger.sqlmapVersion, SQLMAP_VERSION, 'JSON 里的 sqlmapVersion 与脚本常量不一致');
  // 状态译名：每个出现的 kind 都必须有中文标签（doc 渲染不能出空标签）
  const kinds = new Set(Object.values(STATUS).map((c) => parseCode(c).kind));
  for (const k of kinds) assert.ok(STATUS_LABEL[k], `状态 ${k} 没有中文标签`);
  // 说明表：NOTES 的键必须都真的是 gap/part（残留的过期说明会让读者以为某项还缺）
  const stray = Object.keys(NOTES).filter((o) => !['gap', 'part'].includes(parseCode(STATUS[o]).kind));
  assert.deepEqual(stray, [], `NOTES 里有已不再缺口的残留条目：${stray.join('、')}`);
  // 计划覆盖：**每一个 gap 都必须落在某个计划批次里**（「全方面补齐」不许有关起门来的缺口）
  const planned = new Set(PLAN.flatMap((p) => p.items.map((it) => (it.match(/^--?[a-z0-9-]+/) || [''])[0])));
  const unplanned = Object.entries(STATUS)
    .filter(([, c]) => parseCode(c).kind === 'gap')
    .map(([o]) => o)
    .filter((o) => !planned.has(o));
  assert.deepEqual(unplanned, [], `有缺口没有进任何计划批次（补齐路线不完整）：${unplanned.join('、')}`);
  // 反向：计划里点名的选项必须真实存在于分母里（防计划里写错名字）
  const flat = new Set(INVENTORY.flatMap((g) => g.opts));
  const ghosts = [...planned].filter((o) => o && !flat.has(o));
  assert.deepEqual(ghosts, [], `计划里点了不存在的选项：${ghosts.join('、')}`);
});
test('⑦ --list-tampers 列出的名字必须真能用于 --tamper（否则清单是骗人的）', () => {
  const lines = tamperCatalogLines();
  assert.ok(lines.length > 100, `清单只剩 ${lines.length} 行 —— 注册表可能没被副作用导入`);
  const names = lines.filter((l) => l.startsWith('  ')).map((l) => l.trim().split(/\s+/)[0]);
  assert.ok(names.length > 100, `解析出的插件名只有 ${names.length} 个`);
  // 确定性：同样输入两次必须完全一致（快照/diff 依赖它）
  assert.deepEqual(tamperCatalogLines(), lines);
  // 每个名字都能在注册表里取到（清单与注册表同源；这里独立复核一遍取用面）
  const missing = names.filter((n) => !tamperRegistry.get(n));
  assert.deepEqual(missing, [], `清单里有取不到的插件名：${missing.join('、')}`);
  // 反向：注册表里的插件不许漏在清单外（清单不许只挑一部分显示）
  const shown = new Set(names);
  const absent = tamperRegistry.list().map((p) => p.name).filter((n) => !shown.has(n));
  assert.deepEqual(absent, [], `注册表里有但清单没列的插件：${absent.join('、')}`);
});
