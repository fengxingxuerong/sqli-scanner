// ============================================================================
// server/tests/payloadVersion.wiring.test.js
//
// 拦的是这一类缺陷：**判据本身是对的，但没有任何入口把真值喂进去**。
//   `selectPayloads()` 里 minVersion/maxVersion 的过滤逻辑（payloadRegistry.js:158-162）
//   一直是正确的，`payloadVersion.test.js` 也一直是绿的 —— 因为它**直接调被调函数**、
//   自己传 dbmsVersion。而 2026-10-06 实测：四个检测器调用点（BooleanBlind ×2 /
//   ErrorDetector / TimeBlindDetector）**一个都没传** ⇒ 生产路径上 dbmsVersion 恒为
//   undefined ⇒ 版本门**恒不生效**，注册表里 5 条 minVersion 条目（MySQL 5.7 JSON、
//   MariaDB 10.3 集合运算、PG 9.6 SLEEP FOR、Oracle 12 JSON_VALUE）对所有版本照投。
//   ⇒ 单测全绿 + 入口坏，就是这一类的签名。
//
// 判据形态：源码级扫描每个 `selectPayloads({` 调用点的实参对象，要求含 dbmsVersion 键。
//   选源码级而不是行为级：行为级要替四个检测器搭 ctx/客户端桩，成本高于收益，
//   而且"漏传一个键"这件事本身就是纯静态可判的。
// 变异自证：② 组用两份合成源码把判据本身验红/验绿（摘掉保护看是否真的红）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(HERE, '../src');

/**
 * 从源码里抽出所有 `selectPayloads({` 调用的实参对象文本（花括号配对，含嵌套）。
 * @param {string} code
 * @param {string} callee
 * @returns {string[]} 每个调用点的实参对象字面量文本
 */
function extractCallArgs(code, callee = 'selectPayloads') {
  const out = [];
  const re = new RegExp(`${callee}\\(\\s*\\{`, 'g');
  let m;
  while ((m = re.exec(code))) {
    const start = code.indexOf('{', m.index);
    let depth = 0;
    for (let i = start; i < code.length; i++) {
      const c = code[i];
      if (c === '{') depth++;
      else if (c === '}') {
        depth--;
        if (depth === 0) { out.push(code.slice(start, i + 1)); break; }
      }
    }
  }
  return out;
}

const DETECTOR_DIR = join(SRC, 'engine/detectors');
const detectorFiles = readdirSync(DETECTOR_DIR).filter((f) => f.endsWith('.js'));

test('① 每个 selectPayloads 调用点必须把 dbmsVersion 喂进去（否则注册表版本门恒不生效）', () => {
  const violations = [];
  let seen = 0;
  for (const f of detectorFiles) {
    const code = readFileSync(join(DETECTOR_DIR, f), 'utf8');
    for (const args of extractCallArgs(code)) {
      seen++;
      if (!/\bdbmsVersion\s*:/.test(args)) violations.push(`${f}: selectPayloads({...}) 缺 dbmsVersion`);
    }
  }
  assert.ok(seen >= 4, `预期至少 4 个调用点（BooleanBlind×2 / Error / TimeBlind），实得 ${seen} —— 采集面缩了先判红，别让它静默变少`);
  assert.deepEqual(violations, [], `版本门在入口断链：\n${violations.join('\n')}`);
});

test('② 反向对照：本判据对"缺键"确实敏感（防恒真判据）', () => {
  const missing = `const x = selectPayloads({ dbms, technique: 'error', level, risk });`;
  const present = `const x = selectPayloads({ dbms, dbmsVersion: ctx.dbmsVersion, technique: 'error' });`;
  const nested = `const y = selectPayloads({ dbms, nested: { a: 1 }, technique: 'time' });`;
  assert.equal(extractCallArgs(missing).length, 1, '应能定位调用点');
  assert.equal(/\bdbmsVersion\s*:/.test(extractCallArgs(missing)[0]), false);
  assert.equal(/\bdbmsVersion\s*:/.test(extractCallArgs(present)[0]), true);
  // 花括号必须配对到调用点整体，不能被嵌套对象截断
  assert.equal(extractCallArgs(nested)[0].includes('technique'), true, '嵌套对象会让扫描提前收尾的话，判据会漏检后半段');
  assert.equal(/\bdbmsVersion\s*:/.test(extractCallArgs(nested)[0]), false);
});

test('③ ctx 版选择器也必须转发 dbmsVersion（入口有两种写法时不能只钉一种）', async () => {
  const code = readFileSync(join(SRC, 'engine/payloadRegistry.js'), 'utf8');
  const args = extractCallArgs(code, 'selectPayloads');
  assert.ok(args.length >= 2, `payloadRegistry 内应有 ≥2 处 selectPayloads 调用（含 selectPayloadsForCtx 的转发），实得 ${args.length}`);
  const forwarding = args.find((a) => /dbmsVersion\s*:\s*(extra\.dbmsVersion\s*\?\?\s*)?ctx\.dbmsVersion/.test(a));
  assert.ok(forwarding, 'selectPayloadsForCtx 必须把 ctx.dbmsVersion 转发给 selectPayloads');
});

test('④ 端到端：真把版本喂进去时，minVersion 条目按版本投放/退场（不是只测被调函数）', async () => {
  const { selectPayloads } = await import('../src/engine/payloadRegistry.js');
  const ids = (v) => selectPayloads({ dbms: 'MySQL', technique: 'error', level: 3, dbmsVersion: v }).map((e) => e.id);
  const v8 = ids({ major: 8, minor: 0, raw: '8.0.35' });
  const v56 = ids({ major: 5, minor: 6, raw: '5.6.51' });
  const jsonEntries = v8.filter((id) => id.includes('json'));
  assert.ok(jsonEntries.length > 0, 'MySQL 8 应投放带 minVersion 的 JSON 报错条目（否则本用例只是在演空集）');
  assert.ok(jsonEntries.every((id) => !v56.includes(id)), 'MySQL 5.6 不得投放这些条目');
});
