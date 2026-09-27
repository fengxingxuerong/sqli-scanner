// ============================================================================
// acceptanceExpect.wiring.test.js —— 「--expect 真跑要求」必须三方都在
//
// 缺陷本体（2026-09-27 全栈审计）：acceptance 的 optional 套件缺依赖时只打一行 SKIP，
// 收尾是 `process.exit(failed.length ? 1 : 0)` ⇒ file-read / file-write / oob-real 这些
// 头条能力可以整轮不测而门禁仍然绿。CI 里 PG 与红队靶场正是 continue-on-error 拉起来的，
// 起不来就落进这条静默通道。
//
// 修法分三方，任何一方的"没接上"本仓都发生过（见下方反例自证为何存在）：
//   ① 判据本体（e2e/lib/suiteVerdict.mjs:evaluateExpect，另有纯函数单测）；
//   ② 调用点：acceptance.mjs 解析 --expect 且把它算进退出码；
//   ③ 声明方：ci.yml 的 acceptance 步骤真的传了这个参数，且传的 id 确实存在。
// 只加 ① 会"能力在、没人用"；只加 ②③ 而 id 拼错 ⇒ 判据判"未知 id"红（不会静默放过），
// 而**若 ③ 整行被删**（最常见的手工回退）则没人再要求 —— 所以 ③ 要有守卫。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const ci = readFileSync(path.join(REPO, '.github', 'workflows', 'ci.yml'), 'utf8');
const acc = readFileSync(path.join(REPO, 'e2e', 'acceptance.mjs'), 'utf8');

/** SUITES 的 id 清单（文本解析：acceptance.mjs 是脚本，import 会真的跑起来） */
function suiteIds(text) {
  const start = text.indexOf('const SUITES');
  const end = text.indexOf('\n];', start);
  assert.ok(start >= 0 && end > start, '解析不到 const SUITES 数组 —— 本守卫的取数源失效');
  return [...text.slice(start, end).matchAll(/\n\s{4}id:\s*['"`]([^'"`]+)['"`]/g)].map((m) => m[1]);
}

/** ci.yml 里 acceptance 那一步传给 --expect 的 id（没有则返回 null） */
function expectArgFromCi(text) {
  const m = text.match(/npm run acceptance(?:\s+--)?\s+--expect=([A-Za-z0-9_,-]+)/);
  return m ? m[1].split(',').map((s) => s.trim()).filter(Boolean) : null;
}

const IDS = suiteIds(acc);

test('② 调用点：acceptance.mjs 解析 --expect 并把它算进退出码', () => {
  assert.match(acc, /x\.startsWith\('--expect='\)/, '没有 --expect 的解析点 —— 参数会被静默忽略');
  assert.match(acc, /evaluateExpect\(EXPECT/, '判据没被调用（或改了名）—— 参数解析了也没用');
  assert.match(acc, /process\.exit\(failed\.length \|\| expectViolations\.length/, '退出码没把 --expect 算进去 ⇒ 违规仍绿');
});

test('③ 声明方：CI 的 acceptance 步骤确实传了 --expect，且 id 全部真实存在', () => {
  const ids = expectArgFromCi(ci);
  assert.ok(ids && ids.length, 'ci.yml 的 acceptance 步骤没带 --expect —— 静默 SKIP 通道又打开了');
  const unknown = ids.filter((id) => !IDS.includes(id));
  assert.deepEqual(unknown, [], `--expect 传了不存在的套件 id：${unknown.join(',')}（可用：${IDS.join(', ')}）`);
});

test('③b CI 只要求它确实 provisioning 过的套件（PG/红队是 continue-on-error，不许写进来）', () => {
  const ids = expectArgFromCi(ci) || [];
  const flakyEnv = ['oob-real', 'redteam'];
  const wrong = ids.filter((id) => flakyEnv.includes(id));
  assert.deepEqual(wrong, [], `${wrong.join(',')} 依赖 continue-on-error 起的环境，写进 --expect 会把环境抖动变成长期红`);
});

test('④ 不空转：SUITES 解析必须命中 15 个 id（否则上面几条可能在拿空集合比）', () => {
  assert.equal(IDS.length, 15, `SUITES 解析到 ${IDS.length} 个 id：${IDS.join(', ')}`);
  assert.ok(IDS.includes('file-read') && IDS.includes('file-write'), '文件读写两个套件不在 SUITES 里 —— 取数口径变了');
});

test('⑤ 反例自证：删掉 CI 那行 / 传错 id / 摘掉退出码，守卫都必须红', () => {
  const stripped = ci.replace(/--expect=[A-Za-z0-9_,-]+/, '--expect=nope-missing');
  assert.ok(expectArgFromCi(stripped).includes('nope-missing'), '反例构造失败（替换没生效）');
  assert.throws(() => {
    const unknown = expectArgFromCi(stripped).filter((id) => !IDS.includes(id));
    assert.deepEqual(unknown, [], '未知 id');
  }, /未知 id/, '传了不存在的 id 却没被抓 ⇒ ③ 那条判据在空转');

  assert.equal(expectArgFromCi(ci.replace(/--expect=[A-Za-z0-9_,-]+/, '')), null,
    '删掉 --expect 后 expectArgFromCi 仍返回内容 ⇒ 解析器不可靠');

  const noExit = acc.replace(/process\.exit\(failed\.length \|\| expectViolations\.length/, 'process.exit(failed.length');
  assert.ok(!/process\.exit\(failed\.length \|\| expectViolations\.length/.test(noExit),
    '反例构造失败：退出码那行没被改到');
});
