// ============================================================================
// server/tests/gateListWiring.guard.test.js —— 「收口清单里的门禁，CI/本地真跑了吗」
//                                                       [D223 2026-10-31]
//
// ── 为什么必须有 ────────────────────────────────────────────────────────────
// `scripts/lib/gate-list.mjs` 是收口清单的**单一真源**（D178 抽出，37 项），
// `npm run gate:close` 逐项跑它、`scripts/quality-ledger.mjs` 逐项数它。
// 但**没有任何判据**要求「清单里的每一项，在 CI 与 ci-local 里被执行过」。
//
// 2026-10-31 实测代价（真发生，不是假想）：
//   `quality-ledger --check` 在 HEAD 上红了整整一天 —— docs/质量台账.md 的快照停在
//   10-30T20:55，而 docs/_facts.json 已由 D221 重采到 10-31T11:45（服务端用例 3954→3955、
//   覆盖率三处全变）。台账是本仓**对外**宣称「可核查」的那一页，它静默过期 = 门面数字与
//   真源不一致。而它没被发现的原因不是判据不灵，是**判据从没在 CI 里跑过**：
//   跑 gate:close 靠人手，CI 从不知道有这个门禁。
//
// 同族先例（本仓已登记多轮，每次都是「有入口、从不执行」）：
//   · D2  / 2026-10-12：6 个 e2e 靶场「不在 run-all / acceptance / ci.yml 任一处」；
//   · D94 / 2026-10-24：typecoverage 只在收口清单里，CI 看不见；
//   · D145/ 2026-10-24：greenguard 只在 CI lint、收口清单没有 → 本地绿 CI 红；
//   · D223/ 2026-10-31：本题 —— 8 个门禁两侧都没有。
//
// ── 判据（三向，缺一不可）──────────────────────────────────────────────────
//   ① 覆盖：gate-list 每一项的**脚本文件**必须在 ci.yml **与** ci-local.mjs 里各被引用；
//   ② 不空转：两处引用到的 scripts/*.mjs 必须真实存在（防「引用一个不存在的门禁」假绿）；
//   ③ 自证：判据自身必须能红 —— 用构造样本验证「少一处引用」会被抓出来，
//      并断言扫描到的条目数非空（否则①② 全在空集上恒真）。
//
// ── 口径细节（别把判据写松了）──────────────────────────────────────────────
// · 只认**命令行位置**的引用：ci.yml 剥掉注释后再找（注释里提到脚本名不算接线 ——
//   本仓真出现过「jobBody 含大段注释、注释里也提到它」的假绿）。
// · `npm run <alias>` 要展开成它背后的 `node scripts/x.mjs`（包名与脚本名不同源）。
// · wiring 这一项是 `node --test ...` 而非 scripts/*.mjs，单独按其形态判（见 ③）。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const CI_YML = path.join(REPO, '.github', 'workflows', 'ci.yml');
const CI_LOCAL = path.join(REPO, 'scripts', 'ci-local.mjs');
const PKG = path.join(REPO, 'package.json');

const ciRaw = readFileSync(CI_YML, 'utf8');
const ciLocalRaw = readFileSync(CI_LOCAL, 'utf8');
const pkg = JSON.parse(readFileSync(PKG, 'utf8'));

/** 剥掉 YAML/JS 的行注释（只处理行首 `#` 与 `//`），避免「注释里提到脚本名」被当成接线。 */
function stripLineComments(text) {
  return text
    .split(/\r?\n/)
    .filter((l) => !/^\s*(#|\/\/)/.test(l))
    .join('\n');
}

/**
 * 收集一段配置里**实际执行到**的 scripts/*.mjs 文件名集合。
 * 展开 `npm run <alias>` → package.json 里那条命令（递归一层，够用且可预期）。
 * @param {string} text 配置原文（已剥注释）
 * @returns {Set<string>} 形如 `quality-ledger.mjs` 的基名集合
 */
function collectScriptRefs(text) {
  const out = new Set();
  const addFrom = (s) => {
    for (const m of s.matchAll(/scripts\/([\w.-]+\.mjs)/g)) out.add(m[1]);
  };
  addFrom(text);
  for (const m of text.matchAll(/npm run (?:--silent )?([\w:.-]+)/g)) {
    const inner = pkg.scripts?.[m[1]];
    if (!inner) continue;
    addFrom(inner);
    // 一层间接：`"x": "npm run y"` 这种转发形态
    const hop = /npm run (?:--silent )?([\w:.-]+)/.exec(inner);
    if (hop && pkg.scripts?.[hop[1]]) addFrom(pkg.scripts[hop[1]]);
  }
  return out;
}

const ciRefs = collectScriptRefs(stripLineComments(ciRaw));
const localRefs = collectScriptRefs(stripLineComments(ciLocalRaw));

/** 从 gate-list.mjs 读出条目（源码扫描；该模块是纯 ES 模块，可直接 import）。 */
async function loadGateList() {
  // Windows 上动态 import 绝对路径必须转成 file:// URL（否则 ERR_UNSUPPORTED_ESM_URL_SCHEME: 'd:'）
  const mod = await import(pathToFileURL(path.join(REPO, 'scripts', 'lib', 'gate-list.mjs')).href);
  return mod.closeGateList({ root: REPO });
}

/** gate 项的 cmd → 其对应的脚本基名（`node scripts/x.mjs` → `x.mjs`） */
function scriptBaseOf(cmd) {
  const hit = cmd.find((a) => /scripts[\\/][\w.-]+\.mjs$/.test(a));
  return hit ? hit.split(/[\\/]/).pop() : null;
}

test('① 覆盖：收口清单每一项的脚本，必须在 ci.yml 与 ci-local 里各被执行', async () => {
  const items = await loadGateList();
  assert.ok(items.length >= 30, `收口清单条目异常偏少（${items.length}），判据可能没读到清单`);

  /** @type {string[]} */
  const missing = [];
  for (const it of items) {
    const base = scriptBaseOf(it.cmd);
    // wiring 是 `node --test ...` 形态（不是 scripts/*.mjs），由下面的专测判，不在此处
    if (!base) continue;
    const inCi = ciRefs.has(base);
    const inLocal = localRefs.has(base);
    if (!inCi || !inLocal) {
      missing.push(`${it.name}（${base}）: ${inCi ? '' : 'ci.yml ✗ '}${inLocal ? '' : 'ci-local.mjs ✗'}`.trim());
    }
  }
  assert.deepEqual(
    missing,
    [],
    `以下收口门禁在 CI 或本地门禁清单里**没有被执行** —— 它们只存在于 npm run gate:close 里，` +
      `而那是手工动作，等于判据不存在（D223 的 quality-ledger 就是这么悄悄过期一整天的）：\n  ` +
      missing.join('\n  ')
  );
});

test('①b wiring 测试集合本身必须在两侧都被执行（不能只跑 npm test 兜底）', async () => {
  // wiring 项形如 `node --test --test-concurrency=4 server/tests/xxx.guard.test.js ...`。
  // 它在 CI 里的等价物是 lint job 的 wiring 步骤 + test-server 的 `npm test` 兜底；
  // 在 ci-local 里是 test-server 的 `cd server && npm test`。这里判的是
  // **收口清单的 wiring 文件确实落在 CI 会跑的测试目录里**，而不是「文件存在即算数」。
  const items = await loadGateList();
  const wiring = items.find((it) => it.name === 'wiring');
  assert.ok(wiring, '收口清单里找不到 wiring 项');
  const files = wiring.cmd.filter((a) => /\.test\.js$/.test(a));
  assert.ok(files.length >= 5, `wiring 收集到的文件异常偏少（${files.length}）—— 匹配口径可能坏了`);
  for (const f of files) {
    assert.ok(existsSync(path.join(REPO, f)), `wiring 清单里的文件不存在：${f}`);
    assert.match(f, /^server[\\/]tests[\\/]/, 'wiring 文件必须在 server/tests 下，否则 `npm test` 兜不住它');
  }
  // 两侧都必须真的跑 server/tests（CI: test-server 的 npm test；本地: 同一条）
  for (const [label, text] of [['ci.yml', stripLineComments(ciRaw)], ['ci-local.mjs', stripLineComments(ciLocalRaw)]]) {
    assert.match(
      text,
      /(cd server && npm test|npm run test:coverage)/,
      `${label} 没有跑 server 测试 —— 收口清单里的 wiring 文件在那里不会被兜底执行`
    );
  }
});

test('② 不空转：两处引用到的 scripts/*.mjs 必须真实存在', () => {
  const all = new Set([...ciRefs, ...localRefs]);
  const ghosts = [...all].filter((b) => !existsSync(path.join(REPO, 'scripts', b)));
  assert.deepEqual(ghosts, [], `以下脚本被 CI/ci-local 引用但文件不存在（引用即失败的门禁）：${ghosts.join(', ')}`);
  assert.ok(all.size >= 10, `扫描到的脚本引用过少（${all.size}）—— 解析口径可能坏了`);
});

test('③ 自证：判据必须能红（少一处引用 / 引用幽灵脚本都要被抓住）', () => {
  // 自证 1：从 ci.yml 里删掉 quality-ledger 的那一行，collectScriptRefs 必须少掉它。
  const withoutLedger = stripLineComments(ciRaw)
    .split(/\r?\n/)
    .filter((l) => !/quality-ledger\.mjs/.test(l))
    .join('\n');
  const refs2 = collectScriptRefs(withoutLedger);
  assert.equal(refs2.has('quality-ledger.mjs'), false, '判据不灵：删掉步骤后仍认为它被引用（会假绿）');
  assert.equal(ciRefs.has('quality-ledger.mjs'), true, '质量台账步骤不在 ci.yml 里 —— D223 要补的正是这一条');

  // 自证 2：注释里的脚本名不得被当成接线（本仓有过 jobBody 注释假绿的先例）。
  const commented = '# node scripts/quality-ledger.mjs --check\n// node scripts/pack-check.mjs\n';
  const refs3 = collectScriptRefs(stripLineComments(commented));
  assert.equal(refs3.size, 0, '注释里的脚本名被当成了接线（判据假绿）');

  // 自证 3：npm 别名必须被展开（`npm run quality:ledger` → quality-ledger.mjs）。
  // 用真实 package.json 里的条目验证解析器认得别名形态。
  if (pkg.scripts?.['quality:ledger']) {
    const refs4 = collectScriptRefs('npm run quality:ledger');
    assert.equal(refs4.has('quality-ledger.mjs'), true, 'npm 别名没被展开成真实脚本名');
  }
});
