// crsGatedFamilies.wiring.test.js —— 「代码声明受管的族」与「清单真的跑它」必须同源
// ============================================================================
// 为什么要单独一道守卫（2026-09-25，接 930 进门禁的当轮）：
//   门禁族名单 `GATED_FAMILIES` 写在 crs-equivalence.mjs 里，而"这一族到底跑没跑"写在
//   `.github/workflows/ci.yml` 与 `scripts/ci-local.mjs` 两份清单里 —— **三处各写一份真相**。
//   只改代码会出现最难查的那种状态：读代码的人以为 930 受管，CI 却从来没裁过它，
//   于是它既不会红、也没有任何一行输出说明它被跳过了。
//   这与本仓反复出现的"注册成功≠在干活"是同一种失效，只是这次的对象是门禁本身。
//
// 三个方向（缺一个就有空档）：
//   ① 覆盖：GATED_FAMILIES 里每一族，必须在 ci.yml **和** ci-local.mjs 各有一个真跑它的步骤；
//   ② 不空转：清单里出现的 `--family=X` 必须对应一个**确实受管**的族 —— 否则那一步
//      "看起来在裁 930"，实际 930 只报数不判红，等于给免检族发合格证；
//   ③ 素材：受管族必须已有**自己的**基线文件，且每条点名分歧都带理由（理由没补的条目
//      等于没点名）。默认族与 BASE_FAMILY 的等价关系也钉住 —— ①里"裸 waf-fidelity 算裁
//      BASE_FAMILY"这一步依赖它。
// ============================================================================
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const HARNESS = path.join(REPO, 'e2e/waf-real', 'crs-equivalence.mjs');
const SRC = readFileSync(HARNESS, 'utf8');
const PKG = JSON.parse(readFileSync(path.join(REPO, 'package.json'), 'utf8'));
const CI_YML = readFileSync(path.join(REPO, '.github', 'workflows', 'ci.yml'), 'utf8');
const CI_LOCAL = readFileSync(path.join(REPO, 'scripts', 'ci-local.mjs'), 'utf8');

/** 从源码里取 `const NAME = ['a','b']` 形式的族清单（取不到就红，不让它静默返回空数组）。 */
function listConst(name) {
  const m = new RegExp(`const ${name} = \\[([^\\]]*)\\]`).exec(SRC);
  assert.ok(m, `crs-equivalence.mjs 里找不到数组常量 ${name} —— 守卫的解析要先于它的断言可信`);
  return [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
}
const GATED = listConst('GATED_FAMILIES');
const BASE_MATCH = /const BASE_FAMILY = '(\w+)'/.exec(SRC);
const BASE = () => BASE_MATCH?.[1];

test('族清单非空，且都是 FAMILY_CONF 里成对存在的族', () => {
  assert.ok(GATED.length >= 2, `受门禁管的族应≥2（942 与 930），实得 ${GATED.length}`);
  const conf = /const FAMILY_CONF = \{([^}]*)\}/.exec(SRC);
  assert.ok(conf, 'FAMILY_CONF 没解析出来');
  const known = [...conf[1].matchAll(/(\d{3})\s*:/g)].map((x) => x[1]);
  for (const f of GATED) assert.ok(known.includes(f), `族 ${f} 受门禁管却没有成对的 conf（素材错配）`);
});

test('默认调用裁的就是 BASE_FAMILY（下一步据此认定裸 waf-fidelity = 裁该族）', () => {
  const b = BASE();
  assert.ok(b, "找不到 const BASE_FAMILY = '…'");
  assert.equal(b, '942', 'BASE_FAMILY 变了要同步改本守卫与两份清单');
  assert.match(SRC, /process\.env\.CRS_EQUIV_FAMILIES \|\|\s*\n?\s*'942'/,
    'EVAL_FAMILIES 的兜底族不再是 942 ⇒ "不带 --family 的那一步 = 裁 942"这个前提失效');
});

test('每个受管族在 ci.yml 与 ci-local.mjs 里都真的被跑（双向覆盖）', () => {
  for (const f of GATED) {
    const cmd = f === BASE() ? 'npm run waf-fidelity' : `npm run waf-fidelity:${f}`;
    // 清单里写的可能是 npm 脚本名，要**解析到真正的命令行**再判断带没带 --family
    const resolved = (PKG.scripts[cmd.replace(/^npm run /, '')] || '').trim();
    const expect = f === BASE()
      ? /crs-equivalence\.mjs(?!.*--family=)/
      : new RegExp(`crs-equivalence\\.mjs.*--family=${f}\\b`);
    for (const [where, text, hit] of [
      ['ci.yml', CI_YML, new RegExp(`run: ${cmd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm')],
      ['ci-local.mjs', CI_LOCAL, new RegExp(`cmd: '${cmd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'`)],
    ]) {
      assert.ok(hit.test(text), `族 ${f} 受门禁管，但 ${where} 里没有 \`${cmd}\` 这一步 ⇒ 它永远不会红`);
      assert.match(resolved, expect, `族 ${f} 的入口 ${cmd} 解析出的命令行不是裁这一族：${resolved}`);
    }
  }
});

test('清单里出现的 --family=X 必须确实受管（反向：不给免检族发合格证）', () => {
  const claimed = new Set(
    [...`${CI_YML}\n${CI_LOCAL}\n${Object.values(PKG.scripts || {}).join('\n')}`
      .matchAll(/--family=(\w+)/g)].map((m) => m[1])
  );
  for (const f of claimed) assert.ok(GATED.includes(f), `清单在跑族 ${f}，代码却说它不受门禁管`);
});

test('每个受管族都有自己的基线文件，且逐条点名了理由', () => {
  for (const f of GATED) {
    const file = path.join(
      REPO, 'e2e/waf-real',
      f === BASE() ? 'crs-known-divergences.json' : `crs-known-divergences-${f}.json`
    );
    assert.ok(existsSync(file), `族 ${f} 受门禁管却没有基线文件（首次跑才会生成 ⇒ 这一步漏跑就是"从没裁过"）`);
    const j = JSON.parse(readFileSync(file, 'utf8'));
    assert.match(String(j.tag || ''), new RegExp(`REQUEST-${f}`), `基线 ${path.basename(file)} 的 tag 不属于族 ${f}`);
    for (const d of j.divergences || []) {
      assert.ok(
        d.原因 && d.原因 !== '待补理由' && d.原因.length > 20,
        `族 ${f} 的分歧 ${d.用例} 没写理由（或理由太短）—— 没理由的条目等于没点名`
      );
    }
  }
});
