// ============================================================================
// waf.dbmsAwareChains.test.js —— DBMS 感知链选择（批次 D5 2026-10-05）
//
// 背景：unionvaluesrow 系链（真机 2/19 打穿，modsec-live #162）是 MySQL 8 专用语法，
// 曾被提为通用首选 ⇒ artifact-drift 门禁当场抓到 multi-engine PL1 lab 在 H2/HSQLDB 上
// union 技术丢失。本批改为 DBMS 感知：指纹确认 MySQL 时才前置真机打穿链进候选。
// 判据（全部可证伪）：
//   ① unionvaluesrow 必须声明 dbms: ['MySQL']（validateChain 对 H2 目标告警+ok=false）；
//   ② MYSQL_DBMS_CHAINS 导出且内容是真机打穿形态；
//   ③ detect.js：dbms === 'MySQL' 时真机链前置进 blockAdaptive 候选（源码守卫）；
//   ④ 通用 OPERATOR_SWAP_CHAINS 保持 DBMS 无关（不含 unionvaluesrow）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import '../src/core/tamper/applyTampers.js';
import { MYSQL_DBMS_CHAINS, OPERATOR_SWAP_CHAINS, ENCODING_FALLBACK_CHAINS } from '../src/core/waf/wafRecommend.js';
import { rankChainsByProfile } from '../src/core/waf/blockProfile.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const read = (rel) => readFileSync(path.join(REPO, rel), 'utf8');

test('① unionvaluesrow 声明 dbms:["MySQL"]：H2 目标上 validateChain 告警且 ok=false', () => {
  const p = tamperRegistry.get('unionvaluesrow');
  assert.ok(p, '插件应已注册');
  assert.deepEqual(p.dbms, ['MySQL'], 'dbms 声明缺失 —— 非 MySQL 目标将产出语法错误的 payload');
  const v = tamperRegistry.validateChain(['unionvaluesrow'], { dbms: 'H2' });
  assert.equal(v.ok, false, 'H2 目标必须判不通过');
  assert.match(v.warnings.join(''), /MySQL/);
  const m = tamperRegistry.validateChain(['unionvaluesrow'], { dbms: 'MySQL' });
  assert.equal(m.ok, true, 'MySQL 目标应通过');
});

test('② MYSQL_DBMS_CHAINS：真机打穿形态在案（#162 链对拍）', () => {
  assert.deepEqual(MYSQL_DBMS_CHAINS[0], ['unionvaluesrow', 'dash2hash']);
  assert.deepEqual(MYSQL_DBMS_CHAINS[1], ['unionvaluesrow', 'dash2hash', 'hexliterals']);
});

test('④ 通用 OPERATOR_SWAP_CHAINS 保持 DBMS 无关（不含 unionvaluesrow / scalarselectinline 组合链）', () => {
  for (const chain of OPERATOR_SWAP_CHAINS) {
    assert.ok(!chain.includes('unionvaluesrow'), '通用链表不得含 MySQL 专用链（H2/HSQLDB 会语法错误）');
  }
});

test('③ detect.js：dbms=MySQL 时真机链前置进 blockAdaptive 候选（源码守卫）', () => {
  const src = read('server/src/engine/scan/detect.js');
  // ⚠️ 只钉「该导入里有 MYSQL_DBMS_CHAINS」，不钉完整列表 —— 钉完整列表会让**合法新增导入**
  //    也报"导入缺失"（D19 加 `ENCODING_FALLBACK_CHAINS` 时被误伤过）。
  assert.match(
    src,
    /import \{[^}]*\bMYSQL_DBMS_CHAINS\b[^}]*\} from '\.\.\/\.\.\/core\/waf\/wafRecommend\.js'/,
    '导入缺失',
  );
  const prep = src.indexOf("if (dbms === 'MySQL') {");
  const generic = src.indexOf('for (const plugins of OPERATOR_SWAP_CHAINS) {', prep >= 0 ? prep : 0);
  assert.ok(prep >= 0 && generic > prep, 'MySQL 专属链必须**前置**于通用链（真机打穿链优先）');
  // 顺序守卫：真机打穿链在通用链之前被 push
  const pushMysql = src.indexOf('MYSQL_DBMS_CHAINS)', prep);
  const pushGeneric = src.indexOf("suggestions.push({ vendor: GENERIC_BLOCK_VENDOR, plugins: [...plugins] });", pushMysql);
  assert.ok(pushMysql > 0 && pushGeneric > pushMysql, 'MySQL 链必须先于通用链 push');
  // [D19 2026-10-09] 编码兜底链也必须真接进候选 —— 它此前只靠动态生成，被 D15 的池子扩张
  // 挤到 codec 第 30+，导致 acceptance 的 waf403 连续 3 个 run 漏检（见 CHANGELOG D19）。
  assert.match(src, /for \(const plugins of ENCODING_FALLBACK_CHAINS\)/, '编码兜底链必须接进 blockAdaptive 候选');
});

// [D19 2026-10-09] 行为断言（比源码文本强）：画像拦**关键词**时，编码兜底链必须排到链首。
//
// 这条钉的是真回归的"最后一毫米"：`chainVerify` 的静态名额只有 2 个（`MAX_CHAINS - GENERATED_SLOTS`），
// 排不到前 2 就等于没进候选。此前 `TAMPER_COVERS.chardoubleencode` 只列标点类
// （quote/space/paren/comma/cmp），与关键词画像交集为 0 ⇒ hit=0 ⇒ 排静态链最后 ⇒ 被切掉 ⇒
// acceptance 的 waf403（关键字即拦）连续 3 个 run 漏检。
test('★ D19：画像拦关键词时编码兜底链（chardoubleencode）必须排链首（进得了 2 个静态名额）', () => {
  const V = 'generic_block';
  const chains = [
    ...ENCODING_FALLBACK_CHAINS.map((c) => ({ vendor: V, plugins: [...c] })),
    ...OPERATOR_SWAP_CHAINS.map((c) => ({ vendor: V, plugins: [...c] })),
  ];
  const ranked = rankChainsByProfile(chains, ['comment', 'and', 'or', 'union', 'select', 'sleep']);
  assert.equal(
    ranked[0].plugins.join('+'),
    'chardoubleencode',
    `编码兜底链没排到链首 ⇒ 会被 chainVerify 的 2 个静态名额切掉 ⇒ 关键字即拦场景漏检。实际前 3：` +
      ranked.slice(0, 3).map((c) => c.plugins.join('+')).join(' | '),
  );
  // 对照：画像为空时不重排（保持原序）—— 防"无条件把它提到第一"
  const plain = rankChainsByProfile(chains, []);
  assert.equal(plain[0].plugins.join('+'), 'chardoubleencode', '空画像下保持入参序（它本就在最前）');
  assert.equal(plain.length, chains.length, '重排不得增删链');
});
