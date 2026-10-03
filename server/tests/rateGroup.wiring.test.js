// ============================================================================
// rateGroup.wiring.test.js —— 共享限速桶这条链必须**四方都在**
//
// 与 loginFlow.wiring / batchLab.wiring 同一套做法：单测（rateGroup.test.js）验模块语义，
// 本文件验「这些语义有没有真的接进产品」。判据用**源码文本**而不是 import ——
// 把 httpClient 跑起来要建 Agent，把 scanConfigGuard 跑起来要构造 REST 上下文。
//
// 另含三条**形态收紧**的行为断言（rateGroup 会当 Map 的 key 用，形态不收紧 ⇒
// 调用方能构造海量 key 撑爆桶表，或撞名去蹭别的扫描的桶）。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { guardScalarsCore } from '../src/api/scanGuard/scalarsCore.js';
import { buildConfig } from '../bin/cli/config.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const read = (rel) => readFileSync(path.join(REPO, rel), 'utf8');

const httpClient = read('server/src/core/httpClient.js');
const sessionState = read('server/src/core/http/sessionState.js');
const scanClient = read('server/src/engine/scan/scanClient.js');
const scalarsCore = read('server/src/api/scanGuard/scalarsCore.js');
const routes = read('server/src/api/scanRoutes.js');
const cli = read('server/bin/cli.js');

test('① 生产侧：forScan 支持第三参 rateKey，且组桶已存在时不重建', () => {
  assert.match(httpClient, /forScan\(scanId, ratePerSec, rateKey\)/, 'forScan 未接受 rateKey');
  assert.match(
    httpClient,
    /if \(!\(rateKey && this\.buckets\.has\(bucketKey\)\)\) this\.createBucket/,
    '组桶已存在时会重建 —— 会丢掉 _chain 串行化链，总速率上限就不再成立',
  );
});

test('② 限速解析：rateKey 独占优先 + 缺失时惰性重建（绝不回退 per-scan 桶）', () => {
  // [2026-10-03 CI #131 加固] 旧形态「rateKey 查不到 → 落 scanId 桶」会把「单桶总量保证」
  // 静默退化成每扫描各一个桶。新契约：rateKey 命中即返回；查不到就用同一个 key 惰性重建
  // （与本组其它成员继续共享）；scanId 桶只在**没有** rateKey 时才可达。
  assert.match(sessionState, /if \(opts\.rateKey\) \{/, '_resolveRateBucket 没有 rateKey 独占分支');
  assert.match(
    sessionState,
    /this\.buckets\.get\(opts\.rateKey\) \|\| this\.createBucket\(opts\.rateKey/,
    '组桶缺失时必须惰性重建（同 key），不允许回退 scanId/rate 桶',
  );
  const rateKeyBranch = sessionState.indexOf('if (opts.rateKey) {');
  const scanLookup = sessionState.indexOf('opts.scanId && this.buckets.get(opts.scanId)');
  assert.ok(rateKeyBranch >= 0 && scanLookup >= 0 && rateKeyBranch < scanLookup, 'rateKey 分支必须先于 scanId 回落（提前 return 才能保证独占）');
  assert.match(sessionState, /export function releaseGroupBucket/, '组桶引用计数释放函数缺失（REST 长驻进程会泄漏 TokenBucket）');
});

test('③ 扫描视图：getScanClient 把 cfg.rateGroup 传给 forScan', () => {
  assert.match(scanClient, /forScan\(scanId, ratePerSec, rateGroup\)/, 'getScanClient 没把 rateGroup 传下去');
  // ⚠ 不能引用下面才声明的 `cfg`（const 有 TDZ，提前引用会 ReferenceError）—— 这条是踩过的坑
  assert.match(scanClient, /target && target\.config && target\.config\.rateGroup/, 'rateGroup 的取数源不对');
});

test('④ 白名单与形态收紧：rateGroup 进 REST 白名单且由 guardScalarsCore 收紧', () => {
  assert.match(routes, /'rateGroup',/, "scanRoutes 的 KNOWN_CFG_KEYS 缺 'rateGroup'");
  assert.match(scalarsCore, /rateGroup/, 'guardScalarsCore 没有处理 rateGroup');
  assert.match(scalarsCore, /\[A-Za-z0-9_-\]\{1,64\}/, 'rateGroup 没有字符集收紧（会当 Map key 用）');
});

test('⑤ CLI 批量：-m 与 -l 两条路径都开组桶（不是只有一条改了）', () => {
  const hits = (cli.match(/const rateGroup = /g) || []).length;
  assert.ok(hits >= 2, `批量两条路径都应建组桶，实得 ${hits} 处`);
  // 组桶要求所有成员传同一个 ratePerSec ⇒ 不能再除以并发度
  assert.doesNotMatch(cli, /ratePerSec: perScanRate/, '仍在按并发度均分 ⇒ 与组桶语义冲突（总量会被两道闸夹住）');
});

// [2026-10-03 CI #131] 本条就是本次事故的判据缺口：⑤ 只钉了「CLI 生成了组 id 变量」，
// 没钉「组 id 进了 target.config」—— buildConfig 是显式键清单，漏一行透传就让组桶
// 在 CLI 路径整体失效（3 目标各建各的桶，CI 实测 18 req/s > 上限 6）。
// 判据用**行为**（真调 buildConfig），不只用源码文本 —— 文本能验「写了这行」，
// 行为能验「这行真的接上了」。
test('⑤b CLI buildConfig：rateGroup 必须透传进 config（漏了就是本次 CI 双红的根因）', () => {
  const cfgSrc = read('server/bin/cli/config.js');
  assert.match(cfgSrc, /args\.rateGroup/, 'buildConfig 没有透传 rateGroup —— CLI 批量的组桶在源头就被丢了');
  const withGroup = buildConfig({ rateGroup: 'batch-abc_X1', level: 1, concurrencyDet: 1 });
  assert.equal(withGroup.rateGroup, 'batch-abc_X1', 'rateGroup 必须原样进 config（getScanClient 从 target.config 读它）');
  const noGroup = buildConfig({ level: 1 });
  assert.equal(noGroup.rateGroup, undefined, '不给组 id 时不得凭空造键（getScanClient 靠 undefined 走 per-scan 旧路径）');
});

test('⑥ 行为：形态收紧 —— 合法收下，非法整体丢弃', () => {
  const okCfg = {};
  guardScalarsCore(okCfg, { rateGroup: 'batch-abc123_X' }, null);
  assert.equal(okCfg.rateGroup, 'batch-abc123_X');

  // 含非法字符 / 空值 / 非字符串 ⇒ 整体丢弃（截断救不了它们：截断后仍是"调用方没写的那个 key"）
  // 注：数字会按 clampStr 的既有契约被 String() 归一后收下（"42" 是合法 key，与 safeUrl 等键同口径）
  for (const bad of ['batch abc', 'a/b', '../../etc', '', {}]) {
    const cfg = {};
    guardScalarsCore(cfg, { rateGroup: bad }, null);
    assert.equal(
      cfg.rateGroup,
      undefined,
      `非法 rateGroup 必须整体丢弃（会当 Map key 用），实得 ${JSON.stringify(cfg.rateGroup)}，输入 ${JSON.stringify(bad)}`,
    );
  }
  // 超长按**截断**处理（与 safeUrl/csrfUrl 等既有键同一口径：clamp 不是 reject）——
  // 截断后仍在字符集内，key 稳定且可预期，比整体丢弃更可用。
  const longCfg = {};
  guardScalarsCore(longCfg, { rateGroup: 'x'.repeat(200) }, null);
  assert.equal(longCfg.rateGroup, 'x'.repeat(64), '超长应截断到 64（既有 clamp 口径）');
});

test('⑦ 行为：不给 rateGroup 时不得写这个键（零回归）', () => {
  const cfg = {};
  guardScalarsCore(cfg, { ratePerSec: 10 }, null);
  assert.equal('rateGroup' in cfg, false, '未传时不应凭空写入（下游据此判断走哪条限速路径）');
});
