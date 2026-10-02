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

test('② 限速解析：rateKey 优先于 scanId（顺序反了组桶永远拿不到）', () => {
  assert.match(sessionState, /opts\.rateKey && this\.buckets\.get\(opts\.rateKey\)/, '_resolveRateBucket 没优先查 rateKey');
  const pref = sessionState.indexOf('opts.rateKey && this.buckets.get(opts.rateKey)');
  const scan = sessionState.indexOf('opts.scanId && this.buckets.get(opts.scanId)');
  assert.ok(pref >= 0 && scan >= 0 && pref < scan, 'rateKey 的查询必须排在 scanId **之前**');
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
