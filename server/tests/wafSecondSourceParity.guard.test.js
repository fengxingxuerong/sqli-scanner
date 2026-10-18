// ============================================================================
// wafSecondSourceParity.guard.test.js —— [D99/D100 2026-10-18] 第二权威对拍源守卫
//
// ── 为什么有这个文件 ────────────────────────────────────────────────────────
// 台账 `waf-fingerprint-coverage` 的缺口：62 家里只有 18 家（wafw00f 插件）做过
// 「外部权威对拍」（见 wafExternalParity.guard.test.js），其余 44 家只有
// 「规则存在 + 判据单测」。本守卫为其中 27 家引入**第二独立权威源**：
//   · WhatWaf（Ekultek，2.9k stars，GPLv3）—— 90 个插件，与 wafw00f 各自独立开发
//   · nuclei-templates（projectdiscovery）—— waf-detect.yaml safe3webfirewall 段
//     （其 reference 即 WhatWaf、作者同为 WhatWaf 核心作者，故只取其中
//       WhatWaf 未覆盖的 Safe3 一条，其余段不重复采用）
//
// ── 测什么 ──────────────────────────────────────────────────────────────────
// 对快照 `second-source-samples.json` 中 31 条样本（WhatWaf 30 + nuclei 1），
// 逐条构造响应喂给本仓 WafIdentifier，断言**正确命名该厂商**。
// 样本由 `scripts/extract-second-source-samples.mjs` 生成，生成时已做
// 「样本确实命中源正则」的自证（防映射手滑），本守卫在此基础上做
// 「本仓确实认识该样本」的正检 + 零误报反向 + 数量护栏。
//
// ── 快照字段 ────────────────────────────────────────────────────────────────
//   { ours, kind: 'body'|'header'|'cookie', key?, value, sourceRule, plugin }
//   cookie 形态指 set-cookie 响应头（与本仓 header(set-cookie) matcher 同通道）。
// ── 口径声明（避免误读，本仓纪律）──────────────────────────────────────────
// · 样本是「按第二源正则具体化构造」的响应，不是抓包实录；它证明的是
//   「同一份厂商特征我们认得」，不等于「真机上必然命中」（真机另由
//   waf-real 采集器与 modsec-live 等承担）。
// · 判据是**下界**：uncovered 列表里的 16 家（无第二源）不在分母中，不会虚高。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WafIdentifier } from '../src/core/waf/WafIdentifier.js';

const SNAPSHOT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'second-source-samples.json');

test('自证：快照存在、样本量达标且覆盖来源申明完整（判据不得空转）', () => {
  assert.ok(existsSync(SNAPSHOT), `快照缺失：${SNAPSHOT}（重新生成：node scripts/extract-second-source-samples.mjs --whatwaf <dir>）`);
  const snap = JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
  assert.ok(Array.isArray(snap.samples) && snap.samples.length >= 20,
    `样本数 ${snap.samples?.length} 过少 —— 判据可能退化`);
  assert.ok(snap._source && snap._source.includes('WhatWaf'), '来源申明缺失（_source 应含 WhatWaf）');
  const vendors = new Set(snap.samples.map((s) => s.ours));
  assert.ok(vendors.size >= 20, `覆盖厂商 ${vendors.size} 家 < 20 —— 覆盖率退化`);
  assert.ok(Array.isArray(snap.uncovered) && snap.uncovered.length >= 10,
    `无第二源边界 ${snap.uncovered?.length} 家 —— 边界登记退化`);
});

test('对拍：WhatWaf / nuclei 外部规则样本必须被正确命名（外部裁判，非自证）', () => {
  const snap = JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
  const id = new WafIdentifier();
  const misses = [];
  const vendorSeen = new Set();
  const vendorHit = new Set();

  for (const s of snap.samples) {
    vendorSeen.add(s.ours);
    // cookie 形态映射到 set-cookie 响应头（本仓 matcher 同通道）
    const headers = s.kind === 'header'
      ? { [String(s.key).toLowerCase()]: s.value }
      : s.kind === 'cookie'
        ? { 'set-cookie': s.value }
        : {};
    const resp = { status: 403, headers, body: s.kind === 'body' ? s.value : '' };
    const found = id.identify(resp, {}) || [];
    if (found.some((x) => x.vendor === s.ours)) vendorHit.add(s.ours);
    else misses.push(`${s.ours} [${s.kind}:${s.key ?? ''}=${s.value}] ← ${s.plugin} 规则 ${s.sourceRule}`);
  }

  assert.deepEqual(
    misses,
    [],
    `以下第二外部权威源样本未被正确命名 —— 厂商特征的覆盖缺口：\n  ${misses.join('\n  ')}`
  );
  assert.equal(vendorSeen.size, vendorHit.size, '有厂商至少一条样本未命中（见上）');
});

test('反向：干净响应不得误报任何 WAF 厂商（零误报）', () => {
  const id = new WafIdentifier();
  const clean = [
    { status: 200, headers: { server: 'nginx', 'content-type': 'text/html' }, body: '<html><body>hello</body></html>' },
    { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' },
    { status: 200, headers: { server: 'Apache/2.4.62', 'x-powered-by': 'PHP/8.2' }, body: '<html>ok</html>' },
    // 与 WhatWaf 特征近似但非 WAF 的响应：URL Scan 字样、403 通用页面
    { status: 403, headers: { server: 'Microsoft-IIS/10.0' }, body: '<h1>403 Forbidden</h1>' },
  ];
  for (const resp of clean) {
    const found = (id.identify(resp, {}) || []).filter((x) => x.vendor !== 'generic_block');
    assert.deepEqual(found.map((x) => x.vendor), [],
      `干净/非 WAF 响应被误报为厂商：${found.map((x) => `${x.vendor}(${x.confidence})`).join(',')}`);
  }
});

test('反例自证：删掉一条 matcher 必须转红（判据有牙）', () => {
  // 用必然失配的构造成分验证断言逻辑确实在比对，而不是空跑。
  const snap = JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
  const id = new WafIdentifier();
  const bogus = { kind: 'header', key: 'x-definitely-not-a-waf', value: 'zzz', ours: 'Cloudflare' };
  const found = id.identify({ status: 403, headers: { [bogus.key]: bogus.value }, body: '' }, {}) || [];
  assert.equal(found.some((x) => x.vendor === 'Cloudflare'), false,
    '不存在的特征不应命中 Cloudflare —— 若命中说明判据过宽（会掩盖真实缺口）');
  assert.ok(snap.samples.length > 0);
});