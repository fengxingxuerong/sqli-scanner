// ============================================================================
// d202ForcedSurfaces.test.js —— [D202] 强制面与编码四项（对标 sqlmap）
//
// --os / --encoding / --charset / --fingerprint
// 口径：零网络。可真调的一律真调（parseArgs / buildConfig / sanitizeStart /
// decodeResponseBody / finalizeAxiosResponse / buildEgressOpts / 三个纯判据模块）；
// 调度层用剔注释的源码接线守卫钉住，防「实现在、没人调」。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { parseArgs } from '../bin/cli/args.js';
import { buildConfig } from '../bin/cli/config.js';
import { buildKnownArgKeys } from '../bin/cli/configFile.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';
import { FORCED_SURFACE_KEYS, normalizeForcedSurface } from '../src/config/forcedSurfaces.js';
import { decodeResponseBody, finalizeAxiosResponse } from '../src/core/http/responseCodec.js';
import { buildEgressOpts } from '../src/engine/egressOpts.js';
import { charsetRanges, classProbeStep } from '../src/engine/charsetRanges.js';
import { buildFingerprint } from '../src/engine/scan/summaryFingerprint.js';

const URL0 = 'http://127.0.0.1:9/?q=';
const ROOT = new URL('../..', import.meta.url);
const read = (rel) => readFileSync(new URL(rel, ROOT), 'utf8');
// 判据文本源必须剔注释；顺序固定「先行注释、后块注释」。
const strip = (s) => s.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
const code = (rel) => strip(read(rel));

const ALL = [
  '-u', URL0, '--os', 'Windows', '--encoding', 'gbk',
  '--charset', '0123456789abcdef', '--fingerprint',
];

// ── ① 参数面 ──────────────────────────────────────────────────────────────

test('D202 parseArgs：四旗标全部消费，不落 unknownFlags', () => {
  const a = parseArgs(ALL);
  assert.equal(a.os, 'Windows');
  assert.equal(a.encoding, 'gbk');
  assert.equal(a.charset, '0123456789abcdef');
  assert.equal(a.fingerprint, true);
  assert.deepEqual(a.unknownFlags, []);
});

test('D202 buildConfig：四键落 config，os 大小写归一', () => {
  const c = buildConfig(parseArgs(ALL));
  assert.equal(c.os, 'windows');
  assert.equal(c.encoding, 'gbk');
  assert.equal(c.charset, '0123456789abcdef');
  assert.equal(c.fingerprint, true);
});

test('D202 负向：值型缺值/非法值硬拒（收参数不生效是红线）', () => {
  for (const f of ['--os', '--encoding', '--charset']) {
    assert.throws(() => buildConfig(parseArgs(['-u', URL0, f])), /需要值/);
  }
  assert.throws(() => buildConfig(parseArgs(['-u', URL0, '--os', 'solaris'])), /windows \| linux/);
  assert.throws(() => buildConfig(parseArgs(['-u', URL0, '--encoding', 'a/b'])), /字符集标签/);
  assert.throws(() => buildConfig(parseArgs(['-u', URL0, '--charset', 'a\nb'])), /换行/);
});

test('D202 configFile：四键可写 --config 档案', () => {
  const known = buildKnownArgKeys(parseArgs);
  for (const k of FORCED_SURFACE_KEYS) assert.ok(known.has(k), `档案键集缺 ${k}`);
});

// ── ② 单源校验 / REST ────────────────────────────────────────────────────

test('D202 单源校验：CLI 与 REST 共用 normalizeForcedSurface', () => {
  assert.equal(normalizeForcedSurface('os', 'LINUX'), 'linux');
  assert.equal(normalizeForcedSurface('encoding', 'shift_jis'), 'shift_jis');
  assert.equal(normalizeForcedSurface('fingerprint', true), true);
  assert.equal(normalizeForcedSurface('os', ''), undefined);
  assert.throws(() => normalizeForcedSurface('fingerprint', 1), /布尔/);
  assert.throws(() => normalizeForcedSurface('nope', 1), /未知强制面键/);
});

test('D202 REST：四键白名单 + 透传（真调 sanitizeStart）+ 非法值拒绝', () => {
  const cfg = { os: 'linux', encoding: 'gbk', charset: '0123456789abcdef', fingerprint: true };
  const out = sanitizeStart({ target: { url: 'http://shop.example.com/item?id=1' }, config: cfg }).config;
  for (const k of Object.keys(cfg)) assert.equal(out[k], cfg[k], `${k} 未透传`);
  const base = { target: { url: 'http://shop.example.com/item?id=1' } };
  assert.equal(sanitizeStart({ ...base, config: { os: 'WINDOWS' } }).config.os, 'windows');
  assert.throws(() => sanitizeStart({ ...base, config: { os: 'plan9' } }), /windows \| linux/);
  assert.throws(() => sanitizeStart({ ...base, config: { fingerprint: 1 } }), /布尔/);
  assert.throws(() => sanitizeStart({ ...base, config: { encoding: 'x/y' } }), /字符集标签/);
});

// ── ③ --encoding：显式页面编码 ───────────────────────────────────────────

test('D202 --encoding：显式字符集覆盖 Content-Type 声明（GBK 真解码）', () => {
  const buf = Buffer.from([0xd6, 0xd0, 0xce, 0xc4]); // 「中文」的 GBK 字节
  const headers = { 'content-type': 'text/html; charset=utf-8' };
  const auto = decodeResponseBody(buf, headers);
  assert.equal(auto.charset, 'utf-8', '未配置时按 header 自动探测');
  assert.notEqual(auto.text, '中文');
  const forced = decodeResponseBody(buf, headers, { encoding: 'gbk' });
  assert.equal(forced.text, '中文');
  assert.equal(forced.charset, 'gbk');
  assert.equal(forced.charsetSource, 'explicit');
  assert.equal(decodeResponseBody(buf, headers, { encoding: 'a/b' }).charset, 'utf-8',
    '非法标签当作没配，不静默换成别的字符集');
});

test('D202 --encoding：不支持的标签回退 utf-8 并标记 charsetUnsupported', () => {
  const forced = decodeResponseBody(Buffer.from('abc'), {}, { encoding: 'x-no-such-codec' });
  assert.equal(forced.charset, 'utf-8');
  assert.equal(forced.charsetUnsupported, true);
  assert.equal(forced.declaredCharset, 'x-no-such-codec');
});

test('D202 --encoding：两条传输通道同源（finalizeAxiosResponse + egress 透传）', () => {
  const res = {
    data: Buffer.from([0xd6, 0xd0, 0xce, 0xc4]),
    headers: { 'content-type': 'text/html; charset=utf-8' },
  };
  finalizeAxiosResponse(res, { encoding: 'gbk' });
  assert.equal(res.data, '中文');
  assert.equal(res.__meta.charsetSource, 'explicit');
  assert.equal(buildEgressOpts({ encoding: 'gbk' }).encoding, 'gbk');
  assert.equal(buildEgressOpts({}).encoding, null, '默认路径零变化');
});

// ── ④ --charset：盲注字符类区间 ──────────────────────────────────────────

test('D202 --charset：默认区间与旧硬编码逐值等价；自定义集合收窄', () => {
  assert.deepEqual(charsetRanges(undefined), [[48, 57], [97, 122]]);
  assert.deepEqual(charsetRanges(''), [[48, 57], [97, 122]]);
  assert.deepEqual(charsetRanges('0123456789abcdef'), [[48, 57], [97, 102]]);
  assert.deepEqual(charsetRanges('aa00'), [[48, 48], [97, 97]], '去重 + 区间拆分');
  assert.deepEqual(charsetRanges('aabb00'), [[48, 48], [97, 98]], '连续码值合并为一段');
  assert.deepEqual(charsetRanges('😀'), [[48, 57], [97, 122]], '非单字节码值全部丢弃 → 默认');
  assert.ok(charsetRanges('0a2b4c6d8e0f1g3h5i7j9k').length <= 8, '区间数硬上限 8，防请求放大');
});

test('D202 --charset：classProbeStep 命中收窄 / 未命中推进 / 全不中回退全区间', () => {
  const ranges = [[48, 57], [97, 102]];
  const hit = { lo: 0, hi: 255, phase: 'cls', clsIdx: 0 };
  classProbeStep(hit, true, ranges);
  assert.deepEqual([hit.lo, hit.hi, hit.phase], [48, 57, 'bisect']);
  const miss = { lo: 0, hi: 255, phase: 'cls', clsIdx: 0 };
  classProbeStep(miss, false, ranges);
  assert.equal(miss.clsIdx, 1);
  assert.equal(miss.phase, 'cls');
  classProbeStep(miss, false, ranges);
  assert.deepEqual([miss.lo, miss.hi, miss.phase], [0, 255, 'bisect'], '回退全区间二分');
});

// ── ⑤ --fingerprint / --os 落点 ──────────────────────────────────────────

test('D202 buildFingerprint：汇总已采集信号，未指定 OS 不推断（不编造）', () => {
  const report = { summary: { dbmsEvidence: { level: 'verified' } } };
  const points = [{ dbms: 'MySQL', dbmsVersion: '8.0.28' }];
  const waf = new Map([['ModSecurity', {}]]);
  const fp = buildFingerprint({ report, pointsToScan: points, wafAgg: waf, config: { os: 'linux', encoding: 'gbk' }, dbms: 'MySQL' });
  assert.equal(fp.dbms, 'MySQL');
  assert.equal(fp.dbmsVersion, '8.0.28');
  assert.equal(fp.dbmsEvidenceLevel, 'verified');
  assert.equal(fp.os, 'linux');
  assert.equal(fp.osSource, 'explicit');
  assert.deepEqual(fp.wafVendors, ['ModSecurity']);
  const bare = buildFingerprint({ pointsToScan: points });
  assert.equal(bare.os, null);
  assert.equal(bare.osSource, 'unspecified');
  assert.match(bare.caveat, /未做主动指纹探测/);
});

test('D202 接线守卫（剔注释）：四项真的被调度层调用', () => {
  const be = code('server/src/engine/blindExtractor.js');
  assert.match(be, /charsetRanges\(ctx\.config && ctx\.config\.charset\)/);
  assert.match(be, /classProbeStep\(s, ok, ranges\)/);
  assert.match(be, /ranges\[s\.clsIdx\]/);
  const fin = code('server/src/engine/scan/finalize.js');
  assert.match(fin, /target\.config\?\.fingerprint === true/);
  assert.match(fin, /buildFingerprint\(\{ report, pointsToScan, wafAgg/);
  const cli = code('server/bin/cli.js');
  assert.match(cli, /udfInstall\(ctx, \{ hexPath: args\.udfHex, platform: ctx\.config\?\.os \|\| args\.os \}\)/);
  const codec = code('server/src/core/http/responseCodec.js');
  assert.match(codec, /normalizeCharsetLabel\(opts && opts\.encoding/);
  assert.match(codec, /decodeResponseBody\(raw, res\.headers, \{ encoding: opts && opts\.encoding \}\)/);
  const tr = code('server/src/core/http/transport.js');
  assert.match(tr, /decodeResponseBody\(raw, resHeaders, \{ encoding: opts\.encoding \}\)/);
  const eg = code('server/src/engine/egressOpts.js');
  assert.match(eg, /encoding: cfg\.encoding \?\? null/);
});
