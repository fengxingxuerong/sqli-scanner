// ============================================================================
// d199WireToggles.test.js —— [D199] 协议形态与宿主钩子七件（对标 sqlmap）
//
// 覆盖：--chunked / --skip-urlencode / --skip-xmlencode / --skip-waf /
//       --retry-on / --crawl-exclude / --alert
// 口径：零网络。能真调的函数一律真调（parseArgs/buildConfig/sanitizeStart/
//       buildEgressOpts/buildInjectionRequest/serializeXml/LinkCrawler/纯判据）；
//       不便真调的调度层用**剔注释后的源码接线守卫**钉住，防「实现在、没人调」。
// 负向判据是重点：值型缺值硬拒、alert 不进 config 档案/REST、默认路径零变化。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { parseArgs } from '../bin/cli/args.js';
import { buildConfig } from '../bin/cli/config.js';
import { buildKnownArgKeys } from '../bin/cli/configFile.js';
import { validateAlertCommand, runAlert, MAX_ALERT_CMD } from '../bin/cli/alert.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';
import { buildEgressOpts } from '../src/engine/egressOpts.js';
import { buildInjectionRequest } from '../src/engine/injection.js';
import { parseXmlBody, setXmlLeaf, serializeXml } from '../src/core/xmlBody.js';
import { LinkCrawler } from '../src/engine/crawler.js';
import { applyChunkedBody } from '../src/core/http/transport.js';
import { compileRetryOn, shouldRetryOnStatus } from '../src/core/http/retryOn.js';

const URL0 = 'http://127.0.0.1:9/?q=';
const ROOT = new URL('../..', import.meta.url); // server/tests/ → 仓库根
const read = (rel) => readFileSync(new URL(rel, ROOT), 'utf8');
// 判据文本源必须剔注释；顺序固定「先行注释、后块注释」（runbook 第四次栽的坑）。
const strip = (s) => s.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
const code = (rel) => strip(read(rel));

const ALL = [
  '-u', URL0, '--chunked', '--skip-urlencode', '--skip-xmlencode', '--skip-waf',
  '--retry-on', '408|429|50[23]', '--crawl-exclude', 'logout|admin', '--alert', 'echo HIT',
];

// ── ① 参数面 ──────────────────────────────────────────────────────────────

test('D199 parseArgs：七旗标全部消费、值型取到值、不落 unknownFlags', () => {
  const a = parseArgs(ALL);
  assert.equal(a.chunked, true);
  assert.equal(a.skipUrlencode, true);
  assert.equal(a.skipXmlencode, true);
  assert.equal(a.skipWaf, true);
  assert.equal(a.retryOn, '408|429|50[23]');
  assert.equal(a.crawlExclude, 'logout|admin');
  assert.equal(a.alert, 'echo HIT');
  assert.deepEqual(a.unknownFlags, []);
});

test('D199 buildConfig：六键进 config，alert 刻意不落 config（宿主动作只认 argv）', () => {
  const c = buildConfig(parseArgs(ALL));
  assert.equal(c.chunked, true);
  assert.equal(c.skipUrlencode, true);
  assert.equal(c.skipXmlencode, true);
  assert.equal(c.skipWaf, true);
  assert.equal(c.retryOn, '408|429|50[23]');
  assert.equal(c.crawlExclude, 'logout|admin');
  assert.equal(c.alert, undefined, 'alert 绝不能进扫描 config（否则 --config/REST 可触发宿主动作）');
});

test('D199 负向：三个值型旗标缺值即拒启（收参数不生效是红线）', () => {
  assert.throws(() => buildConfig(parseArgs(['-u', URL0, '--retry-on'])), /--retry-on 需要值/);
  assert.throws(() => buildConfig(parseArgs(['-u', URL0, '--crawl-exclude'])), /--crawl-exclude 需要值/);
  assert.throws(() => buildConfig(parseArgs(['-u', URL0, '--alert'])), /--alert 需要值/);
});

test('D199 负向：非法正则启动期硬拒（不把 parse 错误留到扫描中途）', () => {
  assert.throws(() => buildConfig(parseArgs(['-u', URL0, '--retry-on', '['])), /--retry-on 正则无效/);
  assert.throws(() => buildConfig(parseArgs(['-u', URL0, '--crawl-exclude', '('])), /--crawl-exclude 正则无效/);
});

test('D199 validateAlertCommand：长度/换行硬拒，合法串原样返回', () => {
  assert.equal(validateAlertCommand('echo HIT'), 'echo HIT');
  assert.equal(validateAlertCommand(undefined), null);
  assert.throws(() => validateAlertCommand(true), /需要值/);
  assert.throws(() => validateAlertCommand('x'.repeat(MAX_ALERT_CMD + 1)), /过长/);
  assert.throws(() => validateAlertCommand('echo a\necho b'), /换行/);
});

test('D199 configFile：六键可写档案，alert 不在合法键集（外来 JSON 不能触发宿主动作）', () => {
  const known = buildKnownArgKeys(parseArgs);
  for (const k of ['chunked', 'skipUrlencode', 'skipXmlencode', 'skipWaf', 'retryOn', 'crawlExclude']) {
    assert.ok(known.has(k), `KNOWN_ARG_KEYS 缺 ${k} ⇒ --config 档案会被未知键硬拒`);
  }
  assert.equal(known.has('alert'), false);
});

// ── ② REST 入口 ───────────────────────────────────────────────────────────

test('D199 REST：六键白名单 + 透传（真调 sanitizeStart），alert 不在白名单', () => {
  const cfg = {
    chunked: true, skipUrlencode: true, skipXmlencode: true, skipWaf: true,
    retryOn: '503', crawlExclude: 'logout',
  };
  const out = sanitizeStart({ target: { url: 'http://shop.example.com/item?id=1' }, config: cfg }).config;
  for (const k of Object.keys(cfg)) assert.equal(out[k], cfg[k], `${k} 未透传`);
  const src = read('server/src/api/scanRoutes.js');
  const block = src.match(/const KNOWN_CFG_KEYS = new Set\(\[([\s\S]*?)\]\)/)[1];
  assert.ok(!/'(alert)'/.test(strip(block)), 'alert 不得出现在 REST 白名单');
});

test('D199 REST 负向：布尔键拒绝 truthy 非布尔、正则键拒绝非法表达式', () => {
  const base = { target: { url: 'http://shop.example.com/item?id=1' } };
  assert.throws(() => sanitizeStart({ ...base, config: { chunked: 1 } }), /仅支持布尔/);
  assert.throws(() => sanitizeStart({ ...base, config: { skipWaf: 'true' } }), /仅支持布尔/);
  assert.throws(() => sanitizeStart({ ...base, config: { retryOn: '[' } }), /正则无效/);
  assert.throws(() => sanitizeStart({ ...base, config: { crawlExclude: 7 } }), /仅支持/);
});

// ── ③ 引擎消费面 ─────────────────────────────────────────────────────────

test('D199 egress：retryOn / chunked 经受治出口清单同源透传', () => {
  const o = buildEgressOpts({ retryOn: '503', chunked: true });
  assert.equal(o.retryOn, '503');
  assert.equal(o.chunked, true);
  const zero = buildEgressOpts({});
  assert.equal(zero.retryOn, null);
  assert.equal(zero.chunked, false, '默认路径必须零变化');
});

test('D199 skip-urlencode：注入值不做百分号编码；--param-del 旧分支不回归', () => {
  const mk = (config, baseUrl) => ({
    method: 'GET', baseUrl, headerParams: {}, cookieParams: {}, bodyParams: {}, config,
  });
  const point = { location: 'url', param: 'id', originalValue: '1' };
  const raw = "1' AND 1=1";
  const plain = buildInjectionRequest(mk({}, 'http://x.com/p?id=1&b=2'), point, raw);
  assert.ok(plain.url.includes('%27'), `默认路径应做百分号编码：${plain.url}`);
  const skipped = buildInjectionRequest(mk({ skipUrlencode: true }, 'http://x.com/p?id=1&b=2'), point, raw);
  assert.ok(skipped.url.includes("id=1' AND 1=1"), `skip 后应为原始字节：${skipped.url}`);
  assert.ok(!skipped.url.includes('%27'), 'skip 后不得再编码');
  assert.ok(skipped.url.includes('b=2'), '伴随参数不能丢（D112 静默假阴性同型）');
  // 语法修复回归：半写版把 const paramDel 塞进 else-if 分支内部 ⇒ 整文件语法错
  const del = buildInjectionRequest(mk({ paramDel: ';' }, 'http://x.com/p?id=1;b=2'), point, raw);
  assert.ok(del.url.includes(';b=2'), `param-del 分支被破坏：${del.url}`);
});

test('D199 skip-xmlencode：序列化可跳过实体转义，默认仍转义', () => {
  const tree = parseXmlBody('<GetUser><id>1</id></GetUser>').tree;
  assert.equal(setXmlLeaf(tree, 'GetUser.id', "1' AND <x>&"), true);
  assert.match(serializeXml(tree), /&apos;.*&lt;x&gt;.*&amp;/, '默认必须转义');
  const noEnc = serializeXml(tree, { skipEncode: true });
  assert.ok(noEnc.includes("1' AND <x>&"), `skip 后应保留原始字节：${noEnc}`);
});

test('D199 crawl-exclude：排除正则命中的链接不入队、不取页（真调 LinkCrawler）', async () => {
  const pages = {
    'https://x.com/': '<a href="/list?id=1">list</a><a href="/logout">out</a>',
    'https://x.com/list?id=1': '<a href="/admin/del?id=2">del</a>',
    'https://x.com/logout': '<p>bye</p>',
    'https://x.com/admin/del?id=2': '<p>deleted</p>',
  };
  const http = {
    async request({ url }) {
      if (pages[url] === undefined) throw new Error('not found: ' + url);
      return { data: pages[url], status: 200 };
    },
  };
  const crawler = new LinkCrawler({ httpClient: http, maxPagesPerDepth: 10, maxTotalPages: 20 });
  const r = await crawler.crawl({ baseUrl: 'https://x.com/', config: { crawlExclude: 'logout|admin' }, depth: 3 });
  const all = [...r.links, ...r.pages.map((p) => p.url)];
  assert.ok(!all.some((u) => /logout|admin/.test(u)), `排除正则未生效：${all.join(', ')}`);
  assert.ok(all.some((u) => u.includes('/list')), '未命中的正常链接仍应收录');
});

test('D199 crawl-exclude：非法正则降级为「不排除」（爬虫不整体停摆，真调 LinkCrawler）', async () => {
  const http = {
    async request({ url }) {
      return { data: url.endsWith('/') ? '<a href="/logout">out</a>' : '<p>ok</p>', status: 200 };
    },
  };
  const crawler = new LinkCrawler({ httpClient: http, maxPagesPerDepth: 10, maxTotalPages: 20 });
  const r = await crawler.crawl({ baseUrl: 'https://x.com/', config: { crawlExclude: '[' }, depth: 2 });
  assert.ok(r.links.some((u) => u.includes('/logout')), '非法表达式应降级为不排除，而非吞掉链接');
});

test('D199 retry-on 纯判据：命中即重试、余量用尽不重试、非法正则不启用', () => {
  const re = compileRetryOn('408|429|50[23]');
  assert.equal(shouldRetryOnStatus(re, { status: 503 }, 0, 2), true);
  assert.equal(shouldRetryOnStatus(re, { status: 200 }, 0, 2), false);
  assert.equal(shouldRetryOnStatus(re, { status: 503 }, 2, 2), false, '余量用尽必须交回最后响应');
  assert.equal(compileRetryOn('['), null);
  assert.equal(shouldRetryOnStatus(null, { status: 503 }, 0, 2), false);
  assert.equal(shouldRetryOnStatus(compileRetryOn('503'), { status: 503 }, 0, 0), false);
});

test('D199 chunked 纯判据：默认零变化；开启时字符串体转 Readable 且声明 TE', async () => {
  const headers = { 'content-type': 'application/x-www-form-urlencoded' };
  const off = applyChunkedBody({}, 'a=1&b=2', headers);
  assert.equal(off.data, 'a=1&b=2');
  assert.equal(off.headers, headers, '默认路径必须原对象返回（零行为变化）');
  const on = applyChunkedBody({ chunked: true }, 'a=1&b=2', headers);
  assert.equal(on.headers['Transfer-Encoding'], 'chunked');
  assert.notEqual(on.headers, headers, '不得污染原 headers');
  const chunks = [];
  for await (const c of on.data) chunks.push(c);
  assert.equal(chunks.map((c) => String(c)).join(''), 'a=1&b=2');
  const obj = applyChunkedBody({ chunked: true }, { a: 1 }, headers);
  assert.deepEqual(obj.data, { a: 1 }, '对象体不改道');
  const empty = applyChunkedBody({ chunked: true }, '', headers);
  assert.equal(empty.data, '', '空体不改道');
});

test('D199 接线守卫（剔注释）：retry-on/chunked/alert/skip-waf 真的被调度层调用', () => {
  const hc = code('server/src/core/httpClient.js');
  assert.match(hc, /const retryOnRe = compileRetryOn\(opts\.retryOn\)/);
  assert.match(hc, /shouldRetryOnStatus\(retryOnRe, res, attempt, retry\)/);
  const tr = code('server/src/core/http/transport.js');
  assert.match(tr, /const chunked = applyChunkedBody\(opts, opts\.data, headers\)/);
  assert.match(tr, /data: chunked\.data/);
  const out = code('server/bin/cli/reportOutput.js');
  assert.match(out, /runAlert\(report, args\)/);
  const det = code('server/src/engine/scan/detect.js');
  assert.match(det, /if \(cfg\.skipWaf === true\) return \[\]/, 'skip-waf 总闸必须在识别函数里');
  assert.match(det, /cfg\.skipWaf !== true\s*&& cfg\.activeWafProbe === true/, '主动探测也受总闸约束');
  assert.match(det, /const wafCands = wafCandidates\(sm, cfg, fpResult\)/);
  assert.match(det, /if \(shouldActiveWafProbe\(cfg, wafCands, target\)\)/);
});

// ── ④ 宿主钩子 ───────────────────────────────────────────────────────────

test('D199 --alert：仅命中时触发；命令不含目标数据；失败不影响结论', () => {
  const calls = [];
  const spawn = (cmd, opts) => { calls.push({ cmd, opts }); return { unref() {} }; };
  const report = { vulns: [{ id: 1, url: 'http://target.example/a?id=1' }], riskLevel: 'High' };
  assert.equal(runAlert({ vulns: [] }, { alert: 'echo HIT' }, { spawn }).fired, false, '无命中不得执行');
  assert.equal(runAlert(report, {}, { spawn }).fired, false, '未配置不得执行');
  const r = runAlert(report, { alert: 'echo HIT' }, { spawn, env: { PATH: 'x' } });
  assert.equal(r.fired, true);
  assert.equal(r.findings, 1);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].cmd, 'echo HIT', '命令必须是 argv 字面量，不插值任何目标可控数据');
  assert.ok(!calls[0].cmd.includes('target.example'));
  assert.equal(calls[0].opts.env.SQLI_ALERT_FINDINGS, '1');
  assert.equal(calls[0].opts.env.SQLI_ALERT_RISK, 'High');
  assert.equal(calls[0].opts.stdio, 'ignore');
  const bad = runAlert(report, { alert: 'echo HIT' }, { spawn: () => { throw new Error('spawn fail'); } });
  assert.equal(bad.fired, false);
  assert.equal(bad.reason, 'spawn-failed');
});

test('D199 安全边界守卫（剔注释）：alert 既不在档案键表也不在 REST 白名单', () => {
  const cf = code('server/bin/cli/configFile.js');
  assert.ok(!/'alert'/.test(cf), 'configFile 的动态键表不得收录 alert');
  const cfg = code('server/bin/cli/config.js');
  assert.ok(!/\bconfig\.alert\s*=/.test(cfg), 'config 构建不得落地 alert');
});
