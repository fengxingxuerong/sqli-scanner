// ============================================================================
// tests/tamperHeaderInjectionSingleSource.test.js
// 写请求头的 tamper 插件必须走同一个 header 注入契约，且该契约在引擎真实链路上生效
//
// ── 缺陷（实测确认，非推理）──────────────────────────────────────────────────
// core/tamper/plugins/ 下有 4 个写请求头的插件，但存在**两套不同的注入契约**：
//
//   varnish.js / xforwardedfor.js —— 完整实现
//     if (ctx && ctx.headers && typeof ctx.headers === 'object') return ctx.headers;
//     if (ctx && ctx.target && typeof ctx.target === 'object') {
//       ctx.target.headerParams = ctx.target.headerParams || {};
//       return ctx.target.headerParams;
//     }
//     return null;
//
//   agent.js / arges.js —— 只读 ctx.headers，**无回退**
//     if (ctx && ctx.headers) { ctx.headers['User-Agent'] = ... }
//
// 而引擎传给插件的 ctx 来自 obfuscateWithConfig → applyTampers → _runChain，
// 它的真实形态是检测器上下文：
//     { httpClient, target, point, dbms, config }
// **根本没有 ctx.headers 这个顶层键**（实测 `'headers' in ctx === false`）。
// 引擎读请求头走的是 buildInjectionRequest，它展开的是 **target.headerParams**
// （实测：target.headerParams 里的头确实出现在 req.headers 中）。
//
// 实测（引擎真实 ctx，走 obfuscateWithConfig）：
//   插件 [agent]         → headerParams 写前 {} 写后 {}  ❌ 头全部丢失
//   插件 [arges]         → headerParams 写前 {} 写后 {}  ❌ 头全部丢失
//   插件 [varnish]       → 写入 X-originating-IP        ✅
//   插件 [xforwardedfor] → 写入 7 个头                    ✅
//
// 方向是**降低检出能力**：agent 是伪装 User-Agent（识别扫描器的第一道特征，
// 没它每个请求都带着引擎默认 UA），arges 是伪造来源 IP。两者在真实链路上
// **静默失效** —— 不报错、不告警，插件看起来"已启用"。
//
// 这正是 core/http/ipBytes.js 注释里警告的形态：
//   「同一判据多份实现，一份修了另一份没修」——本仓反复吃过这个亏。
//
// ── 修法 ────────────────────────────────────────────────────────────────────
// 把注入契约收敛到**单一真源** plugins/_headerSink.js（与 quoteScan.js 同一思路）：
//   headerSink(ctx) —— ctx.headers 优先，回退 target.headerParams，都没有则 null
// 4 个插件全部改调它。并加一条守卫钉住"不得再出现第四份实现"。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { obfuscateWithConfig } from '../src/core/tamper/applyTampers.js';
import { buildInjectionRequest } from '../src/engine/injection.js';

// ⚠️ PLUGIN_DIR 必须用 fileURLToPath，不能手写 `.pathname.replace(/^\//, '')`：
// 那写法在 Windows 下会产出 `D:/projects/server/...`（少了仓库目录名 ——
// 多退了一层），目录扫描于是**扫的是不存在的路径**，而 readdirSync 抛错被
// readdirSyncSafe 之外的 try 吞掉 ⇒ 契约-4/5 变成"扫了 0 个文件"的假绿。
// 缺陷注入⑥（新造第 5 个私藏副本的插件）当时就是因此全绿。
import { fileURLToPath } from 'node:url';
const PLUGIN_DIR = fileURLToPath(new URL('../src/core/tamper/plugins/', import.meta.url));
const srcOf = (n) => readFileSync(join(PLUGIN_DIR, `${n}.js`), 'utf8');
// 单一真源放在 tamper/ 下（不在 plugins/ 里）—— plugins/ 的每个文件都要注册到
// tamperRegistry，共享工具放进去会被 tamperPluginCount.guard.test.js 判为
// "能写不能用 = 能力缺失"。所以这里只按**文件名**排它，不按目录。
const SINK_FILE = '_headerSink.js';
const isSink = (f) => f === SINK_FILE || f === 'headerSink.js';

/** 引擎真实形态的检测器上下文（无 ctx.headers 顶层键） */
function realCtx(plugins) {
  return {
    httpClient: { async request() { return { status: 200, data: '' }; } },
    target: { method: 'GET', baseUrl: 'http://127.0.0.1:9/', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { wafEvasion: { tamper: { enabled: true, plugins } } },
  };
}

/** 跑一次 tamper 链，返回 { payload, headerParams } */
function runChain(plugins) {
  const ctx = realCtx(plugins);
  const payload = obfuscateWithConfig('1 AND 1=1-- -', ctx);
  return { payload, headerParams: ctx.target.headerParams, ctx };
}

test('自证-0a) 目录扫描真的扫到了插件（PLUGIN_DIR 路径写错会让本组守卫全成假绿）', () => {
  // 背景：PLUGIN_DIR 曾误写成 `D:/projects/server/...`（少一层目录名），
  // readdirSync 对不存在的路径抛错、被契约-4/5 各自的 try 吞掉 ⇒
  // "扫了 0 个文件 ⇒ 无违规 ⇒ 全绿"。缺陷注入⑥当时就是这样溜过去的。
  const files = readdirSync(PLUGIN_DIR).filter((f) => f.endsWith('.js') && !isSink(f));
  assert.ok(files.length > 200,
    `只扫到 ${files.length} 个插件文件（PLUGIN_DIR=${PLUGIN_DIR}）—— 目录扫描是失效的，`
    + '契约-4/5 会假绿');
  assert.ok(files.includes('agent.js') && files.includes('arges.js'),
    '已知插件没被扫到 —— 目录扫描不可信');
  // 真源不得回到 plugins/ 下：那里每个文件都要注册到 tamperRegistry，
  // 放进去会被 tamperPluginCount.guard.test.js 判为"能写不能用"。
  assert.ok(!readdirSync(PLUGIN_DIR).includes('headerSink.js'),
    'headerSink.js 出现在 plugins/ 下 —— 会被插件总数守卫判为未注册的能力缺失');
});

test('自证-0) 引擎 ctx 确实没有 ctx.headers 顶层键（否则本组守卫的前提失效）', () => {
  const ctx = realCtx([]);
  assert.equal('headers' in ctx, false,
    '测试搭的 ctx 里居然有 headers —— 与引擎真实形态不符，本组守卫全部无效');
  assert.ok(buildInjectionRequest, 'buildInjectionRequest 不可用');
});

test('契约-0) target.headerParams 确实是引擎会展开的那一份（实测 buildInjectionRequest）', () => {
  const target = {
    method: 'GET', baseUrl: 'http://127.0.0.1:9/', headerParams: {}, cookieParams: {},
  };
  target.headerParams = { 'X-Originating-Ip': '127.0.0.1' };
  const req = buildInjectionRequest(target, { location: 'url', param: 'id', value: '1' }, '1');
  const keys = Object.keys(req.headers || {}).map((k) => k.toLowerCase());
  assert.ok(keys.includes('x-originating-ip'),
    `target.headerParams 的头没出现在 req.headers（键：${keys.join(',')}）—— 前提不成立`);
});

test('缺陷-1) agent 插件在引擎真实链路上必须真的写入 User-Agent', () => {
  const { headerParams } = runChain(['agent']);
  assert.ok(headerParams['User-Agent'],
    `agent 在真实 ctx 下头全部丢失（headerParams=${JSON.stringify(headerParams)}）—— UA 伪装静默失效`);
});

test('缺陷-2) arges 插件在引擎真实链路上必须真的写入 X-Forwarded-For', () => {
  const { headerParams } = runChain(['arges']);
  assert.ok(headerParams['X-Forwarded-For'],
    `arges 在真实 ctx 下头全部丢失（headerParams=${JSON.stringify(headerParams)}）—— IP 伪造静默失效`);
});

test('契约-3) 四个写头插件在同一 ctx 下行为必须一致（不得再有分叉实现）', () => {
  const PLUGINS = [
    ['agent', 'User-Agent'],
    ['arges', 'X-Forwarded-For'],
    ['varnish', 'X-originating-IP'],
    ['xforwardedfor', 'X-Forwarded-For'],
  ];
  const missing = PLUGINS
    .map(([name, key]) => [name, key, runChain([name]).headerParams[key]])
    .filter(([, , v]) => !v);
  assert.equal(missing.length, 0,
    `这些插件在引擎真实 ctx 下没写入头：${missing.map(([n, k]) => `${n}(${k})`).join(', ')}`);
});

test('契约-4) 任何写请求头的插件都必须走 headerSink（不得再有第 5 个私藏副本）', () => {
  // ⚠️ 过滤条件只排 _headerSink.js 这**一个文件**，不能排所有 `_` 开头的文件。
  // 第一版写的是 `!f.startsWith('_')`，于是任何下划线开头的私藏副本都能溜过去 ——
  // 缺陷注入⑥（新造 __probe.js）当时就是这样全绿的。
  //   实测：__probe.js 里 `ctx.headers["X-Probe"]="1"` 明明能被 WRITE_HEAD 抓到，
  //   只因它以 `_` 开头就被跳过了。
  const WRITE_HEAD = /headers\s*\[|headers\s*\.\w+\s*=|headerParams\s*\[/;
  const USES_SINK = /headerSink\s*\(/;
  const offenders = [];
  for (const f of readdirSync(PLUGIN_DIR)) {
    if (!f.endsWith('.js') || isSink(f)) continue;   // 只排单一真源自己
    const code = srcOf(f.replace(/\.js$/, '')).replace(/^\s*(?:\/\/|\*).*$/gm, '');
    if (WRITE_HEAD.test(code) && !USES_SINK.test(code)) offenders.push(f);
  }
  assert.equal(offenders.length, 0,
    `这些插件在写请求头但没走 headerSink 单一真源：${offenders.join(', ')}`);
});

test('契约-5) 不得再出现本地实现的 ensureHeaders 副本（单一真源）', () => {
  const dup = readdirSync(PLUGIN_DIR)
    .filter((f) => f.endsWith('.js') && !isSink(f))   // 同上：只排真源自己
    .filter((f) => /^function ensureHeaders|^const ensureHeaders/m.test(srcOf(f.replace(/\.js$/, ''))));
  assert.equal(dup.length, 0,
    `这些插件各自持有一份 ensureHeaders 副本，应改调 headerSink：${dup.join(', ')}`);
});

test('契约-6) payload 不得被这些插件改动（它们只写头）', () => {
  for (const name of ['agent', 'arges', 'varnish', 'xforwardedfor']) {
    const { payload } = runChain([name]);
    assert.equal(payload, '1 AND 1=1-- -', `${name} 改动了 payload：${payload}`);
  }
});