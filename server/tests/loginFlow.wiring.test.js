// ============================================================================
// loginFlow.wiring.test.js —— 登录编排这条链必须**五方都在**
//
// 本仓纪律（写测试必须接线，否则等于没写）：一处能力 = 判据 + 生产调用点 + 白名单 +
// CLI 登记 + 前端类型。单测（loginFlow.test.js / cli.login.test.js）验的是模块语义，
// 本文件验的是「这些语义有没有真的接进产品」—— 缺任何一处，能力都在库里但用户到不了。
//
// 判据一律用**源码文本**而不是 import：把 scanClient 跑起来会创建 HttpClient 单例，
// 把 scanConfigGuard 跑起来要构造整个 REST 上下文。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const read = (rel) => readFileSync(path.join(REPO, rel), 'utf8');

const scanClient = read('server/src/engine/scan/scanClient.js');
const guardChain = read('server/src/api/scanConfigGuard.js');
const objectGroups = read('server/src/api/scanGuard/objectGroups.js');
const routes = read('server/src/api/scanRoutes.js');
const args = read('server/bin/cli/args.js');
const config = read('server/bin/cli/config.js');
const loginFlow = read('server/src/core/loginFlow.js');
const constants = read('src/shared/constants.ts');

test('① 生产调用点：getScanClient 真的挂了 withLoginFlow', () => {
  assert.match(scanClient, /core\/loginFlow\.js/, 'scanClient 没有 import loginFlow');
  assert.match(scanClient, /withLoginFlow\(view, cfg\.login\)/, 'withLoginFlow 没包在 per-scan 视图上');
  // 门必须带 username：无凭据的登录编排没有意义（与 guardLogin 的收紧口径一致）
  assert.match(scanClient, /cfg\.login\.username/, '登录包装的开启条件缺 username 判定');
});

test('② 守卫：guardLogin 挂在 config guard 链上（不是写了没人调）', () => {
  assert.match(objectGroups, /export function guardLogin/, 'guardLogin 不见了');
  assert.match(guardChain, /guardLogin,/, 'guardLogin 没进 import 列表');
  assert.match(guardChain, /guardLogin\(config, cfg\);/, 'guardLogin 没在链上被调用');
});

test('③ 白名单：login 进 REST 的 KNOWN_CFG_KEYS（否则整键被拒）', () => {
  assert.match(routes, /'login',/, "scanRoutes 的 KNOWN_CFG_KEYS 缺 'login'");
});

test('④ CLI：三个开关登记在 args.js（未登记 ⇒ 被记成 unknownFlag 硬失败）', () => {
  for (const f of ['--login-url', '--login-user-field', '--login-pass-field']) {
    assert.match(args, new RegExp(`a === '${f}'`), `${f} 没在 args.js 登记`);
  }
  // 无凭据必须**当场抛错**，不能静默降级
  assert.match(config, /--login-url 需要 --auth user:pass/, 'buildConfig 缺「无凭据即抛错」的守卫');
});

test('⑤ 前端：login 进 SCAN_CONFIG_KEYS 与值类型表（否则 UI 契约守卫会红）', () => {
  assert.match(constants, /'login',/, "SCAN_CONFIG_KEYS 缺 'login'");
  const seg = constants.slice(constants.indexOf('SCAN_CONFIG_VALUE_TYPES'));
  assert.match(seg, /\n\s+login: 'object',/, "SCAN_CONFIG_VALUE_TYPES 缺 login: 'object'");
});

test('⑥ 安全语义：登录请求必须走**传入的 per-scan client**，不得自建 HttpClient', () => {
  // 自建 client 会绕过 per-scan 的 SSRF 校验 / scope 逐跳校验 / 限速桶 ——
  // 登录页 URL 来自配置（网络可达的输入面），这一条是硬要求不是风格。
  assert.doesNotMatch(loginFlow, /new HttpClient\(/, 'loginFlow 自建了 HttpClient ⇒ 绕开 per-scan 校验链');
  assert.match(loginFlow, /client\.request\(\{ method: 'GET', url \}\)/, '登录取页没走传入的 client');
  assert.match(loginFlow, /client\.request\(\{\s*\n\s*method: 'POST',/, '登录提交没走传入的 client');
});

test('⑦ 安全语义：凭据不落日志（只打字段名与状态码）', () => {
  // 密码进日志 = 凭据泄漏到报告/事件流里。logger 调用里不得出现 login.password / 整个 login 对象。
  const logLines = loginFlow.split('\n').filter((l) => /logger\.(info|warn|error)\(/.test(l));
  assert.ok(logLines.length > 0, '解析不到 logger 调用（取数源失效）');
  for (const l of logLines) {
    // 注意 `usernameField` / `passwordField` 是**字段名**不是凭据，允许出现在日志里
    // （它们正是排查时需要的）；要拦的是 username / password 的值本身。
    assert.doesNotMatch(
      l,
      /login\.password(?!Field)|login\.username(?!Field)|\{login\}|JSON\.stringify\(login\)/,
      `日志行带了凭据：${l.trim()}`,
    );
  }
});
