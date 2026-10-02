// ============================================================================
// cli.login.test.js —— 登录编排的 CLI 入口层（批次14 实战 P1-6）
// ============================================================================
// 为什么单独钉这一层：引擎（core/loginFlow.js）与 REST 入口（guardLogin + 白名单透传）
// 各自有守卫，但 `--login-url` → config.login 这一段是第三条独立路径，且凭据来自
// 复用 --auth —— 少拼一个键的结果是「扫描照跑、登录静默不发生」，只有入口层能抓。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, buildConfig } from '../bin/cli.js';

test('parseArgs: --login-url 与两个字段名覆盖解析；缺省为 null（零回归）', () => {
  const bare = parseArgs(['-u', 'http://x/?id=1']);
  assert.equal(bare.loginUrl, null);
  assert.equal(bare.loginUserField, null);
  assert.equal(bare.loginPassField, null);

  const a = parseArgs([
    '-u', 'http://x/?id=1',
    '--login-url', 'http://x/login',
    '--login-user-field', 'uname',
    '--login-pass-field', 'pwd',
    '--dbs', // 不被吞
  ]);
  assert.equal(a.loginUrl, 'http://x/login');
  assert.equal(a.loginUserField, 'uname');
  assert.equal(a.loginPassField, 'pwd');
  assert.equal(a.dbs, true);
});

test('buildConfig: --login-url + --auth user:pass → config.login 四要素齐备', () => {
  const cfg = buildConfig(parseArgs([
    '-u', 'http://x/?id=1', '--login-url', 'http://x/login', '--auth', 'admin:s3cret',
  ]));
  assert.ok(cfg.login && typeof cfg.login === 'object', 'config.login 未建立');
  assert.equal(cfg.login.url, 'http://x/login');
  assert.equal(cfg.login.username, 'admin');
  assert.equal(cfg.login.password, 's3cret');
  // 字段名缺省不下发 —— 引擎按登录页 HTML 自动探测（detectLoginFields）
  assert.equal(cfg.login.usernameField, undefined);
  assert.equal(cfg.login.passwordField, undefined);
});

test('buildConfig: 显式字段名覆盖落到 config.login（非常规表单靠它兜底）', () => {
  const cfg = buildConfig(parseArgs([
    '-u', 'http://x/?id=1', '--login-url', 'http://x/login', '--auth', 'a:b',
    '--login-user-field', 'mail', '--login-pass-field', 'pass',
  ]));
  assert.equal(cfg.login.usernameField, 'mail');
  assert.equal(cfg.login.passwordField, 'pass');
});

test('buildConfig: 只给 --login-url 不给凭据 → 当场抛错，不静默降级', () => {
  assert.throws(
    () => buildConfig(parseArgs(['-u', 'http://x/?id=1', '--login-url', 'http://x/login'])),
    /--login-url/,
    '无凭据的登录编排必须报错（否则用户以为在自动登录）'
  );
});
