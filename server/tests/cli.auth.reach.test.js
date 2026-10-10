// ============================================================================
// cli.auth.reach.test.js —— CLI 的认证参数必须**真的抵达出口**（批次 D36，实战 P0-3）
// ============================================================================
// 这条怎么来的（不是推演）：写 e2e/bearer-lab 时 A 对照组拿到 `authOk=0 / 401=70`，
// 也就是**靶站一条都没收到 Authorization**。查下来是链路断在中间一环：
//   bin/cli.js:273 把 buildAuth() 的结果作为**顶层字段**传给 sm.start(input)
//   而 createTarget() 只把 input.config 展开成 target.config —— input.auth 被原地丢掉
//   引擎侧三个读取点（egressOpts.js:85 / TargetParser.js:392 / crawler.js:176）读的都是 config.auth
// ⇒ `--auth alice:secret`、`--header 'Authorization: Bearer …'`、`--cookie`（认证那半）**全部静默失效**：
// 扫描照跑、报告照发，整站 401 的目标被写成「未检出 + 结论可信」。
//
// 本文件的判据刻意不止到 createTarget：一路走到 mergeAuthHeaders 的出参，
// 断的是"出口那条请求上有没有这个头"。既有 tests/cli.auth.test.js 只断 buildAuth 的返回形态 ——
// 那是「被调函数是对的、调用链下一环是坏的」的教科书案例（本仓反复出现的族）。
// ============================================================================
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { parseArgs, buildAuth } from '../bin/cli/args.js';
import { createTarget } from '../src/engine/models.js';
import { buildEgressOpts } from '../src/engine/egressOpts.js';
import { mergeAuthHeaders } from '../src/core/http/requestContext.js';

/** 复刻 cli.js 的装配顺序：parseArgs → buildAuth → createTarget → 出口 egress opts */
function wireUp(argv, extraConfig = {}) {
  const args = parseArgs(argv);
  const auth = buildAuth(args);
  const input = { url: args.url || 'http://t.test/api/item?id=1', method: 'GET', config: { ...extraConfig }, auth };
  const target = createTarget(input);
  // 检测器发每条请求时走的正是这两步（egress.js → httpClient.request → mergeAuthHeaders）
  const egress = buildEgressOpts(target.config, { method: 'GET', url: target.baseUrl, headers: {} });
  const headers = mergeAuthHeaders({}, egress.auth);
  return { args, auth, target, egress, headers };
}

describe('[cli.auth.reach] --auth / --header / --cookie 到出口', () => {
  test('--auth Basic：出口头里必须有 Authorization: Basic …', () => {
    const { headers, target } = wireUp(['-u', 'http://t.test/api/item?id=1', '--auth', 'alice:secret']);
    assert.ok(target.config.auth, 'createTarget 把顶层 auth 丢了 ⇒ 整条认证链断在这里');
    assert.equal(target.config.auth.basic.username, 'alice');
    assert.equal(
      headers.Authorization,
      `Basic ${Buffer.from('alice:secret').toString('base64')}`,
      'Basic 凭据没到出口：目标会整站 401，而报告写「未检出」',
    );
  });

  test('--header Authorization: Bearer …：出口必须原样带上这枚抓包令牌', () => {
    const { headers } = wireUp(['-u', 'http://t.test/api/item?id=1', '--header', 'Authorization: Bearer TOK-ABC']);
    assert.equal(headers.Authorization, 'Bearer TOK-ABC');
  });

  test('--header 自定义认证头（X-Api-Key）也要到出口（不只 Authorization 这一族）', () => {
    const { headers } = wireUp(['-u', 'http://t.test/api/item?id=1', '--header', 'X-Api-Key: kk123']);
    assert.equal(headers['X-Api-Key'], 'kk123');
  });

  test('--cookie 的认证那半：cookieParams 之外仍要作为 Cookie 头发出', () => {
    // --level 1 时 cookie 不会被升为注入点（level≥2 才生成 cookie 注入点），
    // 这一路靠 auth.cookie 把会话带出去 —— 之前这条也被丢了。
    const { headers } = wireUp(['-u', 'http://t.test/api/item?id=1', '--cookie', 'sid=XYZ']);
    assert.match(headers.Cookie || '', /sid=XYZ/);
  });

  test('多个头一次给（抓包重建的常见形态：Bearer + 租户头 + Cookie）', () => {
    const { headers } = wireUp([
      '-u', 'http://t.test/api/item?id=1',
      '--header', 'Authorization: Bearer T2',
      '--cookie', 'sid=S2',
    ]);
    assert.equal(headers.Authorization, 'Bearer T2');
    assert.match(headers.Cookie, /sid=S2/, 'auth.cookie 与自定义头必须共存，不能互相吃掉');
  });

  test('反向：什么都没配时 config.auth 仍是 null（零配置零行为变化）', () => {
    const { target, headers } = wireUp(['-u', 'http://t.test/api/item?id=1']);
    assert.equal(target.config.auth, null, '未配认证却被写成 {} 会让下游判据误以为"带凭据扫过了"');
    assert.equal(headers.Authorization, undefined);
  });

  test('优先级：config.auth 已给出时赢过顶层 auth（REST 侧就是走 config）', () => {
    const args = parseArgs(['-u', 'http://t.test/api/item?id=1', '--auth', 'cli:cli']);
    const top = buildAuth(args);
    const target = createTarget({
      url: 'http://t.test/api/item?id=1',
      auth: top,
      config: { auth: { headers: { Authorization: 'Bearer FROM-CONFIG' } } },
    });
    assert.equal(target.config.auth.headers.Authorization, 'Bearer FROM-CONFIG');
  });

  test('直连模式（-d）不碰 HTTP 认证面，但也不得因此抛错', () => {
    const target = createTarget({
      mode: 'direct',
      connectionString: 'memory://x',
      sqlTemplate: 'SELECT * FROM t WHERE id={INJECT}',
      auth: { headers: { Authorization: 'Bearer IGNORED' } },
      config: {},
    });
    assert.equal(target.mode, 'direct');
    assert.equal(target.config.headers, undefined);
  });
});
