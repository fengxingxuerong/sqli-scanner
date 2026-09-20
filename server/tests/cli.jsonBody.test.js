// ============================================================================
// cli.jsonBody.test.js —— body 通道：嵌套 JSON 必须变成可注入的叶子点（CLI 与 REST 各一侧）
// ============================================================================
// 缺陷（2026-09-20 实测）：help.js 写 --body 是「JSON 对象字符串」，但 CLI 一律摊进
// bodyParams，而 TargetParser 对每个 body 值做 String(v)：
//   --body '{"user":{"id":1},"tags":["a","b"]}'
//   → body:user = "[object Object]"、body:tags = "a,b"   ← 两个结构上不可能注入的点
// 同一份 body 走 REST 的 jsonBody：
//   → body:user.id / user.name / tags.0 / tags.1          ← 4 个真叶子点
// 于是「嵌套 JSON 注入点只有 REST 用户测得到」。引擎侧 _discoverJsonLeaves 早就有，
// 断的是 CLI 的接线 —— 与同批修的 KNOWN_CFG_KEYS 是同一类问题（能力在引擎、入口收不到）。
//
// 这里刻意**不只测纯函数**：resolveBodyChannel 单测即使全绿，也挡不住 runSingleScan
// 忘了把 jsonBody 放进交给引擎的 input。所以主用例走 parseArgs(argv) → runSingleScan
// → 捕获真正递给 ScanManager.start() 的那个对象，再接 TargetParser 看注入点。
// 这才是"接线"被验过。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, runSingleScan, resolveBodyChannel } from '../bin/cli.js';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';

const URL = 'http://127.0.0.1:9999/api/order';

/** 用真实 CLI 入口跑一遍 argv，捕获递给 ScanManager.start() 的 input（不让真扫描发生）。 */
async function inputFromArgv(argv) {
  const args = parseArgs(argv);
  let captured = null;
  const SENTINEL = Symbol('stop-here');
  const stub = {
    async start(input) {
      captured = input;
      throw SENTINEL; // 拿到 input 就停，绝不进入真实扫描
    },
  };
  await assert.rejects(
    () => runSingleScan(stub, args.url || URL, args),
    (e) => e === SENTINEL,
    'runSingleScan 应在 start() 抛出的哨兵处停下（说明它没提前吞掉异常）'
  );
  assert.ok(captured, 'runSingleScan 没有调用 ScanManager.start()，接线断在更早的地方');
  return captured;
}

async function pointsOf(input) {
  const target = createTarget(input);
  const pts = await new TargetParser().discover(target);
  return pts.filter((p) => p.location === 'body').map((p) => p.param);
}

test('嵌套 --body：递给引擎的 input 带 jsonBody，且解析出叶子路径注入点', async () => {
  const input = await inputFromArgv([
    'node', 'cli', '-u', URL, '--method', 'POST',
    '--body', '{"user":{"id":1,"name":"alice"},"tags":["a","b"],"plain":"x"}',
  ]);
  assert.deepEqual(
    input.jsonBody,
    { user: { id: 1, name: 'alice' }, tags: ['a', 'b'], plain: 'x' },
    '嵌套 body 应作为 jsonBody 交给引擎'
  );
  assert.deepEqual(input.bodyParams, {}, '走 jsonBody 时 bodyParams 必须置空，否则同名点会重复投放');

  const params = await pointsOf({ ...input, config: { level: 1 } });
  for (const leaf of ['user.id', 'user.name', 'tags.0', 'tags.1', 'plain']) {
    assert.ok(params.includes(leaf), `应发现叶子注入点 ${leaf}，实际：${JSON.stringify(params)}`);
  }
  // 反向钉住缺陷本身：这两个畸形值是旧行为的指纹
  assert.ok(!params.includes('user'), '绝不能再出现 body:user（旧行为把它 String() 成了 [object Object]）');
  assert.ok(!params.includes('tags'), '绝不能再出现 body:tags（旧行为是 "a,b"）');
});

test('扁平 --body：既有行为一字不变（继续 bodyParams，不擅自改 JSON 语义）', async () => {
  const input = await inputFromArgv([
    'node', 'cli', '-u', URL, '--method', 'POST', '--body', '{"a":"1","b":"x"}',
  ]);
  assert.equal(input.jsonBody, null, '扁平 body 不该被升级成 jsonBody——那会把 urlencoded 目标发成 application/json');
  assert.deepEqual(input.bodyParams, { a: '1', b: 'x' });
  assert.deepEqual(await pointsOf({ ...input, config: { level: 1 } }), ['a', 'b']);
});

test('resolveBodyChannel 的边界：null / 数组 / 嵌套里的 null 都不该误判', () => {
  assert.deepEqual(resolveBodyChannel(null), { bodyParams: {}, jsonBody: null });
  assert.deepEqual(resolveBodyChannel({}), { bodyParams: {}, jsonBody: null });
  // 数组值本身就是"含嵌套"（顶层是数组则不是 plain object，按扁平走 bodyParams）
  assert.deepEqual(resolveBodyChannel([1, 2]), { bodyParams: [1, 2], jsonBody: null });
  // {a: null} 不是嵌套：null 是标量，不能因为 typeof null === 'object' 就切通道
  assert.deepEqual(resolveBodyChannel({ a: null }), { bodyParams: { a: null }, jsonBody: null });
  assert.deepEqual(
    resolveBodyChannel({ a: { b: 1 } }),
    { bodyParams: {}, jsonBody: { a: { b: 1 } } }
  );
});

test('直连模式不受影响（-d 分支不构造 body 通道）', async () => {
  const input = await inputFromArgv([
    'node', 'cli', '-d', 'memory://x', '--sql-template', 'SELECT * FROM t WHERE id={INJECT}',
  ]);
  assert.equal(input.mode, 'direct');
  assert.equal(input.jsonBody, undefined, '直连模式不该带上 HTTP body 通道');
});

// ── REST 侧同一处坑：行为不变，但必须看得见 ──
test('REST：嵌套值放 bodyParams 时行为不变（仍 String 成畸形值），jsonBody 保持 null', async () => {
  const { sanitizeStart } = await import('../src/api/scanRoutes.js');
  const out = sanitizeStart({
    url: 'http://shop.example.com/api/order',
    bodyParams: { user: { id: 1 }, flat: 'x' },
  });
  assert.equal(out.jsonBody, null, 'bodyParams 不会被自动升级成 jsonBody（两个字段语义必须各管各的）');
  // 钉住"行为不变"：畸形值确实还在。这里不是认可它，是防止有人顺手改成静默丢键——
  // 那会让"我到底测没测过这个参数"再次变成不可见。可见性由 sanitizeStart 的 warn 负责。
  assert.equal(out.bodyParams.user, '[object Object]');
  assert.equal(out.bodyParams.flat, 'x');
});

test('REST：jsonBody 传嵌套对象时原样送达（CLI 与 REST 两条通道终点一致）', async () => {
  const { sanitizeStart } = await import('../src/api/scanRoutes.js');
  const out = sanitizeStart({
    url: 'http://shop.example.com/api/order',
    jsonBody: { user: { id: 1 }, tags: ['a', 'b'] },
  });
  assert.deepEqual(out.jsonBody, { user: { id: 1 }, tags: ['a', 'b'] });
  const params = await new TargetParser()
    .discover(createTarget({ ...out, config: { level: 1 } }))
    .then((pts) => pts.filter((p) => p.location === 'body').map((p) => p.param));
  for (const leaf of ['user.id', 'tags.0', 'tags.1']) {
    assert.ok(params.includes(leaf), `REST 侧应发现 ${leaf}，实际：${JSON.stringify(params)}`);
  }
});
