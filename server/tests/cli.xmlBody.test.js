// ============================================================================
// cli.xmlBody.test.js —— XML / SOAP body 通道的 CLI 接线（对标 ghauri XML·SOAP）
// ============================================================================
// 与 cli.jsonBody.test.js 同口径：**不只测纯函数**。解析器全绿也挡不住 runSingleScan
// 忘了把 xmlBody 递给引擎 —— 所以主用例走 parseArgs(argv) → runSingleScan → 捕获真正
// 传给 ScanManager.start() 的 input，再接 TargetParser 看注入点是不是叶子点路径。
//
// 为什么 --xml-body 必须独立入口：--body 在 CLI 侧是 JSON.parse 消费的（见 cli.js:171），
// XML 不是合法 JSON ⇒ 走 --body 会在解析阶段就炸，用户连提示都拿不到。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseArgs, runSingleScan } from '../bin/cli.js';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';

const URL = 'http://127.0.0.1:9999/soap';

const SOAP = '<?xml version="1.0" encoding="UTF-8"?>'
  + '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
  + '<GetUser><id>1</id><name>alice</name></GetUser></soap:Body></soap:Envelope>';

/** 跑真实 CLI 入口，捕获递给 ScanManager.start() 的 input（不让真扫描发生） */
async function inputFromArgv(argv) {
  const args = parseArgs(argv);
  let captured = null;
  const SENTINEL = Symbol('stop-here');
  const stub = {
    async start(input) {
      captured = input;
      throw SENTINEL;
    },
  };
  await assert.rejects(
    () => runSingleScan(stub, args.url || URL, args),
    (e) => e === SENTINEL,
    'runSingleScan 应在 start() 抛出的哨兵处停下',
  );
  assert.ok(captured, 'runSingleScan 没有调用 ScanManager.start()，接线断在更早的地方');
  return captured;
}

// ① --xml-body：XML 原文一路递到引擎 input.xmlBody
test('xmlBody: --xml-body 递到引擎 input', async () => {
  const input = await inputFromArgv(['-u', URL, '--method', 'POST', '--xml-body', SOAP]);
  assert.equal(typeof input.xmlBody, 'string', '--xml-body 未递到引擎');
  assert.ok(input.xmlBody.includes('<GetUser>'));
});

// ② --xml-body-file：多行 SOAP 信封从文件读（真实用法）
test('xmlBody: --xml-body-file 从文件读原文', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sqli-xml-'));
  const f = path.join(dir, 'envelope.xml');
  writeFileSync(f, SOAP, 'utf8');
  const input = await inputFromArgv(['-u', URL, '--method', 'POST', '--xml-body-file', f]);
  assert.equal(input.xmlBody, SOAP, '文件内容未原样递到引擎');
});

// ③ ★接线★ 递到引擎后必须真的变成**叶子注入点**（不是整份 XML 当一个参数）
test('xmlBody: 递到引擎后 TargetParser 产出叶子点路径', async () => {
  const input = await inputFromArgv(['-u', URL, '--method', 'POST', '--xml-body', SOAP]);
  const points = await new TargetParser().discover(createTarget(input));
  const params = points.map((p) => `${p.location}:${p.param}`);
  assert.ok(
    params.includes('body:soap:Envelope.soap:Body.GetUser.id'),
    `应产出 XML 叶子点路径，实得 ${JSON.stringify(params)}`,
  );
  assert.ok(
    params.includes('body:soap:Envelope.soap:Body.GetUser.name'),
    `name 叶子也应成为注入点，实得 ${JSON.stringify(params)}`,
  );
});

// ④ 未给 XML 通道时零行为变化（回归护栏：不能有 xmlBody 键冒出来）
test('xmlBody: 未传 --xml-body 时 input 不带该键（零回归）', async () => {
  const input = await inputFromArgv(['-u', URL, '--method', 'POST', '--body', '{"q":"chair"}']);
  assert.equal(input.xmlBody, null, '未给 XML 时不应出现 xmlBody');
});
