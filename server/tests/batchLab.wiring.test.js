// ============================================================================
// batchLab.wiring.test.js —— 批量故障隔离这条链必须三方都在
//
// 本仓纪律（写测试必须接线，否则等于没写）：e2e 套件要同时进
//   ① e2e/run-all.mjs 的 LABS（ci.yml 的 e2e-self-contained job 与 ci-local 都跑它）
//   ② e2e/acceptance.mjs 的 SUITES（acceptance 门禁）
// 只进一处 = 另一处永远看不到它 = 改坏了不红。
//
// 另外两条是**内容守卫**，防的是比"整条被删"更常见的退化：
//   · 套件还在，但断言被删/被放宽 ⇒ 条目绿着而什么都没验；
//   · 生产侧（cli.js）不再走 batchPool ⇒ 单测与靶场都绿，真实 CLI 却回到「整批中断」。
// 判据一律用**源码文本**而不是 import —— 这两个都是脚本，import 会把它们真的跑起来。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const read = (rel) => readFileSync(path.join(REPO, rel), 'utf8');

const acc = read('e2e/acceptance.mjs');
const runAll = read('e2e/run-all.mjs');
const lab = read('e2e/batch-lab/run.mjs');
const cli = read('server/bin/cli.js');

/** acceptance.mjs 的 SUITES id 清单（文本解析，不 import） */
function suiteIds(text) {
  const start = text.indexOf('const SUITES');
  const end = text.indexOf('\n];', start);
  assert.ok(start >= 0 && end > start, '解析不到 const SUITES 数组 —— 本守卫的取数源失效');
  return [...text.slice(start, end).matchAll(/\n\s{4}id:\s*['"`]([^'"`]+)['"`]/g)].map((m) => m[1]);
}

test('① 接线：batch-lab 进了 run-all 的 LABS（CI 自足 job 与 ci-local 都靠它）', () => {
  assert.match(runAll, /name:\s*'batch-lab'/, 'run-all.mjs 缺 batch-lab 条目');
  assert.match(runAll, /entry:\s*'e2e\/batch-lab\/run\.mjs'/, 'batch-lab 的入口路径不对');
  // deps 必须为空：它起的是 sql.js（SQLite WASM）靶站，不需要宿主 MySQL。
  // 标成 ['sandbox'] 会让它在无 DB 的 CI job 上被判 SKIP —— 又变成"从未真跑"。
  assert.match(runAll, /entry:\s*'e2e\/batch-lab\/run\.mjs',\s*deps:\s*\[\]/, 'batch-lab 的 deps 应为空（自起靶站，不依赖宿主 DB）');
});

test('② 接线：batch-lab 进了 acceptance 的 SUITES', () => {
  const ids = suiteIds(acc);
  assert.ok(ids.includes('batch-lab'), `acceptance.mjs 的 SUITES 缺 batch-lab：${JSON.stringify(ids)}`);
});

test('③ 内容守卫：批量靶场的三条核心断言还在（防整条被静默放宽）', () => {
  // 退出码正常（原实现是 unhandled rejection）
  assert.match(lab, /code === 0 \|\| code === 2/, '丢了「批量应正常退出」断言');
  // 死目标结论不得是「无漏洞」—— 一个请求都没发时阴性结论是假的
  assert.match(lab, /verdict === 'inconclusive'/, '丢了「死目标结论必须 inconclusive」断言');
  // 摘要必须点名（只报数字 = 把「哪个目标没扫」变成悬案）
  assert.match(lab, /个需复核/, '丢了「需复核计数」断言');
  // 成功目标的报告必须真落盘（原实现池一 reject 全丢）
  assert.match(lab, /files\.length >= 3/, '丢了「报告落盘」断言');
});

test('③b 内容守卫：集合目标生成（对标 sqlmap 2.0 OpenAPI 生成）的断言还在', () => {
  assert.match(lab, /请求集合（openapi）/, '丢了「点名识别为 openapi 集合」断言');
  assert.match(lab, /展开 2 个目标/, '丢了「openapi 展开出 2 个目标」断言');
  assert.match(lab, /请求集合（har）/, '丢了「点名识别为 har 集合」断言');
  // ★ 最关键的一条：POST 的 body 必须保住 —— 保不住就只剩 URL（无 query）⇒ 0 注入点 ⇒ 根本没测
  assert.match(lab, /POST body 未保住/, '丢了「POST body 保住」断言（这是集合展开唯一能假绿的形态）');
});

test('④ 接线守卫：CLI 的批量两条路径真的走 batchPool（不是只在单测里用）', () => {
  assert.match(cli, /cli\/batchPool\.js/, 'cli.js 没有引用 batchPool');
  // -m 与 -l 各一处；只改一处会让另一条路径继续保持「整批中断」的旧行为
  const hits = (cli.match(/runBatch\(\{/g) || []).length;
  assert.ok(hits >= 2, `runBatch( 调用点应至少 2 处（-m 与 -l），实得 ${hits}`);
  // 退出码语义：全批失败 → 1（与「扫了但没高危」区分）
  assert.match(cli, /summary\.allFailed\) process\.exit\(1\)/, '丢了「全批失败 → 1」的退出码语义');
});

test('⑤ 接线守卫：-m 真的接了集合展开（不是只在单测里用）', () => {
  assert.match(cli, /cli\/batchTargets\.js/, 'cli.js 没有引用 batchTargets');
  assert.match(cli, /expandBatchTargets\(/, 'cli.js 没调用 expandBatchTargets');
  // 集合条目必须按 method/headers/body 逐目标派生，否则 GET-only ⇒ POST 端点一个都测不到
  assert.match(cli, /scanArgsFromRequest\(args, item\)/, '集合条目没有走 scanArgsFromRequest 派生');
  // 「识别成什么格式、展开出几个目标」必须在 stderr 说出来（静默降级是本仓反复踩的坑）
  assert.match(cli, /批量目标来源/, '丢了「批量目标来源」的点名输出');
});
