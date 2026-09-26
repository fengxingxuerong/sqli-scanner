// e2e/lib/labRegistry.test.mjs —— run-all 的靶场清单必须真的包含"有信息量的那一档"
// ============================================================================
// 起因（2026-09-25，远端 run 09a5e92 的日志）：CI 里 multi-engine-lab 第一次真跑成功，
// 打印的是 `tamper 收益 on(0) ≥ off(0)=✅` —— 挂 CRS 的 ≈PL3 档实测 36 格全空（探针被整档
// 403），所以 CI 花力气下载并校验了 4 个引擎 jar，跑的却是**唯一证不出任何事的那一档**。
// 真正测覆盖面/定库的 `NO_WAF=1` 档只在我手动跑过一次：产物入了库，清单里没有它。
// 同类形状还有 `verify-dialect-templates.mjs`：文档写着"退出码 0 = 全通过"，从 09-22 起
// 没进过任何门禁。
//
// 为什么用静态断言而不是跑一遍：这两件事的性质是"清单里有没有这一条"，
// 不需要真起 JVM 就能判，而且真跑的 CI job 已经会执行它们（这里只钉注册关系）。
// 判据不许空转：解析结果为空 / 条数异常偏低直接红（第一轮 e2eArtifacts 守卫就是被
// 恒假的文件过滤器骗过的，形状一样的坑不能再踩第二次）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = readFileSync(join(REPO, 'e2e/run-all.mjs'), 'utf8');

/**
 * 从 LABS 数组里解析出 { name, entry, raw }。
 * ⚠ 按**行**切，一行的对象体就是一个条目。第一版用"从 name 起截 600 字符"，
 *   结果 CRS-on 那条的窗口吃进了紧跟其后的注释与下一条 ⇒ 两条都匹配 NO_WAF，
 *   守卫当场把自己的解析缺陷报成"注册了两遍"。窗口式解析在清单里必然串条目。
 */
function parseLabs(src) {
  const start = src.indexOf('const LABS = [');
  assert.ok(start >= 0, 'run-all.mjs 里找不到 `const LABS = [` —— 清单结构变了，本守卫必须跟着改');
  const body = src.slice(start, src.indexOf('\n];', start));
  return body
    .split(/\r?\n/)
    .filter((l) => /^\s*\{ name: '/.test(l))
    .map((l) => ({ raw: l, name: /name: '([^']+)'/.exec(l)[1], entry: /entry: '([^']+)'/.exec(l)?.[1] || '' }));
}

const labs = parseLabs(SRC);

test('清单解析本身不得空转（解析失败会把下面所有断言变成恒真）', () => {
  assert.ok(labs.length >= 20, `只解析到 ${labs.length} 个靶场 —— run-all 清单远超此数，解析规则失效了`);
  assert.ok(labs.every((l) => l.name && l.entry), '存在没有 entry 路径的条目 —— 解析规则与清单写法不匹配');
});

test('multi-engine 的三档都必须注册（每一档回答的问题不一样）', () => {
  const me = labs.filter((l) => l.entry === 'e2e/multi-engine-lab/verify.mjs');
  // CRS≈PL3（默认）：只验误报红线；NO_WAF：覆盖面 + 定库；CRS_PL=1：官方默认档下的"可检出"。
  // 少任何一档，README 里就有一句结论没有产物支撑 —— 2026-09-25 缺的就是后两档。
  assert.equal(
    me.length,
    3,
    `只注册了 ${me.length} 个 multi-engine 档位，应为 3 档（PL3 默认 / 无 WAF / PL1）；` +
      `当前实际在清单里的是：[${me.map((l) => l.name).join(', ') || '空'}]`
  );
  const noWaf = me.filter((l) => /NO_WAF: '1'/.test(l.raw));
  const pl1 = me.filter((l) => /CRS_PL: '1'/.test(l.raw));
  assert.equal(noWaf.length, 1, 'NO_WAF 档要么没注册、要么注册了两遍（后者会把产物写重）');
  assert.equal(pl1.length, 1, 'CRS_PL=1 档要么没注册、要么注册了两遍 ⇒ README 那句"默认 CRS 下可检出"没有来源');
  assert.notEqual(noWaf[0].name, pl1[0].name, '两档必须用不同靶场名，否则 run-all 汇总会合并成一条');
});

test('只在真引擎上成立的取证脚本必须登记进清单（否则它永远只被写它的那个人跑过一次）', () => {
  const dialect = labs.find((l) => l.entry === 'e2e/multi-engine-lab/verify-dialect-templates.mjs');
  assert.ok(dialect, 'verify-dialect-templates.mjs（16 条方言模板真机断言）不在 run-all 清单里 ⇒ CI 永不执行');
  assert.match(dialect.raw, /deps: \['java'\]/, '方言模板档必须声明 java 依赖，缺环境时按依赖跳过而不是崩');
});

test('同一个入口被注册成多档时，产物文件名必须按档分开（否则后跑的覆盖先跑的）', () => {
  const v = readFileSync(join(REPO, 'e2e/multi-engine-lab/verify.mjs'), 'utf8');
  assert.match(v, /NO_WAF \? '\.no-waf'/, 'NO_WAF 档的产物没有独立文件名 ⇒ 会覆盖 CRS 档基线');
  assert.match(v, /EFFECTIVE_PL === 3 \? '' : `\.pl\$\{EFFECTIVE_PL\}`/,
    '改档（CRS_PL≠3）跑出来的产物仍写默认文件名 ⇒ 一次探索就悄悄换掉入库基线');
});
