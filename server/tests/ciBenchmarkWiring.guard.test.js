// ============================================================================
// tests/ciBenchmarkWiring.guard.test.js —— [D298] Benchmark 接进 CI 的接线静态守卫
// ============================================================================
// 真因：外部裁判 4 号在 CI 长期 SKIP，不是引擎漏检，而是「CI 从来没起过靶场」+
// 「acceptance 的 --require-labs 不带 benchmark ⇒ 起得来也会静默跳过」。
// 本守卫钉住四件事：JDK17 步骤、硬起脚本、require-labs 双端口、脚本自身的
// 失败-closed 契约（win32 拒绝 / -Pdeploy / 就绪探针 / 显式非零退出）。
// 只认 ci.yml 的 **run/uses 指令体与实参**，不认注释（防「注释假绿」）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const YAML = readFileSync(join(REPO, '.github', 'workflows', 'ci.yml'), 'utf8');
const SCRIPT = readFileSync(join(REPO, 'scripts', 'ci-benchmark.mjs'), 'utf8');

/** 从 ci.yml 抽出 run 实参行与 uses 行（注释行不算指令）。 */
function directives(yaml) {
  return yaml.split(/\r?\n/)
    .filter((l) => !/^\s*#/.test(l))
    .filter((l) => /^\s*(?:-[ \t]+)?(?:run|uses):/.test(l))
    .map((l) => l.trim())
    .join('\n');
}

function assertWiring(yaml, script) {
  const cmd = directives(yaml);
  assert.match(cmd, /ci-benchmark\.mjs up/, 'acceptance 没有硬起 Benchmark 的 run 指令');
  assert.match(cmd, /actions\/setup-java@v4/, '缺 JDK setup-java 步骤');
  assert.match(yaml, /java-version:\s*'17'/, 'JDK 版本未钉 17（BenchmarkJava 要求真 JDK17）');
  assert.match(cmd, /--require-labs=[^\s]*benchmark-db,benchmark-app/,
    '--require-labs 未纳入 9001/8443 ⇒ 起得来也会静默 SKIP');
  assert.match(yaml, /timeout-minutes:\s*(4[5-9]|[5-9]\d)/,
    'acceptance job 超时未给 Maven 冷构建留余量');
  assertWiringContainsNoSwallow(yaml);
  for (const needle of ['-Pdeploy', '-Dspotless.apply.skip=true', 'org.hsqldb.Server',
    "--port', '9001'", '8443/benchmark', "process.platform === 'win32'", 'process.exit(1)']) {
    assert.ok(script.includes(needle), `ci-benchmark.mjs 缺片段：${needle}`);
  }
  assertTomcatArchiveOverride(script);
}

/**
 * [D299] pin 的 Tomcat 9.0.122 已从 downloads.apache.org 撤下（实测 404，#456 真因）。
 * 脚本必须在 **package 与 cargo:run 两处**用 -Dtomcat.url 覆盖到 archive.apache.org，
 * 且版本仍是 9.0.122（保留 pin 可复现，只换下载底座）。只认指令片段，不认注释。
 */
function assertTomcatArchiveOverride(script) {
  const code = script.split(/\r?\n/).filter((l) => !/^\s*\/\//.test(l)).join('\n');
  const hits = [...code.matchAll(/-Dtomcat\.url=\$\{TOMCAT_URL\}/g)];
  assert.ok(hits.length >= 2,
    `缺 -Dtomcat.url 覆盖（build + cargo:run 两处都要；实测 ${hits.length} 处）`);
  assert.match(code, /TOMCAT_URL[\s\S]{0,200}archive\.apache\.org\/dist\/tomcat\/tomcat-9\/v9\.0\.122/,
    'TOMCAT_URL 未指向 archive 的 9.0.122（downloads 已 404）');
  assert.ok(!/tomcat\.url=[^\n`]*downloads\.apache\.org/.test(code),
    'tomcat.url 指回 downloads.apache.org（9.0.122 已 404）');
}

test('D298-1) 真实 ci.yml 与脚本必须四件接线齐备', () => {
  assertWiring(YAML, SCRIPT);
});

test('D298-2) 反例自证：去掉 require-labs 的 benchmark 必须判红', () => {
  const broken = YAML.replace(/,benchmark-db,benchmark-app/, '');
  assert.throws(() => assertWiring(broken, SCRIPT), /--require-labs/);
});

test('D298-3) 反例自证：把硬起改成容错（|| true）必须判红', () => {
  const broken = YAML.replace('node scripts/ci-benchmark.mjs up', 'node scripts/ci-benchmark.mjs up || true');
  // 容错形态仍含 up 字面量 ⇒ 判据必须额外拒绝 `|| true`，否则守卫会被吞成恒绿。
  assertWiringContainsNoSwallow(YAML);
  assert.throws(() => assertWiringContainsNoSwallow(broken), /吞/);
});

test('D298-4) 反例自证：删掉就绪探针 / 改 JDK 版本必须判红', () => {
  assert.throws(() => assertWiring(YAML, SCRIPT.replace('8443/benchmark', '8443/')), /8443\/benchmark/);
  assert.throws(() => assertWiring(YAML.replace("java-version: '17'", "java-version: '11'"), SCRIPT), /JDK 版本/);
});

test('D299-1) 真脚本的 Tomcat archive 覆盖（两处）必须齐备', () => {
  assertTomcatArchiveOverride(SCRIPT);
});

test('D299-2) 反例自证：删掉任一处 -Dtomcat.url 覆盖必须判红', () => {
  const oneGone = SCRIPT.replace('`-Dtomcat.url=${TOMCAT_URL}`,', '');
  assert.throws(() => assertTomcatArchiveOverride(oneGone), /实测 1 处/);
});

test('D299-3) 反例自证：把 archive 换成 downloads（已 404）必须判红', () => {
  const wrong = SCRIPT.replace('https://archive.apache.org/dist/tomcat', 'https://downloads.apache.org/tomcat');
  assert.throws(() => assertTomcatArchiveOverride(wrong), /archive/);
});

/** 拒绝「起靶场失败被吞」：ci.yml 的 Benchmark 步骤不得带 continue-on-error 或 || true。 */
function assertWiringContainsNoSwallow(yaml) {
  const block = yaml.split(/\r?\n/);
  const at = block.findIndex((l) => l.includes('ci-benchmark.mjs up'));
  assert.ok(at >= 0, '找不到 Benchmark 启动指令');
  const near = block.slice(Math.max(0, at - 4), at + 6).join('\n');
  assert.ok(!/\|\| true|continue-on-error/.test(near), '启动步骤被吞（失败不判红）⇒ 会静默 SKIP');
}
