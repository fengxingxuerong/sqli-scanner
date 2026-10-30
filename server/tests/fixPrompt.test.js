// ============================================================================
// tests/fixPrompt.test.js —— [D176] 修复提示词的判据（不是文案快照）
//
// 守的是三件用户感受得到的事：
//   ① 每条命中都给出**能复现的**复测命令（带参数与通道），不是一句「请修复」；
//   ② 结论不可信（inconclusive / unverifiedSurfaces）时提示词必须**先说口径**，
//      否则 agent 会对着「没测成」的结论去改代码；
//   ③ 落盘文件名对怪异参数也安全（不产生 `../` 或空格路径），且一条命中一份文件。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  guidanceFor,
  buildRetestCommand,
  buildFixPrompt,
  renderFixPrompts,
} from '../src/services/fixPrompt.js';

const VULN = {
  technique: 'union',
  param: 'cat',
  location: 'URL 查询参数（GET query）',
  url: 'http://lab.local/items?cat=1',
  riskLevel: 'High',
  vulnType: { nameZh: 'SQL 注入（联合查询注入）', cwe: 'CWE-89', owasp: 'A03:2021-Injection' },
  poc: { curl: "curl 'http://lab.local/items?cat=1%27%20UNION%20SELECT%201--%20-'" },
};

test('guidanceFor：9 条通道都有「为什么 + 怎么改」，未知通道回落且标注未收录', () => {
  for (const t of ['union', 'error', 'boolean', 'time', 'stacked', 'oob', 'second_order', 'inline', 'nosql']) {
    const g = guidanceFor(t);
    assert.equal(g.known, true, `${t} 应被收录`);
    assert.ok(g.why.length > 10, `${t} 缺 why`);
    assert.ok(g.rewrite.length >= 2, `${t} 的改法应至少两条`);
  }
  const unknown = guidanceFor('made-up');
  assert.equal(unknown.known, false);
  assert.ok(unknown.rewrite.length >= 2);
});

test('buildRetestCommand：带目标/参数/通道，可直接复制执行', () => {
  const cmd = buildRetestCommand(VULN, {});
  assert.match(cmd, /node server\/bin\/cli\.js/);
  assert.match(cmd, /-u "http:\/\/lab\.local\/items\?cat=1"/);
  assert.match(cmd, /-p "cat"/);
  assert.match(cmd, /--technique union/);
});

test('buildFixPrompt：包含参数/通道/PoC/改法/复测命令与期望值', () => {
  const md = buildFixPrompt(VULN, { verdict: 'vulnerable' });
  assert.match(md, /CWE-89/);
  assert.match(md, /`cat`/);
  assert.match(md, /UNION SELECT/);
  assert.match(md, /## 该怎么改/);
  assert.match(md, /## 改完怎么验（复制即用）/);
  assert.match(md, /\*\*0 条 finding\*\*/);
  // 修复建议必须落到「参数化查询」这种可执行动作，而不是「请加固」
  assert.match(md, /参数化查询|预编译/);
});

test('buildFixPrompt：结论不可信时先声明口径，并拒绝把「未测成」当通过', () => {
  const md = buildFixPrompt(VULN, {
    verdict: 'inconclusive',
    unverifiedSurfaces: ['HTTP 请求头 2/2'],
  });
  assert.match(md, /## 结论口径/);
  assert.match(md, /inconclusive/);
  assert.match(md, /HTTP 请求头 2\/2/);
  assert.match(md, /不能.*当作修复已验证/);
});

test('renderFixPrompts：一条命中一份文件，怪异参数名不逃出目录', () => {
  const evil = { ...VULN, param: '../../etc/passwd x' };
  const { index, items } = renderFixPrompts({ vulns: [VULN, evil], summary: { verdict: 'vulnerable' } }, { url: VULN.url });
  assert.equal(items.length, 2);
  assert.match(index, /fix-01-/);
  for (const it of items) {
    assert.ok(!it.file.includes('/') && !it.file.includes('\\') && !it.file.includes('..'), `文件名不安全：${it.file}`);
    assert.ok(it.file.endsWith('.md'));
  }
  assert.notEqual(items[0].file, items[1].file);
});

test('renderFixPrompts：无命中时索引如实说明（不生成空提示词）', () => {
  const { index, items } = renderFixPrompts({ vulns: [], summary: { verdict: 'no_vulnerability_detected' } }, {});
  assert.equal(items.length, 0);
  assert.match(index, /没有 findings/);
  assert.match(index, /no_vulnerability_detected/);
});

test('接线：--fix-prompt 真落盘（索引 + 每条一份），不带值时落在 out/fix-prompts', async () => {
  const { writeFixPromptsForReport } = await import('../bin/cli.js');
  const dir = mkdtempSync(join(tmpdir(), 'fixprompt-'));
  try {
    const report = { url: VULN.url, vulns: [VULN], summary: { verdict: 'vulnerable' } };
    const r = writeFixPromptsForReport(report, { fixPrompt: true, out: dir });
    assert.equal(r.count, 1);
    assert.equal(r.dir, join(dir, 'fix-prompts'));
    const files = readdirSync(r.dir).sort();
    assert.ok(files.includes('README.md'), `缺索引：${files}`);
    assert.equal(files.length, 2);
    assert.match(readFileSync(join(r.dir, files[1]), 'utf8'), /改完怎么验/);
    // 带值 ⇒ 直接写进该目录（不再套一层 fix-prompts/）
    const explicit = join(dir, 'explicit');
    const r2 = writeFixPromptsForReport(report, { fixPrompt: explicit, out: '/nope' });
    assert.equal(r2.dir, explicit);
    // --out 是**文件**路径时，落在它所在目录下的 fix-prompts/（不是 "report.json/fix-prompts"）
    const r3 = writeFixPromptsForReport(report, { fixPrompt: true, out: join(dir, 'sub', 'report.json') });
    assert.equal(r3.dir, join(dir, 'sub', 'fix-prompts'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
