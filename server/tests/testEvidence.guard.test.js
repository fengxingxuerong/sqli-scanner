import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeTestEvidence } from '../../scripts/lib/testEvidence.mjs';
import { collectFrontend, collectServer } from '../../scripts/facts-sync.mjs';

function tempRoot(t) {
  const root = mkdtempSync(join(tmpdir(), 'sqli-test-evidence-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function serverRoot(t) {
  const root = tempRoot(t);
  mkdirSync(join(root, 'server'));
  writeFileSync(join(root, 'server', 'package.json'), JSON.stringify({
    scripts: { test: 'fake-test', 'test:coverage:report': 'fake-coverage' },
  }));
  return root;
}

const tap = (fail) => [
  'TAP version 13',
  ...(fail ? ['not ok 1 - 失败用例', "  error: 'maxGap=52ms'"] : ['ok 1 - 通过用例']),
  '# tests 1',
  `# pass ${fail ? 0 : 1}`,
  `# fail ${fail ? 1 : 0}`,
  '# skipped 0',
].join('\n');

function metadata(root) {
  const dir = join(root, 'logs', 'test-evidence');
  return readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')));
}

test('失败证据：完整输出与结构化摘要同批落盘', (t) => {
  const root = tempRoot(t);
  const output = [
    'TAP version 13',
    'not ok 1 - 用例甲',
    '  error: \'maxGap=52ms elapsed=8000ms\'',
    'not ok 2 - 用例乙',
    '  error: \'expected 2 actual 1\'',
    '# tests 2',
    '# pass 0',
    '# fail 2',
    '# skipped 0',
  ].join('\n');
  const ev = writeTestEvidence({
    root,
    suite: 'server',
    attempt: 'first',
    command: 'node --test',
    exitCode: 1,
    output,
    now: new Date('2026-11-24T01:02:03.004Z'),
  });
  assert.equal(readFileSync(ev.outputPath, 'utf8'), output);
  const meta = JSON.parse(readFileSync(ev.metaPath, 'utf8'));
  assert.equal(meta.exitCode, 1);
  assert.deepEqual(meta.counts, { tests: 2, pass: 0, fail: 2, skipped: 0 });
  assert.equal(meta.failures.length, 2);
  assert.match(meta.failures[0].detail, /maxGap=52ms/);
  assert.match(meta.outputFile, /^logs\/test-evidence\//);
});

test('失败证据：同一时间、同一标签连续写入也不会覆盖', (t) => {
  const root = tempRoot(t);
  const opts = { root, suite: 'server', attempt: 'retry', command: 'node --test', exitCode: 0, output: '# fail 0', now: new Date('2026-11-24T01:02:03.004Z') };
  const a = writeTestEvidence(opts);
  const b = writeTestEvidence(opts);
  assert.notEqual(a.outputPath, b.outputPath);
  assert.equal(readdirSync(join(root, 'logs', 'test-evidence')).length, 4);
});

test('失败证据：标签不能穿越目录，空输出也可留痕', (t) => {
  const root = tempRoot(t);
  const ev = writeTestEvidence({ root, suite: '../../escape', attempt: 'a/b', command: [], exitCode: null, output: '' });
  assert.ok(ev.outputPath.startsWith(join(root, 'logs', 'test-evidence')));
  assert.equal(readFileSync(ev.outputPath, 'utf8'), '');
  const meta = JSON.parse(readFileSync(ev.metaPath, 'utf8'));
  assert.equal(meta.exitCode, null);
  assert.deepEqual(meta.failures, []);
});

test('facts 集成：前端失败与无法解析汇总都保留现场', (t) => {
  const root = tempRoot(t);
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'error', () => {});
  const failed = collectFrontend({
    root,
    run: () => ({ out: 'Test Files 1 failed\nTests 1 failed | 2 passed (3)', code: 1 }),
  });
  assert.equal(failed.fail, 1);
  const frontendEvidence = metadata(root).find((m) => m.suite === 'frontend');
  assert.ok(frontendEvidence, '前端失败现场未落盘');
  assert.equal(frontendEvidence.exitCode, 1);
  assert.throws(() => collectFrontend({ root, run: () => ({ out: 'worker crashed', code: 1 }) }), /找不到 Tests 行/);
  assert.ok(metadata(root).some((m) => m.attempt === 'first-unparsed'));
});

test('facts 集成：首轮失败、复跑通过时，两轮完整现场都落盘', (t) => {
  const root = serverRoot(t);
  t.mock.method(console, 'warn', () => {});
  const runs = [{ out: tap(true), code: 1 }, { out: tap(false), code: 0 }];
  const res = collectServer({ root, run: () => runs.shift() });
  assert.deepEqual(res, { tests: 1, pass: 1, fail: 0, skip: 0 });
  const metas = metadata(root);
  assert.equal(metas.length, 2);
  assert.equal(metas.find((m) => m.attempt === 'first').counts.fail, 1);
  assert.equal(metas.find((m) => m.attempt === 'retry').counts.fail, 0);
  assert.match(metas.find((m) => m.attempt === 'first').failures[0].detail, /maxGap=52ms/);
});

test('facts 集成：连续两轮失败时保留 fail 计数与两轮现场', (t) => {
  const root = serverRoot(t);
  t.mock.method(console, 'warn', () => {});
  const res = collectServer({ root, run: () => ({ out: tap(true), code: 1 }) });
  assert.equal(res.fail, 1);
  assert.equal(metadata(root).length, 2);
});

test('facts 集成：覆盖率失败或无法解析时也保留完整现场', (t) => {
  const root = serverRoot(t);
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'error', () => {});
  const runs = [{ out: tap(false), code: 0 }, { out: 'coverage exploded', code: 1 }];
  assert.throws(() => collectServer({ root, coverage: true, run: () => runs.shift() }), /找不到 all files/);
  const cov = metadata(root).find((m) => m.suite === 'server-coverage');
  assert.ok(cov, '覆盖率失败现场未落盘');
  assert.equal(cov.exitCode, 1);
  assert.equal(readFileSync(join(root, cov.outputFile), 'utf8'), 'coverage exploded');
});

test('失败证据：超过十条也保留全部失败用例名', (t) => {
  const root = tempRoot(t);
  const output = Array.from({ length: 12 }, (_, i) => `not ok ${i + 1} - 用例${i + 1}\n  error: 'detail${i + 1}'`).join('\n');
  const ev = writeTestEvidence({ root, suite: 'server', attempt: 'retry', command: 'node --test', exitCode: 1, output });
  const meta = JSON.parse(readFileSync(ev.metaPath, 'utf8'));
  assert.equal(meta.failures.length, 12);
  assert.match(meta.failures[11].title, /用例12/);
});
