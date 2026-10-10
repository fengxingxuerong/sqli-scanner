// [D41 2026-10-11] 配置档案（--config / --save-config）单测
// 对标 sqlmap -c/--save + ffuf -config：档案预载（argv > 档案 > 默认）、未知键硬拒、
// 增量落盘可复扫。文件层走临时目录，不动仓库任何现有文件。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from '../bin/cli.js';
import {
  buildKnownArgKeys,
  loadConfigFile,
  diffFromDefaults,
  saveConfigFile,
  presetFromArgv,
  INTERNAL_ARG_KEYS,
} from '../bin/cli/configFile.js';

const tmp = mkdtempSync(join(tmpdir(), 'sqli-config-file-'));
test.after?.(() => {});
process.on?.('exit', () => {
  try { rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
});

const write = (name, obj) => {
  const p = join(tmp, name);
  writeFileSync(p, typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2), 'utf-8');
  return p;
};

const KNOWN = buildKnownArgKeys(parseArgs);

test('buildKnownArgKeys：默认键 ∪ 动态键（--os-shell/--prefix/--crawl 这类「传了才存在」的键不能漏）', () => {
  for (const k of ['url', 'level', 'risk', 'osShell', 'prefix', 'crawl', 'testParam', 'retries', 'httpTimeoutMs']) {
    assert.ok(KNOWN.has(k), `KNOWN 应含 ${k}`);
  }
  assert.ok(!KNOWN.has('headerObj')); // 内部键不在合法键集
});

test('loadConfigFile：合法档案 → preset 剔除内部键；未知键全部列出（硬拒由调用方执行）', () => {
  const p = write('ok.json', { url: 'http://example.com/?id=1', level: 5, headerObj: { x: '1' }, bogusKey: 1 });
  const { preset, unknown } = loadConfigFile(p, KNOWN);
  assert.deepEqual(preset, { url: 'http://example.com/?id=1', level: 5 });
  assert.deepEqual(unknown, ['bogusKey']);
});

test('loadConfigFile：文件不存在 / 非 JSON / 非对象 → 抛错（错误文案含路径）', () => {
  assert.throws(() => loadConfigFile(join(tmp, 'missing.json'), KNOWN), /不存在/);
  const bad = write('bad.json', '{not json');
  assert.throws(() => loadConfigFile(bad, KNOWN), /JSON/);
  const arr = write('arr.json', '[1,2]');
  assert.throws(() => loadConfigFile(arr, KNOWN), /JSON 对象/);
});

test('parseArgs(argv, preset)：档案作底、argv 显式开关覆盖、未传键保持档案值', () => {
  const preset = { level: 5, risk: 2, tamper: 'space2comment' };
  // argv 不传 → 档案值生效
  const a = parseArgs([], preset);
  assert.equal(a.level, 5);
  assert.equal(a.risk, 2);
  assert.equal(a.tamper, 'space2comment');
  // argv 传了 → argv 赢
  const b = parseArgs(['--level', '2'], preset);
  assert.equal(b.level, 2);
  assert.equal(b.risk, 2);
  // 无 preset → 行为与旧签名逐字一致（回归钉）
  const c = parseArgs(['--level', '3']);
  assert.equal(c.level, 3);
  assert.equal(c.risk, null);
});

test('diffFromDefaults：只含非默认键；内部键与 undefined 键不出现', () => {
  const args = parseArgs(['-u', 'http://example.com/?id=1', '--level', '4']);
  const delta = diffFromDefaults(args, parseArgs);
  assert.deepEqual(delta, { url: 'http://example.com/?id=1', level: 4 });
  // 动态键（默认对象里不存在）只要有值就计入
  const args2 = parseArgs(['-u', 'http://example.com/?id=1', '--prefix', "'"]);
  assert.equal(diffFromDefaults(args2, parseArgs).prefix, "'");
  // 内部键永不出现
  for (const k of Object.keys(diffFromDefaults({ ...args, unknownFlags: ['-x'], headerObj: {} }, parseArgs))) {
    assert.ok(!INTERNAL_ARG_KEYS.has(k), `${k} 不应出现在增量里`);
  }
});

test('saveConfigFile：落盘 → --config 复扫 round-trip（档案值与原增量一致）', () => {
  const out = join(tmp, 'saved.json');
  const args = parseArgs(['-u', 'http://example.com/?id=1', '--level', '4', '--test-param', 'id', '--param-filter', 'get']);
  const n = saveConfigFile(out, args, parseArgs);
  assert.ok(n >= 3);
  const { preset, unknown } = loadConfigFile(out, KNOWN);
  assert.deepEqual(unknown, []);
  const reloaded = parseArgs([], preset);
  assert.equal(reloaded.level, 4);
  assert.equal(reloaded.testParam, 'id'); // 档案键=长参数名（testParam），config 层的 testParameter 由 buildConfig 再派生
  assert.equal(reloaded.paramFilter, 'get');
  assert.equal(reloaded.url, 'http://example.com/?id=1');
});

test('saveConfigFile：全默认时写出空对象（合法档案，复扫=默认行为）', () => {
  const out = join(mkdirSync(join(tmp, 'sub'), { recursive: true }), 'empty.json');
  const n = saveConfigFile(out, parseArgs([]), parseArgs);
  assert.equal(n, 0);
  const { preset } = loadConfigFile(out, KNOWN);
  assert.deepEqual(preset, {});
});

test('presetFromArgv：无 --config 返回 null；合法档案返回 preset；未知键抛错（双入口同源硬拒）', () => {
  assert.equal(presetFromArgv(['-u', 'http://a/?id=1'], parseArgs), null);
  const p = write('ok2.json', { level: 3 });
  assert.deepEqual(presetFromArgv(['--config', p], parseArgs), { level: 3 });
  const bad = write('bad2.json', { nope: 1 });
  assert.throws(() => presetFromArgv(['--config', bad], parseArgs), /未知键/);
  // 值形态 --config=file 不在支持范围（本 CLI 全部开关只认空格形态）→ 按「未带 --config」处理
  assert.equal(presetFromArgv([`--config=${p}`], parseArgs), null);
});
