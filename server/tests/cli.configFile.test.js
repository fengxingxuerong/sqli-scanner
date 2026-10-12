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

// ── [2026-10-12 优化空间勘查 §A2] NoSQL / OOB 默认关通道的 CLI 可达性 ──
// 缺口实录：引擎早有（ScanManager._runNoSql / oobReceiver），UI 与 REST 都可达，
// 唯独 CLI 一无旗标、二不登记档案键 ⇒ --config 写 {"oob":{...}} 都被未知键硬拒。
// 本组用例钉三条：旗标可开、档案可开、档案整组透传时其余子键不吃亏（patchGroup 语义）。
test('parseArgs：--no-sql / --oob 旗标可开（默认 false，零回归）', () => {
  const base = parseArgs([]);
  assert.equal(base.noSql, false);
  assert.equal(base.oob, false);
  assert.equal(parseArgs(['--no-sql']).noSql, true);
  assert.equal(parseArgs(['--oob']).oob, true);
  // 两开关独立，不互相隐含
  const onlyOob = parseArgs(['--oob']);
  assert.equal(onlyOob.noSql, false);
});

test('loadConfigFile：oob / noSql 组键是合法档案键（整组子键经档案透传）', () => {
  const p = write('oob.json', { oob: { enabled: true, callbackBase: 'cb.example:8899' }, noSql: { kinds: ['nosql'] } });
  const { preset, unknown } = loadConfigFile(p, KNOWN);
  assert.deepEqual(unknown, [], 'oob/noSql 不应再被报未知键（§A2 修的可达性缺口）');
  assert.deepEqual(preset.oob, { enabled: true, callbackBase: 'cb.example:8899' });
  assert.deepEqual(preset.noSql, { kinds: ['nosql'] });
});

test('buildConfig：旗标只开总开关；档案整组透传时其余子键保持引擎默认（带底合并）', async () => {
  const { buildConfig } = await import('../bin/cli/config.js');
  const { defaults } = await import('../src/config/defaults.js');

  // ① 旗标：enabled=true，其余子键一律引擎默认（不是 undefined）
  const byFlag = buildConfig(parseArgs(['--oob', '--no-sql']));
  assert.equal(byFlag.oob.enabled, true, '--oob 应开启 oob.enabled');
  assert.equal(byFlag.noSql.enabled, true, '--no-sql 应开启 noSql.enabled');
  assert.equal(byFlag.oob.httpPort, defaults.oob.httpPort, '旗标不应动其它子键（带底合并）');
  assert.equal(byFlag.noSql.concurrency, defaults.noSql.concurrency, '旗标不应动其它子键');

  // ② 档案整组：只覆盖显式子键，未写的子键回落默认（patchGroup，不是整体赋值）
  const byFile = buildConfig(parseArgs([], { oob: { enabled: true, dnsDomain: 'attacker.example' }, noSql: { kinds: ['graphql'] } }));
  assert.equal(byFile.oob.enabled, true);
  assert.equal(byFile.oob.dnsDomain, 'attacker.example');
  assert.equal(byFile.oob.callbackBase, defaults.oob.callbackBase, '档案未写的子键必须回落默认');
  assert.equal(byFile.oob.dnsOob, defaults.oob.dnsOob, '档案未写的子键必须回落默认');
  assert.deepEqual(byFile.noSql.kinds, ['graphql']);
  assert.equal(byFile.noSql.concurrency, defaults.noSql.concurrency, '档案未写的子键必须回落默认');

  // ③ 不传：buildConfig 是显式键清单 ⇒ 两通道一个键都不写（引擎回落 defaults，零回归）
  const off = buildConfig(parseArgs([]));
  assert.ok(!('oob' in off) && !('noSql' in off),
    '未传开关时不该凭空写出这两个组（引擎按 defaults 走；误写等于覆盖引擎默认）');
  assert.equal(defaults.oob.enabled, false, '引擎默认必须保持关闭（opt-in 语义不变）');
  assert.equal(defaults.noSql.enabled, false, '引擎默认必须保持关闭（opt-in 语义不变）');
});

test('save-config round-trip：--oob 落盘后可复扫（增量含旗标键）', () => {
  const out = join(tmp, 'oob-saved.json');
  const args = parseArgs(['-u', 'http://example.com/?id=1', '--oob']);
  const n = saveConfigFile(out, args, parseArgs);
  assert.ok(n >= 2, `增量应含 url 与 oob，实际 ${n}`);
  const { preset, unknown } = loadConfigFile(out, KNOWN);
  assert.deepEqual(unknown, []);
  assert.equal(preset.oob, true);
  assert.equal(parseArgs([], preset).oob, true, '复扫时旗标应从档案恢复');
});
