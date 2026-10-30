// ============================================================================
// tests/reproPack.test.js —— [D177] 可复现件与重放判定
//
// 守的是四件用户感受得到的事：
//   ① 「已复现」的判据是**两次重放结果一致**，不是「跑了一次没报错」；
//   ② 不一致时必须落成「单次命中」，不能被当成可复现证据；
//   ③ 生成的 repro.sh 对含引号的 URL/body 仍然可执行（不能拼坏或注入）；
//   ④ 不可重放（没有 PoC / 网络失败）要如实标注原因，不静默当成功。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  normalizeForCompare,
  sameSample,
  shq,
  buildReproScript,
  buildExpectJson,
  safeReproName,
} from '../src/services/reproPack.js';
import { replayVuln, annotateRepro, writeReproPack } from '../src/services/reproCheck.js';

const VULN = {
  technique: 'union',
  param: 'cat',
  location: 'URL 查询参数（GET query）',
  poc: {
    method: 'GET',
    url: "http://lab.local/items?cat=1' UNION SELECT 1-- -",
    headers: { 'User-Agent': 'sqli-scanner' },
    body: null,
  },
};

test('normalizeForCompare：只留状态码 + 响应体哈希（字符串/Buffer/httpClient 的 data 同口径）', () => {
  const a = normalizeForCompare({ status: 200, body: 'hello' });
  const b = normalizeForCompare({ status: 200, body: Buffer.from('hello') });
  // 引擎 httpClient 返回的是 axios 风格 `data`（D177 首版漏读 ⇒ 空体哈希假绿）
  const c = normalizeForCompare({ status: 200, data: 'hello' });
  assert.equal(a.hash, b.hash);
  assert.equal(a.hash, c.hash);
  assert.equal(a.len, 5);
  assert.equal(sameSample(a, b), true);
  // 同一请求换个状态码或换个体 → 必须判为不同（否则「单次命中」永远出不来）
  assert.equal(sameSample(a, { ...b, status: 500 }), false);
  assert.equal(sameSample(a, normalizeForCompare({ status: 200, body: 'hell0' })), false);
  // 空体不等于「没读到」：真实响应有内容时两者哈希必须不同
  assert.notEqual(normalizeForCompare({ status: 200, data: '' }).hash, c.hash);
});

test('stripVolatile：只剥机器时间标记（稳定页面不因跨秒时间戳被判单次命中）', () => {
  const page = (ts) => `<html><!-- generated at ${ts} --><p>商品列表</p></html>`;
  const a = normalizeForCompare({ status: 200, data: page('1793002213') });
  const b = normalizeForCompare({ status: 200, data: page('1793002214') });
  assert.equal(a.hash, b.hash, '仅时间戳不同应判为同一响应');
  assert.equal(a.stableLen, b.stableLen);
  // 但真实内容变化必须仍然判为不同（不做模糊匹配）
  const changed = normalizeForCompare({ status: 200, data: page('1793002213').replace('商品列表', '系统错误') });
  assert.notEqual(a.hash, changed.hash);
  // ISO 时间戳同样剥掉
  const iso1 = normalizeForCompare({ data: '{"at":"2026-10-26T08:10:13.753Z","v":1}', status: 200 });
  const iso2 = normalizeForCompare({ data: '{"at":"2026-10-26T09:11:14.999Z","v":1}', status: 200 });
  assert.equal(iso1.hash, iso2.hash);
});

test('shq：单引号被安全转义（含引号的 URL 不能把脚本拼坏）', () => {
  assert.equal(shq("a'b"), `'a'\\''b'`);
  const script = buildReproScript(VULN, { repeats: 2 });
  assert.match(script, /UNION SELECT 1-- -/);
  assert.ok(script.includes(`'\\''`), '脚本里必须出现转义后的单引号');
  // 未转义形态（`cat=1'` 紧贴引号）会把 shell 字符串提前闭合
  assert.ok(!/items\?cat=1' UNION/.test(script), '出现了未转义的单引号');
});

test('buildReproScript：两次重放 + 哈希比对 + 一致/不一致各自退出码', () => {
  const s = buildReproScript(VULN, { repeats: 2 });
  assert.match(s, /^#!\/usr\/bin\/env bash/);
  assert.match(s, /REPEATS=2/);
  assert.match(s, /sha256sum/);
  assert.match(s, /INCONSISTENT：/);
  assert.match(s, /exit 1/);
  assert.match(s, /CONSISTENT：/);
  assert.match(s, /exit 0/);
  // 判据写在脚本里：一致 ≠ 漏洞仍存在
  assert.match(s, /一致 ≠ 漏洞仍存在/);
});

test('buildExpectJson：机器可读口径与脚本一致（status + body_sha256）', () => {
  const e = buildExpectJson(VULN, { repeats: 2, target: VULN.poc.url });
  assert.equal(e.repeats, 2);
  assert.deepEqual(e.compare, ['status', 'body_sha256']);
  assert.equal(e.expect, 'consistent');
  assert.equal(e.param, 'cat');
  assert.match(e.note, /不表示漏洞仍存在/);
});

test('replayVuln：一致→reproduced；不一致→single_hit；无 PoC/请求失败→unreplayable', async () => {
  const same = await replayVuln(VULN, { request: async () => ({ status: 200, body: 'stable' }) });
  assert.equal(same.status, 'reproduced');
  assert.equal(same.samples.length, 2);

  let n = 0;
  const drifting = await replayVuln(VULN, { request: async () => ({ status: 200, body: `v${n++}` }) });
  assert.equal(drifting.status, 'single_hit');
  assert.equal(drifting.consistent, false);

  const noPoc = await replayVuln({ param: 'x' }, { request: async () => ({ status: 200, body: '' }) });
  assert.equal(noPoc.status, 'unreplayable');
  assert.match(noPoc.reason, /PoC/);

  const boom = await replayVuln(VULN, { request: async () => { throw new Error('ECONNREFUSED'); } });
  assert.equal(boom.status, 'unreplayable');
  assert.match(boom.reason, /ECONNREFUSED/);
});

test('annotateRepro：每条 finding 挂判定，summary.repro 计数自洽', async () => {
  const report = {
    target: { url: VULN.poc.url },
    vulns: [VULN, { ...VULN, param: 'tag', poc: undefined }],
  };
  const summary = await annotateRepro(report, { request: async () => ({ status: 200, body: 'same' }) });
  assert.equal(summary.checked, 2);
  assert.equal(summary.reproduced, 1);
  assert.equal(summary.unreplayable, 1);
  assert.equal(summary.singleHit, 0);
  assert.equal(report.vulns[0].repro.status, 'reproduced');
  assert.equal(report.vulns[1].repro.status, 'unreplayable');
  assert.deepEqual(report.summary.repro, summary);
});

test('writeReproPack：每条一份 sh + expect.json，索引带判定状态，文件名不逃目录', () => {
  const dir = mkdtempSync(join(tmpdir(), 'repro-pack-'));
  try {
    const report = {
      target: { url: VULN.poc.url },
      vulns: [
        { ...VULN, repro: { status: 'reproduced' } },
        { ...VULN, param: '../../etc/passwd', repro: { status: 'single_hit' } },
      ],
    };
    const r = writeReproPack(report, dir, { repeats: 2, target: VULN.poc.url });
    assert.equal(r.count, 2);
    const files = readdirSync(dir).sort();
    assert.equal(files.length, 5); // 2 sh + 2 expect + README
    const index = readFileSync(join(dir, 'README.md'), 'utf8');
    assert.match(index, /reproduced/);
    assert.match(index, /single_hit/);
    assert.match(index, /一致 ≠ 漏洞仍存在/);
    for (const f of files.filter((x) => x.endsWith('.sh'))) {
      assert.ok(!f.includes('..') && !f.includes('/'), `文件名不安全：${f}`);
    }
    const expect = JSON.parse(readFileSync(join(dir, files.find((f) => f.endsWith('.expect.json'))), 'utf8'));
    assert.equal(expect.expect, 'consistent');
    // 安全化本身也要有牙：`..` 与斜杠都不得存活
    assert.equal(safeReproName('../../etc/passwd'), 'etc_passwd');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
