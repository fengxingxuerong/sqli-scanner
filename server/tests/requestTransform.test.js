// [D32 实战 P0-1] 自定义请求变换扩展点 —— 模块级行为与四条硬约束
//
// 这批测试钉的不是「函数能跑」，而是四条**失效方向**：
//   ① 不传脚本 ⇒ 逐位零变化（连对象引用都不换）；
//   ② 脚本失败 ⇒ 请求不发（fail-closed）；「算不出签名就发没签名的」是静默假阴性的源头；
//   ③ 脚本只能改 url/method/headers/data/params ⇒ 不得摘掉 signal/scanId/限速；
//   ④ 不得原地改调用方 opts ⇒ HttpClient 重试复用同一个对象，改过一次等于签两遍。
import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  TRANSFORMABLE_KEYS,
  applyScanTransform,
  assertScriptPath,
  ensureScanTransform,
  loadRequestScript,
  notifyTransformOutcome,
  registerScanTransform,
  releaseScanTransform,
  scanTransformCount,
  setTransformObserver,
  transformActiveForScan,
} from '../src/core/requestTransform.js';
import { ErrorCode } from '../src/core/errors.js';

let DIR;
before(() => { DIR = mkdtempSync(path.join(tmpdir(), 'sqli-xform-')); process.env.REQUEST_SCRIPT_DIR = DIR; });
after(() => {
  releaseScanTransform('s-any');
  delete process.env.REQUEST_SCRIPT_DIR;
  try { rmSync(DIR, { recursive: true, force: true }); } catch { /* 临时目录清理失败不影响结论 */ }
});

/** 写一个一次性脚本（每次唯一文件名：import() 有模块缓存，同名改写会读到旧模块） */
let seq = 0;
function script(body) {
  const file = path.join(DIR, `signer${++seq}.mjs`);
  writeFileSync(file, body, 'utf8');
  return file;
}

describe('路径闸门（REQUEST_SCRIPT_DIR 白名单根）', () => {
  test('未设置白名单根 ⇒ 拒绝加载任何脚本（不是"放行但告警"）', () => {
    const saved = process.env.REQUEST_SCRIPT_DIR;
    delete process.env.REQUEST_SCRIPT_DIR;
    try {
      // ⚠ 断言取「未设置」这一支独有的文案：只按 /REQUEST_SCRIPT_DIR/ 匹配会被
      //   「目录不存在」那支顺带满足（变异验证 F 实测：把 root 判据摘掉仍然全绿）。
      assert.throws(
        () => assertScriptPath(script('export function transform(r){return r}\n')),
        (e) => e.code === ErrorCode.REQUEST_SCRIPT_INVALID && /拒绝加载任何脚本/.test(e.message),
      );
    } finally { process.env.REQUEST_SCRIPT_DIR = saved; }
  });

  test('白名单根之外的**已存在**脚本 ⇒ 拒（真测包含判定，而不是被"不存在"分支顺带挡住）', () => {
    const inside = script('export function transform(r){return r}\n');
    assert.ok(assertScriptPath(inside).resolved);
    // 落在 DIR 之外但真实存在：如果只拿一个不存在的路径来测，「不存在」分支会先命中，
    // 包含判定本身坏没坏根本看不出来（假绿）。
    const outside = path.join(tmpdir(), `sqli-xform-outside-${path.basename(DIR)}.mjs`);
    writeFileSync(outside, 'export function transform(r){return r}\n', 'utf8');
    try {
      assert.throws(() => assertScriptPath(outside), /不在 REQUEST_SCRIPT_DIR/);
      // `..` 写法与绝对路径写法必须同判（同一道闸，不能只认一种形态）
      assert.throws(
        () => assertScriptPath(path.join(DIR, '..', path.basename(outside))),
        /不在 REQUEST_SCRIPT_DIR/,
      );
    } finally { rmSync(outside, { force: true }); }
  });

  test('后缀 / 不存在 / 不是普通文件 / 空路径 四种非法各自报错文案点名原因', () => {
    assert.throws(() => assertScriptPath(path.join(DIR, 'a.txt')), /必须是 \.js\/\.mjs\/\.cjs/);
    assert.throws(() => assertScriptPath(path.join(DIR, 'nope.mjs')), /不存在/);
    mkdirSync(path.join(DIR, 'adir.js'));
    assert.throws(() => assertScriptPath(path.join(DIR, 'adir.js')), /不是普通文件/);
    assert.throws(() => assertScriptPath('   '), /路径为空/);
  });

  test('没有 transform 导出 ⇒ 拒（并在文案里给出可接受的两种形态）', async () => {
    const f = script('export const nope = 1;\n');
    await assert.rejects(loadRequestScript(f), /必须导出 transform/);
  });

  test('脚本自身语法错 ⇒ 拒且带回底层原因，不静默返回 null', async () => {
    const f = script('export function transform(r){ return ((( }\n');
    await assert.rejects(loadRequestScript(f), (e) => e.code === ErrorCode.REQUEST_SCRIPT_INVALID);
  });

  test('三种导出形态都认，且 sha256 由文件内容算出（报告取证用）', async () => {
    const forms = [
      'export function transform(r){ r.headers = r.headers || {}; r.headers["X-K"]="1"; return r }\n',
      'export default function (r){ r.headers = r.headers || {}; r.headers["X-K"]="1"; return r }\n',
      'export default { transform(r){ r.headers = r.headers || {}; r.headers["X-K"]="1"; return r } };\n',
    ];
    for (const body of forms) {
      const entry = await loadRequestScript(script(body));
      assert.equal(typeof entry.fn, 'function');
      assert.match(entry.sha256, /^[0-9a-f]{64}$/);
    }
  });
});

describe('未开启时的零变化契约', () => {
  test('未登记 scanId ⇒ applyScanTransform 原样返回**同一个对象引用**', async () => {
    const opts = { url: 'http://t/x?id=1', method: 'GET', headers: { A: 'b' } };
    const out = await applyScanTransform('s-none', opts);
    assert.equal(out.opts, opts, '未开启时不得拷贝/包装（性能与语义都应保持原样）');
    assert.equal(out.injected, false);
    assert.equal(transformActiveForScan('s-none'), false);
  });

  test('config 无 requestScript ⇒ ensureScanTransform 返回 null 且不登记', async () => {
    assert.equal(await ensureScanTransform('s-empty', { requestScript: '' }), null);
    assert.equal(await ensureScanTransform('s-empty', {}), null);
    assert.equal(transformActiveForScan('s-empty'), false);
  });
});

describe('变换本体', () => {
  test('签名注入 query 与头；返回的新 opts 保留脚本无权改的引擎键', async () => {
    const f = script(`export function transform(r){
      r.url = r.url + '&sign=abc';
      r.headers = { ...r.headers, 'X-Sign': 'abc' };
      r.scanId = 'HACKED'; r.signal = undefined; r.retry = 99; r.rateGroup = 'x';
      return r;
    }\n`);
    registerScanTransform('s1', await loadRequestScript(f));
    const signal = { aborted: false };
    const base = {
      url: 'http://t/p?id=1', method: 'GET', headers: { Accept: '*/*' },
      scanId: 's1', signal, retry: 2, rateGroup: 'g1',
    };
    const { opts } = await applyScanTransform('s1', base);
    assert.match(opts.url, /sign=abc$/);
    assert.equal(opts.headers['X-Sign'], 'abc');
    assert.equal(opts.headers.Accept, '*/*');
    // 引擎控制权：脚本赋值必须被忽略（TRANSFORMABLE_KEYS 之外一律不透传）
    assert.equal(opts.scanId, 's1');
    assert.equal(opts.signal, signal);
    assert.equal(opts.retry, 2);
    assert.equal(opts.rateGroup, 'g1');
    assert.deepEqual([...TRANSFORMABLE_KEYS], ['url', 'method', 'headers', 'data', 'params']);
    releaseScanTransform('s1');
  });

  test('不得原地修改入参 opts（重试复用同一对象 ⇒ 原地改等于签两遍）', async () => {
    const f = script('export function transform(r){ r.url = r.url + "&sign=1"; r.headers["X-S"]="1"; return r }\n');
    registerScanTransform('s2', await loadRequestScript(f));
    const base = { url: 'http://t/a', method: 'GET', headers: {} };
    const first = await applyScanTransform('s2', base);
    assert.equal(base.url, 'http://t/a', '入参被回写了');
    assert.deepEqual(base.headers, {});
    // 第二次（模拟重放）必须与第一次同形，而不是在已签名的 URL 上再加一次
    const second = await applyScanTransform('s2', base);
    assert.equal(second.opts.url, first.opts.url);
    releaseScanTransform('s2');
  });

  test('注入请求的 injected 标记在**签名之前**判定（整包加密后密文里看不见 payload）', async () => {
    const f = script('export function transform(r){ r.url = "http://t/enc?b=Zm9vYmFy"; return r }\n');
    registerScanTransform('s3', await loadRequestScript(f));
    const inj = await applyScanTransform('s3', { url: "http://t/p?id=1' AND 1=1-- -", method: 'GET', headers: {} });
    const baseReq = await applyScanTransform('s3', { url: 'http://t/p?id=1', method: 'GET', headers: {} });
    assert.equal(inj.injected, true, 'payload 在签名前就该被识别出来');
    assert.equal(baseReq.injected, false);
    releaseScanTransform('s3');
  });

  test('async 脚本（要算 HMAC / 取时钟）支持', async () => {
    const f = script('export async function transform(r){ await new Promise((k)=>setTimeout(k,1)); r.url = r.url + "&t=ok"; return r }\n');
    registerScanTransform('s4', await loadRequestScript(f));
    const { opts } = await applyScanTransform('s4', { url: 'http://t/x', method: 'GET', headers: {} });
    assert.match(opts.url, /&t=ok$/);
    releaseScanTransform('s4');
  });
});

describe('fail-closed（本扩展点最重要的一条）', () => {
  test('脚本抛异常 ⇒ 上抛 REQUEST_SCRIPT_FAILED，**绝不返回原始 opts**', async () => {
    const f = script('export function transform(){ throw new Error("key missing") }\n');
    registerScanTransform('s5', await loadRequestScript(f));
    await assert.rejects(
      applyScanTransform('s5', { url: 'http://t/x', method: 'GET', headers: {} }),
      (e) => e.code === ErrorCode.REQUEST_SCRIPT_FAILED && /key missing/.test(e.message),
    );
    releaseScanTransform('s5');
  });

  test('返回 null / 非对象 / 空 url / 非对象 headers ⇒ 一律拒，不降级发送', async () => {
    const bad = [
      ['export function transform(){ return null }\n', /必须返回请求对象/],
      ['export function transform(){ return "x" }\n', /必须返回请求对象/],
      ['export function transform(){ return [] }\n', /必须返回请求对象/],
      ['export function transform(r){ return { ...r, url: "" } }\n', /url 必须是非空字符串/],
      ['export function transform(r){ return { ...r, headers: "x" } }\n', /headers 必须是对象/],
    ];
    for (const [body, re] of bad) {
      registerScanTransform('s6', await loadRequestScript(script(body)));
      await assert.rejects(
        applyScanTransform('s6', { url: 'http://t/x', method: 'GET', headers: {} }),
        (e) => e.code === ErrorCode.REQUEST_SCRIPT_FAILED && re.test(e.message),
        `产出形态 ${body.trim().slice(0, 40)} 应被拒`,
      );
      releaseScanTransform('s6');
    }
  });

  test('脚本只返回部分字段 ⇒ 未返回的字段沿用原值（不能把 data 弄丢）', async () => {
    const f = script('export function transform(r){ return { url: r.url + "&s=1" } }\n');
    registerScanTransform('s7', await loadRequestScript(f));
    const { opts } = await applyScanTransform('s7', {
      url: 'http://t/x', method: 'POST', headers: { A: 'b' }, data: '{"id":1}',
    });
    assert.equal(opts.method, 'POST');
    assert.equal(opts.headers.A, 'b');
    assert.equal(opts.data, '{"id":1}');
    assert.match(opts.url, /&s=1$/);
    releaseScanTransform('s7');
  });
});

describe('登记回收与观察者', () => {
  test('ensureScanTransform 登记 → releaseScanTransform 回收，计数回到基线', async () => {
    const f = script('export function transform(r){ return r }\n');
    const before0 = scanTransformCount();
    const info = await ensureScanTransform('s8', { requestScript: f });
    assert.equal(transformActiveForScan('s8'), true);
    assert.equal(info.file, path.basename(f));
    assert.match(info.sha256, /^[0-9a-f]{64}$/);
    assert.equal(scanTransformCount(), before0 + 1);
    releaseScanTransform('s8');
    assert.equal(transformActiveForScan('s8'), false);
    assert.equal(scanTransformCount(), before0, '回收必须真的减回去（长驻进程的 Map 无界增长是本仓反复出现的坑）');
  });

  test('ensureScanTransform 失败 ⇒ 不留下半截登记', async () => {
    const before0 = scanTransformCount();
    await assert.rejects(ensureScanTransform('s9', { requestScript: path.join(DIR, 'missing.mjs') }));
    assert.equal(transformActiveForScan('s9'), false);
    assert.equal(scanTransformCount(), before0);
  });

  test('观察者收到回传；观察者抛错被吞（不得影响发包）', () => {
    const seen = [];
    registerScanTransform('s10', { fn: (r) => r, source: 'x', sha256: 'y' });
    assert.equal(setTransformObserver('s10', (ev) => { seen.push(ev); }), true);
    notifyTransformOutcome('s10', { injected: true, res: { status: 400 } });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].injected, true);
    // 换成会抛的观察者
    setTransformObserver('s10', () => { throw new Error('guard bug'); });
    assert.doesNotThrow(() => notifyTransformOutcome('s10', { injected: false, res: { status: 200 } }));
    // 摘掉观察者后不再回传
    setTransformObserver('s10', null);
    notifyTransformOutcome('s10', { injected: true, res: { status: 400 } });
    assert.equal(seen.length, 1);
    releaseScanTransform('s10');
  });

  test('未登记的 scanId ⇒ setTransformObserver 返回 false（接线失败必须可判，不能静默）', () => {
    assert.equal(setTransformObserver('s-ghost', () => {}), false);
  });
});
