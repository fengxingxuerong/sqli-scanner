// [D32 实战 P0-1] 请求变换层的**接线**验证 —— 从 sm.getScanClient 进、从内层客户端
// 实际收到的请求出。
//
// 为什么不满足于 requestTransform.test.js 的纯函数绿：本仓反复出现「被调函数是对的、
// 调用链下一环是坏的」（§O 的 multipart 导入、§N 的 --body、§L 的白名单断口都是这一族）。
// 这里断言的是"引擎真正发出去的那条请求带没带签名"，不是"变换函数会不会签名"。
import { test, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';

import { ScanManager } from '../src/engine/ScanManager.js';
import {
  ensureScanTransform,
  releaseScanTransform,
  setTransformObserver,
  transformActiveForScan,
} from '../src/core/requestTransform.js';
import { ErrorCode } from '../src/core/errors.js';

const DIR = mkdtempSync(path.join(tmpdir(), 'sqli-xform-wire-'));
process.env.REQUEST_SCRIPT_DIR = DIR;
let seq = 0;
function script(body) {
  const f = path.join(DIR, `w${++seq}.mjs`);
  writeFileSync(f, body, 'utf8');
  return f;
}
const SIGNER = script(
  'export function transform(r){ r.url = r.url + (r.url.includes("?") ? "&" : "?") + "sign=SIG"; return r }\n',
);

after(() => {
  releaseScanTransform('w-any');
  delete process.env.REQUEST_SCRIPT_DIR;
  try { rmSync(DIR, { recursive: true, force: true }); } catch { /* 清理失败不影响结论 */ }
});

/** 记录型内层客户端：所有断言都看「它实际收到了什么」；responder 可定制响应形态 */
function stubClient(responder) {
  const sent = [];
  const def = ({ url }) => (String(url || '').includes('/login') && !/method=post/i.test(String(url))
    ? { status: 200, data: '<form action="/login" method="post"><input type="text" name="username"><input type="password" name="password"></form>', headers: { 'content-type': 'text/html' } }
    : { status: 200, data: 'ok', headers: {} });
  const reply = responder || def;
  return {
    sent,
    forScan() {
      return {
        request: async (opts) => {
          sent.push({ kind: 'request', opts });
          return reply(opts, sent.length);
        },
        headRequest: async (url, opts) => {
          sent.push({ kind: 'head', url, opts });
          return { status: 200, data: '', headers: {} };
        },
      };
    },
    removeBucket() {},
    releaseGroupBucket() {},
    removeRequestCount() {},
    clearJar() {},
  };
}

function manager(target, responder) {
  const stub = stubClient(responder);
  const sm = new ScanManager();
  sm.httpClient = stub; // getConnector 对非 direct 目标返回 this.httpClient
  return { sm, stub, target: { url: 'http://target.test/p?id=1', baseUrl: 'http://target.test/p?id=1', mode: 'http', config: target || {} } };
}

describe('接线：引擎发出的请求真的带上了签名', () => {
  test('GET 注入请求经变换后再到出口层', async () => {
    const { sm, stub, target } = manager();
    await ensureScanTransform('w1', { requestScript: SIGNER });
    const view = sm.getScanClient('w1', target);
    await view.request({ url: "http://target.test/p?id=1' AND 1=1-- -", method: 'GET', headers: {} });
    assert.equal(stub.sent.length, 1);
    assert.match(stub.sent[0].opts.url, /sign=SIG/);
    releaseScanTransform('w1');
  });

  test('HEAD（--null-connection）必须走同一层，且用的是**变换后**的 URL', async () => {
    const { sm, stub, target } = manager();
    await ensureScanTransform('w2', { requestScript: SIGNER });
    const view = sm.getScanClient('w2', target);
    await view.headRequest('http://target.test/p?id=1', {});
    assert.equal(stub.sent.length, 1);
    assert.equal(stub.sent[0].kind, 'head');
    // ⚠ HttpClient.headRequest(url, opts) 用第一个实参覆盖 opts.url ⇒ 只改 opts 等于没改
    assert.match(stub.sent[0].url, /sign=SIG/, 'HEAD 的 URL 必须也带签名');
    releaseScanTransform('w2');
  });

  test('脚本无权摘掉引擎控制键（signal/retry/scanId 原样抵达出口层）', async () => {
    const evil = script(
      'export function transform(r){ r.signal = undefined; r.retry = 99; r.scanId = "other"; r.url = r.url + "?sign=1"; return r }\n',
    );
    const { sm, stub, target } = manager();
    await ensureScanTransform('w3', { requestScript: evil });
    const view = sm.getScanClient('w3', target);
    const signal = { aborted: false };
    await view.request({ url: 'http://target.test/p?id=1', method: 'GET', headers: {}, signal, retry: 2, scanId: 'w3' });
    const got = stub.sent[0].opts;
    assert.equal(got.signal, signal, '脚本可以中断 stop() 能力 = 合规闸门被绕过');
    assert.equal(got.retry, 2);
    assert.equal(got.scanId, 'w3');
    releaseScanTransform('w3');
  });

  test('safeUrl 保活页与 csrf 取页也必须带签名（变换层要挂在包装链**最内**）', async () => {
    const { sm, stub, target } = manager({
      safeUrl: 'http://target.test/health',
      safeFreq: 1,
      csrfUrl: 'http://target.test/login',
      csrfTokenName: 'csrf_token',
    });
    await ensureScanTransform('w4', { requestScript: SIGNER });
    const view = sm.getScanClient('w4', target);
    await view.request({ url: 'http://target.test/p?id=1', method: 'GET', headers: {} });
    assert.ok(stub.sent.length >= 2, `保活/取页应当真的发出（实测 ${stub.sent.length} 条）`);
    const unsigned = stub.sent.filter((s) => !/sign=SIG/.test(String(s.opts?.url ?? s.url ?? '')));
    assert.deepEqual(
      unsigned.map((s) => String(s.opts?.url ?? s.url)),
      [],
      '有请求绕过了变换层：内层包装自带自发请求，变换挂在它们之外就会被跳过',
    );
    releaseScanTransform('w4');
  });

  test('config.login 的登录取页与提交也必须带签名（重登路径同一条链）', async () => {
    let scanTries = 0;
    const { sm, stub, target } = manager({
      login: { url: 'http://target.test/login', username: 'alice', password: 'pw' },
    }, (opts) => {
      const u = String(opts.url || '');
      if (u.includes('/login')) {
        if (String(opts.method || 'GET').toUpperCase() === 'POST') return { status: 200, data: 'ok', headers: {} };
        return {
          status: 200,
          data: '<form action="/login" method="post"><input type="text" name="username"><input type="password" name="password"></form>',
          headers: { 'content-type': 'text/html' },
        };
      }
      scanTries += 1;
      // 首条扫描请求吃 401 ⇒ 触发「重登一次 + 重试原请求」（loginFlow 的既有语义）
      return scanTries === 1
        ? { status: 401, data: 'nope', headers: {} }
        : { status: 200, data: 'ok', headers: {} };
    });
    await ensureScanTransform('w9', { requestScript: SIGNER });
    const view = sm.getScanClient('w9', target);
    await view.request({ url: 'http://target.test/p?id=1', method: 'GET', headers: {} });
    const loginHits = stub.sent.filter((s) => /\/login/.test(String(s.opts?.url || '')));
    assert.ok(loginHits.length >= 2, `登录取页 + 提交都应经变换层（实测登录类 ${loginHits.length} 条）`);
    const unsigned = stub.sent.filter((s) => !/sign=SIG/.test(String(s.opts?.url || '')));
    assert.deepEqual(unsigned.map((s) => s.opts.url), [], '有请求绕过了变换层');
    // 重试复用同一个 opts 对象 ⇒ 变换必须是"每次从原始形态重签"，而不是在已签名 URL 上叠加
    const retried = stub.sent.filter((s) => /p\?id=1/.test(String(s.opts?.url || '')));
    assert.ok(retried.length >= 2 && retried.every((s) => /sign=SIG(?!.*sign=)/.test(String(s.opts.url))),
      '重试请求不得被二次签名（sign 只出现一次）');
    releaseScanTransform('w9');
  });

  test('脚本抛异常 ⇒ 出口层一条请求都没收到（fail-closed 在接线层同样成立）', async () => {
    const boom = script('export function transform(){ throw new Error("no key") }\n');
    const { sm, stub, target } = manager();
    await ensureScanTransform('w5', { requestScript: boom });
    const view = sm.getScanClient('w5', target);
    await assert.rejects(
      view.request({ url: 'http://target.test/p?id=1', method: 'GET', headers: {} }),
      (e) => e.code === ErrorCode.REQUEST_SCRIPT_FAILED,
    );
    assert.equal(stub.sent.length, 0, '原始（未签名）请求绝不能发出去');
    releaseScanTransform('w5');
  });

  test('暂停优先于变换：paused 期间连签名都不发生（不得在暂停窗口里加工请求）', async () => {
    const { sm, stub, target } = manager();
    await ensureScanTransform('w6', { requestScript: SIGNER });
    sm.scans.set('w6', { paused: true, cancelled: false, status: 'running' });
    const view = sm.getScanClient('w6', target);
    let signedCount = 0;
    // 观察者只在请求真正发生后被调用 ⇒ 用它计数即可判断"暂停期间有没有在准备请求"
    setTransformObserver('w6', () => { signedCount += 1; });
    const p = view.request({ url: 'http://target.test/p?id=1', method: 'GET', headers: {} });
    await new Promise((k) => setTimeout(k, 250));
    assert.equal(stub.sent.length, 0, '暂停期间不得发包');
    assert.equal(signedCount, 0, '暂停期间不应产生已发送请求的判定素材');
    sm.scans.get('w6').paused = false;
    await p;
    assert.equal(stub.sent.length, 1);
    assert.equal(signedCount, 1);
    sm.scans.delete('w6');
    releaseScanTransform('w6');
  });

  test('未登记脚本的扫描 ⇒ 请求对象原样抵达出口层（默认路径零变化）', async () => {
    const { sm, stub, target } = manager();
    const view = sm.getScanClient('w7', target);
    const opts = { url: 'http://target.test/p?id=1', method: 'GET', headers: { A: 'b' } };
    await view.request(opts);
    assert.equal(stub.sent[0].opts, opts, '未开启变换时连对象引用都不该换');
    assert.equal(stub.sent[0].opts.url, 'http://target.test/p?id=1');
  });

  test('_disposeScan 回收变换登记：回收后新视图不再签名（不只是账面干净）', async () => {
    const { sm, stub, target } = manager();
    await ensureScanTransform('w8', { requestScript: SIGNER });
    assert.equal(transformActiveForScan('w8'), true);
    sm.scans.set('w8', { status: 'completed', createdAt: Date.now() });
    const view = sm.getScanClient('w8', target);
    await view.request({ url: 'http://target.test/p?id=1', method: 'GET', headers: {} });
    assert.match(stub.sent[0].opts.url, /sign=SIG/);

    sm._disposeScan('w8');
    assert.equal(
      transformActiveForScan('w8'), false,
      '扫描退役后变换登记还在 ⇒ 长驻进程里 registry 无界增长',
    );
    // 视图缓存也一并回收，重建后必须回到「不签名」—— 证明回收真的作用到流量上
    stub.sent.length = 0;
    await sm.getScanClient('w8', target).request({ url: 'http://target.test/p?id=2', method: 'GET', headers: {} });
    assert.equal(stub.sent.length, 1, '重建视图后请求仍应抵达出口层');
    assert.doesNotMatch(stub.sent[0].opts.url, /sign=SIG/, '已退役的脚本不该继续改写请求');
  });
});

describe('start() 闸门：脚本非法时扫描不启动', () => {
  test('requestScript 不存在 ⇒ start 抛出且不留下 running 条目（不是"200 + 扫完说未检出"）', async () => {
    const sm = new ScanManager();
    sm.httpClient = stubClient();
    const before = sm.scans.size;
    await assert.rejects(
      sm.start({ url: 'http://target.test/p?id=1', config: { requestScript: path.join(DIR, 'ghost.mjs') } }),
      (e) => e.code === ErrorCode.REQUEST_SCRIPT_INVALID,
    );
    assert.equal(sm.scans.size, before, '失败的扫描不得留下半截上下文');
  });
});
