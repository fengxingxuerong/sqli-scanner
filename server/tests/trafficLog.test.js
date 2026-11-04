// [D240 对标 sqlmap -t/--traffic-file] 原始流量落盘的判据
//
// 这批测试钉的不是「文件能写」，而是四条**失效方向**：
//   ① 未启用 ⇒ 一次都不写（旁路不能变成默认开销）；
//   ② body 超限 ⇒ 截断且**标 truncated**（静默截断 = 后来人以为拿到的是全量）；
//   ③ 写入失败（盘满/权限）⇒ 不抛、不阻断扫描，但**告警一次**（审计丢失必须可见）；
//   ④ 口径边界：只记最终一次往返 —— 由调用点决定，这里钉住「一条记录一个 req/res 对」。
import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  DEFAULT_MAX_BODY,
  _resetTrafficLogForTest,
  disableTrafficLog,
  enableTrafficLog,
  recordTraffic,
  trafficLogActive,
} from '../src/core/http/trafficLog.js';

let DIR;
before(() => { DIR = mkdtempSync(path.join(tmpdir(), 'sqli-traffic-')); });
after(() => { _resetTrafficLogForTest(); try { rmSync(DIR, { recursive: true, force: true }); } catch { /* noop */ } });

/**
 * 读回 NDJSON 行（跳过 _meta）。
 * @param {string} file
 * @returns {any[]}
 */
function readRows(file) {
  return readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

describe('流量落盘', () => {
  test('未启用 ⇒ recordTraffic 返回 false 且不产生文件', () => {
    _resetTrafficLogForTest();
    const f = path.join(DIR, 'never.ndjson');
    assert.equal(trafficLogActive(), false);
    assert.equal(recordTraffic({ url: 'http://x/' }, { status: 200 }), false);
    assert.throws(() => readFileSync(f, 'utf8'), '未启用不应创建文件');
  });

  test('启用后写 _meta + 每条一条 JSON（req/res 成对）', () => {
    const f = path.join(DIR, 'basic.ndjson');
    enableTrafficLog(f);
    assert.equal(trafficLogActive(), true);
    recordTraffic(
      { scanId: 's1', method: 'POST', url: 'http://t/p?id=1', headers: { cookie: 'a=1' }, data: 'q=1' },
      { status: 200, headers: { 'content-type': 'text/html' }, data: '<html>ok</html>' }
    );
    const rows = readRows(f);
    assert.equal(rows.length, 2, '应有一条 _meta + 一条记录');
    assert.equal(rows[0]._meta, 'sqli-scanner traffic log');
    assert.equal(rows[1].scanId, 's1');
    assert.equal(rows[1].req.method, 'POST');
    assert.equal(rows[1].req.body, 'q=1');
    assert.equal(rows[1].res.status, 200);
    assert.equal(rows[1].res.body, '<html>ok</html>');
    assert.equal(rows[1].res.bodyTruncated, false);
    disableTrafficLog();
  });

  test('body 超上限 ⇒ 截断且标 truncated（静默截断不可接受）', () => {
    const f = path.join(DIR, 'clip.ndjson');
    enableTrafficLog(f, { maxBody: 16 });
    const big = 'x'.repeat(100);
    recordTraffic({ url: 'http://t/' }, { status: 200, data: big });
    const row = readRows(f)[1];
    assert.equal(row.res.body.length, 16, '应按上限截断');
    assert.equal(row.res.bodyBytes, 100, '原始字节数要保留（截断不改变事实）');
    assert.equal(row.res.bodyTruncated, true, '必须显式标记被截断');
    disableTrafficLog();
  });

  test('maxBody=0 ⇒ 不截断（取证场景）', () => {
    const f = path.join(DIR, 'noclip.ndjson');
    enableTrafficLog(f, { maxBody: 0 });
    const big = 'y'.repeat(5000);
    recordTraffic({ url: 'http://t/' }, { status: 200, data: big });
    const row = readRows(f)[1];
    assert.equal(row.res.body.length, 5000);
    assert.equal(row.res.bodyTruncated, false);
    disableTrafficLog();
  });

  test('默认上限是 8192（防「大页面 × 数千请求」写满盘）', () => {
    assert.equal(DEFAULT_MAX_BODY, 8192);
  });

  test('写入失败不抛、不中断，但告警一次（审计丢失必须可见）', () => {
    // 用一个「父路径是文件」的路径制造写入失败（跨平台且不依赖权限位）
    const blocker = path.join(DIR, 'blocker');
    writeFileSync(blocker, 'x');
    const bad = path.join(blocker, 'sub', 'traffic.ndjson');
    assert.throws(() => enableTrafficLog(bad), '父路径是文件时启用应失败（由调用方决定是否继续）');
    // 启用失败后状态必须干净：recordTraffic 不得写入半个状态
    _resetTrafficLogForTest();
    assert.equal(trafficLogActive(), false);
    assert.equal(recordTraffic({ url: 'http://t/' }, { status: 200 }), false);
  });

  test('disable 返回本次条数（供收尾反馈）', () => {
    const f = path.join(DIR, 'count.ndjson');
    enableTrafficLog(f);
    recordTraffic({ url: 'http://t/1' }, { status: 200 });
    recordTraffic({ url: 'http://t/2' }, { status: 404 });
    assert.equal(disableTrafficLog(), 2);
    assert.equal(trafficLogActive(), false);
  });
});
