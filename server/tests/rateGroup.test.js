// ============================================================================
// rateGroup.test.js —— 批量共享限速桶（谁在用谁拿，总量由单桶保证）
//
// 背景（交付文档 §7.8 记过的边界）：跨目标限速原为「启动时按并发度均分」
// （ratePerSec / concurrency，算一次就不再变）⇒ 队列排空后剩下的目标仍按 1/并发度 跑，
// 预算白白闲着。本批改成**整批共用一个令牌桶**：
//   ① 总速率严格 ≤ ratePerSec —— 由**单桶**保证，不依赖"均分算得准不准"；
//   ② 谁在用谁就能拿 —— 排空后剩下的目标自动吃满，不需要运行期改桶速率。
//
// 判据三条，缺一不可：
//   · 给了 rateKey ⇒ 两个 scanId **共用同一个桶对象**（不是各建一个）；
//   · 共享是真的：A 消耗令牌后，B 看到的桶 tokens 也变少（不是只比对象地址）；
//   · 不给 rateKey ⇒ 行为与原来完全一致（per-scan 桶）—— 这是零回归的前提。
// ============================================================================
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { HttpClient } from '../src/core/httpClient.js';

let server;
let baseUrl;

before(async () => {
  server = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((r) => server.close(r));
});

describe('[rateGroup] forScan 共享桶', () => {
  test('给了 rateKey ⇒ 两个 scanId 共用同一个桶对象', () => {
    const c = new HttpClient();
    const a = c.forScan('scan-a', 10, 'grp-1');
    const b = c.forScan('scan-b', 10, 'grp-1');
    assert.ok(a && b, '两个视图都应建出来');
    const bucketA = c.buckets.get('grp-1');
    assert.ok(bucketA, '组桶应挂在 rateKey 上');
    // ⚠ 组桶模式下**不再**按 scanId 建桶 —— 否则每个扫描还是各限各的，共享等于没做
    assert.equal(c.buckets.get('scan-a'), undefined, '组桶模式下不应再建 per-scan 桶');
    assert.equal(c.buckets.get('scan-b'), undefined, '组桶模式下不应再建 per-scan 桶');
    // 后建者不能覆盖先建者的桶（重建会重置令牌 ⇒ 先跑的扫描白等一轮）
    const b2 = c.forScan('scan-c', 10, 'grp-1');
    assert.ok(b2);
    assert.equal(c.buckets.get('grp-1'), bucketA, '同组再建桶时不得重置已有桶对象');
  });

  test('★共享是真的：A 消耗令牌后 B 的桶 tokens 同步变少', async () => {
    const c = new HttpClient();
    const a = c.forScan('scan-a', 10, 'grp-2');
    const b = c.forScan('scan-b', 10, 'grp-2');
    const bucket = c.buckets.get('grp-2');
    assert.ok(bucket);
    // 先跑一次让桶进入稳定态（初始 tokens = capacity = rate）
    await a.request({ method: 'GET', url: `${baseUrl}/x` });
    const after1 = bucket.tokens;
    await b.request({ method: 'GET', url: `${baseUrl}/y` });
    const after2 = bucket.tokens;
    assert.ok(
      after2 < after1,
      `两个视图必须共扣同一个桶：A 之后 ${after1} → B 之后 ${after2}（没减少 = 各限各的）`,
    );
  });

  test('不给 rateKey ⇒ 仍是 per-scan 桶（向后兼容，零回归）', () => {
    const c = new HttpClient();
    c.forScan('scan-x', 10);
    c.forScan('scan-y', 10);
    const bx = c.buckets.get('scan-x');
    const by = c.buckets.get('scan-y');
    assert.ok(bx && by, '未给 rateKey 时必须按 scanId 建桶（既有行为）');
    assert.notEqual(bx, by, '两个扫描的桶必须是各自独立的（既有行为）');
  });

  test('不限速语义不变：rate<=0 的组桶也是不限速', async () => {
    const c = new HttpClient();
    const a = c.forScan('scan-u1', 0, 'grp-unlimited');
    const bucket = c.buckets.get('grp-unlimited');
    assert.equal(bucket.ratePerSec, 0, '0 = 不限速（tokenBucket 的既有语义，不能改成默认值）');
    const t0 = Date.now();
    await a.request({ method: 'GET', url: `${baseUrl}/x` });
    await a.request({ method: 'GET', url: `${baseUrl}/y` });
    assert.ok(Date.now() - t0 < 1000, '不限速时连续两次请求不应被令牌桶拖住');
  });
});

describe('[rateGroup] 限速解析优先级', () => {
  test('_resolveRateBucket 优先 rateKey，其次 scanId', () => {
    const c = new HttpClient();
    c.createBucket('scan-p', 10);
    c.createBucket('grp-p', 10);
    const hit = c._resolveRateBucket({ scanId: 'scan-p', rateKey: 'grp-p' }, 10);
    assert.equal(hit, c.buckets.get('grp-p'), 'rateKey 必须优先 —— 反过来的话组桶永远拿不到');
    const onlyScan = c._resolveRateBucket({ scanId: 'scan-p' }, 10);
    assert.equal(onlyScan, c.buckets.get('scan-p'), '无 rateKey 时回落到 scanId 桶（既有行为）');
  });

  // [2026-10-03 CI #131] 组桶查不到时**惰性重建**而不是回退 —— 旧行为是静默落到
  // scanId/rate 桶，「单桶总量保证」在异常路径下悄悄变成每扫描各一个桶。
  test('★组桶缺失时惰性重建：请求走完后组 key 下必须重新有桶（不回退 per-scan）', async () => {
    const c = new HttpClient();
    const a = c.forScan('scan-a', 10, 'grp-resurrect');
    c.buckets.delete('grp-resurrect'); // 模拟组桶被外力清掉（如旧版本退役逻辑 / Map 被动过）
    await a.request({ method: 'GET', url: `${baseUrl}/x` });
    assert.ok(c.buckets.has('grp-resurrect'), '请求后组 key 必须重新有桶 —— 回退 per-scan/ rate 桶 = 总量保证失效');
    assert.equal(c.buckets.get('scan-a'), undefined, '绝不能在 scanId 下建桶（那是共享语义的死亡）');
    const rebuilt = c.buckets.get('grp-resurrect');
    assert.equal(rebuilt.ratePerSec, 10, '重建桶的速率取 effectiveRate（与 forScan 建桶口径一致）');
    // 重建后仍共享：b 视图（同组）扣的是同一个桶对象
    const b = c.forScan('scan-b', 10, 'grp-resurrect');
    const before = rebuilt.tokens;
    await b.request({ method: 'GET', url: `${baseUrl}/y` });
    assert.ok(rebuilt.tokens < before || c.buckets.get('grp-resurrect') === rebuilt, '重建后的组桶必须仍是同一个对象（共享不因重建断开）');
  });
});

describe('[rateGroup] 组桶引用计数回收（2026-10-03 CI #131）', () => {
  test('最后一个成员退役才删桶；先退出的不拆还在跑的桶', () => {
    const c = new HttpClient();
    c.forScan('scan-a', 10, 'grp-refs');
    c.forScan('scan-b', 10, 'grp-refs');
    const bucket = c.buckets.get('grp-refs');
    assert.ok(bucket, '前提：组桶已建');
    assert.equal(c.releaseGroupBucket('scan-a'), false, '还有成员在用 ⇒ 桶必须留着');
    assert.equal(c.buckets.get('grp-refs'), bucket, '先退出者不得删除组桶对象');
    assert.equal(c.releaseGroupBucket('scan-b'), true, '最后一个成员退役 ⇒ 桶删除（返回 true）');
    assert.equal(c.buckets.get('grp-refs'), undefined, '组桶已从注册表移除（REST 长驻进程防泄漏）');
  });

  test('未注册的 scanId 释放是安全 no-op；同一 scanId 重复注册不重复计数', () => {
    const c = new HttpClient();
    assert.equal(c.releaseGroupBucket('scan-ghost'), false, '未注册 scanId ⇒ no-op，不抛错');
    c.forScan('scan-dup', 10, 'grp-dup');
    c.forScan('scan-dup', 10, 'grp-dup'); // 防御：getScanClient 有缓存，这里模拟意外重复调用
    assert.equal(c.releaseGroupBucket('scan-dup'), true, '重复注册只计一次 ⇒ 一次释放即删');
    assert.equal(c.buckets.get('grp-dup'), undefined);
  });

  test('组桶删光后新成员加入 ⇒ 建新桶照常共享（重建路径与 forScan 汇合）', () => {
    const c = new HttpClient();
    c.forScan('scan-e1', 10, 'grp-cycle');
    c.releaseGroupBucket('scan-e1');
    c.forScan('scan-e2', 10, 'grp-cycle');
    c.forScan('scan-e3', 10, 'grp-cycle');
    assert.ok(c.buckets.get('grp-cycle'), '新成员加入应重建组桶');
    assert.equal(c.releaseGroupBucket('scan-e2'), false);
    assert.equal(c.releaseGroupBucket('scan-e3'), true);
  });
});
