// ============================================================================
// tests/support/listenSafe.test.js —— 端口安全分配器的判据（D224 2026-10-31）
//
// 为什么这道自证必须存在：helper 的价值是「消灭一类偶发红」，而偶发红**没法靠跑一遍证明
// 已经修好**（0.025% 的概率，跑一万次也可能一次都不命中）。所以判据不能是「跑起来绿」，
// 必须是**机制层面的证明**：
//   ① 清单真实性：清单里的端口，内置 fetch 确实以 `bad port` 拒绝（行为验证，不是抄文档）；
//   ② 分配器有效性：listenSafe 返回的端口**永远**不在清单里（多次采样 + 单调性）；
//   ③ 自证判据有牙：把监听逻辑换回裸 `listen(0)` 时，若恰好落在清单上必须能被本判据抓住 ——
//      用「注入固定端口」的等价形态模拟（不去赌随机数）。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { UNDICI_BLOCKED_PORTS, isBlockedPort, listenSafe, listenAppSafe } from './listenSafe.js';

test('① 清单真实性：清单里的端口，内置 fetch 必须以 bad port 拒绝', async () => {
  // 只抽样 3 个（全量 78 个要绑 78 次，太慢）：选可绑定的高位端口，避开 privileged
  const sample = [2049, 4045, 5060, 6665, 10080].filter((p) => UNDICI_BLOCKED_PORTS.has(p));
  assert.ok(sample.length >= 3, '清单里竟然没有这几个高位 blocked 端口 —— 清单可能被大幅改小');
  const verified = [];
  for (const port of sample.slice(0, 3)) {
    const server = http.createServer((_q, r) => r.end('ok'));
    try {
      await new Promise((res, rej) => { server.once('error', rej); server.listen(port, '127.0.0.1', res); });
    } catch {
      continue; // 端口被本机别的进程占着 ⇒ 无法验证，跳过（不是判据失败）
    }
    let rejected = false;
    try {
      await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(2000) });
    } catch (e) {
      rejected = e?.cause?.code === 'bad port' || /bad port/i.test(String(e?.cause?.message || ''));
    }
    await new Promise((r) => server.close(r));
    assert.equal(rejected, true, `端口 ${port} 在清单里，但 fetch 没有以 bad port 拒绝 ⇒ 清单与运行时脱节`);
    verified.push(port);
  }
  assert.ok(verified.length >= 2, `只验证到 ${verified.length} 个端口（期望 ≥2）—— 本机端口占用过多，判据没跑实`);
});

test('② 分配器有效性：listenSafe 返回的端口永不在清单里（多次采样）', async () => {
  const ports = [];
  for (let i = 0; i < 12; i++) {
    const srv = await listenSafe();
    const port = srv.address().port;
    ports.push(port);
    assert.equal(isBlockedPort(port), false, `listenSafe 返回了 blocked 端口 ${port} —— 分配器失效`);
    // 顺带验证它真的可 fetch（这才是分配器要保证的最终性质）
    const res = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(3000) });
    assert.equal(res.status, 200, 'listenSafe 返回的端口 fetch 不通');
    await new Promise((r) => srv.close(r));
  }
  // ⚠ 不断言「12 次端口两两不同」：close 之后内核**会**回收端口，采样到重复是合法的
  //   （实测确实会重复；写死这条等于自己制造一个新的随机红 —— 本批刚修完同类 flake）。
  //   真正要保证的性质是「每次都能 fetch 通」，上面每条已断言；这里只做一个宽松的多样性下限。
  assert.ok(new Set(ports).size >= 3, `12 次只分配到 ${new Set(ports).size} 个不同端口 —— 可能写死了端口而非走内核分配`);
});

test('②b listenAppSafe：express 式 listen(0, host, cb) 形态同样避开雷区', async () => {
  // 用一个最小替身实现 express 的 listen 语义（真 express 由各测试自己创建）
  const fakeApp = {
    listen(port, host, cb) {
      const s = http.createServer((_q, r) => r.end('app'));
      s.listen(port, host, cb);
      return s;
    },
  };
  for (let i = 0; i < 4; i++) {
    const srv = await listenAppSafe(fakeApp);
    const port = srv.address().port;
    assert.equal(isBlockedPort(port), false, `listenAppSafe 返回了 blocked 端口 ${port}`);
    const res = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(3000) });
    assert.equal(res.status, 200);
    await new Promise((r) => srv.close(r));
  }
});

test('③ 自证：判据对「裸 listen(0) 落在雷区」的形态有反应', async () => {
  // 不赌随机数：直接把一个 known-blocked 端口交给同样的判定链，
  // 证明「若分配器没避开，这里的断言会红」。
  const blocked = 2049;
  assert.equal(isBlockedPort(blocked), true, '判定函数对 known-blocked 端口返回了 false');

  const server = http.createServer((_q, r) => r.end('ok'));
  await new Promise((res, rej) => { server.once('error', rej); server.listen(blocked, '127.0.0.1', res); });
  let failedAsExpected = false;
  try {
    await fetch(`http://127.0.0.1:${blocked}/`, { signal: AbortSignal.timeout(2000) });
  } catch (e) {
    failedAsExpected = e?.cause?.code === 'bad port' || /bad port/i.test(String(e?.cause?.message || ''));
  }
  await new Promise((r) => server.close(r));
  assert.equal(failedAsExpected, true,
    '裸端口 ' + blocked + ' 竟然 fetch 成功 ⇒ 要么清单错了，要么运行时行为变了（本判据要跟着改）');

  // 反向：清单外的随机端口必须能通（否则「避开清单」这个策略本身没意义）
  const srv = await listenSafe();
  const port = srv.address().port;
  assert.ok(!UNDICI_BLOCKED_PORTS.has(port));
  const res = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(3000) });
  assert.equal(res.status, 200);
  await new Promise((r) => srv.close(r));
});
