// ============================================================================
// tests/tamperXforwardedForReservedRanges.test.js
// xforwardedfor 伪造的来源 IP 必须落在公网可路由段
//
// ── 缺陷（实测确认，非推理）──────────────────────────────────────────────────
// core/tamper/plugins/xforwardedfor.js 的 randomIP：
//
//   while (octets.length === 0 || octets[0] === 10 || octets[0] === 172 || octets[0] === 192)
//
// 只挡了私网的**整段首字节** 10/172/192，漏掉：
//   · 127.0.0.0/8    回环
//   · 169.254.0.0/16 链路本地（同时是云元数据段 169.254.169.254）
//   · 0.0.0.0/8      本网络
//   · ≥224           组播/保留
//   · 172.32.0.0+    已经不在私网 B 段内（这里无妨），但 172.16-31 的判定
//     同样只按首字节拦，等于把 172.0.0.0/12 整段当私网 —— 反向过宽，
//     真实公网 172.32+ 段被误杀（次要）
//
// 实测（10 万次 × 2 个头）：
//   组播/保留 24637 次、回环 813 次、链路本地/云元数据 3 次
// ⇒ 约 25% 的伪造头落在**不可路由段**。
//
// 方向是**降低检出能力**：伪造头本是为了绕过"基于来源 IP"的 WAF，
// 而大量 WAF 看到组播/回环/链路本地来源会直接按非法源整体拦截
//（Cloudflare、部分 ModSecurity 规则、云厂商入口都是如此）——
// 插件不但没帮上忙，反而把这些请求推进了更严格的分支。
//
// ⚠️ 修法不能简单地"补一个 if"：不能改成 while 直到合法（可能不终止，
// 或在 Math.random 被 mock 成常数时死循环）。必须是**有界重试**。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { xforwardedfor } from '../src/core/tamper/plugins/xforwardedfor.js';

/** 该 IP 是否为不可路由/保留段（RFC 6890 意义上的"不能作为公网源"） */
function reservedReason(ip) {
  const o = String(ip).split('.').map(Number);
  if (o.length !== 4 || o.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return '非法 IP';
  const [a, b] = o;
  if (a === 0) return '0.0.0.0/8 本网络';
  if (a === 10) return '10/8 私网';
  if (a === 127) return '127/8 回环';
  if (a === 169 && b === 254) return '169.254/16 链路本地（含云元数据）';
  if (a === 172 && b >= 16 && b <= 31) return '172.16/12 私网';
  if (a === 192 && b === 168) return '192.168/16 私网';
  if (a === 100 && b >= 64 && b <= 127) return '100.64/10 CGNAT';
  if (a >= 224) return '≥224 组播/保留';
  return null;
}

/** 收集 n 次 transform 产出的所有 XFF 系头的值 */
function sampleHeads(n) {
  const out = [];
  for (let k = 0; k < n; k++) {
    const h = {};
    xforwardedfor.transform('1', { headers: h });
    out.push(...['X-Forwarded-For', 'X-Client-Ip', 'X-Real-Ip', 'CF-Connecting-IP', 'True-Client-IP']
      .map((k2) => h[k2]).filter(Boolean));
  }
  return out;
}

test('自证-0) 插件确实在写 XFF 系头（否则本组守卫是装饰品）', () => {
  const h = {};
  const r = xforwardedfor.transform('payload', { headers: h });
  assert.equal(r, 'payload', 'payload 被改动了 —— 插件契约变了');
  assert.ok(h['X-Forwarded-For'], 'X-Forwarded-For 未被写入 —— 守卫无效');
  assert.ok(Object.keys(h).length >= 5, `只写了 ${Object.keys(h).length} 个头，插件行为变了`);
});

test('缺陷-1) 伪造来源 IP 不得落在回环段 127/8', () => {
  const bad = sampleHeads(20000).filter((v) => reservedReason(v) === '127/8 回环');
  assert.equal(bad.length, 0,
    `${bad.length} 个伪造头落在 127/8 回环（样本 ${sampleHeads(2000).length} 个），例如 ${bad[0]}`);
});

test('缺陷-2) 伪造来源 IP 不得落在组播/保留段（≥224）', () => {
  const all = sampleHeads(20000);
  const bad = all.filter((v) => (reservedReason(v) || '').includes('组播'));
  assert.equal(bad.length, 0,
    `${bad.length}/${all.length} 个伪造头落在 ≥224 组播/保留段，例如 ${bad[0]}`);
});

test('缺陷-3) 伪造来源 IP 不得落在链路本地 169.254/16（含云元数据）', () => {
  const bad = sampleHeads(20000).filter((v) => (reservedReason(v) || '').includes('链路本地'));
  assert.equal(bad.length, 0, `${bad.length} 个伪造头落在 169.254/16，例如 ${bad[0]}`);
});

test('契约-4) 全部伪造头都必须是可路由的公网地址（一次采样，不分组）', () => {
  const all = sampleHeads(20000);
  const reasons = new Map();
  for (const v of all) {
    const r = reservedReason(v);
    if (r) reasons.set(r, (reasons.get(r) || 0) + 1);
  }
  assert.equal(reasons.size, 0,
    `仍产出 ${reasons.size} 类保留段地址：${JSON.stringify([...reasons])}`);
});

test('契约-5) 必须是有界重试：Math.random 恒落在保留段时不得死循环', async () => {
  // 若实现写成 `while (不合法) 重新随机`，在 random 恒定时会**永不返回**。
  //
  // ⚠️⚠️ 第一版这条例定 `Math.random = () => 0.5`，看起来能触发死循环，
  // 实测发现**触发不了**：
  //   Math.floor(0.5 * 254) + 1 = 128 ⇒ 128.128.128.128 是**可路由**地址
  //   ⇒ while 第一次判断就退出，探针形同虚设。缺陷注入（退化为无界重试）
  //   实测本条**仍全绿** ⇒ 证实它是个装饰品。
  // 恒定 0.9 才落在保留段：Math.floor(0.9 * 254) + 1 = 229 ⇒ 229 ≥ 224 组播/保留。
  // （扫描 k = 0 / 0.001 / 0.01 / 0.2 / 0.5 / 0.9 / 0.99 / 0.999 得到的。）
  //
  // 死循环的探测方式：**不能**用 setTimeout（同步调用栈里事件循环没机会跑
  // 那个定时器，死循环只会挂住整个测试进程而不会"超时失败"；第一版就栽在这）。
  // 必须丢进 worker 线程真计时 —— 那里死循环只会烧 CPU，worker 可被 terminate。
  const { Worker } = await import('node:worker_threads');
  const modUrl = new URL('../src/core/tamper/plugins/xforwardedfor.js', import.meta.url).href;
  const src = `
    import { parentPort } from 'node:worker_threads';
    Math.random = () => 0.9;
    const mod = await import(${JSON.stringify(modUrl)});
    const t0 = Date.now();
    mod.default.transform('1', { headers: {} });
    parentPort.postMessage(Date.now() - t0);
  `;
  const cost = await new Promise((resolve, reject) => {
    const w = new Worker(src, { eval: true });
    const timer = setTimeout(() => {
      w.terminate();
      reject(new Error('Math.random 恒为 0.9（产出 229.x 组播段）时超过 5s 未返回 ⇒ 无界重试死循环'));
    }, 5000);
    w.once('message', (ms) => { clearTimeout(timer); w.terminate(); resolve(ms); });
    w.once('error', (e) => { clearTimeout(timer); reject(e); });
  });
  assert.ok(cost < 1000, `恒定 Math.random 下耗时 ${cost}ms —— 实现疑似无界重试`);
});

test('契约-6) 不带 ctx 时退化为恒等变换（不得抛错，保留既有契约）', () => {
  assert.equal(xforwardedfor.transform('1 AND 1=1', undefined), '1 AND 1=1');
  assert.equal(xforwardedfor.transform('1 AND 1=1', {}), '1 AND 1=1');
});