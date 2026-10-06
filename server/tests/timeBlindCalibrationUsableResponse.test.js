// ============================================================================
// tests/timeBlindCalibrationUsableResponse.test.js
// TimeBlind 标定探针必须校验响应可用性，否则会把"探针失败"当成"标定成功"
//
// ── 缺陷（实测确认，非推理）──────────────────────────────────────────────────
// TimeBlindDetector 的 [--time-sec 自适应] 标定探针（timeBlindCalibrate=true
// 时启用，默认 false 零回归）：
//
//   const t0 = Date.now();
//   await this.send(httpClient, ctx, req, { timeoutMs: probeTimeout });  ← 返回值被丢弃
//   const elapsed = Date.now() - t0;
//   if (elapsed / 1000 >= threshold) effectiveSleep = calibrateMin;    ← 只看耗时
//
// send 的返回值被直接丢弃，于是**任何"耗时够长但请求没成功"的情况**都会被当成
// 标定成功，把 sleep 从 sleep 缩短到 calibrateMin：
//   · WAF 返回 403 拦截页：连接正常完成，耗时可能不短
//   · 目标对畸形 payload 回 500：服务端处理完才回包
//   · 慢站排队 / 连接池等待：耗时达标，但根本没执行到注入语句
//
// 后果链条（方向性错误 ⇒ 漏报）：
//   sleep 被缩短 → 后续每次采样只睡 calibrateMin 秒
//             → 采样耗时 = μ + calibrateMin，低于含 μ 与 zσ 的 threshold
//             → 恒判"未延迟" ⇒ **时间盲注在该目标上必然漏报**
//
// 且它只在**慢站**上触发（那正是标定开关服务的目标），全程无任何报错。
//
// 注释里写的"只会更少地缩短延时，不会更激进"恰恰是问题所在：
// 真正的风险不是"缩得太少"，而是"把失败当成成功"。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';
import { defaults } from '../src/config/defaults.js';

/**
 * 脚本化 httpClient。
 * @param {(req, n) => {data?: string, status?: number, headers?: object, delayMs?: number}} fn
 */
function mock(fn) {
  const calls = [];
  return {
    calls,
    async request(opts) {
      calls.push(opts);
      const n = calls.length;
      const q = typeof opts?.url === 'string' ? opts.url : '';
      const r = fn(q, n, opts) || {};
      if (r.delayMs) await new Promise((x) => setTimeout(x, r.delayMs));
      // 网络层失败必须用 __netErr 表达 —— 实测 isUnusableResponse 对
      // {status: 0} 判 false（它只看网络失败标记与截断，不看状态码）。
      // 第一版 mock 用 {status: 0} 模拟超时，守卫因此测不到任何东西。
      if (r.netErr) return { __netErr: { kind: r.netErr, message: r.netErr }, data: '' };
      return { data: r.data ?? 'page', status: r.status ?? 200, headers: r.headers ?? {} };
    },
  };
}

function ctx(httpClient, extra = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://127.0.0.1:9/?id=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: {
      timeoutMs: 5000,
      retry: 0,
      ...defaults,
      ...defaults.blindRobust,
      timeBlindCalibrate: true,
      timeBlindCalibrateMin: 1,
      timeBlindSamples: 3,
      ...extra,
    },
  };
}

/**
 * 取出请求 URL 的**解码后**形态。
 * ⚠️ payload 在 query 里是百分号编码的：`SLEEP%281%29` ⇒ `SLEEP(1)`。
 * 第一版直接拿原始 url 匹配编码文本，一个探针都认不出 ——
 * 4 条用例全成装饰品，却"看起来"在测东西。
 */
const decodedUrl = (c) => {
  const u = String(c?.url ?? '');
  try { return decodeURIComponent(u); } catch { return u; }
};

/** 该请求是否含延迟函数（即"标定探针 / 采样"这类带 sleep 的注入请求） */
const isDelayReq = (c) => /SLEEP\(|pg_sleep\(|WAITFOR|DELAY\s+'0/i.test(decodedUrl(c));

/** 从解码后的 URL 里取 sleep 秒数（无延迟函数则 null） */
function sleepOf(c) {
  const u = decodedUrl(c);
  const m = u.match(/SLEEP\((\d+(?:\.\d+)?)\)/i) || u.match(/pg_sleep\((\d+(?:\.\d+)?)\)/i);
  return m ? Number(m[1]) : null;
}

/** 所有带 sleep 的请求各自用的 sleep 秒数 */
const probeSleeps = (calls) => calls.filter(isDelayReq).map(sleepOf).filter((x) => x !== null);

/**
 * **采样**请求（不含标定探针本身）用的 sleep 秒数。
 * ⚠️ 判据要点：标定探针本来就发 sleep=calibrateMin，把它算进来会让
 * "标定失败 ⇒ 不缩短" 这条断言自己就红 —— 第一版正是这么翻车的：
 * 修复后实际序列是 [标定探针 1, 采样 2, 采样 2, 采样 2]，
 * 说明修复生效，却被误判成"仍在缩短"。要看的是**标定探针之后**那些请求。
 */
const sampleSleeps = (calls) => {
  const idx = calls.findIndex(isDelayReq);
  return idx < 0 ? [] : calls.slice(idx + 1).filter(isDelayReq).map(sleepOf).filter((x) => x !== null);
};

test('自证-0) 标定路径确实可达（否则本组守卫是装饰品）', async () => {
  const http = mock(() => ({ data: 'page', status: 200 }));
  const d = new TimeBlindDetector();
  await d.detect(ctx(http)).catch(() => null);
  assert.ok(http.calls.length > 0, 'httpClient 一次都没被调用 —— 路径不可达，本组守卫无效');
  assert.ok(http.calls.some(isDelayReq),
    `发出的请求里没有任何带延迟函数的（标定/采样探针）：${JSON.stringify(http.calls.map((c) => c?.url))}`);
});

test('缺陷-1) 标定探针被 WAF 拦截（403）时不得据此缩短 sleep', async () => {
  // 探针（含延迟函数）的响应一律是 WAF 拦截页，但**耗时照样很长**（模拟拦截发生在
  // 目标处理之后）。旧实现只看 elapsed ⇒ 判成"标定成功" ⇒ sleep 被缩到 1。
  const http = mock((q, n) => {
    if (isDelayReq({ url: q })) {
      return { data: '<html>Blocked by WAF</html>', status: 403, delayMs: 2200 };
    }
    return { data: 'page', status: 200 };
  });
  const d = new TimeBlindDetector();
  const r = await d.detect(ctx(http)).catch(() => null);

  const used = sampleSleeps(http.calls);
  assert.ok(probeSleeps(http.calls).length > 0, '没有发出带 sleep 的探针 —— 守卫无效');
  assert.ok(used.length === 0 || used.every((x) => x !== 1),
    `探针被 WAF 拦截，却按缩短后的 sleep=1 继续采样：${JSON.stringify(used)}`
    + `（判定结果 vulnerable=${r?.vulnerable}）`);
});

test('缺陷-2) 标定探针的网络失败（超时/连接错）不得据此缩短 sleep', async () => {
  // ⚠️ 第一版这条测的是"探针返回 500"。方向错了 —— 500 不是不可用信号：
  //   服务端处理完才回包是常态，时间盲注站点上同样会发生；单看状态码会把
  //   真实可用的响应也毙掉，反而加剧漏报。实测 detectGenericBlock 对
  //   {status:500} 返回 null，unusableOf 也判它可用 —— 它本来就该通过。
  // 真正该拦的是**网络层失败**：探针压根没打到注入语句，却因超时而"耗时很长"。
  // 这正是最隐蔽的一种 —— 超时耗时必然超过 threshold。
  const http = mock((q) => {
    if (isDelayReq({ url: q })) return { netErr: 'timeout', delayMs: 2200 };
    return { data: 'page', status: 200 };
  });
  const d = new TimeBlindDetector();
  await d.detect(ctx(http)).catch(() => null);
  const used = sampleSleeps(http.calls);
  assert.ok(probeSleeps(http.calls).length > 0, '没有发出带 sleep 的探针 —— 守卫无效');
  assert.ok(used.length === 0 || used.every((x) => x !== 1),
    `探针网络层超时，却按缩短后的 sleep=1 继续采样：${JSON.stringify(used)}`);
});

test('契约-3) 标定成功时确实会缩短 sleep（护栏不得把标定整个禁掉）', async () => {
  // 正常响应 + 探针真的延迟 ⇒ 应当缩短到 calibrateMin。
  // 这条防"为了保守而直接禁用标定"——那会损失本开关的既有能力。
  const http = mock((q) => {
    if (isDelayReq({ url: q })) return { data: 'page', status: 200, delayMs: 2600 };
    return { data: 'page', status: 200 };
  });
  const d = new TimeBlindDetector();
  await d.detect(ctx(http)).catch(() => null);
  const used = sampleSleeps(http.calls);
  assert.ok(probeSleeps(http.calls).length > 0, '没有发出带 sleep 的探针 —— 守卫无效');
  assert.ok(used.some((x) => x === 1),
    `探针正常响应且耗时达标，却始终用原 sleep=${used.join(',')}（标定被误禁）`);
});