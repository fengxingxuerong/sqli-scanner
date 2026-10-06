// ============================================================================
// tests/stackedTruncatedResponse.test.js
// StackedDetector 的延迟样本必须过「响应可用性」校验，截断响应不得计入 stable
//
// ── 缺陷（实测确认，非推理）──────────────────────────────────────────────────
// server/src/engine/detectors/StackedDetector.js 的样本筛选只有一道：
//
//   const r = resps[i] || {};
//   if (r.__error || r.resp == null) continue;      // 只挡网络失败 / 没有响应
//   if (r.__elapsed >= effectiveThreshold) { stable++; ... }
//
// r.resp 非空但**响应体被截断**的样本照样计入 stable。截断判据见
// egressOpts.js 的 isTruncatedResponse：`res.__meta.truncated === true`。
//
// 这在堆叠注入上是高频现象，不是边角情况 —— 注入真生效后常返回超大结果集，
// 被 maxBytes 砍断。此时"耗时够长 + resp 非空"两个条件都成立，
// 于是一次真实的、可解释的慢响应被当成注入证据。
//
// 实测（修前）：基线 28ms、注入样本 2s 且全部 __meta.truncated
//   → 判定 vulnerable=true，证据「堆叠注入确认：MySQL 连续 5/5 次响应延迟 ≥ 1500ms」
//
// 与上一轮 TimeBlind 标定探针同型：**探测样本必须先确认可用，再计入判定**。
// 方向是误报（把不可信证据当成命中），与 TimeBlind 的漏报方向相反但同样有害。
//
// ⚠️ 判据为什么是「截断」而不是「状态码」：
//   实测 isUnusableResponse 对 {status:500} 与 {data:''} 都判 false ——
//   服务端处理完才回包、返回空结果集都是**正常业务响应**，在时间/延迟通道上
//   完全可用。若把它们也毙掉，会把真实的延迟注入判成未触发 ⇒ 反而漏报。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { StackedDetector } from '../src/engine/detectors/StackedDetector.js';
import { defaults } from '../src/config/defaults.js';

/** 脚本化 httpClient。injectRes 控制"注入样本"的响应形态 */
function mock({ injectRes, injectDelayMs = 2000, baseDelayMs = 20 }) {
  const calls = [];
  return {
    calls,
    async request(opts) {
      calls.push(opts);
      const u = String(opts?.url ?? '');
      const decoded = (() => { try { return decodeURIComponent(u); } catch { return u; } })();
      const isInject = /SLEEP\(|pg_sleep\(|WAITFOR|DELAY\s+'0/i.test(decoded)
        || (/;|%3B/i.test(decoded) && /sleep/i.test(decoded));
      if (isInject) {
        await new Promise((r) => setTimeout(r, injectDelayMs));
        return { ...injectRes };
      }
      await new Promise((r) => setTimeout(r, baseDelayMs));
      return { data: 'page', status: 200 };
    },
  };
}

function ctx(httpClient) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://127.0.0.1:9/?id=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, ...defaults, ...defaults.blindRobust },
  };
}

/** 基线响应形态与注入响应形态分别可控 */
function mockBaseline(baseRes, injectRes) {
  const calls = [];
  return {
    calls,
    async request(opts) {
      calls.push(opts);
      const u = String(opts?.url ?? '');
      const d = (() => { try { return decodeURIComponent(u); } catch { return u; } })();
      const isInject = /sleep|SLEEP|;/i.test(d) && !/^\?id=1$/.test(d);
      if (isInject) {
        await new Promise((r) => setTimeout(r, 2000));
        return { ...injectRes };
      }
      await new Promise((r) => setTimeout(r, baseRes.__slowMs ?? 20));
      const { __slowMs, ...rest } = baseRes;
      return { ...rest };
    },
  };
}

test('自证-0) 堆叠延迟路径确实可达（否则本组守卫是装饰品）', async () => {
  const http = mock({ injectRes: { data: 'page', status: 200 } });
  const d = new StackedDetector();
  const r = await d.detect(ctx(http)).catch(() => null);
  assert.ok(http.calls.length > 0, 'httpClient 一次都没被调用 —— 路径不可达，守卫无效');
  assert.equal(r?.vulnerable, true,
    `正常延迟样本（200/无截断）竟未判命中 —— 守卫在测一个不存在的路径`);
});

test('缺陷-1) 截断响应不得计入延迟证据（实测修前报 vulnerable=true）', async () => {
  const http = mock({
    injectRes: { data: 'x'.repeat(50), status: 200, __meta: { truncated: true, bodyBytes: 9_000_000 } },
  });
  const d = new StackedDetector();
  const r = await d.detect(ctx(http)).catch(() => null);
  assert.notEqual(r?.vulnerable, true,
    `全部样本都是截断响应，却判定 vulnerable=true：${r?.evidence ?? ''}`);
});

test('契约-2) 正常（未截断）延迟样本仍必须判命中（护栏不得把整个通道禁掉）', async () => {
  const http = mock({ injectRes: { data: 'result page', status: 200 } });
  const d = new StackedDetector();
  const r = await d.detect(ctx(http)).catch(() => null);
  assert.equal(r?.vulnerable, true,
    `正常延迟样本被判未命中 —— 为规避误报而牺牲了检出能力（真漏报）`);
});

test('契约-3) 空响应体仍是合法业务响应，不得因此漏报', async () => {
  // 注入生效但查询结果为空（0 行）是很常见的真实场景，耗时照样达标。
  // 实测 isUnusableResponse 对 {data: ''} 判 false —— 它本来就该通过。
  const http = mock({ injectRes: { data: '', status: 200 } });
  const d = new StackedDetector();
  const r = await d.detect(ctx(http)).catch(() => null);
  assert.equal(r?.vulnerable, true,
    '注入生效但结果为空（0 行）被判未命中 —— 把正常业务响应误当不可用，反而漏报');
});

test('契约-4) 基线水位不得被截断响应抬高（否则真实延迟样本够不到阈值 ⇒ 漏报）', async () => {
  // ⚠️ 诚实标注：**不是实测复现的缺陷**。实测（3 个基线里 1 个截断且慢 3s）
  // 修前修后都判命中 —— 中位数本来就抗单点污染。基线过滤是**防御性**加固：
  // 若多数基线样本被截断（maxBytes 调小、或目标本身就是大结果集页面），
  // 中位数被抬起来 ⇒ effectiveThreshold 抬高 ⇒ 真实延迟样本够不到阈值 ⇒ 漏报。
  //
  // 判据用证据文案里回显的 baselineMs（直接可观测，不靠猜）。
  //   第一次跑：基线全部正常（快）      → baselineMs 应很小
  //   第二次跑：基线全部被截断（慢）    → baselineMs 仍应很小（过滤掉了）
  // 若第二种的 baselineMs 明显更大 ⇒ 基线过滤被回退。
  const small = { data: 'page', status: 200 };
  // 截断的基线：传输了 maxBytes 才停，耗时明显更长（__slowMs 只是 mock 的注记，
  // 会在返回前被剥掉，不会混进响应体）
  const slowTrunc = { data: 'x'.repeat(50), status: 200, __meta: { truncated: true, bodyBytes: 9e6 }, __slowMs: 3000 };

  const run = async (baseRes) => {
    const http = mockBaseline(baseRes, { data: 'result', status: 200 });
    const d = new StackedDetector();
    const r = await d.detect(ctx(http)).catch(() => null);
    const m = String(r?.evidence ?? '').match(/基线\s*(\d+)ms/);
    return m ? Number(m[1]) : NaN;
  };

  const normalBase = await run(small);
  const truncBase = await run(slowTrunc);
  assert.ok(Number.isFinite(normalBase) && Number.isFinite(truncBase),
    '证据文案里读不到 baselineMs（未命中或格式变了）—— 守卫无效');
  assert.ok(truncBase <= normalBase + 50,
    `截断基线把水位从 ${normalBase}ms 抬到 ${truncBase}ms —— 基线过滤被回退`
    + '（effectiveThreshold 会跟着抬高，真实延迟样本够不到阈值 ⇒ 漏报）');
});