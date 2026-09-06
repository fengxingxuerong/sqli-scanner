// [G3-FIX] useRegistry 双拷贝漂移回归测试：
//   原缺陷：useRegistry=true 时 _clauseRound 被子句轮门控整体跳过 → level>=2 显式配置下
//   ORDER BY/GROUP BY/HAVING/LIMIT 位置注入探测缺失。
//   修复：主轮收敛为 where 子句条目；子句轮独立承担位置探测（两条路径统一）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';

// 捕获客户端：记录每个请求的注入值（query q 参数），可通过数据集判定子句轮是否发出 ORDER BY 变体
function captureClient() {
  const calls = [];
  return {
    calls,
    async request(opts) {
      calls.push(opts);
      return { status: 200, headers: {}, data: '<p>基准页面</p>' };
    },
  };
}

function buildCtx(client, config = {}) {
  return {
    httpClient: client,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, useRegistry: true, level: 2, risk: 1, ...config },
  };
}

function extractQuery(u) {
  const m = String(u || '').match(/[?&]q=([^&]*)/);
  return m ? decodeURIComponent(m[1]).replace(/\+/g, ' ') : '';
}

const d = new BooleanBlindDetector();

test('G3: useRegistry=true + level=2 → 子句轮发出位置布尔对（ORDER BY 逗号拼接 / HAVING）', async () => {
  const client = captureClient();
  await d.detect(buildCtx(client, { useRegistry: true, level: 2 }));
  const payloads = client.calls.map((c) => extractQuery(c.url));
  // ORDER BY 位置用逗号拼接标量子查询（mysqlClauses.orderby 形态），HAVING 是另一子句位置
  assert.ok(
    payloads.some((p) => /,\\(SELECT 1\\)|\\+HAVING\\+|HAVING 1=1/.test(p)),
    `应发出子句位置（ORDER BY/HAVING）布尔对（实际样例: ${payloads.slice(0, 8).join(' | ')}）`
  );
});

test('G3: useRegistry=true + level=1 → 不发出子句位置 payload（level 门控零变化）', async () => {
  const client = captureClient();
  await d.detect(buildCtx(client, { useRegistry: true, level: 1 }));
  const payloads = client.calls.map((c) => extractQuery(c.url));
  assert.ok(
    !payloads.some((p) => /ORDER BY|GROUP BY|HAVING|LIMIT/.test(p)),
    `level=1 不应有子句位置 payload（实际样例: ${payloads.slice(0, 6).join(' | ')}）`
  );
});

test('G3: useRegistry=true + level=3 → 主轮仅 where 子句条目（不含注册表 orderby 条目）', async () => {
  const client = captureClient();
  // 仅验证 _getBooleanPairs 的主轮 clause 过滤：直接调私有方法
  const ctx = buildCtx(client, { useRegistry: true, level: 3 });
  ctx.point.boundary = null; // 不触发 boundary 对，聚焦注册表条目
  const pairs = d._getBooleanPairs(ctx, []);
  // 主轮所有条目都应是 where 子句注册表条目（不混入 orderby/groupby）
  for (const p of pairs) {
    // registry 条目带 id → 断言其对应 clause 为 where（无法直接读条目，检查 payload 形态：
    // where 子句用 AND/OR 拼接、非 "ORDER BY n" 形态）
    if (p.id) {
      assert.ok(
        !/ORDER BY \d/.test(p.truePayload),
        `主轮不应含 ORDER BY 位置条目（${p.id}）`
      );
    }
  }
  assert.ok(pairs.some((p) => p.id), 'useRegistry 路径应从注册表取到 where 条目');
});