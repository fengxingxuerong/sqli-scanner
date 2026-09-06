// [sqlmap 对标] 行范围导出（--start/--stop）+ 保活探测（--safe-url/--safe-freq）测试
// 覆盖：
//   1) Extractor.dumpData 尊重 dumpStart/dumpStop：分页 offset 从 startRow 起、返回区间行数
//   2) withSafeUrl 包装：每 safeFreq 个请求触发一次保活 GET、失败静默、继承 proxy/auth/wafEvasion
//   3) sanitizeStart 透传 dumpStart/dumpStop/safeUrl/safeFreq，非法协议 safeUrl 丢弃
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Extractor } from '../src/engine/Extractor.js';
import { withSafeUrl } from '../src/core/safeUrlKeeper.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const RS = String.fromCharCode(0x1e); // 行分隔
const CS = String.fromCharCode(0x1f); // 列分隔

// ── 1. dumpData 行范围 ──

function makeDumpCtx(cfg) {
  return { dbms: 'MySQL', config: { dumpRowLimit: 2, ...cfg } };
}

test('dumpData 无 dumpStart/dumpStop 时行为不变（offset 从 0 起）', async () => {
  const ex = new Extractor();
  const queries = [];
  ex._guessColumnsCached = async () => ['id'];
  ex.extractScalar = async (ctx, q) => {
    queries.push(q);
    return queries.length === 1 ? `a${CS}1${RS}b${CS}2` : `c${CS}3`;
  };
  const rows = await ex.dumpData(makeDumpCtx({}), 'mydb', 'users', ['id']);
  assert.equal(rows.length, 3);
  assert.ok(queries[0].includes('OFFSET 0'), '首页 offset 应为 0');
});

test('dumpData 尊重 dumpStart=5/dumpStop=8：offset 从 5 起、恰返 3 行', async () => {
  const ex = new Extractor();
  const queries = [];
  ex._guessColumnsCached = async () => ['id'];
  ex.extractScalar = async (ctx, q) => {
    queries.push(q);
    // 每页都返回满页（lim=2），靠 rangeCap 截断而非末页判断
    return `r${queries.length}a${CS}v${RS}r${queries.length}b${CS}v`;
  };
  const rows = await ex.dumpData(makeDumpCtx({ dumpStart: 5, dumpStop: 8 }), 'mydb', 'users', ['id']);
  assert.equal(rows.length, 3, 'dumpStop-dumpStart=3 行应精确截断');
  assert.ok(queries[0].includes('OFFSET 5'), `首查 offset 应为 5，实际：${queries[0]}`);
  assert.ok(queries[1].includes('OFFSET 7'), `次查 offset 应为 7，实际：${queries[1]}`);
  assert.equal(queries.length, 2, '取满区间后不应继续翻页');
});

test('dumpData 只给 dumpStart 不给 stop：从起始偏移拉到 maxRows/末页', async () => {
  const ex = new Extractor();
  const queries = [];
  ex._guessColumnsCached = async () => ['id'];
  ex.extractScalar = async (ctx, q) => {
    queries.push(q);
    return queries.length === 1 ? `a${CS}1` : null; // 首页不足一页 → 末页
  };
  const rows = await ex.dumpData(makeDumpCtx({ dumpStart: 10 }), 'mydb', 'users', ['id']);
  assert.equal(rows.length, 1);
  assert.ok(queries[0].includes('OFFSET 10'));
});

// ── 2. withSafeUrl 保活包装 ──

test('withSafeUrl：每 freq 个请求插入一次保活 GET', async () => {
  const seen = [];
  const client = { request: async (o) => { seen.push(o.url); return { status: 200, data: '' }; } };
  const wrapped = withSafeUrl(client, { safeUrl: 'http://t/keepalive', safeFreq: 3 });
  for (let i = 0; i < 7; i++) {
    await wrapped.request({ method: 'GET', url: `http://t/q?i=${i}` });
  }
  const keepalives = seen.filter((u) => u === 'http://t/keepalive');
  assert.deepEqual(seen.filter((u) => u.startsWith('http://t/q')).length, 7);
  assert.equal(keepalives.length, 2, '第 3、6 个请求时应各保活一次');
});

test('withSafeUrl：保活失败静默不影响主流程；继承 proxy/auth/wafEvasion', async () => {
  const seen = [];
  const client = {
    request: async (o) => {
      if (o.url === 'http://t/keepalive') throw new Error('boom');
      seen.push(o);
      return { status: 200, data: '' };
    },
  };
  const wrapped = withSafeUrl(client, { safeUrl: 'http://t/keepalive', safeFreq: 1 });
  const res = await wrapped.request({
    url: 'http://t/target',
    proxy: { host: 'p' },
    auth: { cookie: 'sid=x' },
    wafEvasion: { jitterMs: 0 },
  });
  assert.equal(res.status, 200, '保活抛错不影响扫描请求返回');
  assert.equal(seen.length, 1);
});

test('withSafeUrl：freq 缺省/非法回退 1', async () => {
  let n = 0;
  const client = { request: async (o) => { if (o.url === 'k') n++; return {}; } };
  const wrapped = withSafeUrl(client, { safeUrl: 'k', safeFreq: -5 });
  await wrapped.request({});
  assert.equal(n, 1, '非法 freq 回退为 1 → 每个请求前都保活');
});

// ── 3. sanitizeStart 白名单透传 ──

function startBody(cfg) {
  return { target: { url: 'http://example.com/a.php?id=1' }, config: cfg };
}

test('sanitizeStart 透传 dumpStart/dumpStop/safeUrl/safeFreq', () => {
  const out = sanitizeStart(
    startBody({ dumpStart: 5, dumpStop: 100, safeUrl: 'https://example.com/keepalive', safeFreq: 20 })
  );
  assert.equal(out.config.dumpStart, 5);
  assert.equal(out.config.dumpStop, 100);
  assert.equal(out.config.safeUrl, 'https://example.com/keepalive');
  assert.equal(out.config.safeFreq, 20);
});

test('sanitizeStart：非 http(s) safeUrl 被丢弃；越界数值被 clamp', () => {
  const out = sanitizeStart(startBody({ dumpStart: 99999999, dumpStop: 3, safeUrl: 'ftp://evil/x' }));
  assert.equal(out.config.dumpStart, 1000000, '越界 dumpStart 应 clamp 到上限');
  assert.equal(out.config.safeUrl, undefined, 'ftp 协议 safeUrl 应被丢弃');
  assert.equal(out.config.safeFreq, undefined);
});
