// UNION 方言/闭合链路回归（CRS-FIX 2026-09-10）
//
// 覆盖三个此前「只在特定上下文坏」的缺陷：
//   1) 回显列标记探测缺尾部行注释 → 字符串型注入点末尾引号无法闭合 → 探测恒 500
//   2) 全 NULL 哨兵短路 → 列数不匹配时跳过 N 条逐列探测（否则 N=50 时空转 51 条）
//   3) commentSuffix 方言判据：MySQL 系 + tamper 用 `#`，其余一律 `-- -`
//
// 背景（实测数据，真实 MySQL 8.0.28 靶场）：
//   修复前 5 场景 834 请求、方言浪费 193（23.1%）、union 仅 /num 命中；
//   修复后 333 请求、浪费 10（3.0%）、union 在 /num /str /like /blind 均命中。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { discoverEchoColumnsDetailed } from '../src/engine/injection.js';
import { commentSuffix } from '../src/engine/DialectSqlBuilder.js';

// 计数型 httpClient：按注入串返回脚本化响应，并记录每条发出的 payload
function makeCtx(script, { dbms = 'MySQL', config = {}, point = {} } = {}) {
  const sent = [];
  return {
    ctx: {
      httpClient: {
        request: async (opts) => {
          const u = new URL(opts.url);
          const injected = decodeURIComponent(u.searchParams.get('id') || '');
          sent.push(injected);
          return script(injected, sent.length - 1);
        },
      },
      target: { mode: 'http', baseUrl: 'http://t.local/u?id=1', method: 'GET', cookieParams: {}, headerParams: {}, config: {} },
      point: { location: 'url', param: 'id', originalValue: 'alice', boundary: "'", ...point },
      dbms,
      config,
    },
    sent,
  };
}

// ── 1) 尾注 ────────────────────────────────────────────────────────────────

test('标记探测必须以行注释结尾（字符串型注入点残留引号要被注释掉）', async () => {
  const { ctx, sent } = makeCtx(() => ({ status: 200, data: '<html>x</html>' }));
  await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 3, "'");
  assert.ok(sent.length > 0);
  const probe = sent.find((s) => /UNION SELECT/i.test(s));
  assert.match(probe, /SQLISCANNER0/);
  // 关键断言：末尾必须是行注释，否则 `WHERE name='alice' UNION SELECT 'S0'...'` 引号未闭合
  assert.match(probe, /(-- -|#)$/);
});

test('MySQL + tamper 开启 → 尾注用 #（躲 CRS 942460 的 \\W{4}）', async () => {
  const { ctx, sent } = makeCtx(() => ({ status: 200, data: '<html>x</html>' }), {
    config: { wafEvasion: { tamper: { enabled: true, plugins: ['dash2hash'] } } },
  });
  await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 3, "'");
  const probe = sent.find((s) => /UNION SELECT/i.test(s));
  assert.match(probe, /#$/);
  assert.doesNotMatch(probe, /--\s*-$/);
});

test('commentSuffix：非 MySQL 系即使 tamper 开启也用 -- -（# 只有 MySQL 认）', () => {
  assert.equal(commentSuffix('PostgreSQL', { tamperEnabled: true }), '-- -');
  assert.equal(commentSuffix('SQL Server', { tamperEnabled: true }), '-- -');
  assert.equal(commentSuffix('MySQL', { tamperEnabled: true }), '#');
  assert.equal(commentSuffix('MariaDB', { tamperEnabled: true }), '#');
  assert.equal(commentSuffix('TiDB', { tamperEnabled: true }), '#');
  assert.equal(commentSuffix('MySQL', { tamperEnabled: false }), '-- -');
  assert.equal(commentSuffix(null, { tamperEnabled: true }), '-- -');
});

// ── 2) 全 NULL 哨兵短路 ────────────────────────────────────────────────────

test('列数不匹配 → 全 NULL 哨兵短路，不发 N 条逐列探测', async () => {
  // 任何 UNION 都返回「列数不匹配」错误页：模拟 ORDER BY 二分猜错列数的后果
  const { ctx, sent } = makeCtx((injected) => {
    if (/UNION SELECT/i.test(injected)) {
      return { status: 500, data: '<pre>The used SELECT statements have a different number of columns</pre>' };
    }
    return { status: 200, data: '<html>plain</html>' };
  });
  await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 50, "'");
  const unionReqs = sent.filter((s) => /UNION SELECT/i.test(s));
  // 修复前：1（全列标记）+ 50（逐列）+ 2（数字 A/B 族）= 53 条
  // 修复后：1（全列标记）+ 1（全 NULL 哨兵）= 2 条
  assert.equal(unionReqs.length, 2, `实际发送 ${unionReqs.length} 条：${unionReqs.map((s) => s.slice(0, 60))}`);
  // 哨兵本身必须是全 NULL（不放任何标记）→ 与列类型无关，只探「列数对不对」
  assert.match(unionReqs[1], /UNION SELECT NULL,NULL/i);
  assert.doesNotMatch(unionReqs[1], /SQLISCANNER/);
});

test('哨兵不误伤严格类型库：全 NULL 成功时必须继续逐列探测（PG INT 列场景）', async () => {
  // 第 1 列是 INT（文本标记 → 500），其余列可回显文本。
  // 全 NULL 版本必须成功（NULL 与任何类型兼容）→ 不应短路 → 逐列探测应定位到文本列
  const { ctx, sent } = makeCtx((injected) => {
    const m = injected.match(/UNION SELECT (.+?)(?:--\s*-|#)?$/);
    if (!m) return { status: 200, data: '<html>plain</html>' };
    const exprs = m[1].split(',').map((s) => s.trim());
    const out = [];
    for (let i = 0; i < exprs.length; i++) {
      const t = exprs[i];
      if (t === 'NULL') continue;
      if (/^'.*'$/.test(t) && i !== 0) out.push(t.replaceAll("'", ''));
      else return { status: 500, data: '<pre>invalid input syntax for type integer</pre>' };
    }
    return { status: 200, data: `<html>${out.join('|')}</html>` };
  }, { dbms: 'PostgreSQL' });

  const r = await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 3, '');
  assert.deepEqual(r.cols, [1, 2], '哨兵成功后必须继续逐列探测并定位文本列');
  // 3 列场景：1 全列 + 1 哨兵 + 3 逐列 = 5 条（未短路）
  const unionReqs = sent.filter((s) => /UNION SELECT/i.test(s));
  assert.equal(unionReqs.length, 5);
});

// ── 3) boundary 缺省回落 ───────────────────────────────────────────────────

test('boundary 缺省回落到 point.boundary（指纹路径此前传空导致 UNION 恒失败）', async () => {
  const { ctx, sent } = makeCtx(() => ({ status: 200, data: '<html>x</html>' }), {
    point: { boundary: "')" },
  });
  // 不传 boundary 参数 —— 应自动取 point.boundary = "')"
  await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 2);
  const probe = sent.find((s) => /UNION SELECT/i.test(s));
  assert.match(probe, /^alice'\)\s+UNION SELECT/, `实际：${probe}`);
});
