// injection.js 回显列探测单元测试（P0-FIX 2026-09-07）
// 覆盖点：
//   1) 错误回显不假命中：500 错误页回显「转换失败的输入值」不能被当作回显列
//   2) 逐列文本探测：严格类型库（PG）任一 INT 列使全列标记整条失败时，仍能定位真文本列
//   3) 宽松类型库零回归：第一轮全列标记命中即返回，零额外请求
//   4) 纯 INT 回显列：数字 A/B 族交叉确认路径保持可用
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { discoverEchoColumnsDetailed } from '../src/engine/injection.js';

// —— PG 式严格类型库模拟器 ——
// textCols / numCols：可回显文本 / 可回显数字的列。其余列遇非 NULL 表达式 →
// 500 + invalid input syntax（错误页回显输入值，模拟真实 PG 行为）。
function pgLike(textCols, numCols = []) {
  return (injected) => {
    const m = injected.match(/UNION SELECT (.+?)(?:--\s*-)?$/);
    if (!m) return { status: 200, data: '<html>plain page</html>' };
    const exprs = m[1].split(',').map((s) => s.trim());
    const echoed = [];
    for (let i = 0; i < exprs.length; i++) {
      const t = exprs[i];
      if (t === 'NULL') continue;
      const isText = /^'[^']*'$/.test(t);
      const isNum = /^\d+$/.test(t);
      if (isText && textCols.includes(i)) echoed.push(t.replaceAll("'", ''));
      else if (isNum && (numCols.includes(i) || textCols.includes(i))) echoed.push(t);
      else return { status: 500, data: `<pre>invalid input syntax for type integer: "${t}"</pre>` };
    }
    return { status: 200, data: `<html>row ${echoed.join('|')}</html>` };
  };
}

function makeCtx(script, dbms = 'PostgreSQL') {
  let reqCount = 0;
  return {
    ctx: {
      httpClient: {
        request: async (opts) => {
          reqCount++;
          const u = new URL(opts.url);
          return script(decodeURIComponent(u.searchParams.get('id') || ''));
        },
      },
      target: { mode: 'http', baseUrl: 'http://t.local/u?id=1', method: 'GET', cookieParams: {}, headerParams: {}, config: {} },
      point: { location: 'url', param: 'id', originalValue: '1' },
      dbms,
      config: {},
    },
    reqCount: () => reqCount,
  };
}

test('错误回显不假命中：纯 INT 表上标记出现在 500 错误页 ≠ 回显列', async () => {
  // 修复前：错误页回显 "SQLISCANNER0" → cols=[0]（int 列被误判可回显文本）→ 拖库全 500
  const { ctx } = makeCtx(pgLike([], []));
  const r = await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 4);
  assert.equal(r.cols.length, 0);
  assert.equal(r.numericCols.length, 0);
  assert.equal(r.style, 'none');
});

test('逐列文本探测：PG 严格类型（列0=INT，列1/2=TEXT）定位真文本列', async () => {
  const { ctx } = makeCtx(pgLike([1, 2]));
  const r = await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 4);
  assert.deepEqual(r.cols, [1, 2]);
  assert.equal(r.style, 'text');
});

test('宽松类型库零回归：第一轮全列标记命中即返回（零额外请求）', async () => {
  const { ctx, reqCount } = makeCtx(pgLike([0, 1, 2, 3]));
  const r = await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 4);
  assert.deepEqual(r.cols, [0, 1, 2, 3]);
  assert.equal(reqCount(), 1);
});

test('纯数字结果集：数字 A/B 族交叉确认仍可用（如 COUNT(*) 场景）', async () => {
  const { ctx } = makeCtx(pgLike([], [0, 1, 2, 3]));
  const r = await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 4);
  assert.deepEqual(r.cols, []);
  assert.deepEqual(r.numericCols, [0, 1, 2, 3]);
  assert.equal(r.style, 'numeric');
});

test('混合类型（INT+TEXT+BOOL）：逐列文本先命中，不被 BOOL 列阻断', async () => {
  // users 表真实形态：id=INT, username/email=TEXT, admin=BOOL。
  // BOOL 列连数字也放不进（PG unknown→bool 失败）→ 数字 A 族整条 500；
  // 但逐列文本探测先命中文本列，拖库不受影响——这正是修复的实战意义。
  const script = (injected) => {
    const m = injected.match(/UNION SELECT (.+?)(?:--\s*-)?$/);
    if (!m) return { status: 200, data: '<html>plain</html>' };
    const exprs = m[1].split(',').map((s) => s.trim());
    const kinds = ['num', 'text', 'text', 'bool'];
    const echoed = [];
    for (let i = 0; i < exprs.length; i++) {
      const t = exprs[i];
      if (t === 'NULL') continue;
      const isText = /^'[^']*'$/.test(t);
      const isNum = /^\d+$/.test(t);
      if (kinds[i] === 'text') echoed.push(t.replaceAll("'", ''));
      else if (kinds[i] === 'num' && isNum) echoed.push(t);
      else return { status: 500, data: `<pre>invalid input syntax for type ${kinds[i] === 'bool' ? 'boolean' : 'integer'}: "${t}"</pre>` };
    }
    return { status: 200, data: `<html>row ${echoed.join('|')}</html>` };
  };
  const { ctx } = makeCtx(script);
  const r = await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 4);
  assert.deepEqual(r.cols, [1, 2]);
  assert.equal(r.style, 'text');
});

test('未知 DBMS：FROM dual 兜底轮仍生效（Oracle 式必须有 FROM）', async () => {
  // 模拟 Oracle：无 FROM 子句必报错，带 FROM dual 且文本列命中
  let usedDual = false;
  const script = (injected) => {
    if (!/FROM dual/.test(injected)) return { status: 500, data: '<pre>ORA-00923: FROM keyword not found</pre>' };
    usedDual = true;
    const m = injected.match(/UNION SELECT (.+?) FROM dual/);
    const exprs = m[1].split(',').map((s) => s.trim());
    const echoed = exprs.filter((t) => /^'[^']*'$/.test(t)).map((t) => t.replaceAll("'", ''));
    return { status: 200, data: `<html>${echoed.join('|')}</html>` };
  };
  const { ctx } = makeCtx(script, null);
  const r = await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 2);
  assert.ok(usedDual);
  assert.deepEqual(r.cols, [0, 1]);
});
