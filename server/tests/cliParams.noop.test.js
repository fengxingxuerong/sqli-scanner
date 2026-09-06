// P2-5b: --union-cols / --union-from / --no-cast 接线测试（原静默 no-op 参数）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UnionDetector } from '../src/engine/detectors/UnionDetector.js';
import { discoverEchoColumnsDetailed } from '../src/engine/injection.js';
import { resolveFromClause, sanitizeUnionFrom, WRAP_NOCAST } from '../src/engine/DialectSqlBuilder.js';
import { Extractor } from '../src/engine/Extractor.js';
import { binaryGuessColumns } from '../src/engine/columnGuess.js';

function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

function buildCtx(httpClient, dbms, configExtra = {}) {
  return {
    httpClient,
    target: {
      method: 'GET',
      baseUrl: 'http://mock/?q=1',
      headerParams: {},
      cookieParams: {},
      config: {},
    },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', boundary: '', confirmed: false },
    dbms,
    config: { timeoutMs: 5000, timeThresholdMs: 800, maxColumnsGuess: 4, unionSkipGate: true, ...configExtra },
  };
}

// ========== 1) --union-cols：固定列数跳过 ORDER BY 二分 ==========
test('unionCols>0 时跳过 ORDER BY 二分（零 ORDER BY 请求）', async () => {
  const calls = [];
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      calls.push(q);
      if (/ORDER BY \d+/.test(q)) return { data: 'ERR', status: 200 }; // ORDER BY 不应被调用
      if (/UNION SELECT/.test(q)) return { data: `echo:${q}`, status: 200 };
      return { data: 'normal', status: 200 };
    },
  };
  const ctx = buildCtx(mock, 'MySQL', { unionCols: 3 });
  const d = new UnionDetector();
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(ctx.point.columns, 3, '列数应直接取 unionCols=3');
  assert.ok(!calls.some((q) => /ORDER BY/.test(q)), '不应发出任何 ORDER BY 请求');
  assert.ok(ctx.point.echoCols.length > 0, '回显列定位应正常（基于给定列数）');
});

test('unionCols 非法（0/负数/超上限）时回退自动二分', async () => {
  let orderCalls = 0;
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      if (/ORDER BY (\d+)/.test(q)) {
        orderCalls++;
        const n = Number(q.match(/ORDER BY (\d+)/)[1]);
        return n > 3 ? { data: 'ERR', status: 200 } : { data: 'normal', status: 200 };
      }
      if (/UNION SELECT/.test(q)) return { data: `echo:${q}`, status: 200 };
      return { data: 'normal', status: 200 };
    },
  };
  const ctx = buildCtx(mock, 'MySQL', { unionCols: 'abc' }); // 非数字 → 回退
  const d = new UnionDetector();
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.ok(orderCalls > 0, '非法 unionCols 应回退 ORDER BY 二分');
});

test('binaryGuessColumns fixed 选项：合法 fixed 直接返回、零请求', async () => {
  let probes = 0;
  const val = await binaryGuessColumns(async () => { probes++; return { data: 'x', status: 200 }; }, {
    baseLen: 100, maxCols: 50, fixed: 7,
  });
  assert.equal(val, 7);
  assert.equal(probes, 0, 'fixed 时不应发任何探测请求');
});

// ========== 2) --union-from：覆盖方言伪表判定 ==========
test('resolveFromClause：unionFrom 覆盖自动判定，且清洗非法字符', async () => {
  assert.equal(resolveFromClause('Oracle', 'dual'), ' FROM dual');
  assert.equal(resolveFromClause('MySQL', 'dual'), ' FROM dual', 'MySQL 也强制 FROM dual（用户显式指定）');
  assert.equal(resolveFromClause('Oracle', undefined), ' FROM dual', '未指定 → 走方言自动判定');
  assert.equal(resolveFromClause('MySQL', undefined), '', 'MySQL 自动判定为无 FROM');
  // 清洗：注释/分号/引号/连字符剔除（防注入逃逸，仅留安全字符）
  assert.equal(sanitizeUnionFrom('dual; DROP TABLE x--'), 'dual DROP TABLE x');
  assert.equal(sanitizeUnionFrom("'-- x"), 'x');
  assert.equal(sanitizeUnionFrom('SYSIBM.SYSDUMMY1'), 'SYSIBM.SYSDUMMY1', '点号保留');
  assert.equal(sanitizeUnionFrom('(VALUES(0)) t'), '(VALUES(0)) t', '括号保留');
});

test('unionFrom=dual 强制注入到探测 payload（MySQL 场景）', async () => {
  const calls = [];
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      calls.push(q);
      if (/ORDER BY \d+/.test(q)) return { data: 'ERR', status: 200 };
      if (/UNION SELECT/.test(q)) return { data: `echo:${q}`, status: 200 };
      return { data: 'normal', status: 200 };
    },
  };
  const ctx = buildCtx(mock, 'MySQL', { unionCols: 2, unionFrom: 'dual' });
  const d = new UnionDetector();
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  const unionCalls = calls.filter((q) => /UNION SELECT/.test(q));
  assert.ok(unionCalls.length > 0);
  assert.ok(unionCalls.every((q) => /FROM dual/i.test(q)), '所有 UNION 探测应带 FROM dual');
});

// ========== 3) --no-cast：WRAP_NOCAST 隐式文本化 ==========
test('WRAP_NOCAST：MySQL 无 CAST 包裹', () => {
  assert.equal(WRAP_NOCAST.MySQL('version()'), "CONCAT('__S__',(version()),'__E__')");
  assert.equal(WRAP_NOCAST.PostgreSQL('version()'), "('__S__' || (version()) || '__E__')");
  assert.equal(WRAP_NOCAST.Oracle('user'), "('__S__' || (user) || '__E__')");
  assert.equal(WRAP_NOCAST['SQL Server'], undefined, 'SQL Server 无 NOCAST → 调用方回退 WRAP');
});

test('noCast=true 时 extractScalar 用隐式文本化（无 CAST 关键字）', async () => {
  const calls = [];
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      calls.push(q);
      if (/UNION SELECT/.test(q)) {
        // 模拟 MySQL：回显整个注入串供标记匹配
        return { data: `page ... __S__5.7.42__E__ ...`, status: 200 };
      }
      return { data: 'normal', status: 200 };
    },
  };
  const ctx = buildCtx(mock, 'MySQL', { unionCols: 2, noCast: true });
  const ex = new Extractor();
  // 手动给 point 回显列（跳过探测）
  ctx.point.echoCols = [0];
  const val = await ex.extractScalar(ctx, 'version()', 2);
  assert.equal(val, '5.7.42');
  const unionQ = calls.find((q) => /UNION SELECT/.test(q));
  assert.ok(unionQ, '应发出 UNION 提取');
  assert.ok(!/CAST\(/.test(unionQ), 'noCast 时提取 payload 不应含 CAST(');
  assert.ok(/CONCAT\('__S__',\(version\(\)\),'__E__'\)/.test(unionQ), '应使用 WRAP_NOCAST 隐式拼接');
});

test('noCast 缺省时 extractScalar 仍走 CAST 显式转换（默认行为不变）', async () => {
  const calls = [];
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      calls.push(q);
      if (/UNION SELECT/.test(q)) return { data: 'page ... __S__5.7.42__E__ ...', status: 200 };
      return { data: 'normal', status: 200 };
    },
  };
  const ctx = buildCtx(mock, 'MySQL', { unionCols: 2 });
  ctx.point.echoCols = [0];
  const ex = new Extractor();
  const val = await ex.extractScalar(ctx, 'version()', 2);
  assert.equal(val, '5.7.42');
  const unionQ = calls.find((q) => /UNION SELECT/.test(q));
  assert.ok(/CAST\(/.test(unionQ), '默认应使用 CAST 显式转换（WRAP）');
});
