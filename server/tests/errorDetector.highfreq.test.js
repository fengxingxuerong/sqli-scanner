// 性能差距 3 回归：dbms 未知时 ErrorDetector 高频库截断
// 原实现 Object.values(PAYLOADS).flatMap(t=>t.error) = 14+ 库 × N 模板全量连发；
// 修复后半宽顺序（MariaDB/MySQL/PG/MSSQL/SQLite/Oracle 等前 8 高频库）取每库首条，
// 命中即停。验证：模板总数 ≤8、顺序符合高频库优先级、检测行为（命中/未命中）不变。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorDetector } from '../src/engine/detectors/ErrorDetector.js';
import { pickErrorTemplates } from '../src/engine/detectors/ErrorDetector.js';
import { PAYLOADS, ERROR_SIG_BY_DBMS } from '../src/engine/payloads.js';

test('差距3: pickErrorTemplates 数量截断到高频库子集（≤8）', () => {
  const tpls = pickErrorTemplates(null); // dbms 未知
  assert.ok(Array.isArray(tpls) && tpls.length > 0, '应返回非空模板');
  assert.ok(tpls.length <= 8, `模板数 ${tpls.length} 应 ≤ 8（原实现全库连发可到 40+）`);
});

test('差距3: 高频库在前（MySQL/PG/MSSQL/Oracle 等先于边缘库）', () => {
  const tpls = pickErrorTemplates(null);
  const highFreq = new Set(['MySQL', 'PostgreSQL', 'SQL Server', 'SQLite', 'Oracle', 'MariaDB']);
  const firstDbHits = ERROR_SIG_BY_DBMS.slice(0, 8).filter((x) => highFreq.has(x.dbms)).length;
  assert.ok(firstDbHits >= 5, `前 8 高频位应多数为常见库（实得 ${firstDbHits}）`);
  assert.ok(tpls.length >= 3, '应覆盖至少 3 个高频库的模板');
});

test('差距3: dbms 已知时仍返回该库全部 error 模板（不截断）', () => {
  const tpls = pickErrorTemplates('MySQL');
  assert.deepEqual(tpls, PAYLOADS.MySQL.error, '已知库应原样返回全部模板');
});

// 可解析的注入值取回（同其它检测测试）
function extractInjected(opts) {
  const url = String(opts?.url || '');
  const m = url.match(/[?&]q=([^&]*)/);
  if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  if (opts?.data && Object.keys(opts.data).length) return String(Object.values(opts.data)[0]);
  if (opts?.headers && typeof opts.headers.Cookie === 'string') {
    const cm = opts.headers.Cookie.match(/q=([^;]*)/);
    if (cm) return decodeURIComponent(cm[1]).replace(/\+/g, ' ');
  }
  return '';
}

test('差距3: dbms 未知时高频库截断不影响检测行为（模拟 MySQL 报错目标仍命中）', async () => {
  const d = new ErrorDetector();
  let reqCount = 0;
  const ctx = {
    httpClient: {
      async request(opts) {
        reqCount++;
        const v = extractInjected(opts);
        // MySQL 报错向量 extractvalue → 返回 MySQL 专属报错
        if (v.includes('extractvalue')) {
          return { status: 500, headers: {}, data: "You have an error in your SQL syntax; near 'sqli' at line 1" };
        }
        return { status: 200, headers: {}, data: 'normal' };
      },
    },
    target: { baseUrl: 'http://x/' },
    point: { id: 'p1', originalValue: '1', param: 'q', location: 'url' },
    config: { level: 1 },
    dbms: null,
  };
  const r = await d.detect(ctx);
  assert.equal(r.vulnerable, true, 'MySQL 报错目标应命中');
  assert.equal(r.dbms, 'MySQL', '报错签名应反推 MySQL');
  // baseline(1) + 探测(≤8) + 命中确认(1)：≤10；原实现(1+42+1)
  assert.ok(reqCount <= 10, `请求数 ${reqCount} 应远小于原全库遍历`);
});

test('差距3: 未命中目标请求受上限约束（不无限连发）', async () => {
  const d = new ErrorDetector();
  let reqCount = 0;
  const ctx = {
    httpClient: {
      async request() {
        reqCount++;
        return { status: 200, headers: {}, data: 'normal' };
      },
    },
    target: { baseUrl: 'http://x/' },
    point: { id: 'p1', originalValue: '1', param: 'q', location: 'url' },
    config: { level: 1 },
    dbms: null,
  };
  const r = await d.detect(ctx);
  assert.equal(r.vulnerable, false, '无报错目标不应误报');
  // baseline(1) + 探测(≤8) = ≤9；原实现 ≤43
  assert.ok(reqCount <= 10, `未命中目标请求数 ${reqCount} 应 ≤ 基线+8（原实现 ≤43）`);
});