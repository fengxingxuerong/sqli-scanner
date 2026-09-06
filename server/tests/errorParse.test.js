// [G4 对标 sqlmap --parse-errors] 测试：
//   · extractErrorContext / extractSqlFragment 纯函数（MySQL/PG 报错形态）
//   · ErrorDetector 默认关闭零行为变化（证据不含 errorDetail）
//   · ErrorDetector parseErrors=true 时错误原文/上下文/SQL 片段进 result.errorDetail
//   · CLI --parse-errors 解析 + buildConfig 透传
//   · REST sanitizeStart 白名单接受 parseErrors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractErrorContext, extractSqlFragment } from '../src/engine/parseErrors.js';
import { ErrorDetector } from '../src/engine/detectors/ErrorDetector.js';
import { parseArgs, buildConfig } from '../bin/cli.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';

// —— parseErrors.js 纯函数 ——
test('extractErrorContext: MySQL 报错 → 提取签名/上下文/原文', () => {
  const body = `<html><body>You have an error in your SQL syntax; check the manual near '1'' OR 1=1-- -' at line 1</body></html>`;
  const out = extractErrorContext(body);
  assert.ok(out);
  assert.match(out.match, /SQL syntax/);
  assert.match(out.context, /SQL syntax/);
  assert.match(out.bodyTruncated, /SQL syntax/);
});

test('extractErrorContext: 无报错特征 → null；非字符串入参 → null', () => {
  assert.equal(extractErrorContext('<p>no db error here</p>'), null);
  assert.equal(extractErrorContext(null), null);
  assert.equal(extractErrorContext(undefined), null);
});

test('extractErrorContext: 长 body 截断（maxBody）但 context 保留', () => {
  const longBody = `<pre>PostgreSQL ERROR: relation "users" does not exist\nLINE 1: SELECT * FROM users WHERE id=1</pre>${'x'.repeat(5000)}`;
  const out = extractErrorContext(longBody, { maxBody: 500 });
  assert.ok(out);
  assert.ok(out.bodyTruncated.length <= 500);
  assert.match(out.context, /PostgreSQL ERROR/);
});

test('extractSqlFragment: PG LINE n: 提取 SQL 行', () => {
  const body = `ERROR: new row violates ... LINE 1: SELECT * FROM users WHERE id=1 AND 1=1-- -`;
  assert.match(extractSqlFragment(body) || '', /SELECT \* FROM users/);
});

test('extractSqlFragment: MySQL near 提取片段；无片段 → null', () => {
  // 真实 MySQL 形态：near 后跟单引号包裹片段（片段内单引号是注入点原样带出）
  const body = `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '1\\' OR 1=1-- -' at line 1`;
  const frag = extractSqlFragment(body);
  assert.ok(frag, '应提取到 near 片段');
  assert.match(frag, /OR 1=1|1' OR/);
  assert.equal(extractSqlFragment('<p>nothing here</p>'), null);
});

// —— ErrorDetector 集成 ——
function makeErrorOracle() {
  // 基线无报错；注入含 SQL syntax 报错 → 返回报错体（含 PG 风格 LINE 片段）
  return {
    async request(opts) {
      const u = typeof opts.url === 'string' ? opts.url : '';
      if (u.includes('1=2') || !u.includes('%27') && !u.includes('%22')) {
        return { data: '<p>正常页面</p>', status: 200 };
      }
      return {
        data: `<pre>PostgreSQL ERROR: syntax error at or near "1"\nLINE 1: SELECT * FROM users WHERE id=1 AND 1=1-- -</pre>`,
        status: 500,
      };
    },
  };
}

function buildDetectorCtx(httpClient, config = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1' },
    dbms: 'PostgreSQL',
    config: { timeoutMs: 5000, retry: 0, ...config },
  };
}

test('ErrorDetector: 默认（parseErrors 未开）证据不含 errorDetail（零回归）', async () => {
  const d = new ErrorDetector();
  const res = await d.detect(buildDetectorCtx(makeErrorOracle()));
  assert.equal(res.vulnerable, true);
  assert.ok(!res.errorDetail, '默认关闭不应产生 errorDetail');
});

test('ErrorDetector: parseErrors=true → errorDetail 含签名/上下文/SQL 片段/原文', async () => {
  const d = new ErrorDetector();
  const res = await d.detect(buildDetectorCtx(makeErrorOracle(), { parseErrors: true }));
  assert.equal(res.vulnerable, true);
  assert.ok(res.errorDetail, '开启后应有 errorDetail');
  assert.match(res.errorDetail.signature, /PostgreSQL.*ERROR|SQL syntax/i);
  assert.match(res.errorDetail.context, /PostgreSQL ERROR|SQL syntax/i);
  assert.match(res.errorDetail.sqlFragment || '', /SELECT \* FROM users/);
  assert.ok(res.errorDetail.body.length > 0);
});

// —— CLI 解析 ——
test('CLI: parseArgs 识别 --parse-errors', () => {
  const args = parseArgs(['-u', 'http://t/?q=1', '--parse-errors']);
  assert.equal(args.parseErrors, true);
  const args2 = parseArgs(['-u', 'http://t/?q=1']);
  assert.ok(!args2.parseErrors);
});

test('CLI: buildConfig 透传 parseErrors', () => {
  const cfg = buildConfig({ parseErrors: true });
  assert.equal(cfg.parseErrors, true);
  const cfg2 = buildConfig({});
  assert.ok(!cfg2.parseErrors, '默认不开启');
});

// —— REST 白名单 ——
test('sanitizeStart: parseErrors 透传 + 默认丢弃', () => {
  const s1 = sanitizeStart({ url: 'http://t/?q=1', config: { parseErrors: true } });
  assert.equal(s1.config.parseErrors, true);
  const s2 = sanitizeStart({ url: 'http://t/?q=1', config: { parseErrors: false } });
  assert.equal(s2.config.parseErrors, false);
  const s3 = sanitizeStart({ url: 'http://t/?q=1', config: {} });
  assert.ok(!s3.config.parseErrors, '未配置默认不含该键（引擎回退 defaults false）');
});