// SecondOrderDetector 单元测试：mock HttpClient 维护"已存值状态"，
// 触发页按已存值是否含探针（单引号）回显报错特征，验证三态判定（基线/实验/阴性对照）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SecondOrderDetector } from '../src/engine/detectors/SecondOrderDetector.js';
import { ErrorCode } from '../src/core/errors.js';

// 模拟目标：维护一个"已存值"。POST 把表单某字段值写入 state；GET 触发页按已存值是否含单引号回显报错。
// param：指定哪个字段是触发点（取 data[param] 作为已存值）。
// alwaysError：为 true 时无论已存值如何，触发页恒回显报错（用于验证阴性对照门控）。
function makeMockForState({ param, initialStored = '1', alwaysError = false } = {}) {
  const state = { value: initialStored, posts: 0, gets: 0 };
  const httpClient = {
    async request(opts) {
      if (opts.method === 'POST') {
        state.posts++;
        const data = opts.data && typeof opts.data === 'object' ? opts.data : {};
        // 取触发点字段值；否则取第一个值兜底
        state.value = param && data[param] != null ? data[param] : Object.values(data)[0] ?? state.value;
        return { data: 'OK', status: 200 };
      }
      if (opts.method === 'GET') {
        state.gets++;
        const hasQuote = String(state.value).includes("'");
        const body = alwaysError || hasQuote ? 'You have an error in your SQL syntax' : '<html>profile ok</html>';
        return { data: body, status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
  return { httpClient, state };
}

function makeCtx({
  httpClient,
  dbms = 'MySQL',
  enabled = true,
  triggerUrl = 'http://mock/trigger',
  param = 'username',
  originalValue = '1',
  negativeControl = true,
  refreshCsrf = false,
} = {}) {
  const config = {
    timeoutMs: 5000,
    retry: 1,
    secondOrder: {
      enabled,
      triggerUrls: triggerUrl ? [triggerUrl] : [],
      refreshCsrf: refreshCsrf ?? false,
      negativeControl,
      oobTrigger: false,
    },
  };
  const target = {
    method: 'GET',
    baseUrl: 'http://mock/?q=1',
    headerParams: {},
    cookieParams: {},
    config,
  };
  const point = {
    id: 'p1',
    location: 'body',
    param,
    originalValue,
    confirmed: false,
    technique: null,
    dbms: null,
    formMethod: 'POST',
    actionUrl: 'http://mock/store',
    formValues: { [param]: originalValue, _token: 'csrf' },
    csrfTokenName: '_token',
  };
  return { httpClient, target, point, dbms, config, triggerUrl };
}

test('二阶未启用 → 抛 SECOND_ORDER_DISABLED，不发起任何请求', async () => {
  const { httpClient, state } = makeMockForState({ param: 'username' });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, enabled: false });
  await assert.rejects(
    () => d.detect(ctx),
    (e) => e instanceof Error && e.code === ErrorCode.SECOND_ORDER_DISABLED
  );
  assert.equal(state.posts, 0);
  assert.equal(state.gets, 0);
});

test('无触发页 triggerUrl → 未命中且零请求', async () => {
  const { httpClient, state } = makeMockForState({ param: 'username' });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, triggerUrl: null });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, false);
  assert.equal(res.technique, 'second_order');
  assert.equal(state.posts, 0);
  assert.equal(state.gets, 0);
});

test('三态判定命中：基线无/实验有/阴性无 → vulnerable=true', async () => {
  const { httpClient } = makeMockForState({ param: 'username', initialStored: '1' });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, dbms: 'MySQL' });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'second_order');
  assert.equal(res.dbms, 'MySQL');
  assert.ok(res.evidence.includes('二阶注入确认'));
  assert.ok(Array.isArray(res.payloads) && res.payloads.length === 1);
  assert.ok(res.payloads[0].includes("'")); // 探针为报错型（含单引号）
  // 与现有检测器一致：同步标记注入点
  assert.equal(ctx.point.confirmed, true);
  assert.equal(ctx.point.technique, 'second_order');
});

test('基线已含报错（存储初值即触发）→ 判定为页面固有，未命中', async () => {
  // 初始已存值含单引号 → 基线即报错 → !baselineErr 不成立 → 不命中
  const { httpClient } = makeMockForState({ param: 'username', initialStored: "'" });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, dbms: 'MySQL', originalValue: "'" });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, false);
  assert.equal(ctx.point.confirmed, false);
});

test('阴性对照门控：实验与阴性均回显报错 → 判定不可信，未命中', async () => {
  // alwaysError → 基线无（'1'）、实验有、阴性也有（良性值仍报错）→ !negErr 不成立 → 不命中
  const { httpClient } = makeMockForState({ param: 'username', initialStored: '1', alwaysError: true });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, dbms: 'MySQL' });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, false);
  assert.equal(ctx.point.confirmed, false);
});

test('关闭阴性对照（negativeControl=false）→ 仅基线+实验判定，可命中', async () => {
  const { httpClient } = makeMockForState({ param: 'username', initialStored: '1' });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, dbms: 'MySQL', negativeControl: false });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'second_order');
});

test('未知 dbms 时回退 SECOND_ORDER_PROBES 仍可命中', async () => {
  const { httpClient } = makeMockForState({ param: 'username', initialStored: '1' });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, dbms: null }); // 未知库
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.dbms, null);
});

test('refreshCsrf=true 时存储前 GET actionUrl 重抓 token（best-effort，不阻断）', async () => {
  // 触发页 GET 在重抓阶段返回无报错 HTML → 不影响后续判定
  const { httpClient } = makeMockForState({ param: 'username', initialStored: '1' });
  const d = new SecondOrderDetector();
  const ctx = makeCtx({ httpClient, dbms: 'MySQL', refreshCsrf: true });
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
});
