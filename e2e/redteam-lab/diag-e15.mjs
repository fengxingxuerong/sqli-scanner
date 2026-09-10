// ============================================================================
// diag-e15 —— 二阶注入（E15）失败点逐步诊断
// 直接调用 SecondOrderDetector，打印：基线/存储/触发/阴性 四步的请求与响应指纹
// ============================================================================
import { HttpClient } from '../../server/src/core/httpClient.js';
import { SecondOrderDetector } from '../../server/src/engine/detectors/SecondOrderDetector.js';
import { createTarget } from '../../server/src/engine/models.js';
import { ERROR_SIG } from '../../server/src/engine/payloads.js';

const LAB = 'http://127.0.0.1:8231';
const TRIGGER = `${LAB}/account/me`;
const WRITE = `${LAB}/account/update`;

process.env.NO_PROXY = '127.0.0.1,localhost';

const target = createTarget({
  url: WRITE,
  method: 'POST',
  jsonBody: { name: 'alice' },
  cookieParams: { sid: 'rt1' },
  config: {
    secondOrder: { enabled: true, allowWrites: true },
    productionMode: false,
    timeoutMs: 15000,
    ratePerSec: 50,
  },
});

const point = {
  id: 'p-e15', location: 'body', param: 'name', originalValue: 'alice',
  isStorePoint: true, actionUrl: WRITE,
};

const detector = new SecondOrderDetector();
const httpClient = new HttpClient();

// 包装 httpClient.request 打出每次请求与响应指纹
const origRequest = httpClient.request.bind(httpClient);
const seen = [];
httpClient.request = async (req) => {
  const res = await origRequest(req);
  const body = String(res?.data ?? '');
  seen.push({
    method: req.method,
    url: req.url,
    data: req.data,
    cookie: req.headers?.Cookie || req.headers?.cookie || null,
    status: res?.status,
    len: body.length,
    errMatch: (body.match(ERROR_SIG) || [])[0] || null,
    head: body.slice(0, 90).replace(/\s+/g, ' '),
  });
  return res;
};

const ctx = {
  httpClient,
  target,
  point,
  dbms: null,
  config: target.config,
  triggerUrl: TRIGGER,
};

console.log('=== probe 构造 ===');
const probe = detector._buildProbe(ctx, null);
console.log('probe =', JSON.stringify(probe));

console.log('\n=== 1) 基线（读触发页）===');
const baseBody = await detector._trigger(httpClient, ctx, TRIGGER);
console.log('len =', baseBody.length, '| ERROR_SIG =', (baseBody.match(ERROR_SIG) || [])[0] || null);
console.log('body:', baseBody.slice(0, 160).replace(/\s+/g, ' '));

console.log('\n=== 2) 存储探针 ===');
await detector._store(httpClient, ctx, probe);

console.log('\n=== 3) 触发（读触发页，期待报错）===');
const expBody = await detector._trigger(httpClient, ctx, TRIGGER);
console.log('len =', expBody.length, '| ERROR_SIG =', (expBody.match(ERROR_SIG) || [])[0] || null);
console.log('body:', expBody.slice(0, 160).replace(/\s+/g, ' '));

console.log('\n=== 4) 完整 detect() ===');
const result = await detector.detect(ctx);
console.log('vulnerable =', result.vulnerable, '| evidence =', result.evidence || '(空)');

console.log('\n=== 请求流水 ===');
for (const [i, s] of seen.entries()) {
  console.log(`#${i + 1} ${s.method} ${s.url} cookie=${s.cookie} status=${s.status} len=${s.len} err=${s.errMatch ? 'YES' : 'no'}`);
  console.log(`    data=${JSON.stringify(s.data)} | ${s.head.slice(0, 80)}`);
}
