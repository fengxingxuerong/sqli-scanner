// QA 独立验证（严过关）：P2 五项增强的"能用"证明，非照搬工程师单测。
// 重点：代理/认证的不变量、WAF 混淆后检测仍有效（语义等价 + 检测器可检出）、
// 以及无代理/认证/WAF 时的回归护栏。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpClient, buildProxyAgent, mergeAuthHeaders } from '../src/core/httpClient.js';
import { Detector } from '../src/engine/Detector.js';
import { fillPayload, obfuscatePayload } from '../src/engine/payloads.js';

// ===== F-14 代理：独立确认 buildProxyAgent 行为 =====
test('QA-代理: buildProxyAgent socks5 → SocksProxyAgent 实例且 proxy:false', () => {
  const conf = buildProxyAgent('socks5://127.0.0.1:1080');
  assert.equal(conf.proxy, false);
  assert.ok(conf.httpAgent instanceof SocksProxyAgent, 'httpAgent 应为 SocksProxyAgent');
  assert.ok(conf.httpsAgent instanceof SocksProxyAgent, 'httpsAgent 应为 SocksProxyAgent');
});

test('QA-代理: buildProxyAgent http → axios 原生 proxy 配置（不挂 agent）', () => {
  const conf = buildProxyAgent('http://127.0.0.1:8080');
  assert.equal(conf.proxy.protocol, 'http');
  assert.equal(conf.proxy.host, '127.0.0.1');
  assert.equal(conf.proxy.port, 8080);
  assert.equal(conf.httpAgent, undefined);
  assert.equal(conf.httpsAgent, undefined);
});

test('QA-代理: buildProxyAgent 空值 → { proxy: false }（等价于 v1.0.0）', () => {
  assert.deepEqual(buildProxyAgent(null), { proxy: false });
  assert.deepEqual(buildProxyAgent(''), { proxy: false });
  assert.deepEqual(buildProxyAgent(false), { proxy: false });
});

// ===== F-15 认证：独立确认 mergeAuthHeaders 行为 =====
test('QA-认证: basic → Authorization: Basic base64(a:b)', () => {
  const h = mergeAuthHeaders({}, { basic: { username: 'a', password: 'b' } });
  assert.equal(h['Authorization'], 'Basic ' + Buffer.from('a:b').toString('base64'));
});

test('QA-认证: cookie → 生成 Cookie 头', () => {
  const h = mergeAuthHeaders({}, { cookie: 'x=y' });
  assert.equal(h['Cookie'], 'x=y');
});

test('QA-认证: 自定义 headers 合并任意头（叠加已有头）', () => {
  const h = mergeAuthHeaders({ 'X-Orig': '1' }, { headers: { 'X-Test': '1' } });
  assert.equal(h['X-Orig'], '1');
  assert.equal(h['X-Test'], '1');
});

// ===== 回归护栏：无代理/无认证/无 WAF 时行为完全不变 =====
test('QA-回归护栏: 无 proxy/auth/wafEvasion → 不出 agent、不覆盖 UA、不 sleep、不翻译头', async () => {
  const client = new HttpClient();
  let captured = null;
  client.instance.request = async (cfg) => {
    captured = cfg;
    return { data: 'ok', status: 200 };
  };
  const start = Date.now();
  await client.request({ method: 'GET', url: 'http://127.0.0.1:9999/', headers: {} });
  const elapsed = Date.now() - start;

  // 代理不变量：proxy:false，不挂 SocksProxyAgent
  assert.equal(captured.proxy, false);
  assert.equal(captured.httpAgent, undefined);
  assert.equal(captured.httpsAgent, undefined);
  // 不翻译任何认证头
  assert.equal(captured.headers['Authorization'], undefined);
  assert.equal(captured.headers['Cookie'], undefined);
  // 不覆盖 User-Agent（关闭随机 UA 时不应新增该头）
  assert.equal(captured.headers['User-Agent'], undefined);
  // 不 sleep（jitter 未开启应几乎瞬时返回）
  assert.ok(elapsed < 1000, `不应发生随机延时，实际耗时 ${elapsed}ms`);
});

// ===== F-16 WAF 混淆：证明混淆后 payload 仍语义有效 =====
test('QA-WAF: obfuscatePayload 语义等价（数字/引号/__S__/__E__ 标记不被破坏）', () => {
  // 提取标记场景：字符串字面量内内容整体透传
  const tagged = obfuscatePayload("'__S__secret__E__' AND 1=1");
  assert.ok(tagged.includes("'__S__secret__E__'"), '字符串字面量内标记应原样保留');
  assert.ok(tagged.includes('1=1'), '数字表达式应保留');

  // 多次随机化后，剥除内联注释 + 归一化大小写，仍等价于原始 SQL
  for (let i = 0; i < 30; i++) {
    const out = obfuscatePayload('AND 1=1');
    const normalized = out
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .toUpperCase();
    assert.equal(normalized, 'AND 1=1');
  }
});

// ---- 轻量 mock 目标：模拟服务端对注入值的 SQL 感知判定（忽略内联注释，符合 SQL 语义）----
function stripComments(s) {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').toUpperCase();
}

function makeMockClient(serverFn) {
  return {
    async request(opts) {
      const u = new URL(opts.url);
      const injected = u.searchParams.get('q') || '';
      return { data: serverFn(injected), status: 200 };
    },
  };
}

// 复用真实 Detector 的 buildRequest / obfuscateValue / send，仅替换底层 httpClient
class UnionDetector extends Detector {
  async detect(ctx) {
    const filled = fillPayload('{ORIG} UNION SELECT {NULLS}-- -', { orig: '1', nulls: 'NULL' });
    const value = this.obfuscateValue(ctx, filled);
    const req = this.buildRequest(ctx.target, { location: 'url', param: 'q' }, value);
    const res = await this.send(ctx.httpClient, ctx, req);
    return res.data === 'HIT';
  }
}

class BooleanDetector extends Detector {
  async detect(ctx) {
    const filled = fillPayload('{ORIG} AND 1=1-- -', { orig: '' });
    const value = this.obfuscateValue(ctx, filled);
    const req = this.buildRequest(ctx.target, { location: 'url', param: 'q' }, value);
    const res = await this.send(ctx.httpClient, ctx, req);
    return res.data === 'TRUE';
  }
}

const unionTarget = (inj) =>
  stripComments(inj).includes('UNION') && stripComments(inj).includes('SELECT') ? 'HIT' : 'MISS';
const boolTarget = (inj) => (stripComments(inj).includes('1=1') ? 'TRUE' : 'FALSE');

test('QA-WAF: 混淆后 UNION 检测仍生效（mock 目标，证明"能用"）', async () => {
  const client = makeMockClient(unionTarget);
  const ctxOn = {
    httpClient: client,
    target: { baseUrl: 'http://t/', method: 'GET' },
    config: { wafEvasion: { randomUA: false, jitterMs: 0, obfuscate: true } },
  };
  const ctxOff = {
    httpClient: client,
    target: { baseUrl: 'http://t/', method: 'GET' },
    config: { wafEvasion: { randomUA: false, jitterMs: 0, obfuscate: false } },
  };
  const d = new UnionDetector('union');
  assert.equal(await d.detect(ctxOff), true, '未混淆应命中');
  assert.equal(await d.detect(ctxOn), true, '混淆后仍应命中（WAF 规避不能破坏检测）');
});

test('QA-WAF: 混淆后布尔(1=1)检测仍生效（mock 目标）', async () => {
  const client = makeMockClient(boolTarget);
  const ctxOn = {
    httpClient: client,
    target: { baseUrl: 'http://t/', method: 'GET' },
    config: { wafEvasion: { randomUA: false, jitterMs: 0, obfuscate: true } },
  };
  const d = new BooleanDetector('boolean');
  assert.equal(await d.detect(ctxOn), true, '混淆后布尔探针仍应能区分 1=1');
});

test('QA-WAF: 混淆后 payload 仍能被 fillPayload 正确还原（占位符不被破坏）', () => {
  const tpl = "{ORIG}' UNION SELECT {NUM}-- -";
  const obf = obfuscatePayload(fillPayload(tpl, { orig: '1', num: 42 }));
  const stripped = obf.replace(/\/\*[\s\S]*?\*\//g, ' ');
  assert.ok(/UNION/i.test(stripped) && /SELECT/i.test(stripped), '关键字应保留');
  assert.ok(stripped.toUpperCase().includes('42'), '列数占位符应保留');
  assert.ok(!stripped.toUpperCase().includes('{ORIG}'), '占位符应已被填充');
});
