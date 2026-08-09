// P2 回归测试：验证「无代理/无认证/无 WAF」时 httpClient 行为完全不变（回归护栏），
// 以及 buildProxyAgent / mergeAuthHeaders / obfuscatePayload 的关键不变量。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpClient, buildProxyAgent, mergeAuthHeaders } from '../src/core/httpClient.js';
import { obfuscatePayload } from '../src/engine/payloads.js';

// ===== buildProxyAgent =====
test('buildProxyAgent: 空值返回 { proxy: false }', () => {
  assert.deepEqual(buildProxyAgent(null), { proxy: false });
  assert.deepEqual(buildProxyAgent(''), { proxy: false });
  assert.deepEqual(buildProxyAgent(false), { proxy: false });
});

test('buildProxyAgent: socks5 返回 SocksProxyAgent 且 proxy:false', () => {
  const conf = buildProxyAgent('socks5://127.0.0.1:1080');
  assert.equal(conf.proxy, false);
  assert.ok(conf.httpAgent instanceof SocksProxyAgent);
  assert.ok(conf.httpsAgent instanceof SocksProxyAgent);
});

test('buildProxyAgent: socks:// 也走 SocksProxyAgent', () => {
  const conf = buildProxyAgent('socks://user:pass@127.0.0.1:1080');
  assert.equal(conf.proxy, false);
  assert.ok(conf.httpAgent instanceof SocksProxyAgent);
});

test('buildProxyAgent: http 代理返回 axios 原生 proxy 配置', () => {
  const conf = buildProxyAgent('http://127.0.0.1:8080');
  assert.deepEqual(conf, { proxy: { protocol: 'http', host: '127.0.0.1', port: 8080 } });
});

test('buildProxyAgent: https 代理解析协议/主机/端口', () => {
  const conf = buildProxyAgent('https://proxy.example.com:3128');
  assert.equal(conf.proxy.protocol, 'https');
  assert.equal(conf.proxy.host, 'proxy.example.com');
  assert.equal(conf.proxy.port, 3128);
});

// ===== mergeAuthHeaders =====
test('mergeAuthHeaders: 空 auth 原样返回', () => {
  assert.deepEqual(mergeAuthHeaders({ a: '1' }, null), { a: '1' });
});

test('mergeAuthHeaders: Basic Auth 生成 Authorization 头', () => {
  const h = mergeAuthHeaders({}, { basic: { username: 'user', password: 'pass' } });
  assert.equal(h['Authorization'], 'Basic ' + Buffer.from('user:pass').toString('base64'));
});

test('mergeAuthHeaders: Cookie 与已有 Cookie 合并', () => {
  const h = mergeAuthHeaders({ Cookie: 'a=1' }, { cookie: 'b=2' });
  assert.equal(h['Cookie'], 'a=1; b=2');
});

test('mergeAuthHeaders: 仅 cookie 且无已有 Cookie', () => {
  const h = mergeAuthHeaders({}, { cookie: 'b=2' });
  assert.equal(h['Cookie'], 'b=2');
});

test('mergeAuthHeaders: 自定义 headers 合并', () => {
  const h = mergeAuthHeaders({ 'X-A': '1' }, { headers: { 'X-B': '2', 'X-C': '3' } });
  assert.equal(h['X-A'], '1');
  assert.equal(h['X-B'], '2');
  assert.equal(h['X-C'], '3');
});

// ===== request 无配置不变量（回归护栏）=====
test('request 无代理/无认证/无 WAF 时行为不变', async () => {
  const client = new HttpClient();
  let captured = null;
  client.instance.request = async (cfg) => {
    captured = cfg;
    return { data: 'ok', status: 200 };
  };
  const start = Date.now();
  const res = await client.request({ method: 'GET', url: 'http://x/', headers: {} });
  const elapsed = Date.now() - start;

  assert.ok(res && res.data === 'ok');
  // 代理不变量：proxy:false（不挂 SocksProxyAgent 等原生代理 agent）
  assert.equal(captured.proxy, false);
  // 注意：默认 keepAlive=true 时会挂一个 node:http 标准 keepAlive agent（连接复用优化，非副作用）；
  // 这里只断言"不是 SOCKS 代理 agent"，且 keepAlive 关闭时确实不再挂 agent。
  if (client.keepAlive) {
    assert.ok(captured.httpAgent instanceof (await import('node:http')).Agent, '默认开启 keepAlive 应挂 http 标准 agent');
    assert.equal(captured.httpAgent.constructor.name, 'Agent');
  } else {
    assert.equal(captured.httpAgent, undefined);
    assert.equal(captured.httpsAgent, undefined);
  }
  // 不翻译任何认证头
  assert.equal(captured.headers['Authorization'], undefined);
  assert.equal(captured.headers['Cookie'], undefined);
  // 不覆盖 User-Agent（关闭随机 UA 时不应新增该头）
  assert.equal(captured.headers['User-Agent'], undefined);
  // 不 sleep（jitter 未开启应几乎瞬时返回）
  assert.ok(elapsed < 1000, `不应发生随机延时，实际耗时 ${elapsed}ms`);
});

test('request 开启 randomUA 时覆盖 User-Agent', async () => {
  const client = new HttpClient();
  let captured = null;
  client.instance.request = async (cfg) => {
    captured = cfg;
    return { data: '', status: 200 };
  };
  await client.request({
    method: 'GET',
    url: 'http://x/',
    headers: {},
    wafEvasion: { randomUA: true, jitterMs: 0, obfuscate: false },
  });
  assert.equal(typeof captured.headers['User-Agent'], 'string');
  assert.ok(captured.headers['User-Agent'].length > 0);
});

test('request 透传 proxy/auth 参数', async () => {
  const client = new HttpClient();
  let captured = null;
  client.instance.request = async (cfg) => {
    captured = cfg;
    return { data: '', status: 200 };
  };
  await client.request({
    method: 'GET',
    url: 'http://x/',
    headers: { 'X-T': '1' },
    proxy: 'http://127.0.0.1:8080',
    auth: { basic: { username: 'u', password: 'p' } },
    wafEvasion: { randomUA: false, jitterMs: 0, obfuscate: false },
  });
  assert.equal(captured.proxy.protocol, 'http');
  assert.equal(captured.headers['Authorization'], 'Basic ' + Buffer.from('u:p').toString('base64'));
  // 透传但关闭的 WAF 开关不覆盖 UA
  assert.equal(captured.headers['User-Agent'], undefined);
});

// ===== obfuscatePayload =====
test('obfuscatePayload 不改变数字与引号（字符串字面量安全）', () => {
  const out = obfuscatePayload("SELECT 123 FROM 'table' WHERE 1=1");
  assert.ok(out.includes('123'), '数字应保留');
  assert.ok(out.includes("'table'"), '引号内字面量应原样保留');
  assert.ok(out.includes('1=1'), '数字表达式应保留');
});

test('obfuscatePayload 输出仍可解析为等价 SQL', () => {
  const out = obfuscatePayload('UNION SELECT 1');
  const normalized = out
    .replace(/\/\*[a-zA-Z0-9]*\*\//g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toUpperCase();
  assert.equal(normalized, 'UNION SELECT 1');
});

test('obfuscatePayload 连续多次均保持可解析', () => {
  for (let i = 0; i < 20; i++) {
    const out = obfuscatePayload(
      "AND 1=(SELECT 1 FROM dual WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE('a',2))"
    );
    const normalized = out
      .replace(/\/\*[a-zA-Z0-9]*\*\//g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .toUpperCase();
    assert.ok(normalized.includes("DBMS_PIPE.RECEIVE_MESSAGE('A',2)"));
  }
});
