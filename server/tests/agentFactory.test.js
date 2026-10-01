// [四期拆分 2026-09-30] core/http/agentFactory.js 直接单测。
//
// 为什么补：agentsForTls / buildProxyAgent 原先只能经 httpClient.p2.test 间接覆盖，
// 而「TLS 校验开关的 Agent 组合缓存」是安全语义的承载点 —— 共享 httpsAgent 一旦被
// insecure 组合复用，等于一个自签目标关掉了全局证书校验（httpClient.js 头部注释的
// 原话）。抽成独立模块后可以直测的边界：
//   ① 默认组合（secure + keepAlive）必须复用共享单例（零行为变化的前提）
//   ② insecure 组合必须新建 Agent 且 httpsAgent.rejectUnauthorized === false
//   ③ 缓存按 {insecure, keepAlive} 双维 key —— 组合不同不得串用实例
//   ④ buildProxyAgent：socks 分流 / 代理内嵌凭据 / insecure|secure 分 key 缓存
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  agentsForTls, buildProxyAgent, httpAgent, httpsAgent,
} from '../src/core/http/agentFactory.js';

test('agentsForTls: 默认组合（secure + keepAlive）复用共享单例（零行为变化前提）', () => {
  const conf = agentsForTls(false, true);
  assert.equal(conf.httpAgent, httpAgent, 'secure+ka 必须复用模块级共享 httpAgent');
  assert.equal(conf.httpsAgent, httpsAgent, 'secure+ka 必须复用模块级共享 httpsAgent');
});

test('agentsForTls: insecure 组合新建 Agent 且 httpsAgent 关闭证书校验', () => {
  const conf = agentsForTls(true, true);
  assert.notEqual(conf.httpAgent, httpAgent, 'insecure 不得复用共享实例（自签目标不得关全局校验）');
  // 判据读 Node 真正消费的位置：https.Agent 把 rejectUnauthorized 存进 options，
  // 由 createConnection 的 TLS 握手消费（实例顶层没有这个属性）
  assert.equal(conf.httpsAgent.options.rejectUnauthorized, false);
  assert.equal(conf.httpAgent.options.keepAlive, true);
});

test('agentsForTls: 缓存按 {insecure, keepAlive} 双维 key，同组合同实例、跨组合不串用', () => {
  const a1 = agentsForTls(true, true);
  const a2 = agentsForTls(true, true);
  assert.equal(a1, a2, '同组合命中缓存（同一实例）');
  const b = agentsForTls(true, false);
  assert.notEqual(a1, b, 'keepAlive 不同 = 不同组合，不得串用');
  assert.equal(b.httpsAgent.options.keepAlive, false);
  // secure 组合与 insecure 组合也必须不同对象
  assert.notEqual(agentsForTls(false, false), agentsForTls(true, false));
});

test('buildProxyAgent: 空代理 → { proxy: false }（直连语义）', () => {
  assert.deepEqual(buildProxyAgent(undefined), { proxy: false });
  assert.deepEqual(buildProxyAgent(''), { proxy: false });
});

test('buildProxyAgent: http 代理内嵌凭据进入 proxy.auth（P2-FIX 回归钉）', () => {
  const conf = buildProxyAgent('http://user:p%40ss@127.0.0.1:8888');
  assert.equal(conf.proxy.protocol, 'http');
  assert.equal(conf.proxy.host, '127.0.0.1');
  assert.equal(conf.proxy.port, 8888);
  assert.deepEqual(conf.proxy.auth, { username: 'user', password: 'p@ss' }, 'URL 编码凭据须解码');
});

test('buildProxyAgent: 缓存按 proxyUrl+insecure 双维 key（同 key 同实例、跨 key 不串用）', () => {
  const s1 = buildProxyAgent('http://127.0.0.1:8888', { insecureTls: false });
  const s2 = buildProxyAgent('http://127.0.0.1:8888', { insecureTls: false });
  assert.equal(s1, s2, '同 key 命中缓存（keep-alive 复用的前提）');
  const i1 = buildProxyAgent('http://127.0.0.1:8888', { insecureTls: true });
  assert.notEqual(s1, i1, 'insecure/secure 必须分 key —— 否则自签目标复用严格校验 Agent');
});
