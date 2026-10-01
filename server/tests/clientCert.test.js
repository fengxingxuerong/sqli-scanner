// ============================================================================
// tests/clientCert.test.js —— mTLS 客户端证书（对标 sqlmap --cert，2026-10-01）
// ============================================================================
// 吸收竞品能力：sqlmap --cert=<pem>（单文件证书+私钥）。本仓此前 vs sqlmap 完全没有
// mTLS —— 要求双向认证的站点在检测阶段之前就出局。本测试钉四层：
//   ① 加载层：缺文件/形状错抛错（要响），合法 PEM 按 path+mtime 缓存；
//   ② Agent 层：mTLS 组合挂 cert/key、按证书指纹分池、不污染共享单例；
//   ③ 解析层：effectiveClientCert 的 opts/defaults 优先序与空值语义；
//   ④ 入口层：REST 白名单透传 + CLI --cert 落 config（断链即红）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadClientCert } from '../src/core/http/clientCert.js';
import { agentsForTls, httpsAgent as sharedHttpsAgent } from '../src/core/http/agentFactory.js';
import { effectiveClientCert } from '../src/core/http/requestContext.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const FAKE_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'MIIBszCCAVmgAwIBAgIUfakesO2FWGnFk0X6uA5f4lRk3Y4wCgYIKoZIzj0EAwIw',
  '-----END CERTIFICATE-----',
  '-----BEGIN PRIVATE KEY-----',
  'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfakekeymaterial0',
  '-----END PRIVATE KEY-----',
  '',
].join('\n');

const dir = mkdtempSync(join(tmpdir(), 'mtls-'));
const pemPath = join(dir, 'client.pem');
writeFileSync(pemPath, FAKE_PEM);
const badPath = join(dir, 'bad.pem');
writeFileSync(badPath, 'not a pem at all');

test('加载层：缺文件 / 形状错 → 抛错（配置错误要响，不静默降级）', () => {
  assert.throws(() => loadClientCert(join(dir, 'missing.pem')), /不可读/);
  assert.throws(() => loadClientCert(badPath), /CERTIFICATE 与 PRIVATE KEY/);
});

test('加载层：合法 PEM → cert/key 同缓冲；同路径二次加载命中缓存（同对象）', () => {
  const a = loadClientCert(pemPath);
  assert.ok(Buffer.isBuffer(a.cert) && Buffer.isBuffer(a.key));
  const b = loadClientCert(pemPath);
  assert.equal(a.cert, b.cert, '同 path+mtime 必须命中缓存（扫描期不得每请求读盘）');
});

test('Agent 层：mTLS 组合挂 cert/key、按指纹分池、共享单例不被污染', () => {
  const m = loadClientCert(pemPath);
  const conf1 = agentsForTls(false, true, m);
  assert.notEqual(conf1.httpsAgent, sharedHttpsAgent, 'mTLS 不得复用共享 httpsAgent（会污染全局）');
  assert.equal(conf1.httpsAgent.options.cert, m.cert, 'httpsAgent 必须挂客户端证书');
  assert.equal(conf1.httpsAgent.options.key, m.key);
  assert.equal(conf1.httpsAgent.options.rejectUnauthorized, undefined, 'mTLS 不得顺走 insecure 语义');
  const conf2 = agentsForTls(false, true, m);
  assert.equal(conf2.httpsAgent, conf1.httpsAgent, '同证书必须命中 Agent 缓存');
  const other = agentsForTls(false, true, { cert: Buffer.from('other'), key: Buffer.from('other') });
  assert.notEqual(other.httpsAgent, conf1.httpsAgent, '不同证书不得串池');
  // 零 mTLS 的默认组合仍是共享单例（零回归）
  assert.equal(agentsForTls(false, true).httpsAgent, sharedHttpsAgent);
});

test('解析层：opts 优先、defaults 兜底、空串/非字符串视为未配置', () => {
  assert.equal(effectiveClientCert({ clientCert: ' /x.pem ' }), '/x.pem', 'trim 后取值');
  assert.equal(effectiveClientCert({ clientCert: '' }), null);
  assert.equal(effectiveClientCert({ clientCert: 123 }), null);
  assert.equal(effectiveClientCert({}), null, 'defaults.clientCert=null 时未配置');
});

test('入口层：REST 白名单透传 clientCert；非法形状 1003', () => {
  const ok = sanitizeStart({ url: 'http://example.com/?id=1', config: { clientCert: '/tmp/client-cert.pem' } });
  assert.equal(ok.config.clientCert, '/tmp/client-cert.pem', 'REST 传入被静默丢弃＝断链复发');
  assert.throws(
    () => sanitizeStart({ url: 'http://example.com/?id=1', config: { clientCert: 123 } }),
    /1003|clientCert/
  );
});
