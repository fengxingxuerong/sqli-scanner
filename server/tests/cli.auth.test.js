// ============================================================================
// cli.auth.test.js — CLI 认证参数解析（parseAuth / buildAuth）
//
// 背景（实战分析 P0-1，2026-10-02）：引擎 NTLM Type1-3 握手早已完整实现
// （ntlmAuth.js 自带 MD4+DES-L、ntlmHandshake.js 按 host 缓存，e2e/ntlm-lab
// 真机验证），CLI 却按「未实现」拒收 —— 报错与引擎现状矛盾。
// 本套件钉住：NTLM 解禁后的凭据解析形态与引擎 ntlmHandshake.cred() 的约定一致
// （auth.type='ntlm' 时读 auth.basic，domain 可选）。
// ============================================================================

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAuth, buildAuth } from '../bin/cli/args.js';

describe('[cli.auth] parseAuth 三种 scheme', () => {
  test('basic：user:pass → { basic: { username, password } }', () => {
    assert.deepEqual(parseAuth('admin:s3cret', 'basic'), {
      basic: { username: 'admin', password: 's3cret' },
    });
  });

  test('digest：→ { digest: {...} }（RFC 7616 挑战-响应，行为不变）', () => {
    assert.deepEqual(parseAuth('admin:s3cret', 'digest'), {
      digest: { username: 'admin', password: 's3cret' },
    });
  });

  test('ntlm：DOMAIN\\user:pass → basic 承载 + domain 剥离（sqlmap --auth-cred 形态）', () => {
    const pa = parseAuth('CORP\\john:hunter2', 'ntlm');
    assert.deepEqual(pa, {
      basic: { username: 'john', password: 'hunter2', domain: 'CORP' },
    });
  });

  test('ntlm：无域（user:pass）→ domain 不设置', () => {
    const pa = parseAuth('john:hunter2', 'ntlm');
    assert.deepEqual(pa, { basic: { username: 'john', password: 'hunter2' } });
    assert.equal('domain' in pa.basic, false);
  });

  test('ntlm：密码里含 \\ 不影响（域剥离只认第一个反斜杠前的段）', () => {
    const pa = parseAuth('CORP\\john:pa\\ss', 'ntlm');
    assert.equal(pa.basic.username, 'john');
    assert.equal(pa.basic.password, 'pa\\ss');
    assert.equal(pa.basic.domain, 'CORP');
  });

  test('ntlm：无冒号 → 密码空串（与 basic 同语义）', () => {
    assert.deepEqual(parseAuth('CORP\\john', 'ntlm'), {
      basic: { username: 'john', password: '', domain: 'CORP' },
    });
  });

  test('pki / 未知 scheme 维持 unsupported（客户端证书走 --client-cert）', () => {
    assert.deepEqual(parseAuth('x:y', 'pki'), { unsupported: true, type: 'pki' });
    assert.deepEqual(parseAuth('x:y', 'kerberos'), { unsupported: true, type: 'kerberos' });
  });

  test('空凭据串 → undefined（与既有语义一致，不抛错）', () => {
    assert.equal(parseAuth('', 'ntlm'), undefined);
  });
});

describe('[cli.auth] buildAuth 组装', () => {
  test('--auth-type NTLM + --auth "CORP\\john:hunter2" → { type:\'ntlm\', basic:{...} }', () => {
    const auth = buildAuth({ auth: 'CORP\\john:hunter2', authType: 'NTLM' });
    // 这个形态与 ntlmHandshake.cred() 的约定一致（auth.type==='ntlm' ? auth.basic），
    // 且与 e2e/ntlm-lab 真机验证的 auth 形状相同
    assert.equal(auth.type, 'ntlm');
    assert.deepEqual(auth.basic, { username: 'john', password: 'hunter2', domain: 'CORP' });
  });

  test('NTLM 与 --cookie 共存（会话 + 挑战响应可叠加）', () => {
    const auth = buildAuth({ cookie: 'SID=x', auth: 'CORP\\john:hunter2', authType: 'ntlm' });
    assert.equal(auth.cookie, 'SID=x');
    assert.equal(auth.type, 'ntlm');
    assert.equal(auth.basic.username, 'john');
  });

  test('PKI 仍拒绝且报错文本更新（不再声称 NTLM 未实现）', () => {
    assert.throws(
      () => buildAuth({ auth: 'x:y', authType: 'pki' }),
      (e) => /--client-cert/.test(e.message) && !/NTLM 需 Type1-3 协商未实现/.test(e.message)
    );
  });

  test('--auth-type ntlm 但未给 --auth：不产 auth（与 basic 同语义，不抛错）', () => {
    assert.equal(buildAuth({ authType: 'ntlm' }), undefined);
  });
});
