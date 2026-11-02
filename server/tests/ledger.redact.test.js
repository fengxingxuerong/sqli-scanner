// [P0-SEC 2026-11-02] 台账落盘脱敏守门测试：
// 真实文件系统 + 真实 recordScan，确保 report.json / poc/*.txt / meta.json / index.jsonl
// 都不含 auth/proxy/Cookie/Authorization 明文。不 mock fs —— 这类缺陷只在落盘层暴露。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const scanLedger = await import('../src/services/scanLedger.js');

function withLedger(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-redact-'));
  const prev = process.env.SQLI_LEDGER_DIR;
  process.env.SQLI_LEDGER_DIR = dir;
  try {
    return fn(dir);
  } finally {
    if (prev === undefined) delete process.env.SQLI_LEDGER_DIR;
    else process.env.SQLI_LEDGER_DIR = prev;
    rmSync(dir, { recursive: true, force: true });
  }
}

/** 构造一份「凭据齐全」的报告：target auth/proxy/cookie/header + PoC Cookie/Authorization。 */
function dirtyReport() {
  return {
    scanId: 'led-s1',
    target: {
      baseUrl: 'http://user:pass@target.example/items?id=1',
      method: 'GET',
      config: {
        auth: { basic: { username: 'alice', password: 'basic-secret' } },
        proxy: 'http://proxy:proxy-secret@127.0.0.1:8080',
        login: { url: 'http://target.example/login', username: 'alice', password: 'login-secret' },
        clientCert: '/tmp/client-secret.pem',
        pocRedactAuth: false,
      },
      cookieParams: { sid: 'cookie-secret' },
      headerParams: { Authorization: 'Bearer header-secret' },
    },
    vulns: [{
      id: 'v1',
      pointId: 'p1',
      technique: 'union',
      riskLevel: 'High',
      payloads: ["1 UNION SELECT 'SQLISCANNER'-- -"],
      poc: {
        method: 'GET',
        url: 'http://target.example/items?id=1',
        headers: { Cookie: 'sid=cookie-secret', Authorization: 'Bearer poc-secret' },
        body: '',
        curl: "curl -H 'Cookie: sid=cookie-secret' -H 'Authorization: Bearer poc-secret' 'http://target.example/items?id=1'",
        raw: 'GET /items?id=1 HTTP/1.1\r\nCookie: sid=cookie-secret\r\nAuthorization: Bearer poc-secret\r\n\r\n',
      },
    }],
    points: [{ id: 'p1' }],
    summary: { verdict: 'vulnerability_detected' },
  };
}

function readAllFiles(dir) {
  const out = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) out.push(...readAllFiles(p));
    else if (ent.isFile()) out.push({ path: p, text: readFileSync(p, 'utf8') });
  }
  return out;
}

test('recordScan：report.json / poc / meta / index 不含凭据明文', () => {
  withLedger((dir) => {
    const rec = scanLedger.recordScan(dirtyReport());
    const files = readAllFiles(join(dir, rec.scanId));
    assert.ok(files.some((f) => f.path.endsWith('report.json')));
    assert.ok(files.some((f) => f.path.includes(`${join('poc')}`)) || files.some((f) => f.path.includes('/poc/') || f.path.includes('\\poc\\')));
    for (const f of files) {
      for (const secret of ['basic-secret', 'proxy-secret', 'login-secret', 'cookie-secret', 'header-secret', 'poc-secret']) {
        assert.equal(
          f.text.includes(secret),
          false,
          `${f.path} 仍含凭据明文 ${secret}`,
        );
      }
    }
    const idx = readFileSync(join(dir, 'index.jsonl'), 'utf8');
    assert.equal(idx.includes('user:pass@'), false, 'index.jsonl 的 target URL 仍含内嵌凭据');
  });
});

test('recordScan：调用方预渲染的 docs.json 也会被解析后脱敏', () => {
  withLedger((dir) => {
    const rec = scanLedger.recordScan(dirtyReport(), { json: JSON.stringify(dirtyReport()) });
    const saved = JSON.parse(readFileSync(join(dir, rec.scanId, 'report.json'), 'utf8'));
    assert.equal(JSON.stringify(saved).includes('basic-secret'), false);
    assert.equal(saved.target.config.auth, null);
    assert.equal('cookieParams' in saved.target, false);
  });
});

test('redactPocText：裸 Cookie/Set-Cookie 头与 URL 凭据都被打码', async () => {
  const { redactPocText } = await import('../src/services/reportRedaction.js');
  const s = redactPocText('Cookie: sid=abc\nSet-Cookie: x=1\nurl=http://u:p@h/');
  assert.equal(s.includes('sid=abc'), false);
  assert.equal(s.includes('http://u:p@h'), false);
});
