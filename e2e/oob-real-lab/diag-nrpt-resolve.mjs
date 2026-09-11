// 诊断：系统解析器 NRPT 链路验证（与 mysqld 同路径）
// 接收端监听 53 → Resolve-DnsName/ping 查询 *.ooblab.test → 应被 NRPT 路由到 127.0.0.1
// 若接收端捕获到 token → NRPT 单播路由生效；否则 .test 后缀另有解析路径问题
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const { oobReceiver } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/core/oobReceiver.js')).href);

await oobReceiver.start({
  enabled: true,
  callbackBase: '127.0.0.1:8899',
  httpPort: 8899,
  timeoutMs: 5000,
  dnsOob: true,
  dnsDomain: 'ooblab.test',
  dnsPort: 53,
});
console.log('接收端已监听 53（域名 ooblab.test）');

// 用 ping 触发系统解析器（mysqld UNC 解析同路径：getaddrinfo）
let pingOut = '';
try {
  pingOut = execFileSync('ping', ['-n', '1', '-w', '2000', 'sysresolv01.ooblab.test'], { encoding: 'utf8', timeout: 15000 });
} catch (e) {
  pingOut = String(e.stdout || e.message || '');
}
console.log('ping 输出（截断）:', pingOut.replace(/\n/g, ' ').slice(0, 150));

const hit = await oobReceiver.waitForToken('sysresolv01', 3000);
console.log(`接收端捕获 sysresolv01: ${hit ? '✅ NRPT 单播路由生效（mysqld 同路径可达）' : '❌ 未捕获（系统解析器未走 NRPT/53）'}`);
process.exit(hit ? 0 : 1);
