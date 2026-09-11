// 诊断 v2：双端口旁路监听（53 + 5334），确认 Windows nslookup 单次查询模式实际发往哪个端口
import dgram from 'node:dgram';
import { execFile } from 'node:child_process';

const hits = { 53: 0, 5334: 0 };
const sockets = [];

function bind(port) {
  return new Promise((res) => {
    const s = dgram.createSocket('udp4');
    s.on('message', (msg, rinfo) => {
      hits[port]++;
      const labels = [];
      let off = 12;
      while (off < msg.length) {
        const len = msg[off];
        if (len === 0) break;
        if ((len & 0xc0) === 0xc0) break;
        if (off + 1 + len > msg.length) break;
        labels.push(msg.toString('utf8', off + 1, off + 1 + len));
        off += 1 + len;
      }
      console.log(`[port ${port}] 收到查询: labels=${JSON.stringify(labels)} len=${msg.length}`);
    });
    s.bind(port, '0.0.0.0', () => { sockets.push(s); res(); });
  });
}

await bind(53);
await bind(5334);
console.log('双端口旁路监听就绪（53 + 5334）');

execFile('nslookup', ['-port=5334', 'portcheck01.oob-lab.local', '127.0.0.1'], { timeout: 10000 }, (e, so, se) => {
  console.log('--- nslookup 输出 ---');
  console.log(String(so || se || '').slice(0, 300));
  setTimeout(() => {
    console.log(`\n结论：port53=${hits[53]} 个报文，port5334=${hits[5334]} 个报文`);
    console.log(hits[53] > 0 && hits[5334] === 0
      ? '→ 证实：Windows nslookup 单次查询模式忽略 -port= 参数（发往默认 53）'
      : hits[5334] > 0
        ? '→ -port= 生效（此前接收端侧另有原因）'
        : '→ 两端口均无报文（另有原因，需抓包）');
    sockets.forEach((s) => s.close());
    process.exit(0);
  }, 500);
});
