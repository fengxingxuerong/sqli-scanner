// 诊断：旁路 UDP 监听，抓 nslookup 实际发出的 DNS 报文（qname 标签 / qtype / 头部标志）
import dgram from 'node:dgram';
import { execFile } from 'node:child_process';

const PORT = 5334;
const sock = dgram.createSocket('udp4');
const seen = [];

sock.on('message', (msg, rinfo) => {
  // 解析
  const id = msg.readUInt16BE(0);
  const flags = msg.readUInt16BE(2);
  const qd = msg.readUInt16BE(4);
  let offset = 12;
  const labels = [];
  while (offset < msg.length) {
    const len = msg[offset];
    if (len === 0) { offset += 1; break; }
    if ((len & 0xc0) === 0xc0) { offset += 2; break; }
    if (offset + 1 + len > msg.length) break;
    labels.push(msg.toString('utf8', offset + 1, offset + 1 + len));
    offset += 1 + len;
  }
  let qtype = null;
  if (offset + 4 <= msg.length) qtype = msg.readUInt16BE(offset);
  seen.push({ id, flags: '0x' + flags.toString(16), qd, labels, qtype, len: msg.length, hex: msg.toString('hex').slice(0, 80) });
  console.log(`收到: qd=${qd} labels=${JSON.stringify(labels)} qtype=${qtype} len=${msg.length}`);
  // 回一个极简响应让 nslookup 快速退出
  const resp = Buffer.from(msg);
  resp.writeUInt16BE((id & 0xffff), 0);
  resp.writeUInt16BE(0x8180, 2); // QR+RD+RA
  sock.send(resp, rinfo.port, rinfo.address);
});

sock.bind(PORT, '127.0.0.1', () => {
  console.log(`旁路监听 127.0.0.1:${PORT}`);
  execFile('nslookup', ['-port=' + PORT, 'probenslk02.oob-lab.local', '127.0.0.1'], { timeout: 8000 }, (e, so, se) => {
    console.log('--- nslookup stdout ---');
    console.log(String(so || '').slice(0, 400));
    if (se) console.log('--- stderr ---');
    if (se) console.log(String(se).slice(0, 200));
    setTimeout(() => {
      console.log(`共捕获 ${seen.length} 个报文`);
      process.exit(0);
    }, 300);
  });
});
