// DNS OOB 接收端单元测试
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { oobReceiver } from '../src/core/oobReceiver.js';

// 构造 DNS 查询报文（A 记录，QNAME 格式）
function buildDnsQuery(qname, id = 12345) {
  const labels = qname.split('.');
  const buf = Buffer.alloc(512);
  let offset = 0;

  // 头部
  buf.writeUInt16BE(id, offset); offset += 2; // ID
  buf.writeUInt16BE(0x0100, offset); offset += 2; // 标志：标准查询 + RD
  buf.writeUInt16BE(1, offset); offset += 2; // QDCOUNT
  buf.writeUInt16BE(0, offset); offset += 2; // ANCOUNT
  buf.writeUInt16BE(0, offset); offset += 2; // NSCOUNT
  buf.writeUInt16BE(0, offset); offset += 2; // ARCOUNT

  // QNAME（长度前缀标签序列）
  for (const label of labels) {
    buf.writeUInt8(label.length, offset); offset += 1;
    buf.write(label, offset, 'utf8'); offset += label.length;
  }
  buf.writeUInt8(0, offset); offset += 1; // 根标签

  // QTYPE = A (1), QCLASS = IN (1)
  buf.writeUInt16BE(1, offset); offset += 2;
  buf.writeUInt16BE(1, offset); offset += 2;

  return buf.slice(0, offset);
}

// 解析 DNS 响应提取 NXDOMAIN 标志
function isNxdomain(response) {
  if (!response || response.length < 4) return false;
  const flags = response.readUInt16BE(2);
  return (flags & 0x000F) === 0x0003; // RCODE = 3 (NXDOMAIN)
}

// 测试用固定 DNS 端口（与 HTTP 端口不同端口，但 UDP 与 TCP 可同端口）
// （HTTP 与 DNS 共用 18899，见 start 调用）

test('DNS OOB 接收端启动：HTTP 接收端先启动，DNS 接收端跟随启动', async () => {
  await oobReceiver.start({ httpPort: 18899, dnsPort: 18899, dnsDomain: 'test.local' });
  assert.ok(oobReceiver.isStarted());
});

test('DNS OOB 收到查询并提取 token：解析子域名中的 token', async () => {
  // 通过 UDP 发送 DNS 查询到接收端
  const token = 'testtoken123';
  const query = buildDnsQuery(`${token}.test.local`);
  const socket = dgram.createSocket('udp4');

  await new Promise((resolve, reject) => {
    // 先注册等待 token
    const waitPromise = oobReceiver.waitForToken(token, 3000);
    // 发送 DNS 查询
    socket.send(query, 0, query.length, 18899, '127.0.0.1', (err) => {
      if (err) reject(err);
    });
    // 等待 token 被接收
    waitPromise.then((hit) => {
      try {
        assert.ok(hit, 'DNS OOB token 应被接收');
        socket.close();
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

test('DNS OOB 返回 NXDOMAIN 响应', async () => {
  const token = 'testtoken456';
  const query = buildDnsQuery(`${token}.test.local`, 45678);
  const socket = dgram.createSocket('udp4');

  const response = await new Promise((resolve, reject) => {
    socket.once('message', (msg) => {
      resolve(msg);
    });
    socket.send(query, 0, query.length, 18899, '127.0.0.1', (err) => {
      if (err) reject(err);
    });
    // 超时机制
    setTimeout(() => resolve(null), 2000);
  });

  assert.ok(response, '应收到 DNS 响应');
  assert.ok(isNxdomain(response), '响应应为 NXDOMAIN');
  socket.close();
});

test('DNS OOB 忽略系统查询（_ 前缀）', async () => {
  const token = '_acme-challenge';
  const query = buildDnsQuery(`${token}.test.local`);
  const socket = dgram.createSocket('udp4');

  await new Promise((resolve) => {
    const waitPromise = oobReceiver.waitForToken(token, 1500);
    socket.send(query, 0, query.length, 18899, '127.0.0.1', () => {
      waitPromise.then((hit) => {
        assert.ok(!hit, '系统查询不应被接收为 token');
        socket.close();
        resolve();
      });
    });
  });
});

test('DNS OOB 不处理非 A/AAAA 查询', async () => {
  const token = 'mxquery';
  const query = buildDnsQuery(`${token}.test.local`);
  // 修改 QTYPE 为 MX (15)
  const mxQuery = Buffer.concat([
    query.slice(0, query.length - 4),
    Buffer.from([0x00, 0x0f, 0x00, 0x01]), // QTYPE=MX, QCLASS=IN
  ]);
  const socket = dgram.createSocket('udp4');

  await new Promise((resolve) => {
    const waitPromise = oobReceiver.waitForToken(token, 1500);
    socket.send(mxQuery, 0, mxQuery.length, 18899, '127.0.0.1', () => {
      waitPromise.then((hit) => {
        assert.ok(!hit, 'MX 查询不应被接收');
        socket.close();
        resolve();
      });
    });
  });
});

after(async () => {
  await oobReceiver.stop();
});