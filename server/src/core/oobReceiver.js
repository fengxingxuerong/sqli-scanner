// ============================================================================
// patch/oobReceiver.js —— 安全加固版 OOB 带外接收端（HTTP + DNS 双通道）
// 基于 server/src/core/oobReceiver.js 修改，修复项：
//   [P1-2] 默认只绑定 127.0.0.1（与主引擎一致）；OOB_LISTEN_HOST 环境变量可显式放开
//   [P1-2] _received 改为有上限 LRU（默认 10,000 条，超出淘汰最旧）——防远程 flood 内存 DoS
//   [P1-2] 按来源 IP 令牌桶限速（默认 60 req/min，OOB_RATE_PER_MIN 可调）——防伪造命中/刷爆
//   [DNS] 新增 DNS OOB 通道：监听 UDP 53 端口，从子域名提取 token 并注册
// ============================================================================

import http from 'node:http';
import dgram from 'node:dgram';
import { ErrorCode, AppError } from './errors.js';
import { logger } from './logger.js';

// ── 加固配置 ────────────────────────────────────────────────────────────────
const LISTEN_HOST = process.env.OOB_LISTEN_HOST || '127.0.0.1';
const RECEIVED_MAX = (() => {
  const n = Number(process.env.OOB_RECEIVED_MAX);
  return Number.isInteger(n) && n >= 100 ? n : 10000;
})();
const PER_IP_RATE = (() => {
  const n = Number(process.env.OOB_RATE_PER_MIN);
  return Number.isFinite(n) && n >= 1 ? n : 60;
})();
// DNS OOB 配置
const DNS_PORT = (() => {
  const n = Number(process.env.OOB_DNS_PORT);
  return Number.isInteger(n) && n > 0 ? n : 53;
})();
const DNS_DOMAIN = process.env.OOB_DNS_DOMAIN || '';

// DNS 报文解析常量
const DNS_HEADER_SIZE = 12;

class OobReceiver {
  constructor() {
    this._server = null;       // HTTP server
    this._dnsServer = null;    // DNS UDP socket
    this._listening = false;
    this._port = null;
    this._config = null;
    this._waiters = new Map();
    // 已收到的 token：插入序 Map + 上限淘汰（LRU 语义）
    this._received = new Map();
    // 按来源 IP 的令牌桶：{ ip: { tokens, last } }
    this._ipBuckets = new Map();
    // P1: 互斥锁 — 序列化 start()/stop()，防并发 _stopAll 互相关闭对方服务器
    this._mutex = Promise.resolve();
  }

  // P1: 互斥锁辅助 — 串行化异步操作，防 start/stop 交叉执行
  _withLock(fn) {
    const next = this._mutex.then(() => fn());
    this._mutex = next.catch(() => {});
    return next;
  }

  // 来源 IP 限速
  _rateOk(ip) {
    const now = Date.now();
    const b = this._ipBuckets.get(ip) || { tokens: PER_IP_RATE, last: now };
    const elapsed = (now - b.last) / 60000;
    b.tokens = Math.min(PER_IP_RATE, b.tokens + elapsed * PER_IP_RATE);
    b.last = now;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    if (this._ipBuckets.size > 1024) {
      const oldest = this._ipBuckets.keys().next().value;
      if (oldest !== undefined) this._ipBuckets.delete(oldest);
    }
    return true;
  }

  async start(oobConfig) {
    // P1: 互斥锁 — 序列化并发 start() 调用，防 _stopAll 互相关闭对方服务器
    return this._withLock(() => this._doStart(oobConfig));
  }

  async _doStart(oobConfig) {
    const port = oobConfig && Number(oobConfig.httpPort);
    if (!Number.isFinite(port) || port <= 0) {
      throw new AppError(ErrorCode.INVALID_PARAM, 'oob 接收端端口非法');
    }
    // 如果已经启动且端口一致，跳过
    if (this._listening && this._server && this._port === port) {
      return;
    }
    // 关闭旧实例
    await this._stopAll();
    this._config = oobConfig;
    this._port = port;

    // 启动 HTTP 接收端
    await this._startHttp(port);
    // 启动 DNS 接收端
    await this._startDns();
  }

  async _startHttp(port) {
    const server = http.createServer((req, res) => this._handleHttp(req, res));
    this._server = server;
    return new Promise((resolve, reject) => {
      server.once('error', (err) => {
        this._listening = false;
        if (this._server === server) this._server = null;
        logger.error(`OOB HTTP 接收端启动失败：${err.message}`);
        reject(new AppError(ErrorCode.OOB_RECEIVER_START_FAILED, `OOB HTTP 接收端启动失败：${err.message}`));
      });
      server.listen(port, LISTEN_HOST, () => {
        this._listening = true;
        logger.info(`OOB HTTP 接收端已启动：监听 ${LISTEN_HOST}:${port}`);
        resolve();
      });
    });
  }

  async _startDns() {
    if (this._dnsServer) {
      try { this._dnsServer.close(); } catch { /* ignore */ }
      this._dnsServer = null;
    }
    // 优先使用 config 中的 dnsPort/dnsDomain，回退到环境变量
    const cfg = this._config || {};
    const dnsPort = (cfg.dnsPort != null && Number.isInteger(cfg.dnsPort) && cfg.dnsPort > 0)
      ? cfg.dnsPort : DNS_PORT;
    const dnsDomain = cfg.dnsDomain || DNS_DOMAIN;
    this._dnsDomain = dnsDomain; // [B-8] 供 _handleDns 校验 qname 归属
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this._dnsServer = socket;

    return new Promise((resolve, reject) => {
      socket.on('error', (err) => {
        logger.warn(`OOB DNS 接收端启动失败：${err.message}（DNS OOB 不可用，HTTP OOB 仍正常工作）`);
        this._dnsServer = null;
        resolve(); // 不阻断——HTTP OOB 仍正常工作
      });

      socket.on('message', (msg, rinfo) => {
        this._handleDns(msg, rinfo);
      });

      socket.on('listening', () => {
        const addr = socket.address();
        logger.info(`OOB DNS 接收端已启动：监听 ${LISTEN_HOST}:${addr.port}（已配置域名: ${dnsDomain || '未配置'})`);
        resolve();
      });

      try {
        socket.bind(dnsPort, LISTEN_HOST);
      } catch (err) {
        logger.warn(`OOB DNS 绑定端口 ${dnsPort} 失败：${err.message}（DNS OOB 不可用，HTTP OOB 仍正常工作）`);
        this._dnsServer = null;
        resolve();
      }
    });
  }

  async _stopAll() {
    if (this._server) {
      try { if (typeof this._server.closeAllConnections === 'function') this._server.closeAllConnections(); } catch { /* ignore */ }
      // 等待 close 回调完成，确保端口释放后再 start（防 EADDRINUSE）
      await new Promise((resolve) => {
        try { this._server.close(resolve); } catch { resolve(); }
      });
      this._server = null;
    }
    if (this._dnsServer) {
      try { this._dnsServer.close(); } catch { /* ignore */ }
      try { this._dnsServer.unref(); } catch { /* ignore */ }
      this._dnsServer = null;
    }
    this._listening = false;
    this._port = null;
  }

  // ── HTTP 请求处理 ──────────────────────────────────────────────────────
  _handleHttp(req, res) {
    const url = (req.url || '').split('?')[0];
    const m = url.match(/^\/oob\/([^/]+)\/?$/);
    if (!m) {
      res.statusCode = 404;
      res.end('not found');
      return;
    }
    const ip = (req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
    if (!this._rateOk(ip)) {
      res.statusCode = 429;
      res.end('too many requests');
      return;
    }
    // [安全修复] decodeURIComponent 对畸形百分号序列（如 /oob/%E0%A4%A）同步抛 URIError，
    // 未捕获会导致 uncaughtException 整进程退出（无认证 DoS）。必须包 try/catch 并校验白名单。
    let token;
    try {
      token = decodeURIComponent(m[1]);
    } catch {
      res.statusCode = 400;
      res.end('bad token');
      return;
    }
    // token 白名单：仅 URL-safe 字符且限长（合法 token 由 nanoid 生成，字母表即 A-Za-z0-9_-），
    // 同时封死超长 token 的内存面滥用。
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(token)) {
      res.statusCode = 400;
      res.end('bad token');
      return;
    }
    this.receive(token);
    res.statusCode = 200;
    res.end('ok');
  }

  // ── DNS 请求处理 ────────────────────────────────────────────────────────
  _handleDns(msg, rinfo) {
    // 来源 IP 限速
    const ip = rinfo.address.replace(/^::ffff:/, '');
    if (!this._rateOk(ip)) return;

    if (msg.length < DNS_HEADER_SIZE) return;

    try {
      // 解析 DNS 头部：提取 ID 和问题数
      const id = msg.readUInt16BE(0);
      const qr = (msg[2] & 0x80) !== 0; // 响应标志
      const qdcount = msg.readUInt16BE(4); // 问题数

      // 只处理查询（非响应）且有问题的报文
      if (qr || qdcount === 0) return;

      // 解析问题部分（QNAME 格式：长度前缀标签序列）
      let offset = DNS_HEADER_SIZE;
      let labels = [];

      while (offset < msg.length) {
        const len = msg[offset];
        if (len === 0) { offset += 1; break; } // 根标签
        // 处理压缩指针（0xC0 开头）
        if ((len & 0xC0) === 0xC0) {
          if (offset + 1 >= msg.length) return;
          // 压缩指针，不继续解析
          offset += 2;
          break;
        }
        if (offset + 1 + len > msg.length) return;
        const label = msg.toString('utf8', offset + 1, offset + 1 + len);
        labels.push(label);
        offset += 1 + len;
      }

      if (labels.length === 0) return;

      const qname = labels.join('.');
      const qtype = msg.readUInt16BE(offset); // 查询类型

      // 仅处理 A/AAAA 记录查询（其他类型如 MX/CNAME 可能来自其他工具）
      if (qtype !== 1 && qtype !== 28) return;

      // 从子域名提取 token：
      // 格式：token.domain.com → 第一个标签为 token
      // 或 token.attacker.com → 同
      const firstLabel = labels[0] || '';
      if (!firstLabel) return;

      // 过滤掉常见系统查询（如 _dnsauth, _acme-challenge 等）
      if (firstLabel.startsWith('_')) return;

      // [B-8] 校验 qname 归属：只接受以配置 dnsDomain 结尾的查询，
      // 防止非 OOB 流量的 DNS 查询（系统 DNS、其他工具）误触发 token 注册
      if (this._dnsDomain) {
        const suffix = this._dnsDomain.replace(/^\./, '');
        if (!qname.endsWith('.' + suffix) && qname !== suffix) return;
      }

      // 将子域名作为 token 注册
      logger.debug(`DNS OOB 收到查询：${qname} (${ip})`);
      this.receive(firstLabel);

      // 返回 NXDOMAIN 响应（目标不关心响应内容，只要发了查询即可）
      const response = this._buildDnsResponse(id, msg, labels.join('.'));
      if (response && this._dnsServer) {
        this._dnsServer.send(response, rinfo.port, rinfo.address, (err) => {
          if (err) logger.debug(`DNS 响应发送失败：${err.message}`);
        });
      }
    } catch (err) {
      logger.debug(`DNS 报文解析失败：${err.message}`);
    }
  }

  _buildDnsResponse(id, query, qname) {
    // 构造最小 DNS 响应（NXDOMAIN）
    const buf = Buffer.alloc(512);
    let offset = 0;

    // 头部（12 字节）
    buf.writeUInt16BE(id, offset); offset += 2; // 事务 ID
    buf.writeUInt16BE(0x8183, offset); offset += 2; // 标志：响应+标准查询+NXDOMAIN+RD+RA
    buf.writeUInt16BE(1, offset); offset += 2; // 问题数
    buf.writeUInt16BE(0, offset); offset += 2; // 回答数
    buf.writeUInt16BE(0, offset); offset += 2; // 权威数
    buf.writeUInt16BE(0, offset); offset += 2; // 附加数

    // 问题部分：复制原始查询的问题
    // 找到原始查询的 QNAME 起始位置（从头 12 字节开始）
    const qnameStart = DNS_HEADER_SIZE;
    const qnameEnd = query.indexOf(0, qnameStart); // 找到根标签的 0x00
    if (qnameEnd < 0 || qnameEnd + 5 > query.length) return null;

    // 复制 QNAME
    const qnameLen = qnameEnd - qnameStart + 1; // 包含末尾的 0x00
    query.copy(buf, offset, qnameStart, qnameEnd + 1);
    offset += qnameLen;

    // 复制 QTYPE 和 QCLASS
    buf.writeUInt16BE(query.readUInt16BE(qnameEnd + 1), offset); offset += 2; // QTYPE
    buf.writeUInt16BE(query.readUInt16BE(qnameEnd + 3), offset); offset += 2; // QCLASS

    return buf.slice(0, offset);
  }

  /**
   * 记录某 token 被接收，并唤醒其等待者。
   * 上限淘汰：超过 RECEIVED_MAX 时淘汰最旧 token。
   */
  receive(token) {
    if (!token) return;
    if (!this._received.has(token) && this._received.size >= RECEIVED_MAX) {
      const oldest = this._received.keys().next().value;
      if (oldest !== undefined) this._received.delete(oldest);
    }
    this._received.set(token, Date.now());
    const ws = this._waiters.get(token);
    if (ws) {
      this._waiters.delete(token);
      for (const w of ws) w.resolve(true);
    }
  }

  waitForToken(token, timeoutMs) {
    if (!token) return Promise.resolve(false);
    if (this._received.has(token)) return Promise.resolve(true);
    return new Promise((resolve) => {
      const entry = {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
      };
      const timer = setTimeout(() => {
        const ws = this._waiters.get(token);
        if (ws) {
          ws.delete(entry);
          if (ws.size === 0) this._waiters.delete(token);
        }
        resolve(false);
      }, Number.isFinite(timeoutMs) ? timeoutMs : 5000);
      if (!this._waiters.has(token)) this._waiters.set(token, new Set());
      this._waiters.get(token).add(entry);
    });
  }

  isStarted() {
    return !!this._listening && !!this._server;
  }

  async stop() {
    // P1: 互斥锁 — 防止 stop() 与 start() 交叉执行导致 _stopAll 互相关闭对方服务器
    return this._withLock(() => this._stopAll());
  }
}

// 单例：全应用（含扫描与测试）共享同一接收端
export const oobReceiver = new OobReceiver();
export default oobReceiver;