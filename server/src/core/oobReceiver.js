import http from 'node:http';
import { ErrorCode, AppError } from './errors.js';
import { logger } from './logger.js';

// OOB 带外接收端（独立 HTTP 服务，单例 oobReceiver）
// 与引擎主应用（Express，端口 4567）解耦：自带独立端口监听 GET /oob/:token。
// 当目标 DBMS 执行了带外回调（DNS/SMB/HTTP），本端收到 /oob/:token 即唤醒等待者，
// 从而确认"无回显注入"存在。真实环境需自有域名 + 权威 NS（DNS）或 SMB 共享，
// 本实现以本地 HTTP 接收端为可测落点；测试可直接调用 receive(token) 模拟回连。
class OobReceiver {
  constructor() {
    this._server = null; // http.Server 实例
    this._listening = false; // 是否已成功监听
    this._port = null; // 当前监听端口
    this._config = null; // 最近一次 start 的配置
    // 引用计数：并发扫描共享同一接收端，start 时 +1、stop 时 -1，归零才真正关闭。
    // 解决"扫描 A 结束后 stop 误杀正在用的扫描 B 接收端"的并发问题。
    this._refCount = 0;
    // token -> { resolve }：waitForToken 注册的唤醒函数
    this._waiters = new Map();
    // 已收到的 token 集合（迟到/重复回调也能判定命中）
    this._received = new Set();
  }

  /**
   * 启动监听（幂等：已在同一端口监听则 no-op，仅引用计数 +1，不重复起服务）。
   * 并发扫描共享同一端口接收端；若已监听**其他端口**则明确抛错（一个进程只应有一个接收端）。
   * @param {{callbackBase:string, httpPort:number, timeoutMs:number}} oobConfig
   * @returns {Promise<void>}
   */
  async start(oobConfig) {
    const port = oobConfig && Number(oobConfig.httpPort);
    if (!Number.isFinite(port) || port <= 0) {
      throw new AppError(ErrorCode.INVALID_PARAM, 'oob 接收端端口非法');
    }
    // 幂等：已监听且端口一致，引用计数 +1 后直接返回
    if (this._listening && this._server && this._port === port) {
      this._refCount += 1;
      return;
    }
    // 已监听但端口不一致：明确拒绝（避免第二个 server 覆盖引用导致泄漏）
    if (this._listening && this._server) {
      throw new AppError(
        ErrorCode.OOB_RECEIVER_START_FAILED,
        `OOB 接收端已在端口 ${this._port} 监听，无法切换到 ${port}（并发扫描共享同一接收端）`
      );
    }
    const server = http.createServer((req, res) => this._handle(req, res));
    this._server = server;
    this._config = oobConfig;
    this._port = port;
    this._refCount += 1;
    return new Promise((resolve, reject) => {
      server.once('error', (err) => {
        this._listening = false;
        this._refCount = Math.max(0, this._refCount - 1);
        logger.error(`OOB 接收端启动失败：${err.message}`);
        reject(new AppError(ErrorCode.OOB_RECEIVER_START_FAILED, `OOB 接收端启动失败：${err.message}`));
      });
      server.listen(port, () => {
        this._listening = true;
        logger.info(`OOB 接收端已启动：监听端口 ${port}（引用计数 ${this._refCount}）`);
        resolve();
      });
    });
  }

  // 请求路由：仅 GET /oob/:token 视为带外回调
  _handle(req, res) {
    const url = (req.url || '').split('?')[0];
    const m = url.match(/^\/oob\/([^/]+)\/?$/);
    if (!m) {
      res.statusCode = 404;
      res.end('not found');
      return;
    }
    const token = decodeURIComponent(m[1]);
    this.receive(token);
    res.statusCode = 200;
    res.end('ok');
  }

  /**
   * 记录某 token 被接收，并唤醒其等待者（供真实回连或测试直接调用）。
   * @param {string} token
   */
  receive(token) {
    if (!token) return;
    this._received.add(token);
    const w = this._waiters.get(token);
    if (w) {
      this._waiters.delete(token);
      w.resolve(true);
    }
  }

  /**
   * 轮询等待某 token 被接收。
   * @param {string} token
   * @param {number} timeoutMs 超时（取 config.oob.timeoutMs）
   * @returns {Promise<boolean>} 收到 true / 超时 false
   */
  waitForToken(token, timeoutMs) {
    if (!token) return Promise.resolve(false);
    // 已收到（迟到回调）直接命中
    if (this._received.has(token)) return Promise.resolve(true);
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this._waiters.delete(token);
        resolve(false);
      }, Number.isFinite(timeoutMs) ? timeoutMs : 5000);
      this._waiters.set(token, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
      });
    });
  }

  // 是否已启动（供 OobDetector 检测前确认）
  isStarted() {
    return !!this._listening && !!this._server;
  }

  // 当前引用计数（供诊断/测试断言）
  refCount() {
    return this._refCount;
  }

  /**
   * 释放一次引用（与 start 配对）。引用计数归零时才真正关闭服务并清理状态。
   * 并发扫描各自调用 stop，不会误杀其他扫描正在使用的接收端。
   */
  stop() {
    this._refCount = Math.max(0, this._refCount - 1);
    if (this._refCount > 0) return; // 仍有扫描在使用，保持监听
    if (this._server) {
      try {
        this._server.close();
      } catch {
        /* 忽略关闭异常 */
      }
      this._server = null;
    }
    this._listening = false;
    this._port = null;
    this._waiters.clear();
    this._received.clear();
  }
}

// 单例：全应用（含扫描与测试）共享同一接收端
export const oobReceiver = new OobReceiver();
export default oobReceiver;
