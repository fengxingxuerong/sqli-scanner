// ============================================================================
// oobTunnel.js —— OOB 隧道选择器（[D87] 2026-10-18）
//
// 存在的理由：带外通道有**两种回连拓扑**，检测器不该各自判断该用哪条：
//   · local      —— 内置 oobReceiver 本地监听 HTTP(UDP DNS)，**要求目标能回连扫描器**
//                    （同网段/内网授权测试可用；NAT、跨网段、云上目标通常不通）
//   · interactsh —— 外部协作端隧道，**只要求扫描器能出网**：把回连地址指向协作端域名，
//                    扫描器主动 poll 取回连记录。补 P1-3 缺口（真实目标上 OOB 拿不到）。
//
// 设计取舍：对外暴露 **receive / waitForToken / isStarted / start / stop** 与 oobReceiver
// 逐字同形，并把「回调地址怎么拼」收进 resolveAddresses()——检测器因此**零分支**：
// 它只问隧道要地址、等 token，不需要知道背后是本地监听还是外部轮询。
//
// 默认行为不变：oob.interactsh.enabled 缺省 false ⇒ 仍走本地 oobReceiver（零行为漂移）。
// ============================================================================

import { oobReceiver } from './oobReceiver.js';
import { interactshClient } from './interactshClient.js';

/**
 * 本地模式下从 callbackBase 派生 UNC 路径（原 OobDetector.deriveUncPath 语义，逐字保留）。
 * @param {string} callbackBase 回连基址（可含 scheme/端口）
 * @param {string} token 检测器 token
 * @returns {string} UNC 路径
 */
export function deriveUncPath(callbackBase, token) {
  const bareHost = String(callbackBase || '')
    .replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '') // 剥 scheme
    .split('/')[0] // 剥路径
    .replace(/:\d+$/, '') // 剥端口
    .trim();
  return `${bareHost}\\oob\\${token}`;
}

class OobTunnel {
  constructor() {
    /** @type {null | typeof oobReceiver | typeof interactshClient} */
    this._client = null;
    /** @type {'local'|'interactsh'|null} */
    this._mode = null;
  }

  /**
   * 当前模式（未启动为 null），供检测器/报告标注使用。
   * @returns {'local'|'interactsh'|null}
   */
  get mode() {
    return this._mode;
  }

  /**
   * 按配置启动隧道（幂等：同一模式重复 start 由底层客户端自行短路）。
   * @param {any} cfg oob 配置段
   * @returns {Promise<void>}
   */
  async start(cfg) {
    const inter = cfg && cfg.interactsh;
    if (inter && inter.enabled === true) {
      await interactshClient.start(inter);
      this._client = interactshClient;
      this._mode = 'interactsh';
      return;
    }
    await oobReceiver.start(cfg);
    this._client = oobReceiver;
    this._mode = 'local';
  }

  /**
   * 当前活跃的隧道客户端。
   *
   * ⚠️ 为什么要有「委托回退」而不是只认 this._client（2026-10-18 实测踩到）：
   * 既有测试与部分调用方会**直接** `oobReceiver.start(cfg)`（不经隧道）。若检测器只认
   * `this._client`，这些路径下 `isStarted()` 恒 false ⇒ 检测器抛 OOB_DISABLED ⇒
   * 用例挂死（实测 oobDetector.test.js / oobDetector.dns.test.js 双双超时）。
   * 这正是本仓最忌讳的形状：**同一件事两个入口各记各的状态**。
   * 修法：本地接收端被直接启动时，隧道**委托**给它 —— 检测器始终只问隧道一个入口，
   * 而既有直连用法零回归。
   * @returns {null | typeof oobReceiver | typeof interactshClient}
   */
  _active() {
    if (this._client && this._client.isStarted()) return this._client;
    // 委托：外部隧道未启动但本地接收端在跑（直连用法/测试）
    if (oobReceiver.isStarted()) return oobReceiver;
    return null;
  }

  /**
   * 隧道是否已就绪（活跃客户端存在）。
   * @returns {boolean}
   */
  isStarted() {
    return !!this._active();
  }

  /**
   * 转发回连记录到活跃客户端。
   * @param {string} token 回连 token
   * @returns {void}
   */
  receive(token) {
    const c = this._active();
    if (c) c.receive(token);
  }

  /**
   * 等待某 token 被回连（转发到活跃客户端）。
   * @param {string} token 检测器 token
   * @param {number} timeoutMs 等待窗口
   * @returns {Promise<boolean>} 是否在窗口内收到回连
   */
  waitForToken(token, timeoutMs) {
    const c = this._active();
    return c ? c.waitForToken(token, timeoutMs) : Promise.resolve(false);
  }

  /**
   * 停止两条隧道（可能切换过模式），任一失败不影响另一条。
   * @returns {Promise<void>}
   */
  async stop() {
    // 两条通道都收（可能切换过模式），任一失败不影响另一条
    try { await interactshClient.stop(); } catch { /* ignore */ }
    try { await oobReceiver.stop(); } catch { /* ignore */ }
    this._client = null;
    this._mode = null;
  }

  /**
   * 为 token 解析出该填进 payload 的回连地址。
   * @param {string} token
   * @param {any} oobCfg oob 配置段（本地模式的 httpPort/callbackBase 由它派生）
   * @returns {{http:string, unc:string, host:string, mode:'local'|'interactsh'}}
   */
  resolveAddresses(token, oobCfg) {
    const cfg = oobCfg || {};
    const active = this._active();
    // interactsh 模式（或外部隧道已启动）走协作端域名
    if (this._mode === 'interactsh' || active === interactshClient) {
      const host = interactshClient.hostForToken(token);
      return {
        // http 回连走协作端；UNC/SMB 向量用同一主机名（token 在标签里，经 DNS 归因）
        http: `http://${host}/oob`,
        unc: `${host}\\oob\\x`,
        host,
        mode: 'interactsh',
      };
    }
    // 本地模式：未显式配 callbackBase 时按接收端 httpPort 派生（P2-13 原语义，避免回连打到旧端口）
    const httpPort = Number(cfg.httpPort);
    const callbackBase =
      typeof cfg.callbackBase === 'string' && cfg.callbackBase.trim() !== ''
        ? cfg.callbackBase
        : Number.isFinite(httpPort) && httpPort > 0
          ? `127.0.0.1:${httpPort}`
          : '127.0.0.1:8899';
    return {
      http: `${callbackBase}/oob/${token}`,
      unc: deriveUncPath(callbackBase, token),
      host: callbackBase,
      mode: 'local',
    };
  }
}

// 单例：全应用共享（与 oobReceiver 同一治理方式）
export const oobTunnel = new OobTunnel();
export default oobTunnel;
