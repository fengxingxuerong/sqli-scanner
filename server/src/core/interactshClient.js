// ============================================================================
// interactshClient.js —— 外部 OOB 隧道（对标 interactsh / Burp Collaborator）
//
// ── 为什么必须有这个文件（[D87] 2026-10-18）──────────────────────────────────
// 补的是**实战一线缺口 P1-3**（TODO.md 2026-10-10 缺口盘点）：
//   「OOB 通道在真实目标上拿不到 —— oobReceiver 默认绑 127.0.0.1、DNS 需自建域+占 53；
//    无 interactsh/Collaborator 对接」
// 症状是**静默假阴性**：无回显盲注（OOB 是唯一可达通道）在真实目标上永远不会命中，
// 报告照常落成「未检出」——与「这个站没有注入」长得一模一样。
//
// 内置 oobReceiver 只能监听本机，要求「目标能回连到扫描器」。真实授权测试里目标多在
// 别的网段/有 NAT，这条回连路径通常不通。interactsh 模式改为：**扫描器主动轮询**公共
// （或自建）协作端的回连记录，目标只要能出站访问公网即可，不要求任何入站可达。
//
// ── 协议实现说明（零依赖，只用 Node 内置 crypto/fetch）──────────────────────
// 引擎纪律：**不加运行时 npm 依赖**（AGENTS.md §3）。故此处手写 interactsh 协议：
//   · 注册：POST /register {public-key, secret-key, correlation-id}
//     public-key = RSA-2048 SPKI PEM 的 base64（**明文**，非加密——上游
//     encodeRegistrationRequest 只做 JSON marshal，见 client.go）
//   · 轮询：GET /poll?id=<corr>&secret=<secret> → {aes_key, data[]}
//   · 解密：aes_key 用 RSA-OAEP(SHA-256) 解出 32 字节 AES key；
//     data 项 = base64(IV(16) ‖ AES-256-CTR 密文)（上游 decryptMessage）
//   · 注销：POST /deregister
//
// ── ⚠️ 域名长度硬约束（本文件最重要的坑，2026-10-18 用受控实验实测确认）──────
// 回调域名 = `<correlationID><nonce>.<server>`，且**首标签长度必须 ≥ 33**
// （correlationID 20 + nonce ≥ 13，即上游 CorrelationIdLength/NonceLength 默认值）。
// 实测（同一注册会话内逐档递增，唯一变量为首标签长度）：
//   首标签 20 / 26 / 31 / 32 字符 → 服务端滑窗匹配不到 → poll 恒为空（6 轮内）
//   首标签 33 / 34 / 36 字符      → 稳定命中
// 服务端 DNS 侧用 `SlideWithLength(chunk, GetIdLength())` 在标签上滑窗找 correlationID，
// 长度不足时窗口根本落不下。**不过这道坎会表现为「回连偶发成功」**——本文件最初版本
// 用固定 20 字符首位标签，探针时而成功时而失败，极易被误判成「公共服务器限流」。
// 故：nonce 长度取 13（上游默认），并在 _buildCallbackDomain 处硬校验，短于阈值直接抛错，
// 绝不静默降级为「短域名 + 侥幸成功」。
//
// ── 安全边界 ────────────────────────────────────────────────────────────────
// · 默认**关闭**（oob.interactsh.enabled 缺省 false）：开启即对外发带外请求，属授权范围内行为。
// · 公共协作端（oast.*）会把回连记录交给其运营方——**真实项目建议自建**，文档已写明。
// · token 归因：命中判定要求回连记录的 full-id **以 correlationID+nonce 开头且含本次 token**，
//   避免把同一协作端上其它会话/其它工具的流量误认成自己的命中（防误报）。
// ============================================================================

import crypto from 'node:crypto';
import { ErrorCode, AppError } from './errors.js';
import { logger } from './logger.js';

/** 上游默认值（settings.CorrelationIdLengthDefault / CorrelationIdNonceLengthDefault） */
const CORR_ID_LENGTH = 20;
const NONCE_LENGTH = 13;
/** 首标签最小长度：短于此服务端无法滑窗匹配（实测阈值，见文件头） */
export const MIN_FIRST_LABEL_LENGTH = CORR_ID_LENGTH + NONCE_LENGTH;

/** 默认公共协作端（上游 DefaultOptions.ServerURL 子集，按可用性排序） */
export const DEFAULT_SERVERS = ['oast.pro', 'oast.live', 'oast.online'];

/**
 * token 归一化：**DNS 标签不区分大小写**，interactsh 服务端存下来的回连记录恒为小写。
 * 引擎的 token 是 nanoid（含大写）⇒ 两侧必须归一到同一形态，否则「隧道通了却恒不命中」。
 * 归一化只用于**比较与索引**，不改变对外展示的 token 语义。
 * @param {unknown} token
 * @returns {string}
 */
function normToken(token) {
  return String(token == null ? '' : token).toLowerCase();
}

/** 随机字母表：zbase32 子集（小写字母+数字），与上游 nonce 编码同族，避免 DNS 非法字符 */
const NONCE_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/**
 * 生成指定长度的随机 nonce（DNS 标签安全字符集）。
 * @param {number} len 长度
 * @returns {string}
 */
function randomNonce(len) {
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i += 1) out += NONCE_ALPHABET[bytes[i] % NONCE_ALPHABET.length];
  return out;
}

/**
 * AES-256-CTR 解密（IV 前置），key 为 32 字节原始密钥。
 * 与上游 decryptMessage 的 `iv := cipherText[:aes.BlockSize]` + `cipher.NewCTR` 语义一致。
 * @param {Buffer} key 32 字节 AES key
 * @param {string} secureMessage base64(IV ‖ ciphertext)
 * @returns {string} 明文
 */
export function decryptInteraction(key, secureMessage) {
  const cipherText = Buffer.from(secureMessage, 'base64');
  if (cipherText.length < 16) {
    throw new AppError(ErrorCode.INVALID_PARAM, 'interactsh 密文块过短（< 16 字节 IV）');
  }
  const iv = cipherText.subarray(0, 16);
  const body = cipherText.subarray(16);
  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
}

/**
 * 由 base64 的 aes_key 解出 32 字节 AES key（RSA-OAEP + SHA-256）。
 * @param {string} privateKeyPem RSA 私钥 PEM
 * @param {string} aesKeyB64 服务端返回的加密 key
 * @returns {Buffer} 32 字节 key
 */
export function unwrapAesKey(privateKeyPem, aesKeyB64) {
  return crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(aesKeyB64, 'base64')
  );
}

/**
 * 外部 OOB 隧道客户端（interactsh 协议）。
 *
 * 与内置 oobReceiver 的关系：**接口同形**（start/receive/waitForToken/isStarted/stop），
 * 因此检测器侧可用同一套调用，无需分支。差别只在回连来源：
 *   · oobReceiver：本地监听，等目标回连（要求目标能访问扫描器）
 *   · 本类：主动轮询协作端，取回连记录（只要求扫描器能出网）
 */
export class InteractshClient {
  constructor() {
    this._server = null;
    this._publicKeyPem = '';
    this._privateKeyPem = '';
    this._secret = '';
    this._correlationId = '';
    this._nonce = ''; // 本次会话的非ce，域名前缀 = correlationId + nonce
    /** @type {Map<string, number>} token → 收到时间（有上限，与 oobReceiver 同语义） */
    this._received = new Map();
    /** @type {Map<string, Set<{resolve:(v:any)=>void}>>} 等待者 */
    this._waiters = new Map();
    this._pollTimer = null;
    this._running = false;
    this._receivedMax = 10000;
  }

  /**
   * 启动：注册协作端并开始轮询。
   * @param {any} [cfg] interactsh 配置段（见 defaults.oob.interactsh）
   * @returns {Promise<void>}
   */
  async start(cfg = {}) {
    if (this._running) return;
    const servers = Array.isArray(cfg.servers) && cfg.servers.length
      ? cfg.servers
      : (typeof cfg.server === 'string' && cfg.server.trim() ? [cfg.server.trim()] : DEFAULT_SERVERS);
    const rawMax = Number(cfg.receivedMax);
    this._receivedMax = Number.isInteger(rawMax) && rawMax >= 100 ? rawMax : 10000;

    // 生成密钥材料（RSA-2048；上游同规格）
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    this._publicKeyPem = publicKey;
    this._privateKeyPem = privateKey;
    this._secret = crypto.randomBytes(16).toString('hex');
    this._correlationId = crypto.randomBytes(10).toString('hex').slice(0, CORR_ID_LENGTH);
    this._nonce = randomNonce(NONCE_LENGTH);

    // 逐服务器尝试注册（上游同语义：首个可用即用）
    let lastErr = null;
    for (const host of servers) {
      const base = /^https?:\/\//.test(host) ? host.replace(/\/$/, '') : `https://${host}`;
      try {
        await this._register(base);
        this._server = base;
        lastErr = null;
        break;
      } catch (err) {
        lastErr = err;
        logger.warn(`[interactsh] 注册失败（${base}）：${err.message}`);
      }
    }
    if (lastErr || !this._server) {
      throw new AppError(
        ErrorCode.OOB_RECEIVER_START_FAILED,
        `interactsh 注册失败（尝试 ${servers.length} 个协作端）：${lastErr ? lastErr.message : '无可用服务器'}`
      );
    }

    this._running = true;
    this._schedulePoll(cfg.pollIntervalMs);
    logger.info(
      `[interactsh] 已注册协作端 ${this._server}，回连域前缀 ${this._domainPrefix()}（域 ${this.callbackDomain()}）`
    );
  }

  /** 协作端域名前缀 = correlationId + nonce（长度已由构造保证 ≥33） */
  _domainPrefix() {
    return `${this._correlationId}${this._nonce}`;
  }

  /**
   * 本次可用于回连的域名（token 由调用方拼在**前缀之后、根域之前**）。
   * 形态：`<correlationId><nonce><token>.<server-host>` ——首标签含前缀故长度足够。
   * @returns {string} 例如 `ab12…cd34tok.en.oast.pro`
   */
  callbackDomain() {
    const host = String(this._server || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    return `${this._domainPrefix()}.${host}`;
  }

  /**
   * 为某个 token 生成完整回连主机名，并做长度硬校验。
   * @param {string} token 检测器生成的 token（nanoid）
   * @returns {string} 完整主机名
   */
  hostForToken(token) {
    const label = `${this._domainPrefix()}${normToken(token)}`;
    if (label.length < MIN_FIRST_LABEL_LENGTH) {
      // fail-fast：不静默降级为短域名（那会变成「偶发命中」的假能力）
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        `interactsh 首标签长度 ${label.length} < ${MIN_FIRST_LABEL_LENGTH}：服务端无法匹配 correlationID`
      );
    }
    const host = String(this._server || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    return `${label}.${host}`;
  }

  /** 拼出可供目标回连的 URL（http 形态）。 */
  callbackUrlForToken(token, scheme = 'http') {
    return `${scheme}://${this.hostForToken(token)}/oob`;
  }

  /** 协作端根域名（去掉前缀），供 UNC/裸主机类向量使用。 */
  bareHost() {
    return String(this._server || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  }

  async _register(base) {
    const body = JSON.stringify({
      'public-key': Buffer.from(this._publicKeyPem, 'utf8').toString('base64'),
      'secret-key': this._secret,
      'correlation-id': this._correlationId,
    });
    const res = await fetch(`${base}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
      const t = await res.text().catch(() => '');
      throw new AppError(ErrorCode.OOB_RECEIVER_START_FAILED, `register ${res.status} ${t.slice(0, 120)}`);
    }
  }

  _schedulePoll(intervalMs) {
    const ms = Number.isFinite(intervalMs) && intervalMs >= 500 ? intervalMs : 2000;
    const tick = async () => {
      if (!this._running) return;
      try {
        await this._pollOnce();
      } catch (err) {
        logger.debug(`[interactsh] poll 失败：${err.message}`);
      }
      if (this._running) this._pollTimer = setTimeout(tick, ms);
    };
    this._pollTimer = setTimeout(tick, ms);
  }

  async _pollOnce() {
    if (!this._server) return;
    const res = await fetch(
      `${this._server}/poll?id=${this._correlationId}&secret=${this._secret}`,
      { signal: AbortSignal.timeout(20000) }
    );
    if (!res.ok) return;
    /** @type {{aes_key?: string, data?: string[]}} */
    const payload = /** @type {any} */ (await res.json());
    const aesKey = payload && typeof payload.aes_key === 'string' ? payload.aes_key : '';
    const rawRows = payload ? payload.data : undefined;
    /** @type {string[]} */
    const rows = Array.isArray(rawRows) ? rawRows : [];
    if (!aesKey || rows.length === 0) return;

    let key;
    try {
      key = unwrapAesKey(this._privateKeyPem, aesKey);
    } catch (err) {
      logger.debug(`[interactsh] aes_key 解封失败：${err.message}`);
      return;
    }

    for (const row of rows) {
      let plain;
      try {
        plain = decryptInteraction(key, row).trim();
      } catch (err) {
        logger.debug(`[interactsh] 交互解密失败：${err.message}`);
        continue;
      }
      const token = this._extractToken(plain);
      if (token) this.receive(token);
    }
  }

  /**
   * 从解密后的交互记录里提取属于**本次会话**的 token。
   * 归因判据：full-id（或 host）必须以上述域前缀开头，剩余部分即 token。
   * 不满足归属的记录一律丢弃——防把同协作端上其它会话的流量认成自己的命中（误报面）。
   * @param {string} plain JSON 字符串
   * @returns {string|null}
   */
  _extractToken(plain) {
    let j;
    try {
      j = JSON.parse(plain);
    } catch {
      return null;
    }
    const candidates = [j['full-id'], j.host, j['remote-address']].filter((x) => typeof x === 'string');
    // ⚠️ 大小写归一化（2026-10-18 整链实测踩到）：DNS 标签不区分大小写，interactsh 服务端
    // 在 storeMatch 里对匹配到的部分做 `strings.ToLower` 后再存，回连记录的 full-id 因此
    // **恒为小写**；而引擎投放的 token 由 nanoid 生成，含大写字母。
    // 不归一化 ⇒ 大小写不一致 ⇒ 归因失败 ⇒ 命中恒为 0（实测：靶站真实回连 14 次、
    // 记录也确实进了协作端，但本地判据恒不成立，表现为「隧道通了却检不出」）。
    // 故两侧统一小写比较：前缀取小写，回连标签取小写，返回的 token 也取回原始大小写
    // （用 index 切原串，而非返回小写串——否则 _received 里存的 key 与被等待的 token 不一致）。
    const prefix = this._domainPrefix().toLowerCase();
    for (const cand of candidates) {
      const first = cand.split('.')[0];
      const lowerFirst = first.toLowerCase();
      if (lowerFirst.startsWith(prefix) && lowerFirst.length > prefix.length) {
        return normToken(first.slice(prefix.length));
      }
    }
    return null;
  }

  /** 记录 token 被回连（接口与 oobReceiver.receive 同形）。 */
  receive(token) {
    const key = normToken(token);
    if (!key) return;
    if (!this._received.has(key) && this._received.size >= this._receivedMax) {
      const oldest = this._received.keys().next().value;
      if (oldest !== undefined) this._received.delete(oldest);
    }
    this._received.set(key, Date.now());
    const ws = this._waiters.get(key);
    if (ws) {
      this._waiters.delete(key);
      for (const w of ws) w.resolve(true);
    }
  }

  /**
   * 等待某 token 被回连（接口与 oobReceiver.waitForToken 同形）。
   * 注：外部隧道是**轮询**取回，故等待窗口内可能需要跨多个 poll 周期；
   * 调用方给的 timeoutMs 需 ≥ pollIntervalMs * 2 才有意义（默认轮询 2s）。
   * @param {string} token
   * @param {number} timeoutMs
   * @returns {Promise<boolean>}
   */
  waitForToken(token, timeoutMs) {
    const key = normToken(token);
    if (!key) return Promise.resolve(false);
    if (this._received.has(key)) return Promise.resolve(true);
    return new Promise((resolve) => {
      const entry = {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
      };
      const timer = setTimeout(() => {
        const ws = this._waiters.get(key);
        if (ws) {
          ws.delete(entry);
          if (ws.size === 0) this._waiters.delete(key);
        }
        resolve(false);
      }, Number.isFinite(timeoutMs) ? timeoutMs : 5000);
      const set = this._waiters.get(key) || new Set();
      this._waiters.set(key, set);
      set.add(entry);
    });
  }

  isStarted() {
    return this._running && !!this._server;
  }

  async stop() {
    this._running = false;
    if (this._pollTimer) {
      clearTimeout(this._pollTimer);
      this._pollTimer = null;
    }
    if (this._server) {
      try {
        await fetch(`${this._server}/deregister`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 'correlation-id': this._correlationId, 'secret-key': this._secret }),
          signal: AbortSignal.timeout(10000),
        });
      } catch { /* 注销失败不影响本地状态 */ }
    }
    this._server = null;
    this._received.clear();
    this._waiters.clear();
  }
}

// 单例：与 oobReceiver 并列（谁是活跃隧道由 OobDetector 按配置选择）
export const interactshClient = new InteractshClient();
export default interactshClient;
