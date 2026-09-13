// ============================================================================
// ntlmHandshake.js —— NTLM 握手状态机（供 HttpClient 接线）
//
// 独立成文件的原因：httpClient.js 已是 1600+ 行的技术债（arch-guard 基线「只减不增」），
// NTLM 的状态管理若内联进去会再涨 120 行 → 被架构门禁拦下。状态机本就与传输层无关，
// 抽出来既过门禁，也让握手逻辑可被单独测试。
//
// 握手流程（NTLM over HTTP，Authorization: NTLM <base64>）：
//   ① 裸请求 → 401 + WWW-Authenticate: NTLM（空挑战）
//   ② 带 Type1 → 401 + WWW-Authenticate: NTLM <Type2>（含 8 字节 challenge）
//   ③ 带 Type3 → 200
// 状态按 hostKey 缓存：同主机后续请求可跳过 ①②，直接带 Type3（1 跳直达）。
// ============================================================================

import { createType1Message, createType3Message, extractNtlmChallenge } from './ntlmAuth.js';

export class NtlmHandshake {
  constructor() {
    /** @type {Map<string, {challenge: Buffer|null, username: string}>} */
    this._states = new Map();
  }

  /**
   * 解析 NTLM 凭据：auth.ntlm 优先，或 auth.type=ntlm 时回落到 auth.basic。
   * @param {any} auth
   * @returns {null | {username:string, password:string, domain?:string, workstation?:string}}
   */
  cred(auth) {
    if (!auth || typeof auth !== 'object') return null;
    const c = auth.ntlm || (auth.type && String(auth.type).toLowerCase() === 'ntlm' ? auth.basic : null);
    if (!c || c.username == null) return null;
    return {
      username: String(c.username),
      password: c.password != null ? String(c.password) : '',
      domain: c.domain,
      workstation: c.workstation,
    };
  }

  /**
   * 请求前的预附加头：已持有 Type2 challenge 时直接给 Type3（省握手）。
   * @param {string} url
   * @param {any} auth
   * @returns {null | string} Authorization 头值
   */
  preAuthHeader(url, auth) {
    const cred = this.cred(auth);
    if (!cred) return null;
    const hostKey = this.keyOf(url);
    if (!hostKey) return null;
    const state = this._states.get(hostKey);
    if (!state || state.username !== cred.username || !state.challenge) return null;
    try {
      return 'NTLM ' + createType3Message({
        username: cred.username,
        password: cred.password,
        domain: cred.domain,
        workstation: cred.workstation,
        challenge: state.challenge,
      });
    } catch {
      // 兜底：DES 已自实现，正常不会抛；真抛了就丢弃状态走完整握手
      this._states.delete(hostKey);
      return null;
    }
  }

  /**
   * 401 + WWW-Authenticate: NTLM → 下一跳用的头。
   * @param {string} url
   * @param {any} auth
   * @param {{status?:number, headers?:any}} res
   * @returns {{replay:boolean, header?:string, done?:boolean}} done=true 表示已发 Type3（终态）
   */
  replay(url, auth, res) {
    if (!res || res.status !== 401) return { replay: false };
    const cred = this.cred(auth);
    if (!cred) return { replay: false };
    const wa = res.headers && (res.headers['www-authenticate'] || res.headers['WWW-Authenticate']);
    if (!wa || !/ntlm/i.test(String(wa))) return { replay: false };
    const hostKey = this.keyOf(url);
    if (!hostKey) return { replay: false };

    const parsed = extractNtlmChallenge(res.headers);
    if (!parsed || !parsed.challenge) {
      // 空挑战：服务端只要 Type1
      try {
        const t1 = createType1Message({ domain: cred.domain, workstation: cred.workstation });
        this._states.set(hostKey, { challenge: null, username: cred.username });
        return { replay: true, header: 'NTLM ' + t1, done: false };
      } catch { return { replay: false }; }
    }
    // 拿到 Type2 challenge → Type3（终态）
    try {
      const t3 = createType3Message({
        username: cred.username,
        password: cred.password,
        domain: cred.domain,
        workstation: cred.workstation,
        challenge: parsed.challenge,
      });
      this._states.set(hostKey, { challenge: parsed.challenge, username: cred.username });
      return { replay: true, header: 'NTLM ' + t3, done: true };
    } catch {
      this._states.delete(hostKey);
      return { replay: false };
    }
  }

  /**
   * 主机键（protocol//host）；URL 非法时返回 null。
   * @param {string} url
   * @returns {string|null}
   */
  keyOf(url) {
    try {
      const u = new URL(url);
      return u.protocol + '//' + u.host;
    } catch { return null; }
  }

  /**
   * 清除某主机的握手状态（凭据变更/被拒时用）。
   * @param {string} url
   */
  clear(url) {
    const k = this.keyOf(url);
    if (k) this._states.delete(k);
  }
}
