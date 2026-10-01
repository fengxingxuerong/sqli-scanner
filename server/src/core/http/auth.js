// =====================================================================
// auth.js — 认证挑战处理：Digest 挑战-重放（_digestAuthHeader/_digestReplay/
// _setDigestChallenge）+ 401 分发（Digest 与 NTLM 三步握手，_after401）。
// 自 httpClient.js 拆出（纯搬移）：由 HttpClient.prototype 挂载（this 语义不变）。
// =====================================================================
import { URL } from 'url';
import { defaults } from '../../config/defaults.js';
import {
  parseDigestChallenge, extractDigestChallenge, buildDigestHeader, makeCnonce,
} from '../digestAuth.js';

  // ===== [P2-4] Digest 认证（对标 sqlmap --auth-type=Digest） =====
  // 状态模型：_digestStates 按 hostKey(protocol+host) 缓存 { challenge, nc, username, cnonce }。
  //   · 首个请求（无缓存 challenge）→ 发裸请求；收到 401+Digest 挑战 → 建 state → 重放一次。
  //   · 缓存复用 → nc 每次单调递增（服务端防重放计数校验）。
  //   · 服务端 nonce 过期再返 401 → 刷新 challenge 重建 state（防死循环：仅允许挑战-重放一轮）。

  // 尝试构造 Digest Authorization 头。
  // @returns {null} 无 digest 配置 | { header } 可直用 | { needChallenge:true, hostKey, cred, uri } 需先裸请求
export function _digestAuthHeader(method, url, auth) {
    if (!auth || typeof auth !== 'object') return null;
    const cred = auth.digest || (auth.type && String(auth.type).toLowerCase() === 'digest' ? auth.basic : null);
    if (!cred || cred.username == null) return null;
    let u;
    try { u = new URL(url); } catch { return null; }
    const hostKey = u.protocol + '//' + u.host;
    const uri = u.pathname + u.search;
    const state = this._digestStates.get(hostKey);
    if (state && state.username === cred.username) {
      const nc = state.nc + 1;
      state.nc = nc;
      const header = buildDigestHeader({
        method, uri,
        challenge: state.challenge,
        username: cred.username,
        password: cred.password != null ? cred.password : '',
        nc, cnonce: state.cnonce,
      });
      return { header };
    }
    return { needChallenge: true, hostKey, cred, uri };
  }

  // 401 + WWW-Authenticate: Digest → 建 state 并返回重放头
  // @returns {replay:false} | {replay:true, header}
export function _digestReplay(method, url, auth, res) {
    if (!res || res.status !== 401) return { replay: false };
    if (!auth || typeof auth !== 'object') return { replay: false };
    const cred = auth.digest || (auth.type && String(auth.type).toLowerCase() === 'digest' ? auth.basic : null);
    if (!cred || cred.username == null) return { replay: false };
    const ch = extractDigestChallenge(res.headers);
    if (!ch) return { replay: false };
    let u;
    try { u = new URL(url); } catch { return { replay: false }; }
    const hostKey = u.protocol + '//' + u.host;
    const cnonce = makeCnonce();
    if (!this._setDigestChallenge(hostKey, cred, res.headers['www-authenticate'], cnonce)) {
      return { replay: false };
    }
    const state = this._digestStates.get(hostKey);
    state.nc = 1;
    const header = buildDigestHeader({
      method, uri: u.pathname + u.search,
      challenge: state.challenge,
      username: cred.username,
      password: cred.password != null ? cred.password : '',
      nc: 1, cnonce,
    });
    return { replay: true, header };
  }

export function _setDigestChallenge(hostKey, cred, challengeHeader, cnonce) {
    const challenge = parseDigestChallenge(challengeHeader);
    if (!challenge) return false;
    this._digestStates.set(hostKey, { challenge, nc: 0, cnonce: cnonce || makeCnonce(), username: cred.username });
    return true;
  }

  /**
   * 401 响应的认证挑战处理（原 request() 内联逻辑迁移）：
   * ① [P2-4] Digest 挑战-重放：请求未显式带 Authorization 且收到 401+Digest challenge →
   *    本轮构造响应头并经 send() 重发一次（对标 curl --digest 的 challenge→response 往返）。
   *    · 预附加的缓存 Digest 头被 401 拒绝 → 清 state，下次请求重新挑战（nonce 过期自愈）；
   *    · 用户显式 Authorization（Basic/Bearer/自定义）→ 不干预；
   *    · digest 配置缺失 / 非 401 / 无 Digest challenge → 不干预；
   *    · 重发仍 401 → 返回该响应（凭据无效，语义与普通 401 一致，不死循环）。
   * ② [P1-2026-09-14] NTLM 三步握手重放：最多 2 跳（Type1 → Type2 → Type3）——与 Digest
   *    单次重放不同，NTLM 要服务端先回 Type2 才能算 Type3，故是**有上限的循环**
   *    （hop<2 硬上限，且 done=true 后仍 401 即清 state 退出，双保险防死循环）。
   * @returns {Promise<object>} 最终响应（可能与传入相同，也可能来自认证重发）
   */
export async function _after401(res, opts, headers, send, digestPreAttached) {
    if (res && res.status === 401 && digestPreAttached) {
      // [P2-4] 服务端拒绝缓存的 Digest 凭据（nonce 过期/凭据变更）→ 清 state，下次请求重新挑战
      try { this._digestStates.delete(new URL(opts.url).protocol + '//' + new URL(opts.url).host); } catch { /* ignore */ }
    } else if (res && res.status === 401 && !headers['Authorization'] && !headers['authorization']) {
      const da = opts.auth ?? defaults.auth ?? null;
      if (da && typeof da === 'object') {
        const need = this._digestAuthHeader(opts.method || 'GET', opts.url, da);
        if (need && need.needChallenge) {
          // 无缓存 challenge：首次裸请求返回 401 → 建立 state 并重放
          const rp = this._digestReplay(opts.method || 'GET', opts.url, da, res);
          if (rp.replay) {
            headers['Authorization'] = /** @type {string} */ (rp.header);
            res = await send();
            // 重放后仍 401 → 凭据无效/nonce 过期：清 state 防死循环（下次请求重新挑战）
            if (res && res.status === 401 && opts.url) {
              try { this._digestStates.delete(new URL(opts.url).protocol + '//' + new URL(opts.url).host); } catch { /* ignore */ }
            }
          }
        } else if (need && need.header) {
          // 有缓存 challenge：直接带（mergeAuthHeaders 不处理 digest）
          headers['Authorization'] = need.header;
          res = await send();
        }
      }
    }
    // NTLM 与 Digest 相互独立：上面的分支无论是否命中，这里都按同一判据进入；
    // 仅当配置了 NTLM 凭据且响应仍是 401+NTLM 挑战时生效；用户显式 Authorization 优先不干预。
    {
      const na = opts.auth ?? defaults.auth ?? null;
      if (res && res.status === 401 && na && typeof na === 'object' && this._ntlm.cred(na)) {
        for (let hop = 0; hop < 2; hop++) {
          const rp = this._ntlm.replay(opts.url, na, res);
          if (!rp.replay || !rp.header) break;
          headers['Authorization'] = rp.header;
          res = await send();
          if (!res || res.status !== 401) break; // 认证通过（或其它状态）→ 结束握手
          if (rp.done) {
            // 已发 Type3 仍 401 → 凭据无效：清 state，避免后续请求一直重试坏凭据
            this._ntlm.clear(opts.url);
            break;
          }
        }
      }
    }
    return res;
  }
