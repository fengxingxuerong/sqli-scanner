// ============================================================================
// authInjectionOverlap.js —— [D101 2026-10-18] 「注入点 × 认证配置」同名夹击去重
// ----------------------------------------------------------------------------
// 类别来源（D91 → D92 → D101 通用化）：
// 请求头/Cookie 被显式纳入注入点（--test-headers / headerParams / cookieParams）后，
// config.auth 里的同名副本会在发送层 mergeAuthHeaders 把注入值**顶回原值**
// （auth.headers 是覆盖语义；auth.cookie 是追加语义但同名双份由目标解析顺序决定谁生效）
// ⇒ 该注入点全部探针打在未注入值上 ⇒ 报告「未检出」，与「这个站没有注入」同形。
//
// 本模块把 CLI（server/bin/cli.js，原先精确键名 delete，大小写变体漏删）与
// REST（server/src/api/scanRoutes.js，原先只在 testHeaders 时去重、且不管 auth.cookie）
// 的去重口径收敛为**单点实现**（P0-3 / TODO.md:78 的「抽共享函数」）。
//
// 语义（与 D91/D92 既有口径逐条对齐，不新增行为）：
//   ① headerParams 中除 cookie 外的键：从 auth.headers 删同名副本（头名大小写不敏感）。
//      触发条件 = 实际存在同名副本；与 testHeaders 无关——构造层对每个请求都写
//      `{...target.headerParams}`（injection.js:147），同名 auth 副本即便不是注入点
//      也会静默顶替显式传入的请求头值（D92 门「仅 testHeaders」漏掉 level≥3 无
//      testHeaders 的 headerParam 同名场景，D101 收紧）。
//   ② cookieParams 中的键名：从 auth.cookie 里删同名对（cookie 名**大小写敏感**，
//      按 RFC 6265），残余对重拼；删空则移除字段。目的：Cookie 头 = 构造层整串 +
//      发送层追加 ⇒ 同名双份（`uid=<payload>; uid=1`），取第一还是取最后取决于目标
//      解析顺序 ⇒ 同一目标重跑结论可能翻转（CLI 既有 leftover 逻辑的同源泛化）。
//   ③ auth.headers.cookie 不在此删：会话语义由 auth.cookie 承担；其覆盖由发送层
//      D91-B「已有 Cookie 即跳过」拦截（mergeAuthHeaders）。
//
// ⚠ 不得就地修改入参 auth：REST 的 config.auth 与调用方 cfg.auth 同引用
// （buildGuardedConfig 不深拷贝），就地 delete 会让同一 body 复用第二次起静默丢认证
// （D92-④ 已实证）。本模块一律「无改动原样返回、有改动浅拷贝新对象」。
// ============================================================================

/**
 * Cookie 串（`a=1; b=2`）→ 有序键值对数组；无 `=` 的片段忽略。
 * 与 server/bin/cli/config.js parseCookiePairs 同口径（trim 名与值、空名忽略），
 * 保留有序对是为了残余重拼时不重排。
 * @param {string} raw
 * @returns {Array<[string, string]>}
 */
function parseCookiePairList(raw) {
  /** @type {Array<[string, string]>} */
  const pairs = [];
  for (const pair of String(raw || '').split(';')) {
    const eq = pair.indexOf('=');
    if (eq > 0) {
      const name = pair.slice(0, eq).trim();
      const val = pair.slice(eq + 1).trim();
      if (name) pairs.push([name, val]);
    }
  }
  return pairs;
}

/**
 * ① 自定义头去重：headerParams（除 cookie）与 auth.headers 同名 ⇒ 删 auth 副本。
 * @param {object} auth 认证配置
 * @param {object|undefined} headerParams 显式请求头
 * @returns {object} 去重后的 auth（无改动返回原引用）
 */
function dedupeHeadersFromAuth(auth, headerParams) {
  if (!headerParams || typeof headerParams !== 'object') return auth;
  const authHeaders = auth.headers;
  if (!authHeaders || typeof authHeaders !== 'object') return auth;
  const kept = { ...authHeaders };
  let changed = false;
  for (const k of Object.keys(headerParams)) {
    if (String(k).toLowerCase() === 'cookie') continue;
    const hit = Object.keys(kept).find((hk) => String(hk).toLowerCase() === String(k).toLowerCase());
    if (hit) {
      delete kept[hit];
      changed = true;
    }
  }
  if (!changed) return auth;
  if (Object.keys(kept).length === 0) {
    const { headers: _dropped, ...rest } = auth;
    return { ...rest };
  }
  return { ...auth, headers: kept };
}

/**
 * ② 会话 Cookie 去重：cookieParams 键名与 auth.cookie 同名对 ⇒ 删对重拼（cookie 名大小写敏感）。
 * @param {object} auth 认证配置
 * @param {object|undefined} cookieParams 显式 cookie 键值
 * @returns {object} 去重后的 auth（无改动返回原引用）
 */
function dedupeCookiesFromAuth(auth, cookieParams) {
  if (!cookieParams || typeof cookieParams !== 'object' || typeof auth.cookie !== 'string') return auth;
  const names = new Set(Object.keys(cookieParams));
  if (names.size === 0) return auth;
  const pairs = parseCookiePairList(auth.cookie);
  const leftover = pairs.filter(([name]) => !names.has(name));
  if (leftover.length === pairs.length) return auth;
  if (leftover.length === 0) {
    const { cookie: _dropped, ...rest } = auth;
    return { ...rest };
  }
  return { ...auth, cookie: leftover.map(([n, v]) => `${n}=${v}`).join('; ') };
}

/**
 * 纯函数入口：把「显式纳入注入点/显式传入的请求头与 cookie」的键从 auth 同名副本中剔除。
 * @param {object|undefined} auth 认证配置 { headers?, cookie?, basic?, ... }
 * @param {{headerParams?: Record<string,string>, cookieParams?: Record<string,string>}} [points]
 *   显式请求头与 cookie 键值（CLI: buildInjectionTargets 产物；REST: sanitizeStart 收敛后的字段）
 * @returns {object|undefined} 去重后的 auth（无改动时返回原引用；有改动时为浅拷贝新对象）
 */
export function dropInjectionOverlapFromAuth(auth, points) {
  if (!auth || typeof auth !== 'object' || !points || typeof points !== 'object') return auth;
  return dedupeCookiesFromAuth(dedupeHeadersFromAuth(auth, points.headerParams), points.cookieParams);
}

/**
 * REST 就地入口：把去重结果写回 config.auth —— **仅在引用变化时回写**。
 * 无条件 `config.auth = undefined` 会凭空造出 `auth` 键并落入 config 键集合
 * （entryParity「两入口逐键相等」实测抓到）；分支放在本 helper 内以免 sanitizeStart
 * 复杂度升值（复杂度基线只许持平）。
 * @param {object} config 已过守卫的配置（就地替换 auth 字段，不污染入参对象）
 * @param {{headerParams?: Record<string,string>, cookieParams?: Record<string,string>}} [points]
 * @returns {void}
 */
export function applyDropInjectionOverlap(config, points) {
  const next = dropInjectionOverlapFromAuth(config.auth, points);
  if (next !== config.auth) config.auth = next;
}
