// =====================================================================
// scanClient.js — 扫描作用域客户端工厂：连接器选择（direct/http）/ _maybeClose
// 连接回收 / getScanClient（per-scan 限速桶 + safeUrl/csrf/forceSsl/egress 包装链）。
// 自 ScanManager.js 拆出（纯搬移）：由 ScanManager.prototype 挂载（this 语义不变）。
//
// [D67 2026-10-14] getScanClient 的五个内联包装块拆为独立 helper（逐字搬移，
// 零行为变化）：请求变换 / 响应解密 / 协议出口层 / 暂停闸 / 限速桶参数。
// 主函数只保留「顺序即语义」的装配链——包装次序本身就是契约（见各层注释），
// 不再让单个函数承担 53 个分支。
// =====================================================================
import { withSafeUrl } from '../../core/safeUrlKeeper.js';
import { withCsrf } from '../../core/csrfKeeper.js';
// [批次14 实战 P1-6] 登录编排：会话过期自动重登（挂在 csrf 之后——登录表单也可能要 csrf）
import { withLoginFlow } from '../../core/loginFlow.js';
// [D32 实战 P0-1] 自定义请求变换（签名/加密参数）扩展点
import { applyScanTransform, notifyTransformOutcome, transformActiveForScan } from '../../core/requestTransform.js';
// [D52] 自定义响应解密（--postprocess，与请求变换对偶）：密文响应体的解密点
import { applyResponseTransform, responseTransformActiveForScan } from '../../core/responseTransform.js';
// [D36 实战 P0-2] Bearer/Token 自动续期
import { refreshActiveForScan, withBearerRefresh } from '../../core/bearerKeeper.js';
// [D198 对标 sqlmap --live-cookies] 每请求重读的 cookie 文件（会话入口面，挂在最内层：
// 保活取页/CSRF 取页/登录提交这些**内层自发请求**也要带上最新会话 cookie）
import { withLiveCookies } from '../../core/liveCookies.js';
import { DirectConnector } from '../../core/directConnector.js';

  // 连接器选择：direct 目标用 DirectConnector 直连数据库，其余用统一 HttpClient 单例。
export function getConnector(target) {
    return target && target.mode === 'direct' ? new DirectConnector(target) : this.httpClient;
  }

  // 关闭非单例的连接器（如直连 DirectConnector），避免连接泄漏；HttpClient 单例不关。
export async function _maybeClose(connector) {
    if (connector && connector !== this.httpClient && connector.close) {
      try {
        await connector.close();
      } catch {
        /* ignore */
      }
    }
  }

// ── getScanClient 的包装层 helper（D67 自 36-258 行的单函数逐字搬移）─────────

/**
 * 限速桶参数推导：reqRate > 0 时覆盖 ratePerSec（[sqlmap 对标] --reqrate）。
 * [2026-10-03] rateGroup：批量模式下所有目标共用**一个**限速桶（组桶）。
 * 与「每扫描按 ratePerSec/concurrency 均分」的区别：均分是启动时算死的，队列排空后
 * 剩下的目标仍按 1/并发度 跑（预算白白闲着）；组桶是动态的 —— 谁在用谁就能拿到，
 * 总量由单桶保证。不给 rateGroup 时行为与原来完全一致（按 scanId 建桶）。
 * ⚠ 调用方注意 TDZ：此函数必须在 cfg 声明**之前**可调用（原本就有此约束，
 *   提前用 cfg 会 ReferenceError —— 故这里独立成函数，输入直接取 target）。
 * @param {object} target 扫描目标（非空；http 分支才会到达此处）
 * @returns {{ratePerSec:number|undefined, rateGroup:string|undefined}}
 */
function deriveBucketOptions(target) {
  const reqRate = target.config && target.config.reqRate;
  const ratePerSec = (reqRate && reqRate > 0 ? reqRate : (target.config && target.config.ratePerSec)) || undefined;
  const rateGroup = (target && target.config && target.config.rateGroup) || undefined;
  return { ratePerSec, rateGroup };
}

/**
 * [D32 实战 P0-1] 自定义请求变换（签名/加密参数）—— 挂在包装链的**最内层**，两个理由缺一不可：
 *   ① 签名必须是最后一道加工。safeUrl/csrf/login 三层都往请求里加东西（保活 cookie、
 *      csrf token、登录会话），加在它们之上(外) ⇒ 后加的内容不在签名范围内 ⇒ 目标照样拒。
 *      挂最内 = 每个加工方先写完、脚本最后签。
 *   ② 内层自发的请求也要合法。csrfKeeper 取页、loginFlow 的登录 GET/POST 调的是
 *      **传给它们的那一层视图**，不经过外层 ⇒ 挂外层这些请求会绕过签名。
 * ⚠ 不变量：本层改写 URL 发生在 HttpClient.request 的 SSRF/scope 校验**之前**，
 *   所以校验作用于变换之后的 URL。反过来挂（先校验再变换）= 脚本可把已授权请求
 *   改写到内网元数据地址，这个扩展点立刻变成 SSRF 跳板。
 * ⚠ fail-closed：脚本抛错/产出非法请求 ⇒ AppError 上抛、**原始请求绝不发出去**。
 *   「算不出签名就发没签名的」会把一次必然被目标拒绝的请求记成「已检测」，
 *   而那正是本扩展点要消灭的静默假阴性。错误经 ctxBase 的 observeValidity 回流，
 *   该点按既有网络失败语义记为未决（不是「未检出」）。
 * 未配置 --request-script 时 transformActiveForScan 为 false ⇒ 调用方零包装、零行为变化。
 * @param {object} view 当前视图
 * @param {string} scanId 扫描 id
 * @returns {object} 包装后的视图
 */
function wrapRequestTransformLayer(view, scanId) {
  const baseReq = view.request.bind(view);
  const baseHead = typeof view.headRequest === 'function' ? view.headRequest.bind(view) : null;
  const notify = (prepared, ev) =>
    notifyTransformOutcome(scanId, { injected: prepared.injected, ...ev });
  return {
    ...view,
    request: async (opts) => {
      let prepared;
      try {
        prepared = await applyScanTransform(scanId, opts);
      } catch (e) {
        // 脚本自身故障：一条都没发出去 ⇒ 不伪造 injected，直接上抛
        notify({ injected: false }, { error: e });
        throw e;
      }
      try {
        const res = await baseReq(prepared.opts);
        notify(prepared, { res });
        return res;
      } catch (e) {
        notify(prepared, { error: e });
        throw e;
      }
    },
    // HEAD（--null-connection）必须走同一层：F1 那批的教训是「只包 request 等于 HEAD
    // 一路看不到出口语义」—— 自签目标上 GET 能扫、开 --null-connection 就全量失败。
    // ⚠ 变换后的 URL 必须作为第一个实参传给 baseHead：HttpClient.headRequest(url, opts)
    //   用显式 url 覆盖 opts.url，只改 opts 会让签名算完又被原 URL 顶掉。
    ...(baseHead
      ? {
          headRequest: async (url, opts = {}) => {
            let prepared;
            try {
              prepared = await applyScanTransform(scanId, { ...opts, url });
            } catch (e) {
              notify({ injected: false }, { error: e });
              throw e;
            }
            const targetUrl = typeof prepared.opts.url === 'string' && prepared.opts.url
              ? prepared.opts.url
              : url;
            try {
              const res = await baseHead(targetUrl, prepared.opts);
              notify(prepared, { res });
              return res;
            } catch (e) {
              notify(prepared, { error: e });
              throw e;
            }
          },
        }
      : {}),
  };
}

/**
 * [D52] 响应解密（--postprocess）—— 与请求变换挂在**同一层（最内层）**，理由对偶：
 *   ① 解密必须是最外层的读者之前、最内层的生产者之后：safeUrl/csrf/login 各层都要看
 *      明文（csrf 取页读 body 提 token、loginFlow 读登录响应），挂在它们外层这些
 *      层看到的还是密文；挂在最内层 ⇒ 每个加工方读到的都是解密后的响应。
 *   ② 只包经 getScanClient 的请求（与请求变换的覆盖边界逐字一致：不含爬虫阶段的
 *      表单收集请求）。
 * ⚠ fail-closed：脚本抛错/产出非法形态 ⇒ AppError 上抛，该响应按「请求失败」处理
 *   （_send 记 null、位置重试/放弃，与网络失败同义）。绝不「解不动就用密文继续比」
 *   —— 那正是本扩展点要消灭的静默假阴性。
 * 未配置 --postprocess 时 responseTransformActiveForScan 为 false ⇒ 调用方零包装、零行为变化。
 * @param {object} view 当前视图
 * @param {string} scanId 扫描 id
 * @returns {object} 包装后的视图
 */
function wrapResponseTransformLayer(view, scanId) {
  const baseReq2 = view.request.bind(view);
  const baseHead2 = typeof view.headRequest === 'function' ? view.headRequest.bind(view) : null;
  return {
    ...view,
    request: async (opts) => applyResponseTransform(scanId, await baseReq2(opts)),
    ...(baseHead2
      ? {
          headRequest: async (url, opts = {}) =>
            applyResponseTransform(scanId, await baseHead2(url, opts)),
        }
      : {}),
  };
}

/**
 * [P1-FIX 2026-09-08] 出口层补丁构建：insecureTls / trustProxyEnv / ssrfViaProxy
 * （此前只能靠 defaults 或环境变量——Detector.send 等 7 个调用点只透传 `proxy/auth`，
 * per-scan config 到不了 HttpClient，于是「UI 勾了忽略自签证书」对实际发包无效）。
 * [2026-10-01] mTLS（clientCert）走同一注入点（httpClient 双通道均消费 opts.clientCert）。
 * @param {object} cfg 目标 config
 * @returns {object} 补丁对象（未配置任何键时为空对象）
 */
function buildEgressPatch(cfg) {
  const egressPatch = {};
  if (cfg.insecureTls === true) egressPatch.insecureTls = true;
  if (cfg.trustProxyEnv !== undefined) egressPatch.trustProxyEnv = cfg.trustProxyEnv !== false;
  if (cfg.ssrfViaProxy !== undefined) egressPatch.ssrfViaProxy = cfg.ssrfViaProxy;
  if (typeof cfg.clientCert === 'string' && cfg.clientCert) egressPatch.clientCert = cfg.clientCert;
  return egressPatch;
}

/**
 * 把协议/出口补丁合并进单个请求的 opts（request 与 headRequest 双路复用，逐字等价于内联合并）。
 * @param {object} opts 原请求 opts
 * @param {object} cfg 目标 config
 * @param {object} egressPatch buildEgressPatch 的产物
 * @returns {object} 合并后的 opts
 */
function mergeEgressOpts(opts, cfg, egressPatch) {
  return {
    ...opts,
    ...(cfg.forceSsl === true ? { forceSsl: true } : {}),
    ...(cfg.ignoreRedirects === true ? { ignoreRedirects: true } : {}),
    ...egressPatch,
  };
}

/**
 * [P2-5] --force-ssl / --ignore-redirects：协议层策略注入每个请求（对标 sqlmap）。
 * forceSsl：目标 http:// 强制升级 https（httpClient.request 消费改写）；
 * ignoreRedirects：不跟随 3xx（httpClient.request 消费跳转上限 0）。
 * 在 forScan 视图之上再包一层，Detector/Extractor/二阶/NoSQL/WAF 全路径统一生效，
 * 且不影响未配协议策略的存量扫描（无配置时 view 原样返回零开销）。
 * 出口类配置新增只需改 defaults + 白名单 + buildEgressPatch，不再漏接线。
 * @param {object} view 当前视图
 * @param {object} cfg 目标 config
 * @returns {object} 包装后的视图（无任何出口/协议配置时原样返回）
 */
function wrapEgressLayer(view, cfg) {
  const egressPatch = buildEgressPatch(cfg);
  const proto =
    cfg.forceSsl === true || cfg.ignoreRedirects === true || Object.keys(egressPatch).length > 0
      ? egressPatch
      : null;
  if (!proto) return view;
  const baseHead = typeof view.headRequest === 'function' ? view.headRequest.bind(view) : null;
  const baseRequest = view.request.bind(view);
  return {
    ...view,
    request: (opts) => baseRequest(mergeEgressOpts(opts, cfg, egressPatch)),
    // [P0-FIX 2026-09-09] headRequest（--null-connection）必须走同一层包装：
    // 它不经过 view.request，以前只包 request 等于「HEAD 一路看不到 insecureTls/代理/scope 以外的出口语义」。
    // 实战表现：自签目标上 GET 能扫、开了 --null-connection 就全量失败，现场极难归因。
    ...(baseHead
      ? {
          headRequest: (url, opts = {}) => baseHead(url, mergeEgressOpts(opts, cfg, egressPatch)),
        }
      : {}),
  };
}

/**
 * [F1 2026-10-03] 暂停闸下沉到**视图本身**（request 与 headRequest 都过闸）。
 *   此前暂停只挂在 scanRunner 的 ctxBase 包装层，而 detect.js 的两支 ad-hoc 客户端
 *   （tamper 链验证 / 拦截驱动重跑）直接调用 sm.getScanClient 拿裸视图 —— 暂停期间
 *   它们照常发包，「目标报警了先停手」对这两条路径形同虚设（TODO 09-28 #4 的验证口径：
 *   把暂停闸收到 getScanClient 返回视图上）。闸挂到视图后，所有经 getScanClient 的
 *   消费方（ctxBase 包装、safeUrl/csrf/login 包装链、ad-hoc 客户端）统一在请求边界
 *   等待；ctxBase 的闸保留 —— 双重等待幂等（外层先等，内层见非 paused 即过）。
 *   语义与点边界一致：paused 阻塞轮询、cancelled 放行（stop 的在途取消由 signal 负责）、
 *   扫描条目被回收（!s）也放行（退役后不再有新流量，闸不必拦）。
 * 注意：本层**就地改写** view（不新建对象）——保持与拆分前逐字一致的引用语义。
 * @param {object} view 当前视图
 * @param {string} scanId 扫描 id
 * @param {(scanId:string)=>Promise<void>} waitWhilePaused 绑定到 ScanManager 的等待函数
 * @returns {object} 同一个 view（就地包装后返回，便于链式调用）
 */
function wrapPauseGate(view, scanId, waitWhilePaused) {
  if (typeof view.request === 'function') {
    const req0 = view.request.bind(view);
    view.request = async (opts) => {
      await waitWhilePaused(scanId);
      return req0(opts);
    };
  }
  if (typeof view.headRequest === 'function') {
    const head0 = view.headRequest.bind(view);
    view.headRequest = async (url, opts) => {
      await waitWhilePaused(scanId);
      return head0(url, opts);
    };
  }
  return view;
}

  // 获取扫描作用域的 HttpClient 视图：http 目标包装为按 scanId 独立限速桶的客户端
  // （前端 ratePerSec 设置由此生效，Detector/Extractor 无需改动），direct 目标原样返回。
  // [D67] 装配链的**次序即契约**：变换/解密在最内层（每个加工方先写完、脚本最后签），
  //   safeUrl → csrf → login → bearer 四层会话准备依次向外，协议/出口层与暂停闸
  //   在最外层（全部消费方统一生效）。改次序前先读各 helper 的「为什么」注释。
/**
 * [D205] 会话层装配：live-cookies → safeUrl → csrf → login → bearer。
 * 从 `getScanClient` 抽出（D198 接 `--live-cookies` 后它涨到 42 行/22 圈，超了存量基线 36/18）。
 * **次序即契约**，改序前先读每一层的「为什么」：
 *   · live-cookies 必须**最内层**（变换层之后、safeUrl 之前）—— 保活/取页/CSRF/登录这些
 *     **内层自发请求也要带上最新会话 cookie**；
 *   · safeUrl 的保活/取页请求要吃到 live 层的最新 cookie；
 *   · csrf 取页要吃保活/协议策略；
 *   · login 的表单 hidden csrf 字段由 loginFlow 自行探测（故在 csrf 之后）；
 *   · bearer 续期请求要吃到 csrf/登录两层的会话准备（故在最外层会话位）。
 * @param {any} view 当前客户端视图（变换/解密层已包好）
 * @param {string} scanId 扫描 id
 * @param {Record<string, any>} cfg 目标配置（`target.config`）
 * @param {Record<string, any>|null|undefined} target 目标；**`cookieParams` 在 target 上，不在 config**
 * @returns {any} 装配好的视图
 */
function wrapSessionLayers(view, scanId, cfg, target) {
  let v = view;
  // [D198 对标 sqlmap --live-cookies] 每请求用文件里的最新值覆盖同名会话 cookie。
  // 被当作注入点的 cookie 键由 cookieParams 排除，否则 payload 会被文件里的原值顶回去。
  // [D205 代 D198 收口] excludeNames 原写 `cfg.cookieParams` —— cfg 是 `target.config`，
  // 而 cookieParams 在 **target 上**，旧写法恒为空数组 ⇒ 排除清单永不生效（该防的场景正是注入点本身）。
  if (typeof cfg.liveCookiesFile === 'string' && cfg.liveCookiesFile.trim()) {
    v = /** @type {any} */ (withLiveCookies(v, scanId, {
      file: cfg.liveCookiesFile,
      excludeNames: Object.keys((target && target.cookieParams) || {}),
    }));
  }
  // --safe-url/--safe-freq 保活（SSRF 校验在 client.request 内逐请求执行；失败静默不影响扫描）
  if (typeof cfg.safeUrl === 'string' && /^https?:\/\//i.test(cfg.safeUrl)) {
    v = /** @type {any} */ (withSafeUrl(v, { safeUrl: cfg.safeUrl, safeFreq: cfg.safeFreq }));
  }
  // --csrf-url/--csrf-token 会话层（取页提取 token，每请求携带 + 定期刷新）
  if (typeof cfg.csrfUrl === 'string' && /^https?:\/\//i.test(cfg.csrfUrl)) {
    v = /** @type {any} */ (withCsrf(v, {
      csrfUrl: cfg.csrfUrl,
      csrfTokenName: cfg.csrfTokenName,
      csrfMethod: cfg.csrfMethod,
      refreshFreq: cfg.csrfRefreshFreq,
    }));
  }
  // 登录编排：会话过期自动重登一次并重试原请求；SSRF/scope/限速逐请求照常生效
  if (
    cfg.login && typeof cfg.login.url === 'string' &&
    /^https?:\/\//i.test(cfg.login.url) && cfg.login.username
  ) {
    v = /** @type {any} */ (withLoginFlow(v, cfg.login));
  }
  // Bearer/Token 自动续期：与表单登录可共存（cookie 会话 + API bearer）
  if (cfg.bearerRefresh && refreshActiveForScan(scanId)) {
    v = /** @type {any} */ (withBearerRefresh(v, scanId));
  }
  return v;
}

export function getScanClient(scanId, target) {
    const connector = this.getConnector(target);
    if (connector !== this.httpClient || typeof connector.forScan !== 'function') return connector;
    if (!this._scanClients.has(scanId)) {
      const { ratePerSec, rateGroup } = deriveBucketOptions(target);
      const sc = connector.forScan(scanId, ratePerSec, rateGroup);
      const cfg = (target && target.config) || {};
      let view = sc;
      if (transformActiveForScan(scanId)) view = wrapRequestTransformLayer(view, scanId);
      if (responseTransformActiveForScan(scanId)) view = wrapResponseTransformLayer(view, scanId);

      // 会话层装配（live-cookies → safeUrl → csrf → login → bearer）：次序即契约，见 wrapSessionLayers
      view = wrapSessionLayers(view, scanId, cfg, target);
      // [P2-5] 协议/出口层（最外层的非闸包装）+ [F1] 暂停闸（视图自身，request/headRequest 都过闸）
      view = wrapEgressLayer(view, cfg);
      view = wrapPauseGate(view, scanId, this._waitWhilePaused.bind(this));
      this._scanClients.set(scanId, view);
    }
    return this._scanClients.get(scanId);
  }
