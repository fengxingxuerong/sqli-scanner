// =====================================================================
// scanClient.js — 扫描作用域客户端工厂：连接器选择（direct/http）/ _maybeClose
// 连接回收 / getScanClient（per-scan 限速桶 + safeUrl/csrf/forceSsl/egress 包装链）。
// 自 ScanManager.js 拆出（纯搬移）：由 ScanManager.prototype 挂载（this 语义不变）。
// =====================================================================
import { withSafeUrl } from '../../core/safeUrlKeeper.js';
import { withCsrf } from '../../core/csrfKeeper.js';
// [批次14 实战 P1-6] 登录编排：会话过期自动重登（挂在 csrf 之后——登录表单也可能要 csrf）
import { withLoginFlow } from '../../core/loginFlow.js';
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

  // 获取扫描作用域的 HttpClient 视图：http 目标包装为按 scanId 独立限速桶的客户端
  // （前端 ratePerSec 设置由此生效，Detector/Extractor 无需改动），direct 目标原样返回。
export function getScanClient(scanId, target) {
    const connector = this.getConnector(target);
    if (connector !== this.httpClient || typeof connector.forScan !== 'function') return connector;
    if (!this._scanClients.has(scanId)) {
      // [sqlmap 对标] --reqrate：reqRate > 0 时覆盖 ratePerSec 作为 TokenBucket 速率
      const reqRate = target.config && target.config.reqRate;
      const ratePerSec = (reqRate && reqRate > 0 ? reqRate : (target.config && target.config.ratePerSec)) || undefined;
      // [2026-10-03] cfg.rateGroup：批量模式下所有目标共用**一个**限速桶（组桶）。
      // 与「每扫描按 ratePerSec/concurrency 均分」的区别：均分是启动时算死的，队列排空后
      // 剩下的目标仍按 1/并发度 跑（预算白白闲着）；组桶是动态的 —— 谁在用谁就能拿到，
      // 总量由单桶保证。不给 rateGroup 时行为与原来完全一致（按 scanId 建桶）。
      // ⚠ 这里不能用下面的 `cfg`（它在**之后**才声明，const 有 TDZ，提前引用会 ReferenceError）
      const rateGroup = (target && target.config && target.config.rateGroup) || undefined;
      const sc = connector.forScan(scanId, ratePerSec, rateGroup);
      // [sqlmap 对标] --safe-url/--safe-freq：配置了保活 URL 时包装客户端
      // （SSRF 校验在 client.request 内逐请求执行；失败静默不影响扫描）
      const cfg = (target && target.config) || {};
      let view = sc;
      if (typeof cfg.safeUrl === 'string' && /^https?:\/\//i.test(cfg.safeUrl)) {
        view = /** @type {any} */ (withSafeUrl(sc, { safeUrl: cfg.safeUrl, safeFreq: cfg.safeFreq }));
      }
      // [sqlmap 对标 2026-09-14] --csrf-url/--csrf-token：CSRF 会话层（取页提取 token，
      // 每请求自动携带 + 定期刷新）。挂在 safeUrl 之后：token 取页吃到保活/协议策略。
      if (typeof cfg.csrfUrl === 'string' && /^https?:\/\//i.test(cfg.csrfUrl)) {
        view = /** @type {any} */ (withCsrf(view, {
          csrfUrl: cfg.csrfUrl,
          csrfTokenName: cfg.csrfTokenName,
          csrfMethod: cfg.csrfMethod,
          refreshFreq: cfg.csrfRefreshFreq,
        }));
      }
      // [批次14 实战 P1-6] 登录编排（cfg.login.url 显式开启）：标准表单登录自动提交 +
      // 会话过期（401/403/登录跳转）自动重登一次并重试原请求。挂在 csrf 之后：登录
      // 表单本身的 hidden csrf 字段由 loginFlow 自行探测透传。登录请求走同一 per-scan
      // client —— SSRF/scope/限速逐请求照常生效。凭据错误时重登失败即放行原响应
      // （authLost 统计按既有口径收尾），不会死循环。
      if (
        cfg.login && typeof cfg.login.url === 'string' &&
        /^https?:\/\//i.test(cfg.login.url) && cfg.login.username
      ) {
        view = /** @type {any} */ (withLoginFlow(view, cfg.login));
      }
      // [P2-5] --force-ssl / --ignore-redirects：协议层策略注入每个请求（对标 sqlmap）。
      // forceSsl：目标 http:// 强制升级 https（httpClient.request 消费改写）；
      // ignoreRedirects：不跟随 3xx（httpClient.request 消费跳转上限 0）。
      // 在 forScan 视图之上再包一层，Detector/Extractor/二阶/NoSQL/WAF 全路径统一生效，
      // 且不影响未配协议策略的存量扫描（无配置时 view 原样返回零开销）。
      // [P1-FIX 2026-09-08 接线补齐] 出口层三键走同一个注入点：
      //   insecureTls / trustProxyEnv / ssrfViaProxy 此前只能靠 defaults 或环境变量——
      //   Detector.send 等 7 个调用点只透传 `proxy/auth`，per-scan config 到不了 HttpClient，
      //   于是「UI 勾了忽略自签证书」对实际发包无效（引擎已实现能力在 API 层不可达）。
      //   在扫描级视图统一注入后，新增出口类配置只需改 defaults + 白名单 + 这一处，不再漏接线。
      const egressPatch = {};
      if (cfg.insecureTls === true) egressPatch.insecureTls = true;
      if (cfg.trustProxyEnv !== undefined) egressPatch.trustProxyEnv = cfg.trustProxyEnv !== false;
      if (cfg.ssrfViaProxy !== undefined) egressPatch.ssrfViaProxy = cfg.ssrfViaProxy;
      // [2026-10-01] mTLS：与出口层三键同一个注入点（httpClient 双通道均消费 opts.clientCert）
      if (typeof cfg.clientCert === 'string' && cfg.clientCert) egressPatch.clientCert = cfg.clientCert;
      const proto =
        cfg.forceSsl === true || cfg.ignoreRedirects === true || Object.keys(egressPatch).length > 0
          ? egressPatch
          : null;
      const baseHead = typeof view.headRequest === 'function' ? view.headRequest.bind(view) : null;
      if (proto) {
        const baseRequest = view.request.bind(view);
        view = {
          ...view,
          request: (opts) => baseRequest({
            ...opts,
            ...(cfg.forceSsl === true ? { forceSsl: true } : {}),
            ...(cfg.ignoreRedirects === true ? { ignoreRedirects: true } : {}),
            ...egressPatch,
          }),
          // [P0-FIX 2026-09-09] headRequest（--null-connection）必须走同一层包装：
          // 它不经过 view.request，以前只包 request 等于「HEAD 一路看不到 insecureTls/代理/scope 以外的出口语义」。
          // 实战表现：自签目标上 GET 能扫、开了 --null-connection 就全量失败，现场极难归因。
          ...(baseHead
            ? {
                headRequest: (url, opts = {}) =>
                  baseHead(url, {
                    ...opts,
                    ...(cfg.forceSsl === true ? { forceSsl: true } : {}),
                    ...(cfg.ignoreRedirects === true ? { ignoreRedirects: true } : {}),
                    ...egressPatch,
                  }),
              }
            : {}),
        };
      }
      this._scanClients.set(scanId, view);
    }
    return this._scanClients.get(scanId);
  }
