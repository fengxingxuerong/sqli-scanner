// =====================================================================
// transport.js — 传输层：axios 单跳（_rawRequest）/ undici HTTP/2 单跳（_rawUndici）/
// 响应后处理薄委托（_finishResponse）/ insecureTls 专用 Agent（undiciAgentInsecure）。
// 自 httpClient.js 拆出（纯搬移）：由 HttpClient.prototype 挂载（this 语义不变）。
// =====================================================================
import { Agent as UndiciAgent, request as undiciRequest } from 'undici';
import { defaults } from '../../config/defaults.js';
import { logger } from '../logger.js';
import { effectiveInsecureTls, effectiveClientCert, logSafeUrl } from './requestContext.js';
import { agentsForTls } from './agentFactory.js';
import { loadClientCert } from './clientCert.js';
import {
  decompressResponseBody, decodeResponseBody, attachResMeta, getResponseHeader, finalizeAxiosResponse,
} from './responseCodec.js';
import { AGENT_MAX_SOCKETS } from './agentPool.js';
import { logOnce } from './logOnce.js';
import { MAX_BODY_BYTES } from './limits.js';

  // [P1-FIX ①] insecureTls 专用 Agent：connect.rejectUnauthorized:false（undici 的 TLS 选项在
  // connect 上，而不是 Agent 顶层），与默认 Agent 分开持有，避免关掉共享 Agent 的证书校验。
export function undiciAgentInsecure() {
    if (!this._undiciAgentInsecure) {
      this._undiciAgentInsecure = new UndiciAgent({
        connect: { timeout: defaults.timeoutMs, rejectUnauthorized: false },
        connections: AGENT_MAX_SOCKETS,
        pipelining: 1,
      });
    }
    return this._undiciAgentInsecure;
  }

  // 单跳请求（已通过 SSRF 校验的 URL）
export async function _rawRequest(cfg, opts, headers, proxyConf, timeoutMs, disableKA) {
    // [P0-FIX] 提取路径（opts.maxContentLength）动态放大响应上限：默认 10MB，提取可至 50MB
    const maxBody = opts.maxContentLength ?? MAX_BODY_BYTES;
    const insecureTls = effectiveInsecureTls(opts);
    // [mTLS 2026-10-01] 客户端证书（对标 sqlmap --cert）：目标要求 TLS 双向认证时，
    // 没有证书在检测阶段之前就出局。证书加载失败（路径错/形状错）**抛错**——配置错误要响，
    // 静默降级等于全程握手失败还被读成「目标不可达」。
    const mtlsPath = effectiveClientCert(opts);
    const mtls = mtlsPath ? loadClientCert(mtlsPath) : null;
    // [P1-FIX ①] 传输层 Agent 选择（insecureTls 与 disableKeepAlive 交叉）：
    //   · 代理自带 Agent（socks）→ 保留代理 Agent（证书校验由 markAgentInsecure 注入，不另挂 Agent）；
    //     mTLS 与代理叠加时证书挂不上代理隧道，warn 一次明示「clientCert 未生效」（不静默）。
    //   · insecureTls / mtls → 换用专用 Agent（keepAlive 跟随 disableKA），绝不改共享 Agent 实例
    //   · 其余 → 沿用 instance 默认；disableKA 时回退 Node 默认 Agent（保持历史语义）
    if (mtls && proxyConf.httpAgent) logOnce('warn', 'clientCert 与代理叠加时 mTLS 证书未生效（代理隧道不支持挂证书），直连目标才能使用客户端证书');
    const transport = proxyConf.httpAgent
      ? {}
      : insecureTls || mtls
        ? agentsForTls(insecureTls, !disableKA, mtls)
        : disableKA
          ? { httpAgent: false, httpsAgent: false }
          : {};
    const res = await this.instance.request({
      method: opts.method || 'GET',
      url: opts.url,
      params: opts.params,
      data: opts.data,
      headers,
      timeout: timeoutMs,
      maxContentLength: maxBody,
      maxBodyLength: maxBody,
      ...proxyConf,
      ...transport,
      maxRedirects: 0,
      // [P1-FIX 2026-09-08 ③] 响应体取原始字节（arraybuffer），由本类按声明字符集解码后再赋回
      // res.data —— 旧值 'text' 让 axios 无条件按 utf8 解码，GBK/Big5/Shift-JIS/EUC-KR 目标不可逆地
      // 变 U+FFFD（中文报错文案丢失 + 布尔比对字节碰撞漏检 + 拖库中文乱码）。
      // 另一层不变的原因：不能省掉 responseType（axios 默认按 Content-Type 自动 JSON.parse →
      // res.data 变对象/数组，检测器 String(res.data) 得到 "[object Object]"/""，JSON API 上的
      // 布尔真假判定语义全失 → 恒漏检），解码后契约仍是 string，与 undici 通道一致。
      responseType: 'arraybuffer',
      // 配套跳过 axios 的隐式响应转换（双保险，防止默认 transformResponse 再解析）
      transformResponse: [(d) => d],
      ...(opts.signal ? { signal: opts.signal } : {}),
      ...cfg,
    });
    return this._finishResponse(res, opts);
  }

  // [P1-FIX ③④] axios 通道响应后处理：解码文本（对外仍是 string）+ 挂 __meta 元数据。
  // 超限在 axios 侧是「抛错」而非截断（maxContentLength 命中即 reject），故 truncated 恒 false；
  // 真正的静默截断风险在 undici 通道（见 _rawUndici），两通道共用同一元数据契约。
  // [大文件二期拆分 2026-09-20] 逻辑已外移至 http/responseCodec.js#finalizeAxiosResponse
  // （纯函数、无 this 依赖）。此处保留同名方法作为薄委托：方法名不动 = 既有调用方与
  // 打桩测试零影响，行为与原实现逐字节一致。
export function _finishResponse(res, opts) {
    return finalizeAxiosResponse(res, opts);
  }

  // [HTTP/2] undici 传输层（对标 sqlmap --http2）：HTTP/2 + HTTP/1.1 ALPN 协商，
  // 单连接多路复用对批量请求（爬虫取页 / 常用标量提取）有吞吐收益。
  // 返回与 axios 响应同构的 { status, data, headers }；SSRF 校验已在 request() 入口完成。
  // [P1-FIX ①] insecureTls 时改用专用 undici Agent（connect.rejectUnauthorized:false），
  // 不复用 this.undiciAgent —— 后者是 per-client 共享给「校验开启」流量的，关掉它等于全局裸奔。
  // [P1-FIX ③④] 与 axios 通道共用 decodeResponseBody + __meta（超限不再只留一行文本）。
export async function _rawUndici(opts, headers, timeoutMs, pinnedLookup) {
    const insecureTls = effectiveInsecureTls(opts);
    const dispatcher = insecureTls ? this.undiciAgentInsecure() : this.undiciAgent;
    // DNS 钉死：优先用已校验 IP（防 rebinding）；无法钉死时回退常规解析（undici 自行解析）
    let lookup;
    if (pinnedLookup) {
      lookup = (hostname, o, cb) => pinnedLookup(hostname, o, cb);
    }
    const connectOpts = { ...(/** @type {any} */ (dispatcher).opts?.connect || {}) };
    if (insecureTls) connectOpts.rejectUnauthorized = false;
    if (lookup) connectOpts.lookup = lookup;
    // [mTLS 2026-10-01] undici 通道同语义：per-request connect.cert/key（加载失败抛错，同 axios 通道）
    const mtlsPath = effectiveClientCert(opts);
    if (mtlsPath) {
      const m = loadClientCert(mtlsPath);
      connectOpts.cert = m.cert;
      connectOpts.key = m.key;
    }
    const { statusCode, headers: resHeaders, body } = await undiciRequest(opts.url, {
      dispatcher,
      method: String(opts.method || 'GET'),
      headers: { ...headers },
      body: opts.data,
      headersTimeout: timeoutMs,
      bodyTimeout: timeoutMs,
      connect: connectOpts,
      ...(opts.signal ? { signal: opts.signal } : {}),
      // [P0-FIX] 手动重定向（逐跳 SSRF 校验 + 跨域剥离敏感头由 _followRedirectsH2 负责）：
      // undici 内置 maxRedirections 跟随的跳转目标不经过 assertSafeHttpTarget 校验、不钉 DNS，
      // 302 可跳内网/元数据地址（绕过出口 SSRF 防护）。置 0 关闭内置跟随。
      // @ts-expect-error undici 支持 maxRedirections，但其 RequestOptions 类型未收录（运行时有效）
      maxRedirections: 0,
    });
    // 体积上限：读流但截断超限（与 axios maxContentLength 语义近似，防 OOM）
    const chunks = [];
    let total = 0;
    let truncated = false;
    const maxBody = opts.maxContentLength ?? MAX_BODY_BYTES;
    for await (const chunk of body) {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += b.length;
      if (total > maxBody) {
        // [P1-FIX ④] 不再把「截断说明」混进 body 就返回：检测器只看 data/status，
        // 截断会被当成「内容不同/相同」。这里保留同样的提示文本（位置不变），并额外挂
        // __meta.truncated + warn 一次，让上层/报告可判定「本次比对不可信」。
        truncated = true;
        break;
      }
      chunks.push(b);
    }
    let raw = Buffer.concat(chunks);
    // [P0-FIX 2026-09-09] undici 通道不自动解压（axios 会）。目标或前置代理返回 gzip/deflate/br 时，
    // 原实现把压缩字节当文本解码 → 整页 U+FFFD，检测器看到的是「内容差异巨大」，于是
    // `--http2` 与默认通道对同一目标给出相反结论（一边正常、一边全盲）。这里补齐，失败则显式标注。
    const enc = getResponseHeader(resHeaders, 'content-encoding');
    let encodingUnsupported = false;
    if (enc && enc !== 'identity' && !truncated) {
      try {
        raw = /** @type {any} */ (decompressResponseBody(raw, enc));
      } catch (e) {
        encodingUnsupported = true;
        logger.warn(
          `响应 content-encoding=${enc} 解压失败（${e.message}）：本次响应未按解压结果使用，` +
            '该点差异比对不可信。建议关闭 http2（走 axios 通道）或确认代理未改写编码头'
        );
      }
    }
    const decoded = decodeResponseBody(raw, resHeaders);
    let text = decoded.text;
    if (truncated) text += `[响应超限截断 ${total} 字节 > ${maxBody}]`;
    const res = { status: statusCode, data: text, headers: resHeaders, isHttp2: true };
    if (truncated) {
      logOnce(
        'warn',
        `响应体超限已截断（${total} 字节 > ${maxBody} 字节）：${logSafeUrl(opts.url || '')}。` +
          `差异比对可能失真（漏检风险），请调高 SSRF_MAX_BODY_MB（当前 ${Math.round(MAX_BODY_BYTES / 1048576)}MB）`
      );
    }
    attachResMeta(res, {
      bodyBytes: raw.length,
      truncated,
      charset: decoded.charset,
      charsetSource: decoded.charsetSource,
      ...(decoded.charsetUnsupported
        ? { charsetUnsupported: true, declaredCharset: decoded.declaredCharset }
        : {}),
      ...(encodingUnsupported ? { contentEncodingUnsupported: true, contentEncoding: enc } : {}),
    });
    return res;
  }
