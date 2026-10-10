// =====================================================================
// scalarsEgress.js — buildGuardedConfig 的出口与护栏段（auth/techniques/proxy 校验、
// 出口三键、生产护栏、ssrfViaProxy、http2/xpAutoEnable、applyTuningKnobs 唯一调用点）。
// 自 scanConfigGuard.js 拆出（纯搬移）。⚠ applyTuningKnobs 全链路只此一调（幂等，
// 但两处调用会让「哪个键在哪被写」重新变成读代码才能知道的事）。
// =====================================================================
import { ErrorCode, AppError } from '../../core/errors.js';
import { TECHNIQUE_TYPES } from '../../engine/payloads.js';
import { pickBool } from '../scanConfigUtils.js';
import { applyTuningKnobs } from '../scanConfigTuning.js';

export function guardScalarsEgress(config, cfg) {
  // 认证配置透传（httpClient.mergeAuthHeaders 消费：basic/cookie/自定义头）
  // 注：凭据仅在引擎内存/报告/会话中使用，服务端导出侧已脱敏（见 ReportGenerator/ScanManager patch）。
  if (cfg.auth && typeof cfg.auth === 'object') config.auth = cfg.auth;

  if (cfg.techniques) {
    if (!Array.isArray(cfg.techniques) || cfg.techniques.some((tech) => !TECHNIQUE_TYPES.includes(tech))) {
      throw new AppError(ErrorCode.INVALID_PARAM, 'techniques 含非法技术类型');
    }
    config.techniques = cfg.techniques;
  }
  // [P1-FIX 2026-09-08 接线补齐] proxy scheme 与 httpClient.PROXY_SCHEMES 对齐（补 socks4/socks4a）：
  // 原正则只认 https?|socks5?，引擎已支持的 socks4 在 API 层就被拒（功能可达性与实现不一致）。
  if (cfg.proxy) {
    if (typeof cfg.proxy !== 'string' || !/^(?:https?|socks5h?|socks4a?):\/\//i.test(cfg.proxy)) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        'proxy 格式非法（支持 http:// https:// socks5:// socks5h:// socks4:// socks4a://；需强制直连请设 trustProxyEnv=false）'
      );
    }
    config.proxy = cfg.proxy;
  }
  // [P1-FIX 2026-09-08] 出口层三键透传：此前只进了 defaults/env，per-scan config 到不了
  // HttpClient（engine 侧靠 opts 逐层透传），导致 UI 勾了「忽略自签证书」对检测请求无效。
  const insecureTls = pickBool(cfg, 'insecureTls');
  if (insecureTls !== undefined) config.insecureTls = insecureTls;
  // [2026-10-01] mTLS 客户端证书路径（sqlmap --cert 语义）：形状只收字符串 + 长度上限；
  // 文件存在性与 PEM 形状在引擎实际加载时校验（core/http/clientCert.js，失败抛错要响）。
  if (cfg.clientCert !== undefined && cfg.clientCert !== null) {
    if (typeof cfg.clientCert !== 'string' || !cfg.clientCert.trim() || cfg.clientCert.length > 1024) {
      throw new AppError(ErrorCode.INVALID_PARAM, 'clientCert 须为非空 PEM 文件路径（≤1024 字符）');
    }
    config.clientCert = cfg.clientCert.trim();
  }
  // [D32 实战 P0-1] requestScript：自定义请求变换脚本路径（签名/加密参数接口）。
  // 入口只做形状（长度上限 + 类型）；存在性、REQUEST_SCRIPT_DIR 白名单根、
  // 导出形态三道校验在 ScanManager.start 的 ensureScanTransform 里**硬失败**（扫描不启动），
  // 因为「收了路径却没加载成功」若降级继续，产出的是整轮静默假阴性。
  //
  // ⚠️ **空白串 = 未启用，必须放行**（D35 由 api-range-lab 实测抓到）：
  //   defaults.requestScript 的关闭态就是 ''，而「单点重测」这类接口会把**整份基线配置原样回放**
  //   进 /scan/start —— 于是"要求非空"的写法把默认值判成了 1003，retest 直接启动失败。
  //   与 clientCert 的区别就在默认值：那个是 null（空串不是它的合法关闭态），这个是 ''。
  //   方向选择：宁可让"传了个空白串"静默当未启用（与默认值同义），也不能拒绝默认值本身。
  if (cfg.requestScript !== undefined && cfg.requestScript !== null) {
    if (typeof cfg.requestScript !== 'string') {
      throw new AppError(ErrorCode.INVALID_PARAM, 'requestScript 须为脚本路径字符串');
    }
    const trimmed = cfg.requestScript.trim();
    if (trimmed) {
      // 超长是明确的写错（路径不可能 1KB），静默丢弃就变成"收了不生效"——本仓最忌的那类；
      // 而空白串不是写错，它就是默认关闭态（见上），所以只给它放行。
      if (trimmed.length > 1024) {
        throw new AppError(ErrorCode.INVALID_PARAM, 'requestScript 路径过长（>1024 字符）');
      }
      config.requestScript = trimmed;
    }
  }
  const trustProxyEnv = pickBool(cfg, 'trustProxyEnv');
  if (trustProxyEnv !== undefined) config.trustProxyEnv = trustProxyEnv;
  // [P0-FIX 2026-09-09] 生产护栏透传：productionMode 默认 true（按生产环境对待遇），
  // 关掉它（false）是显式脱离护栏——只应出现在靶场/自建演练环境。
  const productionMode = pickBool(cfg, 'productionMode');
  if (productionMode !== undefined) config.productionMode = productionMode;
  const confirmDestructive = pickBool(cfg, 'confirmDestructive');
  if (confirmDestructive !== undefined) config.confirmDestructive = confirmDestructive;
  // [2026-09-23] 报错模板按机制族裁剪：引擎侧按 `config.compactErrorTemplates === true`
  // **严格**判定（ErrorDetector._resolveErrorTemplates），与 hex 同口径 —— 走 pickBool 而不是
  // 通用标量透传，否则 `1`/`"true"` 会被 REST 收下却在引擎侧不生效（白名单有、引擎收不到）。
  const compactErrorTemplates = pickBool(cfg, 'compactErrorTemplates');
  if (compactErrorTemplates !== undefined) config.compactErrorTemplates = compactErrorTemplates;
  // [2026-09-24 接入口] 提取/统计层的 11 个旋钮（引擎一直在读、注释一直写着"可经 config.X
  // 调整"，而 defaults / 本白名单 / CLI / 面板四处都没接）。逐键区间与理由抽到
  // api/scanConfigTuning.js —— 一是让 scanRoutes 回到 arch:guard 的 1200 行预算内
  // （**拆分而不是加进基线**：基线是"承认既有债"，不该用来收自己刚造的债），
  // 二是这批键形状一致（单值严格透传 + 一个带底阈值组），单独成模块能逐键穷举测试。
  // 默认值逐个等于引擎内部兜底 ⇒ 不发等于零行为变化。
  applyTuningKnobs(config, cfg);
  if (typeof cfg.ssrfViaProxy === 'string') {
    const v = cfg.ssrfViaProxy.trim().toLowerCase();
    // [P1-FIX 2026-09-09] 新增 strict-dns：本地能解析就先按严格层判（解不出才下放给代理）。
    // 为什么需要：auto 语义下，内网 DNS 把域名指到 169.254.169.254 时代理解析会照打，
    // 边界完全转移到代理配置上；挂 Burp/企业代理扫内网时至少要有一个选项能把门要回来。
    if (v === 'auto' || v === 'off' || v === 'strict-dns') config.ssrfViaProxy = v;
    else if (v === 'true' || v === '1') config.ssrfViaProxy = 'auto';
    else if (v === 'false' || v === '0') config.ssrfViaProxy = 'off';
    else throw new AppError(ErrorCode.INVALID_PARAM, 'ssrfViaProxy 仅支持 "auto" | "off" | "strict-dns"');
  }
  // [P0-FIX 2026-09-09] proxyBypassLocal：默认 true（本地/私网不吃环境变量代理）；
  // 显式传 false 可恢复「连本地也走代理」的旧行为。
  const proxyBypassLocal = pickBool(cfg, 'proxyBypassLocal');
  if (proxyBypassLocal !== undefined) config.proxyBypassLocal = proxyBypassLocal;
  // [2026-09-24] HTTP 传输形态两键：defaults.js 的注释早在 2026-09-09 就写着
  // 「本键与 http2 此前只存在于 defaults，未进 KNOWN_CFG_KEYS → 已补白名单+透传」，
  // 但白名单里**从来没有它们**（本轮实测：sanitizeStart 对 config.http2 / 
  // config.disableKeepAlive 都不落地，还会回一条「未知字段」warn）。后果不是"不好看"：
  //   · http2 —— crawler.js:169 / TargetParser.js:288 的判据是 `config?.http2 === true`，
  //     收不到就永远走 axios HTTP/1.1，而调用方以为换了协议形态（WAF 侧指纹也不同）；
  //   · disableKeepAlive —— httpClient.js:322 只看构造参数，REST 传了等于没传。
  // CLI 侧这两个键连旋钮都没有 ⇒ 此前没有任何入口能让引擎读到非默认值。
  // 走严格布尔（同 compactErrorTemplates）：`1`/`"true"` 在 REST 收下却不被引擎生效，
  // 是一种更难的查法，不如在入口就拒掉。
  const http2 = pickBool(cfg, 'http2');
  if (http2 !== undefined) config.http2 = http2;
  const disableKeepAlive = pickBool(cfg, 'disableKeepAlive');
  if (disableKeepAlive !== undefined) config.disableKeepAlive = disableKeepAlive;
  // [2026-09-24] xpAutoEnable：**不可逆动作的拒绝位**。Exploiter.js:450 的判据是
  // `ctx.config?.xpAutoEnable !== false`，命中就发
  // `EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE`（实例级永久配置变更，MSSQL 侧
  // 对标 sqlmap 的自动开启行为）。原实现该键在任何入口都不存在 ⇒ 使用者**无法拒绝**
  // 一次改服务器配置的写操作——这与本仓「高危动作必须显式确认」（productionMode /
  // confirmDestructive / secondOrder.allowWrites）的口径不一致。
  // 默认仍为 true（零行为变化，避免把既有 MSSQL 利用链打断了还没人知道），
  // 但从本轮起 `config.xpAutoEnable=false` 真的能把这一步关掉。
  const xpAutoEnable = pickBool(cfg, 'xpAutoEnable');
  if (xpAutoEnable !== undefined) config.xpAutoEnable = xpAutoEnable;
}
