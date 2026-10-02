// =====================================================================
// objectGroups.js — 五个嵌套对象配置组的「带底重建/逐字段 clamp」：
// secondOrder（含读写分离三键与 cookie 脱险键）/ wafEvasion（带底重建防浅合并丢子键）/
// oob / noSql / blindRobust（统计判定组，含误报防线硬下限）。
// 自 scanConfigGuard.js 拆出（纯搬移）：每组的整段重建逻辑原样平移为独立函数。
// =====================================================================
import { clampInt, clampNum, boolOf, pickInt, pickBool, sanitizeCookieMap } from '../scanConfigUtils.js';
import { defaults } from '../../config/defaults.js';

export function guardSecondOrder(config, cfg) {
  if (cfg.secondOrder) {
    const so = cfg.secondOrder;
    config.secondOrder = {
      enabled: !!so.enabled,
      // [P0-1 配套] triggerUrls 的 SSRF 校验在路由处理器 async 层执行（见 /scan/start
      // handler：对 sanitized.config.secondOrder.triggerUrls 逐个 assertSafeHttpTarget），
      // 此处仅做协议白名单过滤（同步函数不能 await）。
      triggerUrls: Array.isArray(so.triggerUrls)
        ? so.triggerUrls.filter((x) => typeof x === 'string' && /^https?:\/\//i.test(x))
        : [],
      refreshCsrf: so.refreshCsrf !== false,
      // [P0-FIX 2026-09-09] 二阶写请求确认位：productionMode=true 时，非幂等 method
      // （POST/PUT/PATCH/DELETE）与触发页写请求必须 allowWrites===true 才放行。
      // 实战后果：二阶检测天然要「写一次」才能触发存储型路径，而对 /order/create 这类
      // GET 写端点，“只读复核”的说法从一开始就不成立——必须把“我在写”这件事显式开关化。
      allowWrites: so.allowWrites === true,
      triggerMethod: typeof so.triggerMethod === 'string'
        ? so.triggerMethod.slice(0, 16)
        : defaults.secondOrder.triggerMethod,
      negativeControl: so.negativeControl !== false,
      oobTrigger: !!so.oobTrigger,
      // 存储组间并行度（引擎 supplementalRuns._runSecondOrder 真读；与 defaults 同源回落）
      concurrency: clampInt(so.concurrency, defaults.secondOrder.concurrency, 1, 16),
      // [P0-REACH 2026-09-23] 读写分离二阶注入（对标 sqlmap --second-url/--second-method/--second-data）：
      // 引擎在 SecondOrderDetector._trigger 里**真读**这三个字段（`so.secondUrl || url`、
      // resolveSecondOrderMethod(so.secondMethod, …)、`so.secondData`），但本 clamp 此前不保留它们、
      // CLI 也没有可设入口 → 该能力**三条路径全不可达**（CLI 不能设 / REST 传了被丢弃 / UI 更无入口）。
      // 与 extractScope 那次是同一病灶：能力在，入口不在，而报告只会写「未检出」。
      // ⚠️ 形状只做协议白名单 + 长度上限；**SSRF/授权范围校验在路由 handler 的 async 层**执行
      // （与 triggerUrls 同一条链，见下方 secondUrl 校验段）—— 不能在这里放行未校验的 URL。
      // 方法白名单刻意不在此重复：单一真相在引擎的 resolveSecondOrderMethod（含幂等门）。
      // 未传时回落 defaults 而非 undefined：浅合并下 undefined 会让「引擎读到 undefined」
      // 与「用户没配」在现场无法区分，报告/审计取 config.secondOrder.secondMethod 时也是空的。
      secondUrl: typeof so.secondUrl === 'string' && /^https?:\/\//i.test(so.secondUrl)
        ? so.secondUrl.slice(0, 2048)
        : defaults.secondOrder.secondUrl,
      secondMethod: typeof so.secondMethod === 'string'
        ? so.secondMethod.slice(0, 16)
        : defaults.secondOrder.secondMethod,
      secondData: typeof so.secondData === 'string'
        ? so.secondData.slice(0, 8192)
        : (so.secondData && typeof so.secondData === 'object' ? so.secondData : defaults.secondOrder.secondData),
      // [todo#39 2026-09-11] 跨角色触发（读写分离身份）：存储与触发页可分属不同会话身份
      // （低权账号写入、高权账号读出是存储型注入的实战高发形态）。键值均须为字符串，
      // 过滤 __proto__/constructor/prototype 等危险键（对象字面量展开会沿原型链污染）。
      storeCookies: sanitizeCookieMap(so.storeCookies),
      triggerCookies: sanitizeCookieMap(so.triggerCookies),
    };
  }
}

export function guardWafEvasion(config, cfg) {
  if (cfg.wafEvasion && typeof cfg.wafEvasion === 'object') {
    const we = cfg.wafEvasion;
    // [2026-09-24] 必须**带底重建**（对照下面的 oob 分支）：models.js:113 的 config 合并是
    // 浅合并（{...defaults, ...input.config}），wafEvasion 一旦整体替换，未转发的子键就成了
    // undefined。而引擎侧 filterAdaptive 的判据是 `=== true`（defaults.js 里默认开、且实测
    // 把关键词过滤靶场从 [error] 提到 [error,boolean]）—— 于是「只带 tamper 的请求」
    // （UI 的 tamper 编辑器、CLI 的 --tamper 都发这种）会**静默关掉自适应过滤重跑**：
    // 扫描照常跑完、照常报绿，只是少了一整轮绕过。实测 sanitizeStart 旧写法对
    // {wafEvasion:{tamper:{...}}} 只转发回 tamper 一个键，9 个子键丢 8 个。
    const waf = { ...defaults.wafEvasion };
    const randomUA = pickBool(we, 'randomUA');
    if (randomUA !== undefined) waf.randomUA = randomUA;
    const obfuscate = pickBool(we, 'obfuscate');
    if (obfuscate !== undefined) waf.obfuscate = obfuscate;
    const jitterMs = pickInt(we, 'jitterMs', defaults.wafEvasion.jitterMs, 0, 5000);
    if (jitterMs !== undefined) waf.jitterMs = jitterMs;
    // 其余四个布尔位：引擎判据有 `=== true` 与 `!== false` 两种，两种都要求键**存在**
    // 才是用户真正表达的意图，故逐个显式转发（非法/未传则保持 defaults）。
    for (const k of ['adaptiveOnBlock', 'bypassSearch', 'filterAdaptive', 'autoRetry', 'channelDegrade']) {
      const v = pickBool(we, k);
      if (v !== undefined) waf[k] = v;
    }
    if (we.tamper && typeof we.tamper === 'object') {
      const t = we.tamper;
      const intensity = ['low', 'medium', 'high'].includes(t.intensity) ? t.intensity : defaults.wafEvasion.tamper.intensity;
      const plugins = Array.isArray(t.plugins) ? t.plugins.filter((p) => typeof p === 'string') : defaults.wafEvasion.tamper.plugins;
      waf.tamper = { ...defaults.wafEvasion.tamper, enabled: !!t.enabled, plugins, intensity };
    }
    config.wafEvasion = { ...config.wafEvasion, ...waf };
  }
}

export function guardOob(config, cfg) {
  if (cfg.oob && typeof cfg.oob === 'object') {
    const o = cfg.oob;
    config.oob = {
      enabled: !!o.enabled,
      callbackBase: typeof o.callbackBase === 'string' ? o.callbackBase : defaults.oob.callbackBase,
      httpPort: clampInt(o.httpPort, defaults.oob.httpPort, 1, 65535),
      timeoutMs: clampInt(o.timeoutMs, defaults.oob.timeoutMs, 1000, 60000),
      // [B-perf] DNS OOB 接收端参数（oobReceiver._startDns 消费 cfg.dnsPort / cfg.dnsDomain，
      // 此前不在白名单被丢弃，REST 层只能靠环境变量 DNS_PORT/DNS_DOMAIN 兜底）。
      // dnsDomain 截断到 253（RFC 域名长度上限）；dnsPort clamp 到 [1,65535]。
      // [主代理收尾] dnsOob 开关透传：OobDetector DNS 轮消费（生成 <token>.<dnsDomain> 触发查询）。
      dnsOob: !!o.dnsOob,
      dnsDomain: typeof o.dnsDomain === 'string' ? o.dnsDomain.slice(0, 253) : defaults.oob.dnsDomain,
      dnsPort: clampInt(o.dnsPort, defaults.oob.dnsPort, 1, 65535),
    };
  }
}

export function guardNoSql(config, cfg) {
  if (cfg.noSql && typeof cfg.noSql === 'object') {
    const ns = cfg.noSql;
    config.noSql = {
      enabled: !!ns.enabled,
      kinds: Array.isArray(ns.kinds)
        ? ns.kinds.filter((k) => typeof k === 'string' && ['nosql', 'graphql', 'ssti'].includes(k))
        : defaults.noSql.kinds,
      // [2026-09-24] 本组此前整键漏转发 concurrency：ScanManager.js:633 读
      // `Number(noSql.concurrency) || 2`，而 sanitizeStart 只重建 {enabled, kinds} ⇒
      // 传 concurrency:8 静默回到 2（非 SQL 补充趟的并发上不去，大点集扫描白等）。
      concurrency: clampInt(ns.concurrency, defaults.noSql.concurrency, 1, 16),
    };
  }
}

// [批次14 实战 P1-6] 登录编排最小版（loginFlow.js 消费）：标准表单登录自动提交 +
// 会话过期自动重登。形状收紧：url 必须 http(s)（SSRF/scope 由 per-scan client 逐请求
// 校验兜底，这里只做协议白名单 + 长度上限，与 secondOrder.triggerUrls 同口径）；
// 字段名只认 [A-Za-z0-9_-]（要拼进表单键）；username 必填（scanClient 的包装门也按
// username 存在与否判定——无凭据的登录编排没有意义）。
export function guardLogin(config, cfg) {
  if (cfg.login && typeof cfg.login === 'object') {
    const l = cfg.login;
    if (typeof l.url !== 'string' || !/^https?:\/\//i.test(l.url)) return; // 非法形态整体丢弃
    const fieldRe = /^[A-Za-z0-9_-]{1,64}$/;
    const optField = (v) => (typeof v === 'string' && fieldRe.test(v) ? v : undefined);
    config.login = {
      url: l.url.slice(0, 2048),
      username: typeof l.username === 'string' ? l.username.slice(0, 256) : '',
      password: typeof l.password === 'string' ? l.password.slice(0, 256) : '',
      usernameField: optField(l.usernameField),
      passwordField: optField(l.passwordField),
    };
  }
}

export function guardBlindRobust(config, cfg) {
  if (cfg.blindRobust && typeof cfg.blindRobust === 'object') {
    const br = cfg.blindRobust;
    const d = defaults.blindRobust;
    config.blindRobust = {
      enabled: boolOf(br.enabled, d.enabled),
      booleanSamples: clampInt(br.booleanSamples, d.booleanSamples, 1, 10),
      baselineSamples: clampInt(br.baselineSamples, d.baselineSamples, 1, 20),
      timeConfidenceZ: clampNum(br.timeConfidenceZ, d.timeConfidenceZ, 1, 5),
      minStableRatio: clampNum(br.minStableRatio, d.minStableRatio, 0.5, 1),
      booleanSignificanceZ: clampNum(br.booleanSignificanceZ, d.booleanSignificanceZ, 1, 5),
      adaptive: boolOf(br.adaptive, d.adaptive),
      adaptiveHeadroom: clampNum(br.adaptiveHeadroom, d.adaptiveHeadroom, 0, 1),
      // [P0-FIX 2026-09-08] 统计判定的「关掉护栏」下限：原 clamp 允许 floor=0 / z=0，
      // 而 adaptive=true 时门槛 = clamp(噪声 + headroom, floor, cap)，floor=0 会把噪声目标的
      // 一致率门槛拉到 0 → 任何抖动都算「稳定」；booleanSignificanceZ=0 则「false 组与基线
      // 完全相同也判阳」——两个都是误报放大器。盲注误报的代价（往报告里写假漏洞）远大于漏报，
      // 故给硬下限：一致率门槛不低于 0.5、显著性 z 不低于 1.0（单侧≈84% 置信）。
      minStableRatioFloor: clampNum(br.minStableRatioFloor, d.minStableRatioFloor, 0.5, 1),
      minStableRatioCap: clampNum(br.minStableRatioCap, d.minStableRatioCap, 0.5, 1),
      adaptiveTimeFloorScale: clampNum(br.adaptiveTimeFloorScale, d.adaptiveTimeFloorScale, 0, 10),
      concurrency: clampInt(br.concurrency, d.concurrency, 1, 16),
      // [2026-09-24] 本组此前**整键漏转发**：blindExtractor 读 `config.blindRobust.extractVerify`
      // （`!== false` 判据），而 defaults.blindRobust 有 13 键、这里只重建 12 键 ——
      // 于是带 blindRobust 的请求会把 defaults 里的 `extractVerify: true` 替换成 undefined，
      // 表面上"看起来还是 true"（undefined !== false 为真），实际后果是**关不掉**：
      // 调用方显式传 `extractVerify:false` 被丢弃，提取阶段的逐字节等值验证 + 整体投票复验
      // （每字符 1 次 + 收尾 1 次请求）照跑不误。CLI/面板都没有这个旋钮 ⇒ REST 是**唯一**入口，
      // 而这个唯一入口是断的。
      extractVerify: boolOf(br.extractVerify, d.extractVerify),
    };
  }
}
