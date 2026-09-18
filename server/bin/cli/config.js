// ============================================================================
// config.js —— 参数 → 运行配置的转换层（注入点 / 配置对象 / 枚举范围）
//
// 从 bin/cli.js 抽离，[拆上帝对象 2026-09-14]。抽离依据：整族依赖闭环，
// 族内仅 buildConfig→isEnumMode，族外为 0（脚本报的 buildConfig→main 是注释里
// 出现 `main()` 字样造成的假阳性，已逐行核实）。
//
// cli.js 保留 import 与 export —— 6 个测试文件从 '../bin/cli.js' 导入 buildConfig 等，
// 导入路径不变是硬约束。
// ============================================================================
import { parseHeaders } from './args.js';
import { logger } from '../../src/core/logger.js';
import { PAYLOADS, enableDestructivePayloads } from '../../src/engine/payloads.js';

/**
 * Cookie 串（`a=1; b=2`）→ 键值对象；无 `=` 的片段忽略。
 * @param {string} raw @param {Record<string,string>} into
 */
export function parseCookiePairs(raw, into) {
  for (const pair of String(raw || '').split(';')) {
    const eq = pair.indexOf('=');
    if (eq > 0) {
      const name = pair.slice(0, eq).trim();
      const val = pair.slice(eq + 1).trim();
      if (name) into[name] = val;
    }
  }
  return into;
}

export function buildInjectionTargets(args) {
  const result = {};
  // [P0-FIX 2026-09-18] `--cookie` 本身就是「这个 Cookie 是注入面」的显式表达，不再要求
  // 同时给 `--test-headers`。此前 cookieParams 只能从 `--header 'cookie: …'` 那条路填进来，
  // 于是最主流的写法反而静默失效：实测 `--cookie uid=1 -u …/api/profile --level 5` 解析出
  // **0 个注入点** → 0 请求 → 报告「未检出」。cookie 型数字注入在 PHP/JSP 老系统上是高频洞，
  // 而「参数被忽略」比慢更糟——它看起来像一次干净的低风险扫描。
  // 是否真的投放 cookie 注入点仍由 TargetParser 的 level≥2 门控决定（与 sqlmap 同语义）。
  const cookieObj = parseCookiePairs(args.cookie, {});
  if (!args.testHeaders) {
    if (Object.keys(cookieObj).length) result.cookieParams = cookieObj;
    return result;
  }
  const hdrs = {};
  if (args.headerObj) Object.assign(hdrs, args.headerObj);
  const parsed = args.headers ? parseHeaders(args.headers) : undefined;
  if (parsed) Object.assign(hdrs, parsed);
  const EXCLUDE = new Set(['host', 'content-length', 'content-type', 'authorization']);
  const headerParams = {};
  for (const [k, v] of Object.entries(hdrs)) {
    const lk = String(k).toLowerCase();
    if (EXCLUDE.has(lk)) continue; // 传输层/认证类头排除
    if (lk === 'cookie') {
      // Cookie 头：解析为 k=v，填入 cookieParams（TargetParser 在 level≥2 生成 cookie 注入点）。
      // 同名键以 `--cookie` 为准（显式参数优先于从 --header 顺带解析出来的那一份）。
      for (const [name, val] of Object.entries(parseCookiePairs(v, {}))) {
        if (!(name in cookieObj)) cookieObj[name] = val;
      }
      continue;
    }
    headerParams[k] = v;
  }
  if (Object.keys(headerParams).length) result.headerParams = headerParams;
  if (Object.keys(cookieObj).length) result.cookieParams = cookieObj;
  return result;
}

// 构建 config：透传 level/risk/technique/dump/tamper/proxy/rate/threads
export function buildConfig(args) {
  const enumActive = isEnumMode(args);
  const config = {
    concurrency: args.concurrencyDet,
    ratePerSec: args.ratePerSec,
    enableExtract: args.dump || enumActive,
  };
  if (args.level != null) config.level = Math.max(1, Math.min(5, args.level));
  else if (args.crawl || args.forms) config.level = 5; // [UX] --crawl/--forms 隐含 level 5（TargetParser 要求）
  if (args.risk != null) config.risk = Math.max(1, Math.min(3, args.risk));
  // --risk=3：显式启用高危 payload 池（写文件 / RCE / 外连 / DoS 类向量）。
  // [P0-FIX 2026-09-09] 高危池投放必须 --confirm-destructive 硬门：risk=3 本身不是「授权声明」。
  // 旧行为是 `--risk 3` 直接往进程级 PAYLOADS 合并 DROP/写文件/RCE 向量，一行拼错就打到不相关的
  // 主机（一个进程只跑一个扫描时看不出来，共用引擎时污染面更大）。
  // 逃生口：--no-production-mode（靶场/自建演练环境）等价于已确认。
  config.productionMode = !args.noProductionMode;
  config.confirmDestructive = args.confirmDestructive === true;
  if (args.allowSecondOrderWrites) {
    config.secondOrder = { ...(config.secondOrder || {}), allowWrites: true };
  }
  if (config.risk >= 3) {
    if (!config.confirmDestructive && config.productionMode) {
      logger.warn(
        'ℹ --risk=3 但本次未投放高危 payload 池：写文件 / 命令执行 / 资源消耗型向量均**未发送**。' +
          '确认目标已书面授权且可承担影响时，加 --confirm-destructive（或在靶场用 --no-production-mode）。'
      );
      config.destructiveSuppressed = true;
    } else {
      try {
        enableDestructivePayloads(PAYLOADS, config.risk);
        logger.warn(
          '⚠️ --risk=3 + 已确认：高危 payload 池已投放（含文件读写 / 命令执行 / 外连探测 / 资源消耗型向量）。' +
          '仅在已获书面授权的渗透测试中使用，且注意本进程内其他扫描会共享同一份 payload 池。'
        );
      } catch (e) {
        logger.error(`高危 payload 池启用失败：${e.message}`);
      }
    }
  }
  // --test-filter / --test-skip / --use-registry（对标 sqlmap --test-filter / --test-skip）
  if (args.testFilter) config.testFilter = args.testFilter;
  if (args.testSkip) config.testSkip = args.testSkip;
  if (args.useRegistry) config.useRegistry = true;
  // 注入点扩展开关（本期新增，默认关闭，零回归）：透传给 TargetParser 决定是否把请求头 / path 末段生成注入点
  if (args.testHeaders) config.testHeaders = true;
  if (args.testPath) config.testPath = true;
  if (args.technique) {
    const valid = ['union', 'error', 'boolean', 'time', 'stacked', 'oob', 'inline', 'second_order'];
    const list = String(args.technique).split(',').map(s => s.trim().toLowerCase()).filter(t => valid.includes(t));
    if (list.length) config.techniques = list;
  }
  if (args.tamper) {
    // 自定义 tamper 文件已在 main() 经 resolveTamperPlugins 异步解析（args.tamperResolved）
    const plugins = Array.isArray(args.tamperResolved) && args.tamperResolved.length
      ? args.tamperResolved
      : String(args.tamper).split(',').map(s => s.trim()).filter(Boolean);
    if (plugins.length) {
      config.wafEvasion = { tamper: { enabled: true, plugins, intensity: 'medium' } };
    }
  }
  if (args.proxy) config.proxy = args.proxy;
  // [P0-SEC] --scope：授权范围硬约束（CIDR/域名/URL 前缀，逗号分隔）；空=不启用（零行为变化）。
  // 引擎侧 scopeGuard 在目标解析与每一跳重定向前校验，越界直接拒发。
  if (args.scope) {
    const rules = String(args.scope).split(',').map(s => s.trim()).filter(Boolean);
    if (rules.length) config.scope = rules;
  }
  // --insecure：config.insecureTls=true（HttpClient 换用 rejectUnauthorized:false 专用 Agent）
  if (args.insecureTls) config.insecureTls = true;
  // --no-validation-skip：显式关闭输入校验短路（引擎默认开）；不影响预筛 prefilter
  if (args.noValidationSkip) config.validationSkip = false;
  // [P0-FIX 2026-09-09] --no-proxy-bypass-local：显式恢复「本地也走环境变量代理」
  if (args.proxyBypassLocal === true) config.proxyBypassLocal = true;
  else if (args.proxyBypassLocal === false) config.proxyBypassLocal = false;
  // [对标 sqlmap --dbms] 强制指定 DBMS（scanRunner 消费：跳过指纹直接按指定库检测）
  if (args.dbms) config.dbms = String(args.dbms).trim();
  // [对标 sqlmap --second-order] 二阶触发页（写入后回访触发判定）
  if (args.secondOrderUrl && /^https?:\/\//i.test(args.secondOrderUrl)) {
    config.secondOrder = {
      ...(config.secondOrder || {}),
      enabled: true,
      triggerUrls: [...((config.secondOrder && config.secondOrder.triggerUrls) || []), args.secondOrderUrl],
    };
  }
  if (args.smart) config.prefilter = true;
  // [P0 2026-09-09 实战批次] 失效值替换（对标 sqlmap --invalid-bignum/--invalid-logical/--invalid-string）：
  // 布尔盲注的有效值前缀替换为随机大数/恒真逻辑式/随机串，规避缓存页/静态页噪声
  if (args.invalidBignum) config.invalidValue = 'bignum';
  else if (args.invalidLogical) config.invalidValue = 'logical';
  else if (args.invalidString) config.invalidValue = 'string';
  // [P0 2026-09-09 实战批次] 已知注入点直通：--known-point "param=id;quote=';paren=);techniques=union,error"
  // 键值对用 ; 分隔（techniques 值内含逗号，与 --technique 同名法）
  // 手工确认的可注入参数跳过预筛选与闭合探测；techniques 限定技术位
  if (args.knownPoint) {
    try {
      const kp = {};
      for (const pair of String(args.knownPoint).split(';')) {
        const i = pair.indexOf('=');
        if (i <= 0) continue;
        const k = pair.slice(0, i).trim();
        const v = pair.slice(i + 1).trim();
        if (k === 'param') kp.param = v;
        else if (k === 'quote') kp.quote = v;
        else if (k === 'paren') kp.paren = v;
        else if (k === 'techniques') kp.techniques = v;
      }
      if (kp.param) {
        config.knownPoint = { param: kp.param };
        if (kp.quote != null) config.knownPoint.quote = kp.quote;
        if (kp.paren != null) config.knownPoint.paren = kp.paren;
        if (kp.techniques) {
          const valid = ['union', 'error', 'boolean', 'time', 'stacked', 'oob', 'inline', 'second_order'];
          const list = String(kp.techniques).split(',').map((s) => s.trim().toLowerCase()).filter((t) => valid.includes(t));
          if (list.length) config.knownPoint.techniques = list;
        }
      } else {
        logger.warn('--known-point 缺少 param= 键，已忽略（示例：--known-point "param=id,quote=\',techniques=union"）');
      }
    } catch (e) {
      logger.warn(`--known-point 解析失败，已忽略：${e.message}`);
    }
  }
  // 限速三件套（对标 sqlmap --delay / --reqrate / --max-requests）
  if (args.delaySec > 0) config.delay = Math.min(Number(args.delaySec) || 0, 60);
  if (args.reqRate > 0) config.reqRate = Number(args.reqRate) || 0;
  if (args.maxRequests > 0) config.maxReq = Number(args.maxRequests) || 0;
  // 高级检测参数（对标 sqlmap --prefix/--suffix/--string/--not-string/--code/--text-only/--titles/--regexp）
  if (args.prefix) config.prefix = args.prefix;
  if (args.suffix) config.suffix = args.suffix;
  if (args.string) config.matchString = args.string;
  if (args.notString) config.notString = args.notString; // [P1-3] 引擎消费 notString（非 matchNotString）
  if (args.code != null) config.matchCode = { true: args.code }; // [P1-3] 状态码精确匹配语义
  if (args.textOnly) config.matchText = true; // [P1-3] 引擎消费 matchText（非 textOnly）
  if (args.titles) config.matchTitle = true;
  if (args.regexp) config.matchRegexp = args.regexp;
  // 爬虫/表单/会话/延迟参数（对标 sqlmap --forms/--crawl/--session-file/--time-sec/--delay/--predict-output/--skip-static）
  if (args.forms) config.crawlForms = true; // [验证] 引擎消费 crawlForms（TargetParser.js:94）
  if (args.crawl) config.crawlDepth = args.crawl;
  if (args.sessionFile) config.sessionFile = args.sessionFile;
  if (args.timeSec) config.timeBlindSleepSec = args.timeSec;
  // [验证] 引擎延迟走 wafEvasion.jitterMs（httpClient.js applyJitter），非独立 requestDelayMs 字段
  if (args.delay) config.wafEvasion = { ...(config.wafEvasion || {}), jitterMs: args.delay };
  if (args.predictOutput) config.predictOutput = true;
  if (args.skipStatic) config.skipStatic = true;
  // —— 行范围导出 + 保活探测（对标 sqlmap --start/--stop/--safe-url/--safe-freq）——
  if (args.startRow > 0) config.dumpStart = Math.min(args.startRow, 1000000);
  if (args.stopRow > 0) config.dumpStop = Math.min(args.stopRow, 1000000);
  if (args.safeUrl && /^https?:\/\//i.test(args.safeUrl)) {
    config.safeUrl = args.safeUrl;
    config.safeFreq = args.safeFreq > 0 ? args.safeFreq : 1;
  }
  // [sqlmap 对标 2026-09-14] CSRF 会话层
  if (args.csrfUrl && /^https?:\/\//i.test(args.csrfUrl)) {
    config.csrfUrl = args.csrfUrl;
    if (args.csrfTokenName) config.csrfTokenName = args.csrfTokenName;
    if (args.csrfMethod) config.csrfMethod = args.csrfMethod;
    if (args.csrfRefreshFreq > 0) config.csrfRefreshFreq = Math.min(args.csrfRefreshFreq, 10000);
  if (Array.isArray(args.skipParams) && args.skipParams.length) config.skipParams = args.skipParams.slice(0, 64);
  }
  // --tor：Tor 本地代理（默认 socks5://127.0.0.1:9050）；已设 --proxy 时不覆盖
  if (args.tor && !config.proxy) config.proxy = 'socks5://127.0.0.1:9050';
  // --mobile：随机移动端 UA 池
  if (args.mobile) config.wafEvasion = { ...(config.wafEvasion || {}), randomUA: 'mobile' };
  // [对标 sqlmap --random-agent] 随机桌面/移动 UA（--mobile 更窄，两者都给时 --mobile 优先）
  if (args.randomAgent && !args.mobile) config.wafEvasion = { ...(config.wafEvasion || {}), randomUA: 'desktop' };
  // [对标 sqlmap --where] 拖库条件过滤（透传 extractScope → dumpData opts.where）
  if (args.where) config.dumpWhere = String(args.where);
  // [对标 sqlmap --param-del] 自定义参数分隔符（TargetParser 按该分隔符切 query）
  if (args.paramDel) config.paramDel = String(args.paramDel).slice(0, 1);
  // —— HTTP 协议层（对标 sqlmap --force-ssl / --ignore-redirects / --hpp）——
  // forceSsl：目标 http:// 强制升级 https（对标 sqlmap --force-ssl，httpClient.request 消费）
  if (args.forceSsl) config.forceSsl = true;
  // ignoreRedirects：不跟随 3xx 跳转，直接返回跳转响应（对标 sqlmap --ignore-redirects；
  // httpClient.request 消费——跳转上限置 0。注意：目标本身上行 302 到登录页等场景会因此
  // 看到 3xx 而非最终页，检测判定以状态码/头为准时需知悉）
  if (args.ignoreRedirects) config.ignoreRedirects = true;
  // hpp：注入参数双份提交（query+body 同名，对标 sqlmap --hpp 的 WAF 绕过形态，
  // buildInjectionRequest 消费——仅注入请求生效，基线请求不污染）
  if (args.hpp) config.hpp = true;
  // parseErrors：解析错误响应原文 + SQL 上下文进证据链（对标 sqlmap --parse-errors，
  // ErrorDetector 消费，opt-in 默认关闭）
  if (args.parseErrors) config.parseErrors = true;
  // —— 对标 sqlmap 增强参数透传（引擎消费同名字段）——
  if (args.randomUA) config.randomUA = true;
  if (args.flushSession) config.flushSession = true;
  if (args.freshQueries) config.freshQueries = true;
  if (args.noCast) config.noCast = true;
  // [对标 sqlmap --hex] 字符常量十六进制化：作用于 --search 的 LIKE 模式
  //   （Extractor.searchColumnData → hexLiteral.buildLikePattern）。
  //   仅 MySQL/MariaDB/TiDB/SQLServer/PostgreSQL/SQLite 有明确写法，其余方言提取时告警并回退。
  if (args.hex) config.hex = true;
  if (args.unionCols) config.unionCols = String(args.unionCols).slice(0, 16);
  if (args.unionFrom) config.unionFrom = String(args.unionFrom).slice(0, 100);
  // 注：--no-escape / --union-char 已移除（原为"保留接口"= 收参数不生效）。
  //   --union-char 若要实现，需改 marker.js 的 MARKER_RE 与 tamper 保护链（P0-D3 高危区），
  //   评估后判定风险 > 收益；--no-escape 与本项目的转义实现不同源，语义无法对齐。
  return config;
}

// 是否处于枚举模式（任一枚举开关开启）
export function isEnumMode(args) {
  return !!(args.dbs || args.tables || args.columns || args.currentDb || args.currentUser || args.count || args.users || args.passwords || args.hostname || args.isDba || args.schema || args.privileges || args.roles || !!args.search
    || args.dumpAll || args.commonTables || args.commonColumns);
}

// 构造 extractScope（对标 sqlmap 枚举模式）：
//   --dbs            → { mode:'dbs' }
//   --tables  -D db  → { mode:'tables', dbs:[db] }
//   --columns -D db -T t → { mode:'columns', dbs:[db], tables:[t] }
//   --dump    -D db [-T t] [-C a,b] → { mode:'dump', dbs:[db], tables?:[t], cols?:[a,b] }
//   --current-db     → { mode:'currentDb' }
//   --current-user   → { mode:'currentUser' }
//   --users          → { mode:'users' }
//   --passwords      → { mode:'passwords' }
//   --hostname       → { mode:'hostname' }
//   --is-dba         → { mode:'isDba' }
//   --schema -D db -T t → { mode:'schema', dbs:[db], tables:[t] }
//   --privileges     → { mode:'privileges' }
//   --roles          → { mode:'roles' }
//   --count   -D db -T t → { mode:'count', dbs:[db], tables:[t] }
// 无枚举开关返回 undefined（--dump 走既有全量拖库分支）
export function buildExtractScope(args) {
  const ex = scope => ({ excludeSysdbs: args.excludeSysdbs !== false, ...scope });
  // 全库拖库优先（对标 sqlmap --dump-all：忽略 -D/-T，直接枚举全部库并拖）
  if (args.dumpAll) return ex({ mode: 'dumpAll' });
  // 字典爆破：表名/列名（对标 sqlmap --common-tables / --common-columns）
  // information_schema 不可用时（WAF 拦截 / 权限不足 / 非 MySQL）继续推进枚举的唯一路径。
  if (args.commonTables) return ex({ mode: 'commonTables', dbs: args.db ? [args.db] : [] });
  if (args.commonColumns) return ex({ mode: 'commonColumns', dbs: args.db ? [args.db] : [], tables: args.table ? [args.table] : [] });
  if (args.search) return ex({ mode: 'search', keyword: args.search });
  if (args.dbs) return ex({ mode: 'dbs' });
  if (args.tables) return ex({ mode: 'tables', dbs: args.db ? [args.db] : (args.excludeSysdbs ? [] : []) });
  if (args.columns) return ex({ mode: 'columns', dbs: args.db ? [args.db] : (args.excludeSysdbs ? [] : []), tables: args.table ? [args.table] : [] });
  if (args.currentDb) return ex({ mode: 'currentDb' });
  if (args.currentUser) return ex({ mode: 'currentUser' });
  if (args.users) return ex({ mode: 'users' });
  if (args.passwords) return ex({ mode: 'passwords' });
  if (args.hostname) return ex({ mode: 'hostname' });
  if (args.isDba) return ex({ mode: 'isDba' });
  if (args.schema) return ex({ mode: 'schema', dbs: args.db ? [args.db] : [], tables: args.table ? [args.table] : [] });
  if (args.privileges) return ex({ mode: 'privileges' });
  if (args.roles) return ex({ mode: 'roles' });
  if (args.count) return ex({ mode: 'count', dbs: args.db ? [args.db] : (args.excludeSysdbs ? [] : []), tables: args.table ? [args.table] : [] });
  if (args.dump && (args.db || args.table || args.columnsList)) {
    return ex({
      mode: 'dump',
      dbs: args.db ? [args.db] : [],
      tables: args.table ? [args.table] : [],
      cols: args.columnsList ? String(args.columnsList).split(',').map(s => s.trim()).filter(Boolean) : undefined,
    });
  }
  return undefined;
}

// 校验枚举参数组合（对标 sqlmap 用法约束）；非法返回错误串，合法返回 null。
export function validateEnumArgs(args) {
  if (args.tables && !args.db) return '使用 --tables 需指定数据库：-D <dbname>';
  if (args.columns && (!args.db || !args.table)) return '使用 --columns 需指定：-D <dbname> -T <table>';
  if (args.count && (!args.db || !args.table)) return '使用 --count 需指定：-D <dbname> -T <table>';
  if (args.schema && (!args.db || !args.table)) return '使用 --schema 需指定：-D <dbname> -T <table>';
  if (args.columnsList && !args.table) return '使用 -C/--columns-list 需配合 -T <table>';
  if (args.columnsList && !args.dump) return '-C/--columns-list 仅在 --dump 模式下生效';
  return null;
}
