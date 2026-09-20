// ============================================================================
// args.js —— CLI 输入解析族（参数 / 请求文件 / 代理日志 / 头与认证）
//
// 从 bin/cli.js 抽离，[拆上帝对象 2026-09-14]。抽离依据：这组符号的依赖**完全闭环在族内**，
// 族外依赖为 0（族内仅 applyRequestFile→bodyToJsonString、buildAuth→parseAuth/parseHeaders）。
//
// cli.js 会再导出其中的公开符号 —— 8 个测试文件从 '../bin/cli.js' 导入这些函数，
// 保持导入路径不变是硬约束。
// ============================================================================
import { readFileSync, existsSync } from 'node:fs';
import { parseRequestFile } from '../../src/core/requestFileParser.js';
import { logger } from '../../src/core/logger.js';
import { tamperRegistry } from '../../src/core/tamper/TamperRegistry.js';
import path from 'node:path';
import { pathToFileURL } from 'node:url';


export function parseArgs(argv) {
  /** @type {any} */
  const args = {
    url: null, batch: null, method: 'GET', body: null, cookie: null, headers: null,
    format: 'json', out: null, timeoutMs: 0, concurrency: 1, help: false,
    technique: null, level: null, risk: null, dump: false, tamper: null, proxy: null, auth: null,
    // —— 授权范围 / 传输安全 / 输入校验跳过（[P0-SEC 2026-09-09] 对应引擎新增三能力）——
    scope: null, insecureTls: false, noValidationSkip: false,
    // [P0-FIX 2026-09-09] 生产护栏开关：高危池投放确认 / 脱离护栏 / 二阶写请求放行
    confirmDestructive: false, noProductionMode: false, allowSecondOrderWrites: false,
    // —— HTTP 协议层（对标 sqlmap --force-ssl / --ignore-redirects / --hpp）——
    forceSsl: false, ignoreRedirects: false, hpp: false,
    ratePerSec: 50, concurrencyDet: 4,
    direct: null, sqlTemplate: null, driverType: null,
    // —— 枚举模式（对标 sqlmap）——
    dbs: false, tables: false, columns: false,
    db: null, table: null, columnsList: null,
    currentDb: false, currentUser: false, count: false,
    users: false, passwords: false,
    hostname: false, isDba: false, schema: false, privileges: false, roles: false,
    search: null, // --search <keyword>
    excludeSysdbs: true,
    smart: false,
    requestFile: null, // 对标 sqlmap -r：从请求文件导入
    logFile: null,     // 对标 sqlmap -l：从代理/Burp 日志批量导入请求
    // —— 注入点扩展开关（本期新增，默认关闭，零回归）——
    // --test-headers：把显式传入的请求头（--header / -r 解析的 headerObj）作为注入点
    //   （引擎 TargetParser 早已支持 header/cookie 注入点，此前 CLI 从未填充这些字段，
    //   导致 Cookie / X-Forwarded-For 等真实注入点被完全跳过）。
    // --test-path：把 URL path 末段作为注入点（path 型注入点）。
    testHeaders: false,
    testPath: false,
    checkTor: false,   // 对标 sqlmap --check-tor：校验 Tor 出口后继续
    // —— 攻击操作（对标 sqlmap --os-cmd/--sql-shell/--file-read/--file-write；需 EXPLOIT_ENABLED=1）——
    osCmd: null, sqlShell: null, fileRead: null, fileWrite: null, fileDest: null,
    // —— 强制 DBMS / 二阶触发页 / 授权声明 ——
    dbms: null, secondOrderUrl: null, authorized: false,
    dumpAll: false, identifyWaf: false, commonTables: null, commonColumns: null,
    randomAgent: false, where: null, paramDel: null,
    // 内部：从请求文件解析出的 header 对象（buildAuth 直接使用）
    headerObj: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    // peekValue：可选值参数——下一参数存在且不以 -- 开头时取值，否则返回 null（布尔开关语义）
    const peekValue = () => {
      const v = argv[i + 1];
      return v != null && !v.startsWith('--') ? argv[++i] : null;
    };
    if (a === '-r' || a === '--request-file') args.requestFile = next();
    else if (a === '-l' || a === '--log-file') args.logFile = next();
    else if (a === '--check-tor') args.checkTor = true;
    // —— 攻击操作（对标 sqlmap --os-cmd/--sql-shell/--file-read/--file-write）——
    // --sql-shell / --os-shell：带值=单次执行；不带值（或值以 -- 开头）= 交互式 REPL（对标 sqlmap 同名参数）
    else if (a === '--os-cmd') args.osCmd = next();
    else if (a === '--sql-shell') args.sqlShell = peekValue() ?? true;
    else if (a === '--os-shell') args.osShell = peekValue() ?? true;
    else if (a === '--file-read') args.fileRead = next();
    else if (a === '--file-write') args.fileWrite = next();
    else if (a === '--file-dest') args.fileDest = next();
    else if (a === '--udf-hex') args.udfHex = next();
    else if (a === '--udf-install') args.udfInstall = true;
    // —— 强制 DBMS / 二阶触发页 / 授权声明 ——
    else if (a === '--dbms') args.dbms = next();
    else if (a === '--second-order') args.secondOrderUrl = next();
    else if (a === '--authorized') args.authorized = true;
    else if (a === '-u' || a === '--url') args.url = next();
    else if (a === '-d' || a === '--direct') args.direct = next();
    else if (a === '--sql-template') args.sqlTemplate = next();
    else if (a === '--driver') args.driverType = next();
    else if (a === '-m' || a === '--batch') args.batch = next();
    else if (a === '--method') args.method = next();
    else if (a === '--body') args.body = next();
    else if (a === '--cookie') args.cookie = next();
    else if (a === '--header' || a === '--headers') args.headers = next();
    else if (a === '--technique') args.technique = next();
    // [P0 2026-09-09 实战批次] 失效值替换 + 已知注入点直通（对标 sqlmap --invalid-*）
    else if (a === '--invalid-bignum') args.invalidBignum = true;
    else if (a === '--invalid-logical') args.invalidLogical = true;
    else if (a === '--invalid-string') args.invalidString = true;
    else if (a === '--known-point') args.knownPoint = next();
    else if (a === '--level') args.level = Number(next()) || null;
    else if (a === '--risk') args.risk = Number(next()) || null;
    else if (a === '--test-filter') args.testFilter = next();
    else if (a === '--test-skip') args.testSkip = next();
    // —— 注入点扩展开关（本期新增，默认关闭，零回归）——
    else if (a === '--test-headers') args.testHeaders = true;
    else if (a === '--test-path') args.testPath = true;
    // —— 扫描前风险评估（--advise）：只打印建议，不执行；配 --yes 才继续扫描 ——
    else if (a === '--advise') args.advise = true;
    else if (a === '--yes') args.yes = true;
    // 极高危专用：`--yes` 不够，必须再加本开关（防把「我看过建议」当成「我接受后果」）
    else if (a === '--confirm-extreme') args.confirmExtreme = true;
    else if (a === '--use-registry') args.useRegistry = true;
    else if (a === '--dump') args.dump = true;
    // [对标 sqlmap --dump-all] 全库拖库（枚举所有库 → 逐库逐表拖）
    else if (a === '--dump-all') args.dumpAll = true;
    // [对标 sqlmap --identify-waf] 主动识别 WAF 厂商并给出推荐 tamper 链（不触发注入检测）
    else if (a === '--identify-waf') args.identifyWaf = true;
    // [对标 sqlmap --common-tables / --common-columns] 字典爆破表名/列名
    //   （information_schema 被 WAF 拦 / 权限不足 / 非 MySQL 时的唯一出路）
    else if (a === '--common-tables') args.commonTables = '1';
    else if (a === '--common-columns') args.commonColumns = '1';
    // [对标 sqlmap --random-agent] 每次请求从 UA 池随机取（含桌面 + 移动端）
    else if (a === '--random-agent') args.randomAgent = true;
    // [对标 sqlmap --where] 拖库条件过滤（仅 --dump / --dump-all 生效）
    else if (a === '--where') args.where = next();
    // [对标 sqlmap --param-del] 自定义参数分隔符（默认 &，用于 a=1;b=2 这类非标准站点）
    else if (a === '--param-del') args.paramDel = next();
    else if (a === '--tamper') args.tamper = next();
    else if (a === '--proxy') args.proxy = next();
    else if (a === '--scope') args.scope = next();
    else if (a === '--insecure') args.insecureTls = true;
    else if (a === '--no-validation-skip') args.noValidationSkip = true;
    else if (a === '--confirm-destructive') args.confirmDestructive = true;
    else if (a === '--no-production-mode') args.noProductionMode = true;
    else if (a === '--allow-second-order-writes') args.allowSecondOrderWrites = true;
    else if (a === '--auth') args.auth = next();
    else if (a === '--auth-type') args.authType = next();
    else if (a === '--rate' || a === '--ratePerSec') args.ratePerSec = Number(next()) || 50;
    else if (a === '--threads' || a === '--concurrency-det') args.concurrencyDet = Number(next()) || 4;
    else if (a === '--format' || a === '-f') args.format = next();
    else if (a === '--out' || a === '-o') args.out = next();
    else if (a === '--timeout') args.timeoutMs = Number(next()) || 0;
    else if (a === '--concurrency' || a === '-c') args.concurrency = Number(next()) || 1;
    // —— HTTP 协议层（对标 sqlmap --force-ssl / --ignore-redirects / --hpp）——
    else if (a === '--force-ssl') args.forceSsl = true;
    else if (a === '--ignore-redirects') args.ignoreRedirects = true;
    else if (a === '--hpp') args.hpp = true;
    else if (a === '--parse-errors') args.parseErrors = true;
    else if (a === '-h' || a === '--help') args.help = true;
    // —— 枚举模式（对标 sqlmap --dbs/--tables/--columns/--dump/-D/-T/-C/...）——
    else if (a === '--dbs') args.dbs = true;
    else if (a === '--tables') args.tables = true;
    else if (a === '--columns') args.columns = true;
    else if (a === '-D' || a === '--db') args.db = next();
    else if (a === '-T' || a === '--table') args.table = next();
    else if (a === '-C' || a === '--columns-list') args.columnsList = next();
    else if (a === '--current-db') args.currentDb = true;
    else if (a === '--current-user') args.currentUser = true;
    else if (a === '--users') args.users = true;
    else if (a === '--passwords') args.passwords = true;
    else if (a === '--hostname') args.hostname = true;
    else if (a === '--is-dba') args.isDba = true;
    else if (a === '--schema') args.schema = true;
    else if (a === '--privileges') args.privileges = true;
    else if (a === '--roles') args.roles = true;
    else if (a === '--count') args.count = true;
    else if (a === '--exclude-sysdbs') args.excludeSysdbs = true;
    else if (a === '--no-exclude-sysdbs') args.excludeSysdbs = false;
    else if (a === '--proxy-bypass-local') args.proxyBypassLocal = true;
    else if (a === '--no-proxy-bypass-local') args.proxyBypassLocal = false;
    else if (a === '--search') args.search = next();
    else if (a === '--smart') args.smart = true;
    // —— 高级检测参数（对标 sqlmap 页面匹配/注入上下文）——
    else if (a === '--prefix') args.prefix = next();
    else if (a === '--suffix') args.suffix = next();
    else if (a === '--string') args.string = next();
    else if (a === '--not-string') args.notString = next();
    else if (a === '--code') args.code = Number(next()) || null;
    else if (a === '--text-only') args.textOnly = true;
    else if (a === '--titles') args.titles = true;
    else if (a === '--regexp') args.regexp = next();
    // —— 爬虫/表单/会话/延迟等高级参数（对标 sqlmap）——
    else if (a === '--forms') args.forms = true;
    else if (a === '--crawl') args.crawl = Number(next()) || 1;
    else if (a === '--session-file') args.sessionFile = next();
    else if (a === '--time-sec') args.timeSec = Number(next()) || null;
    // 注意：--delay 是毫秒级随机抖动（wafEvasion.jitterMs，WAF 规避）；
    // 固定请求间隔（秒）用 --delay-sec（对应 config.delay，对标 sqlmap --delay）。
    else if (a === '--delay') args.delay = Number(next()) || 0;
    else if (a === '--delay-sec') args.delaySec = Number(next()) || 0;
    else if (a === '--max-requests') args.maxRequests = Number(next()) || 0;
    else if (a === '--req-rate') args.reqRate = Number(next()) || 0;
    else if (a === '--predict-output') args.predictOutput = true;
    else if (a === '--skip-static') args.skipStatic = true;
    // —— 行范围导出 + 保活探测（对标 sqlmap --start/--stop/--safe-url/--safe-freq）——
    else if (a === '--start') args.startRow = Number(next()) || 0;
    else if (a === '--stop') args.stopRow = Number(next()) || 0;
    else if (a === '--safe-url') args.safeUrl = next();
    else if (a === '--safe-freq') args.safeFreq = Number(next()) || 0;
  // —— CSRF 会话层（对标 sqlmap --csrf-url/--csrf-token）——
  else if (a === '--csrf-url') args.csrfUrl = next();
  else if (a === '--csrf-token') args.csrfTokenName = next();
  else if (a === '--csrf-method') args.csrfMethod = String(next()).toUpperCase();
  else if (a === '--csrf-refresh') args.csrfRefreshFreq = Number(next()) || 50;
  else if (a === '--skip') args.skipParams = String(next()).split(',').map((s) => s.trim()).filter(Boolean);
    // —— 对标 sqlmap 最后两个参数（--tor/--mobile）——
    else if (a === '--tor') args.tor = true;
    else if (a === '--mobile') args.mobile = true;
    // —— 对标 sqlmap 增强参数（不改变引擎行为，仅控制采样/编码）——
    else if (a === '--random-agent') args.randomUA = true;
    else if (a === '--flush-session') args.flushSession = true;
    else if (a === '--fresh-queries') args.freshQueries = true;
    else if (a === '--no-cast') args.noCast = true;
    else if (a === '--hex') args.hex = true;
    else if (a === '--union-cols') args.unionCols = next();
    else if (a === '--union-from') args.unionFrom = next();
    // --no-escape / --union-char：已移除（详见 buildConfig 尾部注释）。
    // 保留显式识别并给出可操作提示，避免用户以为"传了没生效"而反复排查。
    else if (a === '--no-escape' || a === '--union-char') {
      const flag = a;
      if (a === '--union-char') next(); // 吃掉它的值，避免被当成 URL
      console.error(
        `[warn] ${flag} 暂不支持（本项目未实现，原 help 标注的"保留接口"已移除）：` +
          '--union-char 涉及 tamper 标记保护链改造，--no-escape 与本项目转义实现不同源。' +
          '参数已被忽略，扫描继续。'
      );
    }
  }
  return args;
}


export function readUrlList(filePath) {
  if (!existsSync(filePath)) { console.error(`文件不存在: ${filePath}`); process.exit(1); }
  const content = readFileSync(filePath, 'utf-8');
  return content.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
}

// 对标 sqlmap -l：从代理/Burp 日志文件批量提取请求。
// 支持两种常见格式（无法识别时整文件按单请求文本尝试）：
//   ① 纯文本多请求：连续的多段 "METHOD URL HTTP/1.1 ..."（Burp 剪贴板 / 代理 txt 日志），
//      请求行可带时间戳/前缀（如 "2026-09-01 12:00:00 GET https://... HTTP/1.1"）
//   ② Burp XML 导出（items 列表，按 <url>/<method> 提取，payload 从 url/body 注入）
// 返回 [{ url, method, headers, body }]，解析失败返回空数组。
export const REQ_LINE_RE = /(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/\d/i;
export function parseLogFile(filePath) {
  if (!existsSync(filePath)) {
    console.error(`日志文件不存在: ${filePath}`);
    return [];
  }
  const text = readFileSync(filePath, 'utf-8');
  // —— Burp XML：优先识别 ——
  if (/<items|<item\b|<burp/i.test(text)) {
    const out = [];
    const itemRe = /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
    let m;
    while ((m = itemRe.exec(text)) !== null) {
      const block = m[1];
      const urlMatch = block.match(/<url><!\[CDATA\[([^\]]*)\]\]><\/url>|<url>([^<]*)<\/url>/i);
      const methodMatch = block.match(/<method><!\[CDATA\[([^\]]*)\]\]><\/method>|<method>([^<]*)<\/method>/i);
      const url = urlMatch ? (urlMatch[1] || urlMatch[2] || '').trim() : '';
      if (!/^https?:\/\//i.test(url)) continue;
      const method = (methodMatch ? (methodMatch[1] || methodMatch[2] || '') : 'GET').toUpperCase();
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) continue;
      out.push({ url, method, headers: {}, body: null });
    }
    return out;
  }
  // —— 纯文本多请求：按请求行切分，剥时间戳/前缀重建规范请求行 ——
  const lines = text.split(/\r?\n/);
  const segments = [];
  let cur = [];
  let curReqLine = null;
  for (const line of lines) {
    const m = line.match(REQ_LINE_RE);
    if (m) {
      if (curReqLine && cur.length > 0) {
        segments.push([curReqLine, ...cur].join('\n'));
        cur = [];
      }
      curReqLine = `${m[1]} ${m[2]} HTTP/1.1`;
    } else {
      cur.push(line);
    }
  }
  if (curReqLine) segments.push([curReqLine, ...cur].join('\n'));
  const out = [];
  for (const seg of segments) {
    const parsed = parseRequestFile(seg);
    if (parsed && /^https?:\/\//i.test(parsed.url)) {
      out.push({
        url: parsed.url,
        method: parsed.method,
        headers: parsed.headers || {},
        body: parsed.body || null,
      });
    }
  }
  return out;
}

// 对标 sqlmap --check-tor：通过 Tor 本地代理访问检测端点，确认出口为 Tor 节点。
// 返回 true=出口为 Tor（可继续扫描）；false=不可用（调用方应退出）。
export async function checkTor(proxyUrl) {
  const { HttpClient } = await import('../../src/core/httpClient.js');
  const client = new HttpClient();
  try {
    console.error(`[tor] 通过代理 ${proxyUrl} 检测 Tor 出口…`);
    const res = await client.request({
      url: 'https://check.torproject.org/',
      proxy: proxyUrl,
      timeoutMs: 15000,
      retry: 0,
      headers: {},
    });
    const body = String(res?.data ?? '');
    const isTor = /congratulations/i.test(body);
    if (isTor) {
      console.error('[tor] ✓ 出口为 Tor 节点，匿名化生效');
      return true;
    }
    console.error('[tor] ✗ 出口不是 Tor 节点（代理可能未生效或未走 Tor）');
    return false;
  } catch (e) {
    console.error(`[tor] ✗ 无法通过代理访问检测端点：${e?.message || e}`);
    return false;
  } finally {
    try { client.close?.(); } catch { /* ignore */ }
  }
}

// 对标 sqlmap --tamper=path/to/script.py：支持自定义 tamper 文件。
// 本项目插件为 JS 模块（{ name, transform(payload, ctx) }），文件以 .js 结尾且存在时动态加载
// 并注册到 TamperRegistry，返回插件名；非文件值（内置插件名）原样返回。加载失败返回空数组。
export async function resolveTamperPlugins(tamperArg) {
  const parts = String(tamperArg).split(',').map(s => s.trim()).filter(Boolean);
  const out = [];
  for (const p of parts) {
    if (p.endsWith('.js')) {
      if (!existsSync(p)) {
        logger.warn(`[tamper] 自定义插件文件不存在: ${p}，已忽略`);
        continue;
      }
      try {
        const mod = await import(pathToFileURL(path.resolve(p)).href);
        const plugin = mod.default || Object.values(mod)[0];
        if (plugin && typeof plugin.transform === 'function') {
          const name = plugin.name || path.basename(p, '.js');
          tamperRegistry.register({ name, description: plugin.description || `自定义 tamper: ${p}`, transform: plugin.transform });
          out.push(name);
          logger.info(`[tamper] 已加载自定义插件 ${name} ← ${p}`);
        } else {
          logger.warn(`[tamper] 自定义插件 ${p} 缺少 transform 函数，已忽略`);
        }
      } catch (e) {
        logger.warn(`[tamper] 自定义插件加载失败 ${p}: ${e.message}`);
      }
    } else {
      out.push(p);
    }
  }
  return out;
}

// 解析 --header "k:v,k:v" → auth.headers 对象
export function parseHeaders(str) {
  if (!str) return undefined;
  const out = {};
  for (const pair of String(str).split(',')) {
    const idx = pair.indexOf(':');
    if (idx <= 0) continue;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return Object.keys(out).length ? out : undefined;
}

// 解析 --auth "user:pass" → auth.basic（--auth-type 决定 scheme）
// 对标 sqlmap --auth-type=Basic|Digest|NTLM|PKI：默认 Basic（既有行为）；
// Digest → 标 type:'digest'（httpClient 走 RFC 7616 挑战-响应）；
// NTLM/PKI → 返回带标记但 httpClient 未实现，CLI 层报错提示（见 buildAuth）。
export function parseAuth(str, type) {
  const t = type ? String(type).toLowerCase() : 'basic';
  if (t !== 'basic' && t !== 'digest') {
    return { unsupported: true, type: t };
  }
  if (!str) return undefined;
  const idx = str.indexOf(':');
  const cred = idx < 0
    ? { username: str, password: '' }
    : { username: str.slice(0, idx), password: str.slice(idx + 1) };
  if (t === 'digest') return { digest: cred };
  return { basic: cred };
}

// 请求 body → JSON 字符串（runSingleScan 用 JSON.parse 消费）
// 支持 JSON 与 form-urlencoded 两种形态；无法转换返回 null
// 注：这里只负责"变成字符串"。嵌套 JSON 走 jsonBody 还是扁平走 bodyParams，
// 由 runSingleScan 的 [JSON-BODY-FIX] 判定——-r 导入的抓包里嵌套 body 很常见，
// 所以这个判定必须留在消费侧，不能在两处各写一份。
export function bodyToJsonString(body) {
  if (!body) return null;
  try { return JSON.stringify(JSON.parse(body)); } catch { /* fallthrough */ }
  if (body.includes('=')) {
    const out = {};
    for (const pair of body.split('&')) {
      const idx = pair.indexOf('=');
      if (idx > 0) {
        const k = decodeURIComponent(pair.slice(0, idx));
        const v = decodeURIComponent(pair.slice(idx + 1));
        if (k) out[k] = v;
      }
    }
    if (Object.keys(out).length) return JSON.stringify(out);
  }
  return null;
}

// 对标 sqlmap -r：读取请求文件 → 解析 → 覆盖 args 的 url/method/body/headers/cookie
// 返回 null 表示文件读取或解析失败（调用方应退出并报错）
export function applyRequestFile(args) {
  if (!args.requestFile) return args;
  if (!existsSync(args.requestFile)) {
    console.error(`请求文件不存在: ${args.requestFile}`);
    return null;
  }
  const parsed = parseRequestFile(readFileSync(args.requestFile, 'utf-8'));
  if (!parsed) {
    console.error(`请求文件解析失败（需为 Burp/curl 文本 HTTP 请求格式）: ${args.requestFile}`);
    return null;
  }
  args.url = parsed.url;
  if (parsed.method === 'HEAD' || parsed.method === 'OPTIONS' || parsed.method === 'TRACE' || parsed.method === 'CONNECT') {
    // MethodType 仅支持 GET/POST/PUT/PATCH/DELETE，越界方法回退 GET
    args.method = 'GET';
  } else {
    args.method = parsed.method;
  }
  const bodyJson = bodyToJsonString(parsed.body);
  if (bodyJson) args.body = bodyJson;
  // Cookie 头 → args.cookie；其余请求头 → args.headerObj
  const cookieKey = Object.keys(parsed.headers).find(k => k.toLowerCase() === 'cookie');
  if (cookieKey) args.cookie = parsed.headers[cookieKey];
  const other = {};
  for (const [k, v] of Object.entries(parsed.headers)) {
    const kl = k.toLowerCase();
    if (kl === 'cookie' || kl === 'host' || kl === 'content-length') continue; // Host/CL 由引擎按 URL/body 重建
    other[k] = v;
  }
  if (Object.keys(other).length) args.headerObj = other;
  return args;
}

// 合并 --cookie / --header / --auth / --proxy → auth 对象
export function buildAuth(args) {
  /** @type {any} */ let auth = undefined;
  if (args.cookie) auth = { ...auth, cookie: args.cookie };
  // 请求文件解析出的 header 对象优先（值可能含逗号，避免被 parseHeaders 截断）
  if (args.headerObj) auth = { ...auth, headers: { ...(auth?.headers || {}), ...args.headerObj } };
  else if (args.headers) auth = { ...auth, headers: parseHeaders(args.headers) };
  if (args.auth) {
    const pa = parseAuth(args.auth, args.authType);
    if (pa && pa.unsupported) {
      throw new Error(`--auth-type=${args.authType} 暂不支持（本引擎仅 Basic/Digest；NTLM 需 Type1-3 协商未实现）`);
    }
    auth = { ...auth, ...(pa || {}) };
    if (args.authType && String(args.authType).toLowerCase() !== 'basic') {
      auth.type = String(args.authType).toLowerCase();
    }
  }
  return auth;
}
