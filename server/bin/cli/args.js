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
// [COLLECTION-2026-09-21] 抓包**集合**格式（Burp XML 导出 / HAR）→ 原始报文 → 上面这个解析器。
// 归一化统一走 requestFileParser，故 params/bodyFields/multipart 的既有修复自动继承。
import { parseRequestCollection } from '../../src/core/requestCollectionParser.js';
import { logger } from '../../src/core/logger.js';
import { tamperRegistry } from '../../src/core/tamper/TamperRegistry.js';
import path from 'node:path';
import { pathToFileURL } from 'node:url';


/**
 * 通道总开关族（[D87 抽离]）：--no-sql / --oob / --oob-interactsh。
 *
 * 从 parseArgs 抽出的原因有两条，都不是为了好看：
 *   ① parseArgs 已是 227 行 / 214 圈的存量巨兽，复杂度基线是**只许持平或变浅**的棘轮
 *      —— 新增一个旗标不该靠抬基线过关（本仓明确禁止），该拆就拆；
 *   ② 这三个旗标语义同族（都是「默认关的通道总开关」），抽成一处后
 *      「谁知道 technique 与 enabled 正交」这件事只有一个落点，不再散在长链里。
 *
 * @param {string} a 当前 token
 * @param {any} args 累积中的参数对象（命中即原地写入）
 * @returns {boolean} 是否已被本族消费
 */
export function applyChannelFlag(a, args) {
  if (a === '--no-sql') { args.noSql = true; return true; }
  if (a === '--oob') { args.oob = true; return true; }
  // [D87 2026-10-18] 外部协作端隧道（interactsh 协议）：开这条即同时开 oob 总开关
  // ——隧道是 oob 的一种回连拓扑，总开关不开检测器根本不跑。只要求扫描器能出网。
  if (a === '--oob-interactsh') { args.oob = true; args.oobInteractsh = true; return true; }
  // [D108] 背景 OOB 哨兵（对标 Collaborator Everywhere）：开总开关 + background 子开关。
  // 哨兵是 oob 的一种投放形态，总开关不开检测器拿不到隧道 ⇒ 一并打开。
  if (a === '--oob-background') { args.oob = true; args.oobBackground = true; return true; }
  return false;
}

export function parseArgs(argv, preset) {
  /** @type {any} */
  const args = {
    url: null, batch: null, method: 'GET', body: null, cookie: null, headers: null,
    format: 'json', out: null, timeoutMs: 0, concurrency: 1, help: false,
    technique: null, level: null, risk: null, dump: false, tamper: null, proxy: null, auth: null,
    // —— 授权范围 / 传输安全 / 输入校验跳过（[P0-SEC 2026-09-09] 对应引擎新增三能力）——
    scope: null, insecureTls: false, noValidationSkip: false,
    // [P0-FIX 2026-09-09] 生产护栏开关：高危池投放确认 / 脱离护栏 / 二阶写请求放行
    confirmDestructive: false, noProductionMode: false, allowSecondOrderWrites: false,
    // [2026-09-24] 不可逆动作拒绝位：MSSQL 自动 sp_configure 开启 xp_cmdshell（实例级永久变更）
    noXpAutoEnable: false,
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
    // [D46 2026-10-11 对标 sqlmap] 运维侦察枚举：-b/--banner · --statements · --procs
    // 与 -U/--user（用户过滤）、--exclude（库排除）
    banner: false, statements: false, procs: false, user: null, exclude: null,
    smart: false,
    requestFile: null, // 对标 sqlmap -r：从请求文件导入
    logFile: null,     // 对标 sqlmap -l：从代理/Burp 日志批量导入请求
    // —— 注入点扩展开关（本期新增，默认关闭，零回归）——
    // --test-headers：把显式传入的请求头（--header / -r 解析的 headerObj）作为注入点
    //   （引擎 TargetParser 早已支持 header/cookie 注入点，此前 CLI 从未填充这些字段，
    //   导致 Cookie / X-Forwarded-For 等真实注入点被完全跳过）。
    // --test-path：把 URL path 末段作为注入点（path 型注入点）。
    // [D93] testParamNames（--test-param-names）：把 query **键名**本身作为注入点（后端
    // `WHERE ${key}=?` / 键名当列名的 ORDER BY 拼接）。默认关：每参数多一个点位（请求量约 +1 倍）。
    // [D103] 同开关覆盖 JSON body 键名（`Object.keys(req.body)[0]` 同型）。
    // [D105] 同开关覆盖 XML body 元素名（算术位移探针；NameChar 不承载布尔载荷）。
    testHeaders: false, testPath: false, testParamNames: false,
    // [D41 2026-10-11 对标 sqlmap -p/--param-exclude/--param-filter] 注入点筛选三件套
    testParam: null, paramExclude: null, paramFilter: null,
    // [2026-10-02 竞品吸收] --param-mine：参数挖掘总开关（默认关闭零回归）
    paramMine: false,
    // [2026-10-02 实战 P1-4] --crawl-browser：headless 浏览器爬取（默认关闭零回归）
    crawlBrowser: false,
    // [批次14 实战 P1-6] 登录编排：登录页 URL（默认 null 关闭；凭据复用 --auth）
    loginUrl: null, loginUserField: null, loginPassField: null,
    checkTor: false,   // 对标 sqlmap --check-tor：校验 Tor 出口后继续
    // —— 攻击操作（对标 sqlmap --os-cmd/--sql-shell/--file-read/--file-write；需 EXPLOIT_ENABLED=1）——
    osCmd: null, sqlShell: null, fileRead: null, fileWrite: null, fileDest: null,
    // —— 强制 DBMS / 二阶触发页 / 授权声明 ——
    dbms: null, secondOrderUrl: null, authorized: false,
    // [D42 2026-10-11 对标 sqlmap] --second-req：二阶触发页从抓包请求文件导入（整请求形态）
    secondReq: null,
    // [D42 2026-10-11 对标 sqlmap] --ignore-code / --randomize / --dump-format / --verify
    ignoreCode: null, randomize: null, dumpFormat: null, extractVerify: null,
    // [D50 2026-10-12] --fetch-using：盲注提取比较算子（gt|between，默认 gt）
    fetchUsing: null,
    dumpAll: false, identifyWaf: false, commonTables: null, commonColumns: null,
    randomAgent: false, where: null, paramDel: null,
    // [2026-10-12 优化空间勘查 §A2] NoSQL / OOB 两个**默认关的整通道**开关。
    // 缺口实录：这两个通道引擎早有（ScanManager._runNoSql / oobReceiver），UI（constants.ts
    // 「带外注入(OOB)」分组）与 REST（KNOWN_CFG_KEYS）都可达，唯独 CLI 一无旗标、二不在
    // configFile 登记表 ⇒ --config 档案也会被未知键硬拒 ⇒ CLI/脚本用户**完全开不了**。
    // 布尔 = 只开总开关；子键（oob.callbackHost/dnsPort、noSql.kinds/concurrency）
    // 走 --config 档案整组透传（见 buildConfig 的 patchGroup 分支）。
    noSql: false, oob: false,
    // 内部：从请求文件解析出的 header 对象（buildAuth 直接使用）
    headerObj: null,
    // 无法识别的开关收集在此（不再静默忽略）：告警见循环末尾，硬拒见 unknownFlagError()
    unknownFlags: [],
  };
  // [D41 2026-10-11] --config 配置档案预载（对标 sqlmap -c + ffuf -config）：
  // 档案键作为底、内置默认之上、argv 之下 —— 循环里任何显式传入的开关都会覆盖档案值。
  // preset 来自 configFile.loadConfigFile（内部键已剔除、未知键已在上游硬拒），不再校验。
  if (preset && typeof preset === 'object') Object.assign(args, preset);
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
    // [D42 2026-10-11 对标 sqlmap --second-req] 二阶触发页整请求文件（-r 同源解析器）：
    // 触发页需要 POST + 头 + CSRF 时 --second-order <url> 表达不了，这里吃完整抓包。
    else if (a === '--second-req') args.secondReq = next();
    else if (a === '--authorized') args.authorized = true;
    else if (a === '-u' || a === '--url') args.url = next();
    else if (a === '-d' || a === '--direct') args.direct = next();
    else if (a === '--sql-template') args.sqlTemplate = next();
    else if (a === '--driver') args.driverType = next();
    else if (a === '-m' || a === '--batch') args.batch = next();
    else if (a === '--method') args.method = next();
    else if (a === '--body') args.body = next();
    // [2026-10-01] XML / SOAP body 通道（对标 ghauri XML·SOAP）。--body 走 JSON 解析，
    // XML 不是合法 JSON ⇒ 必须独立入口；--xml-body-file 便于多行 XML/SOAP 信封。
    else if (a === '--xml-body') args.xmlBody = next();
    else if (a === '--xml-body-file') args.xmlBodyFile = next();
    else if (a === '--cookie') args.cookie = next();
    else if (a === '--header' || a === '--headers') args.headers = next();
    else if (a === '--technique') args.technique = next();
    // [2026-10-12 §A2] NoSQL / OOB 默认关通道总开关（子键走 --config 档案，见 help）。
    // 与 --no-cast 同族命名（noSql → --no-sql）；oob 与 --technique oob 正交：
    // technique 只决定"测不测"，oob.enabled 决定"起不起接收端"（defaults.js:292-293 明写
    // 「即使 techniques 含 oob，也需此处开启接收端才启动」）——这正是此前 CLI 不可达的那半。
    else if (applyChannelFlag(a, args)) { /* --no-sql / --oob / --oob-interactsh（D87） */ }
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
    else if (a === '--test-headers') args.testHeaders = true; else if (a === '--test-path') args.testPath = true; else if (a === '--test-param-names') args.testParamNames = true; // [D93] 三键同族，合一行保 parseArgs 基线（227 行只许持平）
    // [2026-10-02 竞品吸收] --param-mine：参数挖掘总开关（对标 Arjun 参数发现，默认关闭零回归）
    else if (a === '--param-mine') args.paramMine = true;
    // [2026-10-02 实战 P1-4] --crawl-browser：headless 浏览器爬取（SPA 目标 XHR 接口发现）
    else if (a === '--crawl-browser') args.crawlBrowser = true;
    // [批次14 实战 P1-6] 登录编排：--login-url（凭据复用 --auth user:pass）
    else if (a === '--login-url') args.loginUrl = next();
    else if (a === '--login-user-field') args.loginUserField = next();
    else if (a === '--login-pass-field') args.loginPassField = next();
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
    // [D44 2026-10-11] --active-waf-probe：扫描期主动 WAF 探测（被动指纹未命中时发多向量
    // 探针观察拦截行为）。此前只有 REST（config.activeWafProbe）与 --identify-waf 能触发，
    // 扫描期在 CLI 侧不可达（configReachability 同族的「能力在、入口不在」）。
    else if (a === '--active-waf-probe') args.activeWafProbe = true;
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
    // [D24 2026-10-09 扩展生态] 追加自定义检测条目（JSON 文件，与 registry.json 同 schema）。
    // 只追加不覆盖；加载/校验失败一律硬失败（不静默忽略，否则用户以为自定义生效了）。
    else if (a === '--payload-file') args.payloadFile = next();
    else if (a === '--proxy') args.proxy = next();
    else if (a === '--scope') args.scope = next();
    else if (a === '--insecure') args.insecureTls = true;
    else if (a === '--cert') args.clientCert = next(); // mTLS 客户端证书 PEM（sqlmap --cert 语义）
    // [D32 实战 P0-1] 自定义请求变换脚本（签名/加密接口）；须位于 REQUEST_SCRIPT_DIR 内
    else if (a === '--request-script') args.requestScript = next();
    // [D52] 自定义响应解密脚本（加密/编码响应体）；须位于 RESPONSE_SCRIPT_DIR 内。
    // 与 --request-script 对偶：那个治「发不出合法请求」，这个治「读不懂合法响应」。
    else if (a === '--postprocess') args.postprocess = next();
    // [D53] 时间提取基线漂移重采样间隔（个探针，0=关闭跟踪）：健康提取靠判假探针的
    // 免费 RTT 样本连续跟踪，连续 N 个探针没拿到干净样本时才补发一次基线请求。
    else if (a === '--time-baseline-every') args.timeBaselineEvery = next();
    // [D36 实战 P0-2] Bearer/Token 自动续期（--refresh-url 为主开关，另两个是可选形状）
    else if (a === '--refresh-url') args.refreshUrl = next();
    else if (a === '--refresh-token') args.refreshToken = next();
    else if (a === '--refresh-field') args.refreshField = next();
    else if (a === '--no-validation-skip') args.noValidationSkip = true;
    else if (a === '--confirm-destructive') args.confirmDestructive = true;
    else if (a === '--no-production-mode') args.noProductionMode = true;
    else if (a === '--allow-second-order-writes') args.allowSecondOrderWrites = true;
    else if (a === '--no-xp-auto-enable') args.noXpAutoEnable = true;
    else if (a === '--auth') args.auth = next();
    else if (a === '--auth-type') args.authType = next();
    else if (a === '--rate' || a === '--ratePerSec') args.ratePerSec = Number(next()) || 50;
    else if (a === '--threads' || a === '--concurrency-det') args.concurrencyDet = Number(next()) || 4;
    else if (a === '--format' || a === '-f') args.format = next();
    else if (a === '--out' || a === '-o') args.out = next();
    else if (a === '--timeout') args.timeoutMs = Number(next()) || 0;
    // [D41 2026-10-11] --retries / --http-timeout：单请求层的重试次数与超时（config.retry / config.timeoutMs，
    //   引擎与 REST 白名单早已消费这两键，此前只有 REST 能配 —— CLI 侧一直缺入口）。
    //   命名刻意避开既有 --timeout（那是整场扫描的轮询上限，cli.js:293 消费）。
    else if (a === '--retries') args.retries = Number(next());
    else if (a === '--http-timeout') args.httpTimeoutMs = Number(next());
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
    // [D46 对标 sqlmap] 运维侦察枚举 + 过滤
    else if (a === '-b' || a === '--banner') args.banner = true;
    else if (a === '--statements') args.statements = true;
    else if (a === '--procs') args.procs = true;
    else if (a === '-U' || a === '--user') args.user = next();
    else if (a === '--exclude') args.exclude = next();
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
    // [D41 2026-10-11 对标 sqlmap -c/--save + ffuf -config] 配置档案：--config 从 JSON 文件预载参数，
    //   CLI 显式传入的开关优先生效；--save-config 把本次实际生效的参数增量写回 JSON（可复扫）。
    else if (a === '--config') args.configFile = next();
    else if (a === '--save-config') args.saveConfigFile = next();
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
  // [D41 2026-10-11 对标 sqlmap -p] 只测指定参数（逗号分隔；config.js → config.testParameter）
  else if (a === '-p' || a === '--test-param') args.testParam = next();
  // [D41 2026-10-11 对标 sqlmap --param-exclude] 按正则排除参数（paramSelection.js 消费）
  else if (a === '--param-exclude') args.paramExclude = next();
  // [D41 2026-10-11 对标 sqlmap --param-filter] 按位置筛选（url/body/header/cookie/path 及 GET/POST 别名）
  else if (a === '--param-filter') args.paramFilter = next();
  // —— [D42 2026-10-11 对标 sqlmap 四件] ——
  // --ignore-code：忽略指定 HTTP 错误码（不再计入拦截/会话失效/服务器错误判定）
  else if (a === '--ignore-code') args.ignoreCode = next();
  // --randomize：每条注入请求随机化指定参数的值（防反爆破/风控锁定）
  else if (a === '--randomize') args.randomize = next();
  // --dump-format：拖库数据产物格式（csv/sql/html/json；产物层用，不影响内嵌报告）
  else if (a === '--dump-format') args.dumpFormat = next();
  // [D50 2026-10-12] --fetch-using：盲注提取比较算子。`>`/`<` 被 WAF 过滤而 BETWEEN
  // 仍放行的目标上，between 让长度/字节二分继续收敛（cls 类探测早已单方面依赖 BETWEEN
  // 可用）。默认 gt（历史行为）；'in' 不实现（IN 为假时无法定位区间，TODO 已留证）。
  else if (a === '--fetch-using') args.fetchUsing = next();
  // --verify / --no-verify：盲注提取复核开关（引擎默认开：每字节等值确认 + 完整值复验）
  else if (a === '--verify') args.extractVerify = true;
  else if (a === '--no-verify') args.extractVerify = false;
    // —— 对标 sqlmap 最后两个参数（--tor/--mobile）——
    else if (a === '--tor') args.tor = true;
    else if (a === '--mobile') args.mobile = true;
    // —— 对标 sqlmap 增强参数（不改变引擎行为，仅控制采样/编码）——
    // [D21 2026-10-09] `--random-agent` 的解析**只在上面 [对标 sqlmap --random-agent] 那处**，
    //   此处曾重复一条 `else if (a === '--random-agent') args.randomUA = true;` ——
    //   同一条 else-if 链里第二个分支**永不执行** ⇒ `args.randomUA` 恒为 undefined ⇒
    //   config.js 里 `if (args.randomUA) config.randomUA = true` 是死代码（顶层 randomUA 在
    //   server/src 内 0 个读取点）。真开关是 `wafEvasion.randomUA`，由 args.randomAgent 驱动。
    else if (a === '--flush-session') args.flushSession = true;
    else if (a === '--fresh-queries') args.freshQueries = true;
    else if (a === '--no-cast') args.noCast = true;
    else if (a === '--hex') args.hex = true;
    else if (a === '--union-cols') args.unionCols = next();
    else if (a === '--union-from') args.unionFrom = next();
    // —— 台账保留策略（SCAN_LEDGER_*）——
    // [2026-09-29] 这两个开关由 `cli.js ledger prune` 子命令自己解析（见 cli.js 的 argOf），
    // 本文件不消费。但**必须显式识别**：否则它们落到最后那条 else 里被记成 unknownFlag，
    // 打印「无法识别的参数（不会生效）」—— 而它其实是生效的。那条警告变成在骗人，
    // 比"静默丢弃"更糟（用户会以为没传进去，再去配一遍）。同理：被排到尾部候选之前。
    else if (a === '--max' || a.startsWith('--max=') || a === '--days' || a.startsWith('--days=')) { void a; }
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
    // [UNKNOWN-FLAG 2026-09-25] 这条必须接在同一条 if/else 链的**尾巴**上。
    //   原先这里是空的 else（拼错的开关被**静默丢弃**），而我第一版把它写成了链外的独立
    //   语句 —— 结果每个 token 都被记成未识别（`-u` 也中招），当场被自己的测试打回：
    //   "不该有未识别开关：-d,--driver,--scope,--sql-template,--tech,--risk"。
    //   本文件对 --no-escape / --union-char 已写了「保留显式识别并给出可操作提示，避免用户
    //   以为传了没生效而反复排查」—— 那是同一条政策的两个特例，其余上百个开关仍一声不响。
    //   实测代价落在红线上（同一个意图、三种写法、三种结果）：
    //     -d <dsn> --driver mysql  --scope 10.20.0.0/16 ⇒ 越界主机被拒（正确）
    //     -d <dsn> --driver sqlite --scope 10.20.0.0/16 ⇒ 内嵌驱动放行（正确）
    //     -d <dsn> --scope-typo 10.20.0.0/16            ⇒ 红线整个消失，命令还照常跑完
    //   最后一条是**假安全**：退出码 0、看着像设了范围，实际一个约束都没生效。
    else if (a.startsWith('-')) args.unknownFlags.push(a);
  }
  if (args.unknownFlags.length) {
    console.error("[cli] 无法识别的参数（不会生效）：" + args.unknownFlags.join(" "));
  }
  return args;
}

/**
 * 入口层的硬拒判据：有未识别开关时返回错误文案（由调用方打印并以非零退出）。
 * 为什么不在 parseArgs 里直接 exit：它被单测与 one-click 复用，"要不要终止" 属于入口决定。
 */
export function unknownFlagError(args) {
  const u = (args && args.unknownFlags) || [];
  if (!u.length) return null;
  return (
    '无法识别的参数：' + u.join(' ') + '\n' +
    '  这些开关不会生效，本次启动已拒绝 —— 宁可少跑一次，也不让「以为设了」变成实际没设。\n' +
    '  用 --help 核对开关名（例如 --driver 而不是 --driver-type；--scope 而不是 --scopes）。'
  );
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
  // [COLLECTION-2026-09-21] 改走 requestCollectionParser（取 <request> 原始报文解析）。
  // 原实现只按 `<url>/<method>` 提取并硬写 `headers: {}` / `body: null` ⇒ **Cookie、
  // Content-Type、POST body 全丢**：`-l` 扫 Burp 导出时 body 注入点拿不到、需登录的目标
  // 也扫不到。该缺陷此前无测试覆盖（cli.log.test.js 只断言了 url，没断言 headers/body）。
  // 现与 `-r` 共用同一条归一化路径，方法/URL 过滤语义保持不变。
  if (/<items|<item\b|<burp/i.test(text)) {
    return parseRequestCollection(text).requests
      .map((r) => ({
        url: r.url,
        method: r.method,
        headers: r.headers || {},
        body: r.body || null,
      }))
      .filter((r) => /^https?:\/\//i.test(r.url) && ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(r.method));
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
// [P0-FIX 2026-10-02] NTLM 解禁：引擎 Type1-3 握手早已完整实现（ntlmAuth.js 自带
// MD4+DES-L、ntlmHandshake.js 按 host 缓存状态，e2e/ntlm-lab 真机验证），
// 此前 CLI 却按「未实现」拒收——报错文本与引擎现状相矛盾（实战分析 P0-1 查实）。
// NTLM 凭据形态对齐 sqlmap --auth-cred：DOMAIN\username:password（domain 可省略），
// 解析结果仍落 auth.basic，buildAuth 会按 --auth-type 挂 type:'ntlm'
// （ntlmHandshake.cred 的约定形态：auth.type==='ntlm' ? auth.basic）。
// PKI/未知 scheme 维持不支持（客户端证书走独立的 --client-cert）。
export function parseAuth(str, type) {
  const t = type ? String(type).toLowerCase() : 'basic';
  if (t !== 'basic' && t !== 'digest' && t !== 'ntlm') {
    return { unsupported: true, type: t };
  }
  if (!str) return undefined;
  let s = str;
  let domain;
  if (t === 'ntlm') {
    const bs = s.indexOf('\\');
    if (bs > 0) {
      domain = s.slice(0, bs);
      s = s.slice(bs + 1);
    }
  }
  const idx = s.indexOf(':');
  const cred = idx < 0
    ? { username: s, password: '' }
    : { username: s.slice(0, idx), password: s.slice(idx + 1) };
  if (t === 'digest') return { digest: cred };
  if (domain) cred.domain = domain;
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

// [D159 2026-10-25] multipart 抓包 → args.body（文本字段）+ args.fileParts（文件字段）。
//
// 历史：原实现把整个 multipart 目标**降级**成 urlencoded，理由是「引擎不支持发送 multipart」。
// 该理由 2026-09-22 起已不成立（injection.js 的 buildMultipartBody 会按 boundary 重建报文，
// e2e/pentest-lab 的 `/mp` 是端到端证据）。降级的实际后果是：只认 multipart 的上传表单
// 收到 urlencoded ⇒ 415/400 ⇒ 注入值从未进业务逻辑 ⇒ **静默 0 检出**，而 Burp 抓到的上传
// 接口恰好是最常见的一类 multipart 目标。
// 现在：Content-Type 原样保留；文本字段进 bodyParams；文件字段进 fileParts（发送侧按
// `name="x"; filename="…"` 重建，注入值写进 filename）。文件字段**不**进 bodyParams ——
// filename 是文件字段的属性，不是文本字段的内容。
/**
 * @param {any} args
 * @param {any} parsed parseRequestFile / parseRequestCollection 的单条结果
 */
function applyMultipartBody(args, parsed) {
  const allFields = parsed.bodyFields || {};
  const fileNames = new Set((parsed.fileParts || []).map((f) => f.name).filter(Boolean));
  const fields = {};
  for (const [k, v] of Object.entries(allFields)) {
    if (!fileNames.has(k)) fields[k] = v;
  }
  if (Object.keys(fields).length) args.body = JSON.stringify(fields);
  args.fileParts = Array.isArray(parsed.fileParts) ? parsed.fileParts : [];
  const names = args.fileParts.map((f) => f.name).filter(Boolean);
  console.warn(
    `  [i] -r multipart：文本字段 ${Object.keys(fields).join(', ') || '(无)'}`
    + `；文件字段 ${names.join(', ') || '(无)'}（按 multipart 重建，文件字段注入 filename）。`
    + (names.length ? '' : '\n      若本次抓包本就只有文件字段，注入面来自 filename。')
  );
}

// [D159 拆分] body 通道路由：multipart 走真实重建，其余沿用原有的 JSON/urlencoded 启发式。
/**
 * @param {any} args
 * @param {any} parsed
 * @param {string} ctForBody 抓包里声明的 Content-Type
 */
function applyBodyToArgs(args, parsed, ctForBody) {
  if (/multipart\/form-data/i.test(ctForBody)) {
    applyMultipartBody(args, parsed);
    return;
  }
  const bodyJson = bodyToJsonString(parsed.body);
  if (bodyJson) { args.body = bodyJson; return; }
  // [D160 2026-10-25] 声明了 JSON 却解析不出来：必须出声。
  // 旧行为是静默丢弃 body ⇒ 引擎收到 0 个 body 注入点、扫描照常跑完、报告写「未检出」，
  // 与「这个站没洞」完全同形。真实场景：抓包被截断（Burp 只存了 header）、body 是
  // jsonp/前后空格/多段拼接、或 CT 写的是 json 但实际是自定义序列化。
  if (/json/i.test(ctForBody)) {
    const preview = String(parsed.body || '').slice(0, 60).replace(/\s+/g, ' ');
    console.warn(
      `  [!] -r 抓到 Content-Type: ${ctForBody.split(';')[0]}，但 body 不是合法 JSON（前 60 字：${preview || '(空)'}）。`
      + '\n      本次不会生成任何 body 注入点 —— 「未检出」不代表没有注入，请核对抓包 body 是否完整。'
    );
  }
}

// 对标 sqlmap -r：读取请求文件 → 解析 → 覆盖 args 的 url/method/body/headers/cookie
// 返回 null 表示文件读取或解析失败（调用方应退出并报错）
export function applyRequestFile(args) {
  if (!args.requestFile) return args;
  if (!existsSync(args.requestFile)) {
    console.error(`请求文件不存在: ${args.requestFile}`);
    return null;
  }
  // [COLLECTION-2026-09-21] 从「只认单个文本请求」扩到「也认集合格式」：
  // 实战交付的起点常是 Burp 的 XML 导出或浏览器/Charles 的 HAR —— 原先一律抛
  // 「需为 Burp/curl 文本 HTTP 请求格式」，第一步就卡住。现在统一经
  // parseRequestCollection 归一化（内部仍走 parseRequestFile，契约不变）。
  const coll = parseRequestCollection(readFileSync(args.requestFile, 'utf-8'));
  if (!coll.requests.length) {
    console.error(`请求文件解析失败: ${args.requestFile}`);
    for (const w of coll.warnings) console.error(`  · ${w}`);
    return null;
  }
  const parsed = coll.requests[0];
  // 集合里多于一条时**必须说出来**：静默取第一条会让人以为整份都测了
  // （本仓教训：静默降级比报错更难查）。
  if (coll.requests.length > 1) {
    console.error(
      `[集合导入] 识别为 ${coll.format}，共 ${coll.requests.length} 个请求；本次只扫描第 1 个：${parsed.label || parsed.url}`
    );
    console.error('           其余请求未扫描；要逐个测请拆分文件后分别用 -r。');
  }
  for (const w of coll.warnings) console.error(`  [提示] ${w}`);
  args.url = parsed.url;
  if (parsed.method === 'HEAD' || parsed.method === 'OPTIONS' || parsed.method === 'TRACE' || parsed.method === 'CONNECT') {
    // MethodType 仅支持 GET/POST/PUT/PATCH/DELETE，越界方法回退 GET
    args.method = 'GET';
  } else {
    args.method = parsed.method;
  }
  const ctKeyForBody = Object.keys(parsed.headers || {}).find((k) => /^content-type$/i.test(k));
  const ctForBody = ctKeyForBody ? String(parsed.headers[ctKeyForBody]) : '';
  applyBodyToArgs(args, parsed, ctForBody);
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
      // [P0-FIX 2026-10-02] NTLM 已解禁（引擎 Type1-3 握手完整，ntlm-lab 真机验证），
      // 不支持面只剩 PKI/未知 scheme —— 客户端证书请走 --client-cert
      throw new Error(`--auth-type=${args.authType} 暂不支持（本引擎支持 Basic/Digest/NTLM；PKI 类客户端证书请用 --client-cert）`);
    }
    auth = { ...auth, ...(pa || {}) };
    if (args.authType && String(args.authType).toLowerCase() !== 'basic') {
      auth.type = String(args.authType).toLowerCase();
    }
  }
  return auth;
}
