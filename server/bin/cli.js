#!/usr/bin/env node
// CLI 模式（P1-U5）：无 UI 的命令行扫描入口，复用同一 ScanManager。
// 用法：
//   单目标：node bin/cli.js -u <url> [--method GET|POST] [--body '{"k":"v"}'] [--format json|html|csv|markdown]
//   直连：  node bin/cli.js -d "sqlite://test.db" --sql-template "SELECT * FROM t WHERE id={INJECT}"
//   批量：  node bin/cli.js -m <urls.txt> [--format json] [--concurrency 2]
// 事件经 eventBus 订阅转控制台进度输出，扫描结束打印报告到 stdout 并可按 --format 导出到文件。
import { ScanManager } from '../src/engine/ScanManager.js';
import * as eventBus from '../src/core/eventBus.js';
import { logger } from '../src/core/logger.js';
import { readFileSync, existsSync } from 'node:fs';
// 对标 sqlmap -r：解析 Burp/curl 文本请求文件
import { parseRequestFile } from '../src/core/requestFileParser.js';
// 高危 payload 池：--risk=3 时显式启用（默认池不含写文件/RCE/外连/DoS 向量）
import { PAYLOADS, enableDestructivePayloads } from '../src/engine/payloads.js';
// 攻击操作（对标 sqlmap --os-cmd/--sql-shell/--file-read/--file-write）：复用引擎 Exploiter
import { Exploiter } from '../src/engine/Exploiter.js';
import { httpClient } from '../src/core/httpClient.js';
// 自定义 tamper 文件加载（对标 sqlmap --tamper=path/to/script.py → 本项目 JS 插件）
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
// [P1-FIX 2026-09-05] --format 出口：原为死参数（解析后从未消费，-o 恒写 JSON）。
// ReportGenerator 的 toCSV/toMarkdown/toHTML 与 REST /report/export 同源，直接复用。
import { ReportGenerator } from '../src/services/ReportGenerator.js';
// [P0-SEC 2026-09-09] --scope 接线：CLI 直走 ScanManager 不经 scanRoutes，需在本层完成
// 「目标先校验 + 按 scanId 登记」，否则 --scope 是静默 no-op（httpClient 逐跳取用登记项）。
import { parseScope, assertInScope, registerScanScope, releaseScanScope } from '../src/core/scopeGuard.js';
import path from 'node:path';

// --format 分发（json|csv|markdown|html）：单目标 -o 与批量目录导出共用。
// 未知格式回退 json（与 REST /report/export 的宽容行为一致）。
export function formatReport(report, fmt = 'json') {
  const f = String(fmt || 'json').toLowerCase();
  if (f === 'csv' || f === 'markdown' || f === 'md' || f === 'html') {
    const rg = new ReportGenerator();
    return f === 'csv' ? rg.toCSV(report)
      : f === 'html' ? rg.toHTML(report)
      : rg.toMarkdown(report);
  }
  return JSON.stringify(report, null, 2);
}

// 极简参数解析（避免引入 commander 依赖）
function parseArgs(argv) {
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

function printHelp() {
  console.log(`sqli-scanner CLI（对标 sqlmap 的 Node 引擎命令行入口）

用法:
  单目标  node bin/cli.js -u <url> [选项]
  请求文件 node bin/cli.js -r request.txt [选项]
  批量    node bin/cli.js -m <urls.txt> [选项]

选项:
  -r, --request-file <file>  从 Burp/curl 文本请求文件导入完整请求（对标 sqlmap -r）：
                             提取 URL/method/headers/body，覆盖 -u/--method/--body/--cookie/--header
  -l, --log-file <file>      从代理/Burp 日志文件批量扫描（对标 sqlmap -l）：
                             支持 Burp XML 导出与纯文本多请求日志，逐请求复用 -r 的字段映射
  -u, --url <url>            目标 URL
  -m, --batch <file>         批量扫描文件（每行一个 URL）
  --method <GET|POST|...>    请求方法（默认 GET；支持 PUT/PATCH/DELETE）
  --body <json>              POST body（JSON 对象字符串）
  --cookie <str>             认证 Cookie 串（透传 config.auth.cookie，非注入点）
  --header <k:v,k:v>          额外请求头（冒号分隔，逗号分隔多组）
  --technique <BEUSTQ>       检测技术子集（union/error/boolean/time/stacked/oob/inline/second_order，逗号分隔；缺省=默认 4 类）
  --level <1-5>              检测等级（1 默认，5 最深，对应注入点边界/子句变体）
  --risk <1-3>               风险等级（1 安全，2 标准，3 含 OR 变体）
  --test-filter <str>        仅运行 id 匹配的测试（逗号分隔子串，大小写不敏感，对标 sqlmap --test-filter）
  --test-skip <str>          跳过 id 匹配的测试（逗号分隔子串，大小写不敏感，对标 sqlmap --test-skip）
  --test-headers             把显式传入的请求头（--header 或 -r 请求文件中的头，如 Cookie / X-Forwarded-For）
                             作为注入点测试（默认关闭：保持现有行为，头仅作会话透传）。授权的渗透测试中，
                             服务端按请求头取值拼 SQL 的场景（如 SELECT ... WHERE id=\${x_forwarded_for}）必须开启才能检出
  --test-path               把 URL path 末段（非空且非静态资源 .html/.js/.css/.png 等）作为注入点测试
                             （默认关闭：保持现有行为。服务端按 path 段取值拼 SQL 的场景必须开启才能检出）
  --use-registry             启用声明式 payload 注册表（检测器改用 PAYLOAD_REGISTRY 筛选，受 level/risk/test-filter/test-skip 控制）
  --dump                     启用数据提取（拖库，默认关闭对标 sqlmap 显式 opt-in）
  --dump-all                 全库拖库（对标 sqlmap --dump-all）：枚举所有库后逐库逐表拖，
                             忽略 -D/-T；默认排除系统库（--no-exclude-sysdbs 关闭）
  --common-tables            字典爆破表名（对标 sqlmap --common-tables）：
                             information_schema 被 WAF 拦 / 权限不足 / 非 MySQL 时的枚举出路
  --common-columns           字典爆破列名（对标 sqlmap --common-columns）：配合 -D/-T 使用
  --where <cond>             拖库条件过滤（对标 sqlmap --where）：如 --dump -D db -T t --where "id>100"
                             仅 --dump / --dump-all 生效；条件原样拼入 SQL，不做转义（与 sqlmap 一致）
  --dbs                      枚举数据库（对标 sqlmap --dbs，自动排除系统库，--no-exclude-sysdbs 关闭）
  --tables -D <db>           枚举指定库的表（对标 sqlmap --tables -D）
  --columns -D <db> -T <t>  枚举指定表列（对标 sqlmap --columns -D -T）
  --dump -D <db> [-T <t>] [-C c1,c2]  拖库，可限定表/列（对标 sqlmap --dump -D -T -C）
  --current-db              当前数据库（对标 sqlmap --current-db）
  --current-user            当前用户（对标 sqlmap --current-user）
  --users                   枚举数据库用户（对标 sqlmap --users；需 mysql.user 等高权限）
  --passwords               枚举用户凭据哈希（对标 sqlmap --passwords；需高权限，失败返回 null）
                            哈希破解需离线进行：MySQL 用 hashcat -m 300，MSSQL 用 -m 1731，
                            PG 用 -m 12（sqlmap 同样不内置破解）
  --hostname                枚举数据库主机名/地址（对标 sqlmap --hostname）
  --is-dba                  判断当前用户是否为 DBA（对标 sqlmap --is-dba，返回 1/0）
  --schema -D <db> -T <t>   枚举表结构/列定义（对标 sqlmap --schema）
  --privileges              枚举当前用户权限（对标 sqlmap --privileges；失败返回 null）
  --roles                   枚举当前用户角色（对标 sqlmap --roles；失败返回 null）
  --count -D <db> -T <t>    表行数统计（对标 sqlmap --count）
  --search <keyword>        按关键字搜索包含该词的库/表/列名（对标 sqlmap --search；自动限 3 库×10 表防请求爆炸）
  --exclude-sysdbs          枚举时排除系统库（默认 true；--no-exclude-sysdbs 关闭）
   --start <n>               拖库起始行偏移（对标 sqlmap --start，0 起）
   --stop <n>                拖库结束行号（对标 sqlmap --stop，绝对行号，0=不限）
   --safe-url <url>          保活 URL：扫描期间定期 GET 维持会话（对标 sqlmap --safe-url）
   --safe-freq <n>           每 n 个请求触发一次保活访问（默认 1，配合 --safe-url）
  -D, --db <dbname>         数据库（枚举目标）
  -T, --table <tablename>   表（枚举目标）
  -C, --columns-list <c1,c2>  列子集（配合 --dump -T）
  --tamper <name,name>       tamper 插件链（逗号分隔，对标 sqlmap --tamper）；传 .js 文件路径可加载自定义插件
  --identify-waf             仅识别 WAF 厂商并给出推荐 tamper 链，不发起注入检测
                             （对标 sqlmap --identify-waf；用于扫描前先摸清对面是什么 WAF）
  --smart                    智能启发式（别名，等价 prefilter: true，跳过非注入参数）
  --proxy <url>              代理（http://host:port 或 socks5://host:port）
  --scope <cidr/域名,...>    授权范围硬约束（[P0-SEC] 如 10.0.0.0/24,target.example.com）：
                             启用后目标与每一跳重定向均须在范围内，越界直接拒发；留空不启用
  --insecure                 忽略自签/内网 CA 证书（关闭 TLS 校验，失去中间人防护，报告须注明）
  --no-validation-skip       关闭「输入校验短路」（参数被白名单拦死也照跑完整检测，审计/对照用）
  --confirm-destructive      确认投放高危 payload 池（--risk 3 默认只「选风险」不「放行写操作」；无本开关时高危向量一条不发）
  --no-production-mode       声明本次不是生产环境（靶场/自建演练）：关掉生产护栏，高危池与二阶写请求不再被预置抑制
  --allow-second-order-writes 允许二阶使用非幂等方法（POST/PUT/PATCH/DELETE）：二阶本质是写操作，默认仅 GET/HEAD
  --no-proxy-bypass-local    关闭本地/私网代理豁免（默认豁免：127.0.0.1/内网不走 *PROXY 环境变量，
                             避免系统代理掐断请求后被记成「无漏洞」）
  --auth <user:pass>         Basic 认证（user:password 形式）
  --auth-type <Basic|Digest>  认证类型（默认 Basic；Digest 走 RFC 7616 挑战-响应，对标 sqlmap）
  --rate <n>                 限速 req/s（默认 50）
  --threads <n>              检测并发数（默认 4）
  -f, --format <fmt>         报告格式 json|html|csv|markdown（默认 json）
  -o, --out <path>           报告输出文件（批量模式输出到目录）
  -c, --concurrency <n>     批量并发扫描数（默认 1）
  --timeout <ms>             单次扫描等待上限（默认 0 = 无限制）

高级检测（对标 sqlmap）:
  --prefix <str>            注入闭合前缀（如 "')"）
  --suffix <str>            注入闭合后缀（如 "-- -"）
  --string <str>            页面匹配真值字符串
  --not-string <str>        页面匹配假值字符串
  --code <n>                匹配 HTTP 状态码
  --text-only               仅比较文本内容（忽略标签）
  --titles                  仅比较页面标题
  --regexp <pat>            页面匹配正则表达式
  --dbms <name>             强制指定 DBMS（跳过指纹，如 MySQL/PostgreSQL/Oracle）
  --second-order <url>      二阶注入触发页（写入后回访触发判定，对标 sqlmap --second-order）
  --invalid-bignum          有效值替换为随机大数（缓存/静态页噪声规避，对标 sqlmap）
  --invalid-logical         有效值替换为恒真逻辑式 n=n（同上）
  --invalid-string          有效值替换为随机字符串（同上；数值上下文会注入失败）
  --known-point <spec>      已知注入点直通（跳过预筛选/闭合探测，键值对用 ; 分隔）：
                            "param=id;quote=';paren=);techniques=union,error"

利用操作（对标 sqlmap --os-cmd/--sql-shell/--file-read/--file-write；需环境变量 EXPLOIT_ENABLED=1 且显式 --authorized）:
  --authorized              声明已获授权（安全红线，仅限授权渗透场景）
  --os-cmd <cmd>            执行系统命令（os-shell 通道）
  --sql-shell <sql>         执行任意 SQL
  --file-read <path>        读取目标文件
  --file-write <content>    写入目标文件（需配合 --file-dest <远程路径>）
  --file-dest <path>        --file-write 的远程目标路径

爬虫与会话（对标 sqlmap）:
  --forms                  收集页面表单注入点（需配 --level 5 才生效）
  --crawl <depth>           站内链接爬取深度（1-3，默认 0=不爬取）
  --session-file <path>     会话文件路径（断点续跑）
  --time-sec <n>            时间盲注 sleep 秒数（对标 sqlmap --time-sec）
  --delay <ms>              请求间**随机**延迟毫秒（WAF 规避，映射 wafEvasion.jitterMs）
  --delay-sec <n>           请求间**固定**延迟秒数（对标 sqlmap --delay，上限 60s）
  --req-rate <n>            每秒请求数上限（0=不限，对标 sqlmap --reqrate）
  --max-requests <n>        单次扫描请求总数上限（0=不限，对标 sqlmap --max-requests）
  --predict-output          启用常见值缓存预测（默认已开，显式覆盖用）
  --skip-static             跳过静态参数预筛
  --tor                     走 Tor（默认 socks5://127.0.0.1:9050）
  --check-tor               先校验 Tor 出口（请求 check.torproject.org 确认匿名化生效）再扫描
  --mobile                  随机移动端 UA 池（对标 sqlmap --mobile）
  --random-agent            每次请求随机 UA（桌面 + 移动全池，对标 sqlmap --random-agent）
  --param-del <c>           自定义参数分隔符（对标 sqlmap --param-del）：默认 &，用于 a=1;b=2 这类站点
  --force-ssl              目标 http:// 强制升级 https（对标 sqlmap --force-ssl）
  --ignore-redirects        不跟随 3xx 跳转，直接返回跳转响应（对标 sqlmap --ignore-redirects）
  --hpp                     注入参数双份提交（query+body 同名，WAF 绕过，对标 sqlmap --hpp）
  --parse-errors            解析错误响应中的数据库报错原文与 SQL 上下文，留存证据链（对标 sqlmap --parse-errors）
  --union-cols <n>          UNION 探测指定列数（跳过 ORDER BY 二分猜测，对标 sqlmap --union-cols）
  --union-from <from>       UNION 探测强制伪表 FROM 子句（如 dual，覆盖方言自动判定，对标 sqlmap --union-from）
  --no-cast                 数据提取禁用 CAST()/TO_CHAR() 显式类型转换（隐式文本化，对标 sqlmap --no-cast）
  --hex                     --search 的 LIKE 模式转十六进制字面量（对标 sqlmap --hex）：
                            用于绕过引号/WAF 对 % 与单引号的过滤。
                            仅 MySQL/MariaDB/TiDB/SQL Server/PostgreSQL/SQLite 支持，
                            其余方言会告警并自动回退普通形态（不产出错误 SQL）
  （--no-escape / --union-char 未实现，已从帮助移除；传入会被忽略并打印提示）

  -h, --help                 显示帮助

直连模式（对标 sqlmap -d）:
  -d, --direct <connStr>     数据库连接串（如 mysql://user:pass@host/db、sqlite://path.db）
  --sql-template <sql>       SQL 模板（含 {INJECT} 标记；默认 SELECT * FROM users WHERE id={INJECT}）
  --driver <type>            驱动类型 memory|sqljs|sqlite（默认 memory；真实驱动需 npm install 接入，见 core/dbDrivers.js）

退出码：
  0 = 扫描完成、无高危命中
  2 = 命中 Critical/High 风险（便于 CI gate）
  1 = 参数错误/扫描失败`);
}

function readUrlList(filePath) {
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
const REQ_LINE_RE = /(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/\d/i;
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
async function checkTor(proxyUrl) {
  const { HttpClient } = await import('../src/core/httpClient.js');
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
async function resolveTamperPlugins(tamperArg) {
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
function parseHeaders(str) {
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
function parseAuth(str, type) {
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

// 请求 body → bodyParams JSON 字符串（runSingleScan 用 JSON.parse 消费）
// 支持 JSON 与 form-urlencoded 两种形态；无法转换返回 null
function bodyToJsonString(body) {
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
function applyRequestFile(args) {
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
function buildAuth(args) {
  let auth = undefined;
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

// 对标 sqlmap --test-headers / --test-path（本期新增，默认关闭，零回归）：
// 把用户显式传入的请求头 / URL path 末段转为注入点。引擎 TargetParser 早已支持
// header/cookie/path 注入点（遍历 target.cookieParams / target.headerParams / path 段），
// 此前 CLI/解析层从未填充这些字段，导致带注入点的请求头（Cookie、X-Forwarded-For）与
// path 末段被完全跳过（危险假阴性）。
//
// --test-headers：把请求头（--header 或 -r 解析出的 headerObj）转为 target.headerParams；
//   Cookie 头特殊解析为 k=v 填入 target.cookieParams；host / content-length / content-type /
//   authorization 排除（传输层/认证类头，避免破坏请求或会话）。
// 返回 { headerParams?, cookieParams? }，供 runSingleScan 注入 target；无内容时返回 {}。
function buildInjectionTargets(args) {
  const result = {};
  if (!args.testHeaders) return result;
  const hdrs = {};
  if (args.headerObj) Object.assign(hdrs, args.headerObj);
  const parsed = args.headers ? parseHeaders(args.headers) : undefined;
  if (parsed) Object.assign(hdrs, parsed);
  const EXCLUDE = new Set(['host', 'content-length', 'content-type', 'authorization']);
  const headerParams = {};
  const cookieObj = {};
  for (const [k, v] of Object.entries(hdrs)) {
    const lk = String(k).toLowerCase();
    if (EXCLUDE.has(lk)) continue; // 传输层/认证类头排除
    if (lk === 'cookie') {
      // Cookie 头：解析为 k=v，填入 cookieParams（TargetParser 在 level≥2 生成 cookie 注入点）
      for (const pair of String(v).split(';')) {
        const eq = pair.indexOf('=');
        if (eq > 0) {
          const name = pair.slice(0, eq).trim();
          const val = pair.slice(eq + 1).trim();
          if (name) cookieObj[name] = val;
        }
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
function buildConfig(args) {
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
function isEnumMode(args) {
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
function buildExtractScope(args) {
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
function validateEnumArgs(args) {
  if (args.tables && !args.db) return '使用 --tables 需指定数据库：-D <dbname>';
  if (args.columns && (!args.db || !args.table)) return '使用 --columns 需指定：-D <dbname> -T <table>';
  if (args.count && (!args.db || !args.table)) return '使用 --count 需指定：-D <dbname> -T <table>';
  if (args.schema && (!args.db || !args.table)) return '使用 --schema 需指定：-D <dbname> -T <table>';
  if (args.columnsList && !args.table) return '使用 -C/--columns-list 需配合 -T <table>';
  if (args.columnsList && !args.dump) return '-C/--columns-list 仅在 --dump 模式下生效';
  return null;
}

// 枚举模式精简文本输出（report.data 视图）
function printExtractView(report) {
  const data = report.data;
  if (!data) { console.log('（无提取数据，注入点未确认或提取失败）'); return; }
  if (data.currentDb !== undefined && data.currentDb !== null) console.log(`current database: ${data.currentDb}`);
  if (data.currentUser !== undefined && data.currentUser !== null) console.log(`current user: ${data.currentUser}`);
  if (data.users !== undefined && data.users !== null) console.log(`users: ${data.users}`);
  if (data.passwords !== undefined && data.passwords !== null) console.log(`passwords: ${data.passwords}`);
  if (data.hostname !== undefined && data.hostname !== null) console.log(`hostname: ${data.hostname}`);
  if (data.isDba !== undefined && data.isDba !== null) console.log(`is DBA: ${data.isDba}`);
  if (data.userPrivs !== undefined && data.userPrivs !== null) console.log(`privileges: ${data.userPrivs}`);
  if (data.roles !== undefined && data.roles !== null) console.log(`roles: ${data.roles}`);
  const hasTables = data.tables && Object.keys(data.tables).length;
  const hasCols = data.columns && Object.keys(data.columns).length;
  const hasRows = data.rows && Object.values(data.rows).some(v => Array.isArray(v) && v.length);
  const hasModeField = data.currentDb || data.currentUser || data.users || data.passwords || data.hostname || data.isDba || data.userPrivs || data.roles || (data.counts && Object.keys(data.counts).length);
  // --dbs：仅库名列表（其它模式不进入此分支）
  if (!hasTables && !hasCols && !hasRows && !hasModeField) {
    for (const db of (data.databases || [])) console.log(db);
    if (!data.databases || !data.databases.length) console.log('（未枚举到数据库）');
  }
  // --tables / --columns / --dump
  for (const [db, tabs] of Object.entries(data.tables || {})) {
    for (const t of tabs) {
      const key = `${db}.${t}`;
      const cols = data.columns ? data.columns[key] : null;
      const rows = data.rows ? data.rows[key] : null;
      if (Array.isArray(rows) && rows.length) {
        const showCols = cols || Object.keys(rows[0]);
        console.log(`[${key}]  共 ${rows.length} 行`);
        console.log('  ' + showCols.join(' | '));
        for (const row of rows.slice(0, 50)) {
          console.log('  ' + showCols.map(c => row[c] == null ? '' : row[c]).join(' | '));
        }
        if (rows.length > 50) console.log(`  …（仅显示前 50 行，共 ${rows.length} 行）`);
      } else if (cols && cols.length) {
        console.log(`${key}: ${cols.join(', ')}`);
      } else {
        console.log(key);
      }
    }
  }
  // --count
  if (data.counts) {
    for (const [k, v] of Object.entries(data.counts)) console.log(`${k}: ${v == null ? 'N/A' : v} 行`);
  }
  // --search：输出匹配的表名和列名汇总
  if (data.search) {
    console.log(`search keyword: ${data.search.keyword}`);
    if (data.search.matchedTables && data.search.matchedTables.length) {
      console.log(`matched tables: ${data.search.matchedTables.join(', ')}`);
    } else {
      console.log('matched tables: (none)');
    }
    if (data.search.matchedColumns && data.search.matchedColumns.length) {
      for (const m of data.search.matchedColumns) {
        console.log(`  ${m.table}: ${m.columns.join(', ')}`);
      }
    }
  }
  // --schema：输出表结构定义
  if (data.schemas && Object.keys(data.schemas).length) {
    console.log('schemas:');
    for (const [k, v] of Object.entries(data.schemas)) {
      console.log(`  ${k}: ${v == null ? '(null)' : v}`);
    }
  }
}

async function runSingleScan(sm, url, args) {
  const bodyParams = args.body ? JSON.parse(args.body) : {};
  const config = buildConfig(args);
  // [P0-SEC] 目标先过一遍 scope（与 scanRoutes sanitizeStart 同步拦截同构）：越界直接报错，
  // 一个包都不发。直连模式（-d）无 HTTP 请求可言，不参与 scope 判定。
  const scopeRules = args.scope && !args.direct
    ? parseScope(String(args.scope).split(',').map(s => s.trim()).filter(Boolean))
    : null;
  if (scopeRules?.enabled) assertInScope(String(url), scopeRules);
  const auth = buildAuth(args);
  // [本期新增] --test-headers：把显式请求头转为注入点字段。被纳入注入点的头不再经 auth 透传，
  // 否则 httpClient.mergeAuthHeaders 会用原始值覆盖注入 payload（请求仍畸形/无注入）。
  // 注入点的原始值由 buildInjectionRequest 始终从 target.headerParams/cookieParams 注入（含基线请求）。
  const injTarget = buildInjectionTargets(args);
  // 被纳入注入点的「请求头」不再经 auth 透传：mergeAuthHeaders 对普通头是**覆盖**语义，
  // 否则会用原始值覆盖注入 payload（请求仍畸形/无注入）。Cookie 头不在此处删除 ——
  // mergeAuthHeaders 对 cookie 是「追加」语义（existing + '; ' + auth.cookie），保留 auth.cookie
  // 既能让注入点的 uid=<payload> 生效，又能带上独立传入的会话 Cookie（如 --cookie session=abc），避免掉会话。
  if (injTarget.headerParams && auth && auth.headers) {
    for (const k of Object.keys(injTarget.headerParams)) delete auth.headers[k];
    if (auth.headers && Object.keys(auth.headers).length === 0) delete auth.headers;
  }
  // 枚举模式：把 CLI 参数解析为 extractScope 挂到 config（对标 sqlmap --dbs/--tables/...）
  const scope = buildExtractScope(args);
  if (scope) config.extractScope = scope;
  // 直连模式（对标 sqlmap -d）：-d <connectionString> --sql-template 'SELECT * FROM t WHERE id={INJECT}'
  const input = args.direct
    ? {
        mode: 'direct',
        connectionString: args.direct,
        driverType: args.driverType || 'memory',
        sqlTemplate: args.sqlTemplate || 'SELECT * FROM users WHERE id={INJECT}',
        config,
      }
    : { url, method: args.method, bodyParams, config, auth, ...injTarget };
  const scanId = await sm.start(input);
  // [P0-SEC] scope 按 scanId 登记：httpClient 在每一跳（含重定向）前取用，防 302 出圈
  if (scopeRules?.enabled) {
    try { registerScanScope(scanId, scopeRules); } catch { /* 登记失败不阻断扫描（入口已校） */ }
  }

  // 订阅事件 → 控制台进度
  const em = eventBus.create(scanId);
  em.on('event', (evt) => {
    const t = evt.type;
    if (t === 'point_discovered') process.stderr.write(`[发现] ${evt.payload.points?.length ?? 0} 个注入点\n`);
    else if (t === 'point_testing') process.stderr.write(`[检测] ${evt.payload.pointId} · ${evt.payload.technique}\n`);
    else if (t === 'detection_found') process.stderr.write(`[命中] ${evt.payload.technique} @ ${evt.payload.pointId}\n`);
    else if (t === 'scan_completed') process.stderr.write(`[完成] 风险等级 ${evt.payload.riskLevel}\n`);
    else if (t === 'scan_error') process.stderr.write(`[错误] ${evt.payload.message}\n`);
  });

  // 轮询扫描状态直到终态（timeoutMs=0 表示无限等待）
  const deadline = args.timeoutMs > 0 ? Date.now() + args.timeoutMs : 0;
  while (true) {
    const s = sm.scans.get(scanId);
    if (s && ['completed', 'stopped', 'error'].includes(s.status)) break;
    if (deadline > 0 && Date.now() >= deadline) break;
    await new Promise((r) => setTimeout(r, 200));
  }

  const report = sm.getReport(scanId);
  if (scopeRules?.enabled) { try { releaseScanScope(scanId); } catch { /* ignore */ } }
  eventBus.dispose(scanId);
  return report;
}

// 攻击操作（对标 sqlmap --os-cmd / --sql-shell / --file-read / --file-write）：
// 复用引擎 Exploiter 对「首个命中注入点」执行。安全红线与 REST 层一致：
//   ① 服务端 EXPLOIT_ENABLED=1 显式开启（双刃剑默认关闭）
//   ② CLI 需显式声明 --authorized（仅限已授权渗透场景）
// 返回 { ok, ... } 或 null（条件不满足/无注入点时打印原因并返回 null）。
async function runExploit(report, args) {
  if (!report || !report.vulns || !report.vulns.length) {
    console.error('[exploit] 未发现注入点，无法执行利用操作');
    return null;
  }
  if (process.env.EXPLOIT_ENABLED !== '1') {
    console.error('[exploit] 利用操作未启用：需设置环境变量 EXPLOIT_ENABLED=1（安全红线，与 REST 层一致）');
    return null;
  }
  if (!args.authorized) {
    console.error('[exploit] 利用操作需显式声明 --authorized（仅限已授权渗透场景）');
    return null;
  }
  const vuln = report.vulns[0];
  const point = (report.points || []).find(p => p.id === vuln.pointId) || (report.points || [])[0];
  if (!point) {
    console.error('[exploit] 报告缺少注入点信息（point）');
    return null;
  }
  const target = report.target || {};
  const exploiter = new Exploiter();
  const ctx = {
    httpClient,
    config: target.config || {},
    target,
    point,
    dbms: report.dbms || vuln.dbms || null,
  };
  let result;
  if (args.udfInstall) {
    console.error(`[exploit] UDF 全链投递（hex=${args.udfHex || '未指定'}）`);
    result = await exploiter.udfInstall(ctx, { hexPath: args.udfHex });
  } else if (args.osCmd) {
    console.error(`[exploit] 执行系统命令: ${args.osCmd}`);
    result = await exploiter.osShell(ctx, args.osCmd);
  } else if (args.osShell === true) {
    await runShellRepl('os', ctx, exploiter);
    return null;
  } else if (typeof args.osShell === 'string') {
    console.error(`[exploit] 执行系统命令: ${args.osShell}`);
    result = await exploiter.osShell(ctx, args.osShell);
  } else if (args.sqlShell === true) {
    await runShellRepl('sql', ctx, exploiter);
    return null;
  } else if (typeof args.sqlShell === 'string') {
    console.error(`[exploit] 执行 SQL: ${args.sqlShell}`);
    result = await exploiter.sqlShell(ctx, args.sqlShell);
  } else if (args.fileRead) {
    console.error(`[exploit] 读取目标文件: ${args.fileRead}`);
    result = await exploiter.fileRead(ctx, args.fileRead);
  } else if (args.fileWrite) {
    if (!args.fileDest) {
      console.error('[exploit] --file-write 需配合 --file-dest <远程路径>');
      return null;
    }
    console.error(`[exploit] 写入目标文件: ${args.fileDest}`);
    result = await exploiter.fileWrite(ctx, args.fileWrite, args.fileDest);
  }
  console.log(JSON.stringify(result, null, 2));
  return result;
}

// 交互式 shell REPL（对标 sqlmap --sql-shell / --os-shell）：
// readline 循环，逐条执行并打印结果，exit/quit 退出。输出走 stderr 提示、stdout 结果。
async function runShellRepl(kind, ctx, exploiter) {
  const readline = await import('node:readline/promises');
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  console.error(`[${kind}-shell] 交互模式（对标 sqlmap --${kind}-shell）；输入 exit 退出`);
  try {
    for (;;) {
      const line = (await rl.question(`${kind}-shell> `)).trim();
      if (!line) continue;
      if (line === 'exit' || line === 'quit') break;
      const r = kind === 'sql' ? await exploiter.sqlShell(ctx, line) : await exploiter.osShell(ctx, line);
      if (r && r.ok) {
        const out = r.value ?? r.raw ?? (r.status != null ? `status=${r.status}` : '(无回显)');
        console.log(typeof out === 'string' ? out : JSON.stringify(out, null, 2));
        if (r.note) console.error(`[*] ${r.note}`);
      } else {
        console.error(`[!] ${r?.error || '执行失败'}`);
      }
    }
  } finally {
    rl.close();
  }
}

// [对标 sqlmap --identify-waf] 只做 WAF 指纹识别 + 推荐 tamper 链：
//   ① 被动：抓一次基线响应，用响应头/体匹配 62 个 WAF 指纹（零额外发包）
//   ② 主动：发 WAF 触发 payload 观察拦截响应（被动无果时的兜底）
// 全程不发起注入检测，对目标零检出副作用；用于扫描前「先摸清对面是什么 WAF」。
async function runIdentifyWaf(args) {
  const { WafIdentifier } = await import('../src/core/waf/WafIdentifier.js');
  const { recommend } = await import('../src/core/waf/wafRecommend.js');
  const { buildEgressOpts } = await import('../src/engine/egressOpts.js');
  const waf = new WafIdentifier();
  const vendors = new Map();

  // ① 被动识别（基线响应）
  try {
    const res = await httpClient.request(
      buildEgressOpts({}, {
        method: 'GET',
        url: args.url,
        headers: args.headers ? parseHeaders(args.headers) : {},
      })
    );
    const cands = waf.identify({ status: res?.status, headers: res?.headers || {}, body: String(res?.data ?? '') });
    for (const c of cands) {
      if (c && c.vendor) vendors.set(c.vendor, c);
    }
  } catch (e) {
    console.error(`[identify-waf] 基线请求失败：${e.message}`);
  }

  // ② 主动探测（仅在无厂商命中时才有意义，但这里保留：多一路证据不亏）
  try {
    const probe = await waf.activeProbe({ baseUrl: args.url, url: args.url, config: {} }, httpClient);
    if (probe && probe.detected) {
      const v = probe.vendor || 'unknown';
      const prev = vendors.get(v);
      if (!prev || (probe.confidence || 0) > (prev.confidence || 0)) {
        vendors.set(v, { vendor: v, confidence: probe.confidence, evidence: 'active probe' });
      }
    }
  } catch (e) {
    console.error(`[identify-waf] 主动探测失败：${e.message}`);
  }

  const list = [...vendors.values()].sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
  if (!list.length) {
    console.log(JSON.stringify({
      target: args.url,
      waf: { detected: false },
      note: '未识别到已知 WAF 指纹：可能是自研/未收录设备，或当前请求未触发拦截（可加 --proxy 或指定路径重试）',
    }, null, 2));
    return;
  }
  const rec = recommend(list.map((v) => ({ vendor: v.vendor })));
  console.log(JSON.stringify({
    target: args.url,
    waf: {
      detected: true,
      vendors: list.map((v) => ({ vendor: v.vendor, confidence: v.confidence, evidence: v.evidence || null })),
      best: list[0].vendor,
    },
    recommendedTamper: rec,
  }, null, 2));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  // 对标 sqlmap -r：请求文件优先于 -u，先应用再校验目标参数
  if (args.requestFile && !applyRequestFile(args)) process.exit(1);
  // 对标 sqlmap -l / -m：日志文件与批量文件同样可替代 -u
  if (args.help || (!args.url && !args.batch && !args.direct && !args.logFile)) {
    printHelp();
    process.exit(args.help ? 0 : 1);
  }
  // 自定义 tamper 文件（--tamper=path/to/custom.js）异步加载注册（buildConfig 消费 tamperResolved）
  if (args.tamper) {
    args.tamperResolved = await resolveTamperPlugins(args.tamper);
  }
  // 对标 sqlmap --check-tor：先验证 Tor 出口（失败退出，不发起任何扫描）
  if (args.checkTor) {
    const proxy = args.tor ? 'socks5://127.0.0.1:9050' : args.proxy;
    if (!proxy) {
      console.error('--check-tor 需要配合 --tor 或 --proxy 使用');
      process.exit(1);
    }
    if (!(await checkTor(proxy))) process.exit(1);
  }

  // [对标 sqlmap --identify-waf] 识别完成即退出，不进入扫描流程
  if (args.identifyWaf) {
    await runIdentifyWaf(args);
    process.exit(0);
  }

  // 枚举参数组合校验（对标 sqlmap 用法约束）
  const enumErr = validateEnumArgs(args);
  if (enumErr) {
    console.error(enumErr);
    process.exit(1);
  }
  const enumActive = isEnumMode(args);

  // ---- 批量模式 ----
  if (args.batch) {
    const urls = readUrlList(args.batch);
    // [P1-2] 全局限速：每个扫描实例的 ratePerSec = 总速率 / 并发数
    // 确保多个并发扫描的总速率 ≤ ratePerSec，防止打爆目标
    const perScanRate = Math.max(1, Math.ceil(args.ratePerSec / args.concurrency));
    console.error(`批量扫描 ${urls.length} 个目标，并发 ${args.concurrency}，每扫描限速 ${perScanRate} req/s（总 ≤ ${args.ratePerSec} req/s）`);
    const results = [];
    // [P1-2] 共享 HttpClient：批量模式所有 ScanManager 共用同一个 httpClient 单例
    // → 所有 scanId 的令牌桶都在同一个 buckets Map 中，forScan 时共享底层的串行化 Promise 链
    // 均分方案 + 共享 HttpClient = 总速率严格 ≤ ratePerSec
    // （原实现每 URL new ScanManager 但 ScanManager 构造器已用模块级 httpClient 单例，
    //  实际已共享；此注释确认此行为是正确设计而非巧合）
    // 并发池：按 args.concurrency 限制并发数
    const pool = async (items, worker, concurrency) => {
      const queue = items.slice();
      let cursor = 0;
      const next = async () => {
        while (cursor < queue.length) {
          const item = queue[cursor++];
          await worker(item);
        }
      };
      await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, () => next()));
    };
    await pool(urls, async (url) => {
      const sm = new ScanManager();
      // 用均分后的速率替换原始 ratePerSec
      const scanArgs = { ...args, ratePerSec: perScanRate };
      const report = await runSingleScan(sm, url, scanArgs);
      results.push({ url, report, riskLevel: report?.riskLevel || 'error', vulns: report?.vulns?.length || 0 });
      console.error(`[${results.length}/${urls.length}] ${url} → ${report?.riskLevel || '失败'}`);
    }, args.concurrency);

    // 聚合摘要
    const byRisk = {};
    for (const r of results) { byRisk[r.riskLevel] = (byRisk[r.riskLevel] || 0) + 1; }
    console.error(`\n批量扫描完成：${results.length} 个目标`);
    console.error(`  风险分布: ${Object.entries(byRisk).map(([k, v]) => `${k}=${v}`).join(' ')}`);

    if (args.out) {
      const { writeFileSync, mkdirSync } = await import('node:fs');
      const { join } = await import('node:path');
      mkdirSync(args.out, { recursive: true });
      // [P1-FIX 2026-09-05] 批量模式同样按 --format 分发（每 URL 一份，扩展名随格式）
      const fmt = String(args.format || 'json').toLowerCase();
      const ext = fmt === 'markdown' || fmt === 'md' ? 'md' : fmt;
      for (const r of results) {
        if (r.report) {
          const safeName = r.url.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 100);
          writeFileSync(join(args.out, `${safeName}.${ext}`), formatReport(r.report, fmt), 'utf-8');
        }
      }
      console.error(`报告已写入 ${args.out}/（格式 ${fmt}）`);
    } else {
      console.log(JSON.stringify(results.map(r => ({ url: r.url, riskLevel: r.riskLevel, vulns: r.vulns })), null, 2));
    }

    const hasHigh = results.some(r => r.riskLevel === 'Critical' || r.riskLevel === 'High');
    process.exit(hasHigh ? 2 : 0);
  }

  // ---- 日志文件批量模式（对标 sqlmap -l） ----
  if (args.logFile) {
    const requests = parseLogFile(args.logFile);
    if (requests.length === 0) {
      console.error('日志文件未解析出任何请求（支持 Burp XML 导出或纯文本多请求日志）');
      process.exit(1);
    }
    const perScanRate = Math.max(1, Math.ceil(args.ratePerSec / args.concurrency));
    console.error(`日志批量 ${requests.length} 个请求，并发 ${args.concurrency}，每扫描限速 ${perScanRate} req/s（总 ≤ ${args.ratePerSec} req/s）`);
    const results = [];
    const pool = async (items, worker, concurrency) => {
      const queue = items.slice();
      let cursor = 0;
      const next = async () => {
        while (cursor < queue.length) {
          const item = queue[cursor++];
          await worker(item);
        }
      };
      await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, () => next()));
    };
    await pool(requests, async (req) => {
      const sm = new ScanManager();
      // 每请求从 args 派生扫描参数：覆盖 url/method/body/headers/cookie（复用 -r 的字段映射逻辑）
      const scanArgs = { ...args, ratePerSec: perScanRate };
      scanArgs.url = req.url;
      scanArgs.method = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? req.method : 'GET';
      if (req.body) {
        const bodyJson = bodyToJsonString(req.body);
        if (bodyJson) scanArgs.body = bodyJson;
      }
      const cookieKey = Object.keys(req.headers).find(k => k.toLowerCase() === 'cookie');
      if (cookieKey) scanArgs.cookie = req.headers[cookieKey];
      const other = {};
      for (const [k, v] of Object.entries(req.headers)) {
        const kl = k.toLowerCase();
        if (kl === 'cookie' || kl === 'host' || kl === 'content-length') continue;
        other[k] = v;
      }
      if (Object.keys(other).length) scanArgs.headerObj = other;
      const report = await runSingleScan(sm, req.url, scanArgs);
      results.push({ url: req.url, report, riskLevel: report?.riskLevel || 'error', vulns: report?.vulns?.length || 0 });
      console.error(`[${results.length}/${requests.length}] ${req.url} → ${report?.riskLevel || '失败'}`);
    }, args.concurrency);

    const byRisk = {};
    for (const r of results) { byRisk[r.riskLevel] = (byRisk[r.riskLevel] || 0) + 1; }
    console.error(`\n日志批量扫描完成：${results.length} 个请求`);
    console.error(`  风险分布: ${Object.entries(byRisk).map(([k, v]) => `${k}=${v}`).join(' ')}`);

    if (args.out) {
      const { writeFileSync, mkdirSync } = await import('node:fs');
      const { join } = await import('node:path');
      mkdirSync(args.out, { recursive: true });
      // [P1-FIX 2026-09-05] 批量模式同样按 --format 分发（每 URL 一份，扩展名随格式）
      const fmt = String(args.format || 'json').toLowerCase();
      const ext = fmt === 'markdown' || fmt === 'md' ? 'md' : fmt;
      for (const r of results) {
        if (r.report) {
          const safeName = r.url.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 100);
          writeFileSync(join(args.out, `${safeName}.${ext}`), formatReport(r.report, fmt), 'utf-8');
        }
      }
      console.error(`报告已写入 ${args.out}/（格式 ${fmt}）`);
    } else {
      console.log(JSON.stringify(results.map(r => ({ url: r.url, riskLevel: r.riskLevel, vulns: r.vulns })), null, 2));
    }
    const hasHigh = results.some(r => r.riskLevel === 'Critical' || r.riskLevel === 'High');
    process.exit(hasHigh ? 2 : 0);
  }

  // ---- 单目标模式（HTTP 或直连） ----
  const sm = new ScanManager();
  const report = await runSingleScan(sm, args.direct || args.url, args);
  if (!report) {
    console.error('扫描超时或报告不存在');
    process.exit(1);
  }

  const jsonContent = JSON.stringify(report, null, 2);
  const exploitMode = !!(args.osCmd || args.sqlShell || args.fileRead || args.fileWrite);
  if (args.out) {
    const { writeFileSync } = await import('node:fs');
    // [P1-FIX 2026-09-05] 按 --format 分发导出（json|csv|markdown|html），与 REST /report/export 同源
    const fmt = String(args.format || 'json').toLowerCase();
    writeFileSync(args.out, formatReport(report, fmt), 'utf-8');
    console.error(`报告已写入 ${args.out}（格式 ${fmt}）`);
  } else if (enumActive || args.dump) {
    // 枚举/拖库模式：默认打印 report.data 精简视图（文本，对标 sqlmap 终端输出）
    printExtractView(report);
  } else if (!exploitMode) {
    console.log(jsonContent);
  }

  // 攻击操作（对标 sqlmap --os-cmd/--sql-shell/--file-read/--file-write）：
  // 需 EXPLOIT_ENABLED=1 + --authorized；对首个命中注入点执行并打印结果
  if (exploitMode) {
    await runExploit(report, args);
    const risk = report.riskLevel;
    process.exit(risk === 'Critical' || risk === 'High' ? 2 : 0);
  }

  const risk = report.riskLevel;
  process.exit(risk === 'Critical' || risk === 'High' ? 2 : 0);
}

// 仅在直接以脚本运行时启动 main（import 进测试时不触发）
import { pathToFileURL } from 'node:url';
const invokedDirectly = (() => {
  try {
    return process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main().catch((e) => {
    logger.error(`CLI 执行失败：${e.message}`);
    console.error(e.message);
    process.exit(1);
  });
}

// 导出供单测使用（parseArgs / buildConfig / buildExtractScope / printExtractView）
export { parseArgs, buildConfig, buildExtractScope, validateEnumArgs, printExtractView, runSingleScan, applyRequestFile, resolveTamperPlugins, buildInjectionTargets };