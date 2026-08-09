#!/usr/bin/env node
// sqli-scanner 命令行入口（对标 sqlmap CLI 形态）
// 不依赖 Express，直接 import ScanManager 在进程内跑扫描、轮询报告、打印结果。
//
// 用法示例：
//   node cli.js -u "http://target/vuln.php?id=1"
//   node cli.js -u "http://target/login" -m POST --data "user=admin&pass=1"
//   node cli.js -u "http://t/?id=1" --techniques union,error,boolean,time,stacked
//   node cli.js -u "http://t/?id=1" --tamper "space2comment,randomcase" --random-ua
//   node cli.js -u "http://t/?id=1" --no-extract --json
//   node cli.js -u "http://t/?id=1" --second-order "http://t/profile.php" --dump
import { ScanManager } from './src/engine/ScanManager.js';
import { validateRiskGate, MIN_RISK, RISK_MIN } from './src/engine/riskGate.js';
import { validateDetectMatch } from './src/engine/detectionMatch.js';

const HELP = `
sqli-scanner CLI（对标 sqlmap）

必填：
  -u, --url <url>            目标 URL（含一个待测参数，如 ?id=1）

可选：
  -m, --method <GET|POST>    请求方法（默认 GET）
  --data <k=v&k2=v2>         POST 表单参数 / GET 附加查询参数
  --cookie <k=v; k2=v2>      Cookie（分号分隔）
  -t, --techniques <list>    启用的检测技术，逗号分隔
                              （默认 union,error,boolean,time；可选 stacked,oob）
  --level <1-5>              等级（对标 sqlmap --level）：扩展注入点位置（1=仅 URL/Body；2=+Cookie；3=+Header 含自动 User-Agent/Referer）。并作 techniques 快捷（1=union；2=+error；3=+boolean；4=+time；5=+stacked，可用 --techniques 覆盖）
  --threads <n>              并发数（默认 4）
  --tamper <list>            启用 tamper 混淆链（逗号分隔插件名）
  --random-ua                随机 User-Agent 池
  --jitter <ms>              请求间随机延时（毫秒）
  --no-keep-alive            关闭 TCP 连接复用（每次请求新连接，Connection: close；规避连接级指纹/速率限制）
  --no-extract               关闭拖库（仅检测，更快）
  --second-order <list>      启用二阶注入，逗号分隔触发页 URL
  --prefix <str>             注入边界前缀（sqlmap 风格，置于原始值之后、payload 之前，如 ')")
  --suffix <str>             注入边界后缀（sqlmap 风格，置于末尾注释掉残余 SQL，如 '-- -' 或 '#')
  --dbms <name>              强制 DBMS（跳过自动指纹）：mysql/mariadb/postgresql/oracle/sqlite/mssql
  --union-cols <n|min-max>   UNION 列数调优：精确值（如 5）跳过枚举，或范围（如 3-8）约束枚举上下界
  --union-char <str>          UNION 回显标记基串（默认 SQLISCANNER，覆盖以避开 WAF 关键字）
  --proxy <url>              代理地址（http://host:port 或 socks5://host:port），默认不走代理
  --timeout <sec>            单请求超时（秒，默认 10）
  --retries <n>              失败重试次数（默认 2）
  --search <kw>              表名/列名关键字搜索（枚举后过滤，大小写不敏感；如 user）
  --string <str>             自定义判定锚点：TRUE 响应应包含该串（布尔/时间盲注确定性判定，对标 sqlmap --string）
  --not-string <str>         自定义判定锚点：TRUE 响应应不含、FALSE 响应应含该串（对标 --not-string）
  --regexp <re>              自定义判定锚点：该正则应匹配 TRUE 响应、不匹配 FALSE 响应（对标 --regexp）
  --code <n>                 自定义判定锚点：TRUE 响应 HTTP 状态码应为 n、FALSE 响应不应为 n（对标 --code）
  --safe-url <url>           安全间隔探测 URL（对标 sqlmap --safe-url；偏离基线即告警；支持逗号分隔多个，随机轮询）
  --safe-urls <csv>          多个安全 URL（逗号分隔，等价于 --safe-url 多值；随机轮询探测）
  --safe-freq <n>            每 N 次真实请求穿插一次安全探测（默认 0=关闭）
  --safe-order               关闭随机，顺序轮询多个安全 URL（默认随机，更隐蔽）
  --risk <1-3>               风险分级（对标 sqlmap --risk）：1=仅一阶基础技术（默认）；
                              2=允许二阶注入/堆查询；3=额外允许带外(OOB)。风险不足启用高风险
                              技术将被拦截。注意 --level 5（含堆查询）隐含至少 --risk 2
  --dump                     打印拖出的数据行（默认只打印行数统计）
  --json                     以 JSON 打印完整报告
  --output <file>            把完整 JSON 报告写入文件
  -h, --help                 显示本帮助
`;

function parseArgs(argv) {
  const args = {
    url: null,
    method: 'GET',
    data: null,
    cookie: null,
    techniques: null,
    level: null,
    threads: 4,
    tamper: null,
    randomUa: false,
    jitter: 0,
    noExtract: false,
    secondOrder: null,
    prefix: null,
    suffix: null,
    dbms: null,
    unionCols: null,
    unionChar: null,
    timeout: null,
    retries: null,
    proxy: null,
    search: null,
    risk: null,
    timeSec: null,
    safeUrl: null,
    safeFreq: null,
    safeUrls: null,
    safeOrder: false,
    delay: null,
    hpp: false,
    noKeepAlive: false,
    string: null,
    notString: null,
    regexp: null,
    code: null,
    dump: false,
    json: false,
    output: null,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case '-u':
      case '--url':
        args.url = next();
        break;
      case '-m':
      case '--method':
        args.method = (next() || 'GET').toUpperCase();
        break;
      case '--data':
        args.data = next();
        break;
      case '--cookie':
        args.cookie = next();
        break;
      case '-t':
      case '--techniques':
        args.techniques = next();
        break;
      case '--level':
        args.level = Number(next());
        break;
      case '--threads':
        args.threads = Number(next()) || 4;
        break;
      case '--tamper':
        args.tamper = next();
        break;
      case '--random-ua':
        args.randomUa = true;
        break;
      case '--jitter':
        args.jitter = Number(next()) || 0;
        break;
      case '--no-extract':
        args.noExtract = true;
        break;
      case '--second-order':
        args.secondOrder = next();
        break;
      case '--prefix':
        args.prefix = next();
        break;
      case '--suffix':
        args.suffix = next();
        break;
      case '--dbms':
        args.dbms = next();
        break;
      case '--union-cols':
        args.unionCols = next();
        break;
      case '--union-char':
        args.unionChar = next();
        break;
      case '--proxy':
        args.proxy = next();
        break;
      case '--timeout':
        args.timeout = Number(next());
        break;
      case '--retries':
        args.retries = Number(next());
        break;
      case '--search':
        args.search = next();
        break;
      case '--string':
        args.string = next();
        break;
      case '--not-string':
        args.notString = next();
        break;
      case '--regexp':
        args.regexp = next();
        break;
      case '--code':
        args.code = Number(next());
        break;
      case '--risk':
        args.risk = Number(next());
        break;
      case '--time-sec':
        args.timeSec = Number(next());
        break;
      case '--safe-url':
        args.safeUrl = next();
        break;
      case '--safe-freq':
        args.safeFreq = Number(next());
        break;
      case '--safe-url':
        args.safeUrl = next();
        break;
      case '--safe-urls':
        // 多个安全 URL（逗号分隔），用于随机轮询探测（对标 sqlmap 多 safe-url 隐蔽增强）
        args.safeUrls = (next() || '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        break;
      case '--safe-order':
        args.safeOrder = true; // 关闭随机，顺序轮询多安全 URL
        break;
      case '--delay':
        args.delay = Number(next());
        break;
      case '--hpp':
        args.hpp = true; // 开关型参数，存在即启用
        break;
      case '--no-keep-alive':
        args.noKeepAlive = true; // 开关型参数：存在即关闭 TCP 连接复用（每次请求新连接）
        break;
      case '--dump':
        args.dump = true;
        break;
      case '--json':
        args.json = true;
        break;
      case '--output':
        args.output = next();
        break;
      case '-h':
      case '--help':
        args.help = true;
        break;
      default:
      // 忽略未知参数
    }
  }
  return args;
}

function parseKv(s, sep) {
  if (!s) return {};
  const out = {};
  for (const part of s.split(sep)) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function levelToTechniques(level) {
  const base = ['union', 'error', 'boolean', 'time'];
  if (level >= 5) return [...base, 'stacked'];
  return base.slice(0, Math.min(level, 4));
}

// 归一化 --dbms 到引擎内部键（大小写/常用别名 → MySQL/MariaDB/PostgreSQL/Oracle/SQLite/SQL Server）
const DBMS_ALIAS = {
  mysql: 'MySQL',
  mariadb: 'MariaDB',
  postgresql: 'PostgreSQL',
  postgres: 'PostgreSQL',
  oracle: 'Oracle',
  sqlite: 'SQLite',
  mssql: 'SQL Server',
  sqlserver: 'SQL Server',
  'sql server': 'SQL Server',
};
function normalizeDbms(s) {
  if (!s) return null;
  return DBMS_ALIAS[String(s).trim().toLowerCase()] || s.trim();
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || !args.url) {
    process.stdout.write(HELP);
    if (!args.url && !args.help) process.exitCode = 2;
    return;
  }

  // 构造目标输入
  let url = args.url;
  let bodyParams = {};
  if (args.data) {
    if (args.method === 'POST') {
      bodyParams = parseKv(args.data, '&');
    } else {
      // GET：把 --data 作为附加查询参数拼到 URL
      const u = new URL(url);
      for (const [k, v] of Object.entries(parseKv(args.data, '&'))) {
        u.searchParams.set(k, v);
      }
      url = u.toString();
    }
  }
  const cookieParams = parseKv(args.cookie, ';');

  // 技术选择：--techniques 优先，否则 --level，否则默认
  let techniques = null;
  if (args.techniques) {
    techniques = args.techniques.split(',').map((s) => s.trim()).filter(Boolean);
  } else if (args.level) {
    techniques = levelToTechniques(args.level);
  }
  // --level（对标 sqlmap --level）：独立于 techniques，控制注入点位置扩展
  // （URL/Body → +Cookie → +Header）。写入 config.level 供 TargetParser 门控。
  const lvl = args.level != null && !Number.isNaN(args.level)
    ? Math.min(5, Math.max(1, Number(args.level)))
    : 1;

  const wafEvasion = { randomUA: args.randomUa, jitterMs: args.jitter, obfuscate: false };
  if (args.tamper) {
    wafEvasion.tamper = {
      enabled: true,
      plugins: args.tamper.split(',').map((s) => s.trim()).filter(Boolean),
      intensity: 'medium',
    };
  }

  const config = {
    enableExtract: !args.noExtract,
    concurrency: args.threads,
    wafEvasion,
  };
  // 注入点位置扩展等级（--level）：写入 config.level 供 TargetParser 门控
  // （URL/Body → +Cookie → +Header）。必须在 config 声明后赋值，避免 TDZ。
  config.level = lvl;
  // 注入边界（sqlmap 风格 --prefix/--suffix）：注入点处于字符串/函数上下文时，
  // 用于在原始值后插入前缀打破上下文、在末尾加注释抵消残余 SQL。
  if (args.prefix || args.suffix) {
    config.injectionBoundary = { prefix: args.prefix || '', suffix: args.suffix || '' };
  }
  // 强制 DBMS（--dbms）：跳过自动指纹，直接采用用户指定的库类型
  const dbms = normalizeDbms(args.dbms);
  if (dbms) config.dbms = dbms;
  // UNION 列数调优（--union-cols）：精确值跳过 ORDER BY 枚举，范围约束枚举上下界
  if (args.unionCols != null) config.unionCols = args.unionCols;
  // UNION 回显标记基串（--union-char）：覆盖默认 SQLISCANNER，规避 WAF 关键字检测
  if (args.unionChar != null) config.unionChar = args.unionChar;
  // 运维开关：超时 / 重试 / 代理（透传进 config，经 createTarget 浅合并覆盖 defaults）
  //   --timeout 以秒为单位（sqlmap 风格），引擎内部为毫秒
  if (args.timeout != null && !Number.isNaN(args.timeout)) {
    config.timeoutMs = args.timeout * 1000;
  }
  if (args.retries != null && !Number.isNaN(args.retries)) {
    config.retry = args.retries;
  }
  if (args.proxy != null) config.proxy = args.proxy;
  // 关键字搜索（--search）：表名/列名枚举后大小写不敏感过滤（对标 sqlmap --search）
  if (args.search != null) config.search = args.search;
  // 时间盲注 SLEEP 触发时长（--time-sec，对标 sqlmap --time-sec）。
  // 范围 [1,100]，越界/非数则丢弃走默认 2s（引擎侧会再 clamp）。
  if (args.timeSec != null && !Number.isNaN(args.timeSec)) {
    const v = Math.min(100, Math.max(1, args.timeSec));
    config.timeSec = v;
  }
  // 安全间隔探测（--safe-url / --safe-urls / --safe-freq / --safe-order，对标 sqlmap）：
  // 周期性访问安全 URL（多个则随机轮询，规避 WAF 把固定 safe-url 模式关联到扫描），
  // 偏离基线即告警。safeFreq<=0 或不传 --safe-url 则不启用。
  // --safe-url 支持逗号分隔多 URL（与 --safe-urls 合并去重）。
  const safeUrlList = [];
  if (args.safeUrl != null) {
    safeUrlList.push(...String(args.safeUrl).split(',').map((s) => s.trim()).filter(Boolean));
  }
  if (Array.isArray(args.safeUrls)) safeUrlList.push(...args.safeUrls);
  if (safeUrlList.length > 0) {
    const uniq = [...new Set(safeUrlList)];
    config.safeProbe = {
      url: uniq[0], // 单 URL 旧字段（兼容引擎 / 报告记录）
      urls: uniq, // 多 URL 数组（随机/顺序轮询）
      freq: args.safeFreq != null && !Number.isNaN(args.safeFreq) ? Math.max(1, Number(args.safeFreq)) : 0,
      randomize: !args.safeOrder, // 默认随机；--safe-order 关闭随机走顺序轮询
    };
  }
  // 固定请求间延时（--delay，对标 sqlmap --delay）：单位为秒（sqlmap 风格），引擎内部转毫秒。
  // 与 --jitter 随机延时正交、叠加生效；<0 或非法则丢弃走默认 0（不延时）。
  if (args.delay != null && !Number.isNaN(args.delay) && args.delay >= 0) {
    config.requestDelayMs = Math.round(args.delay * 1000);
  }
  // HTTP 参数污染（--hpp，对标 sqlmap）：开关型，存在即启用。仅对 URL 注入点展开同名多值。
  if (args.hpp) config.hpp = true;
  // 连接复用（--no-keep-alive，对标 sqlmap）：开关型，存在即关闭 TCP 连接复用（Connection: close）。
  // 默认复用（keepAlive=true），与现有 axios 行为一致、零回归；--no-keep-alive 用于规避连接级指纹/速率限制。
  if (args.noKeepAlive) config.keepAlive = false;
  // 自定义检测判定锚点（--string/--not-string/--regexp/--code）：任一设置即构建 detectMatch
  if (args.string != null || args.notString != null || args.regexp != null || args.code != null) {
    config.detectMatch = {
      string: args.string != null ? args.string : null,
      notString: args.notString != null ? args.notString : null,
      regexp: args.regexp != null ? args.regexp : null,
      code: args.code != null ? args.code : null,
    };
  }
  if (techniques) config.techniques = techniques;
  if (args.secondOrder) {
    config.secondOrder = {
      enabled: true,
      triggerUrls: args.secondOrder.split(',').map((s) => s.trim()).filter(Boolean),
      refreshCsrf: true,
      negativeControl: true,
      oobTrigger: false,
    };
  }

  // 风险分级（--risk）：对标 sqlmap --risk，门控二阶/堆查询/OOB。
  // --level 5 隐含堆查询(stacked) → 至少 risk 2，与门控一致（避免 level5 被门控误伤）。
  let risk = args.risk != null && !Number.isNaN(args.risk) ? Number(args.risk) : MIN_RISK;
  if (args.level != null && args.level >= 5) risk = Math.max(risk, RISK_MIN.stacked);
  config.risk = risk;

  // --risk 门控校验：风险不足却启用二阶/堆查询/OOB 直接拦截（不向目标发起任何请求）
  try {
    validateRiskGate(config);
    validateDetectMatch(config); // 提前拦截非法 --regexp/--code，避免静默忽略
  } catch (e) {
    process.stdout.write(`[-] 配置被拦截：${e.message}\n`);
    process.exitCode = 2;
    return;
  }

  const mgr = new ScanManager();
  const scanId = await mgr.start({
    url,
    method: args.method,
    bodyParams,
    cookieParams,
    config,
  });
  process.stdout.write(`[+] 扫描已启动 scanId=${scanId}  target=${url}\n`);

  // 轮询报告
  let report = null;
  let lastVulnCount = -1;
  const deadline = Date.now() + 5 * 60 * 1000;
  while (Date.now() < deadline) {
    const r = mgr.getReport(scanId);
    if (r && r.finishedAt) {
      report = r;
      break;
    }
    if (r) {
      const n = (r.vulns || []).length;
      if (n !== lastVulnCount) {
        lastVulnCount = n;
        process.stdout.write(`[.] 检测中… 已发现漏洞 ${n} 个\n`);
      }
    }
    await sleep(500);
  }

  if (!report) {
    process.stdout.write('[-] 扫描超时未完成\n');
    process.exitCode = 1;
    return;
  }

  // 输出
  if (args.json) {
    const out = args.output ? JSON.stringify(report, null, 2) : JSON.stringify(report);
    if (args.output) {
      const fs = await import('node:fs');
      fs.writeFileSync(args.output, out);
      process.stdout.write(`[+] 报告已写入 ${args.output}\n`);
    } else {
      process.stdout.write(out + '\n');
    }
    return;
  }

  // 人类可读摘要
  process.stdout.write('\n========== 扫描结果 ==========\n');
  process.stdout.write(`目标:    ${report.target?.baseUrl}\n`);
  process.stdout.write(`DBMS:    ${report.dbms || '未知'}\n`);
  process.stdout.write(`风险:    ${report.riskLevel}\n`);
  process.stdout.write(`注入点:  ${(report.points || []).length} 个\n`);
  process.stdout.write('\n--- 漏洞 ---\n');
  for (const v of report.vulns || []) {
    process.stdout.write(
      `  [${v.riskLevel}] ${v.technique}  point=${v.pointId} dbms=${v.dbms || '-'}\n`
    );
    if (v.payloads && v.payloads.length) {
      process.stdout.write(`        payload: ${v.payloads[0]}\n`);
    }
  }

  if (report.data) {
    process.stdout.write('\n--- 拖库 ---\n');
    for (const db of report.data.databases || []) {
      const tables = report.data.tables[db] || [];
      for (const t of tables) {
        const rows = report.data.rows[`${db}.${t}`] || [];
        process.stdout.write(`  ${db}.${t}: ${rows.length} 行\n`);
        if (args.dump) {
          for (const row of rows) {
            process.stdout.write(`    ${JSON.stringify(row)}\n`);
          }
        }
      }
    }
  }

  if (args.output) {
    const fs = await import('node:fs');
    fs.writeFileSync(args.output, JSON.stringify(report, null, 2));
    process.stdout.write(`\n[+] 完整报告已写入 ${args.output}\n`);
  }
  process.stdout.write('==============================\n');
}

main().catch((e) => {
  process.stdout.write(`[-] 错误: ${e.message}\n`);
  process.exitCode = 1;
});
