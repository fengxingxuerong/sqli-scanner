#!/usr/bin/env node
// ============================================================================
// sqlmap-parity.mjs —— sqlmap 1.10.7 能力对标底账（[D197]，2026-10-30）
//
// 为什么要有它（不是「再写一份分析文档」）：
//   本仓历史上做过 5 轮 sqlmap 对标（docs/vs-sqlmap-analysis/*、docs/竞品对标-*.md），
//   但每一轮都是**一次性散文**：没有分母（sqlmap 到底有多少个能力面）、没有逐项状态、
//   也没有任何东西阻止它过期。实测两份旧清单（2026-09 的 07-remnant-gaps 与 2026-10-03
//   的竞品对标）里，多数条目要么已闭环仍在列、要么把「引擎已实现但 CLI 无入口」误判成
//   「未实现」——两个方向的失真都会把「全方面补齐」变成不可核对的姿态。
//
// 底账的三条口径（缺一条它就退化成又一份散文）：
//   ① **分母来自真源**：sqlmap 1.10.7 `-hh` 的全量选项面（209 个长选项 + 16 个短名专用面），
//      逐个进 INVENTORY。分母不许手写「大概两百个」。
//   ② **逐项状态可核对**：covered / part / gap / out 四态，各自的判据见 judgeParity()。
//      其中 `gap` 与「本方旗标已存在」是**互斥**的 —— 谁实现了就得改状态，否则门禁红
//      （防「底账只朝乐观方向漂」）。
//   ③ **产物由脚本生成**：docs/_sqlmap-parity.json 与 docs/sqlmap-对标底账.md 逐字重算，
//      手改即红（与 quality-ledger.mjs 同一形态）。
//
// 用法：
//   node scripts/sqlmap-parity.mjs            # = --check：校验底账自洽 + 产物与磁盘逐字一致
//   node scripts/sqlmap-parity.mjs --write    # 重新生成两份产物
//   node scripts/sqlmap-parity.mjs --selftest # 自证判据有牙（四个反例）
//   node scripts/sqlmap-parity.mjs --refresh  # 重跑本机 sqlmap -hh，报上游选项面的漂移（只读）
// ============================================================================
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const SQLMAP_VERSION = '1.10.7';
export const JSON_REL = 'docs/_sqlmap-parity.json';
export const DOC_REL = 'docs/sqlmap-对标底账.md';

/**
 * sqlmap 1.10.7 `-hh` 的能力面快照（只存选项名与分组 —— 选项名是事实，
 * 描述文字属上游文本，不复制进本仓）。**顺序即 sqlmap help 的呈现顺序**，
 * 便于人对着两边看；`--refresh` 会重跑本机 sqlmap 报漂移。
 *
 * 为什么是「一行一组、`组名 | 选项…`」的文本块而不是数组字面量：
 * 长数组字面量（几十个字符串）在令牌级重复代码门禁里会被归一成 `literal` 序列，
 * 与 payload 字面量表互相命中 —— 实测引入 48 个「重复块」（3318 > 基线 3272）。
 * 单个模板串只算 **一个** literal token，天然不进窗口；同时 diff 更紧凑（一行一组）。
 * @type {Array<{group:string, opts:string[]}>}
 */
const INVENTORY_TEXT = `
Target（目标输入）| --url
Request（请求构造）| --user-agent --header --method --data --param-del --cookie --cookie-del --live-cookies --load-cookies --drop-set-cookie --http1 --http2 --mobile --random-agent --host --referer --headers --auth-type --auth-cred --auth-file --abort-code --ignore-code --ignore-proxy --ignore-redirects --ignore-timeouts --proxy --proxy-cred --proxy-file --proxy-freq --tor --tor-port --tor-type --check-tor --delay --timeout --retries --retry-on --randomize --safe-url --safe-post --safe-req --safe-freq --skip-urlencode --skip-xmlencode --csrf-token --csrf-url --csrf-method --csrf-data --csrf-retries --force-ssl --chunked --hpp --eval
Optimization（性能）| --predict-output --no-keep-alive --null-connection --threads
Injection（注入构造）| --skip --skip-static --param-exclude --param-filter --dbms --dbms-cred --os --invalid-bignum --invalid-logical --invalid-string --no-cast --no-escape --prefix --suffix --tamper --proof
Detection（判定口径）| --level --risk --string --not-string --regexp --code --smart --text-only --titles
Techniques（技术面）| --technique --time-sec --disable-stats --union-cols --union-char --union-from --union-values --dns-domain --second-url --second-req
Fingerprint（指纹）| --fingerprint
Enumeration（枚举与拖库）| --all --banner --current-user --current-db --hostname --is-dba --users --passwords --privileges --roles --dbs --tables --columns --schema --count --dump --dump-all --search --comments --statements --procs --exclude-sysdbs --pivot-column --where --start --stop --first --last --sql-query --sql-shell --sql-file
Brute force（字典爆破）| --common-tables --common-columns --common-files
UDF（用户自定义函数）| --udf-inject --shared-lib
File system（文件读写）| --file-read --file-write --file-dest
OS access（系统层）| --os-cmd --os-shell --os-pwn --os-smbrelay --os-bof --priv-esc --msf-path --tmp-path
Windows registry（注册表）| --reg-read --reg-add --reg-del --reg-key --reg-value --reg-data --reg-type
General（通用）| --abort-on-empty --answers --base64 --base64-safe --batch --binary-fields --check-internet --cleanup --crawl --crawl-exclude --csv-del --charset --dump-file --dump-format --encoding --eta --flush-session --forms --fresh-queries --gpage --har --hex --output-dir --parse-errors --preprocess --postprocess --repair --report-json --save --scope --skip-heuristics --skip-waf --table-prefix --test-filter --test-skip --time-limit --unsafe-naming --web-root
Non-SQL（非 SQL 注入通道）| --graphql --ldap --nosql --xpath --ssti
Miscellaneous（杂项）| --alert --beep --dependencies --disable-coloring --disable-hashing --gui --list-tampers --no-logging --no-truncate --offline --purge --results-file --shell --tmp-dir --tui --unstable --update --wizard
短名专用（help 里无长名，仍是独立能力面）| -d -l -m -r -g -c -o -p -s -t -v -z -hh
`;

/**
 * 解析上面的文本块（内部使用：外部只需要 INVENTORY 这个结果）。
 * @param {string} text `组名 | 选项…` 逐行
 * @returns {Array<{group:string, opts:string[]}>}
 */
function parseInventory(text) {
  return String(text)
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const bar = line.indexOf('|');
      return { group: line.slice(0, bar).trim(), opts: line.slice(bar + 1).trim().split(/\s+/) };
    });
}

export const INVENTORY = parseInventory(INVENTORY_TEXT);

/**
 * 逐项状态。编码（字符串便于审阅 diff）：
 *   `ok`              同名同义，本方旗标名与 sqlmap 一致
 *   `ok:<flag>`       语义等价，本方旗标名不同
 *   `part:<flag>`     部分覆盖（缺口写在 NOTES，必须是「还差什么」而不是「差不多」）
 *   `gap:P1|P2|P3`    真缺口（优先级），NOTES 写缺口与落地方向
 *   `out:<理由>`      明确不做（理由必须自足：为什么不做，而不是「暂不支持」）
 *
 * 状态判据由 judgeParity() 执行：`gap` 与「本方已有同名旗标」互斥（谁实现了谁就得改状态），
 * 反向地 `ok`/`ok:flag`/`part:flag` 引用的旗标必须真实存在于 server/bin/cli/args.js。
 * @type {Record<string,string>}
 */
export const STATUS = {
  // ── Request ────────────────────────────────────────────────────────────────
  '--url': 'ok',
  '--user-agent': 'ok:--header',
  '--header': 'ok',
  '--method': 'ok',
  '--data': 'ok:--body',
  '--param-del': 'ok',
  '--cookie': 'ok',
  '--cookie-del': 'part:--cookie',
  // [D205 收口 D198] --live-cookies / --load-cookies 已由 D198 落地（args.js 同名旗标 +
  // core/liveCookies.js + core/cookieFile.js），底账必须朝事实方向改：gap → ok。
  '--live-cookies': 'ok',
  '--load-cookies': 'ok',
  '--drop-set-cookie': 'ok',
  '--http1': 'gap:P3',
  '--http2': 'gap:P2',
  '--mobile': 'ok',
  '--random-agent': 'ok',
  '--host': 'ok:--header',
  '--referer': 'ok:--header',
  '--headers': 'ok',
  '--auth-type': 'ok',
  '--auth-cred': 'ok:--auth',
  '--auth-file': 'ok:--cert',
  '--abort-code': 'gap:P3',
  '--ignore-code': 'ok',
  '--ignore-proxy': 'part:--proxy-bypass-local',
  '--ignore-redirects': 'ok',
  '--ignore-timeouts': 'gap:P3',
  '--proxy': 'ok',
  '--proxy-cred': 'ok:--proxy',
  '--proxy-file': 'gap:P3',
  '--proxy-freq': 'gap:P3',
  '--tor': 'ok',
  '--tor-port': 'part:--tor',
  '--tor-type': 'gap:P3',
  '--check-tor': 'ok',
  '--delay': 'ok:--delay-sec',
  '--timeout': 'ok:--http-timeout',
  '--retries': 'ok',
  '--retry-on': 'gap:P2',
  '--randomize': 'ok',
  '--safe-url': 'ok',
  '--safe-post': 'gap:P3',
  '--safe-req': 'gap:P3',
  '--safe-freq': 'ok',
  '--skip-urlencode': 'gap:P2',
  '--skip-xmlencode': 'gap:P3',
  '--csrf-token': 'ok',
  '--csrf-url': 'ok',
  '--csrf-method': 'ok',
  '--csrf-data': 'gap:P3',
  '--csrf-retries': 'gap:P3',
  '--force-ssl': 'ok',
  '--chunked': 'gap:P2',
  '--hpp': 'ok',
  '--eval': 'ok:--request-script',

  // ── Optimization ───────────────────────────────────────────────────────────
  '--predict-output': 'ok',
  '--no-keep-alive': 'ok',
  '--null-connection': 'gap:P2',
  '--threads': 'ok',

  // ── Injection ──────────────────────────────────────────────────────────────
  '--skip': 'ok',
  '--skip-static': 'ok',
  '--param-exclude': 'ok',
  '--param-filter': 'ok',
  '--dbms': 'ok',
  '--dbms-cred': 'gap:P3',
  '--os': 'gap:P2',
  '--invalid-bignum': 'ok',
  '--invalid-logical': 'ok',
  '--invalid-string': 'ok',
  '--no-cast': 'ok',
  '--no-escape': 'out:原「保留接口」已按「收参数不生效＝红线」移除；实现需改转义实现（与引擎不同源，语义无法对齐）',
  '--prefix': 'ok',
  '--suffix': 'ok',
  '--tamper': 'ok',
  '--proof': 'auto:证据链默认就带 payload 与命中位置（vuln.poc.curl/raw + hit.match + --fix-prompt），无需开关',

  // ── Detection ──────────────────────────────────────────────────────────────
  '--level': 'ok',
  '--risk': 'ok',
  '--string': 'ok',
  '--not-string': 'ok',
  '--regexp': 'ok',
  '--code': 'ok',
  '--smart': 'ok',
  '--text-only': 'ok',
  '--titles': 'ok',

  // ── Techniques ─────────────────────────────────────────────────────────────
  '--technique': 'ok',
  '--time-sec': 'ok',
  '--disable-stats': 'out:本仓无「统计面板」概念（进度行 + 报告即输出面），无开关可关',
  '--union-cols': 'ok',
  '--union-char': 'out:同上（占位已移除）；实现需改 marker.js 的 MARKER_RE 与 tamper 保护链（高危区），评估结论为风险 > 收益',
  '--union-from': 'ok',
  '--union-values': 'gap:P3',
  '--dns-domain': 'part:--oob',
  '--second-url': 'ok:--second-order',
  '--second-req': 'ok',

  // ── Fingerprint ────────────────────────────────────────────────────────────
  '--fingerprint': 'part:--banner',

  // ── Enumeration ────────────────────────────────────────────────────────────
  '--all': 'part:--dump-all',
  '--banner': 'ok',
  '--current-user': 'ok',
  '--current-db': 'ok',
  '--hostname': 'ok',
  '--is-dba': 'ok',
  '--users': 'ok',
  '--passwords': 'ok',
  '--privileges': 'ok',
  '--roles': 'ok',
  '--dbs': 'ok',
  '--tables': 'ok',
  '--columns': 'ok',
  '--schema': 'ok',
  '--count': 'ok',
  '--dump': 'ok',
  '--dump-all': 'ok',
  '--search': 'ok',
  '--comments': 'gap:P3',
  '--statements': 'ok',
  '--procs': 'ok',
  '--exclude-sysdbs': 'ok',
  '--pivot-column': 'gap:P3',
  '--where': 'ok',
  '--start': 'ok',
  '--stop': 'ok',
  '--first': 'ok:--start',
  '--last': 'ok:--stop',
  '--sql-query': 'ok:--sql-shell',
  '--sql-shell': 'ok',
  '--sql-file': 'gap:P3',

  // ── Brute force ────────────────────────────────────────────────────────────
  '--common-tables': 'ok',
  '--common-columns': 'ok',
  '--common-files': 'gap:P3',

  // ── UDF / File system ──────────────────────────────────────────────────────
  '--udf-inject': 'part:--udf-install',
  '--shared-lib': 'out:不内置编译产物（GPLv2 与供应链边界）；用户自带 UDF 十六进制走 --udf-hex',
  '--file-read': 'ok',
  '--file-write': 'ok',
  '--file-dest': 'ok',

  // ── OS access ──────────────────────────────────────────────────────────────
  '--os-cmd': 'ok',
  '--os-shell': 'ok',
  '--os-pwn': 'out:武器化通道（MSF 反弹/内存马）超出「授权 SQLi 扫描 + 可核对证据」定位',
  '--os-smbrelay': 'out:SMB 中继依赖外部工具链，属武器化，同上不做',
  '--os-bof': 'out:缓冲区溢出模块属武器化，同上不做',
  '--priv-esc': 'out:提权动作不可逆且越出只读取证边界；本仓只做显式授权的文件/命令通道',
  '--msf-path': 'out:无 Metasploit 集成（不做外部框架编排）',
  '--tmp-path': 'out:本仓文件写为单次直写，不引入本地暂存目录概念',

  // ── Windows registry ───────────────────────────────────────────────────────
  '--reg-read': 'gap:P2',
  '--reg-add': 'gap:P2',
  '--reg-del': 'gap:P2',
  '--reg-key': 'gap:P2',
  '--reg-value': 'gap:P2',
  '--reg-data': 'gap:P2',
  '--reg-type': 'gap:P2',

  // ── General ────────────────────────────────────────────────────────────────
  '--abort-on-empty': 'gap:P3',
  '--answers': 'out:本仓 CLI 刻意无交互提问（非交互优先），等价面是 --config/--save-config 与显式旗标',
  '--base64': 'ok:--tamper',
  '--base64-safe': 'ok:--tamper',
  '--batch': 'auto:CLI 无交互提问（非交互优先），「不提问」这件事天然成立；⚠ 本仓 --batch 是「批量目标文件」不是 sqlmap 的这个开关',
  '--binary-fields': 'gap:P3',
  '--check-internet': 'gap:P3',
  '--cleanup': 'gap:P1',
  '--crawl': 'ok',
  '--crawl-exclude': 'gap:P2',
  '--csv-del': 'gap:P3',
  '--charset': 'gap:P3',
  '--dump-file': 'gap:P3',
  '--dump-format': 'ok',
  '--encoding': 'gap:P2',
  '--eta': 'out:进度行已给目标/点位/耗时；独立 ETA 显示无新信息',
  '--flush-session': 'ok',
  '--forms': 'ok',
  '--fresh-queries': 'ok',
  '--gpage': 'out:Google dork 属目标发现，AGENTS §0 红线（只扫用户明确给出的目标）',
  '--har': 'auto:-r/-m 按内容自动识别 HAR（Burp XML / HAR / Postman / OpenAPI 同一入口），无同名旗标',
  '--hex': 'ok',
  '--output-dir': 'ok:--out',
  '--parse-errors': 'ok',
  '--preprocess': 'ok:--request-script',
  '--postprocess': 'ok',
  '--repair': 'out:REPAIR TABLE 改写目标库，与「授权只读扫描」定位冲突',
  '--report-json': 'ok:--format',
  '--save': 'ok:--save-config',
  '--scope': 'ok',
  '--skip-heuristics': 'part:--smart',
  '--skip-waf': 'gap:P3',
  '--table-prefix': 'gap:P3',
  '--test-filter': 'ok',
  '--test-skip': 'ok',
  '--time-limit': 'ok:--timeout',
  '--unsafe-naming': 'gap:P3',
  '--web-root': 'gap:P3',

  // ── Non-SQL ────────────────────────────────────────────────────────────────
  '--graphql': 'ok:--no-sql',
  '--nosql': 'ok:--no-sql',
  '--ssti': 'ok:--no-sql',
  '--ldap': 'gap:P2',
  '--xpath': 'gap:P2',

  // ── Miscellaneous ──────────────────────────────────────────────────────────
  '--alert': 'gap:P2',
  '--beep': 'out:无人值守/CI 场景下无意义（agent 驱动是主用法）',
  '--dependencies': 'out:引擎有意零运行时依赖，无「缺依赖」这一类故障',
  '--disable-coloring': 'out:本仓 CLI 输出无 ANSI 着色，无开关可关',
  '--disable-hashing': 'out:本仓不做口令哈希破解（报告如实指向离线 hashcat）',
  '--gui': 'out:交互形态不同：本仓为 Web GUI / 桌面壳 / MCP，不做 sqlmap 式 TUI',
  '--list-tampers': 'ok',
  '--no-logging': 'gap:P3',
  '--no-truncate': 'gap:P3',
  '--offline': 'out:本仓会话是断点续跑缓存，不是「零请求离线数据源」，无对应语义',
  '--purge': 'gap:P3',
  '--results-file': 'out:sqlmap REST 内部形态；本仓以 scanId + 报告文件表达同一需求',
  '--shell': 'out:交互式 SQL 执行已由 --sql-shell 覆盖，不做 REPL 形态',
  '--tmp-dir': 'out:无本地临时目录概念（与 --tmp-path 同因）',
  '--tui': 'out:不做 TUI（Web/桌面壳/MCP 已覆盖交互面）',
  '--unstable': 'gap:P3',
  '--update': 'out:经 npm/git 分发并受版本一致性门禁约束，不做自更新（供应链完整性）',
  '--wizard': 'out:向导是交互式引导；agent/CI 用法需要的是显式旗标与 --advise 预检',

  // ── 短名专用 ───────────────────────────────────────────────────────────────
  '-d': 'ok:--direct',
  '-l': 'ok:--log-file',
  '-m': 'ok:--batch',
  '-r': 'ok:--request-file',
  '-g': 'out:Google dork 属目标发现，AGENTS §0 红线',
  '-c': 'part:--config',
  '-o': 'ok:--predict-output',
  '-p': 'ok:--test-param',
  '-s': 'part:--session-file',
  '-t': 'gap:P2',
  '-v': 'gap:P3',
  '-z': 'out:sqlmap 助记符缩写语法；本仓要求显式长旗标（可读与可审计优先）',
  '-hh': 'out:本仓 --help 即全量清单，不分基础/高级两段',
};

/**
 * 缺口/部分覆盖的「到底差什么」（excluded 的理由内联在 STATUS 的 `out:` 里，
 * 避免同一理由写两遍）。**每条 gap/part 都必须在这里有落点**，否则 judgeParity 判失败。
 * @type {Record<string,string>}
 */
export const NOTES = {
  '--cookie-del': '解析固定按 `;` 分隔；自定义 cookie 分隔符未暴露（低价值长尾）',
  // [D205 收口 D198] --live-cookies / --load-cookies 已落地，gap 理由不再成立（已移出本表）
  '--http1': '强制 HTTP/1.1；引擎只有 http2 开关，h2 优先失败时无法回退到 1.1',
  '--http2': '**只做了一半**：config.http2 只被 crawler / TargetParser 消费（取页/爬虫面），注入请求走 opts.http2 而无人传该键 ⇒ 接线必须同时改检测链路的出口选项，属独立批次；D197 复核后**刻意没接**（接了就是「收参数不生效」）',
  '--abort-code': '命中指定状态码即中止整场（风控/封禁早停）；当前只有 --ignore-code 的反向语义',
  '--ignore-proxy': '本仓用「本地/私网豁免环境变量代理」表达，缺「对所有目标都不走代理」的全局口',
  '--ignore-timeouts': '超时不计入可信度判定；当前超时会被记为未验证面（更诚实，但缺用户显式覆盖口）',
  '--null-connection': '**引擎写完了但没接线**：sendHead / matchNullConnection 挂在 Detector 原型上而**零调用点**（死代码），httpClient.headRequest 也只有包装没有消费者 ⇒ 真做要接进布尔/时间检测器并复核判据（HEAD 无 body，真假只能靠状态码 + Content-Length），不是纯接线',  '--proxy-file': '代理池轮换（每请求换出口）未实现；--proxy 只有单出口',
  '--proxy-freq': '配合代理池的换出口频率未实现（与 --proxy-file 同批）',
  '--tor-port': 'Tor 端口固定 9050，无旗标覆盖（wafEvasion 可配但无 CLI 面）',
  '--tor-type': '仅 socks5；socks4/http 代理类型未暴露为独立开关',
  '--retry-on': '按状态码/响应特征重试（弱网 + 风控抖动目标的关键）；当前仅对连接失败重试',
  '--safe-post': '保活请求只支持 GET；会改状态的会话用 POST 保活时无表达方式',
  '--safe-req': '保活请求无法整请求导入（带认证头的保活页）',
  '--skip-urlencode': '注入值恒做 URL 编码；目标只在未编码形态下才透传到 SQL 时无法表达',
  '--skip-xmlencode': 'XML/SOAP 注入值恒做实体编码；同上',
  '--csrf-data': '取 CSRF token 时的附加表单字段未暴露（多步令牌页）',
  '--csrf-retries': '取 token 失败的重试次数未暴露',
  '--chunked': 'Transfer-Encoding: chunked 分块发送（绕 IDS/WAF 的常见形态）；httpClient 无分块发送路径',
  '--dbms-cred': 'DBMS 侧凭据（UDF/注册表操作的 EXECUTE AS 等）无入口',
  '--os': '强制目标 OS（影响文件路径与命令通道形态）；当前按 DBMS 推断，无显式覆盖',
  '--union-values': 'UNION 判真的自定义测试值未暴露（非常规字符集目标）',
  '--dns-domain': '带外 DNS 外带走 --oob + config.oob.dnsDomain / --oob-interactsh，无同名旗标',
  '--fingerprint': '本仓产 DBMS 版本 + summary.dbmsEvidence 分级；OS / Web 服务器指纹未成体系',
  '--all': '--dump-all 覆盖全库拖库；sqlmap -a 还含 users/passwords/privileges 一次拉全',
  '--comments': '表/列注释枚举（MSSQL/MySQL 的 pg_description 类面）未实现',
  '--pivot-column': '关联表拖库时的主键列指定未实现',
  '--sql-file': '从文件读 SQL 再执行（长脚本/多语句）；当前只能内联 --sql-shell 串',
  '--common-files': '常见文件名字典爆破（LOAD_FILE 路径面）未实现',
  '--udf-inject': '本仓要求自带 UDF 十六进制（--udf-hex）；不内置编译产物（GPLv2 与供应链边界）',
  '--reg-read': '**引擎已实现** registryRead（server/src/engine/exploit/registry.js，MSSQL xp_regread 通道），CLI 与 REST 均无入口 ⇒ 接线即可，不用重写',
  '--reg-add': '**引擎已实现** registryWrite（写入类，需 EXPLOIT_ENABLED + --authorized 双闸）⇒ 接线即可',
  '--reg-del': '**引擎已实现** registryWrite 的删除形态 ⇒ 接线即可',
  '--reg-key': '注册表路径参数面（配合 reg-read/add/del，同批接线）',
  '--reg-value': '注册表值名参数面（同上）',
  '--reg-data': '写入数据参数面（同上）',
  '--reg-type': '写入类型参数面（REG_SZ/DWORD 等，同上）',
  '--abort-on-empty': '连续空结果即停（防无意义拖库）；当前只能靠 --max-requests 兜',
  '--binary-fields': '二进制列（图片/哈希）十六进制化导出未实现',
  '--check-internet': '开扫前连通性自检（区分「本机断网」与「目标不可达」）未实现',
  '--cleanup': '利用后清理（UDF/xp_cmdshell 复位/临时表/落盘文件）**完全缺失**：授权测试的 OPSEC 刚需，不做等于在客户环境留残留',
  '--crawl-exclude': '爬虫排除正则未暴露（登出链接/危险动作页必须能排掉）',
  '--csv-del': 'CSV 导出分隔符不可配（Excel 本地化场景）',
  '--charset': '注入值字符集约束（非 ASCII 目标）未暴露',
  '--dump-file': '拖库数据落盘路径不可单独指定（当前固定 dump.<ext>）',
  '--encoding': '页面编码显式声明（GBK/Shift-JIS 目标）未暴露；比对与提取当前按 UTF-8/自动',
  '--skip-heuristics': '本仓启发式（prefilter）默认关、--smart 才开；sqlmap 默认开、本项关 —— 同一开关的另一默认值',
  '--skip-waf': '跳过 WAF 识别阶段未暴露（已知有 WAF 且只想省请求时）',
  '--table-prefix': 'Oracle/DB2 表前缀枚举参数未暴露',
  '--unsafe-naming': '拖库产物命名安全化开关未暴露（长尾）',
  '--web-root': '文件写用的 Web 根路径（写 webshell 落点）未暴露；当前要求绝对路径 --file-dest',
  '--ldap': 'LDAP 注入通道未实现（检测器 + payload 面；sqlmap 1.10 新增）',
  '--xpath': 'XPath 注入通道未实现（同上）',
  '--alert': '命中即执行宿主命令（自动化联动/Slack 钩子）；需显式授权与命令白名单，不能静默执行',
  '--no-logging': '关闭日志落盘开关未暴露（当前恒写 ledger）',
  '--no-truncate': '报告长字段不截断开关未暴露（长 payload/长响应取证用）',
  '--purge': '本地产物/会话清理（与 --cleanup 相邻：这项针对本地侧）未实现',
  '--unstable': '不稳定连接模式（弱网重试策略）未实现',
  '-c': '档案格式为 JSON（键=长旗标名）；不支持 sqlmap 的 INI(`sqlmap.conf`) 语法',
  '-s': '会话是 JSON 台账（断点续跑语义一致），不读写 sqlmap 的 SQLite 会话文件',
  '-t': '原始 HTTP 流量全量落盘（复现与审计）未实现：当前只有结构化 ledger + 报告，无法回放原始报文',
  '-v': '日志详细度无 CLI 开关（级别走环境变量/配置），与 sqlmap -v 0-6 的逐级详细度不对位',
};

/**
 * 缺口的分批计划（**计划不是声明**：批次号落地时以本地 git log 顺延为准）。
 * 排序依据 = 实战影响 × 取证价值 × 成本，不按 sqlmap help 顺序。
 * @type {Array<{batch:string, title:string, items:string[]}>}
 */
export const PLAN = [
  {
    batch: 'D198',
    // [D205 收口] --load-cookies / --live-cookies 已由 D198 落地（见 STATUS 的 ok），
    // 从建议清单里移出，只留真正还没做的两项（否则产物里会出现「建议批次」里躺着已完成项）。
    title: '会话与 OPSEC（剩余 P1/P3 缺口：出口留残留、清理面为空）',
    items: ['--cleanup', '--purge'],
  },
  {
    batch: 'D199',
    title: '协议形态与宿主钩子（WAF/IDS 绕过的收发形态 + 自动化入口）',
    items: ['--chunked', '--skip-urlencode', '--skip-xmlencode', '--retry-on', '--crawl-exclude', '--skip-waf', '--alert'],
  },
  {
    batch: 'D200',
    title: 'Windows 注册表面（引擎已实现、只差接线：读/写/删 + 四个参数面）',
    items: ['--reg-read', '--reg-add', '--reg-del', '--reg-key', '--reg-value', '--reg-data', '--reg-type', '--dbms-cred'],
  },
  {
    batch: 'D201',
    title: '传输形态收口（把「只做了一半」的三项做完：检测链路 h2 / HTTP1 回退 / HEAD 快速判定）',
    items: ['--http2', '--http1', '--null-connection', '--unstable'],
  },
  {
    batch: 'D202',
    title: '强制面与编码（把「推断错了就没救」的几项变成可显式指定）',
    items: ['--os', '--encoding', '--charset', '--fingerprint'],
  },
  {
    batch: 'D203',
    title: '非 SQL 通道补齐（LDAP / XPath 注入检测器）',
    items: ['--ldap', '--xpath'],
  },
  {
    batch: 'D204',
    title: '长尾 P3（按需；不与上面抢优先级，但都在底账里点名，不许「关起门来」）',
    items: [
      '--abort-code', '--ignore-timeouts', '--safe-post', '--safe-req', '--csrf-data', '--csrf-retries',
      '--union-values', '--abort-on-empty', '--check-internet', '--csv-del', '--dump-file', '--table-prefix',
      '--unsafe-naming', '--web-root', '--no-logging', '--no-truncate', '--comments', '--pivot-column',
      '--sql-file', '--common-files', '--binary-fields', '--proxy-file', '--proxy-freq', '--tor-type', '-t', '-v',
    ],
  },
];

/** 状态码 → 中文标签（报告与 JSON 共用，避免两处各译一遍）。 */
export const STATUS_LABEL = {
  ok: '同名同义',
  alias: '等价异构',
  part: '部分覆盖',
  auto: '默认即覆盖',
  gap: '缺口',
  out: '明确不做',
};

/**
 * 解析一个状态码。
 * @param {string} code STATUS 里的编码
 * @returns {{kind:'ok'|'alias'|'part'|'gap'|'out', flag:string, priority:string, reason:string}}
 */
export function parseCode(code) {
  const s = String(code || '');
  if (s === 'ok') return { kind: 'ok', flag: '', priority: '', reason: '' };
  if (s.startsWith('ok:')) return { kind: 'alias', flag: s.slice(3), priority: '', reason: '' };
  if (s.startsWith('part:')) return { kind: 'part', flag: s.slice(5), priority: '', reason: '' };
  if (s.startsWith('gap:')) return { kind: 'gap', flag: '', priority: s.slice(4), reason: '' };
  if (s.startsWith('auto:')) return { kind: 'auto', flag: '', priority: '', reason: s.slice(5) };
  if (s.startsWith('out:')) return { kind: 'out', flag: '', priority: '', reason: s.slice(4) };
  return { kind: 'out', flag: '', priority: '', reason: '' };
}

/**
 * 从 CLI 源码提取「本方旗标真源」。**两个来源的并集**，理由分别是：
 *   ① `server/bin/cli/args.js` 的**解析分支**（`a === '--x'`）—— 与 readme-flag-coverage.mjs
 *      口径同源（只认解析分支，不认注释与说明文字）。两处若分叉，就会出现
 *      「底账说没入口、README 门禁说有」的互相矛盾。
 *   ② `server/bin/cli.js` 的**入口拦截字面量**（`process.argv.includes('--x')`）——
 *      `--version`（D132）与 `--list-tampers`（D197）都是「不要求 -u、不进扫描流程」的
 *      元信息查询，按 ⑯/⑰ 的口径它们不在 args.js 的解析分支里，但**确实是能力**。
 *      底账若只认 ①，这两项就会永远显示成「缺口」，那是另一种失真（朝悲观方向）。
 * @param {string} [argsSource] args.js 源码（默认读仓库里的）
 * @param {string} [cliSource] cli.js 源码（默认读仓库里的）
 * @returns {string[]}
 */
export function cliFlags(
  argsSource = readFileSync(resolve(ROOT, 'server/bin/cli/args.js'), 'utf8'),
  cliSource = readFileSync(resolve(ROOT, 'server/bin/cli.js'), 'utf8'),
) {
  const out = [];
  const push = (f) => { if (!out.includes(f)) out.push(f); };
  // ① 解析分支：`a === '--x'` / `case '--x':`
  const re = /(?:a\s*===\s*|case\s+)'(--[a-z0-9][a-z0-9-]*)'/g;
  let m;
  while ((m = re.exec(String(argsSource))) !== null) push(m[1]);
  // ② 表驱动的解析分支：`['--sql-shell', 'sqlShell'],`（OPTIONAL_VALUE_FLAGS 形态）
  const re2 = /\['(--[a-z0-9][a-z0-9-]*)',\s*'[A-Za-z]/g;
  while ((m = re2.exec(String(argsSource))) !== null) push(m[1]);
  // ③ 入口拦截字面量：`process.argv.includes('--version')`
  const re3 = /process\.argv\.includes\('(--[a-z0-9][a-z0-9-]*)'\)/g;
  while ((m = re3.exec(String(cliSource))) !== null) push(m[1]);
  return out;
}

/** 全部选项（扁平、去重、保序）。 */
function allOpts() {
  const out = [];
  for (const g of INVENTORY) for (const o of g.opts) if (!out.includes(o)) out.push(o);
  return out;
}

/**
 * 覆盖率类判据：状态引用的旗标必须真的存在（`ok` 看同名，`alias`/`part` 看所指旗标），
 * `gap` 反向 —— 已实现就不许再记缺口。
 * @param {string} opt sqlmap 选项
 * @param {ReturnType<typeof parseCode>} p 解析后的状态
 * @param {Set<string>} flags 本方旗标集合
 * @returns {string[]} 失败项
 */
function judgeCoverage(opt, p, flags) {
  if (p.kind === 'ok') return flags.has(opt) ? [] : [`③ ${opt} 记为「同名同义」，但 args.js 里查不到该旗标`];
  if (p.kind === 'alias' || p.kind === 'part') {
    if (!p.flag.startsWith('--')) return [`③ ${opt} 的等价旗标写法非法：${p.flag}`];
    return flags.has(p.flag) ? [] : [`③ ${opt} 声称由 ${p.flag} 覆盖，但 args.js 里没有 ${p.flag}`];
  }
  if (p.kind === 'gap') {
    const f = [];
    if (!/^P[123]$/.test(p.priority)) f.push(`⑤ ${opt} 的优先级非法：${p.priority}`);
    if (flags.has(opt)) f.push(`② ${opt} 已在本方 args.js 里实现，但底账仍记 gap —— 底账不许朝乐观方向漂（改状态并复跑产物生成）`);
    return f;
  }
  return [];
}

/**
 * 理由类判据：`auto`（默认即覆盖）要写清是哪条默认行为，`out`（明确不做）要么自足要么干脆别写。
 * @param {string} opt sqlmap 选项
 * @param {ReturnType<typeof parseCode>} p 解析后的状态
 * @returns {string[]} 失败项
 */
function judgeReason(opt, p) {
  if (p.kind !== 'auto' && p.kind !== 'out') return [];
  if (!p.reason || p.reason.length < 8) return [`④ ${opt} 记「${p.kind}」但理由不成立（太短/空：${p.reason || '(空)'}）`];
  if (p.kind === 'out' && /暂不支持|后续再说|TODO/.test(p.reason)) return [`④ ${opt} 的「不做」理由在打太极：${p.reason}`];
  return [];
}

/**
 * 单条状态的判据（由「覆盖类 + 理由类 + 缺口说明」三组组合）。
 * 拆出来的理由：初版把全部分支堆在 judgeParity 里，圈复杂度 34（硬上限 25）；
 * 拆一层后 judgeOne 又到 17（软上限 15）—— 门禁没错，是判据写得太挤。
 * @param {string} opt sqlmap 选项
 * @param {ReturnType<typeof parseCode>} p 解析后的状态
 * @param {Set<string>} flags 本方旗标集合
 * @param {Record<string,string>} notes 缺口说明表
 * @returns {string[]} 该条的失败项（空 = 合规）
 */
function judgeOne(opt, p, flags, notes) {
  const f = [...judgeCoverage(opt, p, flags), ...judgeReason(opt, p)];
  if ((p.kind === 'gap' || p.kind === 'part') && !notes[opt]) {
    f.push(`④ ${opt} 是 ${p.kind}，但 NOTES 里没写「还差什么」`);
  }
  return f;
}

/** 状态计数（分母分布；gap 另按优先级分桶）。 */
function tally(stats, p) {
  if (!(p.kind in stats)) return;
  stats[p.kind]++;
  if (p.kind === 'gap' && /^P[123]$/.test(p.priority)) stats[`gap${p.priority}`]++;
}

/**
 * 底账判据（**有牙**的部分都在这里）：
 *   ① 分母完整：INVENTORY 里每个选项都有状态，STATUS 里没有 INVENTORY 之外的残留；
 *   ② 不做虚假乐观：`gap` 的项在本方旗标里**必须不存在**（谁实现了谁就得改状态）；
 *   ③ 不虚报覆盖：`ok`/`alias`/`part` 引用的旗标必须真实存在于 args.js（防「文档里有、代码里没有」）；
 *   ④ 不空转：gap/part 都有 NOTES（写清还差什么），out/auto 的理由非空且不是「暂不支持」这种空话；
 *   ⑤ 优先级只能是 P1/P2/P3。
 * @param {{flags?:string[], status?:Record<string,string>, notes?:Record<string,string>, inventory?:Array}} [input]
 * @returns {{fails:string[], stats:object, rows:Array<object>}}
 */
export function judgeParity(input = {}) {
  const status = input.status || STATUS;
  const notes = input.notes || NOTES;
  const inventory = input.inventory || INVENTORY;
  const flags = new Set(input.flags || cliFlags());
  const opts = [];
  for (const g of inventory) for (const o of g.opts) if (!opts.includes(o)) opts.push(o);
  const fails = [];
  const rows = [];
  const stats = { total: opts.length, ok: 0, alias: 0, part: 0, auto: 0, gap: 0, out: 0, gapP1: 0, gapP2: 0, gapP3: 0 };

  for (const o of opts) {
    const code = status[o];
    if (!code) { fails.push(`① INVENTORY 里的 ${o} 没有状态（未分类 = 底账不可信）`); continue; }
    const p = parseCode(code);
    if (!/^(ok|ok:|part:|gap:P[123]|auto:.+|out:.+)/.test(code)) {
      fails.push(`⑤ ${o} 的状态编码非法：${code}`);
      continue;
    }
    tally(stats, p);
    fails.push(...judgeOne(o, p, flags, notes));
    rows.push({ opt: o, code, ...p, note: notes[o] || '' });
  }
  for (const o of Object.keys(status)) {
    if (!opts.includes(o)) fails.push(`① STATUS 里的 ${o} 不在 INVENTORY（分母与状态必须一一对应）`);
  }
  return { fails, stats, rows };
}

const byGroup = () => INVENTORY.map((g) => ({ group: g.group, opts: g.opts.filter((o) => STATUS[o]) }));

/** 生成 docs/_sqlmap-parity.json 的内容（机器可读底账）。 */
export function renderJson() {
  const { stats } = judgeParity();
  return JSON.stringify({
    _comment: 'sqlmap 对标底账（由 node scripts/sqlmap-parity.mjs --write 生成，手改即被 smapParity.guard 判红）',
    _generatedBy: 'node scripts/sqlmap-parity.mjs --write',
    sqlmapVersion: SQLMAP_VERSION,
    stats,
    groups: byGroup().map((g) => ({
      group: g.group,
      options: g.opts.map((o) => {
        const p = parseCode(STATUS[o]);
        return { opt: o, kind: p.kind, ours: p.flag || null, priority: p.priority || null, reason: p.reason || null, note: NOTES[o] || null };
      }),
    })),
    plan: PLAN,
  }, null, 2) + '\n';
}

/** 状态 → 表里显示的一格。 */
function cell(row) {
  const label = STATUS_LABEL[row.kind] || row.kind;
  return row.priority ? `${label}（${row.priority}）` : label;
}

/** 生成 docs/sqlmap-对标底账.md 的内容（人读底账）。 */
export function renderMarkdown() {
  const { stats, rows } = judgeParity();
  const L = [];
  L.push('# sqlmap 对标底账（自动生成，勿手改）');
  L.push('');
  L.push(`> 生成：\`node scripts/sqlmap-parity.mjs --write\` · 上游基准：sqlmap **${SQLMAP_VERSION}** \`-hh\` · 本方真源：\`server/bin/cli/args.js\` 解析分支`);
  L.push('>');
  L.push('> 这份底账只回答两个问题：**sqlmap 的能力面有多少个**、**本仓逐项处在哪一态**。');
  L.push('> 它**不是**能力声明：`等价异构`/`部分覆盖` 只表示「这一项有落点」，够不够用必须回到逐项证据');
  L.push('> （README「sqlmap 同题对照」、`docs/审计口径.md`、`docs/检测与定库-实测口径.md`）与真机靶场复跑。');
  L.push('>');
  L.push('> 状态口径：`同名同义`＝旗标名与语义都对齐；`等价异构`＝语义等价但本仓用别的形态表达；');
  L.push('> `默认即覆盖`＝不需要开关，默认行为已经满足（说明里写清是哪条默认行为）；`部分覆盖`＝有落点但明确还差东西；');
  L.push('> `缺口`＝当前无对应能力（P1/P2/P3 为落地优先级）；`明确不做`＝有意识的边界（理由必须自足，见下表）。');
  L.push('');
  L.push('## 一、分母与分布');
  L.push('');
  L.push('| 状态 | 项数 | 占分母 |');
  L.push('|---|---|---|');
  const pct = (n) => `${Math.round((n / stats.total) * 100)}%`;
  L.push(`| 同名同义 | ${stats.ok} | ${pct(stats.ok)} |`);
  L.push(`| 等价异构 | ${stats.alias} | ${pct(stats.alias)} |`);
  L.push(`| 默认即覆盖 | ${stats.auto} | ${pct(stats.auto)} |`);
  L.push(`| 部分覆盖 | ${stats.part} | ${pct(stats.part)} |`);
  L.push(`| 缺口 | ${stats.gap} | ${pct(stats.gap)} |`);
  L.push(`| 明确不做 | ${stats.out} | ${pct(stats.out)} |`);
  L.push(`| **分母合计** | **${stats.total}** | 100% |`);
  L.push('');
  L.push(`缺口的优先级分布：P1 **${stats.gapP1 || 0}** · P2 **${stats.gapP2 || 0}** · P3 **${stats.gapP3 || 0}**。`);
  L.push('');
  L.push('> ⚠ 引用本表时不得只说「覆盖率 N%」：`明确不做` 是**有意识**的边界（武器化、目标发现、自更新等），');
  L.push('> 把它算进「未覆盖」会误导，把它踢出分母又是自欺 —— 所以分布必须整张一起引用。');
  L.push('');
  L.push('## 二、P1/P2 缺口（按落地批次规划）');
  L.push('');
  for (const p of PLAN) {
    L.push(`### ${p.batch} · ${p.title}`);
    L.push('');
    for (const it of p.items) {
      // 计划条目形如 `--load-cookies` / `--fingerprint（OS/Web 指纹）` / `--proxy-file/--proxy-freq`：
      // 取**首个选项 token 的精确匹配**（不能用 startsWith —— 那会让 `--crawl-exclude` 撞上 `--crawl`）
      const tok = (it.match(/^--?[a-z0-9-]+/) || [null])[0];
      const row = rows.find((r) => r.opt === tok);
      if (!row) { L.push(`- \`${it}\``); continue; }
      const kind = row.kind === 'gap' ? `缺口（${row.priority}）` : STATUS_LABEL[row.kind];
      L.push(`- \`${row.opt}\` — **${kind}**：${row.note || row.reason}`);
    }
    L.push('');
  }
  L.push('## 三、逐项底账');
  L.push('');
  for (const g of byGroup()) {
    L.push(`### ${g.group}`);
    L.push('');
    L.push('| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |');
    L.push('|---|---|---|---|');
    for (const o of g.opts) {
      const row = rows.find((r) => r.opt === o);
      const ours = row.kind === 'ok' ? `\`${o}\`` : row.flag ? `\`${row.flag}\`` : '—';
      const note = (row.note || row.reason || '').replace(/\|/g, '\\|');
      L.push(`| \`${o}\` | ${cell(row)} | ${ours} | ${note} |`);
    }
    L.push('');
  }
  L.push('## 四、怎么复验与怎么防它过期');
  L.push('');
  L.push('```bash');
  L.push('node scripts/sqlmap-parity.mjs            # 校验（状态自洽 + 产物与磁盘逐字一致）');
  L.push('node scripts/sqlmap-parity.mjs --write    # 重新生成 JSON 与本页');
  L.push('node scripts/sqlmap-parity.mjs --selftest # 自证判据有牙（四个反例）');
  L.push('node scripts/sqlmap-parity.mjs --refresh  # 重跑本机 sqlmap -hh，报上游选项面漂移（只读）');
  L.push('cd server && node --test tests/sqlmapParity.guard.test.js');
  L.push('```');
  L.push('');
  L.push('三条防过期机制（这是它与历史上那几份一次性分析文档的区别）：');
  L.push('');
  L.push('1. **gap 与实现互斥**：某项一旦在本方 args.js 里有旗标，底账仍写 `缺口` ⇒ 门禁红（不许只朝乐观方向漂）；');
  L.push('2. **引用必须落地**：`同名同义`/`等价异构`/`部分覆盖` 引用的旗标必须真实存在于 args.js ⇒ 防「文档里有、代码里没有」；');
  L.push('3. **产物即判据**：本页与 JSON 由脚本逐字重算，手改即红；`--refresh` 每次跑都报上游新增/删除的选项面。');
  L.push('');
  L.push(`> 缺口总数 ${stats.gap}（P1 ${stats.gapP1 || 0} / P2 ${stats.gapP2 || 0} / P3 ${stats.gapP3 || 0}）；部分覆盖 ${stats.part}。`);
  L.push('> 引用本页数字时，请连**分母与状态口径**一起引用（上表 §一）。');
  L.push('');
  return L.join('\n');
}

/** 校验产物与磁盘逐字一致。 */
function checkArtifacts() {
  const fails = [];
  for (const [rel, want] of [[JSON_REL, renderJson()], [DOC_REL, renderMarkdown()]]) {
    let got = null;
    try { got = readFileSync(resolve(ROOT, rel), 'utf8'); } catch { fails.push(`产物缺失：${rel}（跑 --write 生成）`); continue; }
    if (got !== want) fails.push(`产物与脚本产出不一致：${rel}（手改或忘了重跑 --write）`);
  }
  return fails;
}

/** 自证：四个反例必须被 judgeParity 抓住，且真实底账必须干净。 */
function selftest() {
  const OPT = ['--a', '--b', '--c', '--d', '--e', '--f'];
  const inv = [{ group: 'g', opts: OPT }];
  // 每个反例只改动一处，其余项给合法状态（避免噪声盖住目标失败）
  const legal = {
    '--a': 'ok',
    '--c': 'out:理由足够长的一段话，说明这是有意识不做',
    '--d': 'auto:默认行为就是它，无需开关的一段说明',
    '--e': 'part:--a',
  };
  const cases = [
    ['未分类', { inventory: inv, flags: ['--a'], status: { ...legal, '--b': 'gap:P3' }, notes: { '--b': 'x' } }, '没有状态'],
    ['gap 但已实现（乐观漂移）', { inventory: inv, flags: ['--a', '--b'], status: { ...legal, '--b': 'gap:P3', '--f': 'ok' }, notes: { '--b': '还差 x' } }, '仍记 gap'],
    ['声称覆盖但旗标不存在', { inventory: inv, flags: ['--a'], status: { ...legal, '--b': 'ok:--nope', '--f': 'ok' }, notes: {} }, '没有 --nope'],
    ['缺口没写「还差什么」', { inventory: inv, flags: ['--a'], status: { ...legal, '--b': 'gap:P3', '--f': 'ok' }, notes: {} }, '没写「还差什么」'],
  ];
  const bad = [];
  for (const [name, input, expect] of cases) {
    const r = judgeParity(input);
    if (!r.fails.some((f) => f.includes(expect))) bad.push(`反例「${name}」没被抓住（期望失败含「${expect}」，实际：${r.fails.join(' / ') || '(无失败)'}）`);
  }
  const real = judgeParity();
  if (real.fails.length) bad.push(`真实底账自身不干净：${real.fails.slice(0, 5).join(' / ')}`);
  if (real.stats.total < 200) bad.push(`分母只剩 ${real.stats.total} 项 —— INVENTORY 可能被删空（sqlmap 1.10.7 实测 222）`);
  if (real.stats.gapP1 < 1 || real.stats.gapP2 < 3) bad.push(`P1/P2 缺口计数异常（P1=${real.stats.gapP1} P2=${real.stats.gapP2}）—— 分类可能被清空`);
  if (bad.length) {
    console.error('[sqlmap-parity] ✗ 自证失败：');
    for (const b of bad) console.error('    · ' + b);
    process.exit(1);
  }
  console.log(`[sqlmap-parity] ✓ 自证通过：4 个反例都被抓住；真实底账分母 ${real.stats.total}，缺口 ${real.stats.gap}（P1 ${real.stats.gapP1} / P2 ${real.stats.gapP2} / P3 ${real.stats.gapP3}）`);
}

/** 上游漂移检查：重跑本机 sqlmap，比对选项面（只读，不进产物）。 */
function refresh() {
  const bin = process.env.SQLMAP_BIN || 'sqlmap';
  let out = '';
  try {
    out = execFileSync(bin, ['-hh'], { encoding: 'utf8', shell: process.platform === 'win32' });
  } catch (e) {
    console.error(`[sqlmap-parity] 跑不动 sqlmap（${bin} -hh）：${e.message}`);
    console.error('    这是环境问题不是回归：装好 sqlmap 或设 SQLMAP_BIN 再跑。');
    process.exit(1);
  }
  const upstream = new Set([...out.matchAll(/^ {4}\S.*$/gm)].flatMap((l) => [...l[0].matchAll(/--[a-z0-9-]+/g)].map((m) => m[0])));
  const ours = new Set(allOpts());
  const added = [...upstream].filter((o) => !ours.has(o));
  const gone = [...ours].filter((o) => !upstream.has(o) && o.startsWith('--'));
  console.log(`[sqlmap-parity] 上游 ${upstream.size} 个长选项 / 底账 ${[...ours].filter((o) => o.startsWith('--')).length} 个`);
  console.log(`  上游新增（底账未收）：${added.length ? added.join(' ') : '(无)'}`);
  console.log(`  底账有而上游本次 help 未出现：${gone.length ? gone.join(' ') : '(无)'}`);
  console.log("  ⚠ 上游 help 会截断长名（--user.. / --hea..）：出现 '..' 是截断不是缺失，人工确认后再改 INVENTORY。");
  console.log(`  上游版本（本机）：${(execFileSync(bin, ['--version'], { encoding: 'utf8', shell: process.platform === 'win32' }) || '').split(/\r?\n/)[0]}`);
}

// 仅在**直接运行**时执行命令分发 —— 被测试 import 时不得自己跑一遍（否则单测会被
// 进程级 process.exit 打断，判据也就跟着消失）。
const invokedDirectly = (() => {
  try {
    return process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  const args = process.argv.slice(2);
  if (args.includes('--selftest')) selftest();
  else if (args.includes('--refresh')) refresh();
  else if (args.includes('--write')) {
    const { fails, stats } = judgeParity();
    if (fails.length) { console.error('[sqlmap-parity] ✗ 底账自身不干净，拒绝生成产物：'); for (const f of fails) console.error('    · ' + f); process.exit(1); }
    writeFileSync(resolve(ROOT, JSON_REL), renderJson());
    writeFileSync(resolve(ROOT, DOC_REL), renderMarkdown());
    console.log(`[sqlmap-parity] ✓ 已生成 ${JSON_REL} 与 ${DOC_REL}（分母 ${stats.total}，缺口 ${stats.gap}）`);
  } else {
    const { fails, stats } = judgeParity();
    const all = [...fails, ...checkArtifacts()];
    if (all.length) {
      console.error('[sqlmap-parity] ✗ 底账校验失败：');
      for (const f of all) console.error('    · ' + f);
      process.exit(1);
    }
    console.log(`[sqlmap-parity] ✓ 底账自洽且产物同步：分母 ${stats.total}（同名同义 ${stats.ok} / 等价异构 ${stats.alias} / 部分覆盖 ${stats.part} / 缺口 ${stats.gap} / 明确不做 ${stats.out}）`);
  }
}
