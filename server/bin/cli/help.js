// ============================================================================
// help.js —— CLI 帮助文本（纯静态，零依赖）
//
// 从 bin/cli.js 抽离，[拆上帝对象 2026-09-14]。这是单函数最长的一块，但内容是纯文本；
// 抽出来是为了让 cli.js 的「流程」与「文案」分开，改帮助不影响主流程的阅读。
// 注：bin/ 不在 arch-guard 的 console 检查范围内 —— CLI 用 stdout 输出是本职。
// ============================================================================

export function printHelp() {
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
                             ⚠️ 已知问题（2026-09-15，未修）：目标存在返回 500/403 的路由时，
                             注入后 URL 变为不存在的路径 → 404 页回显 URL → payload 自带关键词
                             被误读为数据库报错 → 该路由会被误报为 error 注入。
                             实测 7 个安全点中 6 个因此误报（sqlmap 同题 0 误报）。
                             生产使用建议暂不开启；详见 README「已知问题」与 e2e/blackbox-lab/
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
   --csrf-url <url>         CSRF 取页 URL：扫描前 GET 提取 token，每请求自动携带（对标 sqlmap --csrf-url）
   --csrf-token <name>      anti-CSRF 字段名（缺省自动探测常见名：csrf_token/_csrf/token 等）
   --csrf-method <m>        取页方法（默认 GET）
   --csrf-refresh <n>       每 n 个请求刷新一次 token（默认 50）
   --skip <params>          排除指定参数不测（逗号分隔参数名，对标 sqlmap --skip）
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
  --advise                   扫描前风险评估：**不发起任何请求**，只按目标 URL 与参数给出
                             风险等级（低/中/高/极高）、问题清单与保守参数建议。
                             规则为确定性实现（不调用 LLM），只给建议、不改你的参数；
                             评估后默认退出，加 --yes 才继续扫描。
  --yes                      配合 --advise：表示「我已看过建议」，允许继续扫描
  --confirm-extreme          配合 --advise：风险等级为「极高」时的第二道确认。
                             --yes 只代表看过建议，本开关才代表接受可能的不可逆后果 ——
                             把两个动作分开，避免一次回车扫平生产库。
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
