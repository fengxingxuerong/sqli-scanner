// ============================================================================
// help.js —— CLI 帮助文本（纯静态，零依赖）
//
// 从 bin/cli.js 抽离，[拆上帝对象 2026-09-14]。这是单函数最长的一块，但内容是纯文本；
// 抽出来是为了让 cli.js 的「流程」与「文案」分开，改帮助不影响主流程的阅读。
// 注：bin/ 不在 arch-guard 的 console 检查范围内 —— CLI 用 stdout 输出是本职。
// ============================================================================

// [D68 2026-10-14] 帮助文本提为可查询数据：readme-consistency 门禁要比对
// 「README 是否收录了全部 CLI 旗标」，靠 import 本常量（零子进程、零 console 捕获）。
export const HELP_TEXT = `sqli-scanner CLI（对标 sqlmap 的 Node 引擎命令行入口）

用法:
  单目标  node bin/cli.js -u <url> [选项]
  请求文件 node bin/cli.js -r request.txt [选项]
  批量    node bin/cli.js -m <urls.txt> [选项]

子命令:
  mcp                        MCP server 模式（[D43] 对标 dalfox mcp / semgrep mcp）：stdio NDJSON，
                             供 AI 代理宿主（Cursor / Claude Code / VS Code 等）直连。工具集：
                             run_scan / get_scan_status / get_findings / get_report / list_scans /
                             stop_scan / pause_scan / resume_scan / preflight（零 payload 侦察）。
                             与 REST 同一配置白名单与 SSRF/scope 护栏——MCP 不是旁路。
                             宿主配置示例（claude_desktop_config.json / .mcp.json）：
                             {"command":"node","args":["<repo>/server/bin/cli.js","mcp"]}

选项:
  -r, --request-file <file>  导入请求（对标 sqlmap -r）。支持的来源：
                             · Burp/curl 文本报文   · Burp XML 导出   · HAR（浏览器 F12 / Charles）
                             · Postman 集合(v2.x)   · OpenAPI/Swagger（JSON 与 YAML 均可）
                             提取 URL/method/headers/body，覆盖 -u/--method/--body/--cookie/--header
                             集合文件含多个请求时只取第 1 个（会打印共几个，不静默）
  -l, --log-file <file>      从代理/Burp 日志文件批量扫描（对标 sqlmap -l）：
                             支持 Burp XML 导出与纯文本多请求日志，逐请求复用 -r 的字段映射
  -u, --url <url>            目标 URL
  -m, --batch <file>         批量扫描文件。两种来源，自动识别（会打印识别结果，不静默）：
                             · URL 列表：每行一个 http(s) 地址
                             · 请求集合：Burp XML 导出 · HAR · Postman 集合(v2.x) ·
                               OpenAPI/Swagger（JSON / YAML；YAML 走零依赖子集解析器，
                               遇锚点·别名·块标量等构造会如实报"解析不了"并建议转 JSON）
                               ⇒ 展开成 N 个目标，逐个保留 method/headers/body
                               （对标 sqlmap 2.0 的 OpenAPI 目标生成）
                             ⚠ OpenAPI 是**接口定义**不是抓包：参数值取自 example/default，
                               缺失处是占位 '1'，扫之前请自行核对
  --method <GET|POST|...>    请求方法（默认 GET；支持 PUT/PATCH/DELETE）
  --body <json>              POST body（JSON 对象字符串）
  --xml-body <xml>           XML / SOAP body 原文（注入点取叶子路径，如 soap:Envelope.soap:Body.GetUser.id）
  --xml-body-file <path>     同上，从文件读（多行 SOAP 信封用这个）
  --cookie <str>             认证 Cookie 串（透传 config.auth.cookie，非注入点）
  --header <k:v,k:v>          额外请求头（冒号分隔，逗号分隔多组）
  --technique <BEUSTQ>       检测技术子集（union/error/boolean/time/stacked/oob/inline/second_order，逗号分隔；缺省=默认 4 类）
  --no-sql                   [2026-10-12 §A2] 开启 NoSQL 注入通道（nosql/graphql/ssti 三类，默认关）。
                             ★ 与 --technique 正交：technique 决定「测不测」，本开关决定「通道起不起」——
                             此前 UI/REST 可达而 CLI 完全无入口（连 --config 档案都被未知键硬拒）。
                             子键（noSql.kinds / noSql.concurrency）走 --config 档案：
                             {"noSql":{"enabled":true,"kinds":["nosql"]}}
  --oob                      [2026-10-12 §A2] 开启 OOB 带外通道接收端（默认关；即使 --technique 含 oob，
                             接收端不起也拿不到回调 —— defaults.js:292 明示）。子键走 --config 档案：
                             {"oob":{"enabled":true,"callbackBase":"your.domain:8899","dnsOob":true,"dnsDomain":"your.domain"}}
                             本地模式要求**目标能回连扫描器**（callbackBase 需目标可解析）
  --oob-interactsh           [D87] 改用外部协作端隧道（interactsh 协议）：只要求**扫描器能出网**，
                             不要求目标入站可达 —— 目标是云上/NAT 后/跨网段时的唯一可行形态。
                             开时一并开启 oob 总开关。子键走 --config 档案：
                             {"oob":{"enabled":true,"interactsh":{"enabled":true,"server":"oast.pro"}}}
                             ⚠ 默认用公共协作端（回连记录交给其运营方，真实项目建议自建）；
                             ⚠ 仅回带 token 不回带数据本身；仅在已授权范围内使用
  --level <1-5>              检测等级（1 默认，5 最深，对应注入点边界/子句变体）
  --risk <1-3>               风险等级（1 安全，2 标准，3 含 OR 变体）
  --test-filter <str>        仅运行 id 匹配的测试（逗号分隔子串，大小写不敏感，对标 sqlmap --test-filter）
  --test-skip <str>          跳过 id 匹配的测试（逗号分隔子串，大小写不敏感，对标 sqlmap --test-skip）
  -p, --test-param <p1,p2>   只测指定参数（[D41] 对标 sqlmap -p；参数名精确匹配，大小写不敏感。
                             复测/CI 定向回归用：大 body 只测可疑参数，不再全量投 payload。
                             一个都没匹配到时拒绝启动并列出可用点位 —— 0 点扫描=「没测」，不许伪装成「未检出」）
  --param-exclude <regex>    按正则排除参数（[D41] 对标 sqlmap --param-exclude，大小写不敏感）：
                             会话/CSRF/风控噪声参数一个表达式全排除（如 --param-exclude "ses|csrf"）。
                             排除到 0 点时同样拒绝启动
  --param-filter <place,...> 按位置筛选注入点（[D41] 对标 sqlmap --param-filter）：
                             url/query/get、body/post/form、header、cookie、path（大小写不敏感）。
                             例：--param-filter body —— 只测 body 参数（query 已签名/已被 CDN 固定时）
  --second-req <file>        二阶触发页整请求文件（[D42] 对标 sqlmap --second-req）：从 Burp/curl
                             抓包导入 URL/method/headers/body（与 -r 同一解析器）。触发页需要
                             POST + 认证头 + Cookie 时 --second-order <url> 表达不了——认证触发页
                             不带会话必 401，二阶必漏。方法仍过幂等门：productionMode 下 POST 触发
                             读取需 --allow-second-order-writes
  --ignore-code <c1,c2>      忽略指定 HTTP 错误码（[D42] 对标 sqlmap --ignore-code，100-599）：
                             这些状态码不再计入「拦截/会话失效/服务器错误」可信度判定（响应内容
                             照常参与比对）。注入点确实坐在 401/500 后面的目标（单点鉴权接口）
                             不配它，结论会被拖成 blocked/session_expired 而不是照常检测
  --randomize <p1,p2>        每条注入请求随机化指定参数的值（[D42] 对标 sqlmap --randomize）：
                             长枚举/拖库时防止反爆破计数把出口 IP 锁死。覆盖 URL query / Cookie /
                             请求头 / 表单伴随字段；注入点自身永不随机化；JSON/XML body 不覆盖
  --dump-format <fmt>        拖库数据独立产物格式（[D42] 对标 sqlmap --dump-format，csv/sql/html/json）：
                             有拖库数据时产出 dump.<ext>（一键扫描目录内）。只影响独立产物，
                             报告内嵌的拖库区不变。非法格式拒绝启动
  --no-verify                关闭盲注提取复核（[D42]；默认开：每字节收敛后等值确认 + 完整值
                             整体复验，失败自动重测——弱网/限速目标的拖库假字符防线，开销约
                             +1 请求/字节）。--verify 显式开启（与默认一致，幂等）
  --fetch-using <gt|between> 盲注提取比较算子（[D50]，默认 gt=历史行为）：> / < 被 WAF 过滤
                             而 BETWEEN 仍放行的目标上，between 把长度/字节二分换成
                             x BETWEEN lo AND mid 窄化（cls 字符类探测本就只用 BETWEEN）。
                             探测次数与 gt 同阶；提取结果经等值复验后应一致。'in' 不支持
                             （IN 为假时无法定位区间）。非法值拒绝启动
  --test-headers             把显式传入的请求头（--header 或 -r 请求文件中的头，如 Cookie / X-Forwarded-For）
                             作为注入点测试（默认关闭：保持现有行为，头仅作会话透传）。授权的渗透测试中，
                             服务端按请求头取值拼 SQL 的场景（如 SELECT ... WHERE id=\${x_forwarded_for}）必须开启才能检出
  --test-path               把 URL path 末段（非空且非静态资源 .html/.js/.css/.png 等）作为注入点测试
                             （默认关闭：保持现有行为。服务端按 path 段取值拼 SQL 的场景必须开启才能检出）
                             [P0-FIX 2026-09-16] 曾因「404 页回显 URL → payload 自带关键词被误读为
                             数据库报错」导致非 200 端点误报（7 个安全点中 6 个），已修复：
                             匹配前先做 HTML 实体 + URL 解码归一化并剔除被回显的 payload。
                             验证：安全点误报 6/7 → 0/7，真阳性保持命中，同点连跑 5 次无偶发。
                             详见 README「已知问题与修复记录」与 e2e/blackbox-lab/
  --param-mine               参数挖掘（2026-10-02 竞品吸收，对标 Arjun 参数发现；默认关闭零回归）：
                             对目标 URL 主动探测字典参数（分组发送+反射定位+二分收敛，请求预算硬顶
                             150），发现的隐藏参数（如 ?debug=1 才触发 SQL 拼接的参数）自动加入注入点。
                             仅支持 GET/HEAD query 与 POST urlencoded 载体；JSON/XML/multipart 目标跳过
  --crawl-browser            headless 浏览器爬取（2026-10-02 实战 P1-4；默认关闭零回归）：用 Playwright
                             （msedge/chrome/自带 chromium 自动探测）渲染页面，收集 SPA 的 XHR/fetch
                             接口与 JS 动态链接为注入点——React/Vue 等前端渲染目标 HTTP 爬虫看不见
                             /api/*，此开关补齐。需安装 playwright（devDeps 已含）；不可用时自动
                             降级为 HTTP 爬虫。深度沿用 --crawl=<depth>（0=只渲染入口页）
  --login-url <url>          登录编排最小版（2026-10-02 实战 P1-6；默认关闭）：标准表单登录自动提交
                             （GET 登录页探测用户名/密码输入框名 + hidden/CSRF 透传 → POST 凭据），
                             会话过期（401/403/登录跳转）自动重登一次并重试原请求。凭据用
                             --auth user:pass；字段名可用 --login-user-field/--login-pass-field 覆盖。
                             诚实边界：SAML、验证码、JS 加密提交不支持——此类目标
                             请人工取 cookie 走 --cookie 静态注入。
                             API 侧的 Bearer/Token 过期不在此列，用下面的 --refresh-url
  --refresh-url <url>        Bearer/Token 自动续期（2026-10-10 实战 P0-2；默认关闭）：请求吃
                             401/403 时 POST 该地址换新 access token，成功后重试原请求一次
                             （并发只刷一次；拿到新 token 之前不动你从抓包带来的 Authorization）。
                             access token 半小时过期的目标上不给它 = 后半程全 401 ⇒ 那些参数
                             全被判「不可注入」，而报告写的是「未检出」。续期失败会把结论降级为
                             inconclusive 并在 reason 里给出失败原因与响应顶层键名
  --refresh-token <token>    刷新凭据（不填则依赖会话 Cookie，多数实现如此）
  --refresh-field <path>     续期响应里取 token 的字段路径（如 data.access_token）；
                             不填按 access_token / token / data.token 等常见形态探测
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
  -b, --banner              数据库横幅/版本串（[D46] 对标 sqlmap -b）：方言版本表达式与盲注指纹
                            同源；不支持的结构性方言诚实返回 null
  --statements              当前正在执行的 SQL 语句（[D46] 对标 sqlmap --statements）：应用侧侦察
                            （第二注入点/表名）。MySQL processlist / PG pg_stat_activity /
                            MSSQL dm_exec_requests / Oracle v$sql，硬上界 20 条；
                            其余方言结构性不支持（诚实降级）
  --procs                   存储过程/函数清单（[D46] 对标 sqlmap --procs）：提权侦察 + 可注入
                            过程入口。information_schema.ROUTINES / pg_proc /
                            INFORMATION_SCHEMA.ROUTINES / ALL_OBJECTS，硬上界 100 条
  -U, --user <name>         用户过滤（[D46] 对标 sqlmap -U）：仅 --users/--passwords 模式生效，
                            从聚合结果中筛出该用户的条目（客户端侧过滤，大小写不敏感）。
                            --privileges/--roles 只覆盖当前用户，-U 对它们不适用（显式报错）
  --exclude <db,db>         枚举时排除指定库（[D46] 对标 sqlmap --exclude，最多 16 个）：
                            跳过已知巨大的/噪声库；与 --exclude-sysdbs 正交（点名排除优先）
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
  --payload-file <file.json>  追加自定义检测条目（与 registry.json 同 schema，见 docs/自定义检测条目.md）；
                             只追加、不允许覆盖内置条目；不传即与内置基线完全一致
  --request-script <file.js>  自定义请求变换脚本（签名/加密参数接口）：扫描/检测阶段每条出站请求
                             的最后一环调用其 transform(req) 重算 sign / 重新加密整包
                             （含保活/CSRF 取页/登录；注入点发现阶段的爬虫请求不经此层）。
                             目标带签名或加密参数时
                             不带本开关的结果是「未检出」，而那**不等于没有洞**——注入值破坏了签名，
                             从未抵达 SQL。脚本必须位于环境变量 REQUEST_SCRIPT_DIR 指定的目录内
                             （出口层的代码注入面，故不给自由路径）；加载/执行失败一律硬失败，
                             不会退化成「发没签名的原始请求」。用法见 docs/请求变换脚本.md
  --postprocess <file.js>     自定义响应解密脚本（加密/编码响应体；与 --request-script 对偶）：
                             扫描/检测阶段每条响应体的最内层调用其 transform(res) 解密/解码，
                             之后检测/提取/可信度守卫看到的都是明文（含保活/CSRF 取页/登录；
                             爬虫请求不经此层）。目标把响应加密封装时
                             不带本开关的结果是「未检出」——真/假条件的差异被加密抹平，
                             而那**不等于没有洞**。脚本只允许替换 data（响应体文本），
                             status/headers 不可改；必须位于环境变量 RESPONSE_SCRIPT_DIR
                             指定的目录内（入口层的代码注入面）；加载失败扫描不启动，
                             执行失败时该响应按失败处理（宁漏不误，绝不用密文继续比对）
  --time-baseline-every <n>  时间提取的基线漂移重采样间隔（个探针，默认 16，0=关闭）。
                             时间判定阈值 = 目标自身耗时 + --time-threshold，目标在一条
                             提取链（60~80 探针）期间变慢时，原先只在开头测一次的基线
                             会被吃掉余量 ⇒ 任何条件都判真 ⇒ 产出看着像数据的错值。
                             本开关让判假探针的耗时当免费 RTT 样本连续喂回基线；连续 n
                             个探针没拿到干净样本（已恒判真/请求失败）才补发一次基线请求
                             ⇒ 健康提取零额外请求。请求失败不入样（异常瞬时返回会压低阈值）
  --identify-waf             仅识别 WAF 厂商并给出推荐 tamper 链，不发起注入检测
                             （对标 sqlmap --identify-waf；用于扫描前先摸清对面是什么 WAF）。
                             两阶段：被动指纹（62 厂商签名 + 通用拦截页）→ 无果时多向量主动探测
                             （[D44] wafw00f 式：sqli-union/sqli-quote/xss/lfi 四向量 + Server 头
                             差分 + 连接级阻断识别——断连型 WAF 此前被 .catch 吞掉看不见）。
                             evidence 给结构化信号（哪些向量被拦/头漂移），可复核
  --active-waf-probe         扫描期开启主动 WAF 探测（[D44]；默认关）：被动指纹未命中的目标
                             在检测前发 5-9 条探测请求，命中拦截即把「unknown 拦截器 + 证据」
                             写进报告 WAF 节。预算：良性 1 + 向量 4（连接级失败向量重试一次）
  --smart                    智能启发式（别名，等价 prefilter: true，跳过非注入参数）
  --proxy <url>              代理（http://host:port 或 socks5://host:port）
  --proxy-bypass-local       本地/私网**也**走环境变量代理（默认豁免 127.0.0.1 与内网）
  --scope <cidr/域名,...>    授权范围硬约束（[P0-SEC] 如 10.0.0.0/24,target.example.com）：
                             启用后目标与每一跳重定向均须在范围内，越界直接拒发；留空不启用
  --insecure                 忽略自签/内网 CA 证书（关闭 TLS 校验，失去中间人防护，报告须注明）
  --cert <path>              mTLS 客户端证书 PEM（证书+私钥同文件，形状非法时引擎侧硬失败）
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
  --no-xp-auto-enable        拒绝自动开启 xp_cmdshell：MSSQL 的 os shell 通路在未启用时会发
                             sp_configure 'xp_cmdshell',1 + RECONFIGURE（实例级永久配置变更）。
                             默认仍自动开启（与历史行为一致）；要把扫描严格停在只读边界内就加本开关。
  --no-proxy-bypass-local    关闭本地/私网代理豁免（默认豁免：127.0.0.1/内网不走 *PROXY 环境变量，
                             避免系统代理掐断请求后被记成「无漏洞」）
  --auth <user:pass>         Basic 认证（user:password 形式）
  --auth-type <Basic|Digest|NTLM>  认证类型（默认 Basic；Digest 走 RFC 7616 挑战-响应；
                             NTLM 走 Type1-3 握手（引擎完整实现），凭据用 DOMAIN\\user:pass
                             形态对齐 sqlmap --auth-cred，domain 可省略）
  --rate <n>                 限速 req/s（默认 50）
  --threads <n>              检测并发数（默认 4）；别名 --concurrency-det（同义）
  -f, --format <fmt>         报告格式 json|csv|markdown|md|html|sarif|db-json（默认 json）。
                             md = markdown 别名；sarif = SARIF 2.1.0（GitHub Security/DefectDojo）；
                             db-json = 仅拖库数据（库/表/列/行，扩展名 db.json，与 REST 导出同源）。
                             未知格式**拒绝启动**（旧行为静默回退 JSON 已修，"传了没生效"红线）
  -o, --out <path>           报告输出文件（批量模式输出到目录）
  -c, --concurrency <n>     批量并发扫描数（默认 1）
  --timeout <ms>             单次扫描等待上限（默认 0 = 无限制）
  --retries <n>              单请求连接失败重试次数（[D41] 对标 sqlmap --retries，0-5，默认 3；
                             此前只有 REST 能配，CLI 无入口）
  --http-timeout <ms>        单请求超时（[D41] 1000-60000，默认 30000）。命名避开 --timeout
                             （那是整场扫描的等待上限）：慢目标（30s+ 才响应）从这里放宽

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
  --os-cmd <cmd>            执行系统命令（os-shell 通道，入口形态）
  --os-shell [cmd]          同 --os-cmd：不带值则走交互式 os-shell（等价 --os-shell=true）
  --udf-hex <src>           UDF 十六进制投放（MSSQL 用；写入目标文件后 CREATE FUNCTION）
  --udf-install             UDF 一键安装（写入 + 建函数 + 调用，需 --udf-hex）
  --sql-shell <sql>         执行任意 SQL
  --file-read <path>        读取目标文件
  --file-write <content>    写入目标文件（需配合 --file-dest <远程路径>）
  --file-dest <path>        --file-write 的远程目标路径

爬虫与会话（对标 sqlmap）:
  --forms                  收集页面表单注入点（需配 --level 5 才生效）
  --crawl <depth>           站内链接爬取深度（1-3，默认 0=不爬取）
  --session-file <path>     会话文件路径（断点续跑）
  --flush-session           每次请求前清会话 Cookie（对标 sqlmap --flush-session）
  --fresh-queries           每个 payload 换一个随机查询串，规避目标侧缓存（对标 sqlmap --fresh-queries）
  --config <file>           从 JSON 配置档案预载参数（[D41] 对标 sqlmap -c + ffuf -config）：
                            键=长参数名（去前导 --，如 {"url":"…","level":5,"tamper":"space2comment"}），
                            CLI 显式开关优先生效（argv > 档案 > 内置默认）。档案含未知键时拒绝启动；
                            认证档案属敏感文件，注意权限与入库（.gitignore）
  --save-config <file>      把本次实际生效的参数增量（相对内置默认的差异）写成 JSON 档案，
                            下次 --config 复用；写完照常继续扫描
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
  1 = 参数错误/扫描失败
已移除的占位参数（收下即丢弃、无效果，仅为兼容旧命令行 —— 不是能力）:
  --no-escape / --union-char    历史保留接口，已无对应实现
  --max / --days                扫描侧占位；⚠️ 与 ledger 子命令的 ledger prune --max=N 同名不同义
  --headers / --concurrency-det  上列 --header / --threads 的同义别名，仍有效

`;

export function printHelp() {
  console.log(HELP_TEXT);
}