# sqlmap 对标底账（自动生成，勿手改）

> 生成：`node scripts/sqlmap-parity.mjs --write` · 上游基准：sqlmap **1.10.7** `-hh` · 本方真源：`server/bin/cli/args.js` 解析分支
>
> 这份底账只回答两个问题：**sqlmap 的能力面有多少个**、**本仓逐项处在哪一态**。
> 它**不是**能力声明：`等价异构`/`部分覆盖` 只表示「这一项有落点」，够不够用必须回到逐项证据
> （README「sqlmap 同题对照」、`docs/审计口径.md`、`docs/检测与定库-实测口径.md`）与真机靶场复跑。
>
> 状态口径：`同名同义`＝旗标名与语义都对齐；`等价异构`＝语义等价但本仓用别的形态表达；
> `默认即覆盖`＝不需要开关，默认行为已经满足（说明里写清是哪条默认行为）；`部分覆盖`＝有落点但明确还差东西；
> `缺口`＝当前无对应能力（P1/P2/P3 为落地优先级）；`明确不做`＝有意识的边界（理由必须自足，见下表）。

## 一、分母与分布

| 状态 | 项数 | 占分母 |
|---|---|---|
| 同名同义 | 98 | 44% |
| 等价异构 | 30 | 14% |
| 默认即覆盖 | 3 | 1% |
| 部分覆盖 | 10 | 5% |
| 缺口 | 52 | 23% |
| 明确不做 | 29 | 13% |
| **分母合计** | **222** | 100% |

缺口的优先级分布：P1 **1** · P2 **19** · P3 **32**。

> ⚠ 引用本表时不得只说「覆盖率 N%」：`明确不做` 是**有意识**的边界（武器化、目标发现、自更新等），
> 把它算进「未覆盖」会误导，把它踢出分母又是自欺 —— 所以分布必须整张一起引用。

## 二、P1/P2 缺口（按落地批次规划）

### D198 · 会话与 OPSEC（剩余 P1/P3 缺口：出口留残留、清理面为空）

- `--cleanup` — **缺口（P1）**：利用后清理（UDF/xp_cmdshell 复位/临时表/落盘文件）**完全缺失**：授权测试的 OPSEC 刚需，不做等于在客户环境留残留
- `--purge` — **缺口（P3）**：本地产物/会话清理（与 --cleanup 相邻：这项针对本地侧）未实现

### D199 · 协议形态与宿主钩子（WAF/IDS 绕过的收发形态 + 自动化入口）

- `--chunked` — **缺口（P2）**：Transfer-Encoding: chunked 分块发送（绕 IDS/WAF 的常见形态）；httpClient 无分块发送路径
- `--skip-urlencode` — **缺口（P2）**：注入值恒做 URL 编码；目标只在未编码形态下才透传到 SQL 时无法表达
- `--skip-xmlencode` — **缺口（P3）**：XML/SOAP 注入值恒做实体编码；同上
- `--retry-on` — **缺口（P2）**：按状态码/响应特征重试（弱网 + 风控抖动目标的关键）；当前仅对连接失败重试
- `--crawl-exclude` — **缺口（P2）**：爬虫排除正则未暴露（登出链接/危险动作页必须能排掉）
- `--skip-waf` — **缺口（P3）**：跳过 WAF 识别阶段未暴露（已知有 WAF 且只想省请求时）
- `--alert` — **缺口（P2）**：命中即执行宿主命令（自动化联动/Slack 钩子）；需显式授权与命令白名单，不能静默执行

### D200 · Windows 注册表面（引擎已实现、只差接线：读/写/删 + 四个参数面）

- `--reg-read` — **缺口（P2）**：**引擎已实现** registryRead（server/src/engine/exploit/registry.js，MSSQL xp_regread 通道），CLI 与 REST 均无入口 ⇒ 接线即可，不用重写
- `--reg-add` — **缺口（P2）**：**引擎已实现** registryWrite（写入类，需 EXPLOIT_ENABLED + --authorized 双闸）⇒ 接线即可
- `--reg-del` — **缺口（P2）**：**引擎已实现** registryWrite 的删除形态 ⇒ 接线即可
- `--reg-key` — **缺口（P2）**：注册表路径参数面（配合 reg-read/add/del，同批接线）
- `--reg-value` — **缺口（P2）**：注册表值名参数面（同上）
- `--reg-data` — **缺口（P2）**：写入数据参数面（同上）
- `--reg-type` — **缺口（P2）**：写入类型参数面（REG_SZ/DWORD 等，同上）
- `--dbms-cred` — **缺口（P3）**：DBMS 侧凭据（UDF/注册表操作的 EXECUTE AS 等）无入口

### D201 · 传输形态收口（把「只做了一半」的三项做完：检测链路 h2 / HTTP1 回退 / HEAD 快速判定）

- `--http2` — **缺口（P2）**：**只做了一半**：config.http2 只被 crawler / TargetParser 消费（取页/爬虫面），注入请求走 opts.http2 而无人传该键 ⇒ 接线必须同时改检测链路的出口选项，属独立批次；D197 复核后**刻意没接**（接了就是「收参数不生效」）
- `--http1` — **缺口（P3）**：强制 HTTP/1.1；引擎只有 http2 开关，h2 优先失败时无法回退到 1.1
- `--null-connection` — **缺口（P2）**：**引擎写完了但没接线**：sendHead / matchNullConnection 挂在 Detector 原型上而**零调用点**（死代码），httpClient.headRequest 也只有包装没有消费者 ⇒ 真做要接进布尔/时间检测器并复核判据（HEAD 无 body，真假只能靠状态码 + Content-Length），不是纯接线
- `--unstable` — **缺口（P3）**：不稳定连接模式（弱网重试策略）未实现

### D202 · 强制面与编码（把「推断错了就没救」的几项变成可显式指定）

- `--os` — **缺口（P2）**：强制目标 OS（影响文件路径与命令通道形态）；当前按 DBMS 推断，无显式覆盖
- `--encoding` — **缺口（P2）**：页面编码显式声明（GBK/Shift-JIS 目标）未暴露；比对与提取当前按 UTF-8/自动
- `--charset` — **缺口（P3）**：注入值字符集约束（非 ASCII 目标）未暴露
- `--fingerprint` — **部分覆盖**：本仓产 DBMS 版本 + summary.dbmsEvidence 分级；OS / Web 服务器指纹未成体系

### D203 · 非 SQL 通道补齐（LDAP / XPath 注入检测器）

- `--ldap` — **缺口（P2）**：LDAP 注入通道未实现（检测器 + payload 面；sqlmap 1.10 新增）
- `--xpath` — **缺口（P2）**：XPath 注入通道未实现（同上）

### D204 · 长尾 P3（按需；不与上面抢优先级，但都在底账里点名，不许「关起门来」）

- `--abort-code` — **缺口（P3）**：命中指定状态码即中止整场（风控/封禁早停）；当前只有 --ignore-code 的反向语义
- `--ignore-timeouts` — **缺口（P3）**：超时不计入可信度判定；当前超时会被记为未验证面（更诚实，但缺用户显式覆盖口）
- `--safe-post` — **缺口（P3）**：保活请求只支持 GET；会改状态的会话用 POST 保活时无表达方式
- `--safe-req` — **缺口（P3）**：保活请求无法整请求导入（带认证头的保活页）
- `--csrf-data` — **缺口（P3）**：取 CSRF token 时的附加表单字段未暴露（多步令牌页）
- `--csrf-retries` — **缺口（P3）**：取 token 失败的重试次数未暴露
- `--union-values` — **缺口（P3）**：UNION 判真的自定义测试值未暴露（非常规字符集目标）
- `--abort-on-empty` — **缺口（P3）**：连续空结果即停（防无意义拖库）；当前只能靠 --max-requests 兜
- `--check-internet` — **缺口（P3）**：开扫前连通性自检（区分「本机断网」与「目标不可达」）未实现
- `--csv-del` — **缺口（P3）**：CSV 导出分隔符不可配（Excel 本地化场景）
- `--dump-file` — **缺口（P3）**：拖库数据落盘路径不可单独指定（当前固定 dump.<ext>）
- `--table-prefix` — **缺口（P3）**：Oracle/DB2 表前缀枚举参数未暴露
- `--unsafe-naming` — **缺口（P3）**：拖库产物命名安全化开关未暴露（长尾）
- `--web-root` — **缺口（P3）**：文件写用的 Web 根路径（写 webshell 落点）未暴露；当前要求绝对路径 --file-dest
- `--no-logging` — **缺口（P3）**：关闭日志落盘开关未暴露（当前恒写 ledger）
- `--no-truncate` — **缺口（P3）**：报告长字段不截断开关未暴露（长 payload/长响应取证用）
- `--comments` — **缺口（P3）**：表/列注释枚举（MSSQL/MySQL 的 pg_description 类面）未实现
- `--pivot-column` — **缺口（P3）**：关联表拖库时的主键列指定未实现
- `--sql-file` — **缺口（P3）**：从文件读 SQL 再执行（长脚本/多语句）；当前只能内联 --sql-shell 串
- `--common-files` — **缺口（P3）**：常见文件名字典爆破（LOAD_FILE 路径面）未实现
- `--binary-fields` — **缺口（P3）**：二进制列（图片/哈希）十六进制化导出未实现
- `--proxy-file` — **缺口（P3）**：代理池轮换（每请求换出口）未实现；--proxy 只有单出口
- `--proxy-freq` — **缺口（P3）**：配合代理池的换出口频率未实现（与 --proxy-file 同批）
- `--tor-type` — **缺口（P3）**：仅 socks5；socks4/http 代理类型未暴露为独立开关
- `-t` — **缺口（P2）**：原始 HTTP 流量全量落盘（复现与审计）未实现：当前只有结构化 ledger + 报告，无法回放原始报文
- `-v` — **缺口（P3）**：日志详细度无 CLI 开关（级别走环境变量/配置），与 sqlmap -v 0-6 的逐级详细度不对位

## 三、逐项底账

### Target（目标输入）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--url` | 同名同义 | `--url` |  |

### Request（请求构造）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--user-agent` | 等价异构 | `--header` |  |
| `--header` | 同名同义 | `--header` |  |
| `--method` | 同名同义 | `--method` |  |
| `--data` | 等价异构 | `--body` |  |
| `--param-del` | 同名同义 | `--param-del` |  |
| `--cookie` | 同名同义 | `--cookie` |  |
| `--cookie-del` | 部分覆盖 | `--cookie` | 解析固定按 `;` 分隔；自定义 cookie 分隔符未暴露（低价值长尾） |
| `--live-cookies` | 同名同义 | `--live-cookies` |  |
| `--load-cookies` | 同名同义 | `--load-cookies` |  |
| `--drop-set-cookie` | 同名同义 | `--drop-set-cookie` |  |
| `--http1` | 缺口（P3） | — | 强制 HTTP/1.1；引擎只有 http2 开关，h2 优先失败时无法回退到 1.1 |
| `--http2` | 缺口（P2） | — | **只做了一半**：config.http2 只被 crawler / TargetParser 消费（取页/爬虫面），注入请求走 opts.http2 而无人传该键 ⇒ 接线必须同时改检测链路的出口选项，属独立批次；D197 复核后**刻意没接**（接了就是「收参数不生效」） |
| `--mobile` | 同名同义 | `--mobile` |  |
| `--random-agent` | 同名同义 | `--random-agent` |  |
| `--host` | 等价异构 | `--header` |  |
| `--referer` | 等价异构 | `--header` |  |
| `--headers` | 同名同义 | `--headers` |  |
| `--auth-type` | 同名同义 | `--auth-type` |  |
| `--auth-cred` | 等价异构 | `--auth` |  |
| `--auth-file` | 等价异构 | `--cert` |  |
| `--abort-code` | 缺口（P3） | — | 命中指定状态码即中止整场（风控/封禁早停）；当前只有 --ignore-code 的反向语义 |
| `--ignore-code` | 同名同义 | `--ignore-code` |  |
| `--ignore-proxy` | 部分覆盖 | `--proxy-bypass-local` | 本仓用「本地/私网豁免环境变量代理」表达，缺「对所有目标都不走代理」的全局口 |
| `--ignore-redirects` | 同名同义 | `--ignore-redirects` |  |
| `--ignore-timeouts` | 缺口（P3） | — | 超时不计入可信度判定；当前超时会被记为未验证面（更诚实，但缺用户显式覆盖口） |
| `--proxy` | 同名同义 | `--proxy` |  |
| `--proxy-cred` | 等价异构 | `--proxy` |  |
| `--proxy-file` | 缺口（P3） | — | 代理池轮换（每请求换出口）未实现；--proxy 只有单出口 |
| `--proxy-freq` | 缺口（P3） | — | 配合代理池的换出口频率未实现（与 --proxy-file 同批） |
| `--tor` | 同名同义 | `--tor` |  |
| `--tor-port` | 部分覆盖 | `--tor` | Tor 端口固定 9050，无旗标覆盖（wafEvasion 可配但无 CLI 面） |
| `--tor-type` | 缺口（P3） | — | 仅 socks5；socks4/http 代理类型未暴露为独立开关 |
| `--check-tor` | 同名同义 | `--check-tor` |  |
| `--delay` | 等价异构 | `--delay-sec` |  |
| `--timeout` | 等价异构 | `--http-timeout` |  |
| `--retries` | 同名同义 | `--retries` |  |
| `--retry-on` | 缺口（P2） | — | 按状态码/响应特征重试（弱网 + 风控抖动目标的关键）；当前仅对连接失败重试 |
| `--randomize` | 同名同义 | `--randomize` |  |
| `--safe-url` | 同名同义 | `--safe-url` |  |
| `--safe-post` | 缺口（P3） | — | 保活请求只支持 GET；会改状态的会话用 POST 保活时无表达方式 |
| `--safe-req` | 缺口（P3） | — | 保活请求无法整请求导入（带认证头的保活页） |
| `--safe-freq` | 同名同义 | `--safe-freq` |  |
| `--skip-urlencode` | 缺口（P2） | — | 注入值恒做 URL 编码；目标只在未编码形态下才透传到 SQL 时无法表达 |
| `--skip-xmlencode` | 缺口（P3） | — | XML/SOAP 注入值恒做实体编码；同上 |
| `--csrf-token` | 同名同义 | `--csrf-token` |  |
| `--csrf-url` | 同名同义 | `--csrf-url` |  |
| `--csrf-method` | 同名同义 | `--csrf-method` |  |
| `--csrf-data` | 缺口（P3） | — | 取 CSRF token 时的附加表单字段未暴露（多步令牌页） |
| `--csrf-retries` | 缺口（P3） | — | 取 token 失败的重试次数未暴露 |
| `--force-ssl` | 同名同义 | `--force-ssl` |  |
| `--chunked` | 缺口（P2） | — | Transfer-Encoding: chunked 分块发送（绕 IDS/WAF 的常见形态）；httpClient 无分块发送路径 |
| `--hpp` | 同名同义 | `--hpp` |  |
| `--eval` | 等价异构 | `--request-script` |  |

### Optimization（性能）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--predict-output` | 同名同义 | `--predict-output` |  |
| `--no-keep-alive` | 同名同义 | `--no-keep-alive` |  |
| `--null-connection` | 缺口（P2） | — | **引擎写完了但没接线**：sendHead / matchNullConnection 挂在 Detector 原型上而**零调用点**（死代码），httpClient.headRequest 也只有包装没有消费者 ⇒ 真做要接进布尔/时间检测器并复核判据（HEAD 无 body，真假只能靠状态码 + Content-Length），不是纯接线 |
| `--threads` | 同名同义 | `--threads` |  |

### Injection（注入构造）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--skip` | 同名同义 | `--skip` |  |
| `--skip-static` | 同名同义 | `--skip-static` |  |
| `--param-exclude` | 同名同义 | `--param-exclude` |  |
| `--param-filter` | 同名同义 | `--param-filter` |  |
| `--dbms` | 同名同义 | `--dbms` |  |
| `--dbms-cred` | 缺口（P3） | — | DBMS 侧凭据（UDF/注册表操作的 EXECUTE AS 等）无入口 |
| `--os` | 缺口（P2） | — | 强制目标 OS（影响文件路径与命令通道形态）；当前按 DBMS 推断，无显式覆盖 |
| `--invalid-bignum` | 同名同义 | `--invalid-bignum` |  |
| `--invalid-logical` | 同名同义 | `--invalid-logical` |  |
| `--invalid-string` | 同名同义 | `--invalid-string` |  |
| `--no-cast` | 同名同义 | `--no-cast` |  |
| `--no-escape` | 明确不做 | — | 原「保留接口」已按「收参数不生效＝红线」移除；实现需改转义实现（与引擎不同源，语义无法对齐） |
| `--prefix` | 同名同义 | `--prefix` |  |
| `--suffix` | 同名同义 | `--suffix` |  |
| `--tamper` | 同名同义 | `--tamper` |  |
| `--proof` | 默认即覆盖 | — | 证据链默认就带 payload 与命中位置（vuln.poc.curl/raw + hit.match + --fix-prompt），无需开关 |

### Detection（判定口径）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--level` | 同名同义 | `--level` |  |
| `--risk` | 同名同义 | `--risk` |  |
| `--string` | 同名同义 | `--string` |  |
| `--not-string` | 同名同义 | `--not-string` |  |
| `--regexp` | 同名同义 | `--regexp` |  |
| `--code` | 同名同义 | `--code` |  |
| `--smart` | 同名同义 | `--smart` |  |
| `--text-only` | 同名同义 | `--text-only` |  |
| `--titles` | 同名同义 | `--titles` |  |

### Techniques（技术面）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--technique` | 同名同义 | `--technique` |  |
| `--time-sec` | 同名同义 | `--time-sec` |  |
| `--disable-stats` | 明确不做 | — | 本仓无「统计面板」概念（进度行 + 报告即输出面），无开关可关 |
| `--union-cols` | 同名同义 | `--union-cols` |  |
| `--union-char` | 明确不做 | — | 同上（占位已移除）；实现需改 marker.js 的 MARKER_RE 与 tamper 保护链（高危区），评估结论为风险 > 收益 |
| `--union-from` | 同名同义 | `--union-from` |  |
| `--union-values` | 缺口（P3） | — | UNION 判真的自定义测试值未暴露（非常规字符集目标） |
| `--dns-domain` | 部分覆盖 | `--oob` | 带外 DNS 外带走 --oob + config.oob.dnsDomain / --oob-interactsh，无同名旗标 |
| `--second-url` | 等价异构 | `--second-order` |  |
| `--second-req` | 同名同义 | `--second-req` |  |

### Fingerprint（指纹）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--fingerprint` | 部分覆盖 | `--banner` | 本仓产 DBMS 版本 + summary.dbmsEvidence 分级；OS / Web 服务器指纹未成体系 |

### Enumeration（枚举与拖库）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--all` | 部分覆盖 | `--dump-all` | --dump-all 覆盖全库拖库；sqlmap -a 还含 users/passwords/privileges 一次拉全 |
| `--banner` | 同名同义 | `--banner` |  |
| `--current-user` | 同名同义 | `--current-user` |  |
| `--current-db` | 同名同义 | `--current-db` |  |
| `--hostname` | 同名同义 | `--hostname` |  |
| `--is-dba` | 同名同义 | `--is-dba` |  |
| `--users` | 同名同义 | `--users` |  |
| `--passwords` | 同名同义 | `--passwords` |  |
| `--privileges` | 同名同义 | `--privileges` |  |
| `--roles` | 同名同义 | `--roles` |  |
| `--dbs` | 同名同义 | `--dbs` |  |
| `--tables` | 同名同义 | `--tables` |  |
| `--columns` | 同名同义 | `--columns` |  |
| `--schema` | 同名同义 | `--schema` |  |
| `--count` | 同名同义 | `--count` |  |
| `--dump` | 同名同义 | `--dump` |  |
| `--dump-all` | 同名同义 | `--dump-all` |  |
| `--search` | 同名同义 | `--search` |  |
| `--comments` | 缺口（P3） | — | 表/列注释枚举（MSSQL/MySQL 的 pg_description 类面）未实现 |
| `--statements` | 同名同义 | `--statements` |  |
| `--procs` | 同名同义 | `--procs` |  |
| `--exclude-sysdbs` | 同名同义 | `--exclude-sysdbs` |  |
| `--pivot-column` | 缺口（P3） | — | 关联表拖库时的主键列指定未实现 |
| `--where` | 同名同义 | `--where` |  |
| `--start` | 同名同义 | `--start` |  |
| `--stop` | 同名同义 | `--stop` |  |
| `--first` | 等价异构 | `--start` |  |
| `--last` | 等价异构 | `--stop` |  |
| `--sql-query` | 等价异构 | `--sql-shell` |  |
| `--sql-shell` | 同名同义 | `--sql-shell` |  |
| `--sql-file` | 缺口（P3） | — | 从文件读 SQL 再执行（长脚本/多语句）；当前只能内联 --sql-shell 串 |

### Brute force（字典爆破）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--common-tables` | 同名同义 | `--common-tables` |  |
| `--common-columns` | 同名同义 | `--common-columns` |  |
| `--common-files` | 缺口（P3） | — | 常见文件名字典爆破（LOAD_FILE 路径面）未实现 |

### UDF（用户自定义函数）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--udf-inject` | 部分覆盖 | `--udf-install` | 本仓要求自带 UDF 十六进制（--udf-hex）；不内置编译产物（GPLv2 与供应链边界） |
| `--shared-lib` | 明确不做 | — | 不内置编译产物（GPLv2 与供应链边界）；用户自带 UDF 十六进制走 --udf-hex |

### File system（文件读写）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--file-read` | 同名同义 | `--file-read` |  |
| `--file-write` | 同名同义 | `--file-write` |  |
| `--file-dest` | 同名同义 | `--file-dest` |  |

### OS access（系统层）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--os-cmd` | 同名同义 | `--os-cmd` |  |
| `--os-shell` | 同名同义 | `--os-shell` |  |
| `--os-pwn` | 明确不做 | — | 武器化通道（MSF 反弹/内存马）超出「授权 SQLi 扫描 + 可核对证据」定位 |
| `--os-smbrelay` | 明确不做 | — | SMB 中继依赖外部工具链，属武器化，同上不做 |
| `--os-bof` | 明确不做 | — | 缓冲区溢出模块属武器化，同上不做 |
| `--priv-esc` | 明确不做 | — | 提权动作不可逆且越出只读取证边界；本仓只做显式授权的文件/命令通道 |
| `--msf-path` | 明确不做 | — | 无 Metasploit 集成（不做外部框架编排） |
| `--tmp-path` | 明确不做 | — | 本仓文件写为单次直写，不引入本地暂存目录概念 |

### Windows registry（注册表）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--reg-read` | 缺口（P2） | — | **引擎已实现** registryRead（server/src/engine/exploit/registry.js，MSSQL xp_regread 通道），CLI 与 REST 均无入口 ⇒ 接线即可，不用重写 |
| `--reg-add` | 缺口（P2） | — | **引擎已实现** registryWrite（写入类，需 EXPLOIT_ENABLED + --authorized 双闸）⇒ 接线即可 |
| `--reg-del` | 缺口（P2） | — | **引擎已实现** registryWrite 的删除形态 ⇒ 接线即可 |
| `--reg-key` | 缺口（P2） | — | 注册表路径参数面（配合 reg-read/add/del，同批接线） |
| `--reg-value` | 缺口（P2） | — | 注册表值名参数面（同上） |
| `--reg-data` | 缺口（P2） | — | 写入数据参数面（同上） |
| `--reg-type` | 缺口（P2） | — | 写入类型参数面（REG_SZ/DWORD 等，同上） |

### General（通用）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--abort-on-empty` | 缺口（P3） | — | 连续空结果即停（防无意义拖库）；当前只能靠 --max-requests 兜 |
| `--answers` | 明确不做 | — | 本仓 CLI 刻意无交互提问（非交互优先），等价面是 --config/--save-config 与显式旗标 |
| `--base64` | 等价异构 | `--tamper` |  |
| `--base64-safe` | 等价异构 | `--tamper` |  |
| `--batch` | 默认即覆盖 | — | CLI 无交互提问（非交互优先），「不提问」这件事天然成立；⚠ 本仓 --batch 是「批量目标文件」不是 sqlmap 的这个开关 |
| `--binary-fields` | 缺口（P3） | — | 二进制列（图片/哈希）十六进制化导出未实现 |
| `--check-internet` | 缺口（P3） | — | 开扫前连通性自检（区分「本机断网」与「目标不可达」）未实现 |
| `--cleanup` | 缺口（P1） | — | 利用后清理（UDF/xp_cmdshell 复位/临时表/落盘文件）**完全缺失**：授权测试的 OPSEC 刚需，不做等于在客户环境留残留 |
| `--crawl` | 同名同义 | `--crawl` |  |
| `--crawl-exclude` | 缺口（P2） | — | 爬虫排除正则未暴露（登出链接/危险动作页必须能排掉） |
| `--csv-del` | 缺口（P3） | — | CSV 导出分隔符不可配（Excel 本地化场景） |
| `--charset` | 缺口（P3） | — | 注入值字符集约束（非 ASCII 目标）未暴露 |
| `--dump-file` | 缺口（P3） | — | 拖库数据落盘路径不可单独指定（当前固定 dump.<ext>） |
| `--dump-format` | 同名同义 | `--dump-format` |  |
| `--encoding` | 缺口（P2） | — | 页面编码显式声明（GBK/Shift-JIS 目标）未暴露；比对与提取当前按 UTF-8/自动 |
| `--eta` | 明确不做 | — | 进度行已给目标/点位/耗时；独立 ETA 显示无新信息 |
| `--flush-session` | 同名同义 | `--flush-session` |  |
| `--forms` | 同名同义 | `--forms` |  |
| `--fresh-queries` | 同名同义 | `--fresh-queries` |  |
| `--gpage` | 明确不做 | — | Google dork 属目标发现，AGENTS §0 红线（只扫用户明确给出的目标） |
| `--har` | 默认即覆盖 | — | -r/-m 按内容自动识别 HAR（Burp XML / HAR / Postman / OpenAPI 同一入口），无同名旗标 |
| `--hex` | 同名同义 | `--hex` |  |
| `--output-dir` | 等价异构 | `--out` |  |
| `--parse-errors` | 同名同义 | `--parse-errors` |  |
| `--preprocess` | 等价异构 | `--request-script` |  |
| `--postprocess` | 同名同义 | `--postprocess` |  |
| `--repair` | 明确不做 | — | REPAIR TABLE 改写目标库，与「授权只读扫描」定位冲突 |
| `--report-json` | 等价异构 | `--format` |  |
| `--save` | 等价异构 | `--save-config` |  |
| `--scope` | 同名同义 | `--scope` |  |
| `--skip-heuristics` | 部分覆盖 | `--smart` | 本仓启发式（prefilter）默认关、--smart 才开；sqlmap 默认开、本项关 —— 同一开关的另一默认值 |
| `--skip-waf` | 缺口（P3） | — | 跳过 WAF 识别阶段未暴露（已知有 WAF 且只想省请求时） |
| `--table-prefix` | 缺口（P3） | — | Oracle/DB2 表前缀枚举参数未暴露 |
| `--test-filter` | 同名同义 | `--test-filter` |  |
| `--test-skip` | 同名同义 | `--test-skip` |  |
| `--time-limit` | 等价异构 | `--timeout` |  |
| `--unsafe-naming` | 缺口（P3） | — | 拖库产物命名安全化开关未暴露（长尾） |
| `--web-root` | 缺口（P3） | — | 文件写用的 Web 根路径（写 webshell 落点）未暴露；当前要求绝对路径 --file-dest |

### Non-SQL（非 SQL 注入通道）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--graphql` | 等价异构 | `--no-sql` |  |
| `--ldap` | 缺口（P2） | — | LDAP 注入通道未实现（检测器 + payload 面；sqlmap 1.10 新增） |
| `--nosql` | 等价异构 | `--no-sql` |  |
| `--xpath` | 缺口（P2） | — | XPath 注入通道未实现（同上） |
| `--ssti` | 等价异构 | `--no-sql` |  |

### Miscellaneous（杂项）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `--alert` | 缺口（P2） | — | 命中即执行宿主命令（自动化联动/Slack 钩子）；需显式授权与命令白名单，不能静默执行 |
| `--beep` | 明确不做 | — | 无人值守/CI 场景下无意义（agent 驱动是主用法） |
| `--dependencies` | 明确不做 | — | 引擎有意零运行时依赖，无「缺依赖」这一类故障 |
| `--disable-coloring` | 明确不做 | — | 本仓 CLI 输出无 ANSI 着色，无开关可关 |
| `--disable-hashing` | 明确不做 | — | 本仓不做口令哈希破解（报告如实指向离线 hashcat） |
| `--gui` | 明确不做 | — | 交互形态不同：本仓为 Web GUI / 桌面壳 / MCP，不做 sqlmap 式 TUI |
| `--list-tampers` | 同名同义 | `--list-tampers` |  |
| `--no-logging` | 缺口（P3） | — | 关闭日志落盘开关未暴露（当前恒写 ledger） |
| `--no-truncate` | 缺口（P3） | — | 报告长字段不截断开关未暴露（长 payload/长响应取证用） |
| `--offline` | 明确不做 | — | 本仓会话是断点续跑缓存，不是「零请求离线数据源」，无对应语义 |
| `--purge` | 缺口（P3） | — | 本地产物/会话清理（与 --cleanup 相邻：这项针对本地侧）未实现 |
| `--results-file` | 明确不做 | — | sqlmap REST 内部形态；本仓以 scanId + 报告文件表达同一需求 |
| `--shell` | 明确不做 | — | 交互式 SQL 执行已由 --sql-shell 覆盖，不做 REPL 形态 |
| `--tmp-dir` | 明确不做 | — | 无本地临时目录概念（与 --tmp-path 同因） |
| `--tui` | 明确不做 | — | 不做 TUI（Web/桌面壳/MCP 已覆盖交互面） |
| `--unstable` | 缺口（P3） | — | 不稳定连接模式（弱网重试策略）未实现 |
| `--update` | 明确不做 | — | 经 npm/git 分发并受版本一致性门禁约束，不做自更新（供应链完整性） |
| `--wizard` | 明确不做 | — | 向导是交互式引导；agent/CI 用法需要的是显式旗标与 --advise 预检 |

### 短名专用（help 里无长名，仍是独立能力面）

| sqlmap | 状态 | 本方对应 | 说明（还差什么 / 为什么不做） |
|---|---|---|---|
| `-d` | 等价异构 | `--direct` |  |
| `-l` | 等价异构 | `--log-file` |  |
| `-m` | 等价异构 | `--batch` |  |
| `-r` | 等价异构 | `--request-file` |  |
| `-g` | 明确不做 | — | Google dork 属目标发现，AGENTS §0 红线 |
| `-c` | 部分覆盖 | `--config` | 档案格式为 JSON（键=长旗标名）；不支持 sqlmap 的 INI(`sqlmap.conf`) 语法 |
| `-o` | 等价异构 | `--predict-output` |  |
| `-p` | 等价异构 | `--test-param` |  |
| `-s` | 部分覆盖 | `--session-file` | 会话是 JSON 台账（断点续跑语义一致），不读写 sqlmap 的 SQLite 会话文件 |
| `-t` | 缺口（P2） | — | 原始 HTTP 流量全量落盘（复现与审计）未实现：当前只有结构化 ledger + 报告，无法回放原始报文 |
| `-v` | 缺口（P3） | — | 日志详细度无 CLI 开关（级别走环境变量/配置），与 sqlmap -v 0-6 的逐级详细度不对位 |
| `-z` | 明确不做 | — | sqlmap 助记符缩写语法；本仓要求显式长旗标（可读与可审计优先） |
| `-hh` | 明确不做 | — | 本仓 --help 即全量清单，不分基础/高级两段 |

## 四、怎么复验与怎么防它过期

```bash
node scripts/sqlmap-parity.mjs            # 校验（状态自洽 + 产物与磁盘逐字一致）
node scripts/sqlmap-parity.mjs --write    # 重新生成 JSON 与本页
node scripts/sqlmap-parity.mjs --selftest # 自证判据有牙（四个反例）
node scripts/sqlmap-parity.mjs --refresh  # 重跑本机 sqlmap -hh，报上游选项面漂移（只读）
cd server && node --test tests/sqlmapParity.guard.test.js
```

三条防过期机制（这是它与历史上那几份一次性分析文档的区别）：

1. **gap 与实现互斥**：某项一旦在本方 args.js 里有旗标，底账仍写 `缺口` ⇒ 门禁红（不许只朝乐观方向漂）；
2. **引用必须落地**：`同名同义`/`等价异构`/`部分覆盖` 引用的旗标必须真实存在于 args.js ⇒ 防「文档里有、代码里没有」；
3. **产物即判据**：本页与 JSON 由脚本逐字重算，手改即红；`--refresh` 每次跑都报上游新增/删除的选项面。

> 缺口总数 52（P1 1 / P2 19 / P3 32）；部分覆盖 10。
> 引用本页数字时，请连**分母与状态口径**一起引用（上表 §一）。
