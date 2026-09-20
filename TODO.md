# sqli-scanner 待办清单

> 生成于 2026-09-13 全面审计后。P0 四项已全部完成（见文末「已完成」），本清单按优先级维护后续优化空间。
> 原则：每项标注依赖前提与验证口径，避免「文件存在=能力存在」的误读。

---

## 2026-09-18 批次 · 定库与检出链路的回显污染（已修，留此防回归）

已修内容见 CHANGELOG「[Unreleased]」与 README「P1-F / P1-G」。这一批**没有新增任何能力**，
全部是把「已经在报『未检出』的地方其实根本没发对请求」挖掉：
r2 档黑盒 9/13 → 13/13，A3-like 从 time 变 union+boolean。

本批实测顺手暴露、**尚未处理**的四项（按性价比排序）：

### A. P1-D 的真实危害面比「20 处冲突」这句话更具体（H2 已修，余下待办见文末）
`node e2e/blackbox-lab/check-dbms-sig.mjs` 报 20 处 sig 冲突，其中**可执行**的那几条才是真风险
（冲突要成立，前提是「A 库的版本函数在 B 库上也能跑」）：
- `MySQL.sig = /^\d+\.\d+\.\d+(?!.*MariaDB).*$/` 会吞掉任何「裸三段版本号」回显 → 若别家库的版本串
  能从 MySQL 那条探针回显出来，就会被定成 MySQL（payload 族整体错配）。
  **但 2026-09-19 的真引擎实测把这条降级了**：MySQL/MariaDB/PG/TiDB/ClickHouse 五条探针各自带的 WRAP
  （`CAST(x AS CHAR)` 等）在 H2 / HSQLDB / Derby 三台上**全部报错、无标记回显**（18/18 echo=N），
  所以「MySQL 抢走别家裸版本号」在这三台上不可达。其余库（真 PG/CH/MSSQL）未测，不作断言。
  （H2 原本也被列进这条，实测**不成立**：H2 根本没有 `version()` 标量函数，见下方撤回。）
- `Sybase.sig = /(Adaptive Server|Sybase|ASE)/i` 的 `ASE` **没有词边界**，
  Oracle 的 banner「Rel**ease** 19.0.0.0.0」直接命中 —— 与 L46 那次 `Server: BaseHTTP` 含
  "ase" 误判 Sybase 是同一个坑（那次只修了 `FINGERPRINT` 头签名，DB_VERSION 与报错签名两处没同步）。

**2026-09-19 补（含一次撤回）：这条已从"理论冲突"进到实测，但我当时的归因是错的。**
先更正：我写过「H2 的 `version()` 返回 `2.2.224 (2023-09-17)` 命中 MySQL 的裸版本号 sig → 真 H2 被定成
MySQL」—— **这句是错的，实际测到的是定库失败（dbms=null），不是定成 MySQL。** A/B 数据（真 JDBC 内存库
H2 2.2.224，`{waf:false}` 才跑得通，见下）：
- 修复前（H2 在遍历末尾 + `func:'version()'`）：18 条探针**全部** `echo=N` → `dbms=null`。
  原因：H2 没有 `version()` 标量函数，而 MySQL 系 WRAP 用的是 `CAST(x AS CHAR)`，H2 直接报错 → 无标记回显。
  也就是说「MySQL 抢走 H2 版本串」这条路径在这台真 H2 上**根本不可达**，我把它当成了观测结果。
- 修复后（H2 前置 + `func:'H2VERSION()'`）：`verFp H2 echo=Y 取到值="2.2.224" sig命中=true` → `dbms=H2`。
- 反向确认（真 MySQL 8.0.28，blackbox-lab r2 三点）：`A1-numeric / A3-like / C2-blindtime` 全部
  `dbms=MySQL`、3/3 HIT、0 误报 —— 前置的 H2 条目不会抢 MySQL。

**已实施**（本批）：`server/src/engine/payloads/index.js` 的 `DB_VERSION.H2` 换成 exclusive 的
`H2VERSION()` 并排到 MySQL 之前（与 `extractionMaps.js:408` 早已用 `H2VERSION()` 对齐）；单测侧把
「假引擎能执行哪些探针表达式」显式建模（`boundary.echoTarget.test.js` 新增正/反两条 exclusive 守卫，
`fingerprint.mariadb.test.js` 的 mock 加 `supportedFuncs`）—— 不给这层，mock 等于「谁探测都回同一个
版本」，会把真实判据（跑不动 → 无回显）抹平，这正是刚才那次错误归因的来源。

- **验收口径（部分已达）**：真引擎 A/B ✅、真 MySQL 回归 ✅、相关单测 58/58 ✅。仍欠两条：
  1. `check-dbms-sig.mjs` 的 20 处冲突是 **sig 层**口径、不等于运行时误判数（脚本头已写明口径边界）；
     要报「可执行冲突」得补跨库可执行性矩阵，尚未做。
  2. 本批新暴露：`e2e/multi-engine-lab` **默认开着 CRS**，UNION 哨兵探针整条被 403 →
     版本回显定库通道在该靶场上从未执行（这就是为什么它"没现形"）。要么给 `verify.mjs` 加一档
     `waf:false`，要么在报告里写清"本靶场只覆盖 boolean 通道"。
  3. 同批实测：HSQLDB / Derby 两台在**关掉 WAF** 后仍 `18/18 echo=N → dbms=null`，即这两台的版本回显
     定库整条失效（各自的 WRAP/伪表问题，与 H2 无关）。README 的分层措辞（「3 种部分通道验证」）不用改，
     但"这三家的**定库**都可用"不成立：三台里只有 H2 现在能被版本回显定库。

### B. `binaryProbe` 的 `capped` 在长度链路上被忽略（**已修，2026-09-20**）
`docs/统一探测判据-设计.md` 3.3 明确要求「拿到 capped=true 不得当正常结果用」；
`engine/blindExtractor.js` `_binarySearch` 原先只 `return r.n + 1`，把 `r.capped` 丢了。

**修法（比原计划的「直接判失败」多一层，因为一刀切会打死正常长值 —— 实测挂了 2 个用例）**：
「顶到上界」有两种成因，探测层面无法区分，必须分层裁决：

| 位置 | 顶到上界的含义 | 处置 |
|---|---|---|
| 主段（hi=255） | 可能只是真实长度 ≥256（合法信号） | 只打 `ctx.blindLenCapped` 标记，交 `_extendLength` 预检 `>255` 裁决 |
| 延伸段（hi=maxLen，用户**显式**配了 `blindMaxLen`） | 用户已授权「最多提这么长」 | 按 maxLen **截断**提取（旧行为不变） |
| 延伸段（hi=maxLen=默认护栏 4096） | 用户没授权过这么长 → 判据失效 | **判失败**（-1 → 该字段提取返回 null） |

失败原因经 `ctx.blindLenCapped` 上浮，由 `scan/extract.js` 写进 `report.summary.constraints`
（「盲注长度探测失败：二分顶到上界 N 且响应差异不可区分」）—— 让「没提取到」不再被读成「目标没数据」。

**验证**：新增 `server/tests/blindLenCapped.test.js`（3 条）。缺陷注入（撤销延伸段终审）→
**只有第 1 条红**，且实际值是一整串 4096 个垃圾字符（直观展示伤害），另两条（显式
blindMaxLen 截断 / 真长值 300 字节延伸）仍绿 —— 三条各测一面，不是一红红一片。

### C. `--test-path` 的闭合候选在 404 段上是噪声（✅ 已修 2026-09-20）
实测 `/api/sleep` 开 `--test-path` 时，path 点拿到 boundary `%"` —— 13 个候选的响应全是同一张
404 页（Express 回显 URL），剔除回显后仍偶有同形判定。path 点本身没洞无所谓，但它会**触发**
整轮指纹/列数探测（每次 ~40 请求）。修法方向：path 点基线为 4xx 时不投放闭合探测（或指纹
提前 bail），既省请求也少一份误判来源。

**✅ 已按此方向修（`Detector.probeBoundary` 基线请求后早退）**：
- **语义论证**：闭合前缀回答的是「怎么跳出 SQL 字符串字面量」，前提是该路径**真的执行了 SQL**。
  路径不存在时后端没路由到查询代码，候选拿到的只是同一张错误页 → 噪声 boundary
  → 触发整轮指纹/列数探测打在一条不存在的路径上。**真存在注入的路径不会是 4xx**
  （要么 200 要么 5xx 报错），故早退不影响任何真实检出。
- **口径**：`kind==='path'` 且 `400 ≤ status < 500`，但**排除 401/403/429** ——
  鉴权/封禁是「路径存在但本次不带凭据」，限流是「稍后可能通」，都不等于路径不存在。
- **留痕**：写入 `point.boundarySkipReason`，报告/排障可解释「这里为什么没探测」。
- **验证**（`tests/boundary.echoTarget.test.js` 新增 4 条，全绿 9/9）：
  · 正向：path+404 → **只发 1 次基线请求**（旧行为 1+13），boundary 回退空串 + 留原因；
  · 反向：path+200 → 照常投放（不误伤真实路径点）；
  · 边界：401/403/429 不跳过；非 path 点（url/body/cookie/header）404 也不走此早退。
- **缺陷注入验证**：临时把早退条件改成恒 false → **只有正向那条变红**（8 pass / 1 fail），
  其余 8 条仍绿 → 证明测试真的钉住了该行为，而非陪跑。

### D. 靶场侧缺陷（✅ 已扫完并修复 2026-09-20）
`e2e/blackbox-lab/lab-app.mjs` 的 `/api/profile` 对 Cookie 值做 `decodeURIComponent`，收到
`%'` 这类非法转义就在 **async handler** 里抛 URIError → Express 4 不捕获 async 异常 →
该请求**永不应答**，把 D3 的整个测段拖成分钟级停顿（真值标定用 `uid=1` 碰不到，所以一直没暴露）。
已加 try/catch 并注明「改的是靶场不应无端挂连接，SQL 拼接形态一字未改」。

**✅ 2026-09-20 全仓扫完 —— 原「待办」的 4 个靶场经实测全部无需修改，但扫出另一处真中招**：

- 原点名 4 靶场实测**都已有防护**：`redteam-lab:190`、`pentest-lab:72` 都是
  `try { decodeURIComponent } catch { 保持原样 }`；`real-mysql-lab` 零 decode；
  `multi-engine-lab` 仅 `JSON.parse` 且已包 try。**「同一形态」这个预判不成立。**
- **真中招的是 `e2e/redteam-lab/lab-app.mjs` 的 `/shop/semi`（D15 靶点）**：
  4 处 `decodeURIComponent` **裸调**（同文件 187 行已备好 `decodeSafe` 却没接上——写了工具没接线）。
- **实测表现比原描述更微妙**：不是"永不应答"，而是被外层 `run()` 的 try 兜成
  **500 + `SQL_ERROR: URIError` 回显**。危害在于——D15 真值是 `tech=union`（测 `--param-del`
  切分），返回的却是「数据库报错」，**靶场亲手给扫描器的 error 通道喂了假信号**。
- **修法**：改用 `decodeSafe`（与 187-191 行既有容错语义一致；真实站点只认分号时也不会
  对已切好的片段二次 decode，失败即用原值）。
- **验证（实测报错文本变化）**：
  | payload | 修复前 | 修复后 |
  |---|---|---|
  | `id=1%` | `URIError` | `MySQL syntax ... near ''`（真 SQL 信号） |
  | `id=1%zz` | `URIError` | `Unknown column 'zz' in 'where clause'` |
  `URIError` 彻底消失，全部转为真实 MySQL 报错。
- **顺带实测的有效能力**：扫描器对不可达目标（155 次请求全无响应）正确给出
  `validity.status="unreachable"` + `reliable:false` + 具体 advice，**拒绝输出阴性结论** ——
  这是 `scanValidityGuard` 的真靶场级正面验证。

### E. 本轮**未跑**的门禁（诚实记录）
`npm run acceptance`（11 套件）没有整跑：`e2e/acceptance.mjs` 与多份 `results/*` 是另一批次
未提交的在制品，跑一次就会覆盖它们的产物、把两批改动混进同一份报告。
本轮实跑到的门禁：服务端全量单测（1885 用例 0 fail）+ 前端 315/315 + `tsc` 0 错 + eslint
0 error + blackbox-lab 两轮 + redteam-lab R1/R2。合入前请补跑 acceptance 一次。

**（2026-09-19 更新）这条已经不再成立**：那批在制品提交后（`381afdb`）acceptance 在本机连跑 3 次
—— 2 次 `11 PASS / 0 FAIL`，1 次 `10 PASS / 1 FAIL`（失败的是「服务端单测」里的 1 条用例，
单独连跑 4 次不复现，属偶发；失败现场当时没留下 → 已改为失败即落盘 `e2e/results/last-failure-<id>.log`）。
同一天还按 ci.yml 的 job 顺序做了本机等价全量跑（`npm run ci:local`，17 段：15 PASS / 1 FAIL / 0 SKIP，
唯一稳定红的是 G 条那个 concurrent-isolation）。

### F. README 的 WAF 绕过口径已经过期（**已重定为 8/8 并定位到规则号**，2026-09-19）
README 原写 2026-09-10 复测的 **tamper off 2/5 → on 10/5 技术位**、自动路径 **11 技术位**。
本批整跑 acceptance 一次 + 单独复跑两套件一次，两次都是 **on=8、auto=8**。量纲也修了：
`N/M` 那个分数把「技术位合计」和「场景数」混在一起（README 于是抄成「10/5」），现打印
「技术位合计 8（5 个注入场景，每场景可有多个技术位）」，`acceptance.mjs` 的解析同步跟上；
`waf-auto-check.mjs` 里写死的「人工 dash2hash 基线 = 10」改成从 `waf-real-report.json` 现读
（写死的对照数不会随被测代码变化，等于长期说谎）。丢的两格都在 `num` 与 `blind` 的 union。

**归因（逐条手工发探针：真 MySQL 8.0.28 × CRS，规则号可复核）**：

| 探针 | 结果 | 规则 |
|---|---|---|
| `1 ORDER BY n-- -` | 403 | 942460（4 连非词字符） |
| `1 UNION SELECT NULL,…`（尾 `-- -` / `-- ` / `#` 三形态都试） | **全部 403** | **942190**（PL1，`union\s*select` 短语）|
| `1 UNION SELECT 'SQLISCANNER…'` | 403 | 942200（单引号字面量） |
| `alice' UNION SELECT NULL,…#`（字符串上下文） | **200** | 未命中 |

> **[修正 2026-09-20]** 第 2 行原记「942361」，**归因有误**。四版探针（见 I 条）逐格复核后确认：
> 拦住数值点 union 的是 **942190（PL1）**，不是 942361（PL2）。942361 是 CRS 里更**松**的兄弟规则，
> 判据是「起始形状」，而 942190 判的是「union↔select 相邻」，后者更早生效、覆盖面更大。
> 这个修正影响到当时的猜测链（见下），但**不影响本条结论**（两格确实丢在 WAF 层）。

即：**同一条 UNION 探针，数值上下文被 942190 拦、字符串上下文放行**；而 `dash2hash` 只规整尾部注释符，
对 942190 无效。所以这两格不是"判据判错"，是**请求在 WAF 层就到不了数据库**。
本批改动已排除（把动过的 4 个引擎文件回退到 `ebc660a^` 重跑，结果逐字相同）。
至于 09-10 那次为什么算进过 10：`e2e/waf-real/results/` 不入库、旧报告没留档，**已无从核对**；
原有一条猜测（链含 `space2comment`，`/**/` 拆开相邻性）**已被 I 条实测推翻** ——
942190 带 `t:removeCommentsChar`，注释在匹配前就被删掉，`/**/` 拆相邻性对它**无效**。
所以"当时算进过 10"至今**仍无可靠解释**，如实留白，不再编因果。本条按「合理代价 + 口径下修」结案，
不做"退化了 2 位"的断言。正面把这两格拿回来另立 I 条 —— **I 条也已结案为「PL1 下拿不回，且原假设错误」**。

顺带记录一个门禁自身的假红（已修）：`acceptance.mjs` 的「服务端单测」套件按 TAP 汇总行取数，
但 node:test 的 reporter 选型随 TTY 探测漂移 → 本机子进程走管道时输出 spec 格式 →
四个数全 null → 报成「FAIL　null 条失败」。现钉 `--test-reporter=tap`，并在取不到汇总行时
明确报「门禁取数口径不符，非单测失败」。同一坑此前已在 `scripts/facts-sync.mjs` 咬过一次
（还咬过 3d63b7 那轮回流解析器），**第三处应该去 `run()` 里统一收口**，别再一处一处打补丁。

### G. concurrent-isolation 是**确定性红**（**已修，2026-09-20**）
`e2e/run-all.mjs` 曾稳定挂在这一套：现象是 PG 那条扫描正常（`dbms=PostgreSQL`、union 命中），
两条 MySQL 扫描**什么都测不到**（`dbms=null techs=[]`）—— 不是判据判错，是请求层面就没拿到可用信号。

1. **`e2e/concurrent-isolation/e2e.mjs` 建 MySQL 池写死 `port: 3306`**（还有 user/password），
   只读了 `MYSQL_PASSWORD` 一个变量；而 `run-all` 按 `deps:['sandbox']` 把它交给
   `run-with-sandbox.py`（沙箱在 3308，并注入 `MYSQL_HOST/PORT/USER/PASSWORD/DATABASE`）。
   「声明走沙箱」与「实际连宿主」自相矛盾。
   实测复现沙箱路径：写死 3306 时沙箱注入的**空口令**连不上宿主 → 退出码 2；改成读 `MYSQL_*`
   契约后沙箱下 PASS（3308，3/3 union 命中）。另加了环境自检（连不上 / 库内 0 张表 → 显式
   BLOCKED 退出码 2），避免再把环境问题判成「并发串扰」归给被测代码。
2. **CI 里永远抓不到**（`deps` 含 `pg`，CI 无 PostgreSQL）：原先缺依赖的靶场被 `run-all`
   直接过滤掉，**连 SKIP 都不显示** → 「通过 6 / 失败 0」看起来是全绿。现汇总新增
   「未跑（缺依赖，本轮零断言）」单列，计数行加 `未跑 N`。
   注：给 CI 补 PG service container 仍未做（那是另一条路，二选一即可，现已不靠它保证诚实）。

**顺带修**：`run-all.mjs --only` 只认空格形式 `--only 名字`，写 `--only=名字` 时
`indexOf('--only')` 返回 -1 → **静默退化成跑全部依赖齐全的靶场**（实测：想跑 1 个 0.5s 套件，
结果跑了 21 个含 77s 红队）。现两种写法都认，并打印「定向模式：只跑 X」。

### H. udf-lab step6 的归因文案会把人带偏（✅ 已修 2026-09-20）
`sys_eval('cmd /c echo <ASCII marker>')` 偶发捕获为空时，step6 的 note 固定写
「典型：Windows 本地化 whoami 的 GBK 输出」。marker 是纯 ASCII，这句话把人往编码方向带，
而实际形态是**输出捕获为空**。改成按实测分支给原因（空捕获与"不可字符化"是两回事）。

**✅ 已按此修（`Exploiter.myOsShell` 路径 2.5）**：
- echo 探针（纯 ASCII 数字 marker）从**单次**改为**最多两次**，用重试结果把三种成因分开：
  | 观测 | 归因 | 关键点 |
  |---|---|---|
  | echo 命中 + 原命令 null | 真·输出不可字符化 | note 明确写「该命令**自身**的输出编码，非探测通道问题」 |
  | echo 首空、重试命中 | 判据抖动（偶发空捕获） | **不写任何编码归因**（ASCII marker 不存在字符化失败） |
  | echo 两次都空 | 探测通道不可靠 | 新增 `probeInconclusive: true`；note 点明 marker 是 ASCII、不是编码问题；**不写 udfInstall**（两次空 ≠ 未注册，不把人引向重投 DLL） |
- **验证**（`tests/exploiter.udfChain.test.js` 新增 3 条，9/9 绿）：
  · 正向（保留原语义）：echo 命中 + 原命令 null → `suggestHexEcho: true`，无 `probeInconclusive`；
  · 抖动：断言 echo 探针**确实发了 2 次**，且 note 不含 `GBK|本地化`；
  · 通道不通：`probeInconclusive: true`，note 含 `ASCII`、不含 `GBK|本地化`、不含 `udfInstall`。
- **缺陷注入验证**：撤掉重试段 → **第 8、9 条变红，第 7 条（保留原语义）仍绿**（7 pass / 2 fail）
  → 证明新测试钉的是新增行为，且没有破坏原归因路径。
- **实测背景**：`e2e/udf-lab/results/udf-takeover.json` 最近一次 `osShell.ok=true`（值 `osshell_ok`）
  未触发该分支，但同次 `whoami` 实测返回 `Admin（无密码）` —— **非 ASCII 用户名**，
  说明这条归因分支在真机上确实可达。

### I. 严格档 CRS 下数值点的 union 怎么拿回来（**已实测结案，两处归因被推翻**）
F 条的探针表给出：**换分隔符这条路对 942361 完全无效**（`/**/`、`%0a`、`%09`、双空格、`UNION ALL`
八种形态全部 403，且这些形态不套 WAF 时 MySQL 全部正常执行）。原因是该规则的判据是
`^[\W\d]+\s*?(?:alter|union)\b` —— 打的是**参数值起始形状**，不是 UNION/SELECT 相邻性。
数值点 `id=1…` 必然以数字开头 → 命中；`alice'…` 以字母开头 → 不命中。

**✅ 第 2 条「换档测量」已完成（实测发现早于本条记录）**：
`CRS_PL` 环境变量机制已落在 `crs-engine.js:287-293`（`DEFAULT_PL` 读环境变量，默认 3），
`e2e/waf-real/waf-bits-baseline.json` 已按 PL 分档锁基线，并写明 `_why_per_pl`：
「不带档位的绕过率没有可比性 —— CRS 官方默认部署是 PL1」。README 已同时给出两档：

| 档位 | tamper off | tamper on | 自动选链 |
|---|---|---|---|
| **PL1（CRS 默认部署档）** | 8 | 8 | 8 |
| **PL3（全规则最严档）** | 0 | 0 | 0 |

门禁默认跑 **PL1**（`WAF_GATE_PL=3 npm run acceptance` 可切档）。
→ 原担忧「README 只有最严档会低估自己在真实默认部署下的表现」**已消除**。

**✅ 第 1 条已实测结案（2026-09-20）—— 结论：原假设方向错误，这两格在 PL1 下拿不回来。**

写了 4 版单点探针（`probe-union-shape.mjs` / `probe-union-shape2.mjs` / `probe-union-ws.mjs` /
`probe-nounion.mjs`，纯发请求 + 直连真库，各几秒出结果），共扫 100+ 形态，逐格记录
「CRS 拦不拦 / MySQL 认不认 / 标记值能不能取回」三个独立事实。**归零，且推翻了本条的两处归因：**

| # | 原假设 | 实测结论 |
|---|---|---|
| 1 | 是 **942361**（`^[\W\d]+\s*?(?:alter\|union)\b`，PL2）拦住数值点的 union | ❌ **错**。拦住的是 **942190（PL1）** —— 它含 `union\b[\s\x0b]*(?:all\|(?:distin\|sele)ct)\b`。942361 是 CRS 里**更松**的兄弟规则，压根不是那道闸。原「起始形状」归因是把两兄弟混成一谈 |
| 2 | 改起始形状（`space2plus`/`1/*x*/UNION`…）能绕过 | ❌ **不成立**。942190 不看起始，只看 union↔select 相邻性。且它带 **`t:removeCommentsChar`** —— 所有注释在匹配前就被删掉，`/**/` 类填充全线失效（30 种填充形态实测 0 通过，唯一没被 942190 拦的 `UNION/*!*/SELECT` 落到 942500） |

**另外三条已排空的路径**（都不是"没想到"，是真测过）：
- **非 ASCII 空白**（NBSP / U+2000–200A / 表意空格 / BOM 等 18 种）：MySQL **全部不认作空白**（语法错），
  物理上不通。→ 这条路是死的，不是我们没用对。
- **改关键字大小写 / 换 `ALL`/`DISTINCT`**：942190 带 `(?i:)`，且 `all` 恰在它第二支里，全拦。
- **绕开 union 字面量**（boolean / subquery / error / time / stacked 五类 17 种）：
  被 **942130 / 942440 / 942120 / 942131 / 942151 / 942160 / 942140 / 942350** 逐一精准拦住，同样 0 通过。

**修正后的定性**：不是"我们的 tamper 链不够好"，而是 **CRS 在 PL1 档对 SQLi 是全覆盖的** ——
每一格都有对口规则守着。这条按「**原假设错误 + 口径下修**」结案，不再作为待办挂账。
`num`/`blind` 两格在 PL1 下丢掉 union 是**正确行为**（真实反映 WAF 强度），不是缺陷。

**如果将来还想再试**（诚实留档，非承诺）：唯一没被穷尽的方向是**真 ModSecurity(PCRE) 与 JS 正则的
语义差异** —— 本次全部用 JS 模拟执行器，JS 的 `\s` 比 PCRE 宽（含 `\v`/NBSP 等），所以「JS 侧拦」
不能直接判死 PCRE 侧。要定论得上真引擎（见 P1 第 1 条，本机无 docker）。

四个探针脚本留在 `e2e/waf-real/`，可复跑复核：`node e2e/waf-real/probe-union-shape.mjs`（余三同）。

---

## P0′ · 门禁可信度（2026-09-20 新增）

### J. 「CI 引用的文件是否存在」应固化成门禁（✅ 已完成 2026-09-20）

**已修的真 bug**（`8144fc7`）：`ci.yml` 里两个 job 引用**不存在**的文件 ——
`e2e/tamper-matrix/run.js`（真入口 `tamper-test.mjs`）与 `e2e/waf-lab/run.js`
（真入口 `compare-real.e2e.mjs`）。两者都带 `continue-on-error: true`，
于是 `node <不存在的文件>` 每次 Cannot find module 却**从不拦人** ——
**这两个 job 从未验证过任何东西**，是彻底的「空转门禁」。

**防护已落地**：新增 `scripts/ref-integrity.mjs`，校验三处引用源：
`.github/workflows/*.yml` 的 `run:` 步骤（含多行块 + `cd X &&` 基准目录偏移）、
两个 `package.json` 的 `scripts`（含 `npm run <name>` 交叉引用）、
`e2e/run-all.mjs` 的 `entry` 字段。当前校验 **82 处，全部存在**。
接入 `npm run refs:check` / `check:all` / `ci-local` 的 lint 组 / `ci.yml` 的 lint job。

**缺陷注入复验（4 例）**：① ci.yml 路径改回不存在的 → 报第 313 行；
② run-all entry 改坏 → 报出条目；③ package.json 引用不存在的 script → 报「脚本引用」；
④ **自指注入**（把 ref-integrity 自己在 ci.yml 里的路径写错）→ 被抓到，证明覆盖了自己。

**修门禁自身时的两个教训**（值得记住）：
- 初版不认 `cd server && node index.js` → 把 3 个**相对子目录**的正确路径误报成缺失。
  **门禁报假红比没有门禁更糟**（会训练人忽略红灯），故校验器自身也要测。
- 缺陷注入② 首次"成功"实为**替换未命中而静默通过** —— 注入脚本必须断言替换真的生效。
  这与 J 条本身的病根同源：**静默失败最危险**。

### K. `tamper-waf-matrix` job 红了没人知道（设计取舍，待决）

该 job 是 `schedule`/`workflow_dispatch` 专属的实验矩阵，`continue-on-error: true` 是
**有意设计**（不阻塞日常流水线），本次**未动**。代价是它失败时没有任何显式信号 ——
J 条那两个 bug 就是靠这个特性藏了不知多久。可选做法：job 末尾加一步读各 step 的
outcome，失败则打 `::warning::` 或开 issue。属设计取舍，需先定「要告警还是要安静」。

### L. 「白名单有、引擎收不到」的第三段断口：CLI↔REST 键集不等（✅ 已修 2026-09-20）

J/K 都在讲 CI 的静默失败，这条是同一病根换了个器官：**扫描配置**。

`sanitizeStart` 的返回 `config` 只由白名单键构成，未知键原来只留一行 `logger.debug`
（默认 info 级等于没有）。于是调用方传 `testPath:true` 会拿到 **200 + 正常 scanId +
一句「未检出」**——请求成功了、开关根本没进引擎。这不是崩溃型 bug，是**静默假阴性**，
而假阴性对扫描器是最贵的一类错。

为什么既有两支守卫都没抱住：`configWhitelist.guard.test` 的正向真值来源是
**defaults.js 顶层键**，而这批键**根本不在 defaults.js 里**（只由 CLI 写入）。
`configWhitelist.passthrough.test` 只遍历 KNOWN_CFG_KEYS，也就永远看不到它们。
注释里已经留着 6 处「此前不在白名单被静默丢弃」——每次都是人肉发现一个补一个。

**判据改成两端交叉**（`configReachability.guard.test.js`，可跑，不靠人眼看 grep）：
CLI 侧 `config.X =` ∧ 引擎侧 `config.X` / `ctx.config?.X` − KNOWN_CFG_KEYS。
第一轮抱出 **9 个**：`testPath` `testHeaders` `noCast` `flushSession` `hex`
`unionFrom` `dumpWhere` `unionCols` `paramDel`。

> 其中 `hex` 是我自己 triage 时丢的：`hex` 这个词在 `server/src` 有上百处无关命中，
> 我按噪声跳过了。**守卫测试第一次跑就把它指出来**。教训写进文件头：判据要能跑。
> 反向 also 有价值——我最初给 `unionFrom` 写了句"大概由别处覆盖"的豁免，
> 实测它被 blindExtractor/DBFingerprinter/Extractor/injection **四处**读取，豁免已撤。

透传时顺手补的两处真校验（不是顺手重构，是这两类值会坏事）：
- `unionCols` 引擎按 `Number()` 当固定列数用 → 收敛成 1..200 整数（否则 `abc`→NaN 进二分）；
- `paramDel` 直接参与请求 URL 的 split/join → 只收 `; , | ^ ~` 单字符。
  这里取**窄集合**：宽集合写错是静默改请求形状，窄集合写错只是误拒且带 warn。
- `hex`/`flushSession` 必须真布尔——引擎按 `config.hex === true` 判定，
  通用标量透传会放过 `1`/`"true"`，那又变回「收了不生效」，同一个 bug 形状换个触发条件。
- `dumpWhere` 拒分号：它是拼进提取 SQL 的原始片段，分号是把「一个条件」变成
  「第二条语句」的那一步，而这个键没有任何合法场景需要分号。

顺手查实的一个**新形状**（已被新守卫的"BACKFILL ⊆ KNOWN"那条钉住）：
`BACKFILL_SCALAR_KEYS` 的透传循环**不看 KNOWN_CFG_KEYS**，所以白名单对这批键其实只管
告警不管放行——把 `testPath` 从 KNOWN 里删掉，它照样能透传到引擎。缺陷注入实测确认了这点。

**剩余待办（本条只修了 REST 可达性，没修 UI 可达性）**
1. 这 9 个键在 Web 面板 / Tauri 桌面版仍然无处可设：前端只发 `SCAN_CONFIG_KEYS`
   推导出来的 16 个键。**桌面版用户拿到的能力面小于 CLI**，与"同一引擎"的承诺不符。
2. `--random-agent` 在 CLI 侧同时写 `config.wafEvasion.randomUA`（活）和顶层
   `config.randomUA`（`server/src` 内 0 个读取点，空转冗余）。已在守卫豁免清单注明，
   但该清的是删掉那次空转写入。
3. ~~CLI `--body` 的 JSON 会摊平成顶层 `bodyParams`，嵌套叶子（`user.id`、`items.0.name`）
   只有 REST 的 `jsonBody` 路径能发现 → **CLI 用户在嵌套 JSON 目标上恒漏注入点**。~~
   **已修 2026-09-20**，见 §N。REST 侧同坑（`bodyParams` 里塞对象）也已补提示。

### M. 随机化电池的 ORDER BY 形态：探针选错让一整类恒被剔出分母（✅ 已修 2026-09-20）

`results/battery.json` 里 `c00/c20/c34-orderby` 三条长期是 `status:"unobservable"`。
看起来是"自证机制正常工作，剔掉了按构造不可观测的案例"，实际是**我自己把分母做空的**：
orderby 形态 `need:''`，于是复用了一对布尔探针 ` AND 1=1-- -` / ` AND 1=2-- -`，
而 `ORDER BY id AND 1=1` 与 `ORDER BY id AND 1=2` 在这张表上分别退化成
`ORDER BY id` 和 `ORDER BY 0`（常量，且与 id 物理序同序）；取 name/price 时字符串转数值恒 0，
两探针更是完全同序。**没有哪个检测器能看见这种案例**，而"看不见就剔掉"让它变成了沉默的
覆盖率漏洞：电池宣称 6 种形态，实际恒测 5 种，n 只有 17 时少一整类会明显抬高召回。

换成列索引有效性对 `, 1` / `, 9999`（后者报 `Unknown column '9999' in 'order clause'`，
正是 sqlmap `--order-by` 的信号）。**同 seed=20260919、同 cases=40 严格对照**：

| | 修复前 | 修复后 |
|---|---|---|
| 召回 | 17/17（3 条剔除） | **20/20（0 条剔除）** |
| orderby | 3/3 不可观测 | 3/3 以 `[error,boolean]` 真检出 |
| Wilson 95%CI 下界 | 81.57% | 83.9% |

分母补全、下界反而更高——是**更强的数字而不是更大的数字**。
可复用的判断：**"不可观测"的剔除清单必须按形态看分布**。三条全落在同一个 shape
就不是随机退化，而是那一类的探针选错了；只看"剔除了 3 条（共 20）"是看不出信号的。

### N. CLI 的嵌套 JSON body 摊平成不可注入的畸形值（✅ 已修 2026-09-20）

§L 第 3 条，也是这批里唯一**直接少测注入点**的一条。

`--body` 在 `help.js:25` 写的是「POST body（JSON 对象字符串）」，但 `runSingleScan`
一律把它摊进 `bodyParams`，而 `TargetParser` 对每个 body 值做 `String(v)`。实测两端：

```
--body '{"user":{"id":1,"name":"alice"},"tags":["a","b"],"plain":"x"}'
  CLI（bodyParams）   →  user="[object Object]"   tags="a,b"   plain="x"
  REST（jsonBody）    →  user.id="1"  user.name="alice"  tags.0="a"  tags.1="b"  plain="x"
```

前两个值**结构上不可能注入**——没有任何 payload 能让 `[object Object]` 变成合法 SQL。
所以同一份抓包，CLI 用户看到的是"这个 body 只有 3 个参数、都没洞"，REST 用户看到的是
5 个真叶子点。断的不是引擎（`_discoverJsonLeaves` 早写了），是 CLI 的接线。

修法保守：**只有 body 真含嵌套时才切 jsonBody**，扁平 body 继续走 bodyParams(urlencoded)。
否则会把"目标是表单接口、但顺手用 JSON 语法写了个扁平 body"的既有扫描全改成
application/json —— 那是回归不是修复。判定抽成 `cli/config.js` 的 `resolveBodyChannel`
（一处定义，`-r` 导入抓包那条路也共用）。

REST 侧同一个坑（`clampParams:696` 的 `String(v)`）选择**只加 warn 不改行为**：
自动把 bodyParams 里的对象路由到 jsonBody 会让两个字段的语义纠缠不清，
而"我传的东西其实没被测"这件事必须可见——这和本批把未知键从 debug 提到 warn 同源。

**验证**：`server/tests/cli.jsonBody.test.js` 6 条。主用例不测纯函数，而是走
`parseArgs(argv)` → `runSingleScan` → 捕获真正递给 `ScanManager.start()` 的对象 → 再接
TargetParser 看点位（只测 `resolveBodyChannel` 挡不住"忘了把 jsonBody 放进 input"）。
缺陷注入复验：从 input 里摘掉 `jsonBody` → 第 1、2 条同时红。
另用一次性靶场（gitignore 的 `e2e/diag/` 下，跑完已删）拿**真 CLI 二进制**打嵌套 JSON
目标，端到端跑出 `dbms=MySQL` + `param=user.id` 的 union/error 两条检出、共 206 请求
无拦截——这条链路是真通了，不是只有测试绿。

### O. `-r` 导入 multipart 抓包：整份 body 塌成一个垃圾键（✅ 已止血 2026-09-20，剩两条）

`-r`（Burp/curl 导入）是实战里喂目标最主要的方式，而这条路上**解析器是对的、接线是坏的**：
`parseRequestFile` 正确抽出 `{username, caption, avatar}`（`requestFileParser.multipart.test.js`
一直是绿的），但 `applyRequestFile` 丢开这些字段、把**原始 body** 交给
`bodyToJsonString` 的 urlencoded 启发式。multipart 里没有 `&`、只有 `name="…"` 里的 `=`，
于是整份 body 塌成**一个**键，键名是

```
--<boundary>\r\nContent-Disposition: form-data; name
```

值为余下全部内容；同时 `Content-Type: multipart/form-data; boundary=…` 被原样保留。
发出去的是"声明 multipart 却带一坨 urlencoded 垃圾"，目标必然解析不到参数 →
**扫描正常跑完、0 检出、零告警**。

修法：给解析器加 `bodyFields`（只装来自 body 的字段，与混了 query 的 `params` 分开），
multipart 时用它构造 body，并**删掉那个已经对不上的 Content-Type**，让引擎按 urlencoded
重发同一批字段名与值。这是"降级但说实话"：很多框架两种编码都吃；不吃的那批由 warn 明确
告知"未检出 ≠ 没有洞"，而不是让人以为目标干净。

**为什么既有测试全绿却没拦住**（这条最值得留）：
`requestFileParser.multipart.test.js` 测的是被调函数，而断点在调用链的下一环。
**只测被调函数、不测调用链**，就会出现"测试全绿而入口是坏的"。新加的
`requestFile.importWiring.test.js` 一律从 `applyRequestFile` 进、从引擎收到的注入点出；
缺陷注入复验（把 multipart 判定短路）→ 第 1、2 条同时红。

**还剩两条（本批未做，按需排）**
1. **引擎不支持发送 multipart**（`injection.js`/`httpClient` 里 0 处 FormData/boundary，
   已核实）。真要覆盖"只吃 multipart 的目标"，得在 body 构造处加一条 multipart 序列化分支
   （含 boundary 生成与文件字段回发）。**风险点要认清**：`buildInjectionRequest` 是全项目
   最吃重的函数，五种技术位每条请求都过它，而当前 multipart 的 e2e 覆盖为 0 ——
   动手前应先补一个 multipart 靶场进 `e2e/`，否则改完没有任何东西能证明没改坏别的。
2. **前端 `src/shared/requestParser.ts` 完全没有 multipart 分支**（0 命中），
   也就是说在 UI 里粘贴 multipart 抓包，连"字段名"这一步都拿不到，比 CLI 修前更空。
   与 §L 第 1 条同源：CLI 与 UI 是两套解析实现，口径会各自漂移。

### P. 版本回显定库在严格类型库上恒失效（✅ HSQLDB 已修，Derby 未修，2026-09-20）

先修的是**测量手段**：`e2e/multi-engine-lab/verify.mjs` 原来只记技术位、**不记定库结果**，
而且靶场默认挂 CRS（UNION 哨兵整条 403）→ 版本回显通道在这里从来没被执行过。
所以"HSQLDB/Derby 定不了库"这句 TODO 里的话，长期**没有任何可跑的验证手段**
（那次 H2 结论是靠临时手写探针跑的，跑完就没了）。补了两件事：
- 报告加 `定库=` 列与"与真实引擎不符则报误判"的告警；
- `NO_WAF=1` 一档，把"探针跑不动（真缺陷）"和"探针没被送达（靶场挡的）"分开——
  这两件事在报告里长得一模一样，都是 `dbms=null`。报告标题强制带口径，两档数字不可互换。

打开 NO_WAF 后，两个**互相独立**的缺陷显形：

**① 探针是死探针（func 与 sig 互不满足）**
`func` 是裸常量串 `'HSQLDB'`，而 09-16 为堵 DB2 误判把 `sig` 收紧成 `/HSQLDB\s+\d/`——
常量里没有数字，于是**回显了自己也永远匹配不上自己的 sig**。不是"探针跑不动"，
是判据写死了不可满足。换成 exclusive 探针（区分力来自只在自家库存在的 FROM 子句，
不是来自字面量，所以正面回应了 DB2 那次教训）：
- HSQLDB：`'HSQLDB ' || COUNT(*)` + `FROM INFORMATION_SCHEMA.SYSTEM_TABLES` → 真机回显 `"HSQLDB 103"`
  （同一条放 H2 报 `Table "system_tables" not found`、放 Derby 报 Schema 不存在）
- 为此给 `DB_VERSION` 加了可选字段 `from`（该条目的 FROM 优先于方言伪表与用户 `--union-from`，
  因为覆盖掉就没区分力了），其余 16 个库的探针构造一字不变。

**② 标记必须落在字符型回显列上**
`idx = echoCols[0]` 无条件取第一个回显列。真机实测同一条 UNION 探针：
放第 1 列（`name` VARCHAR）→ 正常回显；放第 0 列（`id` INTEGER）→
`incompatible data types in combination`，**整条 UNION 直接报错**、echo=N。
也就是严格类型库上这条通道恒失效，而失败症状与"探针跑不动"完全相同。
H2 之所以一直能过，是因为它以 `MODE=MySQL` 运行会隐式转类型——不是判据对了。
修法按代价收敛：只对**声明了 `from` 的候选**换列重试（其余 16 库请求数与形状零变化；
全候选换列会把本靶场 206 请求推到 ~240）。

**结果**：`定库=HSQLDB` ✅（H2 依旧 ✅）。安全对照仍零误报，检出场景仍 3/3。

**必须记下的两点不完美**
1. **一条技术位归因变窄了**：hsqldb 的 `str` 从 `[union,error,boolean]` 变成 `[union,boolean]`
   （3→2）。漏洞照样检出、场景计数不变，但报错通道不再被单独记账——原因是定库成功后
   引擎跳过了那条冗余的报错重探。这是"知道 dbms 之后是否还该报 error 通道"的**策略问题**，
   不是我这次改出来的崩溃，值得单独定口径。
2. **Derby 仍未识别**。探针本身经真机验证可执行（`'DERBY ' || CAST(COUNT(*) AS CHAR(10))`
   over `SYS.SYSTABLES` → `"DERBY 24"`，且 Derby 不做 INTEGER→VARCHAR 隐式转换、
   `CAST(.. AS VARCHAR)` 反而报错、只有 `CHAR(n)` 通——都实测踩过），但组合成引擎实发的
   查询后仍 echo=N。下一个待查方向：手测时发现 Derby 对 select 列表里的**裸 `NULL`**
   报 `Syntax error: Encountered "NULL"`，若成立则影响的不只定库、而是 Derby 上**所有**
   UNION 探针（列数二分/回显列定位/提取都拿 NULL 占位）。该现象与我手工构造的列数
   有关，尚未在引擎实发形状上复现，**不当结论用**。

**守卫升级**：`dbmsExtend6.test.js` 原来只查"func 里有没有标识串"+"sig 能否命中一个
手写的漂亮串"，所以①这类缺陷可以长期全绿。新增一条静态不变量：
**sig 要求 `\d` 时 func 必须有数字来源**（必要条件检查，不替代真机验证）。
缺陷注入复验：把 func 改回 `"'HSQLDB'"` → 该测试立刻红并点名到条目。

### Q. `facts:check` 在采集源过期时给假绿（✅ 已修 2026-09-20）

与 J/K 同源（**静默地没在做事**），但换了个器官：这次是**校验的基准自己脏了**。
`facts:check` 只比对 README ↔ `docs/_facts.json`，**从不校验 _facts.json 是不是当前代码采出来的**。

现场（本会话实测）：后继两批提交带来 +19 条用例（1985 → 2004），没人回填，
`_facts.json` 停在 1985、README 也写 1985 → 门禁报「一致」，而真实用例数早已是 **2004**
（`cd server && npm test` 实跑：2004 / pass 2003 / fail 0 / skip 1）。

**判据选型（三条都权衡过）**：

| 方案 | 结论 |
|---|---|
| 比 mtime 是否新于 `_facts.json` | ❌ CI 上 checkout 后所有文件同一时刻，必然全量误报；git 操作也改 mtime |
| 每次 check 真跑一遍测试对比 | ❌ 每次多花 4 分钟，门禁会被人绕开 |
| **测试文件内容指纹** | ✅ 采用。把「决定跑哪些测试、多少条」的文件集合做 sha256 |

实现：`docs/_facts.sources.json` 存 per-file 短哈希 + 总指纹（当前 276 个文件），
由 `--refresh` 与数字**同批**落盘 —— 分开写会制造「数字已新、指纹还旧」的中间态，
那比「两个都旧」更坏（判据会说 stale，而数字其实是对的）。`--check` 时重算比对。

**两个设计决策（都有缺陷注入复验）**：
1. **指纹缺失不静默通过** —— 文件不存在时报「没有依据」并 exit 1。（实测：删掉 sources.json
   → `[facts] 缺少 …：无法确认 _facts.json 是当前测试代码采出来的` + exit 1。）
   J 条那两个空转 job 正是被「静默跳过」养出来的，这里不重犯。
2. **基准过期时拒绝 `--fix`** —— `_facts.json` 自己过期时按它改 README，等于把旧数字再抄一遍。
   实测：注入「改测试文件 + 把 README 改回 1999」→ `--fix` 打印
   「已**拒绝**本次 --fix：基准自己过期时，按它改 README 等于把旧数字再抄一遍」，
   且 README **仍是 1999**（确认未写盘）+ exit 1。

**缺陷注入复验（原始形态）**：给 `server/tests/blindLenCapped.test.js` 加一行注释 →
`facts:check` 的 **stdout 说「README 与 _facts.json 一致」、stderr 说「采集源已改动 ——
_facts.json 可能过期」并精确指名该文件**、exit 1；撤销后 → 绿。
这一组输出正是本条要抓的假绿现场（"一致"与"过期"同时为真）。

**边界（已写进脚本注释，勿当万能）**：只覆盖测试文件 + 驱动采集的配置
（`vitest.config.ts` / `server/package.json` / `server/tests/_setup.mjs`）。
依赖版本、`.env.test`、被测源码改动**不在内** —— 改源码不改用例数，那是覆盖率门禁的职责。
判据宁可窄而准，不宽而吵。

**后续**：`e2e/acceptance.mjs` 的 12 个套件同样缺「采集于哪一版代码」的凭证 —— 已做，见 §R。


### R. 验收报告的两段可信度断口：无版本凭证 + 定向跑覆盖全量报告（✅ 已修 2026-09-20）

与 §Q 同源（**结论看着正常，语义完全不同**），这次断在**验收报告**上。

**断口 1 —— 实测撞到，不是推测**：`e2e/acceptance.mjs` 支持 `--only=<id>` 做定向门禁，
但它把结果写进**同一个** `e2e/results/acceptance-report.md`，也就是入库的全量报告位置。
本会话实测现场：那份文件的内容变成了

```
| ✅ PASS | fileWrite 真闭环（文件系统侧断言） | PASS=true SKIP=false 文件落盘=true 方式=隔离沙箱重试 |
**汇总：1 PASS / 0 FAIL(含 BLOCKED) / 0 SKIP**
```

一行 + 一句「1 PASS / 0 FAIL」—— 看着全绿，实际 12 个套件只跑了 1 个。
而被覆盖掉的是**已入库**的全量结论（前一份是 12 PASS），信息直接丢失。

**断口 2**：报告头部只有时间戳，回答不了「这份 N PASS 是哪一版代码跑出来的」。
工作区 dirty 时跑出的报告照样入库 → 读的人会以为它对应某个提交。

**修法（三件）**：
1. 报告头加**版本凭证**：HEAD 短 sha + 未提交清单（dirty 时显式写「本报告不对应任何提交」
   + 前 3 个文件名 + 总数）。**必须在开跑前采集** —— 跑验收本身会写 `e2e/*/results/*`，
   结束时采集会把运行产物误读成「跑前的未提交改动」。
2. 报告头加**套件范围判据**：`N/M 跑出断言`（N = PASS+FAIL，即真跑了断言的套件数）
   + 非全量时追加「⚠️ 判定：不完整 —— 不得当作该代码版本的整体验收结论」。
   判据是数字，**不依赖文件名**（文件名可以被改）。
3. 只有**真全量**运行（无 `--only`、无 `--skip-heavy`）才写 `acceptance-report.md`；
   其余写 `acceptance-report.partial.md`，并加进 `.gitignore`（本地产物不入库）。

**验证（哈希对照，可复现）**：跑前 `acceptance-report.md` md5 = `6a38c043042a3b07f7259eed64767f16`
（被污染版本）→ 跑 `--only=report-contract` → 跑后 md5 **逐字相同**（未被覆盖），
终端打印「套件范围：1/12 跑出断言（**非全量**，未覆盖全量报告）」。
新报告头部实测（dirty 与范围两行都在）：

```
> 代码版本：`0ef2bc9`　⚠️ **工作区 dirty**（跑验收前有 9 个未提交改动：…）—— 本报告不对应任何提交
> 套件范围：**1/12 跑出断言**（定向 --only=report-contract）　｜　⚠️ **判定：不完整**
```

**顺带确认（避免误伤 CI）**：`.github/workflows/*.yml` 与 `scripts/ci-local.mjs`
都不用 `--skip-heavy`，CI 走的始终是「真全量」路径 → 报告仍写 `acceptance-report.md`，分流对 CI 无影响。


### S. 沙箱起不来被记成产品 FAIL；失败现场会过期（✅ 两条都修 2026-09-20）

全量 `ci:local` 里 `fileWrite` 报 `FAIL 文件落盘=false`，看着像文件写入被改坏了。
真因来自那份**保留下来的失败现场**：隔离 mysqld 沙箱启动超时 45s 后 python 抛
`RuntimeError`，**一条断言都没执行**。单独 `--only=file-write` 连跑 3 次全绿。

- **定性修正**：`FAIL` = 断言没过（代码有问题）；沙箱没起来 = `BLOCKED`。
  两者**一样进 failed、一样让门禁非零退出**，改的只是语义标签——
  让人一眼知道该去查环境还是查代码。这正是 §G 那次"把环境问题归给被测代码"的重演，
  差别是这次有现场可查。
  匹配只用 ASCII 稳定标记（`mysql_sandbox.py", line N, in` + `Traceback`），因为
  `[mysql-sandbox]` 那些行在本机 cp936 控制台下是乱码，按中文匹配必失效。
  三向验证过：真实现场判 BLOCKED ✅；合成的"真实断言失败"不判（否则就是放水）✅；
  只有中文超时行、没有 traceback 也不判（保守留在 FAIL）✅。
- **现场卫生**：dump 现在带 `失败于 <ISO>`，且**套件这次过了就删掉它的旧现场**。
  此前没有任何清理逻辑（我一度以为有，实测 `grep last-failure` 只有写入处一处）——
  于是一份三天前的失败日志会一直躺在那儿，长得像"刚刚又红了一次"的证据。
  **留着比没有更坏**，因为它会把人往已经作废的方向上带。

### T. udf-lab / 沙箱启动超时是同一个环境抖动源（未修）

§S 那次 traceback 与记忆里"udf-lab 约一半概率跑挂"是同一家族：多个套件各自
`起 mysqld 沙箱 → 用 → 停`，在全量跑批里挤同一个 3308 端口与同一份 datadir。
可选方向（未做，需要先定口径）：acceptance 内**共享一个沙箱实例**跑完所有需要它的套件，
而不是每个套件各起各的；或把启动超时从 45s 提到实测分布的 P99。
现在的能力只是把它正确标成 BLOCKED，**不是消除了它**。


### U. ci-local 声称「对齐 ci.yml」，却少跑 3 个 job 且只声明了 1 个（✅ 已修 2026-09-20）

与 J 条同源，换了个层级：J 那道闸门查「引用的**文件**存不存在」，
这条查「ci.yml 里的 **job** 有没有人执行」—— 都是「配置里写了、实际没人跑」。

**现场**：`scripts/ci-local.mjs` 头部原写

```
· 不覆盖：需要 docker 的 job（`docker`、`acceptance` 的 MySQL+secure_file_priv 前置、…）
```

只提了 **1 个** job，而实测未覆盖的是 **3 个**：

| job | 真实排除理由 |
|---|---|
| `docker` | 本机无 docker（exit 127 已实证）—— 原声明里唯一被提到的 |
| `test-matrix` | 跨平台矩阵（windows/macos）。命令集已被 lint/test-frontend/test-server 覆盖，但「另一个操作系统」本机替代不了 |
| `tamper-waf-matrix` | schedule-only 实验矩阵 + `continue-on-error` 有意设计（见 K 条） |

文件末尾还有一句散文式声明「CI 还有两个本机跑不了的 job」——「两个」里只有 `docker`
一个是 job（另一个是 acceptance 的前置条件，不是 job），而实际是 3 个。**两处声明都错。**

**为什么值得修而不是改几个字**：真正贵的不是这次的数字错，是**将来**——
ci.yml 新增一个 job，本地门禁会静默少跑一段，而没有任何东西会因此变红。
这正是本仓反复出现的那类错（J/K/Q/R 同族）。

**判据（不留默认跳过的口子）**：每个 ci.yml job 必须二选一 ——
① 被 GATES 覆盖；② 在 `EXCLUDED_JOBS` 里登记，并写清「为什么本机替代不了」。
没登记 → 启动即报错 exit 2，逼人当场做选择。反向也查：清单里登记了 ci.yml 已不存在的
job（清单腐烂）同样报错。解析侧另加一道自保：jobs 段之后若冒出新的顶级键，
直接报「结构变了，自检需要跟着改」，而不是静默漏检。

启动时打印一行（**数字即判据**，散文声明全部删掉，避免两处漂移）：
```
job 覆盖自检：ci.yml 12 个 job → 本地覆盖 9 / 显式排除 3 / 未声明 0
```

**缺陷注入复验（两例，均按预期 exit 2）**：
- ci.yml 末尾追加一个未声明 job → 「❌ ci.yml 里有 1 个 job 没有登记的归宿：`zzz-injected-job`」，
  且自检行变成「⚠️ 未声明 1」；
- `EXCLUDED_JOBS` 登记一个不存在的 job → 「❌ EXCLUDED_JOBS 里登记了 ci.yml 已不存在的
  job：`ghost-injected-job` …… 排除清单腐烂了」。
两处注入撤销后 → 自检行回到「未声明 0」、exit 0。

**边界**：这条只管「job 有没有人跑」，**不管 CI job 里的步骤是否被逐条等价覆盖**
（例如 acceptance 在 CI 里是「新克隆 + 空 datadir + docker 起 MySQL」的干净环境，
本机跑的是同一份脚本但环境不同 —— 这种差异本判据看不见，仍需真远端）。


---

## P1 · 实战视角高价值

### 1. 真实 ModSecurity/Coraza WAF 验证（可执行步骤）
- **依赖**：需有 Docker 的机器（本机无 docker，exit 127 已实证；Dockerfile/docker-compose.yml 已在仓库根目录，可复用）
- **现状**：全部 WAF 绕过结论均为「自实现 CRS 执行器 ≈PL3」口径（`e2e/waf-real`，CRS v4.1.0 官方规则原文 942/930），README 已诚实标注但这是对外可信度最大短板
- **验收**：真实 ModSecurity + libinjection 引擎下复测 tamper 链绕过率，README「WAF 绕过能力实测口径」表新增一行真实引擎数据

#### 步骤 0 · 前置确认（Docker 机器上）
```bash
docker --version && docker compose version   # 均需可用
git clone <repo> && cd sqli-scanner          # 或同步工作区到 Docker 机器
```

#### 步骤 1 · 搭真实 ModSecurity 反代容器（`e2e/waf-real/modsec/`）
新建 `docker-compose.modsec.yml`（ owasp/modsecurity-crs:nginx 官方镜像，一次性起完整栈）：
```yaml
services:
  modsec:
    image: owasp/modsecurity-crs:nginx
    ports: ["8088:8080"]
    environment:
      - PARANOIA=3                          # 对齐现有 crs-engine 的 ≈PL3 口径
      - ANOMALY_INBOUND=5                   # 默认阻断阈值
      - BACKEND=http://host.docker.internal:8151
      - ENGINE_MODE=DETECTION_ONLY_NO_BLOCK # 先观察模式校准，再切阻断
    extra_hosts: ["host.docker.internal:host-gateway"]
    volumes:
      - ./modsec/crs-custom.conf:/etc/modsecurity.d/instance.conf:ro
```
- `crs-custom.conf`：`Include` 官方 CRS，显式开启 `SecRuleEngine On` + libinjection（`SecRule ARGS "@detectSQLi"`）
- 关键点：**用 CRS v4.1.0**（与 `e2e/waf-real/crs/REQUEST-942-SQLI.conf` 同版本），镜像 tag 固定为 `owasp/modsecurity-crs:nginx@sha256:<digest>` 保证可复现

#### 步骤 2 · 确定靶场后端拓扑
- 后端 = 现有 `real-mysql-lab`（3306 MySQL + lab-app，端口 8151），**引擎扫描目标指向 8088（ModSec）而非直连后端**
- Windows 主机跑 lab-app：容器内 BACKEND 用 `host.docker.internal:8151`；Linux 机器用宿主 IP
- 自检：`curl "http://<docker-host>:8088/num?id=1"` 正常回显 + `curl "http://<docker-host>:8088/num?id=1' AND 1=1-- -"` 被 403 → WAF 生效

#### 步骤 3 · 观察模式校准（防阻断阈值差异污染对拍）
- `DETECTION_ONLY_NO_BLOCK` 下跑一遍 `tamper-sweep.mjs`（改 BASE 指向 8088）
- 从容器日志（`docker logs`，`ModSecurity: Warning.` 行）提取真实命中规则号与 anomaly 分值
- 若 PL3 + libinjection 的命中集与自实现 crs-engine 的命中集有系统性差异（预期会有：libinjection 是额外探测器），逐条记录差异样本（payload / 命中规则 / 是否拦截）

#### 步骤 4 · 阻断模式正式复测
- 切 `SecRuleEngine On`（去 DETECTION_ONLY），复跑与现有口径**完全相同**的场景矩阵：
  - `tamper-sweep.mjs`（tamper off/on 对比）
  - `waf-verify.mjs`（num/str/like/blind/orderby 5 端点 + safe/echo 安全对照）
- 记录两组数：tamper off X/5 → tamper on Y/5 技术位；安全对照误拦数（应为 0，非 0 说明 CRS 误报，需样本分析）

#### 步骤 5 · 对拍报告与口径更新
- 结果落 `e2e/waf-real/results/modsec-docker-<date>.md`：与自实现引擎逐场景对照表（检出/绕过/差异规则号）
- README「WAF 绕过能力实测口径」表新增一行：`真实 ModSecurity（owasp/modsecurity-crs:nginx，PL3+libinjection）`，数字照实填；若与自实现差异大，在表下加一句差异归因（如「libinjection 额外拦截了 X 类 payload」）
- 若 Docker 不可得，可降级跑 **Coraza**（Go 实现，`docker pull corazawaf/coraza-spoa` 或本地 `go run`），口径注明「Coraza（ModSecurity 兼容引擎）」——同样是真实引擎，可信度高于自实现

#### 常见坑（提前备好）
- 镜像默认 `ENGINE_MODE` 与 `PARANOIA` 环境变量名随版本变——起容器后 `docker exec` 进去 `cat /etc/modsecurity.d/*.conf` 核对生效值，别信文档
- Windows Docker Desktop 的 `host.docker.internal` 在 Linux 机器不存在——用 `host-gateway` extra_hosts 或直接 `--network host`
- CRS 版本漂移——务必固定镜像 digest 并在报告中记录镜像版本 + CRS 版本 + PARANOIA + 阻断阈值四要素，否则结果不可比

### 2. NTLM 接线 HttpClient（✅ 已完成）
- **✅ 已接线（commit f5c40ae）**：独立模块 `core/ntlmHandshake.js`（NtlmHandshake 状态机：cred/preAuthHeader/replay/clear），HttpClient 请求前预附加 Type3（已握手主机免重复挑战）+ 401+NTLM 挑战时三步握手重放（上限 2 跳）；NTLM 模式不发 Basic 头
- **✅ DES 部署前提已消除**：desEcb 换自实现 `core/desEcb.js`（与 OpenSSL 交叉验证一致），不再依赖 `--openssl-legacy-provider`
- **✅ 测试覆盖（14 项）**：模块级 12 项（RFC 1320 向量 + Type1/2/3 闭环）+ HTTP 层集成 2 项（`ntlmHandshake.http.test.js`：mock server 401+Type2 → 自动 Type3 → 200 闭环、同主机状态复用 challenge 只发一次）
- **诚实边界**：mock server 不校验 NT/LM response 密码学正确性（模块级已钉 RFC 向量）；真实 IIS/NTLMv2 环境未实测
- **验收**：新增 NTLM mock 服务端 e2e（401→Type2→Type3→200），README 口径表更新为 ✅

### 3. 二阶跨角色双身份靶场 e2e
- **现状**：`secondOrder.storeCookies`（低权写入）/`triggerCookies`（高权读出）已实现并通过 20/20 单测 + real-world-lab 9/9 回归，但缺端到端双角色场景
- **实现点**：real-world-lab 增加 `/panel-admin`（仅 admin 会话可见的触发页），验证跨角色配置能检出单身份场景漏掉的二阶注入
- **验收**：verify.mjs 新增场景 PASS，README 二阶口径补一句实测结论
- **✅ 已完成（2026-09-14）**：real-world-lab 新增 admin-only 触发页 `/admin/panel`（users.admin 角色门禁 403）+ admin 会话禁写评论（403）；verify.mjs 新增 `second_order_crossrole` 场景——alice（user 会话）写评论、/admin/panel（triggerCookies: admin 会话）触发，检出 `[second_order]`（25 请求 4.1s），自检三连（写入 200 / admin 触发 500 真实引爆 / user+匿名 403 跨角色门禁）全过；现有 second_order 场景切 user 身份后零回归（real-world-lab 10 场景全 PASS）。README 二阶口径已补实测结论

### 3b. redteam-lab env.mjs 间歇性死亡根因排查（✅ 已结案 2026-09-14：连接风暴）
- **现象**：spawn 版 env.mjs 在 run-scan 中段无栈死亡（1/26、4/26、6/26），死亡点随机
- **根因（已坐实）**：**lab-app 的 `q()` 每条查询新建 TCP 连接再销毁**——26 靶点全量扫描 ≈ 2600 次高频短连，连接风暴下 node（靶场）与 mysqld 双双 native fast-fail（CrashDumps 同时存在 node 崩溃观测 `0xC0000409` 与 `mysqld.exe.5948.dmp`）
- **排查过程**（redteam-death-diag.mjs，5 轮对照实验）：
  - 抓到退出证据：`code=3221226505(0xC0000409) signal=null killed=false` → **native fast-fail 自崩，排除外部杀/进程树关联假设**（外部杀必有 signal）
  - stderr 全空 → 排除 JS 异常路径；内存曲线 154→270MB 正常 → 排除 OOM；pipe/inherit 均死 → 排除 stdio 管道断裂；`--report-on-fatalerror` 无报告（fast-fail 绕过诊断钩子）；WER/Defender 无记录 → 排除 EDR
  - 池化改造后连续 2 轮全存活（18/26、19/26），gate-check 19/19 rate=100% [PASS] → 根因坐实
- **修复**：`q()` 与两处 safe 端点改用常驻连接池（poolVuln/poolSafe 分池，严格保留 multipleStatements 语义边界防堆叠能力泄漏到安全端点）
- **教训**：靶场自身的「每请求建连」反模式 + 高频扫描 = 双进程 native 崩溃；门禁此前形同虚设掩盖了它。`--report-on-fatalerror` 对 fast-fail 无效，Windows 下抓这类死亡要靠 exit code（0xC0000409）+ CrashDumps 目录

### 4. 大文件二期拆分（照 scanRunner 模式）
- **对象**：`core/httpClient.js`（1913 行）、`engine/Extractor.js`（1388 行）、`engine/ScanManager.js`（1003 行）
- **模式**：参考 scanRunner 第一轮「阶段外移」——纯搬移封边、输入输出注释明确、行为零变化
- **验收**：全量单测 + e2e 关键 lab（real-mysql/waf-real）回归通过

## P2 · 工程化补强

### 5. coverage 门禁数据刷新（✅ 已完成 2026-09-17）
- **✅ 已完成（2026-09-17）**：
  - 前端实测 `stmts 90.01 / branch 79.01 / func 70.64 / lines 90.01`（补测后由 89.47 提升），
    门禁由 **FAIL 转 PASS**；阈值按「实测 −3pt」刷新为 **87 / 76 / 67 / 87**。
    旧阈值 90 压在实测 90.01 上（差 0.01pt）——门禁架在刀尖：既容不下正常波动，也防不住真回退。
  - 服务端实测 `lines 88.42 / branch 72.67 / func 75.75`，阈值刷新为 **85 / 69 / 72**
    （原 84/71/73；branch 余量仅 1.67pt，太脆）。
  - 本轮补测：`src/shared/htmlSanitize.ts` —— **此前 0% 覆盖的安全模块**（现 100%，
    另修复其 CSS 清洗产出畸形 HTML 的瑕疵：`url()` 残留右括号 + 双引号提前闭合 style 属性）；
    `src/shared/scanConfig.ts` 的授权范围解析（76.31% → 92.1%，scope 解析错 = 扫越界）。

### 6. 弱引用模块补直接单测（✅ 已完成 2026-09-18，含清单纠错）
- **⚠️ 本项原描述已证伪**：原文写「tamperRoutes / digestAuth / egressOpts / reportDelivery 仅 1 个测试文件弱引用」，
  但实测覆盖率完全相反 —— `egressOpts.js` 行覆盖 **100%**、`reportDelivery.js` **99.55%**、
  `digestAuth` 也有专属测试文件。**照原文补测等于白做工**。
- **真实缺口在清单未提之处**：`scanLedger.js` 行 **26.39%** / 函数 **0%**
  （只被 `bin/cli.js` 调用，CLI 走 e2e 不入单测；但 `cli.js ledger list|show` 是真实交付路径，
  且已有 163 个真实台账目录）。
- **✅ 已完成（2026-09-18，commit efabace）**：新增 `server/tests/scanLedger.test.js`（12 条，
  真实文件系统、不 mock 落盘）；覆盖率 **行 26.39→96.02% / 函数 0→91.67%**。
  补测过程实测并修复三个真实缺陷：
  1. **PoC 落盘恒为空（交付级）**：`_attachPoc` 惰性且不可变（返回新对象不回写入参），
     CLI 传原始 report → `if (!v.poc) continue` 全命中 → **163 个真实台账 0 个 poc 文件**。
     修：CLI 两处改传 `rg.attachPoc(report)`。真靶场验证：修复版 poc=5 / 回退版 poc=0。
  2. **`getScan` files 分隔符随平台**：`poc\a.txt` vs `recordScan` 存的 `poc/a.txt`，
     消费方 `startsWith('poc/')` 过滤恒为空。修：统一归一为 `/`。
  3. **scanId 路径穿越**：`../x` 可建目录到 ledger 根之外（`getScan` 的 scanId 直接来自 CLI 参数）。
     修：新增 `safeScanId` 拒绝分隔符/`..`/绝对路径/`\0`。
- **教训**：清单里的模块名与数字都可能过时。**补测前必须先跑覆盖率报告**
  （`cd server && npm run test:coverage:report`）再决定打哪。
- **副产品发现（✅ 已修 2026-09-20）**：`scanManager.scheduling.test.js` 与 `tamper.f20.test.js`
  存在**既有 flaky**（连跑 3 次 2/1/2 个失败，从不全绿）。根因是 `runScan` 轮询预算
  `200×5ms=1s` 太紧（测试注释自承"飘到 1.6s"），机器负载高时扫描未完成即断言。
  与本次改动零引用关系（已核实导入链）。
- **修法与实测（2026-09-20）**：两处都是「拿固定墙钟给异步流水线设上限」，等价于在测机器负载。
  - `scanManager.scheduling.test.js:49`：轮询预算 `200×5ms=1s` → `6000×5ms=30s`（语义不变，仍轮询到终态即返回）。
  - `tamper.f20.test.js:15` `runScanUntilDone`：固定 `8000ms` 超时 → `30000ms`（`TAMPER_SCAN_TIMEOUT_MS` 可覆盖）。
  - **验证**：两文件各自连跑 3 次全绿（scheduling 4/4 ×3；tamper.f20 10/10 ×3）；全量 `npm test` → 1896 用例 / 1895 pass / 0 fail / 1 skip。
  - **踩坑记录（勿重蹈）**：曾把 `runScanUntilDone` 改成「事件 + setInterval 轮询」双通道，
    结果三条全红且报 `cancelledByParent`（`Promise resolution is still pending but the event loop has already resolved`）。
    原因是原实现靠**未 unref 的 setTimeout** 在等待期维持事件循环活跃；一旦把 poll/timer 全 clear 干净，
    事件循环见底，父级判定本轮结束并取消剩余子测试。**此类等待定时器不得 unref，收尾时也不得把活跃锚清光。**

### 7. docs/ 数字口径单一来源（✅ 已完成 2026-09-18）
- 32 个 md 中的测试数/引擎等级表易失真（本次审计修正 2 处）。可复制 `dbmsEvidence.js` 模式：数字由代码统一导出，文档生成时引用
- **✅ 已完成（2026-09-18）**：建立 `docs/_facts.json`（实时口径唯一来源，由 `scripts/facts-sync.mjs --refresh` 实跑采集）
  + 三档命令 `facts:refresh` / `facts:check` / `facts:fix`，并把 `facts:check` 接入 `check:all` 与 CI 的 lint job。
- **本轮实测的漂移（5 处，修正前）**：

  | 位置 | README 原写 | 实测 |
  |---|---|---|
  | 徽章 | tests-2144 | **2172**（294 + 1878） |
  | 「测试」块·服务端 | 1850 个用例 | **1881** |
  | 项目状态·服务端 | 1850 用例（1847 pass） | **1881（1878 pass）** |
  | 项目状态·复测日期 | 2026-09-17 | **2026-09-18** |
  | 项目状态·服务端覆盖率 | 88.42 / 72.67 / 75.75 | **88.82 / 72.95 / 76.26**（偏差 0.51pt） |

- **关键设计决策**：
  1. **只严格校验 README**（对外门面）。`docs/` 下带日期的评估报告与 `release-notes-*` 是历史存档，
     改了就毁证据 —— 已实测它们确实含旧数字（263 / 1815 / 1850），**均按记录保留，不动**。
  2. **阈值不重复定义**：前端读 `vitest.config.ts` 的 `coverage.thresholds`，服务端读 `server/package.json`
     的 `--test-coverage-*` 参数。
  3. **覆盖率给 0.2pt 容差，其余精确比对**：实测同一台机器连跑 3 次，前端 branch 得 79.03 / 79.01 / 79.01
     （抖动 0.02pt，其余字段稳定）。逐位精确比对会把门禁变成 flake 源 —— 正是本项目最反感的「假红」。
  4. **规则未命中即报错**（不静默跳过）：README 结构一变、规则失效，必须显形，否则校验会变假绿。

- **踩到的两个真坑（已修，留档）**：
  - **vitest 即使 stdout 被管道捕获仍输出 ANSI 颜色码**：`Tests \u001b[22m \u001b[1m\u001b[32m294 passed` ——
    数字前带转义序列，任何 `Tests\s+(\d+)` 都匹配不上；覆盖率表格同理。必须先剥离再解析。
  - **README 是纯 CRLF（575/575）且仓库无 `.gitattributes`**：按 `'\n'` 切分会让每行残留 `\r`，
    而 JS 正则的 `$` **不匹配**尾部 `\r` 之前的位置 → 带 `$` 锚点的规则**全部静默失效**（实测踩到）。
    现按检测到的 EOL 切分并原样写回，`--fix` 后 `git diff` 恰好 3 行、CRLF 保持 575/575。

- **顺带清掉一个同类缺陷**：`.eslintignore` 被 ESLint 10 的 flat config **静默忽略**（文件已废弃），
  内容又已被 `eslint.config.js` 的 `ignores` 完全覆盖 —— 一个「看起来在管、实际不工作」的配置，
  与文档数字漂移同源。已删除，删除前后 `npx eslint .` 均为 0 error / 6 warning（无行为变化）。

### 7b. 建议新增 `.gitattributes`（✅ 已完成，本条已过时）
- **实测修正（2026-09-20）**：`.gitattributes` **已存在**，且已按实际需求落地（原文"仓库无 .gitattributes"过时）：
  ```
  e2e/waf-real/crs/** -text
  server/src/core/tamper/upstream-sqlmap-tamper.json -text
  ```
- 取向与原文建议**相反**：不是 `* text=auto` 全仓规整，而是给 **sha256 校验的上游快照**打 `-text`，
  保证字节级保真（CRS 官方回归集、sqlmap upstream tamper）。这比"eol=lf 全仓"更贴合本仓的核心风险
  —— 快照被 EOL 转换后 hash 对不上，保真度门禁会假红。
- 仍可补的（低优先）：`*.md text eol=lf` 治 Windows↔Linux checkout 的整文件 diff 噪声。

### 7c. 前端 func 覆盖率低 = 指标假象（✅ 已查清 2026-09-18）
- **原判断被实测证伪**：此前评估写「func 70.64% 说明存在整块未执行的函数，属函数级盲区」。
  实测把未覆盖函数逐条拉出来后，**这个说法不成立**。
- **实测结构**（`coverage/coverage-final.json`，293 个函数）：

  | 类别 | 数量 | 说明 |
  |---|---|---|
  | 未覆盖合计 | 86 | 占 29.35% |
  | 其中 JSX 内联事件处理器 | **69** | onChange/onClick/onClose 之类，靠用户交互驱动 |
  | 其中「真逻辑」函数 | 17 | 且多数是 1–2 行透传（如 `goScan = () => navigate('/scan')`） |
  | 其中**带分支逻辑值得测** | **4** | 见下 |

- **本轮实际补测的 4 个（21 条用例）**：
  | 函数 | 文件 | 为什么值得测 |
  |---|---|---|
  | `renderValidity` | `components/progress/` | 可信度守卫的 UI 出口（被封/目标挂/会话失效时用户唯一看到的提示），此前 0 覆盖 |
  | `setApiToken` | `shared/apiClient.ts` | **鉴权**：trim/空值归一/localStorage 持久化/隐私模式降级 |
  | `setApiBase` | `shared/apiClient.ts` | **桌面版命门**：sidecar 随机端口经此注入，错了就「连不上」 |
  | `handleImportRequestFile` | `components/TargetForm.tsx` | 唯一带 IO 的多分支处理（取消/解析失败/成功/抛异常），结果直接决定扫描目标 |

- **量化结论**：21 条用例 → 4 个函数 → func 70.64% → **72.01%（+1.37pt）**，
  与 4/293 = 1.37pt 精确吻合，说明每一处都打在真逻辑上。
  但要到 85% 需再覆盖约 46 个函数，而真逻辑只剩 13 个 —— **数学上做不到，除非去测 JSX 样板**。
- **处置**：func 阈值**刻意不跟涨**（保持 67），理由已写进 `vitest.config.ts` 的注释；
  stmts/branch/lines 按「实测 −3pt」上调为 88/77/88。
- **教训**：覆盖率是**聚合指标**，会掩盖结构。看到某一维偏低时，先把它拆成「逐条清单」再下结论 ——
  否则容易把「组件里内联箭头函数多」误读成「有逻辑没测」。

### 7d. 沙箱配置不可复现（✅ 已修 2026-09-18，属真实缺陷）
- **现象**：`mysql_sandbox.py` 用 `mysqld --defaults-file=<INI>` 启动沙箱，但**全仓库
  搜不到任何生成该 INI 的代码**（只有第 48 行的引用）；而 INI 位于 `.mysql-sandbox/`（已 gitignore）
  且内含写死的绝对路径。
- **后果**：新克隆 / CI / 换机器跑 `--init` 会在「找不到 defaults-file」直接失败 →
  **README 报告的 UDF/os-shell 真机验证不可复现**。本机之所以一直能跑，只因为磁盘上
  遗留了一份来路不明的 INI（2175 字节，含 `secure_file_priv` / `plugin_dir` /
  「不要开 skip-name-resolve」等关键项与实测教训，全都只存在于那份未入库的文件里）。
- **修法**：新增 `render_ini()` + `write_ini()`，从脚本常量派生全部路径；在 `do_init` 与
  `do_start` 里**先落配置再起 mysqld**；`write_ini()` 幂等（内容不变不写）。
  另加 `--print-ini` 只读预览，无需启动任何进程即可校验配置。
- **验证（20 项断言全过，均为纯文本/文件操作，不启动 mysqld）**：
  删除 INI 后 `write_ini()` 能自建且**配置项与在用基线逐条一致**（不会把在用沙箱搞挂）、
  幂等、6 个路径项全部锁在沙箱内、`render_ini()` 与磁盘内容一致。
- **教训**：`gitignore` 一份「运行必需的配置」= 本地能跑、别人跑不了。
  凡 `--defaults-file` / 外部配置文件，**必须由代码生成**或入库，不能两头不占。

### 7e. 沙箱磁盘瘦身（⑤ 部分完成 2026-09-18）
- 已清理崩溃残留 `ibtmp1.DDA9.d`（孤儿临时表空间，MySQL 文档明确的 `ibtmp1.<随机>.d` 形态）：
  **202M → 190M**。只删孤儿，未动活动 `ibtmp1`。
- redo 日志仍占 ~100MB（`ib_logfile0/1` 各 50MB）。**不建议贸然改**：本机 MySQL 为 **8.0.28**，
  8.0.30 之前**不支持运行期改 redo 日志大小** —— 对已初始化 datadir 写 `innodb_log_file_size`
  会让 mysqld 拒绝启动。要瘦身必须重建：`SANDBOX_SMALL_REDO=1 python mysql_sandbox.py --init --force`
  （开关已实现并验证：追加而非替换，`skip-log-bin` 不丢）。默认关闭，避免把在用的沙箱搞挂。

### 9. 本地裸仓备份远端（✅ 2026-09-18 建立，属缓解非根治）
- **背景**：仓库长期无 remote（`gh` 未安装、无全局 git 身份、无 SSH 密钥 → 真远端与 CI 均阻塞），
  而本机 `.git` 有反复损坏史（`refs` 被整个删除、被标 Hidden）。
- **已做**：建裸仓 `D:/projects/sqli-scanner-backup.git`，加为名为 **`backup`** 的 remote
  （**刻意不占用 `origin`**，将来接真远端无冲突），push 全部分支 + tag。
  **验证方式不是「push 说 OK」**：实际 clone 出来核对 —— 131 提交与源一致、master 分支、
  两个 tag 在位、文件可读。
- **仍需你提供**：真远端地址 + 凭据。届时 `git remote set-url origin <url> && git push -u origin master --tags`
  即可，backup 可保留或删除。
- 提醒：本地裸仓能防 `.git` 损坏，**防不了磁盘故障**，不等于异地备份。

### 8. 前端测试环境差异固化
- ~~已修 `vitest.config.ts` 强制 `NODE_ENV=test`（jsdom 下 React production build 导致 246 个假失败）+ 契约测试 `@vitest-environment node`~~（已完成）；**CI 已搭建**（`.github/workflows/ci.yml`，2026-09-13）：lint/typecheck + 前端 vitest + 服务端 1767 用例 + `run-all` 自足 6 套靶场，ubuntu/Node 24。**剩余动作：push 后观察首次 CI 实跑**——Linux 与 Windows 的路径/换行差异（e2e 脚本/测试断言）只有真跑才能暴露，若单测在 Linux 出现平台性失败按最小修复处理

---

## 环境清理备忘（一次性）

- [x] NRPT 规则 `.ooblab.test` / `.oob-lab.local` 已提权移除（2026-09-11 完成，`Get-DnsClientNrptRule` 确认清零）
- [x] MySQL 3307 实验实例（secure-file-priv 放行模式）已回收
- [ ] MySQL 3306 常规实例现为后台进程（bash_id 3eb9c610，runtime 存活）；按 mysql-start.bat 语义属本机常驻，无需处理，但注意下次开机需手动拉起
- [x] `D:/mysql/data-backup-20260912`（187MB）**已删除**（2026-09-14，数据未损坏已实证，雪绒确认无回滚需求）
- [ ] 实验用 pg 驱动 --no-save 安装已核验未污染 package.json，无需处理

## 诚实边界（README 已标注，勿夸大）

- 真实 ModSecurity/Coraza/商业云 WAF 未实测
- SQL Server `xp_dirtree` / Oracle `UTL_HTTP` OOB 模板未真机验证
- ⛔ 等级数据库（SQL Server/Oracle/TiDB/DM8 等 11 种）仅有模板适配，结论视为待复核线索
- fileWrite / UDF / os-shell 为未真机验证的实验能力

---

## 已完成（2026-09-13 审计批次，留档防回归）

| 项 | 内容 | 验证 |
|---|---|---|
| NTLM 死文件修复 | 语法断裂 + 缺 import + DES key 截断三重缺陷；MD4 注释向量错误记忆值修正（权威对拍 6/6） | 12 项单测，legacy provider 下 12/12 |
| 前端测试假失败 | `vitest.config.ts` 强制 `NODE_ENV=test`（246 假失败恢复） | 40 文件 263/263 |
| qa_theme 错误断言 | `0f172a`（light 前景色）→ `getComputedStyle(body)` 断言 `rgb(10,14,22)` | 前端全量绿 |
| 契约测试挂起 | `@vitest-environment node`（jsdom 覆盖 node:url 导出） | 9/9 |
| eslint 清零 | scanRunner 20+ 死 import、detect.js `schedulerRef` 未定义真 bug | eslint exit 0 |
| 文档数字对齐 | README 徽章/正文 → 263/1767；docs 评估 1719 → 1753 复测口径 | 双端全量：前端 263/263、服务端 1764 pass/0 fail/3 skip |

> 更早批次成果（DNS OOB 真机验证、强动态页/定库加固、二阶跨角色、sqli-labs 23/23、L46 词边界修复等）见 README 各「实测口径」段与 `e2e/*/results/`。
