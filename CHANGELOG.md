# Changelog

本项目版本号遵循 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 修复：acceptance 把"沙箱根本没起来"记成产品 FAIL，且失败现场会过期

全量 `ci:local` 里 `fileWrite` 报 `FAIL 文件落盘=false`，读起来像文件写入被改坏了。真因来自
那份保留下来的失败现场（上一批加的 `[DIAG-FIX]`）：隔离 mysqld 沙箱启动超时 45s 后 python 抛
`RuntimeError`，**一条断言都没执行**；单独 `--only=file-write` 连跑 3 次全绿。

- **定性**：沙箱没起来判 `BLOCKED` 而不是 `FAIL`。两者**一样进 failed、一样让门禁非零退出**，
  改的只是语义标签——让人一眼知道该查环境还是查代码。这是 TODO §G"把环境问题归给被测代码"
  的重演。匹配只用 ASCII 稳定标记（python 文件名 + `Traceback`），因为 `[mysql-sandbox]`
  那些行在本机 cp936 控制台下是乱码，按中文匹配必失效。三向验证：真实现场→BLOCKED；
  合成真实断言失败→不判（否则就是放水）；只有中文超时行无 traceback→不判（保守留 FAIL）。
- **现场卫生**：dump 加 `失败于 <ISO>`；**套件这次过了就删掉它的旧现场**。此前根本没有清理逻辑
  （`grep last-failure` 只有写入处一处，我一度以为有），于是一份三天前的日志会一直长得像
  "刚刚又红了一次"的证据——**留着比没有更坏**，它会把人往已作废的方向带。
- 环境抖动的**根因未消除**（多套件各起各的沙箱、挤同一 3308 端口与 datadir），记 TODO §T。

### 靶点清单判据推广到第二个靶场，立刻查出一处真缺口：blackbox-lab 有 2 个靶点从未被扫描

把上一条的判据从 redteam-lab 推广到 blackbox-lab（`scripts/lab-targets-check.mjs` 改为
**多靶场**配置）后，第一次跑就露出：

- `blackbox-lab` 的**真值标定是 22 点**，而 `run-scan.mjs` 的 POINTS 只有 **20 点**；
- 三条独立证据：① `run-scan.mjs:49` 的注释写「这两个点由 `run-scenario.mjs` 单独处理」；
  ② `find . -name "run-scenario*"` **零命中**（全仓唯一提及处就是那行注释）；
  ③ `out/` 里 20 个靶点各有 r1/r2/sqlmap 产物，**那两个点一个都没有**；
- 而 README 写「22 靶点（15 漏洞 + 7 安全对照）」「真值标定 15/15」→
  **「真值标定 15 个漏洞点」与「实际扫描 13 个漏洞点」长期被混为一谈**。

新增的第三类判据：**扫描清单 ⊆ 权威，且差集必须显式登记**（反向也查登记腐烂）——
不留「默认跳过」的口子，否则"真值标了、扫描没跑"这件事会一直静默。
`blackbox-lab` 的差集已登记（`D1-postform` / `E1b-secondorder` + 各自理由），
启动输出如实显示「扫描目标 **20/22（差集 2 个，已登记）**」。

同步修正三处：
- `run-scan.mjs:49` 的错注释（原文指向一个不存在的文件）改为事实陈述；
- README 补「扫描覆盖 20/22」并指向 TODO §W；
- TODO §W 记全过程 + 补齐所需的 args 草案（**未验证，明确标注勿照抄**）。

**缺陷注入复验（3/3 按预期 exit 1）**：扫描清单漏掉一个点 → 报「未登记理由」；
补上一个已登记的点 → 报「清单腐烂」；真值表缺一个 → 报「缺 1 个靶点」。

### 新增「红队靶点清单一致性」门禁：真值链断了没人会发现

redteam-lab 的评测结论（检出率 / 误报）建立在一条**真值链**上：

```
selftest.mjs ──生成──▶ ground-truth.json ──被读──▶ gate-check.mjs ◀── results-r2.json
     ▲                                                    ▲                     ▲
     └── id 集合必须一致 ──┐                               │                     │
                          │                               └── 分母只含 truth=true 的 vuln
     run-scan.mjs ────────┘（决定"扫哪些"）─────────────────────────────────────────┘
```

三份清单（`run-scan.mjs` / `selftest.mjs` / `ground-truth.json`）**各自手写**，彼此之间
没有任何判据。不同步的后果是**不对称**的：

- run-scan 多一个点、selftest 少一个 → 该点不进真值表 → **完全不计入分母** → 静默，
  而且结论看起来更漂亮（检出率不受影响，没人会去查）；
- 反向 → 那个不可观测的 id 恒判未命中 → 检出率被拉低 → 变红（至少有人会去查）。

新增 `scripts/lab-targets-check.mjs`（接入 `npm run targets:check` · ci-local 的 lint 组 ·
ci.yml 的 lint job），判据：

- **权威集合** = run-scan 与 selftest 的 TARGETS，两者必须**逐 id 相等**（"扫哪些"与
  "标定哪些"是同一件事的两面，不允许差集）；
- `ground-truth.json` 的 id 集合必须**等于**权威集合，且不留 `truth≠true` 的 vuln；
- 子集清单（`sqlmap-bench` 18 条 / `verify-fix` 10 条）必须 ⊆ 权威，**显式登记"为什么是子集"**，
  规模走**只减不增**基线（悄悄删几项会让对标结论的分母变小而无人察觉）；
- 任一文件解析不到 id 时**直接报错退出**（判据失效必须显形，不静默返回空集合）。

**当前实测**：权威 26（19 vuln + 7 safe）、真值表 26 条、两份子集均 ⊆ 权威且未低于基线
—— 真值链目前是完整的，但**此前没有任何东西会保证它**。

**缺陷注入复验（4 例，全部按预期 exit 1）**：

| 注入 | 门禁报出 |
|---|---|
| selftest 少标定一个靶点 | 权威清单不一致（点名 `F24-safe-static`） |
| 子集引用了不存在的 id | 权威集合之外的靶点 id：`ZZZ-ghost-point` |
| 子集缩到基线以下 | 低于基线 18（只减不增） |
| 真值表出现幽灵条目 | 真值表里有权威集合之外的「幽灵靶点」 |

注入脚本自身也断言「替换真的生效」（未命中即报「用例无效」）—— 这是本项目的既有教训：
**静默空跑的注入会误导归因结论**。

### 新增「ci.yml job 覆盖」自检：本地门禁不再可能静默少跑一段

与「引用完整性」同源：那道闸门查「引用的**文件**存不存在」，这道查「ci.yml 里的 **job**
有没有人执行」。起因是 `scripts/ci-local.mjs` 头部原写「不覆盖：需要 docker 的 job
（`docker`、…）」，只提了 1 个，而实际未覆盖的是 **3 个**（test-matrix / tamper-waf-matrix /
docker）—— 声明与实际不符，而且没有任何东西会因此变红，读者只会以为除 docker 外都覆盖了。
更实际的后果在将来：ci.yml 新增 job 时本地门禁**静默少跑一段**，谁也不会发现。

判据：**每个 ci.yml job 必须二选一** —— 要么被 GATES 覆盖，要么在 `EXCLUDED_JOBS` 里登记
并写清「为什么本机替代不了」。不留「默认跳过」的口子。反向也查：清单里登记了 ci.yml 已不
存在的 job（清单腐烂）同样报错。解析侧另有一道自保：jobs 段之后若冒出新的顶级键，直接报
「本结构变了，自检需要跟着改」，而不是静默漏检 —— 判据失效必须显形。

启动时打印一行（数字即判据）：
`job 覆盖自检：ci.yml 12 个 job → 本地覆盖 9 / 显式排除 3 / 未声明 0`

**缺陷注入复验（两例，都按预期 exit 2）**：
- ci.yml 末尾追加一个未声明 job → 「❌ ci.yml 里有 1 个 job 没有登记的归宿：zzz-injected-job」；
- `EXCLUDED_JOBS` 登记一个不存在的 job → 「❌ ……排除清单腐烂了（那个 job 可能已删除或改名）」。

顺带删掉文件末尾那句散文式声明（原写「CI 还有两个本机跑不了的 job」——但「两个」里只有一个
真是 job，且实际是 3 个），改为指向启动时那行可跑判据的输出，不再复述数量。

### 修复：验收报告的两段可信度断口（定向跑覆盖全量报告 / 无版本凭证）

与下一条同源（**结论看着正常，语义完全不同**），这次断在 `e2e/acceptance.mjs` 的**报告**上。

**断口 1（实测撞到，非推测）**：`--only=<id>` 定向门禁把结果写进**同一个**
`e2e/results/acceptance-report.md` —— 入库的全量报告位置。实测现场：那份文件变成一行
「✅ PASS fileWrite 真闭环」+ 汇总「**1 PASS / 0 FAIL**」，看着全绿，实际 12 个套件
只跑了 1 个；被覆盖的是已入库的全量结论（前一份 12 PASS），信息直接丢失。

**断口 2**：报告头只有时间戳，回答不了「这份 N PASS 是哪一版代码跑出来的」；
工作区 dirty 时跑出的报告照样入库，读的人会以为它对应某个提交。

修法三件：
1. 报告头加**版本凭证**：HEAD 短 sha + 未提交清单（dirty 时明写「本报告不对应任何提交」
   并列出前 3 个文件与总数）。**必须在开跑前采集** —— 跑验收本身会写 `e2e/*/results/*`，
   收尾时采集会把运行产物误读成「跑前的未提交改动」，反过来说谎。
2. 报告头加**套件范围判据**：`N/M 跑出断言`（N = PASS+FAIL），非全量时追加
   「⚠️ 判定：不完整 —— 不得当作该代码版本的整体验收结论」。判据是数字，不依赖文件名。
3. 只有**真全量**运行才写 `acceptance-report.md`；其余写 `acceptance-report.partial.md`
   并加进 `.gitignore`（本地产物不入库）。

**验证**：跑前 `md5sum` = `6a38c043042a3b07f7259eed64767f16` → 跑 `--only=report-contract`
→ 跑后 md5 **逐字相同**（全量报告未被覆盖），终端打印「套件范围：1/12 跑出断言（非全量，
未覆盖全量报告）」。报告头实测两行：

```
> 代码版本：`0ef2bc9`　⚠️ **工作区 dirty**（跑验收前有 9 个未提交改动：…）—— 本报告不对应任何提交
> 套件范围：**1/12 跑出断言**（定向 --only=report-contract）　｜　⚠️ **判定：不完整**
```

CI 侧无影响：`.github/workflows/*.yml` 与 `scripts/ci-local.mjs` 都不用 `--skip-heavy`，
走的一直是真全量路径，报告仍写 `acceptance-report.md`。

### 新增「采集源过期」判据：README 与 _facts.json 一致 ≠ 数字是新的（门禁假绿）

`facts:check` 只比对 README ↔ `docs/_facts.json`，**从不校验 _facts.json 自己是否过期**。
于是出现一种假绿：后继两批提交带来 +19 条用例（1985 → 2004），没人回填，
`_facts.json` 停在 1985、README 也写 1985 → 门禁报「一致」，而真实用例数早已是 2004。
（与 `continue-on-error` 的空转 job 同源：都是**静默地没在做事**。）

判据：把「决定跑哪些测试、总共多少条」的文件集合做**内容指纹**，随 `--refresh`
与数字**同批**落盘（`docs/_facts.sources.json`），`--check` 时重算比对。
用内容哈希而非 mtime —— CI 上 checkout 后所有文件同一时刻，mtime 判据必然全量误报。

两个设计决策：
- **指纹缺失不静默通过**：文件不存在时报「没有依据」并 exit 1，而不是跳过检查。
- **基准过期时拒绝 `--fix`**：`_facts.json` 自己过期时按它改 README，等于把旧数字再抄一遍；
  故 stale 时 fix 不落盘，明确要求先 `--refresh`（顺序反了就是抄旧数）。

边界（写在脚本注释里，勿当万能）：只覆盖测试文件 + 驱动采集的配置；
依赖版本 / `.env.test` / 被测源码改动不在此判据内（改源码不改用例数，那是覆盖率门禁的职责）。

**顺带修正 README 三处陈旧结论**（逐条实测核对后改，非顺手改）：
- 「利用工具」行写「fileRead 已跑通，其余仍为 mock 单测」，但同文件「利用能力实测口径」表
  已记 fileWrite / UDF-os-shell 均为真闭环 —— **同一份 README 自相矛盾**。
- `npm run acceptance` 注释写「10 套件」，实际 `e2e/acceptance.mjs` 的 SUITES 是 **12** 个。
- P1-E 标「根因已定位，未修」，实际 `blindExtractor.js` 的分层裁决早已落地；
  按实情改写并补上**边界**：修的是「静默误用荒谬上界」，真超 4K 的字段仍判失败（有意护栏）。

### 修复：9 个「CLI 能设、引擎真读、REST 收不到」的扫描配置键（静默假阴性）

`sanitizeStart` 的返回 `config` 只由白名单键构成，未知键原来只留一行 `logger.debug`
（默认 info 级等于没有）。后果不是报错，是**调用方拿到 200 + 正常 scanId + 一句「未检出」**：
请求成功了，开关根本没进引擎。假阴性对扫描器是最贵的一类错。

既有两支守卫都抱不到它：`configWhitelist.guard` 的真值来源是 `defaults.js` 顶层键，
而这批键根本不在 defaults.js 里（只由 CLI 写入）；`configWhitelist.passthrough` 只遍历
`KNOWN_CFG_KEYS`，自然也不会去看没进白名单的键。源码注释里已留着 6 处
「此前不在白名单被静默丢弃」——一直是人肉发现一个补一个。

改成**可跑的两端交叉判据**（`server/tests/configReachability.guard.test.js`）：
CLI 侧 `config.X =` ∧ 引擎侧 `config.X`/`ctx.config?.X` − `KNOWN_CFG_KEYS`，
再对每个键**真调 `sanitizeStart`** 断言落地。第一轮抱出 9 个，全部接通：
`testPath` `testHeaders` `noCast` `flushSession` `hex` `unionFrom` `dumpWhere` `unionCols` `paramDel`。

过程里两次自我更正，都写进了代码注释：
- `hex` 最初被我当 grep 噪声跳过（`hex` 一词在 `server/src` 有上百处无关命中），
  是守卫测试第一次跑就把它指出来 —— 判据必须能跑，不能靠人眼看；
- 我最初给 `unionFrom` 写了句"大概由别处覆盖"的豁免，实测它被
  blindExtractor/DBFingerprinter/Extractor/injection **四处**读取，豁免已撤回。

接通时补的真校验（这些值会进 SQL 或进请求 URL，不是顺手重构）：
`unionCols` 收敛 1..200 整数（引擎按 `Number()` 当固定列数，`abc`→NaN 会进二分）；
`paramDel` 只收 `; , | ^ ~` 单字符（取**窄集合**：宽集合写错是静默改请求形状）；
`hex`/`flushSession` 收严格布尔（引擎按 `=== true` 判定，放过 `1` 又变回"收了不生效"）；
`dumpWhere` 拒分号（分号是把"一个条件"变成"第二条语句"那一步）。

未知键的提示从 `debug` 提到 `warn` 并明说"这些设置不会生效"。
顺带查实一个新形状：`BACKFILL_SCALAR_KEYS` 的透传循环**不看** `KNOWN_CFG_KEYS`，
所以白名单对这批键只管告警不管放行 —— 缺陷注入实测确认后，新守卫加了
「BACKFILL ⊆ KNOWN」一条把它钉住。

### 修复：版本回显定库在严格类型库上恒失效（HSQLDB 现已能识别）

先修测量手段：`e2e/multi-engine-lab/verify.mjs` 原来**只记技术位、不记定库结果**，且靶场
默认挂 CRS（UNION 哨兵整条 403）→ 版本回显通道在那里从没被执行过。于是"HSQLDB/Derby
定不了库"长期没有可跑的验证手段（H2 那次结论靠临时手写探针，跑完就没了）。现在报告带
`定库=` 列（与真实引擎不符还会报"误判"告警），并新增 `NO_WAF=1` 一档——用来分开
"探针跑不动（真缺陷）"与"探针没被送达（靶场挡的）"，这两件事在原报告里长得一模一样，
都是 `dbms=null`。报告标题强制带口径，两档数字不可互换。

打开后显形两个互相独立的缺陷：

① **死探针**：`func` 是裸常量串 `'HSQLDB'`，而 09-16 为堵 DB2 误判把 `sig` 收紧成
`/HSQLDB\s+\d/`——常量里没有数字，**回显了自己也匹配不上自己的 sig**。不是探针跑不动，
是判据写死了不可满足。改成 exclusive 探针：区分力来自"只在自家库存在的 FROM 子句"而非
字面量（正面回应 DB2 教训）。HSQLDB 真机回显 `"HSQLDB 103"`，同一条放 H2/Derby 直接报错。
为此给 `DB_VERSION` 加可选字段 `from`，其优先级高于方言伪表与用户 `--union-from`
（覆盖掉就没区分力了），其余 16 个库的探针构造一字不变。

② **标记落错列**：`idx = echoCols[0]` 无条件取第一个回显列。真机实测同一条探针放
`name`(VARCHAR) 正常回显、放 `id`(INTEGER) 报 `incompatible data types in combination`
整条 UNION 失败 → 严格类型库上这条通道恒失效，且症状与"跑不动"完全相同。H2 一直能过
是因为它以 MODE=MySQL 运行会隐式转类型，不是判据对了。按代价收敛：只对声明了 `from`
的候选换列重试（其余 16 库请求数零变化；全候选换列会把 206 请求推到 ~240）。

结果：`定库=HSQLDB` ✅、H2 依旧 ✅，安全对照仍零误报、检出场景仍 3/3。
两点不完美如实记下：**hsqldb 的 `str` 技术位从 `[union,error,boolean]` 变 `[union,boolean]`**
（漏洞仍检出、计数不变，是定库成功后跳过冗余报错重探的归因策略问题，待单独定口径）；
**Derby 仍未识别**——探针单独可执行（`"DERBY 24"`，且 Derby 只吃 `CAST(.. AS CHAR(n))`、
`VARCHAR` 反而报错，均实测），但组合成引擎实发形状后仍 echo=N，下一步查 Derby 对 select
列表里裸 `NULL` 的语法限制是否波及**所有** UNION 探针（该现象尚未在引擎实发形状上复现，
不当结论用）。

守卫升级：`dbmsExtend6.test.js` 原来只查"func 里有没有标识串"+"sig 能否命中一个手写的
漂亮串"，所以①这类缺陷可以长期全绿。新增静态不变量 **sig 要求 `\d` 时 func 必须有数字
来源**（必要条件检查，不替代真机验证）。缺陷注入复验：把 func 改回 `"'HSQLDB'"` → 该测试
立刻红并点名到条目。

### 修复：`-r` 导入 multipart 抓包时整份 body 塌成一个垃圾键（静默 0 检出）

`-r`（Burp/curl 导入）是实战喂目标最主要的方式，而这条路上**解析器是对的、接线是坏的**：
`parseRequestFile` 正确抽出 `{username, caption, avatar}`，但 `applyRequestFile` 丢开这些
字段、把**原始 body** 交给 `bodyToJsonString` 的 urlencoded 启发式。multipart 里没有 `&`、
只有 `name="…"` 里的 `=`，于是整份 body 塌成**一个**键，键名为
`--<boundary>\r\nContent-Disposition: form-data; name`；同时那个
`Content-Type: multipart/form-data; boundary=…` 被原样保留 —— 发出去的是"声明 multipart
却带一坨 urlencoded 垃圾"，目标必然取不到参数 → **扫描正常跑完、0 检出、零告警**。

修法：解析器新增 `bodyFields`（只装来自 body 的字段；原有的 `params` 把 query 和 body 混在
一个扁平对象里，调用方无法区分），multipart 时用它构造 body，并**删掉那个已经对不上的
Content-Type**，让引擎按 urlencoded 重发同一批字段名与值。这是"降级但说实话"：很多框架
两种编码都吃；不吃的那批由 warn 明确告知"未检出 ≠ 没有洞"，而不是让人以为目标干净。

**为什么既有测试全绿却没拦住**：`requestFileParser.multipart.test.js` 测的是被调函数，
断点却在调用链的下一环。**只测被调函数、不测调用链，就会出现"测试全绿而入口是坏的"**。
新增 `requestFile.importWiring.test.js` 一律从 `applyRequestFile` 进、从引擎收到的注入点出
（5 条，含 urlencoded/JSON 两条"别波及既有路径"的对照）；缺陷注入复验：把 multipart 判定
短路 → 第 1、2 条同时红。

真 multipart 发送仍未支持（`injection.js`/`httpClient` 里 0 处 FormData，已核实），
连同"前端 `requestParser.ts` 连 multipart 分支都没有"一起记在 TODO §O，并写明动手前
必须先补 multipart 靶场——`buildInjectionRequest` 是全项目最吃重的函数。

### 修复：CLI 的嵌套 JSON body 被摊平成不可注入的畸形值（同一份抓包 CLI 少测注入点）

`--body` 的文档语义是「JSON 对象字符串」，但 CLI 一律摊进 `bodyParams`，而 TargetParser
对每个值做 `String(v)`。同一份 body 实测两端：

```
--body '{"user":{"id":1,"name":"alice"},"tags":["a","b"],"plain":"x"}'
  CLI（bodyParams） →  user="[object Object]"  tags="a,b"  plain="x"
  REST（jsonBody）  →  user.id  user.name  tags.0  tags.1  plain
```

前两个值结构上不可能注入（没有 payload 能把 `[object Object]` 变成合法 SQL）。断的不是
引擎（`_discoverJsonLeaves` 早已实现），是 CLI 的接线。

修法保守：**只有真含嵌套才切 jsonBody**，扁平 body 继续走 bodyParams(urlencoded)——
否则会把"表单接口但用 JSON 语法写了扁平 body"的既有扫描全改成 application/json，
那是回归不是修复。判定抽成 `cli/config.js` 的 `resolveBodyChannel` 单点定义
（`-r` 导入抓包那条路共用，不在两处各写一份）。REST 侧同一个坑只加 warn 不改行为：
自动路由会让两个字段语义纠缠，但"我传的东西其实没被测"必须可见。

验证：`server/tests/cli.jsonBody.test.js` 6 条。主用例刻意不测纯函数，而是走
`parseArgs(argv)` → `runSingleScan` → 捕获递给 `ScanManager.start()` 的真实 input →
再接 TargetParser 看点位（只测纯函数挡不住"忘了放进 input"）。缺陷注入复验：从 input
摘掉 `jsonBody` → 两条同时红。另用一次性靶场拿**真 CLI 二进制**端到端打出
`dbms=MySQL` + `param=user.id` 的 union/error 两条检出（206 请求、0 拦截）。

### 修复：随机化电池的 ORDER BY 形态恒被剔出分母（探针选错，非引擎缺陷）

`battery.json` 里 `c00/c20/c34-orderby` 长期 `status:"unobservable"`。看着像自证机制在
正常工作，实际是我自己把分母做空的：orderby 复用了 `AND 1=1`/`AND 1=2` 这对布尔探针，
而 `ORDER BY id AND 1=1` 与 `AND 1=2` 在这张表上分别退化成 `ORDER BY id` 与常量 `ORDER BY 0`
（同序）；取 name/price 时字符串转数值恒 0，两探针更完全同序 —— 没有哪个检测器能看见。
电池宣称 6 种形态，实际恒测 5 种。换成列索引有效性对（`, 1` 合法 / `, 9999` 报错，
即 sqlmap `--order-by` 的信号）。

**同 seed、同 cases 的严格对照**：召回 17/17（剔 3 条）→ **20/20（剔 0 条）**，
三条 orderby 全部以 `[error,boolean]` 真检出，Wilson 95%CI 下界 81.57% → **83.9%**。
分母补全而下界更高，是更强的数字而不是更大的数字。


### 新增「引用完整性」门禁（CI 里写的路径必须真实存在）

起因是一次**空转门禁**：`ci.yml` 的 `tamper-waf-matrix` job 里写着
`node e2e/tamper-matrix/run.js` 与 `node e2e/waf-lab/run.js` —— 两个文件**都不存在**
（真入口是 `tamper-test.mjs` / `compare-real.run.py`）。更隐蔽的是它们都带
`continue-on-error: true`，于是 `node <不存在的文件>` 每次报 Cannot find module
却**从不拦人** —— 这两个 job **从未验证过任何东西**。是靠人工 grep 才发现的。

新增 `scripts/ref-integrity.mjs`，校验三处引用源里的本地路径是否真实存在：
- `.github/workflows/*.yml` 的 `run:` 步骤（含多行块，能识别 `cd X && node Y` 的基准目录偏移）
- `package.json` / `server/package.json` 的 `scripts`（含 `npm run <name>` 交叉引用存在性）
- `e2e/run-all.mjs` 的靶场注册表 `entry` 字段

接入：`npm run refs:check` · `npm run check:all` · `ci-local.mjs` 的 lint 组 · `ci.yml` 的 lint job。

**缺陷注入复验（4 例，全部按预期报红）**：
① ci.yml 路径改回不存在的 `run.js` → 报「第 313 行」；
② `run-all` 的 `entry` 改成不存在 → 报出条目；
③ `package.json` 引用不存在的 npm script → 报「脚本引用」；
④ **自指注入**：把 ci.yml 里 `ref-integrity.mjs` 自己写成拼错的名字 → 门禁抓到自己
（证明校验范围确实覆盖了它自身的接入点）。

**过程中修正的两处自身缺陷**（否则会天天报假红，比没有更糟）：
- 初版不认 `cd server && node index.js` → 把 3 个**相对子目录**的正确路径误报为缺失；
  改为按 `&&`/`;`/`|` 切段并跟踪 `cd` 目标。
- 缺陷注入② 首次"注入成功"实为**替换未命中而静默通过**——真实 entry 与我预设的字符串不同，
  这也印证了"注入必须断言替换真的生效"。

### WAF 归因修正（拦住数值点 union 的是 942190，不是 942361）

TODO §I「改起始形状把 num/blind 的 union 拿回来」立项时假定拦路虎是 942361
（`^[\W\d]+\s*?(?:alter|union)\b`，PL2，判**起始形状**）。四版探针实测（100+ 形态，
每格同时记录「CRS 拦不拦 / MySQL 认不认 / 标记值能否取回」三个独立事实）**推翻了这个前提**：

- 真凶是 **942190（PL1）**，含 `union\b[\s\x0b]*(?:all|(?:distin|sele)ct)\b` —— 判的是
  「union↔select 相邻」，与起始形状无关；942361 是 CRS 里更**松**的兄弟规则。
- 942190 带 **`t:removeCommentsChar`**，注释在匹配前已删除 → 全部 `/**/` 填充失效
  （30 种填充 0 通过；唯一逃过 942190 的 `UNION/*!*/SELECT` 落到 942500，换个坑而已）。
- 非 ASCII 空白（NBSP / U+2000–200A / 表意空格 / BOM 等 18 种）：MySQL **一律不认作空白**
  （语法错），这条路物理上不通。
- 绕开 union 字面量的五类等价手法（boolean / subquery / error / time / stacked，17 种）
  被 **942130 / 942440 / 942120 / 942131 / 942151 / 942160 / 942140 / 942350** 逐一精准拦住。

结论定性：**不是 tamper 链不够好，是 CRS 在 PL1 对 SQLi 全覆盖** —— 每格都有对口规则守着。
`num`/`blind` 丢 union 是**正确行为**（如实反映 WAF 强度），非缺陷。TODO §F 的归因表同步修正
（原记 942361）；§F 中「09-10 那次为何算进过 10」的注释猜测也随之失效（注释拆相邻性对
942190 无效），如实留白不再编因果。

四版探针留档：`e2e/waf-real/probe-union-shape.mjs`、`probe-union-shape2.mjs`、
`probe-union-ws.mjs`、`probe-nounion.mjs`（纯发请求 + 直连真库，各几秒，可复跑复核）。

### 架构门禁基线收紧

`server/src/core/httpClient.js` 已瘦到 **1251 行**，基线仍卡在 1256（门禁自报「已瘦 5 行，
可下调」）。基线是「只减不增」的技术债显式登记，留着宽松额度等于给后续膨胀留后门 →
下调至 1251。门禁复跑绿。

### 诊断可信度（归因文案不再把人带向错误方向）

`Exploiter.myOsShell` 的 echo 探针（纯 ASCII 数字 marker）原为**单次**判定：为空即写
「典型：Windows 本地化 whoami 的 GBK 输出」。但 marker 是纯 ASCII，它的空捕获**不可能是
编码问题** —— 这句话在「判据偶发抖动」时会把排障引向编码方向。改为最多两次重试，把三种
成因分开：echo 命中+原命令 null → 真·不可字符化；首空后命中 → 判据抖动（**不写编码归因**）；
两次都空 → 探测通道不可靠（新增 `probeInconclusive`，且**不**写 `udfInstall`，因为两次空
≠ 未注册）。缺陷注入复验：撤掉重试 → 新增两条变红、原语义那条仍绿。

### 靶场侧噪声源（`--test-path` 白烧请求 + redteam 喂假 SQL 错）

- **闭合探测在 404 路径上白烧约 40 请求**（`Detector.probeBoundary`）：闭合前缀的前提是该
  路径真执行了 SQL；路径不存在时后端没路由到查询代码，13 个候选只是同一张错误页（Express
  还回显 URL）→ 噪声 boundary → 触发整轮指纹/列数探测。现于基线请求后早退：
  `kind==='path'` 且 `400≤status<500`（排除 401/403/429 —— 鉴权/限流 ≠ 路径不存在）。
  真存在注入的路径不会是 4xx，故不影响真实检出；留 `boundarySkipReason` 供排障。
  实测来源：`/api/sleep` 开 `--test-path` 时 path 点拿到 boundary `%"`。
- **redteam-lab `/shop/semi` 的 URIError 喂假信号**（D15 靶点）：4 处裸调 `decodeURIComponent`
  （同文件已备好 `decodeSafe` 却没接上）。payload 含裸 `%` 时抛 URIError，被外层 `run()`
  兜成 `500 + SQL_ERROR: URIError` —— 不是「挂连接」，但等于靶场亲手给扫描器的 error 通道
  喂假信号（该看 UNION 结果行，却看到伪 SQL 错误）。改用 `decodeSafe` 后实测报错文本全部
  转为真实 MySQL 错：`id=1%` → `syntax ... near ''`；`id=1%zz` → `Unknown column 'zz'`。
- 附带纠正：TODO 原判「redteam / real-mysql / multi-engine / pentest-lab 同一形态」经实测
  **不成立** —— 这 4 个靶场均已具备防护，只有 `/shop/semi` 真中招。

### 测试可信度（消除两条既有 flaky 的假红）

两条 flaky 同根：**拿固定墙钟给异步扫描流水线设上限**，等价于在测机器负载。负载一高就红，
而同一文件孤立跑却全绿——这种「时红时绿」比稳定红更有害，会训练人对红视而不见。

- **`tamper.f20.test.js` `runScanUntilDone`**：固定 `8000ms` 超时在 `--test-concurrency=3`
  全量门禁下不够，报「scan did not finish in time」。实测同一文件孤立跑 3 次 10/10 全绿，
  全量负载下 8/10 → 放宽到 `30000ms`（`TAMPER_SCAN_TIMEOUT_MS` 可覆盖），语义不变。
- **`scanManager.scheduling.test.js`**：轮询预算 `200×5ms=1s`（测试注释自承"飘到 1.6s"）→ `6000×5ms=30s`。
  该文件自 2026-09-18 起记录为「连跑 3 次 2/1/2 个失败，从不全绿」，本次结案。
- **验证**：`tamper.f20` 10/10 ×3、`scheduling` 4/4 ×3；全量 `npm test` →
  **1896 用例 / 1895 pass / 0 fail / 1 skip**（112s）。

### 检出正确性（黑盒靶场真 MySQL 实测，非 mock 推演）

同一病根「目标回显注入值 → 所有『响应 vs 基线』的比较被污染」在三条链路上复发，全部修掉：

- **闭合探测**（`engine/Detector.js`）：LIKE 搜索框等回显型点上 13 个闭合候选全部判不相似 →
  boundary 回退空串 → 该点 union+boolean 技术位全灭。现相似判定先剔除被回显的 payload，
  并在「一条都不命中」时改用**不依赖基线**的等长真假对差分判据（正常站点零额外请求）。
- **版本回显定库**（`engine/DBFingerprinter.js`）：回显型页面里有两份 `__S__…__E__`
  （被回显的 SQL 文本 + 真实结果行），`match` 恒取前者 → 18 库 sig 全落空、整条通道失效。
  现取标记前先剔除本条 payload 回显。
- **时间向量定库**（`engine/payloads/index.js`）：向量把闭合引号写死在模板里，字符串上下文上
  「向量顺序即优先级」被打乱 → 真 MySQL 判成 ClickHouse（误判直接决定 payload 族/注释符/
  提取语句选哪一套）。现统一用 `{BD}`（该点闭合前缀）填充。
- **指纹缓存粒度**（`engine/ScanManager.js`）：整台目标共享一份，而检测是多点**并发**跑的 ——
  排在最前的若是 path/header 点（探针全 404），那份 null 就被后面每个点继承 → 时间盲注点整点
  漏检。现按点类别（main/header/path）分桶，且未定库结果允许后续点重试（有预算上限）。
- **预筛选不再剪掉数值型时间盲注点**（`engine/ScanManager.js` `_timeProbeValues`）：时间探针
  只有带前导 `'` 的形态，「恒 200 固定页 + 数值上下文」的点两个探针都无信号 → 整点被剪。
  现每种方言补一条数值上下文变体（每点 +1 探测请求）。
- **`--cookie` 现在真的是注入面**（`bin/cli/config.js`、`bin/cli.js`）：此前只进 `auth.cookie`
  （会话携带），`--cookie uid=1 --level 5` 解析出 0 个注入点 → 0 请求 → 报告「未检出」，
  看起来像一次干净的低风险扫描。是否投放仍由 level≥2 门控决定（与 sqlmap 同语义）；
  已升为注入点的键不再经 `auth.cookie` 重复附加（同名两份时结论不可复现）。

### 对目标的自伤风险（一处能力被刻意移除）

- **H2 移出盲探时间向量**：H2 的 `SLEEP()` 以毫秒计、MySQL 同名函数以秒计；原
  `SLEEP({SLEEP}000)` 写法在补上闭合前缀后于数值上下文的 MySQL 完全合法 —— 排前向量因故未延时
  时等于让目标库睡 1000~15000 秒（连接池被我们自己占死）。单位不对称无法两全，H2 定库改由报错
  签名承担，并加防回归断言：盲探向量不得出现任何 `{SLEEP}0+` 放大写法。
- **闭合探测不再重试**（`engine/Detector.js`）：能让目标挂住的探针重发大概率还是挂，
  默认 retry=3 × 30s 会把单点闭合探测拖成数分钟，且重复发送同一攻击特征正是风控封 IP 的触发点。

### 实测口径变化

- blackbox-lab（真 MySQL 8.0.28，22 靶点）：实战档 r2 **9/13 → 13/13**，默认档 r1 **10/13**，
  两档安全点误报均 **0/7**；A3-like 从「蹭误判才命中的 time」变成 `union+boolean`（风险 Medium→High）。
- redteam-lab R1 18/19、R2 19/19、误报 0/7（零回归）；服务端单测 1887 用例 0 fail、前端 315/315、
  `tsc` 0 错、eslint 0 error。
- 工具链：`scripts/facts-sync.mjs` 采集服务端数字时显式钉 `--test-reporter=tap`
  （node:test 的 reporter 选型随 TTY 探测漂移 → 本地 `--refresh` 必失败）。

### 定库判据：从「sig 能不能区分」换成「表达式只在自家库跑得动」

- **H2 改用 exclusive 探针 `H2VERSION()` 并前置到 MySQL 之前**（`engine/payloads/index.js`）。
  真引擎 A/B（`e2e/multi-engine-lab`，H2 2.2.224 经 JDBC，须 `{waf:false}` 才让 UNION 探针过靶场 CRS）：
  修复前 18 条探针全部 `echo=N` → **`dbms=null`（定库失败）**；修复后
  `verFp H2 echo=Y 取到值="2.2.224" sig命中=true` → **`dbms=H2`**。真 MySQL 8.0.28 三点
  （`A1-numeric`/`A3-like`/`C2-blindtime`）仍全部 `dbms=MySQL`、3/3 检出、0 误报，前置不抢库。
  与 `engine/extractionMaps.js` 早已使用的 `H2VERSION()` 对齐。
- **一次公开更正**：本批先前把这条写成「H2 的 `version()` 回显命中 MySQL 的裸版本号 sig → 真 H2 被定成
  MySQL」。实测**不成立**——H2 没有 `version()` 标量函数，MySQL 系 WRAP 的 `CAST(x AS CHAR)` 在 H2 上
  直接报错，那条路径运行时不可达；实际症状是定库失败而非误判。`TODO.md` §A 已按实测改写并留证据。
- 单测侧把「假引擎能执行哪些探针表达式」显式建模（`tests/boundary.echoTarget.test.js` 新增正/反两条
  exclusive 守卫，`tests/fingerprint.mariadb.test.js` 的 mock 加 `supportedFuncs`）。不给这层，mock 等于
  「谁探测都回同一个版本」，会把真实判据（跑不动 → 无回显）抹平 —— 上面那次错误归因正源于此。
- 新测得的欠账（记录未修）：HSQLDB / Derby 两台**关掉 WAF** 后仍 `18/18 echo=N → dbms=null`，
  即版本回显定库对这两台整条失效；`multi-engine-lab` 默认开着 CRS，UNION 哨兵探针全被 403，
  该靶场从未跑到这条通道（见 TODO §A 验收口径 2/3）。

### 门禁可信度：掐掉两条假绿

- **`acceptance` 的 SKIP 不再算 PASS**（`e2e/acceptance.mjs`）：`pass: passed || skipped` 让
  fileRead / fileWrite 在 `secure_file_priv=NULL`（MySQL 8 默认）时以「✅ PASS」进报告并计入顶部
  汇总，一行断言都没跑却算通过，与同仓 `run-all.mjs` 的「跳过的不算通过」自相矛盾。现改为
  `PASS / SKIP / BLOCKED / FAIL` 四态分列，SKIP 带原因、不进失败也不冒充通过。
  本机默认环境实测：**8 PASS / 0 BLOCKED / 0 FAIL / 3 SKIP**（此前同一环境报的是「11 PASS / 0 SKIP」）。
- **撤掉 9 条 eslint 目录/文件级 ignore**（`eslint.config.js`）：被挡住的包括门禁总控
  `e2e/acceptance.mjs` 自己 —— 它因此从未被 lint 过，`tally is assigned but never used`、
  `ntlm-lab` 里 `reject` 未声明（真实缺陷：靶场端口被占时抛 ReferenceError 而非可读错误）都没人看见。
  纳回后 25 条 `no-unused-vars` 全部清零，`eslint .` 现 0 error / 6 warning、退出码 0。
- **WAF 口径的量纲与写死基线**：`waf-verify.mjs` 原输出 `检出 ${det}/${total} 个技术位` 把「技术位合计」
  与「场景数」塞进同一个分数（README 于是抄成「10/5」），改为「技术位合计 8（5 个注入场景…）」；
  `waf-auto-check.mjs` 里写死的「人工 dash2hash 基线 = 10」改成从 `waf-real-report.json` 现读，
  读不到就显示「未采集」。

### 实测口径变化（WAF 绕过率下修，附规则级归因）

> **本节已被 2026-09-19 晚些时候的执行器修复推翻，保留作历史记录。** 用 CRS 官方回归集查出
> 自实现 SecRule 执行器两处结构性缺陷（`(?i)` 内联大小写标记被吃掉、链节点 `TX/MATCHED_VARS`
> 未实现）后，保真度 60.7% → 99.3%，同一批探针在同一份规则上的结论完全变了：
> PL1（默认部署档）off=on=8（挂链无可证增益），PL3（全规则档）0/0（无可证绕过）。
> 故「off 2 → on 8」这类「绕过生效」的表述是宽松执行器白给的假收益，README 已按新基线重写，
> 本节及以下 TODO §F 的归因不再作为对外口径。

- **对外数字从 10（人工挂链）/ 11（自动选链）下修到 8 / 8**（整跑 acceptance 一次 + 单独复跑一次，
  两次一致）。丢的两格是 `num`/`blind` 的 union，**逐条手工探针定位到 CRS 规则原文**：
  942361 是 `^[\W\d]+\s*?(?:alter|union)\b` —— 打的是**参数值起始形状**，数值点 `id=1…` 必命中、
  `alice'…` 不命中；`/**/`、`%0a`、`%09`、双空格、`UNION ALL` 八种换分隔符形态全部 403，
  而它们不套 WAF 时 MySQL 全部正常执行。`dash2hash` 只规整尾部注释符，对这条无效。
  本批改动已排除（回退动过的 4 个引擎文件重跑，结果逐字相同）。
- 另一层口径：942361 官方注释属 **PL2**，而本仓自实现执行器默认全规则（≈PL3 最严档）→
  **8/8 是「最严档」数字，CRS 默认部署档（PL1）的绕过率未测**（TODO §I 已把两档测量列为待办）。
  旧数字 10/11 无留档报告可核对，故只作口径下修，不断言"能力退化"。

### 门禁可信度：掐掉一条环境耦合造成的假红

- **`server/tests/engine.e2e.test.js` 不再复用 4567 端口上的外部引擎**。旧实现把端口写死 4567，
  且 `startEngine()` 发现该端口有实例就直接复用 —— 只要本机跑着一个带 `SCAN_API_TOKEN` 的实例
  （手动起的 server / 桌面版 sidecar / 上一次门禁残留），受保护端点就全部返 401，而用例断言的是
  2001 → **稳定红，且与被测代码毫无关系**（反向验证：另起一个无 token 实例请求同一路径
  返回 `{"code":2001}`，证明引擎契约本身没问题）。
  现改为三条：① `net.listen(0)` 取空闲端口；② 自己 spawn 一个带一次性 token 的实例
  （不再读宿主环境的 `SCAN_API_TOKEN`）；③ 所有请求显式带 `x-api-token`。
- **新增两条鉴权契约用例**（无 token / 错 token 访问受保护端点必须 401）：鉴权链路此前只在
  `release-smoke` 里被覆盖，服务端单测里没有；现在这两条同时是上述修复的回归钉。
- **验证**：单文件连跑 **5 次 7/7**；服务端全量单测 **1893 / 1892 pass / 0 fail / 1 skip**
  （修复前同一环境为 1887 / 1884 pass / **2 fail**）。
- 残余风险写实：`listen(0)` 拿到端口到子进程 bind 之间有极小时间窗被抢占，届时 spawn 会
  `EADDRINUSE` → 健康检查超时并报错，**不会**像旧实现那样静默连上一个来路不明的引擎。

### 发布阻断修复（补记录 + 补测试）：带 token 部署时前端两个主路由打不开

- `server/index.js` [SPA-DEEPLINK-FIX]：启用 `SCAN_API_TOKEN` 后，前端自己的 `/scan`、`/exploit`
  被 `API_SEGMENTS` 白名单当成 API 拦掉 —— 浏览器直接访问/刷新/收藏这两页拿到的是
  `{"code":401,...}` 一段 JSON，页面打不开（`/`、`/history`、`/report/:id` 反而没事）。
  开发模式（Vite 代理）与不带 token 时都看不到，所以此前从没暴露。
  判据收紧为四条**同时成立**才放行：GET + 裸路径（无子路径）+ `Accept` 含 `text/html`
  + `dist/index.html` 真实存在。数据接口（`/api/...` 基址与 `/scan/<id>/...` 子路径）不受影响。
- 新增 `server/tests/spaShellAuth.test.js`（4 条）：放行生效、不得扩大到 API 客户端（无
  `Accept: text/html` 仍 401）、不得扩大到子路径、数据接口带 token 正常返回业务码。
  **已做缺陷注入验证**：临时撤掉修复后**仅第 1 条 FAIL、其余 3 条仍绿**（说明四条边界各测一面，
  不是一红红一片），恢复后 4/4。
- 注：本条此前只存在于工作区未提交，README/CHANGELOG 均无记录，属「修了但没留痕」。

### 修复：盲注长度二分「顶到上界」时拿上界当长度（TODO §B）

`binaryProbe` 早就给出 `capped` 标记，但 `blindExtractor._binarySearch` 只 `return r.n + 1`，
把标记丢了 —— 判据失效时会**按上界逐字节提取**（历史事故：上界 65531，一个 5 字符的值
要提 6.5 万字符）。

修的时候发现「顶到上界」**有两种成因**，探测层面无法区分，一刀切判失败会打死正常长值
（实跑挂了 2 个用例），故分层裁决：

| 位置 | 含义 | 处置 |
|---|---|---|
| 主段（hi=255） | 也可能只是真实长度 ≥256 | 只打 `ctx.blindLenCapped`，交 `_extendLength` 预检 `>255` 裁决 |
| 延伸段，`blindMaxLen` 由用户显式配置 | 用户已授权「最多提这么长」 | 按 maxLen 截断提取（旧行为不变） |
| 延伸段，撞上默认护栏 4096 | 用户没授权过这么长 → 判据失效 | 判失败（-1 → 该字段返回 null） |

失败原因经 `ctx.blindLenCapped` 上浮，由 `scan/extract.js` 写进 `report.summary.constraints`。
新增 `server/tests/blindLenCapped.test.js`（3 条）；缺陷注入（撤销延伸段终审）→ **只有第 1 条红**
且实际值是一整串 4096 个垃圾字符，另两条（显式 blindMaxLen 截断 / 真长值 300 字节延伸）仍绿。

### 修复：concurrent-isolation 的确定性红 + 门禁「未跑」不可见（TODO §G）

- `e2e/concurrent-isolation/e2e.mjs` 建 MySQL 池**写死** `port:3306/user:root/password:'root'`，
  而 `run-all` 按 `deps:['sandbox']` 把它交给 `run-with-sandbox.py`（沙箱在 3308，注入
  `MYSQL_*`）。「声明走沙箱」与「实际连宿主」自相矛盾 → 两条 MySQL 扫描 `dbms=null techs=[]`。
  现统一读 `MYSQL_*` 契约；另加环境自检（连不上 / 库内 0 张表 → 显式 BLOCKED，退出码 2），
  不再把环境问题判成「并发串扰」归给被测代码。
  **实测**：沙箱路径下，写死 3306 时沙箱注入的空口令连不上宿主 → 退出码 2；改后 PASS（3/3 union 命中）。
- `run-all.mjs` 汇总新增「未跑（缺依赖，本轮零断言）」单列：此前缺依赖的靶场被直接过滤，
  连 SKIP 都不显示，「通过 6 / 失败 0」是假绿。
- 顺带：`--only` 只认空格形式，写 `--only=名字` 会**静默退化成跑全部**（实测想跑 1 个 0.5s
  套件结果跑了 21 个，含 77s 红队）。现两种写法都认并打印「定向模式」。

### 修复：CRS 执行器保真度门禁唯一的 FAIL（96% / 23 条未点名分歧 → 99.3% / 0）

- **病根**：CRS v4.1.0 的 pattern 用 PCRE 的组级大小写开关 `(?i:…)`。本仓跑在
  **Node 22.22.2（V8 12.4）**，该语法属 ES2025 regex modifiers（要 V8 13 / Node 23+），
  `new RegExp('(?i:…)', 'i')` 直接抛 `Invalid group` → 执行器 catch 后返回 null →
  **942160 / 942220 / 942250 / 942361 / 942450 五条规则恒不命中**，官方回归集漏 23 条
  （`sleep()/benchmark()`、整数溢出、`EXECUTE IMMEDIATE`、`^[\W\d]+\s*(alter|union)`、`0x` 十六进制）。
  ⚠️ 代码里原先有条注释断言「ES2025 已收进 JS，记进 regexBad 是误报」—— 实测打脸，
  那是把未来语法当现状，已改正。
- **修法**（`e2e/waf-real/crs-engine.js`）：新增 `toJsRegex()`，`(?i)` 删除、`(?i:…)` 降级为
  `(?:…)`（本执行器恒以 `flags:'i'` 编译，二者语义等价）；**运行期 `execOp` 与装载期普查探针
  共用同一个函数**，不再两套真相。反向开关 `(?-i:…)` 无法用全局 flag 表达，遇到即主动放弃
  （继续保守跳过 + 普查记一笔），不伪造大小写不敏感。
- **保留 try/catch**：降级只覆盖今天已知的两类构造；将来 CRS 升版引入别的 PCRE 语法时应
  「该规则不命中 + 普查记一笔 + 门禁 FAIL」，而不是让保真度脚本崩掉（崩掉反而看不见原因）。
- **缺陷注入验证**：撤销降级 → 保真度 **13.2% / 600 条未点名 → FAIL**；恢复 → **99.3% / 0 → PASS**。
- **影响面复测**：WAF 两档基线未退化 —— PL1 `8/8/8`、PL3 `0/0/0`（`waf-bits-baseline.json`
  无需收紧）；PL4 逐规则一致率 92.9% → **96.1%**，整体检出 96.9% → **98.8%**。

### README 口径校正（三处，按 2026-09-19 23:14 本机实测）

| 位置 | 原写 | 实测 / 现状 |
|---|---|---|
| 「WAF 绕过能力实测口径」整节 | off 2 → on 8、自动 11（PL3 归因） | **整节重写**：旧数字出自保真度 60.7% 的执行器，已作废；现按 PL1 `8/8/8`、PL3 `0/0/0` 两档基线表述 |
| 验收门禁「最近一次全量结果」 | 8 PASS / 3 SKIP | **10 PASS / 2 FAIL / 0 SKIP**（12 套件），两个 FAIL 的定位与处置已写进正文 |
| 测试数 / 徽章 | 1887 用例、2199 | **1893 用例、2207**（由 `npm run facts:refresh` + `facts:fix` 自动同步，`facts:check` 现一致） |

## [1.1.0] - 2026-09-18

### 安全加固（破坏性变更，请务必阅读「升级注意」）

- **默认鉴权（fail-closed）**：引擎新增统一 token 解析 `resolveApiToken()`。
  - 优先级：`SCAN_API_TOKEN_FILE`（Docker/K8s secret）→ `SCAN_API_TOKEN` → 回环监听允许无鉴权。
  - **监听非回环地址（含容器必需的 `HOST=0.0.0.0`）且未配置 token 时，引擎拒绝启动**并打印修复指引；
    确知风险可用 `SCAN_API_ALLOW_NO_TOKEN=1` 显式放行（启动打显著告警）。
  - `docker-compose.yml` 的 `SCAN_API_TOKEN` 改为必填（`${VAR:?}`），未设置时 compose 直接报错。
- **CSP 修复（影响 Docker 单端口部署）**：安全响应头按响应类型分流——
  `/api`、`/sqlmap` 仍为 `default-src 'none'`；前端静态资源改为放行 `'self'`（含 MUI 所需的
  `style-src 'unsafe-inline'`）。修复前 Docker/单端口部署打开即白屏（本地 Vite 与桌面端不受影响，
  故开发期难以发现）。
- **桌面端（Tauri）引擎连接加固**：
  - sidecar 端口不再写死 4567——被占用时自动改用空闲端口；
  - 引擎生成一次性 token（`crypto.randomBytes(32)`）经 stdout `ENGINE_TOKEN=` 回传，
    壳通过 `get_engine_info` 命令交给前端自动注入，本机其它进程无法再直连该引擎；
  - sidecar 缺失/启动失败不再 panic，改为广播 `engine-exit` + 前端「重启引擎」入口；
  - 引擎默认 `ALLOWED_ORIGINS` 增加 `http://tauri.localhost`、`tauri://localhost`。
- **静态外壳与 API 鉴权分离**：启用 `SCAN_API_TOKEN` 后，前端外壳（dist 静态资源与 SPA 路由）不再被
  token 中间件拦截（此前 `GET /` 直接返回 401 JSON，Docker/单端口部署下 **Web UI 完全打不开**）；
  所有数据接口（含不带 `/api` 前缀的 `/scan/*`、`/exploit/*`、`/sqlmap/*`）仍需 token。
- **桌面端 sidecar 可打包了**（此前无法构建）：
  - `npm run build:sidecar`（`scripts/build-sidecar.mjs`）走 Node SEA 路线：
    cjs bundle → SEA blob → postject 注入 → 冒烟（起 exe 断言 `/api/health`=200 与
    `ENGINE_TOKEN` 回传）。产物 `src-tauri/binaries/sqli-engine-<target-triple>[.exe]`（Windows x64 约 86 MB）。
  - 为什么不用 pkg：本机实测 `@yao-pkg/pkg --target node20-win-x64` 无预编译 base binary，
    退化为源码编译 Node 并因缺 NASM 失败。
  - 修复 `--format cjs` 产物不可运行：CJS 下 esbuild 不提供 `import.meta.url`，
    引擎入口定位前端产物时抛 `ERR_INVALID_ARG_TYPE`（此前该格式从未被验证过）。
  - 修复 `tauri.conf.json` 缺 `bundle.externalBin`：即使产出了 exe，`tauri build` 也不会打进安装包，
    运行时 `shell().sidecar("sqli-engine")` 找不到可执行文件。
  - `build:tauri` / `package:win` / `package:mac` 三条链已补上 sidecar 构建步骤。
  - **实测打包结果**：`npx tauri build --bundles nsis` 成功产出
    `SQL注入检测工具_1.1.0_x64-setup.exe`（26.4 MB，内含 90 MB sidecar 的 LZMA 压缩）；
    产物结构验证：`target/release/sqli-scanner.exe`（壳）+ `sqli-engine.exe`（sidecar）同目录，
    启动后日志 `[引擎] sidecar 已启动：127.0.0.1:4567`，`sqli-engine.exe` 进程在线。
  - ⚠️ **MSI（WiX）在当前用户目录下会失败**：`light.exe` 无法处理含全角括号的路径
    （`C:\Users\Admin（无密码）\AppData\...`）。因此 `package:win` 默认改用 NSIS；
    需要 MSI 时请在纯 ASCII 路径下构建。
  - **桌面版「直连 SQLite」已可用（B1，全内联方案）**：此前 sql.js 在 bundle 中为 external，
    SEA 单文件不含它，桌面直连 SQLite 会**静默回退**到内存自检驱动（扫得出结果但不是真库）。
    现改为**全内联**：
    - `scripts/build-engine.mjs` 新增 `--inline-sqljs`：sql-wasm.js 打进 bundle（不再 external）；
    - `sql-wasm.wasm` 作为 **SEA asset** 内嵌（`sea-config.json` 的 `assets`）；
    - 新增 `server/src/core/sqlJsLoader.js` 统一三种形态下的定位：SEA 用
      `require('node:sea').getAsset()` 取出 wasm 后经 `initSqlJs({ wasmBinary })` 直喂
      ——sql.js 一收到 `wasmBinary` 就跳过 `__dirname + readFileSync`，因此**零外部文件**。
    - 构建期硬断言：SEA asset 键名与 `sqlJsLoader.js` 的 `SQL_WASM_ASSET` 必须一致，
      且 `tauri.conf.json` 不得声明 sql.js 相关 `bundle.resources`（防两套依赖不同步）。
    - 冒烟升级：exe 在**全新空目录**下运行（旧版用 `cwd=dist-engine` 掩盖了外部依赖），
      并真跑一次直连 SQLite 扫描、按 SSE 事件断言 `detection_found ≥ 1`，
      同时检查引擎日志无「回退到内存自检驱动」告警 —— 负向验证：未内联版本该断言确实报 FAIL。
    - 为什么绕这么一圈：SEA 的 `require` 被劫持为「只认内建模块」，`require('sql.js')` 抛
      `No such built-in module: sql.js`，`NODE_PATH` 同样无效（实测四种方案对照）。
- **sqlmap `--eval` 默认禁用（A4）**：该参数会让 sqlmap 在服务端执行 **Python 表达式**（等价代码执行）。
  旧实现只打一条 warn 就透传；`POST /api/sqlmap/start` 的 body 是原样透传的，因此无鉴权部署下
  任何可达客户端都能提交表达式。现改为**双条件门控**：`SQLMAP_ALLOW_EVAL=1` **且**引擎已启用
  API 鉴权（`SCAN_API_TOKEN`）；不满足直接拒绝并给出启用条件（不静默丢弃参数）。
- **会话落盘注入点原始值加密（A5）**：`sessions/*.json` 的 `points[].originalValue` 在注入点为
  Cookie / 自定义认证头时等同于会话凭据，而 compose 还把 sessions 目录挂在 named volume 上。
  现**写盘封存（AES-256-GCM，`enc:v1:` 前缀）+ 读盘解封**，内存保持明文 ⇒ 断点续跑语义不变。
  密钥来源：`SCAN_SESSION_KEY` → 由 `SCAN_API_TOKEN` 派生 → 进程随机兜底；
  解不开的场景（换 key / 旧随机 key）把该点降级为「待重扫」，不会把密文当参数值发出去。
- **CI 门禁加固**：Docker 冒烟增加「无 token 必须 401」「静态资源 CSP 必须含 'self'」两条断言。
- **Rust 门禁可在本地复现（B4）**：
  - 新增 `src-tauri/rust-toolchain.toml` **单点锁定**工具链版本（`1.98.0` + `rustfmt`/`clippy`）。
    此前 CI 用 `dtolnay/rust-toolchain@stable` 会滚动到最新 stable，而 rustfmt 的换行/宏排版
    在小版本间会变、clippy 也会新增 lint → 会出现「本机格式化通过、CI 报 fmt 失败」这类
    不可复现的红。CI 同步改为 `@master` + `toolchain: 1.98.0`，两边完全同版本。
  - 修复 `src-tauri/src/lib.rs` 两处 `cargo fmt --check` 违规（纯排版：`.env(...)` 多行化、
    `invoke_handler!` 宏参数换行），均为 A3 加固时引入、此前**无任何门禁覆盖**。
  - 新增 npm scripts：`lint:rust`（fmt --check + clippy -D warnings）、`fmt:rust`、
    **`check:all`**（ESLint + 前后端 tsc + 架构门禁 + Rust 门禁，一条命令复现 CI 主门禁）。
  - 门禁灵敏度已实测：故意插入 `x == x` 会被 clippy 判 `error: equal expressions as operands`
    （退出码 101），证明「0 warning」不是空跑。
- **新增发布冒烟 `e2e/diag/release-smoke.mjs`**（已接入 CI 的 `release-smoke` job）：在临时沙箱里以
  **生产配置**（token + 托管 dist + 引擎常驻）跑完整链路——鉴权、跨站、CSP 分流、静态资源可达、
  真靶场扫描（API 与 CLI 两条路径）、五种报告交付物与退出码语义，共 30 项断言。

### 修复

- 报告导出确定性：`POC_CACHE` 由 WeakMap（键＝对象引用）改为稳定字符串键 + 容量上限，
  修复「同一份报告多次导出逐字节一致」偶发失败（实测修复前 3 次挂 1 次，修复后 5 次全过）。
- 拖库行切分（MySQL 系）：`GROUP_CONCAT` 显式行分隔符、分页下推进子查询、
  `CONCAT_WS` 的 NULL 安全包装，修复「多行落成 1 行且跨行串列」。
  - 真库实测：MySQL 8.0.28 的 `SEPARATOR` 只接受字面量（`SEPARATOR CHAR(30)` 为 1064 语法错误），
    改用 `0x1E`/`0x0A`；聚合结果的 `LIMIT/OFFSET` 对聚合输出无意义，已下推到源表行。
- 网络失败不再被判负：新增 `isNetworkFailureError()` 与 `addNetworkErrorPoint()`，
  注入点全部检测器因传输层失败时标记为未决（报告 `reliable=false`），不再写成「已检测、无漏洞」。
- 本地/私网目标默认绕过环境变量代理（`proxyBypassLocal`，默认开），
  修复装了系统代理时本地靶场扫描出现假阴性。
- ESLint 全量 31 处未使用导入/变量清理（大文件拆分遗留），并修复 `e2e/blackbox-lab/lab-app.mjs`
  中 `res` 未定义导致 WAF 拦截路径抛 `ReferenceError` 的缺陷。

### 依赖

- 服务端 `npm audit fix`：qs / body-parser 相关 3 项中危清零（当前 0 vulnerabilities）。

### 升级注意

1. **容器/非回环部署必须设置 `SCAN_API_TOKEN`**（或 `SCAN_API_TOKEN_FILE`），否则引擎起不来。
2. Web 端启用鉴权后需填写一次 token：首次 401 会弹出输入框（写入 `localStorage.scanApiToken`），
   或构建期注入 `VITE_SCAN_API_TOKEN`。
3. 桌面端升级后由应用自动注入端口与 token，无需手工配置；若从旧版升级，建议重新打包 sidecar。

## [1.0.0] - 2026-09-01

- 首个完整版本：Web / Docker / Tauri 桌面三端、CLI、9 类检测技术、拖库与利用能力、
  225 个 tamper 插件、报告导出（HTML/JSON/Markdown/SARIF/CSV）。
