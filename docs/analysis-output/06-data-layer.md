# 06 · 数据/知识库资产审查（tamper / WAF / payloads / DBMS 驱动）

> 审查基线：commit `a3ef37b`（master）。所有结论均来自实际读取的源码与运行时验证
> （`node --input-type=module` 动态导入统计：registry=71、tampers=203、wafRules=62、PAYLOADS 总模板数=1290）。

---

## 一、tamper 插件库（203 个插件 + TamperRegistry / applyTampers / index.js）

### 1.1 数量与命名一致性
- `core/tamper/plugins/*.js` 实测 **203 个文件，注册名恰好 203 个且无重名**（运行时 `tamperRegistry.list()` 去重校验通过），与 README「203 个 tamper 插件」一致。
- 命名风格离群点（3 处）：
  - `keywordSplit.js` 是唯一 camelCase 文件/导出名（其余 202 个均为全小写 kebab-case，如 `space2comment.js`）；注册名 `'keywordSplit'` 同样离群。
  - `0eunion.js` 文件名以数字开头（JS 标识符非法），被迫以别名导入：`import { eunion } from './plugins/0eunion.js'`（applyTampers.js:80），注册名为 `'eunion'`——文件名与注册名不一致。
  - `_360waf.js` 用下划线前缀规避数字开头，注册名 `'_360waf'`；与 `'0eunion'→'eunion'` 的处理方式互相矛盾（一个改注册名、一个加前缀）。

### 1.2 疑似重复插件（仅名称不同 / 功能高度重叠）
未发现 transform 完全等价的纯重复插件，但存在三组「同输入同目标、仅替换产物不同」的家族，属 sqlmap 对标的有意变体而非冗余：
- 单引号家族：`apostrophemask`（'→%EF%BC%87）、`apostrophenullencode`、`apostrophe2char`（'→CHAR(39)）、`escapequotes`、`quote2hex` —— 各自产物不同，保留合理。
- 双重编码家族（`d-` 前缀约定统一）：`base64encode/dbase64encode`、`json/djson`、`charencode/chardoubleencode/doubleencode`。
- 真正值得警惕的两组：
  - **大小写四兄弟**：`randomcase`（按 SQL_KEYWORDS 随机）、`randomcaseall`（全字符随机）、`mixedcase`（硬编码 SeLeCt 模式，仅覆盖 13 个关键字）、`swapcase`。`mixedcase` 与 `swapcase` 输出高度趋同且关键字覆盖远小于 keywords.js 词表，属于「效果重叠、维护双份」的候选合并项。
  - **压缩对**：`gzip.js` 与 `compression.js` 结构完全相同（同一套引号状态机逐字扫描字符串字面量再 zlib 压缩包装），差异仅在算法与包装函数。

### 1.3 参数约定与正确性抽查
- 约定统一：全部插件为 `{ name, description, transform(payload, ctx) }`；绝大多数忽略 `ctx`，无插件读取 `ctx.config`，签名一致性良好。
- **正确性缺陷（gzip.js）**：`gzipSync(Buffer.from(str)).toString('base64')` 产出的是 **gzip 容器格式**，却被包装为 `UNCOMPRESS(FROM_BASE64('…'))`（gzip.js:52 附近）。MySQL `UNCOMPRESS()` 期望的是 zlib 格式数据（即 `compression.js` 中 `deflateSync` 的输出，其描述「对标 sqlmap compression.py」是正确配对）。`gzip` 插件在真实 MySQL 上会产生无法解压的 payload——sqlmap 原 gzip.py 是配合支持 gunzip 的场景使用的，此处移植时丢失了语义。

### 1.4 启动期全量注册开销评估
- `applyTampers.js` 以 **静态 import 一次性拉起全部 203 个插件模块**并 `registerMany`（224-443 行，Map 以 name 幂等去重）。单文件均 <3KB（最大 `space2morehash.js` 2.8KB），合计约 100KB 源码 + 少数 `node:zlib` 依赖（gzip/compression/brotli 等 6 个）。实测动态导入全链路为毫秒级，当前规模下**无需懒加载**；但每新增一批插件都要手工同步 import 区 + registerMany 数组两处（v11~v21 注释显示已重复 12+ 轮），可考虑目录扫描自动注册消除该机械成本。
- 附带数据卫生问题：`keywords.js` 共享词表 Set 内存在重复字面量（`LEFT/RIGHT` 第 16/18 行、`CHAR/DATE/TIME/DATABASE/DISTINCT` 等各出现 2 次）——Set 语义无害，但反映手工维护无查重。

---

## 二、WAF 指纹库（wafRules.js 62 条 + WafIdentifier / wafRecommend.js）

### 2.1 头注释漂移（已确认）
- wafRules.js:4 头注释仍写「**覆盖 7 类常见 WAF：Cloudflare / ModSecurity / AWS WAF / 阿里云 WAF / 百度云加速 / 安全狗 / 腾讯云 WAF**」，实际 `Object.keys(WAF_RULES).length === 62`（运行时验证）。56 行「以下 23 项为 WAF-v2 新增」与 210 行「以下 32 项为 WAF-v3 新增…总 62 项」的段内注释是对的，但顶部总述从未回改。docs/optimization-report-2026-08-25.md §9 已记录同一问题，尚未修复。

### 2.2 matcher 结构一致性
- 全量目测 + 抽查确认：62 条规则的 matchers 仅使用 `type:'header'|'body'|'status'` 三种；cookie 特征一律表达为 `header(set-cookie)`（如 F5_BIG_IP 的 `bigipserver`、华为云 `/^HWWAFSESID=/i`、Airlock `/^al[_-]?(sess|lb)=/i`），与 57-59/211-212 行铁律注释一致。
- **缺口**：该铁律只存在于注释，没有像 `assertRecommendNames()` 那样的启动期断言。`WafIdentifier.matchOne`（WafIdentifier.js:17-31）对未知 type 直接 `return false`——若未来有人写入非法 matcher（如 `type:'cookie'` 或 RegExp key），规则会**静默永不命中**而非 fail-fast。建议补一个对称的 `assertRuleShapes()`。

### 2.3 正则质量抽查
- 高质量（有锚点、有存在性头）：Cloudflare `cf-ray` 存在即特征；EdgeCast `/^ec(acc|d|s)/i`、Fastly `x-served-by: /^cache-[a-z]{3}\d+-[A-Z]{3}/i`、Citrix `/^nsc_/i` 均做了锚定，误报风险低。
- 中风险宽匹配：
  - Cisco_ACE `server ~ /\bace\b/i`（wafRules.js:123）：`\bace\b` 会命中任意含独立 "ACE" 词的 Server 头（含版本号字符串碎片），在 62 条中误报面最大。
  - Baidu_Yunjiasu `server ~ /bws|baidu/i`：`bws` 三字符无边界约束，理论上可子串误命中。
  - ModSecurity `status ~ /^406$|^501$/`：对 String(status) 匹配可行，但 406/501 并非 ModSecurity 独占，作为单特征即可给出 0.8 置信度偏高（identify() 规则：命中即 0.8+）。
- 小众窄签名：Zscaler 的两条 body 特征均绑定 Accenture 定制页（`accenture policy` / `policies.accenture.com`，wafRules.js:306-307），通用 Zscaler 租户不会命中——来源应为 wafw00f 样本，覆盖率有限但无副作用。

### 2.4 wafRecommend.js 与规则的联动
- 结构性联动良好：WAF_RECOMMEND_MAP 覆盖与 WAF_RULES 同名的全部 62 个 vendor key；`assertTamperNames.js` 在模块加载期 fail-fast 校验推荐名 ∈ tamperRegistry（wafRecommend.js:91 尾部调用）；`recommend()` 由 scanRunner.js:178 消费，仅推荐不自动套用，且 shouldAutoRetry 三重门控（autoRetry 开关 + confidence≥0.8 + 用户未显式接管）设计克制。
- **价值缺口**：62 条推荐中约 **50 条是完全相同的通用组合** `['space2comment','randomcase','charencode']`（逐条比对确认：v3 新增 32 条里仅 CloudFront/Azure/GCP/TrafficShield 4 条不同）。该映射目前接近"常量表"，与 tamper 库 203 个插件的能力严重不成比例——识别出 Yundun/SafeLine 与识别出 DotDefender 得到的建议一字不差。国内 WAF 专杀插件（`_360waf/safedog/yundun`，v22 新增）反而没有任何一条 recommend 映射引用它们（assertTamperNames 只查"存在"，不查"被引用"）。

---

## 三、payload 模板与声明式注册表（engine/payloads/ + payloadRegistry.js）

### 3.1 模板宏一致性
- 全库宏使用统计（对 `payloads/*.js` 正则扫描）：`{ORIG}`×922、`{NUM}`×165、`{SLEEP}`×145、`{SEP}`×41、`{CALLBACK}`×31、`{DOMAIN}`×9、`{TOKEN}`×8。index.js 头部第 3 行文档化了全部 7 个宏，声明与实际一致。
- 两处小瑕疵：
  - `{INJECT}` 仅出现在 **2 条注释**里（mysql.js:146、postgres.js:125 的「DELETE FROM t WHERE id=1 {INJECT}」），不是模板占位符也未在宏表文档中，属注释用词与正式宏体系混淆。
  - 正则命中的 `{string}/{object}/{x}/{stored}/{config}` 等均来自 JSDoc/注释文本而非模板串，无真实漂移。

### 3.2 PAYLOADS 扁平结构与 REGISTRY 双轨并存的维护成本
- 实测 PAYLOADS 覆盖 18 个 DBMS key 共 **1290 条模板**（MySQL 199 / MariaDB 199 / TiDB 199 / PostgreSQL 139 / DM8 107 / Oracle 107 / SQL Server 123 / SQLite 74 / ClickHouse 17 / 其余 10 库各 11-20），与 README「1290 条」一致。
- **双轨现状**：PAYLOAD_REGISTRY（71 条，运行时验证）对标 sqlmap `<test>` 元数据设计规范（id/dbms/technique/level/risk/clause/boundary/where + 加载期 id 唯一性自检抛错），但全代码库搜索确认其**唯一生产消费者是 TimeBlindDetector._resolveTimeTemplates**（TimeBlindDetector.js:72-80），且仅在 `config.useRegistry === true` 时生效——该开关默认 false，其余 7 种技术（union/error/boolean/stacked/oob…）完全没有任何检测器走注册表路径。也就是说 71 条声明式条目目前≈**半休眠数据**，仅被自身单测 payloadRegistry.test.js 消费。
- 双轨的直接代价是**模板重复**：registry 的 template/falseTemplate 是从 PAYLOADS 手工抄录的，如 `mysql-bool-sq-1` 的 `{ORIG} AND 1=1 / {ORIG} AND 1=2` 与 mysql.js boolean[4]/[5] 逐字相同、`mysql-time-sleep-1` 与 mysql.js time 数组同源。两份拷贝之间无同步断言（没有"registry 模板必须存在于 PAYLOADS 对应数组"的校验），一旦改一边就会静默漂移。建议要么补同步测试，要么反向生成（以 registry 为单一事实源展开成扁平结构）。
- 克隆成本：index.js 用 `JSON.parse(JSON.stringify())` 为 MariaDB/TiDB 深拷贝 MySQL 全量模板、DM8 深拷贝 Oracle（各 199/199/107 条运行时内存副本）。继承策略本身合理，但意味着这三个库将来要方言化时必须先拆引用；当前内存开销可忽略。

### 3.3 实际重复模板
- mysql.js error 数组内部冗余显著：`extractvalue(1,concat(0x7e,(SELECT version())))-- -` 这一向量以不同闭合方式（裸/'/)、不同注释尾（`#`/`/**/`）出现 ≥4 次（43/46/47/69/70 行等），union 数组中 `UNION SELECT {NUM},database(),version()-- -` 同样按闭合矩阵铺开 ~10 次。这是有意为之的 sqlmap boundary 矩阵（有注释说明），但缺少机器可读的去重口径，1290 这个数字存在"变体膨胀"成分（同一 SQL 语义向量 × 边界组合被计为多条）。
- 好的一面：mysql.js:74-75 有显式的「与子句表条目非重复」防重说明；CLAUSE_PAYLOADS 限每库每 clause 每技术 ≤3 条并有总量截断，克制良好。

---

## 四、DBMS 支持与驱动层（core/dbDrivers.js）

### 4.1 内置驱动 vs README「18 种数据库」
- 真实可用的内置驱动仅 3 条通道：`SqlJsDriver`（sql.js WASM SQLite）、`PgDriver`（@electric-sql/pglite WASM PostgreSQL）、`MysqlDriver`（mysql2，连本地 mysqld/MariaDB）。README 第 38 行表格自身已诚实标注「3 种真实验证，15 种最小适配」，第 40 行补充说明其余 15 种（SQL Server/Oracle/ClickHouse/DB2/Sybase/Firebird/Informix/H2/Access/HSQLDB/Derby/MonetDB + 仅克隆的 TiDB/DM8）**只有模板、未经验证**——文案无夸大，但「18 种数据库」大标题仍可能被读者高估为 18 种已验证支持。
- others.js 的 10 个小库（DB2/Sybase/Firebird/Informix/H2/Access/HSQLDB/Derby/MonetDB/ClickHouse）每库仅 11-20 条模板且注释自认「未经真实环境验证，标注待验证」，与 PAYLOADS 深拷贝克隆同属"模板先行"策略。

### 4.2 getDriver 回退逻辑覆盖范围核查（防"假连接成功"）
代码确有防静默回退设计（dbDrivers.js:243-295 注释明确），但实测其覆盖存在 **两个缺口**：
1. **sqljs/sqlite 分支仍会静默降级**：`type === 'sqljs'|'sqlite'` 时 connect 失败仅 `logger.warn` 后返回 `MemoryRecordDriver`（dbDrivers.js:255-264）。用户显式指定 sqlite 直连、但 sql.js 未安装时，扫描会照常跑完并产出结论——只是对象换成了模拟 `5.7.25-sqlite-sim` 的内存桩。这与 265-266 行对 pglite 的处理哲学（"显式类型说明意图明确，应抛错而非静默退化"）自相矛盾。防回退逻辑**没有覆盖到它自己内置的回退分支**。
2. **缺省/无法识别分支静默回 memory**：driverType 缺省且连接串 scheme 推断不出时直接 `return new MemoryRecordDriver(db)`（dbDrivers.js:293-294），无 warn 日志。若用户传了格式不规范的连接串（如缺 scheme），会无声进入自检模式。
- 覆盖到位的部分：显式 `pglite`/`mysql`/`mariadb` 失败即抛清晰错误；`driverType` 已注册表外值抛 `[direct] 驱动 'x' 未注册`（286-292 行）——这三条路径不会产生假成功。
- 建议的兜底改进：扫描报告/API 中暴露实际使用的 `driver.name`（memory/sqljs/pglite/mysql），让"结果来自模拟桩"对调用方可见。

### 4.3 连接串语义不一致 + MysqlDriver 缺口
- `driverTypeFromConnectionString` 支持 `postgres:// mssql:// oracle:// …`（210-224 行），但这些 scheme 推断出的类型在默认 DRIVER_REGISTRY（空 Map）下全部走"未注册→抛错"。而内置的 pglite **无法通过 `postgres://` 连接串到达**——只能显式 `driverType:'pglite'`。同一文件内两套入口语义割裂：CLI `-d "sqlite://test.db"` 能通，`-d "postgres://…"` 必然报错。
- **MysqlDriver.connect 未传递 password 与 database**：`mysql.createConnection({ host, port, user, charset })`（dbDrivers.js:135 行）只取 `_opts.host/port/user`，`_opts.password/_opts.database` 即使配置了也被丢弃——任何带密码的真实 MySQL 都连不上。这是直连 MySQL 通道的功能性缺陷（当前大概只在免密 root 本机实例上验证过）。

---

## 五、server/scripts / bin/cli.js / .mock 定位

- `blindRobustDemo.mjs`：本地抖动靶机（vuln/noisy 双模式）+ 真实 HTTP 客户端跑 Boolean/Time 检测器，演示 blindRobust 统计判定。纯教学/自证工具，未被 package.json scripts 或 CI 引用，独立可运行，定位清晰。
- `tamperBypassDemo.mjs`：本地关键词 WAF 靶机上统计 4 组 tamper 的绕过率；远程模式强制 `--authorized` 门禁（缺失即 exit 1），红线设计正确。注意其本地 WAF 规则（`/union\s+select/i`、`/and\s+1=1/i`）与 core/waf/wafRules.js 指纹库是**两套互不相干的数据**——一个做拦截模拟、一个做指纹识别，无共享源，属合理分工但命名上都叫"WAF"，易被误认为同源。
- `bin/cli.js`：生产级 CLI 入口（server/package.json bin 链接 `sqli-scan`），复用 ScanManager，43+ 参数对标 sqlmap（--dbs/--tables/-r 等），与 scripts 下 demo 的"演示件"定位区分明确。
- `.mock/sqlmap.py`：789 字节的假 sqlmap，按 sqlmap 输出风格打印固定事件流后退出，专供 sqlmapBridge 的 spawn/流式解析测试，零网络请求，定位纯粹。

---

## 六、问题汇总（高 / 中 / 低）

### 高（影响直连通道结论可信度/可用性）
| # | 问题 | 证据 |
|---|------|------|
| H1 | `MysqlDriver.connect` 丢弃 password/database 配置，带密码的真实 MySQL 无法直连 | dbDrivers.js:132-135，`createConnection({host,port,user,charset})` |
| H2 | getDriver 防静默回退逻辑未覆盖自身内置回退：显式 `sqljs/sqlite` 失败仍降级 memory 桩；driverType 缺省且 scheme 推断失败时无日志静默回 memory——直连"假成功"风险仍在 | dbDrivers.js:255-264（warn 后回退）、293-294（无日志回退）；对照 265-266 行 pglite 的抛错哲学 |

### 中
| # | 问题 | 证据 |
|---|------|------|
| M1 | PAYLOAD_REGISTRY（71 条）为半休眠数据：唯一生产消费者 TimeBlindDetector 且 `useRegistry` 默认 false；71 条与 PAYLOADS 1290 条模板手工双抄、无同步断言，漂移只是时间问题 | payloadRegistry.js 全文消费面搜索；TimeBlindDetector.js:72-80 |
| M2 | WAF_RECOMMEND_MAP 62 条中约 50 条为同一通用组合，经验库价值趋零；v22 国内 WAF 专杀插件（_360waf/safedog/yundun）零引用 | wafRecommend.js:41-72 逐条比对 |
| M3 | wafRules.js 头注释「覆盖 7 类」与实际 62 条漂移（已知未修） | wafRules.js:4；optimization-report-2026-08-25.md §9 |
| M4 | WAF matcher 铁律仅存在于注释，无启动期结构断言；非法 matcher 会静默永不命中 | wafRules.js:57-59 vs WafIdentifier.matchOne return false |
| M5 | MariaDB/TiDB/DM8 以 JSON 深拷贝克隆全量模板（199+199+107），方言化前必须先拆；1290 计数含大量边界变体膨胀 | engine/payloads/index.js 克隆段 |

### 低
| # | 问题 | 证据 |
|---|------|------|
| L1 | gzip 插件用 gzipSync（gzip 容器）却包装 UNCOMPRESS()，MySQL 下不可解压，与 compression.py 的正确配对（deflateSync↔COMPRESS/UNCOMPRESS）冲突 | plugins/gzip.js vs plugins/compression.js |
| L2 | 命名离群：keywordSplit camelCase、0eunion.js→eunion 注册名不一致、_360waf 前缀规避——三种策略并存 | plugins/ 目录清单 + applyTampers.js:80/219 |
| L3 | keywords.js Set 内字面量重复（LEFT/RIGHT/CHAR/DATE/TIME/DATABASE/DISTINCT 等） | keywords.js:16-38 |
| L4 | `{INJECT}` 出现在 2 条注释中但非正式宏，易误导 | mysql.js:146、postgres.js:125 |
| L5 | Cisco_ACE `/\bace\b/i` 等宽匹配误报面偏大；ModSecurity 单一 status 特征即给 0.8 置信度偏高 | wafRules.js:123/18 |
| L6 | 大小写类插件四兄弟（randomcase/randomcaseall/mixedcase/swapcase）效果重叠，mixedcase 仅硬编码 13 关键词 | plugins/mixedcase.js 等 |
| L7 | 203 插件每次扩容需手工同步 import 区 + registerMany 数组两处（已重复 12+ 轮机械操作） | applyTampers.js v3~v22 注释序列 |

### 数据一致性总评
README 三大数字（203 tamper / 62 WAF 指纹 / 71 registry / 1290 模板）经运行时验证**全部准确**；主要风险不在数字造假而在：①防呆断言只建了一半（recommend 名有断言、规则结构与 registry-PAYLOADS 同步没有）；②声明式注册表尚未真正接管检测路径；③直连驱动层的两个功能性缺陷（H1/H2）会让"3 种真实验证"中的 MySQL 通道名不副实。



