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

### C. `--test-path` 的闭合候选在 404 段上是噪声（未修）
实测 `/api/sleep` 开 `--test-path` 时，path 点拿到 boundary `%"` —— 13 个候选的响应全是同一张
404 页（Express 回显 URL），剔除回显后仍偶有同形判定。path 点本身没洞无所谓，但它会**触发**
整轮指纹/列数探测（每次 ~40 请求）。修法方向：path 点基线为 4xx 时不投放闭合探测（或指纹
提前 bail），既省请求也少一份误判来源。

### D. 靶场侧缺陷（已就地修一处，其余待扫）
`e2e/blackbox-lab/lab-app.mjs` 的 `/api/profile` 对 Cookie 值做 `decodeURIComponent`，收到
`%'` 这类非法转义就在 **async handler** 里抛 URIError → Express 4 不捕获 async 异常 →
该请求**永不应答**，把 D3 的整个测段拖成分钟级停顿（真值标定用 `uid=1` 碰不到，所以一直没暴露）。
已加 try/catch 并注明「改的是靶场不应无端挂连接，SQL 拼接形态一字未改」。
**待办**：其余 e2e 靶场（redteam / real-mysql / multi-engine / pentest-lab）同一形态
（async handler + 未包 try 的 decode/parse）值得一次性扫掉，否则下一个漏检又会归因到引擎。

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
| `1 UNION SELECT NULL,…`（尾 `-- -` / `-- ` / `#` 三形态都试） | **全部 403** | **942361**（UNION SELECT 短语） |
| `1 UNION SELECT 'SQLISCANNER…'` | 403 | 942200（单引号字面量） |
| `alice' UNION SELECT NULL,…#`（字符串上下文） | **200** | 未命中 |

即：**同一条 UNION 探针，数值上下文被 942361 拦、字符串上下文放行**；而 `dash2hash` 只规整尾部注释符，
对 942361 无效。所以这两格不是"判据判错"，是**请求在 WAF 层就到不了数据库**。
本批改动已排除（把动过的 4 个引擎文件回退到 `ebc660a^` 重跑，结果逐字相同）。
至于 09-10 那次为什么算进过 10：`e2e/waf-real/results/` 不入库、旧报告没留档，**已无从核对**；
有一条可检验的猜测 —— 当时的链含 `space2comment`，`UNION/**/SELECT` 正好拆开 942361 要的相邻性，
而 `/**/` 同为 4 连非词字符会触发 942460，于是它被摘掉（见 `waf-verify.mjs` 的「组合修正」注释），
**摘它的同时带走了这两格**，而 README 的数字没人跟着复测。本条按「合理代价 + 口径下修」结案，
不做"退化了 2 位"的断言。正面把这两格拿回来另立 I 条。

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

### H. udf-lab step6 的归因文案会把人带偏（未修）
`sys_eval('cmd /c echo <ASCII marker>')` 偶发捕获为空时，step6 的 note 固定写
「典型：Windows 本地化 whoami 的 GBK 输出」。marker 是纯 ASCII，这句话把人往编码方向带，
而实际形态是**输出捕获为空**。改成按实测分支给原因（空捕获与"不可字符化"是两回事）。

### I. 严格档 CRS 下数值点的 union 怎么拿回来（未做，本批已把可行/不可行分开）
F 条的探针表给出：**换分隔符这条路对 942361 完全无效**（`/**/`、`%0a`、`%09`、双空格、`UNION ALL`
八种形态全部 403，且这些形态不套 WAF 时 MySQL 全部正常执行）。原因是该规则的判据是
`^[\W\d]+\s*?(?:alter|union)\b` —— 打的是**参数值起始形状**，不是 UNION/SELECT 相邻性。
数值点 `id=1…` 必然以数字开头 → 命中；`alice'…` 以字母开头 → 不命中。
可做的两条（都要实测，别再抄"sqlmap 这么干"）：
1. **改起始形状**：让投放值不以 `[\W\d]` 直接接 `union`。候选是 `space2plus`/`spatialessuffix`/
   `versionedmore` 这类，或在数值前拼一个词字符再靠 SQL 语义消化掉（`1x` 非法；`1/*x*/UNION`… 需实测）
   —— 先写一条 `e2e/waf-real/probe-*-shape.mjs` 单点探针（纯发请求，几秒出结果）筛掉无效形态。
2. **换档测量**：942361 官方注释写明属 **PL2**，而 `e2e/waf-real/crs-engine.js` 默认全规则（≈PL3 最严档）。
   `evaluate(req, { paranoiaLevel })` 已有参数，只是各靶场的中间件调用处没传 → 加一个 `CRS_PL` 环境变量，
   把 **PL1（CRS 默认部署档）** 的绕过率一并测出来。现在 README 的 8/8 只有最严档，
   拿它当"典型线上值"会**低估**自己在真实默认部署下的表现（也会低估对手）。

验收：任一形态让 `num`/`blind` 的 `on.found` 出现 `union`，且 `safe`/`echo` 两个对照仍零误拦；
或 README/评估报告里同时给出 PL1 与 PL3 两档数字。

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
