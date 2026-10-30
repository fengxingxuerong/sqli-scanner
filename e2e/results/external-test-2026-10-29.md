# 外部靶场全方面测试 · 2026-10-29

> 执行者：AI 代理（授权靶场，全部目标为 127.0.0.1 本机靶场）
> 代码版本：`524d4ea`（D190），**工作区 dirty**（本报告落盘前 18 项）⇒ 本报告不对应任何提交
> 环境：Windows + Node v24.22.1 + MariaDB 10.11.19 + PostgreSQL 16.2 + PHP 8.3 + JDK 17 + Maven 3.9.11
> 原始日志：`.box-agent-scratch/external-test-20261029/`（acceptance.log / run-all.log / 五个外部裁判独立日志）

---

## 一、结论速览

| 项目 | 结果 |
|---|---|
| 外部裁判 1–5 号独立跑 | **5/5 通过**（Juice Shop 2/2、VAmPI 2/2、DVWA 5/5、Benchmark 43/43、VulnLab 2/2；安全侧全部零误报） |
| 全量 e2e（`run-all.mjs`） | **36 通过 / 2 失败 / 0 跳过 / 4 未跑**（共 42 个靶场，38 个依赖满足） |
| 全量验收（`acceptance.mjs --require-labs=…`） | **25 PASS / 1 FAIL / 0 SKIP / 0 BLOCKED**，套件范围 26/26 |
| 发现真实缺陷 | **2 个产品级缺陷 + 1 个判据自身缺陷**（详见第三节） |

**不要把上面的「25 PASS」当成绿灯**：唯一那条 FAIL 是真回归，且它在 26 套里排序第一。
按仓内 `§3.5 推翻协议`，它同时把「D190 批次已收口」这个结论打回待推翻。

---

## 二、外部裁判逐个结果

全部为本机真实靶场，真值来自**靶场官方**（非本仓断言）：

| 裁判 | 靶场 | 真值检出 | 安全侧误报 | 关键形态 | 原始日志 |
|---|---|---|---|---|---|
| 1 号 | OWASP Juice Shop 20.3.0（Node 22） | 2/2（search 搜索、login 登录） | 0 | query + JSON body | `juice.log` |
| 2 号 | VAmPI（Flask+SQLAlchemy+SQLite 双实例 5000/5001） | 2/2 | 0/5（同形态参数化实例） | URL 路径段 + Bearer | `vampi.log` |
| 3 号 | DVWA（PHP 8.3 + MariaDB） | 5/5 | 0（impossible 参数化档） | cookie + POST 表单 + 盲注 | `dvwa.log` |
| 4 号 | OWASP Benchmark（Spring + HSQLDB，https/8443 自签） | 43/43 | 0/24 | HTTP header + 参数名注入（50 条） | `benchmark.log` |
| 5 号 | VulnLab（PHP + pdo_sqlite，自拉自收） | 2/2（low 3 条、medium 1 条） | 0/1（high 参数化修复档） | 三档同应用对照 | `vulnlab.log` |

### 引用这些数字必须一起带的口径

- Benchmark 43/43 里**不含** `{call <过程名>}` 形态：本引擎对该形态 **0/4** 检出，属**已知能力边界**，
  不计入分母（安全侧 0/3 误报已单独核对）。引用「Benchmark 全检出」时必须带这句。
- Benchmark 目标为自签 HTTPS，扫描时 `insecureTls=true` **关闭了证书校验**，本次结果不覆盖中间人场景。
- 外部裁判只覆盖自身方言与形态：Juice Shop/VAmPI 是 SQLite 栈，DVWA 是 MySQL/MariaDB，
  Benchmark 是 HSQLDB，VulnLab 是 SQLite。**不能用它们推断 MSSQL/Oracle/DB2 上的能力**。
- 「红队 19/19」是**本仓自建真值**（`e2e/redteam-lab`），与外部裁判不同源，不可混算。
- CRS 类四套断言挂在 **PL1 档基线**（官方默认部署档）；PL3/PL4 档按既有台账结论为全零，本轮未重测。

---

## 三、发现的真实缺陷（本轮测试的净产出）

### 缺陷 1 · `-r / --request-file / -l / --log-file / --check-tor` 五个开关全部失效（产品级）

**症状**：CLI 对这几个开关一律 `exit 2` + 「无法识别的参数」。而 `--help` 里**明文写着**它们（第 28/33/353 行）。

**根因**（已 A/B 定死，非猜测）：D176（`da1b337`）把 `--sql-shell/--os-shell/--fix-prompt`
抽进 `OPTIONAL_VALUE_FLAGS` 表时，在 `server/bin/cli/args.js:153` 插了一句**不以 `else if` 开头**的
`const optionalKey = …`，**把同一条 if/else 链劈成两半** —— 链上半段（含 `-r/-l/--check-tor`）
变成独立语句块，落到末尾 `else if (a.startsWith('-'))` 兜底里 ⇒ 全部被记成未知开关。

```
148| else if (a === '-l' || a === '--log-file') args.logFile = next();
149| else if (a === '--check-tor') args.checkTor = true;
153| const optionalKey = OPTIONAL_VALUE_FLAGS.get(a);   ← 链在这里断了
154| if (optionalKey) args[optionalKey] = peekValue() ?? true;
155| else if (a === '--os-cmd') args.osCmd = next();      ← 新链的开头
```

**A/B 证据**（同一命令，只换 `args.js` 的一个版本）：

| 命令 | D176 之前 | 当前 HEAD |
|---|---|---|
| `parseArgs(['-r','x.txt']).unknownFlags` | `[]` | `['-r']` |
| `parseArgs(['--log-file','y']).unknownFlags` | `[]` | `['--log-file']` |
| `parseArgs(['--check-tor']).unknownFlags` | `[]` | `['--check-tor']` |

复核脚本：`show-chain.mjs`（打印断链上下文）、`args.pre-d176.js`（D176 之前的 args.js 快照）。

**影响面**（不只是命令行不好用）：
- `e2e/detect-surface-lab` 32 条用例里 **10 条**走真 `-r` 入口，全部 `verdict=no-report`；
  其中 5 条安全对照因「0 检出」被记成 **安全误报 5** ⇒ 该靶场判红（`exit 1`）。
  真正原因是入口坏了，报告写的却是「引擎误报」。
- 提交版 `e2e/detect-surface-lab/results/summary.json`（2026-10-25）里这 10 条是 `ok=true` ——
  **10-25 之前 `-r` 是好的**，回归确实发生在 D176（10-26）之后。
- 文档宣传口径「对标 sqlmap -r 导入抓包」当前**不可用**。

**为什么门禁没抓住**：`server/tests/requestFile.importWiring.test.js` 确实从 `-r` 进，
但它调 `parseArgs(['node','cli','-r',f])` 后**直接用返回的 args**，**从不检查 `unknownFlags`**；
而唯一会硬拒的 `unknownFlagError` 只挂在 `cli.js` 入口。⇒ 单测全绿、真实入口是死的
（正是该文件开头自己写的那句教训「只测被调函数、不测调用链」的又一次重演）。

### 缺陷 2 · `auditPlugin` 的 `changed` 计数被 D190 放大（WAF 语义派生判据污染）

**症状**：`coffee / atbash / gzip / xor` 这类**只改字符串字面量**的插件，`changed` 从 **2** 变成 **12**，
同时 `eliminatesAll` 从 `true` 变成 `false`。

**根因**：D190 新增的 `transformSamples()` 在 `outA === input`（插件对该语料无作用）时
**返回 `[input]` 而不是 `[]`**（`semanticIntegrity.js` 的 `return [outA]`），
于是调用方 `if (!samples.length) continue;` 这条「该语料无作用 ⇒ 不参与派生」的闸门**永远不触发**。

**后果**（实测，脚本 `probe-audit.mjs` / `probe-index.mjs` / `probe-rank.mjs`）：

| 指标 | D190 之前 | 当前 HEAD |
|---|---|---|
| coffee / gzip / xor / atbash 的 `changed` | 2 | 12 |
| 同上 `eliminatesAll` | **true** | **false** |
| 语义索引里「宣称能消 select」的定向插件数 | 14 | **27**（多出 13 条 `derived:12` 假覆盖） |
| `scalarselectinline` 在候选里的位次 | **第 5 位** | **第 24 位** |

假覆盖会挤掉真弹药：`planChainsByProfile({blockedTokens:['and','select'], sample:…})`
实测 `maxChains=10/20` 时 `hasScale=false`，`≥40` 才出现 —— 默认 `maxGenerated=3` 根本进不了候选，
即「WAF 拦 and+select」这个最典型场景，定向搜索不再考虑内联改写。

**已确认单测红了**：`server/tests/waf.bypassSearcher.test.js:191 ★探针相关性：样本里真的有 SELECT 时，
内联插件进入候选` —— 稳定复现（连跑 3 次均 16/17），把 `semanticIntegrity.js` 换回 `524d4ea^` 即 **17/17 绿**。
**这条红就是 acceptance 里唯一的 FAIL。**

### 缺陷 3 · `detect-surface-lab` 的判据把「入口坏了」记成「引擎误报」

不是产品缺陷，是**判据缺陷**：`run.mjs` 用 `hit = vulns>0 || exit===2` 判定；
CLI 参数错误也是 `exit 2` ⇒ 被当成「检出」。安全对照于是被记成误报。
对照：该文件对「靶场挂了」有 BLOCKED 保护，但**对「CLI 自己挂了」没有**。
建议同型处理（`exit 2` + 无 `report.json` ⇒ BLOCKED，而不是误报）。

---

## 四、全量 e2e 逐靶场结果（38 跑 / 42 清单）

`node e2e/run-all.mjs`　→ **36 通过 / 0 跳过 / 2 失败 / 4 未跑**
原始日志：`.box-agent-scratch/external-test-20261029/run-all.log`

| # | 靶场 | 结果 | 耗时 | 备注 |
|---|---|---|---|---|
| 1 | redteam-lab | ✅ | 58.6s | 19/26 hit → 判定 PASS |
| 2 | **detect-surface-lab** | ❌ | 54.5s | 真值漏检 0 / 安全误报 5（缺陷 1+3 下游） |
| 3 | retest-lab | ✅ | 1.0s | 请求收敛 82 次 |
| 4 | multi-engine-lab | ✅ | 6.5s | CRS 默认档，只验 safe 零误报 |
| 5 | multi-engine-lab-no-waf | ✅ | 4.1s | tamper on(9) ≥ off(9) |
| 6 | multi-engine-lab-crs-pl1 | ✅ | 4.8s | PL1 9/9 |
| 7 | dialect-templates | ✅ | 1.7s | PASS 16 |
| 8 | tamper-matrix | ✅ | 0.3s | |
| 9 | real-world-lab | ✅ | 13.6s | 二阶注入 + 跨角色门禁 |
| 10 | real-mysql-lab | ✅ | 24.5s | 11/11（隔离沙箱） |
| 11 | param-name-lab | ✅ | 15.8s | |
| 12 | param-mine-lab | ✅ | 2.5s | |
| 13 | api-range-lab | ✅ | 60.8s | 49/49（隔离沙箱） |
| 14 | pentest-lab | ✅ | 15.1s | 11/11，误报 0（隔离沙箱） |
| 15 | waf-real | ✅ | 0.1s | |
| 16 | oob-real-lab | ✅ | 20.9s | 全链路回连命中（隔离沙箱） |
| 17 | oob-interactsh-lab | ✅ | 10.9s | 14 DNS + 14 HTTP |
| 18 | juice-shop-lab | ✅ | 12.7s | 外部裁判 1 号 |
| 19 | vampi-lab | ✅ | 5.8s | 外部裁判 2 号 |
| 20 | dvwa-lab | ✅ | 36.0s | 外部裁判 3 号 |
| 21 | benchmark-lab | ✅ | 18.8s | 外部裁判 4 号 |
| 22 | vulnlab-lab | ✅ | 2.8s | 外部裁判 5 号 |
| 23 | extract-proof | ✅ | 5.2s | 真库名非残片 |
| 24 | pg-osshell | ✅ | 2.2s | COPY FROM PROGRAM 回显 |
| 25 | concurrent-isolation | ✅ | 12.5s | 隔离沙箱 |
| 26 | csrf-lab | ✅ | 11.2s | 隔离沙箱 |
| 27 | crawl-lab | ✅ | 13.5s | scope 纪律 |
| 28 | file-read | ✅ | 11.2s | 隔离沙箱 |
| 29 | file-write | ✅ | 11.2s | 隔离沙箱 |
| 30 | random-battery | ✅ | 14.3s | 召回 75.7% ≥ 70%，误报 0/12 |
| 31 | recall-lab | ✅ | 1.0s | 零误报 |
| 32 | detection-runner | ✅ | 14.2s | 19 PASS / 0 FAIL |
| 33 | udf-lab | ✅ | 15.3s | 命令执行真实回显 |
| 34 | **waf-lab** | ❌ | 10.4s | `EADDRINUSE: 8099` 与常驻 DVWA 冲突 |
| 35 | batch-lab | ✅ | 69.9s | |
| 36 | login-lab | ✅ | 4.5s | 含「不给登录则 0 检出」对照 |
| 37 | signed-api-lab | ✅ | 16.2s | 三族 × 12 场景 |
| 38 | bearer-lab | ✅ | 9.1s | 续期闭环 |
| — | mssql-lab | ⛔ 未跑 | — | 缺 MSSQL:65039 |
| — | mssql-oshell | ⛔ 未跑 | — | 缺 MSSQL:65039 |
| — | mssql-dump | ⛔ 未跑 | — | 缺 MSSQL:65039 |
| — | oracle-lab | ⛔ 未跑 | — | 缺 Oracle:1521 |

`waf-lab` 失败**已定性为环境冲突、非产品缺陷**：默认端口 8099 与常驻 DVWA 撞车；
`WAF_LAB_PORT=8199 node e2e/run-all.mjs --only waf-lab` 复跑 **20.6s 通过**
（输出：`tamper 确已绕过 WAF ✅`）。

完整现场：`e2e/results/last-failure-detect-surface-lab.log`、`e2e/results/last-failure-waf-lab.log`。

---

## 五、全量验收逐套件结果（26/26）

`node e2e/acceptance.mjs --require-labs=mariadb,dvwa,vampi-vuln,vampi-safe,juice,benchmark-db,benchmark-app`
→ 前置体检 8/8 在监听 ⇒ **0 SKIP 的前提成立**
原始日志：`.box-agent-scratch/external-test-20261029/acceptance.log`
报告落盘：`e2e/results/acceptance-report.md`

| # | 套件 | 结果 | 事实 |
|---|---|---|---|
| 1 | 服务端单测 | ❌ **FAIL** | tests=3879 pass=3872 **fail=1** skipped=6 |
| 2 | 独立刁钻靶场（11 场景） | ✅ | 漏洞场景 11/11 安全误报 0 |
| 3 | 检测回归（19 场景） | ✅ | PASS=19 FAIL=0 |
| 4 | 真 MySQL 靶场 | ✅ | PASS=11 FAIL=0 |
| 5 | 参数名注入真靶场 | ✅ | PASS=1 FAIL=0 |
| 6 | 参数挖掘真靶场 | ✅ | 开挖掘 3/3 关挖掘 0 安全点 0 |
| 7 | 真 PG 靶场（含二阶注入） | ✅ | 全部通过=true 引擎=PGlite |
| 8 | 批量编排故障隔离 | ✅ | PASS=1 FAIL=0 |
| 9 | 登录编排自动重登 | ✅ | PASS=1 FAIL=0 |
| 10 | OOB 带外通道真机 | ✅ | 真实回连 ✅ 对照组 0 检出 |
| 11 | OOB 外部隧道真机 | ✅ | 14 DNS + 14 HTTP，背景哨兵 1 条 |
| 12 | 第三方真框架外部裁判（Juice Shop） | ✅ | 真值 2/2 漏检 0，安全端点误报 0 |
| 13 | 外部裁判 2 号（VAmPI） | ✅ | 真值 2/2，误报 0/5，Bearer 端点 5 个未测 0 |
| 14 | 外部裁判 3 号（DVWA） | ✅ | 真值 5/5，误报 0，形态 cookie+POST+盲注+impossible |
| 15 | 外部裁判 4 号（Benchmark） | ✅ | 真值 43/43，误报 0/24，call 形态安全侧 0/3 |
| 16 | 外部裁判 5 号（VulnLab） | ✅ | 真值档位 2/2，修复档误报 0/1，三档真跑 |
| 17 | 数据泄露实证 | ✅ | 10 个真库名，残片取不到，漏洞 3 请求 142 |
| 18 | 报告契约 | ✅ | 通过 8 不一致 0 |
| 19 | CRS 人工挂链 A/B（PL1） | ✅ | off=8 on=8，安全对照误拦 false |
| 20 | CRS 自动选链绕过（PL1） | ✅ | 技术位 8 ≥ 8，安全误报 0 |
| 21 | CRS 执行器保真度 | ✅ | 99.6%，未点名分歧 0，误触 2 |
| 22 | WAF 定向变异搜索（A2） | ✅ | A 档 2 / B 档 0，验证 6/6 |
| 23 | WAF 通道降级编排（A3） | ✅ | 画像/决策拦截面如列 |
| 24 | 红队实战评测 | ✅ | 检出 19/19，安全点 7 误报 0 |
| 25 | fileRead 真闭环 | ✅ | PASS=true SKIP=false |
| 26 | fileWrite 真闭环 | ✅ | PASS=true，文件落盘 true |

**汇总：25 PASS / 0 BLOCKED / 1 FAIL / 0 SKIP，套件范围 26/26**

唯一 FAIL 的定位与 A/B 证据见第三节缺陷 2。

---

## 六、本轮没做到 / 没测到的（必须一起披露）

1. **MSSQL / Oracle 四个靶场零断言**（缺实例）。本报告**不支持**任何关于这两种方言能力的结论。
2. **`run-all.mjs` 的 `waf-lab` 默认端口与 DVWA 冲突**：常驻外部靶场时全量回归必红一处。
   本轮用 `WAF_LAB_PORT=8199` 绕过；属跑法问题，但容易被读成产品失败，建议修端口策略。
3. **Juice Shop 供应物路径与默认值不符**：`scripts/lib/labs.mjs` 默认找 `.verify-labs/juice-shop-20.3.0`，
   本机实际构建在 `.box-agent-scratch/labs-20261021/juice-shop-20.3.0`，需 `JUICE_DIR` 手工指。
   `labs.mjs --migrate` 报「旧供应物目录不存在」（旧 `%TEMP%\verify-labs` 已不在）——
   D188/D191 的迁移脚本在这台机器上**没有可迁移对象**，属空跑，不构成验证。
4. **`--help` 与 parseArgs 的其余不一致**（本轮顺手审计 191 个 help 开关，脚本 `flag-audit.mjs`）：
   `--version/-V` 由 `cli.js` 前置处理（正常，非缺陷）；`--auth-cred / --time-threshold / --reqrate`
   只在 help 正文里作为**类比提及**（不是开关声明），**不算缺陷**，但易被读成开关 —— 建议 help 改写。

---

## 七、建议处置顺序（未执行，等确认）

1. **P0** 修 `args.js:153` 断链（`const optionalKey` 提到循环顶部，或改回 `else if` 链），
   并补一条**从 `cli.js` 入口进、断言 `unknownFlags` 为空**的守卫（否则同一断链还会再发生）。
2. **P0** 修 `transformSamples` 的 nop 分支（`outA === input` 应返回 `[]`），恢复
   `changed` / `eliminatesAll` / 定向候选排序；`waf.bypassSearcher.test.js:191` 转绿即验收。
3. **P1** `detect-surface-lab`：`exit 2 + 无 report.json` 判 BLOCKED，不判误报。
4. **P1** `waf-lab` 端口策略（默认端口与常驻 DVWA 冲突）。
5. **P2** `JUICE_DIR` 默认值补旧路径回退，避免每台机器手工设环境变量。

任一项修完，**本报告结论都要重跑**再引用 —— 尤其第一节那张速览表。
