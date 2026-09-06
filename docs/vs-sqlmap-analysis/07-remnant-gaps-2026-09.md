# 07-remnant-gaps-2026-09.md — 剩余差距清单（第 7 批体检）

> 生成：2026-09-05 17:00 · 基于：05-parity-audit-2026-09.md + 06-r3-review-and-fixes.md + 全量回归 1316/1316
> 用途：第 6 批三项修复（P2-9 search 漂移 / P2-6 代理凭据 / P2-7 ReportAI opt-in）已闭环，
> 本清单为**剩余未修复项**的当前真实状态（逐项 grep/精读核实），供第 7 批立项。

---

## 一、修复闭环确认（此前遗留，现已完成）

| 项 | 来源 | 状态 |
|---|---|---|
| P0-D3 标记对 tamper 免疫 | 05 审计 §2.1 | ✅ 第一批（tamper-marker-protection） |
| P2-8 `percentage` 缺首字符 | 05 P2-8 | ✅ 第一批 |
| P1 tamper 元数据 terminal/dbms + validateChain | 05 P1 / 06 中影响 | ✅ 第五批 |
| P2-1 后渗透部分：UDF 全链投递 + xp_cmdshell 自动启用 | 05 P2-1 | ✅ 第四批 |
| P1-6 WAF 动态验证推荐（chainVerify） | 05 P1-6 | ✅ 第五批 |
| P2-6 HTTP 代理凭据丢失 | 05 P2-6 | ✅ 第 6 批（buildProxyAgent 注入 auth） |
| P2-7 ReportAI 默认外发 | 05 P2-7 | ✅ 第 6 批（AI_REPORT_API_BASE opt-in，无 base 409） |
| P2-9 search 双实现漂移 | 05 P2-9 | ✅ 第 6 批（复用 Extractor 强实现 + 兜底） |
| tamper 无 dbms 门控 | 06 中影响 | ✅ 随 P1 元数据完成（告警不截断） |
| e2e/tamper-matrix 无语义校验 | 06 中影响 | ⚠️ 部分（chainVerify 已验链，矩阵绕过率口径待查） |

---

## 二、剩余未修复 — 高影响（结构性，建议第 7 批立项）

### G1. boundary→payload 未接线（笛卡尔积缺失）
- **现状**：`probeBoundary` 结果只传给 `fillPayload` 拼 orig；注册表条目自带 `boundary` 字段，但 `selectPayloads` 无消费者。boundary×payload 笛卡尔积 + level 门缺失。
- **对标**：sqlmap `boundaries.xml` × `payloads/*.xml`。
- **验证**：`selectPayloads` 无 boundary 消费点（grep 无笛卡尔积逻辑，仅 sqlite.js 有零星）。

### G2. UNION 无 CAST 类型收口
- **现状**：回显列严格类型（MSSQL/Oracle/PG）时文本/数字标记仍可能类型报错。`DialectSqlBuilder` WRAP 表已存在（`DBFingerprinter.js:75-77` 在用），但 UNION 路径未接。
- **对标**：sqlmap 默认对回显列 `CAST(... AS CHAR)`（`--no-cast` 关闭）。

### G3. useRegistry 双拷贝漂移
- **现状**：默认 `useRegistry:true`，但布尔子句轮在 useRegistry=true 时被跳过（`BooleanBlindDetector.js:63`）；`--level≥2` 需手动显式配置才能吃到子句轮。
- **对标**：sqlmap level/risk 默认渐进。

### G4. 无 `--parse-errors` 等价
- **现状**：错误响应原文不进证据链（仅 `hit.match`）。
- **低成本方案**：错误页原文留存 + SQL 上下文片段正则提取。

### G5. 嵌套 JSON 注入点不支持
- **现状**：bodyParams 仅顶层键（TargetParser.js 确认：level 1 = URL 查询 + POST body 顶层参数）。
- **对标**：sqlmap JSON 嵌套路径注入。

---

## 三、剩余未修复 — P2 长尾（部分）

| # | 差距 | 现状核实 |
|---|---|---|
| P2-1 | **后渗透接管 6/10 未闭环**：`--os-pwn`（反弹/meterpreter/MSF）无；**OLE Automation**（sp_OA*）无 | Exploiter.js 有 udfInstall/xp_cmdshell，无 os-pwn/OLE（grep 空）。UDF 依赖本地 hex（GPLv2 边界，MIT 项目不能内置） |
| P2-2 | **DBMS 版本分支无**：仅识别不分支（MySQL 4/5/8、PG 9/12+、Oracle 11g/19c 运行时差异） | 仅 mysql.js 零星 8.0 分支，无系统化 versionMajor 分支 |
| P2-3 | **MongoDB 无枚举器**（仅检测器 NoSqlInjectionDetector） | Extractor.js 无 nosql 分支（grep 空）；**Access 枚举器实际已有**（extractionMaps.js:218 SYS_QUERIES.Access 完整），非审计时"全 null"——已闭环，勿重复立项 |
| P2-4 | **认证仅 Basic**：Digest/NTLM/客户端证书全无 | httpClient.js 仅 Basic + FORBIDDEN_HEADERS，无 Digest 挑战/NTLM/pfx 双向 TLS（logger 打码正则含 digest 字样非实现） |
| P2-5 | **协议参数原生缺失**：`--hpp`/`--force-ssl`/`--ignore-redirects` 源码零实现（cli.js 无参数、httpClient 无消费）；`--eval` 仅 sqlmap 桥透传+警告不真执行 | grep 全空（仅 sqlmapBridge.js:221 记录 --eval 到 destructive 警告） |

---

## 四、剩余未修复 — 中/低影响（06 文档 82-100 行，逐项核实）

### 中
- **CLI 7 参数静默 no-op**：`--flush-session/--no-cast/--hex/--no-escape/--union-cols/--union-char/--union-from` 内部引擎零消费者（仅桥模式），`--help` 未标注。
- **提取阶段缺陷**：布尔提取未复用 `autoDynamicBlock`（动态页全错）；长度二分上限 255 静默截断；`ASCII()` 多字节 >255 区间错值（中文）；放弃字节置 0 的 NUL 污染。
- **HTTP 代理路径 keep-alive 丢失**（httpClient.js:409-417）；`safeUrlKeeper` 不透传会话 Cookie 头。
- **默认参数比 sqlmap 激进**：timeout 5s/retry 2/ratePerSec 50/concurrency 4（sqlmap 30s/3/不限/1），慢目标+高并发时间判定抖动。
- **WafIdentifier 单特征即 0.8 置信**、status 特征可单独定 vendor（WafIdentifier.js:71）。
- **keywords.js 关键字表小且有重复**，缺 `WAITFOR/DELAY/XP_CMDSHELL`。
- **`-r` 请求文件**：multipart 全漏、JSON body 无候选、仅 `:443` 启发 https、头不过 FORBIDDEN_HEADER_NAMES 黑名单。

### 低
- `--delay` 语义冲突（随机抖动 vs 固定）；`--technique` 不接受 `BEUSTQ` 字母语法、缺 `A`；`--code` 仅映射 true 侧。
- Windows 会话路径盘符大小写误拒（sessionStore.js:25-27）；会话写入非原子（无 tmp+rename）。
- sqlmap 桥报告 60s TTL 即删；桥日志未结构化（technique/payload/dump 全丢）。
- exploit 限流错误码复用 `EXPLOIT_UNAUTHORIZED`（客户端无法区分限流/未授权）；无 `--traffic` 等价全量请求/响应落盘。
- WAF 重跑轮未重跑 boundary 探测（tamper 后响应形态改变原 boundary 失效，scanRunner.js:386-395）；OobDetector dbms 误判时 OOB 静默落空。

---

## 五、第 7 批建议立项（性价比排序）

1. **G1 boundary×payload 接线**（结构性最大缺口，探测→利用核心链路）
2. **G2 UNION CAST 收口**（复用既有 WRAP 表，改动集中、可测）
3. **P2-2 DBMS 版本分支**（识别→打准，18 库中 8 个主库运行时差异）
4. **提取阶段缺陷组**（autoDynamicBlock 复用 / 二分上限 / 多字节 / NUL——真实数据正确性）
5. **P2-5 协议参数**（--hpp 参数污染 + --force-ssl 简单原生实现，CLI 暴露）
6. **G4 --parse-errors 等价**（低成本证据链增强）

> 低优先：P2-4 认证扩展（Digest 可自实现；NTLM/证书依赖库）、P2-1 os-pwn/OLE（高风险+授权边界，建议显式 opt-in 或不做）、tamper priority 排序、CLI 浅层参数语义对齐。

## 附：测试基线
- 第 6 批后：**1316/1316 全绿**（35 suites，~82s，server/ 下 `node --env-file=.env.test --import=./tests/_setup.mjs --test --test-concurrency=3`）
- 环境：D:\projects\sqli-scanner 现**可写**（提权后），后续改动可直接落盘，无需沙箱回拷。
