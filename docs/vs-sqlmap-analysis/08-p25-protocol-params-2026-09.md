# 08 - 第 7 批修复交付：P2-5 协议参数三件套（--force-ssl / --ignore-redirects / --hpp）

- 日期：2026-09-05
- 范围：server/（CLI + httpClient + ScanManager + injection + defaults + 测试）
- 基线：1316/1316 全绿（35 suites ~82s）→ 交付后 **1338/1338 全绿**（35 suites 82.9s，+22 新用例）

## 一、背景

06/07 文档核实结论：P2-5「协议参数原生缺失」为真·未实现——`--hpp / --force-ssl / --ignore-redirects` 在 CLI 参数解析区与源码中完全无实现（此前仅 sqlmap 桥透传，属"记录+警告"不真执行）。本批补齐原生实现，全部对标 sqlmap 同名参数语义。

## 二、改动清单（5 源文件 + 3 测试文件）

### 1. server/bin/cli.js
- parseArgs 新增三开关：`--force-ssl` / `--ignore-redirects` / `--hpp`（布尔 true）
- buildConfig 透传：`config.forceSsl` / `config.ignoreRedirects` / `config.hpp`
- printHelp 帮助文本新增三行（与 --mobile 同段）

### 2. server/src/core/httpClient.js
- `request()`：SSRF 校验**前**改写 URL——`opts.forceSsl && http:// 前缀` → 替换为 `https://`（仅改协议，host/port/path/query/fragment 原样；后续 SSRF 校验/DNS 钉死/代理全作用于改写后 URL）
- `request()`：`redirectsLeft = opts.ignoreRedirects === true ? 0 : 5`
- `_followRedirects(…, redirects)` / `_followRedirectsH2(…, redirects)`：新增第 7 参 redirects（`?? 5` 保持默认），调用点传 redirectsLeft——ignoreRedirects 时 3xx 首跳即返回，零跟随
- HTTP/1.1 与 HTTP/2 双路径一致覆盖

### 3. server/src/engine/ScanManager.js（getScanClient）
- 在 forScan 视图之上加**协议策略层**：读 `target.config.forceSsl/ignoreRedirects`，为 true 时包装 request 把键并入每个 opts
- 与 `withSafeUrl` 同款位置（safeUrl 包装之后），Detector/Extractor/二阶/NoSQL/WAF 全路径统一生效；无配置时零开销原样返回（存量扫描零行为变化）
- `...view` spread 使 headRequest（--null-connection）一并继承

### 4. server/src/engine/injection.js（buildInjectionRequest）
- HPP 落点：`point.location === 'url'`（GET query 注入点）+ `config.hpp === true` + **注入请求**（injected ≠ originalValue）时，把注入值额外写入 `req.data[param]`（query+body 同名双份）
- 基线请求不双份（值=原始值时保持原样，不污染基线）；body/cookie/header/path/direct 注入点不受影响
- 语义对标：WAF 常只查 query 单侧/首份，后端解析差异（ASP.NET/IIS 首份、PHP/Node qs 末份、网关拼接两侧）→ 绕过检测（CAPEC-460）

### 5. server/src/config/defaults.js
- 新增默认键：`forceSsl: false` / `ignoreRedirects: false` / `hpp: false`（含注释说明消费方）

### 6. 测试（3 新文件，22 用例）
- `tests/httpClient.protocol.test.js`（8）：forceSsl http→https 改写（含端口/query/fragment 保留、已 https 不改写、未开启回归护栏）；ignoreRedirects 3xx 首跳即返回（rawCalls=1）、默认仍跟随 5 跳（rawCalls=6 回归护栏）、http2 路径同样忽略、200 正常响应不受影响
- `tests/cli.protocol.test.js`（9）：parseArgs 三开关解析 + 默认 false + 三开关共存不吞后续参数；buildConfig 透传三键 + 未开启回归护栏
- `tests/injection.hpp.test.js`（5）：GET query 注入双份进 body；基线不双份；未开 hpp 不双份；body 注入点不受影响（formValues 保留）；direct 模式无 URL 不受影响

## 三、设计要点与边界

| 参数 | 消费层 | 生效范围 | 边界 |
|---|---|---|---|
| --force-ssl | httpClient.request | 全部请求 | 仅改写 http:// → https://，不触碰 host/port；SSRF 校验在改写后执行 |
| --ignore-redirects | httpClient.request | 全部请求 | 3xx 直接返回（含 http2 路径）；目标上行 302 登录跳转会暴露 3xx，检测判定以状态码/头为准需知悉 |
| --hpp | buildInjectionRequest | 仅 GET query 注入点、仅注入请求 | 基线不双份；body/cookie/header/path/direct 不受影响 |

配置传递链：CLI parseArgs → buildConfig（config.forceSsl/ignoreRedirects/hpp）→ target.config → ScanManager.getScanClient 协议策略层（forceSsl/ignoreRedirects 注入每请求 opts）→ httpClient.request；hpp 由 buildInjectionRequest 直接读 target.config.hpp（9 处调用方统一受益，单点改动影响面最广）。

## 四、验证

- 单测：httpClient.protocol 8/8、cli.protocol 9/9、injection.hpp 5/5
- 全量回归：1338/1338 通过（35 suites，82926ms），0 失败 0 跳过
- 基线对比：上轮 1316（35 suites）→ 本轮 1338，+22 全为新用例，无既有用例破坏

## 五、遗留（P2-5 之外，供后续批参考）

- 真·未实现剩余：P2-1 os-pwn（反弹/meterpreter/MSF）、OLE Automation（sp_OA*，有 GPL 授权约束）；P2-2 DBMS 版本分支（运行时差异切 payload，仅识别不分支）；P2-4 认证仅 Basic（Digest/NTLM/客户端证书 pfx 双向 TLS 无）；P2-3 MongoDB 枚举器（仅检测器）；tamper priority 排序；-r 请求文件 multipart 解析缺失
- G/D 类（06-r3-review 已列）：boundary×payload 笛卡尔积未接线（已核实大部分过时，见 07 文档）；CLI 7 参数静默 no-op（--flush-session/--no-cast/--hex/--no-escape/--union-cols/--union-char/--union-from）
