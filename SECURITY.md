# Security Policy

## 报告漏洞（Reporting a Vulnerability）

如果你发现 sqli-scanner 的安全漏洞（引擎 DoS、SSRF 绕过、凭据泄露、RCE 等），**请勿公开提交 issue** —— 先通过私有渠道报告：

- 首选：向项目维护者发送私有消息 / 邮件（详见仓库主页联系方式）
- 次选：在 GitHub 上创建 **Security Advisory**（若仓库已开启 private vulnerability reporting）

请附上：受影响版本、漏洞类型、复现步骤（含最小 PoC）、影响范围与建议修复。我们会在收到报告后 **72 小时内** 确认并评估。

## 安全设计基线（本项目的威胁模型）

sqli-scanner 是**攻击性安全工具**，自身也是攻击面的一部分。以下基线是防护的边界，改动时不得弱化：

### 1. 引擎边界（本地优先）
- 默认只监听 `127.0.0.1`；暴露到非回环接口（`HOST=0.0.0.0`）时必须设置 `SCAN_API_TOKEN` + `SSRF_STRICT=1`，否则启动打显著告警
- API Token 恒时比较（SHA-256 归一 + timingSafeEqual）；SSE 经 query token 兜底（EventSource 无法设 header）

### 2. SSRF 防护（最高优先级）
- 出站请求统一经 `core/httpClient.js`：分层拒绝（元数据/链路本地无条件拒绝；`SSRF_STRICT` 加拒回环/私网）+ DNS 解析校验 + **DNS 钉死**（防 rebinding）+ 重定向逐跳重新校验
- 发现/爬取阶段同样受限速与 SSRF 校验（per-scan 桶）
- 报告脱敏：URL 内嵌凭据、认证头、Cookie、敏感键值在日志/SSE/报告外泄前一律打码

### 3. 利用能力红线（EXPLOIT_ENABLED）
- 利用端点（sql-shell / file-read / file-write / os-shell）默认关闭，需 `EXPLOIT_ENABLED=1` + 每次请求声明 `authorized: true` + 独立限速桶
- 二阶注入/OOB 带外检测默认关闭（开启即对目标发真实写请求/出站请求）

### 4. 数据安全
- `localStorage` 落盘前剥离认证/代理凭据；会话文件落盘剥离 config.auth/proxy
- AI 报告链路：evidence 进 prompt 前 JSON 包裹 + 截断（防 prompt 注入）；目标 URL 脱敏后外送 LLM
- 拖库/提取路径：标识符/字符串转义防二次注入；响应体积上限防 OOM

### 5. Tauri 桌面壳
- 严格 CSP（`default-src 'self'` 基线）；仅保留 sidecar 所需的 `shell:allow-spawn`，移除 `shell:allow-execute`
- 前端渲染任何来自数据库/目标的不可信内容（拖库行、payload 证据）时按纯文本/转义处理

## 报告处置流程

| 阶段 | 时限 | 动作 |
|---|---|---|
| 确认 | 72h | 复现并确认受影响版本 |
| 修复 | 视严重度 | Critical/High 优先修复并发布补丁 |
| 披露 | 补丁发布后 | 默认 14 天后公开摘要 |

## 安全相关环境变量（配置不当=风险）

| 变量 | 风险 |
|---|---|
| `HOST=0.0.0.0` 且无 token | 无鉴权扫描代理/拖库代理 |
| `SSRF_STRICT=0` + 公网部署 | 目标可被诱导向内网发起请求（SSRF） |
| `EXPLOIT_ENABLED=1` 且未授权 | 任意 SQL/文件/命令执行 |
| `AI_REPORT_KEY_*` 提交进仓库 | API 密钥泄露 |
| `ALLOWED_ORIGINS` 含不可信源 | 跨域滥用（配合无 CSP 的 Tauri 可升级为 RCE） |

## 测试与安全门禁

- CI 强制：TypeScript、ESLint、前端覆盖率阈值、服务端 1249 测试、recall-lab 18 场景、Rust fmt/clippy
- 改动涉及 HttpSClient/SSRF 逻辑必须补测试（`httpClient.*.test.js`）
- 新增出站点/端点：确认默认关闭或受 EXPLOIT_ENABLED 门控