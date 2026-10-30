# sqli-scanner 用户手册

SQL 注入检测工具（SQLi Scanner）—— 一份代码、双形态（Web 全栈 + Tauri 桌面壳）的自动化 SQL 注入检测工具。

### 功能特点

- **AI 漏洞报告**：扫描完成后一键调用 AI 模型（deepseek-v4-flash / sensenova-6.8-flash-lite / glm-5.2）生成自然语言漏洞描述与修复建议；预置 3 组 API key × 3 个模型共 9 种组合可选。

> **仅用于授权环境下的安全测试与学习，禁止用于未授权目标。** 破坏性操作（拖库 / 文件读写 / OS Shell）均需显式确认。

**界面语言切换**：顶部导航栏右侧有「中/EN」切换按钮，支持中文与英文界面，选择后持久化到 localStorage（下次打开保持上次语言）。

---

## 一、两种形态

| 形态 | 启动方式 | 说明 |
|------|------|------|
| Web 版 | `npm run server` + `npm run dev` | 浏览器访问 `http://localhost:5173` |
| Tauri 桌面版 | `npm run tauri dev` | Rust 壳以 sidecar 拉起引擎进程 |

---

## 二、启动

### 2.1 Web 版

```bash
# 1. 安装依赖（仅首次）
npm install
cd server && npm install && cd ..

# 2. 启动检测引擎（终端 A，监听 127.0.0.1:4567）
npm run server

# 3. 启动前端（终端 B，:5173）
npm run dev
```

浏览器打开 `http://localhost:5173`。

### 2.2 Tauri 桌面版

```bash
# 先将 server/ 打成单文件可执行放入 src-tauri/binaries/sqli-engine
npm run build:engine

# 启动桌面壳（需安装 Rust 工具链）
npm run tauri dev
```

### 2.3 CLI 模式（脚本化 / CI）

```bash
node server/bin/cli.js -u "http://target/page?id=1"
node server/bin/cli.js -u "http://target/login" --method POST \
  --body '{"username":"admin","password":"x"}' --format markdown -o report.md
```

| 选项 | 说明 |
|------|------|
| `-u, --url` | 目标 URL（必填） |
| `--method` | GET / POST / PUT / PATCH / DELETE（默认 GET） |
| `--body` | POST body（JSON 对象字符串） |
| `-r, --request` | 请求文件导入（Burp/curl HTTP 请求文本），自动解析 URL / method / headers / body / Cookie |
| `--cookie` | Cookie 串 |
| `-f, --format` | json / html / csv / markdown（默认 json） |
| `-o, --out` | 报告输出文件（缺省打印 stdout） |
| `--timeout` | 整体等待上限（默认 30000ms） |

退出码：`0`=完成（低风险）、`2`=发现 Critical/High 漏洞、`1`=执行失败。

---

## 三、扫描流程

1. **选引擎**：默认「自带引擎（教学/合规）」，或切到「sqlmap 高级模式」（需 `SQLMAP_PATH` 或克隆到 `server/tools/sqlmap`）。
2. **填目标**：URL + 方法（GET/POST/PUT/PATCH/DELETE）+ Body/Cookie/Header（JSON）。
3. **（可选）标记注入点**：在参数值末尾加 `*`，仅测该参数（见 §五）。
4. **配参数**：并发 / 超时 / 重试 / 限速 / 检测技术 / WAF 规避 / 代理 / 认证。
5. **开始扫描**：拖库等破坏性操作会弹二次确认框。
6. **看结果**：实时进度区滚动事件流；完成后「查看报告 →」进入报告页。

---

## 四、关键配置项

> **本节只讲最常用的配置**；**CLI 的全部 168 个开关**见 README 的「CLI 能力速查（按用途分组）」
> 或直接 `node server/bin/cli.js --help`（两者由 `npm run readme:check` 的 ⑯/⑰ 判据钉死一致）。
> ⚠️ 本文件是**上手指南**，不承担参数全表的职责——全表在 README，这里不重复（避免两处漂移）。

| 配置 | 默认 | 说明 |
|------|------|------|
| concurrency | 6 | 并发检测线程（1-10） |
| timeoutMs | 10000 | 单请求超时（ms，可调 1000-60000） |
| retry | 2 | 失败重试次数（0-5） |
| timeThresholdMs | 3000 | 时间盲注判定阈值（ms） |
| ratePerSec | 5 | 请求限速（令牌桶，req/s） |
| enableExtract | true（UI 二次确认） | 拖库开关 |
| proxy | 无 | HTTP/HTTPS/SOCKS5 代理 |
| auth | 无 | Basic / Cookie / 自定义 Header 认证 |
| level | 1 | 检测等级 1-5（越高 payload 越全、越慢） |
| risk | 2 | 风险等级 1-3（1 仅 union/error/boolean；2 含 time/stacked/oob；3 额外 OR 变体） |
| prefix / suffix | 空 | payload 前缀/后缀（对标 sqlmap `--prefix` / `--suffix`，见 §4.2） |
| sessionDefault | false | 断点续跑（见 §4.3） |
| crawlDepth | 1 | 站内链接爬取深度 0-3（对标 sqlmap `--crawl`，发现更多参数入口） |
| techniques | union/error/boolean/time/stacked | 检测技术（OOB/内联按需勾选） |
| wafEvasion.tamper | 关 | tamper 链式绕过（225 插件 + 强度预设，WAF 识别 62 厂商自动推荐） |

### 4.1 检测强度分级（level / risk）

对标 sqlmap `--level` / `--risk`，在内置引擎「高级设置 → 检测强度」中调节：

- **level（1-5）**：payload 复杂度与边界探测强度。1 为默认快速档，5 最深最全（也最慢）。
- **risk（1-3）**：是否尝试可能影响数据完整性的高破坏性向量。risk 1 最保守（无写请求、无长时间等待）；risk 2 为默认（含 time/stacked/oob）；risk 3 额外尝试 OR 变体布尔测试。

### 4.2 payload 前缀/后缀（prefix / suffix）

对标 sqlmap `--prefix` / `--suffix`：在注入点**原参数值前**拼接 `prefix`、在 **payload 之后**拼接 `suffix`，用于手工闭合引号/括号再注释掉尾部。默认空串 = 不拼接；仅影响被注入参数值，不影响基线请求。例：参数值 `1'` 场景可配 `prefix="1' "`、`suffix="-- "`。经 `POST /api/scan/start` 的 `config.prefix` / `config.suffix` 传入（≤200 字符）。

### 4.3 会话持久化 / 断点续跑（resume）

对标 sqlmap `--session` / `--resume`：

| 配置 | 说明 |
|------|------|
| `sessionDefault: true` | 扫描自动用固定文件名 `sqli-session-latest.json` 落盘；下次对**同一 URL** 扫描自动 resume——已完成注入点直接跳过（SSE 可见 `point_skipped` 事件），复扫近乎 0 请求 |
| `sessionFile: "名称"` | 显式指定会话文件（白名单校验：仅工作目录文件名或系统临时目录，拒绝绝对路径/`..`） |

「高级设置 → 会话持久化」开关即 `sessionDefault`；历史记录若带会话配置，「续跑」按钮会携带原配置 + `sessionFile` 重新发起。会话文件落盘前自动剥离认证/代理凭据。

### 4.4 OOB 带外检测（HTTP / DNS 双通道）

无回显盲注的兜底通道，默认关闭。开启需同时：检测技术勾选 `oob` **且** `config.oob.enabled=true`。接收端一次启动同时拉起两个监听：HTTP 通道（默认 8899，检测器自动生成回调 URL 并等待回连）；DNS 通道（UDP 53，需管理员权限，任何 A/AAAA 查询的首个子域标签都会登记进同一 token 池——DNS 出站几乎不被防火墙拦，适合仅放行 DNS 的受限出口，启动失败自动降级仅 HTTP）。DNS 端口/域名经环境变量 `OOB_DNS_PORT` / `OOB_DNS_DOMAIN` 配置。详见 [faq.md §七](./faq.md)。

### sqlmap 高级模式专属

| 配置 | 默认 | 说明 |
|------|------|------|
| level | 1 | 检测等级 1-5（越高越全、越慢） |
| risk | 1 | 风险等级 1-3（越高越可能触发破坏性） |
| techniques | BEUT | 技术字母 B/E/U/S/T/Q |
| threads | 1 | 并发线程 1-10 |
| dbms | 自动 | 指定后端 DBMS |
| dump / osShell / fileRead | 关 | 破坏性操作（需二次确认） |
| proxy / timeoutMs / retry / randomUA | — | 请求控制透传 |
| unionChar / unionFrom / smart / noCast / hex / noEscape | — | 对标 sqlmap `--union-char` / `--union-from` / `--smart` / `--no-cast` / `--hex` / `--no-escape` |

---

## 五、注入点精确指定（对标 sqlmap `-p`）

在**任意参数值末尾加 `*`**，仅测试该注入点：

- URL 查询：`http://target/page?id=1*&foo=bar`
- URL 路径：`http://target/api/v1/users/1*/profile`
- Body：`{"id":"1*","other":"x"}`
- Cookie：`{"sid":"abc*"}`
- Header：`{"X-Forwarded-For":"1*"}`

未标记时引擎自动发现全部参数（URL 查询 / Body / Cookie / Header）。目标录入区会实时提示「已标记注入点」。

---

## 六、报告解读

- **漏洞列表**：风险 + 技术 + 注入点 + 数据库标识（DBMS）。
- **漏洞详情**：注入点、数据库、说明、**证据（Evidence）**、**请求报文（方法 + URL + 关键头 + Payload）**，可据此人工复现。
- **盲注时间线**：布尔 / 时间盲注的统计判定证据链（基线采样、真假对、z 值）。
- **拖库树**：库 → 表 → 列 → 数据（前 20 行预览）；每个表节点可单独**导出该表 CSV / JSON**（纯前端从当前报告切片生成，无需后端会话存活，历史回溯也可用）。

### 风险定级

| 等级 | 含义 |
|------|------|
| Critical | 可拖库 / 堆叠注入 |
| High | 联合查询 / 报错回显 |
| Medium | 布尔 / 时间盲注 / OOB |
| Low | 单点疑似 |

---

## 七、导出格式

| 格式 | 说明 |
|------|------|
| JSON | 完整报告（漏洞 + 拖库 + 证据） |
| HTML | 内联样式单页表格，离线可打开 |
| CSV | 漏洞表 + 拖库数据（Excel 不乱码） |
| Markdown | 适合贴工单 / 报告 |
| DB JSON | 仅拖库数据部分 |
| 单表 CSV / JSON | 拖库树表节点上的「导出该表」按钮，仅导出当前表（含列头，正确转义逗号/引号/换行） |

历史记录存 localStorage（最多 100 条），认证 / 代理凭据已脱敏。

### 修复提示词（`--fix-prompt`，[D176]）

报告是给人读的交付物；如果下一步要**交给编码代理去改代码**，加 `--fix-prompt`：

```bash
node server/bin/cli.js -u "https://target/items?cat=1" -o out/ --fix-prompt
# 产出 out/fix-prompts/{README.md, fix-01-cat.md, …}
# 带值则直接写进指定目录：--fix-prompt ./fixes
```

每条命中一份 Markdown，固定四段：**为什么能注入**（按检测通道）/ **该怎么改**（参数化查询、
标识符白名单、账号降权等）/ **改完怎么验**（可直接复制的复测命令 + 期望 `0 条 finding`）/
**结论口径**（`verdict=inconclusive` 或存在未验证面时先声明——那是"没测成"，不是"没修好"）。

它**不自动修改代码**，也不猜业务语义；`vulns: []` 时只产出一份说明本次无命中的索引。

### AI 自然语言报告（`--ai-report`，[D205]）

JSON / HTML 报告是给机器和评审看的；要一份**能直接贴进 SRC 工单**的自然语言报告，加 `--ai-report`。
此前只有 REST 面板（`POST /api/scan/:id/report/ai`）能生成，CLI 扫完只有 JSON —— [D205] 补上入口：

```bash
export AI_REPORT_API_BASE=http://127.0.0.1:8326/v1/chat/completions   # 完整 chat 端点（不是 base）
export AI_REPORT_KEY_1=<你的 key>
export AI_REPORT_MODEL_1=deepseek-auto/deepseek-v4-flash              # 自建/本机网关要求 provider/model 全名
export AI_REPORT_MODEL_2=deepseek-auto/glm-5.2
export AI_REPORT_MODEL_3=raccoon/sn-sensenova-6-8-flash-lite

node server/bin/cli.js -u "https://target/login" --method POST --body '{"uid":"a","passw":"b"}' \
  -o out/ --ai-report
# 产出 out/ai-report/{ai-report.md, ai-report.json}
# 带值则直接写进指定目录：--ai-report ./ai
```

流水线固定三角色：**analyst**（漏洞分析/风险）→ **writer**（报告撰写/PoC）→ **reviewer**（审计/修复/合规）。
`ai-report.json` 记录用了哪条模型链、耗时、审阅状态、源扫描的 verdict，便于复核口径。

**两个必须知道的取舍**：

| 项 | 默认 | 说明 |
|---|---|---|
| 数据脱敏（`AI_REPORT_MASK`） | 开启 | host 写成 `<目标Host>`、路径写成 `/***`，**PoC 天然不可复现**（这是防外发的默认值）。指向本机/自建网关时设 `AI_REPORT_MASK=0`，host 与路径原样进 prompt，PoC 可直接复制执行 |
| 响应判据来源 | 引擎 trace | 报告里的「真条件 8356B / 假条件 8459B / 长度差 -103B / 首个差异偏移 5130」直接取自扫描器实测的布尔 trace，**不是模型编的**；没有 trace 时 prompt 明确要求写「判据需人工确认」 |

**失败语义**：`--ai-report` 的 env 没配齐 → **开扫前**就报错退出（不会白扫三分钟）；
生成阶段失败 → `exitCode=1`（执行失败），**不改**扫描结论与风险等级——AI 不可用既不等于有洞，也不等于没洞。
`reviewer` 返回空内容时不再标「✅ 已审阅」，而是回退到撰写稿并标注未审阅（[D205] 修的假绿缺陷）。

> 边界：`scripts/one-click-scan.mjs` **不支持** `--ai-report`（它有自己的参数表，不复用 CLI 解析器）。

### 复现检查与可复现件（`--repro-check`，[D177]）
「报告里有一条 High」和「这条 High 能稳定复现」是两件事。加 `--repro-check` 让扫描器自己判：

```bash
node server/bin/cli.js -u "https://target/items?cat=1" -o out/ --repro-check
# 报告里每条 finding 多一个 vuln.repro：{ status, consistent, repeats, samples[], reason? }
# summary.repro：{ checked, reproduced, singleHit, unreplayable }
# 产物：out/repro/repro-01-cat.sh + repro-01-cat.expect.json + README.md
```

三种判定：`reproduced`（两次重放状态码与响应体一致）/ `single_hit`（不一致 → 证据不稳，
先查会话失效、被 WAF 拦、目标抖动）/ `unreplayable`（没有 PoC 或请求发不出去，`reason` 说明原因）。

两个必须知道的口径：

1. **一致 ≠ 漏洞仍存在**，只说明这条证据稳定；判定不替代人工复核。
2. 比对前会剔除**明显的易变标记**（10 位以上数字串、ISO 时间戳），否则带
   `<!-- generated at 1699999999 -->` 的页面会在跨秒重放时被误判成 `single_hit`；
   剔除清单刻意极小，剥完仍是严格字节比较（不做相似度匹配）。

`repro-*.sh` 是给第三方/离线的可移植件（bash + curl + sha256sum，同样剔除易变标记后比对，
一致 exit 0）；Windows 上需 WSL / Git Bash 才能跑。

---

## 八、安全与合规边界

1. 引擎默认仅监听 `127.0.0.1`，不暴露公网。
2. 破坏性操作（拖库 / 文件读写 / OS Shell）均有前端二次确认 + `authorized` 强制勾选 + 后端门控（`EXPLOIT_UNAUTHORIZED`）。
3. 可选 `SCAN_API_TOKEN` 纵深防御；报告 / 导出 / SSE 端点受 token 护栏保护（详见 `docs/api.md`）。
4. 日志对 URL 凭据 / 键值凭据打码。

---

## 九、常见问题（FAQ）

> 完整 FAQ（错误码速查表、sqlmap 定位、超时/SSRF 排查、误报处理、tamper 失效排查、Docker、测试）见 **[faq.md](./faq.md)**；部署细节（Node 版本、生产部署、桌面打包、环境变量全集、安全基线）见 **[deploy.md](./deploy.md)**。

- **端口冲突**：`PORT=4568 npm run server` 覆盖。
- **局域网访问**：`HOST=0.0.0.0 ALLOWED_ORIGINS=http://your-host SCAN_API_TOKEN=xxx npm run server`。
- **sqlmap 不可用**：设 `SQLMAP_PATH=/path/to/sqlmap.py`，或克隆到 `server/tools/sqlmap`。
- **桌面版打包**：先 `npm run build:engine` 打包引擎单文件，再 `npm run tauri dev`。
- **引擎忙（ENGINE_BUSY）**：并发扫描达上限（默认 8），稍后重试或设 `MAX_SCAN_API_CONCURRENT`。
- **目标不可达**：检查目标可达性、代理配置、超时设置；内网目标需显式 `HOST` 放行。
