# AGENTS.md —— AI 代理 / 自动化驱动指引

> 面向 AI 编码代理（Claude Code / Cursor / MCP 客户端等）与 CI 机器人的操作契约。
> 人读文档见 [README.md](README.md) 与 [docs/](docs)；本文件只写「代理该怎么安全、
> 正确地把这台扫描器跑起来」，与 README 同源核对（改 CLI 面 必须同步本文件）。

## 0. 授权红线（先读这个）

- 本工具是**授权渗透测试**用途。代理代人操作时，**只能扫用户明确给出的目标**；
  内网/回环目标默认被 SSRF 防护拒绝（`SSRF_ALLOW_PRIVATE=1` 才放行），这是特性不是故障。
- `--risk 3`（高危 payload 池）需要显式 `--confirm-destructive`；利用面（SQL shell /
  文件读写 / OS shell）需要服务端 `EXPLOIT_ENABLED=1` 且请求带 `authorized: true`。
  不要替用户「顺手」解锁这两道门。
- 扫描结论进报告前，先看 `summary.verdict`：`inconclusive`（会话失效/签名被拒等）**
  不等于**「未检出」，不要向上游汇报成"没有漏洞"。

## 1. 两种驱动方式

### 1.1 CLI（子进程，推荐）

```bash
node server/bin/cli.js --help          # 全部开关；README 的 API/参数表由 npm run readme:check 双向核对
node scripts/one-click-scan.mjs -u "http://target/page?id=1"   # 一条命令出全套报告
```

- **退出码即门禁**：`0` 未发现高危 / `2` 发现 Critical 或 High / `1` 执行失败。CI 里直接判码，
  不要去 parse stdout。
- 产出固定在 `reports/<主机名>-<时间戳>/`（`manifest.json` 是机器可读清单，先读它再读 report.json）。
- **配置档案**：`--config <file.json>` 预载参数（键=长参数名去前导 `--`，如 `{"level":5}`），
  `--save-config <file>` 把本次非默认参数写回。argv > 档案 > 内置默认；档案含未知键会**拒绝启动**。
- **定向复测**：`-p <param>` 只测指定参数、`--param-filter body` 只测某位置、
  `--param-exclude <regex>` 排除噪声参数（[D41] 对标 sqlmap）。筛选把点位删光时报错退出——
  这说明参数写错了，不是目标没洞。
- 代理超时预算紧张时：`--retries 1 --http-timeout 5000 --timeout <整场上限毫秒>` 收敛等待；
  `--skip-static` 与 `--smart` 可显著省请求（语义见 help）。

### 1.2 REST API（长扫描 / 面板形态）

服务：`npm run server`（默认 `http://127.0.0.1:4567`，非回环监听强制 `SCAN_API_TOKEN`）。
端点全集见 README「后端 API」表（与代码双向核对）。代理走 REST 的最小闭环：

1. `POST /api/scan/start`（config 白名单外的键会被丢弃并告警——看响应里 dropped 提示）
2. `GET /api/scan/:id/events`（SSE；EventSource 不能带 header，token 走 query）
3. `GET /api/scan/:id/report` / `GET /api/scan/:id/report/export?format=json|html|markdown|sarif|csv`
4. 异常路径：`POST /api/scan/:id/stop | pause | resume`；单点复测 `POST /api/scan/:id/point/:pointId/retest`

## 2. 结果判读（代理最容易读错的三件事）

| 现象 | 正确判读 |
|---|---|
| `vulns: []` 且 verdict=`no_vulnerability_detected` | 引擎按配置跑完且无命中。若你没配认证（`--auth`/`--cookie`/`--refresh-url`），先补认证再下结论 |
| verdict=`session_expired` / `inconclusive` | 会话半途失效或签名/加密把请求拒了。修认证或配 `--request-script` 后重扫 |
| 报告 `summary.dbmsEvidence.caveat` 存在 | 命中的 DBMS 只有模板适配、未经真引擎验证——对外引用时必须带上该告警 |

## 3. 仓库工程纪律（改代码前必读）

- 每批改动走 **D 编号批次**（见 `TODO.md` 顶部），一次批次 = 代码 + 测试 + README/CHANGELOG 同步 + 门禁全绿。
- `npm run readme:check`：README 参数/API 表与代码**双向核对**，加了开关不写文档会红。
- `npm run acceptance`：17 套件验收门禁，提级提交前必跑。
- 引擎**有意零运行时 npm 依赖**（server 的 runtime deps 除外）；给引擎加能力请用 Node 内置能力。
- 检测判据/定库签名的测试是校准过的——不要为了让测试变绿而放宽断言；行为变化必须有靶场证据。

## 4. MCP（规划中）

原生 MCP server（stdio 模式暴露 run_scan/get_progress/get_findings 等工具）在吸收路线图
`TODO.md`「同源项目优点盘点」批次内（对标 dalfox `dalfox mcp` / semgrep `semgrep mcp` 的
「MCP 是 CLI 的一个模式」形态）。落地前请用 1.1/1.2 的两种方式驱动。
