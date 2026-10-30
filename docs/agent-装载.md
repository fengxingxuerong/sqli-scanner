# 在 AI 代理宿主里装载 sqli-scanner（D175）

> 目标：把「有能力」变成「装得上」。MCP 9 工具自 [D43] 起就有，但此前只写在 `AGENTS.md`
> 的一段 JSON 里——用户得自己抄、自己找入口、自己知道 `mcp` 子命令。本文与三个仓库内文件
> 是这套装载面的唯一真源，一致性由 `npm run agent:check` 守着（版本号、工具名、口径关键词）。
>
> ⚠️ 宿主侧的插件/MCP 配置格式仍在演进：本文给的是**本仓提供的清单形态**；
> 各家读取哪些字段、命令叫什么，以你手上那版宿主的 `--help` / 官方文档为准。
> 清单里任何一项对不上时，先跑 `npm run agent:check` 看是本仓漂移还是宿主版本差异。

## 一、三种装载方式（按侵入性从小到大）

| 方式 | 你需要做什么 | 适合 |
|---|---|---|
| ① 直接跑（零配置） | 宿主里配一条 stdio 命令：`node <repo>/server/bin/cli.js mcp` | 就想试一下；宿主只支持「自定义 MCP 命令」 |
| ② 项目级 `.mcp.json` | 仓库根已有 `.mcp.json`（`mcpServers.sqli-scanner`）；在仓库里打开宿主即可 | 日常在**本仓**里用（Claude Code 的项目级 MCP） |
| ③ 插件 + 技能 | 仓库根已有 `.claude-plugin/plugin.json` + `skills/sqli-scan/SKILL.md`；按宿主方式装载本地插件目录 | 想让代理**知道该怎么用**（先 preflight、三口径、不得代开 risk 3） |

三者的区别只在「谁负责讲用法」：① 只给工具，用法靠模型自己猜；③ 连用法与红线一起给。

## 二、按宿主

### Claude Code（项目级 MCP）

仓库根 `.mcp.json`：

```json
{ "mcpServers": { "sqli-scanner": { "command": "node", "args": ["server/bin/cli.js", "mcp"] } } }
```

在**仓库根**打开 Claude Code，首次会询问是否信任该项目的 MCP 配置。若宿主的工作目录不是仓库根，
把 `server/bin/cli.js` 换成绝对路径（这是最常见的「装上了但连不上」原因）。

### Claude Code（插件 + 技能）

装载本地插件目录的命令随版本变化（`/plugin` 交互菜单或 `--plugin-dir <path>`），以 `claude --help` 为准。
装好后技能名是 `sqli-scan`，它对模型的要求写在 `skills/sqli-scan/SKILL.md` 里，其中三条是硬口径：

1. `verdict=inconclusive / session_expired` **不等于**「没有注入」；
2. 引用阴性结论必须同时声明 `unverifiedSurfaces`（没测成）与 `uncoveredSurfaces`（压根没测）；
3. `risk: 3` 需要用户同意后传 `confirmDestructive: true`；利用面还要服务端 `EXPLOIT_ENABLED=1`
   且请求带 `authorized: true`——**代理不得代开**。

### Cursor / VS Code / 其它 MCP 宿主

拷 `.mcp.json` 里的 `mcpServers` 段到宿主的 MCP 配置文件即可（Cursor 一般是 `.cursor/mcp.json`；
VS Code 的 `mcp.json` 用 `servers` 键且每项多一个 `"type": "stdio"`）。字段差异以宿主文档为准。

## 三、装完先自检（30 秒）

```bash
# 1) 入口活着：应当打印工具清单与服务名
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | node server/bin/cli.js mcp

# 2) 装载面一致：版本号 / 工具名 / 技能口径关键词 / 越界词
npm run agent:check

# 3) 判据自己有牙（改坏任意一项必须红）
npm run agent:check:selftest
```

第 1 步的 stdout 必须是**一行一个 JSON**（MCP stdio 分帧）；日志一律走 stderr——
若你的宿主报「解析失败」，先确认没有别的东西往 stdout 打。

## 四、红线（装上也不变）

- 只扫**用户明确给出**的目标；技能里不提供目标发现/批量清单来源，也不接受搜索引擎结果当目标；
- 内网/回环目标默认被 SSRF 防护拒绝（`SSRF_ALLOW_PRIVATE=1` 才放行），这是特性；
- 高危 payload 池与利用面是**两道人工门**，代理不得替用户答应；
- 代理转述结论时必须带 `verdict` 与两个 surfaces —— 把「没测成」说成「没洞」是本项目最反对的失败形态。

## 五、当前缺口（如实登记，未做）

| 缺口 | 现状 | 下一步 |
|---|---|---|
| 未发布 npm 包 | `package.json` / `server/package.json` 都是 `private: true`；`npx sqli-scanner` 现在拿不到 | **技术侧已就绪（[D182]）**：`files: ["bin/","src/","index.js"]` 让 tarball 从 **27.1 MB → 1.14 MB**，`node scripts/pack-check.mjs` 会打包并解包真跑（`--help` + 离线直连扫描命中 3 条）。剩下的是发版决策（改 `private: false` + `npm publish`） |
| 无公共镜像 | 只有本地 `Dockerfile` / `docker-compose.yml`，没推 GHCR | 与 npm 发布同一批做，二者都属「分发通道」 |
| 宿主矩阵未实测 | 只验了 `.mcp.json` 形态与 MCP 协议层（`tools/list` + 一次扫描） | 需要真机装一次 Claude Code 插件与 Cursor，把版本号记进本文件 |
