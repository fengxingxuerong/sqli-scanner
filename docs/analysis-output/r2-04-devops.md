# R2-04 · DevOps / 交付链第二轮审查

> 审查人：资深 DevOps/发布工程师（ox-alpha）｜ 日期：2026-08-25 ｜ 分支 master @ a3ef37b
> 范围：CI/Docker 近期改动有效性验证 + 交付链剩余风险。已修复项（ci.yml 顶层 on:、前端 --coverage、.dockerignore/.gitignore 的 .env* 与 *.err）不再重复报告。

---

## 1. ci.yml YAML parse 验证 + schedule 触发时 job 依赖图推演

### 1.1 解析验证（实测）

以 `yaml` 包对 `.github/workflows/ci.yml` 做实际 parse：

```
YAML parse OK; triggers = ["push","pull_request","schedule","workflow_dispatch"]
lint(none) | test-frontend(none) | test-server(none)
test-matrix(lint,test-frontend,test-server) | recall-lab(test-server)
tamper-waf-matrix(none) | docker(test-frontend,test-server)
```

**结论：合法。** 上轮指出的「job 级 schedule:/workflow_dispatch: 非法键」已正确上移至顶层 `on:`（ci.yml:3-13），7 个 job 全部解析成功，`if` 条件均为合法表达式。

### 1.2 各事件下的执行图推演

| 触发 | 执行的 job | 说明 |
|---|---|---|
| `schedule`（cron `0 3 * * 1`，周一 03:00 UTC，语法有效） | **仅 tamper-waf-matrix** | 其余 6 个 job 被 `if: github.event_name != 'schedule'` 跳过；tamper-waf-matrix 无 `needs`（ci.yml:124 注释已说明不能用 needs:[test-server]，否则会被 skipped 连带跳过），推演可正常独立运行 ✅ |
| `workflow_dispatch` | **全部 7 个 job** | 其余 job 的条件只排除 schedule，dispatch 时照跑；tamper-waf-matrix 额外放行 dispatch ✅ |
| `push`(main/master) | lint ∥ test-frontend ∥ test-server → test-matrix、recall-lab、docker | docker 由 `needs:[test-frontend,test-server]` 门控 |
| `pull_request` | 同上但 **docker 跳过**（ref 不在 main/master）✅ | |

### 1.3 推演中发现的剩余问题

- **[M-a] tamper-waf-matrix 双 step 均 `continue-on-error: true`（ci.yml:134,138）→ 该 job 永远绿灯。** 周度矩阵的失败没有任何告警出口（无 step 结果上报/issue 创建），「每周实验性矩阵」实质退化为无人查看的静默运行。建议至少聚合两步结果写 `$GITHUB_STEP_SUMMARY` 或失败时开 issue。
- **[L-a] 无 `concurrency` 组**：同分支连续 push 会并行跑多套全矩阵（含 windows/macos），纯浪费 runner 分钟数。建议加 `concurrency: { group: ci-${{ github.ref }}, cancel-in-progress: true }`。
- **[L-b] `permissions:` 未声明 + action 未 pin SHA**：workflow 级未收敛 GITHUB_TOKEN 权限，依赖仓库默认设置；建议顶层 `permissions: contents: read`。同时所有 action 按 tag（@v4）引用而非 commit SHA pin，属供应链弱化项。
- **[L-c] lint / test-frontend / docker 三个 job 无任何 `timeout-minutes`**，吃 GitHub 默认 360 分钟上限（test-server/recall-lab/矩阵仅在 step 级给了 5-10 分钟）。
- **[L-d] GitHub 平台行为**：仓库连续 60 天无 push 活动时 schedule 会被平台自动禁用，需人工 re-enable——周度矩阵存在「悄悄停摆」风险。


---

## 2. Dockerfile：非 root / HEALTHCHECK / 双 lock 漂移现状

### 2.1 非 root：**未做**（本次核心 HIGH）

- 全文无 `USER` 指令 → 运行层以 **root** 跑 `node /app/server/index.js`（Dockerfile:17-42）。node:24-alpine 自带 uid/gid 1000 的 `node` 用户可直接用。
- 加重因素：logger 默认写文件日志（`SQLI_NO_FILE_LOG=1` 才关闭），root 容器内进程被攻破（本工具会向任意用户指定 URL 发 payload，攻击面天然偏大）后可写容器全文件系统。
- 修复建议（两行）：
  ```dockerfile
  RUN mkdir -p /app/server/logs && chown -R node:node /app
  USER node
  ```
  （注意 sessions/ 与 logs/ 目录需对 node 可写。）

### 2.2 HEALTHCHECK：**已具备** ✅

Dockerfile:36-37，`curl -f http://127.0.0.1:4567/api/health`，interval/timeout/start-period 参数合理；配合 tini 作 PID1（:41）信号处理正确。

### 2.3 双 lock 漂移：**无漂移** ✅

实测比对（声明依赖 vs lock 根节点条目，逐包版本一致）：

| 包 | 声明依赖数 | lockfileVersion | 漂移 |
|---|---|---|---|
| 根 package-lock.json | 35 | 3 | 无 |
| server/package-lock.json | 10 | 3 | 无 |

且两个 lock 均被各自 `npm ci` 消费（CI + Dockerfile builder 层），构建可复现性成立。

### 2.4 其他确认项

- `.dockerignore` 已排除 `.env*`/`**/.env*`（保留 .env.example），builder 层不再携带密钥 ✅（已修项，仅确认生效）。
- [L-e] docker job smoke test 用固定 `sleep 8` 后 curl（ci.yml:151）：慢机器上有竞态假红风险；镜像既有 HEALTHCHECK，可改 `docker inspect --format='{{.State.Health.Status}}'` 轮询或 curl 重试循环。

---

## 3. setup-node npm 缓存现状

**现状：7 个 job 的 `actions/setup-node@v4` 均未启用内置缓存（无 `cache: 'npm'`），改用两个 `actions/cache@v4` 直接缓存 node_modules 目录（ci.yml:24-33,49-53,69-73）。**

问题链：

1. **该缓存基本无效**：后续步骤跑的是 `npm ci`，而 npm ci 的语义就是**先整体删除 node_modules 再按 lock 精确安装**——恢复回来的 node_modules 会被立刻丢弃。每次 CI 实际付出「cache restore + cache save（上传整个 node_modules，数百 MB）」的成本，却拿不到任何安装加速。
2. **跨平台隐患**：node_modules 含平台二进制（esbuild 等），若未来把该缓存 key 复用到 windows/macos matrix 会直接装坏；当前矩阵恰好没配缓存才没踩坑。
3. **正确做法**（官方推荐）：setup-node 加 `cache: npm` + `cache-dependency-path` 指向两个 lock 文件（缓存 ~/.npm 包下载，npm ci 只需解压链接），并删除全部三个 actions/cache 块。

定级：不影响正确性、纯效率与维护性问题 → **MEDIUM**。

---

## 4. src-tauri updater / signing

**结论：更新器与签名体系完全缺失（非配置错误，是整条能力不存在）。**

| 检查点 | 结果 |
|---|---|
| tauri.conf.json → `plugins.updater`（endpoints/pubkey） | ❌ 不存在 |
| bundle → `createUpdaterArtifacts` | ❌ 未开启 |
| Cargo.toml → `tauri-plugin-updater` 依赖 | ❌ 无（仅 tauri + tauri-plugin-shell） |
| Rust 侧 updater 调用（src/*.rs） | ❌ 无 |
| macOS `signingIdentity` / 公证配置 | ❌ 无 |

影响：桌面版分发只能靠人工替换安装包；用户无法校验更新包完整性与来源（无签名/公钥锚定），中间人替换安装包不可检测；macOS 侧叠加 Gatekeeper 公证缺失。对一款「安全检测工具」而言分发链完整性应优先补齐：

1. `Cargo.toml` 加 `tauri-plugin-updater = "2"`；
2. conf 增加 `plugins.updater { endpoints, pubkey }` + `bundle.createUpdaterArtifacts: true`；
3. CI 补 `tauri build` + 私钥签名（`TAURI_SIGNING_PRIVATE_KEY` secret），产物附 `.sig` 上传 Release。

定级：**HIGH**（交付链完整性缺口；若桌面版近期不对外分发可降为 MEDIUM）。

> 注：capabilities/permissions 声明位置错误属 R1 已报 H3，此处不重复。

---

## 5. husky 旁路风险

现状：`.husky/pre-commit` 仅一行 `npx lint-staged`（15 字节，husky v9 允许无 shebang 简写）；lint-staged 配置仅 `eslint --fix`（package.json）。

- **绕过方式**：`git commit --no-verify`、GUI 客户端、`git -c core.hooksPath=/dev/null commit` 均可 100% 绕过——hook 天然只是「尽力而为」层，不是安全边界。
- **实际风险评估：LOW**。因为 CI 的 lint job 独立跑 `tsc --noEmit` + `eslint .`（全量、不可绕过），pre-commit 被绕过只损失本地反馈速度，不损失质量门禁。
- **[L-f] 小瑕疵**：若开发者未先 `npm install` 即提交，`npx lint-staged` 会从 registry 临时拉包执行（供应链面 + 首次提交卡顿）。更稳的做法是 pre-commit 内加本地依赖存在性检查。
- hook 未包含 secret 扫描/测试，属设计取舍而非缺陷。

---

## 6. .env.example vs defaults.js / 实际代码变量比对

方法：`.env.example` 全量变量 vs `server/src/**` + `server/index.js` 中 `process.env.*` 实读清单（defaults.js 本身是**扫描引擎参数默认值**，不读环境变量，与 .env.example 属两个层面，见 6.3）。

### 6.1 死文档：.env.example 有、代码不读 ❌

| 变量 | .env.example 注释 | 代码事实 |
|---|---|---|
| `AI_REPORT_KEY_INDEX` | 「默认使用的预置 API key 索引(0-2)」 | **全仓库无任何读取点** |
| `AI_REPORT_MODEL_INDEX` | 「默认模型索引(0-2)」 | **无读取点** |
| `AI_REPORT_TIMEOUT_MS` | 「请求超时(ms) 默认30000」 | **无读取点** |

→ 用户按文档配置这三个变量不会有任何效果。ReportAI.js 实际机制是硬编码 `AI_REPORT_KEY_1/2/3` 数组 + 固定 API_BASE/模型表。

### 6.2 隐形变量：代码在读、.env.example 没写 ⚠️

`AI_REPORT_API_BASE`（ReportAI.js:12）、`AI_REPORT_KEY_1/2/3`（:15-17，启用 AI 报告的唯一途径！）、`PYTHON_PATH` 与 `SQLMAP_OUTPUT_DIR`（sqlmapBridge.js:40,263）、`SSE_GLOBAL_MAX` / `SSE_REPLAY_MAX`。其中 `AI_REPORT_KEY_*` 是功能开关级缺失文档，最影响部署体验。

### 6.3 默认值漂移：文档注释 vs 代码 fallback 不一致

| 变量 | .env.example 声称默认 | 代码实际 fallback | 出处 |
|---|---|---|---|
| `SSE_MAX_CONNECTIONS` | 100 | **20** | eventBus.js:19-21 |
| 其余核对项（EXPLOIT_RATE_PER_SEC=5、MAX_SCAN_API_CONCURRENT=8、HTTP_AGENT_MAX_SOCKETS=32、OOB 系列、SQLMAP 系列） | — | 一致 ✅ | exploitRoutes.js / scanRoutes.js / httpClient.js / oobReceiver.js / sqlmapBridge.js |

### 6.4 defaults.js 层面备注

`server/src/config/defaults.js` 为引擎扫描参数默认值（ratePerSec 已放开至 30、concurrency 4 等），不经环境变量桥接，只能经 REST config 透传——`.env.example` 不覆盖它是合理的；但 `docs/system_design.md` 仍写「限速 ≤3 req/s」，文档与 defaults.js:13 存在陈述性漂移（归档 docs 组，不计入本报告定级）。

定级：6.1/6.2 合并为 **MEDIUM**（部署者按官方样例配不出 AI 报告功能）；6.3 为 LOW 内含。

---

## 7. 汇总：CRITICAL / HIGH / MEDIUM / LOW

> 已修项（顶层 on: 触发器、前端 --coverage、.dockerignore/.gitignore 的 .env* 与 *.err）经验证生效，不再列入。

### CRITICAL（0）
无。上轮 C 级项均已闭环或不在本轮范围复发。

### HIGH（2）
| # | 问题 | 位置 |
|---|---|---|
| H1 | Docker 运行层无 `USER`，容器以 root 跑 Express（logger 还默认写文件），进程被攻破即全容器 root | Dockerfile:17-42 |
| H2 | Tauri 桌面版更新/签名体系整体缺失：无 updater 插件、无 pubkey/endpoints、无 createUpdaterArtifacts、无 macOS signingIdentity → 分发链无完整性校验 | src-tauri/tauri.conf.json、Cargo.toml |

### MEDIUM（3）
| # | 问题 | 位置 |
|---|---|---|
| M1 | CI 缓存策略无效：actions/cache 缓存 node_modules 被 `npm ci` 先删后装直接作废；setup-node 未用 `cache: npm`；白付数百 MB 上下载 | ci.yml:24-33,49-53,69-73 |
| M2 | tamper-waf-matrix 双 step `continue-on-error` → 周度矩阵永远绿灯且零告警出口，失败不可见；叠加 workflow 无 `permissions:` 收敛 + action 未 pin SHA | ci.yml:124-138 |
| M3 | .env.example 与代码漂移：AI_REPORT_KEY_INDEX / MODEL_INDEX / TIMEOUT_MS 为死文档；真实生效的 AI_REPORT_KEY_1..3 / AI_REPORT_API_BASE 未记录 → 按样例配不出 AI 报告 | .env.example:74-80 vs ReportAI.js:12-17 |

### LOW（6）
| # | 问题 |
|---|---|
| L1 | 无 `concurrency` 组，同分支并发 push 全矩阵重复跑 |
| L2 | lint / test-frontend / docker job 无 timeout-minutes（默认 360min） |
| L3 | docker smoke 固定 sleep 8 有竞态假红风险（镜像已有 HEALTHCHECK 可利用） |
| L4 | schedule 依赖 GitHub 活跃度：仓库 60 天无 push 平台自动禁用周度任务，存在静默停摆风险 |
| L5 | pre-commit 可被 --no-verify 绕过（CI 兜底存在，实际影响小）；npx 在未安装依赖时会走 registry 拉包 |
| L6 | .env.example 的 SSE_MAX_CONNECTIONS 注释「默认100」与代码 fallback 20 不符（eventBus.js:21） |

### 正向确认 ✅
ci.yml YAML 合法且 schedule/dispatch 触发图正确；Dockerfile HEALTHCHECK + tini 就位；根/server 双 lock 零漂移且均被 npm ci 消费；.dockerignore 密钥排除已验证有效。


---

## 4. src-tauri updater / signing

**结论：更新器与签名体系完全缺失（非配置错误，是整条能力不存在）。**

| 检查点 | 结果 |
|---|---|
| tauri.conf.json → `plugins.updater`（endpoints/pubkey） | ❌ 不存在 |
| bundle → `createUpdaterArtifacts` | ❌ 未开启 |
| Cargo.toml → `tauri-plugin-updater` 依赖 | ❌ 无（仅 tauri + tauri-plugin-shell） |
| Rust 侧 updater 调用（src/*.rs） | ❌ 无 |
| macOS `signingIdentity` / 公证配置 | ❌ 无 |

影响：桌面版分发只能靠人工替换安装包；用户无法校验更新包完整性与来源（无签名/公钥锚定），中间人替换安装包不可检测；macOS 侧叠加 Gatekeeper 公证缺失。对一款「安全检测工具」而言分发链完整性应优先补齐：

1. `Cargo.toml` 加 `tauri-plugin-updater = "2"`；
2. conf 增加 `plugins.updater { endpoints, pubkey }` + `bundle.createUpdaterArtifacts: true`；
3. CI 补 `tauri build` + 私钥签名（`TAURI_SIGNING_PRIVATE_KEY` secret），产物附 `.sig` 上传 Release。

定级：**HIGH**（交付链完整性缺口；若桌面版近期不对外分发可降为 MEDIUM）。

> 注：capabilities/permissions 声明位置错误（顶层 `permissions` 应位于 capabilities 文件）属 R1 已报 H3，此处不重复。

