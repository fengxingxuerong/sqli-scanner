# 04 — 工程化交付层深度审查（DevOps / 发布工程）

> 审查对象：sqli-scanner @ master (a3ef37b)
> 审查维度：Dockerfile / docker-compose / GitHub Actions CI / Tauri 打包与签名 / engine 构建产物一致性 / git 卫生 / secrets 管理 / hooks 门禁 / 依赖锁定 / 环境变量文档一致性
> 方法：git ls-files 跟踪状态核实、lockfile 版本比对、CI YAML 逐行核对、Tauri 配置与产物目录交叉验证、`.env.example` ↔ 代码消费清单双向比对
> 说明：本报告深化主代理已知基线（.env.ai 泄露 / *.err 跟踪 / coverage 未强制 / compose version 废弃 / waf-lab-v2 兼容性），并补齐 Docker 细节、CI 缓存与 DAG、Tauri 打包完整性等深度项。

---

## CRITICAL

### C1 — 真实 LLM API Key 提交进 Git 历史（含引入提交，泄露已成事实）

- **位置**：`server/.env.ai:2-5`（含 **4 行** `AI_REPORT_KEY*` 条目）、根 `.env.ai`（同样被跟踪）
- **证据**：
  - `git ls-files | grep '\.env'` → `.env.ai`、`.env.development`、`.env.tauri`、`server/.env.ai`、`server/.env.test` 全部被跟踪；
  - `git log --all --follow -- server/.env.ai` → 引入提交 `af372ee feat(ai): 漏洞盒子标准报告 + 限速防护 + 3 key 9 模型 .env 配置`；
  - `ReportAI.js:12-16` 按 `AI_REPORT_KEY_0..2` 消费这些 key，证明 `.env.ai` 中是**可直接盗刷的真实凭据**，非占位符。
- **影响**：任何能 clone/pull 该仓库的人（含未来开源、fork、镜像同步）都能盗用 3+ 个 key 产生费用。密钥已进 git 对象库——**仅从工作区删除不够，历史仍在**。
- **修复（缺一不可）**：
  1. 立即在 SenseNova/DeepSeek/GLM 控制台 **吊销并轮换全部 key**（唯一真正有效的止损）；
  2. `.gitignore` 追加 `.env.*` + `!.env.example`（当前只挡 `.env`/`.env.local`，`.env.ai`/`.env.development`/`.env.tauri` 全部漏网，见 `.gitignore:8-9`）；
  3. 历史清除：`git filter-repo --path server/.env.ai --path .env.ai --invert-paths` 后 force-push 并通知所有协作者重 clone；
  4. 密钥分发改走环境注入（部署平台 secret / 本地未跟踪的 `.env`），`ReportAI.js` 的 `process.env.AI_REPORT_KEY_*` 读取路径保持不变即可。

### C2 — `.dockerignore` 未排除 `.env*` → 密钥被打进镜像构建上下文与 layer 缓存

- **位置**：`.dockerignore:7-9` vs `Dockerfile:13`
- **证据**：`.dockerignore` 仅排除 `.env`、`.env.local`、`.env.*.local` 三种模式；`server/.env.ai`、根 `.env.ai`、`server/.env.test` 均不在列。`Dockerfile:13` 的 `COPY . .` 将其复制进 **builder stage 第 3 层**。
- **影响**：
  - multi-stage 最终 runtime 层确实不含密钥（runtime 只 `COPY --from=builder /app/server`，见 Dockerfile:23），这点是幸运而非设计；
  - 但 builder 各层随 `--target` 构建、buildx 导出、registry 缓存推送而持久化——`docker history` / 按层拉取可还原 `.env.ai`；
  - 同时 `.github/`、`*.md` 已排除说明作者做过"瘦身"却漏掉了最高危的 secrets 类目。
- **修复**：`.dockerignore` 追加：

  ```gitignore
  .env*
  server/.env*
  !.env.example
  ```


---

## HIGH

### H1 — 根级 `*.err` 错误日志被 git 跟踪（.gitignore 模式缺口）

- **位置**：`.gitignore:25`（仅 `server/*.err`）；被跟踪文件：根目录 `preview-server.err`、`server.err`（`git ls-files` 证实）
- **影响**：错误日志含本机路径、目标 URL、可能含 token 片段；且每次运行后 `git status` 出噪音，易诱发"顺手提交"。
- **修复**：`git rm --cached preview-server.err server.err` + `.gitignore` 追加根级 `*.err`（或 `/[a-z-]*\.err`），与已有 `server/*.err` 合并成一条。

### H2 — ci.yml 存在非法 job 级键 `schedule:`/`workflow_dispatch:`，整个 workflow 有解析失败风险

- **位置**：`ci.yml:109-111`
- **证据**：

  ```yaml
  tamper-waf-matrix:
    runs-on: ubuntu-latest
    needs: [test-server]
    schedule:          # ← 非法：schedule 只能出现在顶层 on: 下
      - cron: '0 3 * * 1'
    workflow_dispatch: # ← 同上
  ```

- **影响**：GitHub Actions 的 job schema 不接受这两个键——轻则被忽略导致"每周定时任务从未跑过"，重则 workflow 文件校验失败使 **push/PR 的全部 CI 一并失效**（取决于 runner 端校验严格度）。这是比"缺 coverage 门禁"更基础的 CI 可用性问题。
- **修复**：把 `schedule`/`workflow_dispatch` 移到文件顶部 `on:` 块；若希望定时任务只在主分支跑，用 `if: github.event_name == 'schedule' && github.ref == 'refs/heads/master'` 控制。

### H3 — Tauri 打包完整性三处断裂：icon 缺失 / sidecar 单文件从未产出 / 权限声明位置错误

- **位置**：`src-tauri/tauri.conf.json:26-43`、`src-tauri/src/lib.rs:16-19`、`scripts/build-engine.mjs:195-199`
- **逐项证据**：
  1. **icon 指向不存在的文件**：`bundle.icon: ["icons/icon.png"]`，但 `src-tauri/icons/` 目录不存在（目录枚举仅有 `binaries/ src build.rs Cargo.toml tauri.conf.json`）→ `tauri build` 在资源解析阶段直接报错；
  2. **sidecar 形态错配**：`externalBin: ["binaries/sqli-engine"]` 要求存在单文件可执行 `binaries/sqli-engine-<target-triple>[.exe]`；而 `build-engine.mjs` 只暂存**目录形态**的 `binaries/sqli-engine-assets/`（engine.mjs + sql.js），脚本自己在 :208-209 也承认"单文件化路线见 pkg/SEA"。结果：`lib.rs:17-18` 的 `.sidecar("sqli-engine").expect(...)` 在 dev/build 时 panic——桌面形态当前**不可构建**；
  3. **配置键无效**：
     - `plugins.shell.externalBin`（:33-35）不是 shell 插件的合法配置键（插件只有 `open` 等 scope 配置），externalBin 属于 `bundle`；
     - 顶层 `"permissions"` 数组（:37-43）不是 Tauri v2 config schema 的键——v2 的权限必须经 `src-tauri/capabilities/*.json` 授予（该目录同样不存在）→ 即便修好 icon/sidecar，`shell:allow-execute` 等权限实际未生效，前端 `invoke('start_engine')` 会被 permission denied。
- **附带安全项**：`app.security.csp: null`（:23）+ `fs:default` + `shell:allow-spawn` 组合，一旦前端被注入（扫描报告渲染外部内容）即获得任意进程拉起与文件读写能力。建议至少设置最小 CSP 并将权限收敛为按窗口/按命令白名单。
- **修复优先序**：补 `icons/icon.png`（`tauri icon` 生成全套）→ 决断 sidecar 路线（pkg 打 `engine.cjs` 或改用 `resources` 打包 dist-engine 目录 + `shell.Command` 启 node）→ 建 `capabilities/default.json` 迁移 permissions → 删 `plugins.shell.externalBin` → 设 CSP。

### H4 — CI 缓存策略反模式：actions/cache 缓存 node_modules 且 npm ci 全量重装，缓存零收益

- **位置**：`ci.yml:17-28, 41-46, 59-64`
- **证据**：三个 job 都先 `actions/cache@v4` 恢复 `node_modules`，紧接着无条件 `npm ci`——npm ci 会**删除现有 node_modules 再全量安装**，缓存命中与否结果一样，纯属浪费 cache 上传/下载带宽（每个 job 约 100-400MB）。
- **修复**：删除全部 `actions/cache` 步骤，改为 setup-node 内置缓存：

  ```yaml
  - uses: actions/setup-node@v4
    with:
      node-version: 24
      cache: npm
      cache-dependency-path: |
        package-lock.json
        server/package-lock.json
  ```

### H5 — Docker 容器以 root 运行，无 USER 指令

- **位置**：`Dockerfile:16-42`（runtime stage 无任何降权）
- **影响**：node:24-alpine 默认 root。容器内进程（一个暴露 4567 端口、接收任意扫描目标的 Express 服务）以 uid=0 运行，叠加 `EXPLOIT_ENABLED` 这类"故意执行 SQL/OS 命令"的功能面，容器逃逸后果被放大。`sessions` 卷挂载（docker-compose.yml:16）也会以 root 属主写宿主卷。
- **修复**：

  ```dockerfile
  RUN apk add --no-cache curl tini \
   && mkdir -p /app/server/sessions && chown -R node:node /app
  USER node
  ```


---

## MEDIUM

### M1 — 双独立 lockfile 无一致性保障：axios 当前同版（1.18.1/1.18.1），但漂移只是时间问题

- **位置**：`package.json:43` + `server/package.json:23`（axios 各声明一份）；lock 核实：根 `package-lock.json:3073` 与 `server/package-lock.json:157` 均为 1.18.1
- **风险**：两棵依赖树完全隔离，无 dependabot/renovate、无 CI 校验两 lock 版本对齐；`npm audit` 也需分别跑（CI 目前一个都没跑）。安全补丁（axios 历史上多次发 ReDoS/SSRF 修复）极易只升一边。
- **修复**：引入 Renovate（`packageRules` 按 lock 文件分组同步升级）或至少加一条 CI 步骤比对双 lock 中重叠包的版本并告警；CI 补 `npm audit --omit=dev`（两个目录）。

### M2 — docker-compose.yml `version` 字段废弃 + compose 加固缺失

- **位置**：`docker-compose.yml:1`
- **证据**：Compose V2 已忽略并对 `version:` 发 warning。另外 compose 未设 `user:`、`security_opt: [no-new-privileges:true]`、`read_only`，且 `SCAN_API_TOKEN=` 空值显式覆盖镜像 ENV——语义上"留空=不认证"（`.env.example:16-17`），生产 compose 用户照抄即裸奔。
- **修复**：删 `version:` 行；compose 改为 `${SCAN_API_TOKEN:?set_in_env}` 强制注入；加 `security_opt` 与非 root user（配合 H5）。

### M3 — package.json `waf-lab-v2` 使用 Unix 环境变量前缀，Windows cmd 下不可运行

- **位置**：`package.json:16` — `"waf-lab-v2": "WAF_PROFILE=all_in_one node e2e/waf-lab/lab-server-v2.js"`
- **影响**：Windows cmd 会把 `WAF_PROFILE=all_in_one` 当作命令名 → `'WAF_PROFILE' is not recognized...`；PowerShell 同样失败。本项目主开发平台即 Windows（工作目录 D:\projects）。
- **修复**：脚本内读 `process.env.WAF_PROFILE || 'all_in_one'` 后零参数化，或引入 `cross-env`。

### M4 — Tauri updater/signing 完全缺位 + sidecar 二进制无来源校验

- **位置**：`tauri.conf.json`（无 `plugins.updater`、无 `createUpdaterArtifacts`）；Cargo.toml 无 tauri-plugin-process/updater；`build-engine.mjs` 产物无 checksum 清单
- **影响**：
  - 桌面分发链无签名（Windows 无 Authenticode / macOS 无 codesign+notarization 配置）→ SmartScreen/Gatekeeper 拦截 + 更新通道无法建立；
  - `sqli-engine-assets` 由本地脚本产出后手工放置，无 SHA256 manifest——"外部二进制来源可信度"目前仅靠"自己机器上构建"，一旦进入多人协作或 CI 构建（当前 CI 完全不构建桌面端），产物可被替换而无人察觉。
- **修复**：短期给 `build-engine.mjs` 增加 `engine.SHA256SUMS` 输出并在 lib.rs/文档中记录校验步骤；中期接 `tauri-plugin-updater` + minisign pubkey + CI 内 `tauri build` 矩阵产出签名安装包。

### M5 — husky pre-commit 门禁可被旁路（未 install hooks 即失效）

- **位置**：`.husky/pre-commit:1`（内容仅 `npx lint-staged`）；`package.json:29`（`prepare: husky`）
- **分析**：
  1. `prepare` 只在 `npm install` 时设置 `core.hooksPath=.husky/_`；clone 后若用 pnpm/yarn 或跳过 install 直接提交，hooks 不存在，lint-staged 零执行——本仓库当前 `git config core.hooksPath` 虽已指向 `.husky/_`（本地生效），但对新环境无强制；
  2. hook 用 `npx lint-staged` 而非直接 `lint-staged`：npx 在本地 node_modules 缺失时会**静默联网下载最新版**执行——既慢又有供应链面（husky v9 已把 node_modules/.bin 注入 PATH，直接写 `lint-staged` 即可）；
  3. CI 的 lint job 跑的是 `eslint .`（无 `--max-warnings`），与 lint-staged 的 `eslint --fix` 规则集相同但**不含 staged 过滤差异**——绕过 pre-commit 的提交只要整体 lint 通过仍能进主干，格式门禁实质是"尽力而为"。
- **修复**：hook 改 `lint-staged`（去 npx）；README 贡献指引强调 `npm install` 必跑；可选加一条 CI 校验 `core.hooksPath` 或改用 lefthook 这类可在 CI 复跑同一套钩子的方案。

### M6 — `.env.example` 与代码实际消费双向漂移

- **位置**：`.env.example:76-80` vs `server/src/services/ReportAI.js:12-16`
- **文档化了却未被任何代码消费**（死配置）：
  - `AI_REPORT_KEY_INDEX`（.env.example:76）
  - `AI_REPORT_MODEL_INDEX`（:78）
  - `AI_REPORT_TIMEOUT_MS`（:80）
  - 全仓 grep 仅命中 docs/api.md；ReportAI.js 只读 `AI_REPORT_API_BASE` 和 `AI_REPORT_KEY_0..2`，模型索引/超时是硬编码。（注：这两个变量只在被跟踪的 `.env.ai` 里出现并被赋值——用户以为在调参，实际无效。）
- **代码消费了却未文档化**：
  - `PYTHON_PATH`（sqlmapBridge.js:40，作为 SQLMAP_PYTHON 的前置回退）
  - `SQLMAP_OUTPUT_DIR`（sqlmapBridge.js:263）
  - `SSE_GLOBAL_MAX`（eventBus.js:24，全局 SSE 上限，与已文档化的 SSE_MAX_CONNECTIONS 并存）
  - `VITE_SCAN_API_TOKEN`（src/shared/apiClient.ts:10，前端编译期 token 注入）

---

## LOW

### L1 — Dockerfile 细节：HEALTHCHECK 的 curl 依赖与缓存顺序优化空间

- **位置**：`Dockerfile:20, 36-37`
- **分析**：
  - `apk add curl` 纯为健康检查服务（约多 5-8MB）；busybox 自带的 `wget -qO- http://127.0.0.1:4567/api/health` 可零依赖替代，或用 Node 24 内置 fetch 写一行探针脚本，顺带消除"curl 缺失导致 HEALTHCHECK 恒 fail"的隐性耦合；
  - 层序总体正确（两份 lock → install → COPY . .），但 `COPY . .` 之后才 build 前端：任何 src 改动都会重跑 `npm run build`（合理），而 server 源码改动会同时使前端层失效——可将 server 与前端源码分开 COPY 收窄失效面；
  - 可选：`RUN npm ci` 加 `--mount=type=cache,target=/root/.npm`（BuildKit）加速无锁下载。
- **结论**：非缺陷，属优化项；但 H2/C2 未修前，`COPY . .` 同时也是密钥入层路径。

### L2 — docker job 构建完即丢弃：无镜像推送/标签策略

- **位置**：`ci.yml:127-144`
- **分析**：master 分支每次构建 `sqli-scanner:latest` 冒烟后即随 runner 销毁。缺：GHCR 推送 + `docker/metadata-action` 标签策略（sha/branch/semver）+ `docker/build-push-action` 的 GHA layer cache。当前"镜像只在本地存在"，部署只能靠各环境重新 build——可复现性依赖 Dockerfile 本身（尚可），但回滚/审计无锚点。
- **修复**：加 push 步骤（`permissions: packages: write` + GITHUB_TOKEN 登录 GHCR），标签至少含 `${{ github.sha }}`。

### L3 — CI DAG 串行等待与门禁缺口（深化基线）

- **位置**：`ci.yml:75`（test-matrix needs 三连）、`:95/:108/:129`
- **分析**：
  - test-matrix 需等 lint+test-frontend+test-server 全绿才开跑 win/mac——跨平台回归被人为串行化；它跑的是与前置 job 完全相同的检查（tsc/vitest/server test），仅增量价值在 OS 差异，等待成本 > 收益。建议改为独立并行（去掉 needs）或降级为 nightly schedule；
  - recall-lab/tamper-waf/docker 各自 needs 单一 job，链路合理；
  - 全 workflow 无 `concurrency:` 组（同分支连续 push 会排队跑重复流水线，应加 `cancel-in-progress: true`）;
  - coverage 强制缺失（基线确认）：`server/package.json:19` 已有 `--test-coverage-lines=80` 门限、根目录有 `test:coverage` 脚本，但 CI 一个都不调——门限形同虚设。lint/test job 补 `vitest run --coverage` + 上传 artifact 即可落地。

### L4 — e2e 结果产物入库，gitignore 策略不一致

- **位置**：`.gitignore:39-40`（只忽略 `e2e/recall-lab/results/`）vs 被跟踪的 `e2e/waf-lab/results/*.md|json`、`e2e/tamper-matrix/results/*`、`e2e/sqli-labs/results/sqli-labs.md`
- **影响**：机器生成的基准结果入库后必然随每次本地复跑产生 diff 噪音；若是有意作为"基线快照"入库，应在文件头标注生成命令与日期（compare.md 目前未带元信息）。二选一：全部 ignore，或统一加生成元数据头。

### L5 — 冒烟测试 `sleep 8` 固定等待竞态 & compose/Dockerfile healthcheck 双份冗余

- **位置**：`ci.yml:138`（`sleep 8` 后直接 curl）、`docker-compose.yml:17-21` vs `Dockerfile:36-37`
- **影响**：慢速 runner 上 8 秒可能不足（flaky）；compose 的 healthcheck 与镜像内 HEALTHCHECK 定义重复（无害，但改端口时要同步三处：Dockerfile/compose/EXPOSE）。
- **修复**：CI 冒烟改轮询循环（如 `for i in {1..30}; do curl -f ... && break; sleep 1; done`）；healthcheck 只保留镜像内一份。

---

## 汇总

| # | 级别 | 一句话 | 位置 |
|---|------|--------|------|
| C1 | CRITICAL | 真实 LLM API key 入库且已在 git 历史（引入 af372ee），需吊销+清史+ignore | server/.env.ai:2-5, .env.ai |
| C2 | CRITICAL | .dockerignore 漏排 .env*，密钥进 builder 层缓存 | .dockerignore:7-9 / Dockerfile:13 |
| H1 | HIGH | 根 *.err 被 git 跟踪 | .gitignore:25 |
| H2 | HIGH | ci.yml job 级非法键 schedule/workflow_dispatch，CI 解析风险 | ci.yml:109-111 |
| H3 | HIGH | Tauri 打包断裂：icon 缺失 / sidecar 单文件未产出 / permissions 位置错误（v2 需 capabilities/） | tauri.conf.json:23-43, lib.rs:16-19, build-engine.mjs:195-199 |
| H4 | HIGH | actions/cache node_modules + npm ci = 零收益反模式，应换 setup-node cache:npm | ci.yml:17-28,41-46,59-64 |
| H5 | HIGH | 容器 root 运行，无 USER/chown | Dockerfile:16-42 |
| M1 | MEDIUM | 双 lock 无一致性/审计机制（axios 双份当前同版） | package.json:43 / server/package.json:23 |
| M2 | MEDIUM | compose version 废弃 + SCAN_API_TOKEN= 空覆盖裸奔 | docker-compose.yml:1,14 |
| M3 | MEDIUM | waf-lab-v2 Unix env 前缀 Windows 不可运行 | package.json:16 |
| M4 | MEDIUM | updater/signing 缺位 + sidecar 无 checksum 来源校验 | tauri.conf.json / build-engine.mjs |
| M5 | MEDIUM | pre-commit npx lint-staged 可旁路 + npx 供应链面 | .husky/pre-commit:1 |
| M6 | MEDIUM | .env.example 双向漂移：3 个死变量 / 4 个未文档变量 | .env.example:76-80 等 |
| L1 | LOW | HEALTHCHECK curl 依赖 / COPY 失效面 / BuildKit cache | Dockerfile:20,36-37 |
| L2 | LOW | docker job 无推送/标签策略 | ci.yml:127-144 |
| L3 | LOW | matrix 串行等待 / 无 concurrency / coverage 门限未接 CI | ci.yml:75 等 |
| L4 | LOW | e2e results 入库策略不一致 | .gitignore:39-40 |
| L5 | LOW | sleep 8 冒烟竞态 / healthcheck 三处重复定义 | ci.yml:138 |

### 修复优先级路线图

1. **立即（今天）**：C1 吊销 key → C2/H1 补 ignore 并 `git rm --cached` → filter-repo 清史并 force-push。
2. **本周**：H2 修 ci.yml 结构（否则一切 CI 改进无从谈起）→ H4 换 setup-node cache → L3 接 coverage 门禁与 concurrency → M2/M3 小修。
3. **本迭代**：H5 非 root 化 → H3 逐项打通桌面构建（icon → sidecar 决断 → capabilities → CSP）。
4. **规划项**：M1 Renovate/audit、M4 签名+updater+checksum manifest、L2 GHCR 发布链。

*审查完成于 2026-08-25 · ox-alpha (DevOps/发布工程) · 全部行号基于 master@a3ef37b*



