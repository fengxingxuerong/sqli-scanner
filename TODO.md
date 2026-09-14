# sqli-scanner 待办清单

> 生成于 2026-09-13 全面审计后。P0 四项已全部完成（见文末「已完成」），本清单按优先级维护后续优化空间。
> 原则：每项标注依赖前提与验证口径，避免「文件存在=能力存在」的误读。

---

## P1 · 实战视角高价值

### 1. 真实 ModSecurity/Coraza WAF 验证（可执行步骤）
- **依赖**：需有 Docker 的机器（本机无 docker，exit 127 已实证；Dockerfile/docker-compose.yml 已在仓库根目录，可复用）
- **现状**：全部 WAF 绕过结论均为「自实现 CRS 执行器 ≈PL3」口径（`e2e/waf-real`，CRS v4.1.0 官方规则原文 942/930），README 已诚实标注但这是对外可信度最大短板
- **验收**：真实 ModSecurity + libinjection 引擎下复测 tamper 链绕过率，README「WAF 绕过能力实测口径」表新增一行真实引擎数据

#### 步骤 0 · 前置确认（Docker 机器上）
```bash
docker --version && docker compose version   # 均需可用
git clone <repo> && cd sqli-scanner          # 或同步工作区到 Docker 机器
```

#### 步骤 1 · 搭真实 ModSecurity 反代容器（`e2e/waf-real/modsec/`）
新建 `docker-compose.modsec.yml`（ owasp/modsecurity-crs:nginx 官方镜像，一次性起完整栈）：
```yaml
services:
  modsec:
    image: owasp/modsecurity-crs:nginx
    ports: ["8088:8080"]
    environment:
      - PARANOIA=3                          # 对齐现有 crs-engine 的 ≈PL3 口径
      - ANOMALY_INBOUND=5                   # 默认阻断阈值
      - BACKEND=http://host.docker.internal:8151
      - ENGINE_MODE=DETECTION_ONLY_NO_BLOCK # 先观察模式校准，再切阻断
    extra_hosts: ["host.docker.internal:host-gateway"]
    volumes:
      - ./modsec/crs-custom.conf:/etc/modsecurity.d/instance.conf:ro
```
- `crs-custom.conf`：`Include` 官方 CRS，显式开启 `SecRuleEngine On` + libinjection（`SecRule ARGS "@detectSQLi"`）
- 关键点：**用 CRS v4.1.0**（与 `e2e/waf-real/crs/REQUEST-942-SQLI.conf` 同版本），镜像 tag 固定为 `owasp/modsecurity-crs:nginx@sha256:<digest>` 保证可复现

#### 步骤 2 · 确定靶场后端拓扑
- 后端 = 现有 `real-mysql-lab`（3306 MySQL + lab-app，端口 8151），**引擎扫描目标指向 8088（ModSec）而非直连后端**
- Windows 主机跑 lab-app：容器内 BACKEND 用 `host.docker.internal:8151`；Linux 机器用宿主 IP
- 自检：`curl "http://<docker-host>:8088/num?id=1"` 正常回显 + `curl "http://<docker-host>:8088/num?id=1' AND 1=1-- -"` 被 403 → WAF 生效

#### 步骤 3 · 观察模式校准（防阻断阈值差异污染对拍）
- `DETECTION_ONLY_NO_BLOCK` 下跑一遍 `tamper-sweep.mjs`（改 BASE 指向 8088）
- 从容器日志（`docker logs`，`ModSecurity: Warning.` 行）提取真实命中规则号与 anomaly 分值
- 若 PL3 + libinjection 的命中集与自实现 crs-engine 的命中集有系统性差异（预期会有：libinjection 是额外探测器），逐条记录差异样本（payload / 命中规则 / 是否拦截）

#### 步骤 4 · 阻断模式正式复测
- 切 `SecRuleEngine On`（去 DETECTION_ONLY），复跑与现有口径**完全相同**的场景矩阵：
  - `tamper-sweep.mjs`（tamper off/on 对比）
  - `waf-verify.mjs`（num/str/like/blind/orderby 5 端点 + safe/echo 安全对照）
- 记录两组数：tamper off X/5 → tamper on Y/5 技术位；安全对照误拦数（应为 0，非 0 说明 CRS 误报，需样本分析）

#### 步骤 5 · 对拍报告与口径更新
- 结果落 `e2e/waf-real/results/modsec-docker-<date>.md`：与自实现引擎逐场景对照表（检出/绕过/差异规则号）
- README「WAF 绕过能力实测口径」表新增一行：`真实 ModSecurity（owasp/modsecurity-crs:nginx，PL3+libinjection）`，数字照实填；若与自实现差异大，在表下加一句差异归因（如「libinjection 额外拦截了 X 类 payload」）
- 若 Docker 不可得，可降级跑 **Coraza**（Go 实现，`docker pull corazawaf/coraza-spoa` 或本地 `go run`），口径注明「Coraza（ModSecurity 兼容引擎）」——同样是真实引擎，可信度高于自实现

#### 常见坑（提前备好）
- 镜像默认 `ENGINE_MODE` 与 `PARANOIA` 环境变量名随版本变——起容器后 `docker exec` 进去 `cat /etc/modsecurity.d/*.conf` 核对生效值，别信文档
- Windows Docker Desktop 的 `host.docker.internal` 在 Linux 机器不存在——用 `host-gateway` extra_hosts 或直接 `--network host`
- CRS 版本漂移——务必固定镜像 digest 并在报告中记录镜像版本 + CRS 版本 + PARANOIA + 阻断阈值四要素，否则结果不可比

### 2. NTLM 接线 HttpClient
- **现状**：`core/ntlmAuth.js` 已修复三重缺陷（语法断裂/缺 import/DES key [7:14] 截断）并通过 12 项单测，但 **HttpClient 未消费**——`auth.type=ntlm` 不可用（README 认证口径表已标注 ⚠️）
- **实现点**：仿照 `_digestAuthHeader`（httpClient.js:1541）增加 NTLM 三步握手分支；401 + `WWW-Authenticate: NTLM` 时用 `extractNtlmChallenge` → `createType3Message` 重放
- **部署前提**：DES 原语需服务以 `--openssl-legacy-provider` 启动（OpenSSL 3 默认禁用 des-ecb）；启动脚本与 docs/deploy.md 需同步注明，运行时应探测降级提示
- **验收**：新增 NTLM mock 服务端 e2e（401→Type2→Type3→200），README 口径表更新为 ✅

### 3. 二阶跨角色双身份靶场 e2e
- **现状**：`secondOrder.storeCookies`（低权写入）/`triggerCookies`（高权读出）已实现并通过 20/20 单测 + real-world-lab 9/9 回归，但缺端到端双角色场景
- **实现点**：real-world-lab 增加 `/panel-admin`（仅 admin 会话可见的触发页），验证跨角色配置能检出单身份场景漏掉的二阶注入
- **验收**：verify.mjs 新增场景 PASS，README 二阶口径补一句实测结论
- **✅ 已完成（2026-09-14）**：real-world-lab 新增 admin-only 触发页 `/admin/panel`（users.admin 角色门禁 403）+ admin 会话禁写评论（403）；verify.mjs 新增 `second_order_crossrole` 场景——alice（user 会话）写评论、/admin/panel（triggerCookies: admin 会话）触发，检出 `[second_order]`（25 请求 4.1s），自检三连（写入 200 / admin 触发 500 真实引爆 / user+匿名 403 跨角色门禁）全过；现有 second_order 场景切 user 身份后零回归（real-world-lab 10 场景全 PASS）。README 二阶口径已补实测结论

### 3b. redteam-lab env.mjs 间歇性死亡根因排查（✅ 已结案 2026-09-14：连接风暴）
- **现象**：spawn 版 env.mjs 在 run-scan 中段无栈死亡（1/26、4/26、6/26），死亡点随机
- **根因（已坐实）**：**lab-app 的 `q()` 每条查询新建 TCP 连接再销毁**——26 靶点全量扫描 ≈ 2600 次高频短连，连接风暴下 node（靶场）与 mysqld 双双 native fast-fail（CrashDumps 同时存在 node 崩溃观测 `0xC0000409` 与 `mysqld.exe.5948.dmp`）
- **排查过程**（redteam-death-diag.mjs，5 轮对照实验）：
  - 抓到退出证据：`code=3221226505(0xC0000409) signal=null killed=false` → **native fast-fail 自崩，排除外部杀/进程树关联假设**（外部杀必有 signal）
  - stderr 全空 → 排除 JS 异常路径；内存曲线 154→270MB 正常 → 排除 OOM；pipe/inherit 均死 → 排除 stdio 管道断裂；`--report-on-fatalerror` 无报告（fast-fail 绕过诊断钩子）；WER/Defender 无记录 → 排除 EDR
  - 池化改造后连续 2 轮全存活（18/26、19/26），gate-check 19/19 rate=100% [PASS] → 根因坐实
- **修复**：`q()` 与两处 safe 端点改用常驻连接池（poolVuln/poolSafe 分池，严格保留 multipleStatements 语义边界防堆叠能力泄漏到安全端点）
- **教训**：靶场自身的「每请求建连」反模式 + 高频扫描 = 双进程 native 崩溃；门禁此前形同虚设掩盖了它。`--report-on-fatalerror` 对 fast-fail 无效，Windows 下抓这类死亡要靠 exit code（0xC0000409）+ CrashDumps 目录

### 4. 大文件二期拆分（照 scanRunner 模式）
- **对象**：`core/httpClient.js`（1913 行）、`engine/Extractor.js`（1388 行）、`engine/ScanManager.js`（1003 行）
- **模式**：参考 scanRunner 第一轮「阶段外移」——纯搬移封边、输入输出注释明确、行为零变化
- **验收**：全量单测 + e2e 关键 lab（real-mysql/waf-real）回归通过

## P2 · 工程化补强

### 5. coverage 门禁数据刷新
- vitest.config.ts 阈值是 2026-09-03 口径（stmts 90/branch 77/func 69），本轮修复后重测并按实测收紧 ~3pt 余量

### 6. 弱引用模块补直接单测
- `tamperRoutes` / `digestAuth` / `egressOpts` / `reportDelivery` 目前仅 1 个测试文件弱引用；ntlmAuth 盲区曾藏了三重缺陷，教训明确

### 7. docs/ 数字口径单一来源
- 32 个 md 中的测试数/引擎等级表易失真（本次审计修正 2 处）。可复制 `dbmsEvidence.js` 模式：数字由代码统一导出，文档生成时引用

### 8. 前端测试环境差异固化
- ~~已修 `vitest.config.ts` 强制 `NODE_ENV=test`（jsdom 下 React production build 导致 246 个假失败）+ 契约测试 `@vitest-environment node`~~（已完成）；**CI 已搭建**（`.github/workflows/ci.yml`，2026-09-13）：lint/typecheck + 前端 vitest + 服务端 1767 用例 + `run-all` 自足 6 套靶场，ubuntu/Node 24。**剩余动作：push 后观察首次 CI 实跑**——Linux 与 Windows 的路径/换行差异（e2e 脚本/测试断言）只有真跑才能暴露，若单测在 Linux 出现平台性失败按最小修复处理

---

## 环境清理备忘（一次性）

- [x] NRPT 规则 `.ooblab.test` / `.oob-lab.local` 已提权移除（2026-09-11 完成，`Get-DnsClientNrptRule` 确认清零）
- [x] MySQL 3307 实验实例（secure-file-priv 放行模式）已回收
- [ ] MySQL 3306 常规实例现为后台进程（bash_id 3eb9c610，runtime 存活）；按 mysql-start.bat 语义属本机常驻，无需处理，但注意下次开机需手动拉起
- [x] `D:/mysql/data-backup-20260912`（187MB）**已删除**（2026-09-14，数据未损坏已实证，雪绒确认无回滚需求）
- [ ] 实验用 pg 驱动 --no-save 安装已核验未污染 package.json，无需处理

## 诚实边界（README 已标注，勿夸大）

- 真实 ModSecurity/Coraza/商业云 WAF 未实测
- SQL Server `xp_dirtree` / Oracle `UTL_HTTP` OOB 模板未真机验证
- ⛔ 等级数据库（SQL Server/Oracle/TiDB/DM8 等 11 种）仅有模板适配，结论视为待复核线索
- fileWrite / UDF / os-shell 为未真机验证的实验能力

---

## 已完成（2026-09-13 审计批次，留档防回归）

| 项 | 内容 | 验证 |
|---|---|---|
| NTLM 死文件修复 | 语法断裂 + 缺 import + DES key 截断三重缺陷；MD4 注释向量错误记忆值修正（权威对拍 6/6） | 12 项单测，legacy provider 下 12/12 |
| 前端测试假失败 | `vitest.config.ts` 强制 `NODE_ENV=test`（246 假失败恢复） | 40 文件 263/263 |
| qa_theme 错误断言 | `0f172a`（light 前景色）→ `getComputedStyle(body)` 断言 `rgb(10,14,22)` | 前端全量绿 |
| 契约测试挂起 | `@vitest-environment node`（jsdom 覆盖 node:url 导出） | 9/9 |
| eslint 清零 | scanRunner 20+ 死 import、detect.js `schedulerRef` 未定义真 bug | eslint exit 0 |
| 文档数字对齐 | README 徽章/正文 → 263/1767；docs 评估 1719 → 1753 复测口径 | 双端全量：前端 263/263、服务端 1764 pass/0 fail/3 skip |

> 更早批次成果（DNS OOB 真机验证、强动态页/定库加固、二阶跨角色、sqli-labs 23/23、L46 词边界修复等）见 README 各「实测口径」段与 `e2e/*/results/`。
