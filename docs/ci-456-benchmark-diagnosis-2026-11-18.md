# CI #456 Benchmark 接线首跑失败 · 诊断记录（2026-11-18）

> 性质：D298 接线后首次远端 CI 失败的**只读诊断**。本轮未改任何源码 / CI / 测试 / 门禁，
> 未提交 / 未推送，工作区保持干净。
> 纪律：区分「API 实读确证」与「静态推断」，推断不作为结论、不据此改判据。

## 1. 已确证（GitHub API 只读实读 + 本地复现）

| 项 | 事实 | 来源 |
|---|---|---|
| 触发 | D298 commit `bcc0256` push → 主 CI **run `43909092117`（#456）= FAILURE**；同 sha 另有 CodeQL run `43909092338` success | `actions/runs?event=push` |
| 失败 job | `acceptance` failure；`test-matrix (macos-latest)` failure（已知时间通道假红族，见台账 `macos-time-channel-flake`）；其余 13 job success 或按设计 skip | `actions/runs/43909092117/jobs` |
| 失败步骤 | `acceptance` step **20「启动 Benchmark」failure**，step 21–30 全部 skipped（VAmPI / DVWA / VulnLab / recall / 全方位验收门禁 / 随机化电池 / os-shell / OOB / 并发） | job steps 逐条 |
| 耗时 | step 20 起 `16:47:41Z`、止 `16:52:54Z` = **311s**；整 job 8m16s。step 19（Juice Shop）success 仅 8s | job steps started/completed 时间戳 |
| 失败信号 | check-run annotations 仅通用 `Process completed with exit code 1`，无业务错误行；`output.summary/text` 为空 | `check-runs/133451977655` |
| 后续 run | #459(11-17)、#460(11-18) 为 `event=schedule`、整轮 success，但 `if: github.event_name != 'schedule'` ⇒ acceptance **skipped**，不构成对 D298 接线的裁判 | `actions/runs/{459,460}` |
| 本机复现边界 | `node scripts/ci-benchmark.mjs check` 在本机因无 java 退出 1（正确行为）；`up` 在 win32 被脚本显式拒绝 ⇒ 本机无法复现失败现场 | 本地实跑 |

## 2. 已排除的假设（静态核对 pin 源码）

下载 pin `a452b3aafd232245d0753e54eb243d6651f8ef96` 的 BenchmarkJava 源码逐项核对：

- **codeload pin 可达**：HTTP 200，`content-disposition` 文件名与 pin 一致 ⇒ 非下载源问题。
- **keystore 在源码树内**（`.keystore`），cargo 8443 https 自签配置 `changeit` / `keyAlias=tomcat` 齐备 ⇒ 非缺证书。
- **HSQLDB 版本一致**：pom 声明 `hsqldb:2.7.4`，脚本 `hsqldbJar()` 拼 `hsqldb-${v}.jar` 会命中 ⇒ 非 jar 找不到。
- **dbname / 端口一致**：源码 `jdbc:hsqldb:hsql://localhost/benchmarkDataBase`（默认 9001），脚本显式 `--port 9001 --dbname.0 benchmarkDataBase` ⇒ 一致。
- **探针 URL 一致**：`https://127.0.0.1:8443/benchmark/sqli-00/BenchmarkTest00025?...` 与 README 本机配方逐字一致。
- **javac / enforcer**：pom `java.target=8`、`requireJavaVersion=8`（"至少 8" 语义），本机 README 用 JDK17 成功打包过 ⇒ 非 JDK 版本硬冲突。
- **脚本 `check`/`fail`/退出码**：退出码传播正确，无吞错链。

## 3. 待日志确认的推断（**不是结论**）

311s 的时间分布最可能与下列之一吻合，但**没有日志证据，不得据此改代码**：

1. `mvn package -Pdeploy` 冷构建阶段失败（CI 无 maven 缓存 / 无 aliyun 镜像，依赖全走 Maven Central）。
   —— 本机 README 明确配了 `~/.m2/settings.xml` aliyun 镜像；CI 侧未配。
2. 服务起了但 `waitReady()` 240s 探针超时（脚本 `waitReady` 默认 240s；311 ≈ 前序约 70s + 240s）。
   —— 可能成因：cargo 8443 未真正起来 / HSQLDB 表名未初始化 / 自签探针在该 runner 上行为差异。

脚本在失败时已把 `${LOG}` 尾部 40 行写进 `fail()` 抛出的 message（会进 stderr），
故**失败根因就在 #456 acceptance 的 step 20 日志尾部**，取到即可定性。

## 4. 定性所需的下一步（需授权 / 凭证）

日志 API `actions/jobs/133451977655/logs` 返回 **403 Must have admin rights**；本会话
`GH_TOKEN` 未设置，本机凭证通道被安全策略拦截（未绕过）。两条路任选其一：

1. **CI 页面**：打开 `https://github.com/fengxingxuerong/sqli-scanner/actions/runs/43909092117/job/133451977655`，
   展开 step「启动 Benchmark」，把尾部约 60 行（含 `[ci-benchmark] ✖` 那行）贴回。
2. **带 token 本地拉**：在允许的环境设 `GH_TOKEN` 后
   `curl -sL -H "Authorization: Bearer $GH_TOKEN" .../actions/jobs/133451977655/logs | tail -80`。

拿到日志后按 §2 的排除表对照，定位是 build 失败还是 waitReady 超时，再决定是否改
`scripts/ci-benchmark.mjs` / `ci.yml`（改则另起 D 批次，走完整门禁 + 自证）。

## 4b. 根因已定性（2026-11-18，用户提供 step20 日志 + curl 实证）

用户从已登录的 GitHub 页面贴回 step20 日志，`[ci-benchmark] ✖ 240s 内未就绪（9001/8443）`
前的有效行：`hsqldb 已起 pid=4038` / `cargo 已起 pid=4039` ⇒ 进程都拉起、build 成功，
**卡在 8443 探针**，落在 §3 假设 2（waitReady 超时）。日志尾部满是
`org.hsqldb.HsqlException: Network client is not a HSQLDB JDBC driver` —— 这是
`tcpOpen(9001)` 裸 TCP 探针触发的**无害噪音**，把 cargo 的真实错误刷掉了（诊断盲区）。

进一步 curl 实证（本地）：

| URL | 结果 |
|---|---|
| `downloads.apache.org/tomcat/tomcat-9/v9.0.122/bin/apache-tomcat-9.0.122.zip` | **404** |
| `archive.apache.org/dist/tomcat/tomcat-9/v9.0.122/bin/apache-tomcat-9.0.122.zip` | **200** |
| `downloads.apache.org/tomcat/tomcat-9/` 现存 | 仅 9.0.123 / 9.0.124 |

⇒ **真因**：pin 源码 `pom.xml` 写死 `version.tomcat=9.0.122`，该版本已从 downloads 撤下，
`mvn cargo:run` 下载 Tomcat 失败 ⇒ 8443 永不就绪。§3 的两条推断收敛为这一条，
HSQLDB 异常被降级为噪音（不是第二个根因）。

**已实施修复（D299）**：`scripts/ci-benchmark.mjs` 在 package 与 cargo:run 两处注入
`-Dtomcat.url=<archive 的 9.0.122>`（保留 pin 版本），守卫 D299-1/2/3 钉住、缺陷注入复验通过。
**未重跑远端 CI**，故修复效果待 #456 之后的 push CI 裁判，详见 TODO/CHANGELOG D299。

## 5. 对交付判定的影响（维持上一轮结论）

- D298 仍是「接线完成、远端未裁判」：台账 `benchmark-ci-wiring-d298` = unverified 维持，
  **不得**转 verified。
- v1.3.3 发版事实、tag、6 assets 不受影响（发行物对应 tag 快照，D298 在其后）。
- 24 小时内的两次 schedule run 不算验收，24/7 结论口径不变。
