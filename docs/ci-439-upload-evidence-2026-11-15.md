# #439 / #445 CI 日志取证 · 2026-11-15

> 取证通道：`GH_TOKEN` 由 `git-credential-manager get` 取得（40 位，**token 本身不入库**）。
> 下列 URL 均可公开复现，但 `actions/jobs/<id>/logs` 需要 `repo` 权限的 token。
> GitHub Actions 日志有保留期，过期后须重新取证。

## 复现命令（模板，token 不写进文件）

```bash
export GH_TOKEN=$(printf 'protocol=https\nhost=github.com\n\n' \
  | "/c/Program Files/Git/mingw64/bin/git-credential-manager.exe" get \
  | sed -n 's/^password=//p')
# job 列表（run_id ≠ run_number）
node -e 'fetch("https://api.github.com/repos/fengxingxuerong/sqli-scanner/actions/runs/43441490696/jobs?per_page=100",{headers:{Authorization:"Bearer "+process.env.GH_TOKEN,"User-Agent":"x"}}).then(r=>r.json()).then(d=>console.log(d.jobs.map(j=>[j.id,j.name,j.conclusion].join(" | ")).join("\n")))'
# 原始日志
node -e 'fetch("https://api.github.com/repos/fengxingxuerong/sqli-scanner/actions/jobs/131945353484/logs",{headers:{Authorization:"Bearer "+process.env.GH_TOKEN,"User-Agent":"x"}}).then(r=>r.text()).then(console.log)'
```

## 一、#439 `sidecar-build` 上传失败根因（run `43441490696` / job `131945353484`）

日志 273 行 / 23283 B。关键原文（L220–L238，2026-11-13T14:30Z）：

```
2026-11-13T14:30:26.1462465Z ##[group]Run actions/upload-artifact@v4
2026-11-13T14:30:31.2752107Z Attempt 1 of 5 failed with error: Request timeout: /twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact. Retrying request in 3000 ms...
2026-11-13T14:30:39.2843370Z Attempt 2 of 5 failed with error: Request timeout: /twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact. Retrying request in 6677 ms...
2026-11-13T14:30:50.9672092Z Attempt 3 of 5 failed with error: Request timeout: /twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact. Retrying request in 8766 ms...
2026-11-13T14:31:04.7394299Z Attempt 4 of 5 failed with error: Request timeout: /twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact. Retrying request in 12583 ms...
2026-11-13T14:31:22.3310760Z ##[error]Failed to CreateArtifact: Failed to make request after 5 attempts: Request timeout: /twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact
```

另有一行 `##[warning]Node.js 20 is deprecated ... actions/upload-artifact@v4 ... forced to run on Node.js 24`，
是 warning，不是失败原因。

**定性**：GitHub Actions ArtifactService 的 `CreateArtifact` 请求 5/5 次超时 ⇒ 上传服务端可用性问题；
不是本仓 `ci.yml` 配置错、不是待上传文件缺失、不是 build 失败（step7 success）。
D290 的「取证上传容错 + 显式复核构建结论」对该形态对症。
**不构成**「上传服务已修复」的证据：服务端不在本仓可控范围，#445 只是本轮未复现。

## 二、#445 `acceptance` 套件级明细（run `43715975971` / job `132820105089`）

日志 1053 行 / 80892 B。关键原文（2026-11-15T13:24Z）：

```
2026-11-15T13:24:56.0549422Z ═══ 汇总 ═══
2026-11-15T13:24:56.0549942Z PASS  服务端单测　tests=4293 pass=4288 fail=0 skipped=5
2026-11-15T13:24:56.0565610Z SKIP  外部裁判 4 号（OWASP Benchmark：官方标注真值须全检出 + 同族安全用例零误报）　原因=环境不满足，未执行断言
2026-11-15T13:24:56.0566838Z 25 PASS / 0 BLOCKED / 0 FAIL / 2 SKIP
```

- 另一条 `[汇总] PASS 47 / FAIL 0 / SKIP 2（判定分母 47，共 49 条）` 是 **子套件**汇总，不是全局结论。
- SKIP 项定性：Benchmark 缺前置 `JDK17` / `Maven`；AI 报告网关端到端为 opt-in 且环境不满足。
- ⇒ **27/27 全断言不成立**（25 PASS / 2 SKIP），但「明细未知」升级为「明细与 SKIP 项已定性」。
- 口径差异：CI 服务端单测 `4293 / 4288 pass / 0 fail / 5 skip`；本地 facts
  `4293 / 4287 pass / 0 fail / 6 skip`。总数一致，skip 分布随环境不同，**两套口径不可互相覆盖**。
