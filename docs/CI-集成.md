# 在 CI 里用 sqli-scanner 当 SQLi 门禁

> 定位：本工具不做"更快的 sqlmap"，做**能进 CI 的 SQLi 交付件** —— 原生退出码 + SARIF + 授权声明清单，
> 这三样合起来让"SQL 注入扫描"从人工动作变成一个可判红/绿的流水线步骤。对照分析见
> [`竞品对标分析-2026-10-03.md`](./竞品对标分析-2026-10-03.md)。

<!-- 本文件所有"已实现"的断言都给了源码位置；文末有独立的可信度边界段，未在本仓 CI 真跑过的部分明确标注。 -->

## 一、退出码契约（可直接当门禁判据）

| 退出码 | 含义 | 实现 |
|:-:|---|---|
| `0` | 未发现 Critical / High | `server/bin/cli.js:691`（`summary.hasHigh ? 2 : 0`） |
| `2` | 发现 Critical 或 High | 同上 |
| `1` | 执行失败（参数/目标/环境错误；批量模式下"全批失败"） | `server/bin/cli.js:690`（`if (summary.allFailed) process.exit(1)`） |

口径与 README 首屏一致：`0` 未发现高危 / `2` 发现 Critical 或 High / `1` 执行失败。

> ⚠️ 注意 `1` 是"没扫成"，不是"没漏洞"。CI 里**不要**把 `1` 当"安全"吞掉 —— 它意味着**门禁本身失效**，
> 应当让 job 红。这正是本项目"声明与真值分处两地"纪律的延伸：失败必须显形，不能静默变绿。

## 二、GitHub Actions 示例

```yaml
name: sqli-gate
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # 1) 准备被扫目标（示例：本机起一个测试服务；生产用法是扫已部署的授权环境）
      #    这里省略，换成你自己的 target。

      # 2) 取扫描器（当前未发布 npm 包 / 无官方 Action，需 checkout 本仓）
      - uses: actions/checkout@v4
        with:
          repository: fengxingxuerong/sqli-scanner
          path: .sqli-scanner

      - uses: actions/setup-node@v4
        with: { node-version: '22' }
      - run: npm ci --prefix .sqli-scanner && npm ci --prefix .sqli-scanner/server

      # 3) 扫描：显式指定 sarif，退出码即门禁
      - name: Run SQLi scan
        id: scan
        run: |
          node .sqli-scanner/scripts/one-click-scan.mjs \
            -u "${{ vars.TARGET_URL }}" \
            -F html,json,sarif \
            -o scan-out \
            --scope "${{ vars.SCOPE }}" \
            --quiet
        # 默认：非零退出码让本 step 红 → job 红 → PR 被挡

      # 4) 无论成败都留证据（失败时最需要看报告）
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sqli-report
          path: scan-out/

      # 5) SARIF 进 GitHub Security 面板
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: scan-out/report.sarif
```

要点：

- **`-F ...,sarif`** 才会产出 `report.sarif`（默认格式是 `html,json,markdown`）。SARIF 生成于
  `server/src/services/ReportGenerator.js:430`（SARIF 2.1.0 schema），REST 侧也可导出
  （`server/src/api/scanRoutes.js:615`）。
- **`--scope`** 是授权范围声明，越界目标在**发起任何请求前**被拒（`core/scopeGuard.js`）。
  CI 里务必显式给，别依赖"默认同源"。
- **`if: always()`** 上传：门禁红的时候，报告才是最有用的东西。
- 回环 / 内网目标需 `SSRF_ALLOW_PRIVATE=1`（或 `SSRF_ALLOW_CIDRS=<CIDR>`）。

## 三、对接 DefectDojo / 其他平台

`report.sarif`（SARIF 2.1.0）是通用格式，除 GitHub Security 外可直接喂给 DefectDojo 的
SARIF 解析器、或任何支持 SARIF 的聚合平台。机器可读的完整证据链在 `report.json`，
人读交付物在 `report.html`，扫描元信息 + 文件清单 + **授权声明**在 `manifest.json`。

## 四、批量 / 多目标

`-m` 支持 URL 列表或**请求集合**（Burp XML · HAR · Postman · OpenAPI JSON），语义是
**故障隔离 + 摘要点名 + 退出码三分**（有高危 `2` / 全批失败 `1` / 其余 `0`）：

```bash
node .sqli-scanner/scripts/one-click-scan.mjs -m targets.txt -F json,sarif -o scan-out
```

## 五、可信度边界（诚实标注，勿外推）

| 断言 | 状态 |
|---|---|
| 退出码 `0/1/2` 语义 | ✅ 已实现并本机验证（`cli.js:690-691`，README 首屏有真机实测样例） |
| `report.sarif`（SARIF 2.1.0） | ✅ 已实现（`ReportGenerator.js:430`），`--formats` 含 `sarif` 时产出 |
| `manifest.json` 含授权声明 | ✅ 已实现（README「结构化漏洞报告」段） |
| 上面的 **workflow YAML 本身** | ⚠️ **示例，未在本仓 CI 里端到端跑过**。它引用的每个开关都在 CLI 开关表内，但"Actions 真跑通"没有证据 |
| 官方 GitHub Action（`action.yml`） | ❌ **尚无**。当前必须 checkout 本仓再 `node server/bin/cli.js`。这是"CI 就绪"定位上的**已知空位**，也是后续候选 |

> 纪律说明：本仓反复栽在"把声明当真值"上（见 `竞品对标分析-2026-10-03.md` 的两条自我更正）。
> 所以这里把"已实现"和"未验证"分开列 —— 前者给源码位置，后者直说没跑过，不拿示例冒充能力。

## 六、复现命令

```bash
# 本地验退出码（需一个授权目标）
node scripts/one-click-scan.mjs -u "http://127.0.0.1:8130/items?cat=1" -F html,json,sarif
echo $?   # 2 = 发现 High

# 确认 sarif 产出
ls reports/*/report.sarif

# 确认 CLI 开关存在（workflow 示例引用的都应在内）
node server/bin/cli.js --help | grep -E -- '-F|--formats|--scope'
```
