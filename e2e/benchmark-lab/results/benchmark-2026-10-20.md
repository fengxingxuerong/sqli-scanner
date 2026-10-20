# OWASP Benchmark 子集实跑（D114，2026-10-20）

## 环境

| 项 | 值 |
|---|---|
| 靶场 | OWASP Benchmark for Java **1.2**（`.box-agent-scratch/BenchmarkJava-master`，官方源码 tarball） |
| 技术栈 | JDK **17.0.2** + Maven **3.9.11** + cargo Tomcat + HSQLDB **2.7.4** |
| 地址 | `https://127.0.0.1:8443/benchmark`（自签证书；扫描 config `insecureTls=true`） |
| 起法 | `mvn initialize clean package cargo:run -Pdeploy -Dspotless.check.skip=true -Dspotless.apply.skip=true` |
| 真值来源（外部） | 官方 `expectedresults-1.2.csv`（`real vulnerability true/false`） |
| 子集 | **20/504** sqli 用例：query 真值 10 + query 安全 8 + header 真值 2 |
| 扫描配置 | `concurrency=1 ratePerSec=0 retry=0 timeoutMs=12000 level=2 risk=2 techniques=union,boolean,error,time productionMode=false insecureTls=true` |

## 结果（2026-10-20 17:37）

| 类别 | 结果 |
|---|---|
| query 真值 | **3/10**（检出 00024 / 00027 / 00034） |
| header 真值 | **1/2**（检出 00018；00194 漏检） |
| 真值合计 | **4/12** |
| query 安全对照 | **0/8 误报** |
| 安全对照证据不足（请求<30） | **0** |

漏检清单：

- query：`BenchmarkTest00025, 00026, 00032, 00033, 00037, 00038, 00039`
- header：`BenchmarkTest00194`

## 本轮修掉的 lab 接线问题（不是引擎修复）

首跑 header 两条是 **0 请求 + 「没有匹配到任何注入点」**：`TargetParser` 只在
`level>=3` 或 `config.testHeaders` 时把 `headerParams` 变成注入点，而本 lab 全局
`level=2`。已在 `run.mjs` 对 header 用例显式补 `testHeaders: true`；重跑后 header
用例真实发出 87/95 请求，`BenchmarkTest00018` 检出（error / HSQLDB）。

## 复跑

```bash
BENCHMARK_BASE=https://127.0.0.1:8443/benchmark node e2e/benchmark-lab/run.mjs
```

## 边界（不得越界引用）

- **子集 ≠ 全集**：20/504，且单轮；当前 4/12 只代表这个子集/这次运行，不是
  「Benchmark 检出率」。
- **已知漏检缺口**：query 7 例 + header 1 例未检出，按 DVGA 同口径登记为
  `e2e/reference-labs.json` 参考靶场，不接 acceptance/run-all；修缺口后再转门禁。
- 官方标注 `real=false` 的用例仍可能因别的缺陷（如报错回显差异）误报；本子集
  安全对照 0/8 只证明这 8 个安全用例零误报。
- Benchmark 是外部项目，仓库不 vendor；未就绪时套件按设计 SKIP，不计通过。
- 本套件只读官方用例端点，不写业务数据。
