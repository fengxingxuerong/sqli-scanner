# e2e/mssql-lab 结果产物

## 如何复现

前提：本机已安装并启动 SQL Server 2022 Express，命名实例 `SQLI`，TCP 监听 `127.0.0.1:65039`，
且 `sa/SqLi_2026_T!` 可登录（库 `sqli_lab_mssql` 由脚本自建）。

```bash
node e2e/mssql-lab/e2e.mjs          # 双上下文三通道检测
node e2e/mssql-lab/dump.e2e.mjs     # 拖库正确性（含中文/单引号/跳号）
node e2e/mssql-lab/osshell.e2e.mjs  # xp_cmdshell os-shell（含 auto-enable 真实覆盖）
```

## 产物

| 文件 | 内容 |
|---|---|
| `VERIFICATION-2026-09-22.md` | 带版本凭证的验证报告（环境事实 + 4/4 PASS 汇总 + 未覆盖边界） |
| `last-run.md` | `e2e.mjs` 最近一次执行的完整 stdout |
| `last-run-dump.md` | `dump.e2e.mjs` 最近一次执行的完整 stdout |
| `last-run-osshell.md` | `osshell.e2e.mjs` 最近一次执行的完整 stdout |

> ⚠️ 该靶场依赖**本机静默安装**的 SQL Server 实例，CI 上必然缺项，会打印 `[SKIP]` 并以 0 退出
> （见 `e2e/lib/dbProbe.mjs`）。要让它在 CI 上真跑，需先做容器化改造（凭证/端口/连接方式参数化）。
