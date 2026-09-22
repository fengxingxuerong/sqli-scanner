# e2e/oracle-lab 结果产物

## 如何复现

前提：本机已安装并启动 Oracle AI Database 26ai Free，监听 `127.0.0.1:1521`，
PDB 为 `FREEPDB1`，且 `SYS/SqLi_2026_0!` 可以 SYSDBA 登录（thin 模式，无需 Instant Client）。

```bash
node e2e/oracle-lab/e2e.mjs
```

## 产物

| 文件 | 内容 |
|---|---|
| `last-run.md` | 最近一次执行的完整 stdout（含版本凭证、检出技术位、拖库逐行核对结果） |

> ⚠️ 该靶场依赖**本机静默安装**的 Oracle 实例，CI 上必然缺项，会打印 `[SKIP]` 并以 0 退出
> （见 `e2e/lib/dbProbe.mjs`）。要让它在 CI 上真跑，需先做容器化改造（凭证/端口/连接方式参数化）。
