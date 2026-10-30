# 外部裁判 5 号 · VulnLab（2026-10-29T19:54:02.963Z）

- 靶场：https://github.com/hediwen831-star/vulnlab（D:\projects\sqli-scanner\.verify-labs\vulnlab，php=D:/tools/php83/php.exe，http://127.0.0.1:8135）
- 真值来源：对方 benchmark/manifest.yaml（三档映射 + high 档 52 条绕过断言守护）

| 档位 | 语义 | 预期 | 实测 | 请求 | verdict |
|---|---|---|---|---|---|
| low | 数字型直拼（无引号无预处理） | 检出 | union·id·High、error·id·High、boolean·id·Medium | 121 | vulnerability_detected |
| medium | 黑名单非递归替换，官方标注双写可绕 | 检出 | error·id·High | 92 | vulnerability_detected |
| high | :id 参数化预编译（修复对照档） | 零检出 | 未检出 | 127 | no_vulnerability_detected |

结论：通过（真值档全检出 + 修复档零误报 + 证据充分）
