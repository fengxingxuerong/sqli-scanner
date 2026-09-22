```
[pre] SQL Server @127.0.0.1:65039 可连（认证与查询均通过）
[pre] SQL Server @ 65039 | xp_cmdshell 初始 value_in_use=0
[step1] 靶场就绪 http://127.0.0.1:8284/num?id=1
[2026-09-22 13:26:34] [info] [opsec] 目标 127.0.0.1 为本地/私网地址：本次不走环境变量代理（proxyBypassLocal=true）；如需强制经代理请在 config.proxy 显式指定，或用 proxyBypassLocal=false 恢复旧行为
[step2] 注入点 283e732d（boundary=""）
[step3] osShell → {"ok":true,"value":"msshell_95203","autoEnabled":true,"error":null}

[PASS] MSSQL xp_cmdshell os-shell 真机闭环（含 auto-enable 路径）marker=命中
[cleanup] xp_cmdshell 已复原为 0
```
