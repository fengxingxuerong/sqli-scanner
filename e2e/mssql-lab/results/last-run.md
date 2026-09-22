```
[pre] SQL Server @127.0.0.1:65039 可连（认证与查询均通过）
[mssql-lab] SQL Server 2022 @ 127.0.0.1:65039（sqli_lab_mssql.users 就绪）
[mssql-lab] 靶场就绪 http://127.0.0.1:8284/num?id=1
[2026-09-22 13:26:04] [info] [opsec] 目标 127.0.0.1 为本地/私网地址：本次不走环境变量代理（proxyBypassLocal=true）；如需强制经代理请在 config.proxy 显式指定，或用 proxyBypassLocal=false 恢复旧行为
[num] techs=["union","error","boolean"] dbms=SQL Server
[str] techs=["union","error","boolean"] dbms=SQL Server

[PASS] SQL Server 真机全链路：HTTP 注入点 → 真 MSSQL 执行 → 检出
```
