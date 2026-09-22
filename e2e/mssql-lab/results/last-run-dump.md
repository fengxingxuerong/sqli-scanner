```
[pre] SQL Server @127.0.0.1:65039 可连（认证与查询均通过）
[pre] 基线 users 5 行（含中文/单引号/跳号）
[step1] 靶场就绪 http://127.0.0.1:8285/num?id=1
[2026-09-22 13:26:28] [info] [opsec] 目标 127.0.0.1 为本地/私网地址：本次不走环境变量代理（proxyBypassLocal=true）；如需强制经代理请在 config.proxy 显式指定，或用 proxyBypassLocal=false 恢复旧行为
[step2] 注入点 283e732d（boundary="" columns=3）
[step3] databases: "master,tempdb,model,msdb,sqli_lab_mssql"
[step4] 拖取 5 行
[fails] 无

[PASS] MSSQL 拖库正确性：5/5 行，中文/单引号/跳号全对
```
