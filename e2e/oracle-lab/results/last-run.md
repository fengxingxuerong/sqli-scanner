```
[pre] Oracle @127.0.0.1:1521/FREEPDB1 可连（认证与查询均通过）
[pre] Oracle FREEPDB1 users 5 行基线
[step1] 靶场就绪 http://127.0.0.1:8286/num?id=1
[2026-09-22 13:26:14] [info] [opsec] 目标 127.0.0.1 为本地/私网地址：本次不走环境变量代理（proxyBypassLocal=true）；如需强制经代理请在 config.proxy 显式指定，或用 proxyBypassLocal=false 恢复旧行为
[num] techs=["union","error","boolean"] dbms=Oracle
[str] techs=["union","error","boolean"] dbms=Oracle
[step3] 拖取 5 行: 全对

[PASS] Oracle 真机全链路：检测(union/error/boolean) + 拖库正确性
```
