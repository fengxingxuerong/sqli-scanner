# UDF 接管：验证环境与边界（2026-09-18 起，如实说明，勿夸大）

> 本文原是 README「利用能力实测口径」中的 UDF 沙箱小节，2026-09-27 为给 README 瘦身迁移至此
> （内容逐字保留）。README 保留能力状态表与硬前提。

历史上两个验证脚本连续两轮被环境安全审批拦截。现改为在 **`e2e/udf-lab/` 内的隔离
MySQL 实例**中运行 —— 既让验证可自动化，又把风险面从本机收窄到「用完即毁的实例」：

```
e2e/udf-lab/
  udf_sys.c              最小 UDF：udf_echo(s) 原样返回 + sys_eval(cmd) 执行并返回 stdout
  build-udf.py           MSVC x64 构建（显式 INCLUDE/LIB/PATH，不依赖 vcvars/reg.exe）
  mysql_sandbox.py       隔离 MySQL 实例：独立 datadir + 端口 3308 + secure_file_priv/plugin_dir
                         双锁在沙箱内；--verify-isolation-ephemeral 实测越权写入被拒
                         my-sandbox.ini **由本脚本自动生成**（--print-ini 可只读预览），
                         不依赖磁盘遗留文件 —— 修复了「新克隆/CI 上 --init 因缺配置直接失败」
  sandbox.py             沙箱执行器：起隔离实例 → 跑验证脚本 → 必停；进程/写入/出站三重白名单
  _sandbox_node_guard.cjs  Node 侧守卫（--require 预加载）：真实拦截 node 内越权动作
  udf_direct_probe.py    直连基线：DLL 落地 → 注册 → 调用 → 回传（不经注入通道）
  udf-register.e2e.mjs   经注入通道：注册 + 调用（不含命令执行）
  udf-takeover.e2e.mjs   经注入通道：注册 + sys_eval 执行命令 + Exploiter.osShell
```

实测结果（2026-09-18）：

| 验证项 | 结果 | 外部事实源 |
|---|---|---|
| 沙箱隔离边界 | ✅ PASS 5/5 | 越权写入 `C:\Windows\Temp` 被 `ERROR 1290` 拒绝（真跑，非断言） |
| 沙箱负向拦截 | ✅ PASS 7/7 | powershell/危险 cmd/越权写/外网连接全被拦；白名单内命令放行 |
| UDF 直连基线 | ✅ PASS 6/6 | `mysql.func` 计数 + 回传值等于传入标记 |
| `udf-register` | ✅ PASS | 注入链路✅ 直连✅，回传值双向一致 |
| `udf-takeover` | ✅ PASS | `sys_eval('cmd /c echo ...')` 输出 == 标记；`whoami` 返回真实身份；`Exploiter.osShell` → `{ok:true}` |

**沙箱能力边界（必须如实告知，实测得出）**：

1. **Python 审计钩子不穿透进程边界** —— 钩子只在自身进程生效，被测 node 进程内部
   起的子进程对它不可见。故 node 侧另有 `--require` 预加载的守卫负责真实拦截。
2. **「写文件被拦」不等于沙箱能力** —— 部分拦截来自 Windows 自身权限（实测 `C:/` 根目录
   写入返回 `EPERM`）。凡引用此类证据必须标注来源。
3. 本沙箱定位是「**受控执行 + 取证**」，不是对抗恶意代码的强隔离容器。真实隔离边界由
   **隔离 MySQL 实例**提供（脚本能破坏的最大范围 = 那个用完即毁的 datadir）。
4. 仍未复现的环节：**经 SQL 通道投递 DLL 本体**。DLL hex 约 24 万字符，远超 Node 的
   URL/header 上限（16KB）；走 POST body 也需目标放宽限制（Express json 默认 100kb）。
   故 `udf-takeover` 采用「库文件已落地」前提，只验证**注册与执行**链路。
   实际接管通常靠精简体积的 UDF 库或配合已有文件写权限。
