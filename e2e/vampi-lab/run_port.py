"""VAmPI 对照实例启动器（e2e 外部裁判 2 号辅助脚本，D122 入库）。

为什么需要它：上游 `VAmPI-master/app.py` 把端口硬编码成 5000，而 A/B 对照要求
**漏洞实例在 5000、参数化实例在 5001**（`vulnerable` 开关以外的唯一变量是端口）。
`PORT` 环境变量只改端口；`vulnerable` 仍由官方 `config.py` 读 env 决定，本脚本
不改任何业务逻辑。

用法（在 VAmPI 源码目录内执行，venv 用绝对路径即可）：

    # 漏洞实例（拼接，默认 5000）
    tokentimetolive=7200 <venv>/Scripts/python app.py

    # 对照实例（参数化，5001）
    PORT=5001 vulnerable=0 tokentimetolive=7200 \
        <venv>/Scripts/python <repo>/e2e/vampi-lab/run_port.py

⚠ `tokentimetolive` 必须显式设大（官方默认 60 秒）：一轮扫描 100+ 请求会跨过期，
中途全部 401 ⇒ 真假响应恒等（假零误报 / 假漏检），见 e2e/vampi-lab/README.md。
"""
import os

from config import vuln_app

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    # 关 debug + reloader：reloader 会 fork 子进程，脚本化启动时父进程退出即失联。
    vuln_app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)
