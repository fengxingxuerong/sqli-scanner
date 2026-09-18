#!/usr/bin/env python3
# ============================================================================
# e2e/waf-lab/compare-real.run.py —— WAF A/B 实验的真 MySQL 沙箱启动器
# ============================================================================
# 为什么需要它：
#   宿主会在命令结束后回收后台进程，所以「先 --start 沙箱、再另起命令跑扫描」
#   必然落空。必须把「起沙箱 → 跑扫描 → 停沙箱」收在**同一个进程**里。
#
# 做法：复用 e2e/udf-lab/mysql_sandbox.py 的 launch() 上下文管理器，
#       在其存活期间以子进程方式调 compare-real.e2e.mjs，把连接信息经环境变量传入。
#
# 用法：
#   python e2e/waf-lab/compare-real.run.py
#   python e2e/waf-lab/compare-real.run.py --keep-dir   # 保留沙箱 datadir
# ============================================================================
import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent.parent
sys.path.insert(0, str(PROJECT / "e2e" / "udf-lab"))

import mysql_sandbox  # noqa: E402  （同目录已加入 sys.path）

NODE_SCRIPT = HERE / "compare-real.e2e.mjs"


def _find_node() -> str:
    """优先用受管 Node（版本确定），否则回落到 PATH 上的 node。"""
    managed = Path.home() / ".workbuddy" / "binaries" / "node"
    candidates = sorted(managed.glob("versions/*/node.exe"), reverse=True)
    if candidates:
        return str(candidates[0])
    return "node"


def main() -> int:
    ap = argparse.ArgumentParser(description="WAF A/B 实验（真 MySQL 沙箱）")
    ap.add_argument("--keep-dir", action="store_true", help="保留沙箱 datadir（默认保留）")
    ap.add_argument("--drop-dir", action="store_true", help="退出时删除沙箱 datadir")
    args = ap.parse_args()

    node = _find_node()
    print(f"[waf-ab] node = {node}")

    keep = not args.drop_dir  # 默认保留（沙箱 datadir 可复用，重建成本高）
    with mysql_sandbox.launch(keep_dir=keep) as inst:
        print(f"[waf-ab] 隔离 MySQL 沙箱已就绪：{inst['host']}:{inst['port']} "
              f"user={inst['user']} db=sqli_lab")

        env = dict(os.environ)
        env.update({
            "MYSQL_HOST": inst["host"],
            "MYSQL_PORT": str(inst["port"]),
            "MYSQL_USER": inst["user"],
            "MYSQL_PASSWORD": inst["password"] or "",
            "MYSQL_DATABASE": "sqli_lab",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        env.pop("HTTP_PROXY", None)
        env.pop("HTTPS_PROXY", None)

        proc = subprocess.run([node, str(NODE_SCRIPT)], env=env,
                              cwd=str(PROJECT), text=True)
        rc = proc.returncode
        print(f"[waf-ab] 扫描子进程退出码 = {rc}")
    # with 块退出即停止沙箱实例
    print("[waf-ab] 沙箱实例已停止")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
