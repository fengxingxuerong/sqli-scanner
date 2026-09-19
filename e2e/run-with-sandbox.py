#!/usr/bin/env python3
# ============================================================================
# e2e/run-with-sandbox.py —— 通用「隔离 MySQL 沙箱 + 靶场」运行器
# ============================================================================
# 用途：把任意需要真 MySQL 的 e2e 靶场套上隔离沙箱跑起来，无需占用宿主 3306。
#
# 背景：e2e/run-all.mjs 用端口探测（3306）判断依赖，本机无 MySQL 服务常驻，
#       导致 9 个靶场长期被标记「缺依赖」而跳过。而项目其实自带了隔离 MySQL
#       沙箱（e2e/udf-lab/mysql_sandbox.py），可以按需起停。
#
# 关键约束（踩过坑）：
#   宿主会在命令结束后回收后台进程 → 不能「先起沙箱、再另起命令用」，
#   必须把「起 → 用 → 停」收在同一进程内（launch() 的 with 块）。
#
# 用法：
#   python e2e/run-with-sandbox.py e2e/real-mysql-lab/verify.mjs
#   python e2e/run-with-sandbox.py e2e/pentest-lab/verify.mjs
#   python e2e/run-with-sandbox.py --list          # 列出推荐的沙箱靶场
#   python e2e/run-with-sandbox.py --drop-dir <entry>   # 用后销毁沙箱 datadir
# ============================================================================
import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
sys.path.insert(0, str(HERE / "udf-lab"))

import mysql_sandbox  # noqa: E402

# 推荐用沙箱跑的靶场（纯 MySQL 依赖，不涉及 PG）
SANDBOX_LABS = [
    ("real-mysql-lab", "e2e/real-mysql-lab/verify.mjs"),
    ("pentest-lab", "e2e/pentest-lab/verify.mjs"),
    ("csrf-lab", "e2e/csrf-lab/e2e.mjs"),
    ("crawl-lab", "e2e/crawl-lab/e2e.mjs"),
    ("redteam-lab", "e2e/redteam-lab/run-with-env.mjs"),
    ("waf-real", "e2e/waf-real/selftest.mjs"),
    # 文件读写闭环：宿主 mysqld 默认 secure_file_priv=NULL 只能 SKIP，套上沙箱（限定目录）就能真跑
    ("file-read", "e2e/fileops/exploit-file-read.e2e.mjs"),
    ("file-write", "e2e/fileops/exploit-file-write.e2e.mjs"),
]


def _find_node() -> str:
    managed = Path.home() / ".workbuddy" / "binaries" / "node"
    cands = sorted(managed.glob("versions/*/node.exe"), reverse=True)
    return str(cands[0]) if cands else "node"


def sandbox_env(inst: dict) -> dict:
    """把沙箱连接信息注入环境变量，供靶场读取。"""
    env = dict(os.environ)
    env.update({
        "MYSQL_HOST": inst["host"],
        "MYSQL_PORT": str(inst["port"]),
        "MYSQL_USER": inst["user"],
        "MYSQL_PASSWORD": inst["password"] or "",
        "MYSQL_DATABASE": "sqli_lab",
        # 沙箱把 secure_file_priv 指向这个目录（见 mysql_sandbox.py 的 my.cnf 模板）。
        # 文件读/写两套件要靠它把标记文件放进"被允许的那个目录"，否则在默认配置的机器上
        # 只能报 SKIP —— 而"限定一个目录"也正是现实里 DBA 唯一会批准的放行方式。
        "MYSQL_SECURE_FILE_DIR": str(inst.get("pluginDir") or ""),
        # 本地回环不走代理
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    })
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    env.pop("http_proxy", None)
    env.pop("https_proxy", None)
    return env


def main() -> int:
    ap = argparse.ArgumentParser(description="隔离 MySQL 沙箱 + e2e 靶场运行器")
    ap.add_argument("entry", nargs="?", help="靶场入口脚本（相对项目根）")
    ap.add_argument("--list", action="store_true", help="列出推荐用沙箱跑的靶场")
    ap.add_argument("--drop-dir", action="store_true", help="退出时销毁沙箱 datadir")
    ap.add_argument("--extra-arg", action="append", default=[], help="透传给靶场的额外参数")
    args = ap.parse_args()

    if args.list:
        print("推荐用隔离沙箱运行的靶场（纯 MySQL 依赖）：")
        for name, entry in SANDBOX_LABS:
            print(f"  {name:16} {entry}")
        return 0

    if not args.entry:
        ap.error("需要靶场入口路径，或用 --list 查看推荐列表")

    entry_path = PROJECT / args.entry
    if not entry_path.exists():
        print(f"[sandbox-run] 入口不存在：{entry_path}", file=sys.stderr)
        return 2

    node = _find_node()
    print(f"[sandbox-run] node = {node}")
    print(f"[sandbox-run] entry = {args.entry}")

    with mysql_sandbox.launch(keep_dir=not args.drop_dir) as inst:
        print(f"[sandbox-run] 沙箱就绪：{inst['host']}:{inst['port']} "
              f"user={inst['user']} db=sqli_lab")
        cmd = [node, str(entry_path), *args.extra_arg]
        proc = subprocess.run(cmd, env=sandbox_env(inst),
                              cwd=str(PROJECT), text=True)
        print(f"[sandbox-run] 退出码 = {proc.returncode}")
        rc = proc.returncode
    print("[sandbox-run] 沙箱实例已停止")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
