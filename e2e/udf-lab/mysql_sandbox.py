#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
e2e/udf-lab/mysql_sandbox.py —— 隔离 MySQL 沙箱实例的启停/探测（纯标准库）

============================================================================
它解决什么问题
============================================================================
UDF 接管验证（udf-takeover.e2e.mjs）要跑 `CREATE FUNCTION ... SONAME` +
`sys_eval('cmd /c ...')`。这两个动作本身是敏感的，历史上有两轮卡在审批。
光靠 Python 审计钩子做不出真隔离（已实测：钩子不穿透进程边界），
所以改为**用「一次性 MySQL 实例」当真实隔离边界**：

  · 独立 datadir：脚本能破坏的最大范围 = 这个 datadir，
    而不是宿主数据库。用完 rmtree 即可，影响面归零。
  · secure_file_priv / plugin_dir 都锁在沙箱内：
    UDF 的 .dll 只能在沙箱目录落盘与加载。
  · 独立端口 + 仅监听 127.0.0.1：不与 3306 主实例竞争或互相污染。

这是**真实边界**，不是声明的边界 —— 可用 `--verify-isolation` 实测：
尝试从沙箱实例写 datadir 之外的路径，必须失败。

============================================================================
用法
============================================================================
  python e2e/udf-lab/mysql_sandbox.py --init      # 首次初始化 datadir
  python e2e/udf-lab/mysql_sandbox.py --start     # 启动沙箱实例
  python e2e/udf-lab/mysql_sandbox.py --status    # 查状态
  python e2e/udf-lab/mysql_sandbox.py --stop      # 停止
  python e2e/udf-lab/mysql_sandbox.py --destroy   # 停止 + 删除全部沙箱数据
  python e2e/udf-lab/mysql_sandbox.py --verify-isolation  # 实测隔离边界
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SB = HERE / ".mysql-sandbox"
INI = SB / "my-sandbox.ini"
DATADIR = SB / "data"
PLUGIN_DIR = SB / "plugin"
LOGS = SB / "logs"
TMPDIR = SB / "tmp"
PIDFILE = SB / "mysqld.pid"
ERRORLOG = LOGS / "error.log"

MYSQL_HOME = Path(os.environ.get("MYSQL_HOME", r"D:\mysql"))
MYSQLD = MYSQL_HOME / "bin" / "mysqld.exe"
MYSQL = MYSQL_HOME / "bin" / "mysql.exe"

SANDBOX_PORT = 3308
SANDBOX_USER = "root"
SANDBOX_PASSWORD = "sandbox"

# 主实例痕迹，用于断言「沙箱没碰主库」
HOST_DATADIR = Path(r"D:\mysql\data")


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", **kw)


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    with socket.socket() as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def _ensure_dirs() -> None:
    for d in (SB, DATADIR, PLUGIN_DIR, LOGS, TMPDIR):
        d.mkdir(parents=True, exist_ok=True)


def _mysql_conn_args() -> list[list[str]]:
    """按可靠性排序的连接参数候选：命名管道 → localhost → 127.0.0.1。"""
    return [
        ["--pipe"],
        ["-h", "localhost"],
        ["-h", "127.0.0.1"],
    ]


def _mysql_exec(sql: str, *, user: str, password: str | None = None,
                database: str | None = None, extra: list[str] | None = None) -> tuple[int, str]:
    """执行 SQL，自动尝试各连接方式，返回第一个成功的结果。

    返回 (returncode, 输出)。全部失败时返回最后一次的 (rc, out)。
    """
    last = (1, "")
    for conn in _mysql_conn_args():
        cmd = [str(MYSQL), "-P", str(SANDBOX_PORT), "-u", user, *conn]
        if password:
            cmd.append(f"-p{password}")
        if database:
            cmd.append(database)
        if extra:
            cmd.extend(extra)
        cmd.extend(["-e", sql])
        r = _run(cmd)
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode == 0:
            return 0, out
        last = (r.returncode, out)
    return last


def is_initialized() -> bool:
    return (DATADIR / "mysql").is_dir()


def do_init(force: bool = False) -> int:
    _ensure_dirs()
    if is_initialized() and not force:
        print(f"[mysql-sandbox] datadir 已初始化：{DATADIR}")
        return 0
    if force and DATADIR.exists():
        print("[mysql-sandbox] --force：清空旧 datadir")
        shutil.rmtree(DATADIR, ignore_errors=True)
        DATADIR.mkdir(parents=True, exist_ok=True)

    print(f"[mysql-sandbox] 初始化沙箱 datadir：{DATADIR}")
    r = _run([str(MYSQLD), f"--defaults-file={INI}", "--initialize-insecure", "--console"])
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        print("[mysql-sandbox] 初始化失败：")
        print(out[-3000:])
        return r.returncode

    # 初始化后启动一次，设密码 + 建沙箱库
    print("[mysql-sandbox] 初始化完成，启动以设置账号…")
    rc = do_start(wait_sec=40)
    if rc != 0:
        return rc
    try:
        _provision()
    finally:
        do_stop()
    print("[mysql-sandbox] 就绪。用 --start 启动。")
    return 0


def _provision() -> None:
    """设 root 密码 + 建演示库。

    关键：刚 `--initialize-insecure` 完只有 `root@localhost` 账户。
    要登上它，连接必须被 MySQL 视为「来自 localhost」：
      · Windows 上用 `--pipe` 走命名管道（最可靠，不经 TCP 主机匹配）
      · 或 `-h localhost` 且**未开** skip-name-resolve
    用 `-h 127.0.0.1` 会走 TCP 匹配 127.0.0.1 账户 → ERROR 1130。
    """
    setup_sql = (
        f"CREATE USER IF NOT EXISTS '{SANDBOX_USER}'@'127.0.0.1' IDENTIFIED BY '{SANDBOX_PASSWORD}';"
        f"CREATE USER IF NOT EXISTS '{SANDBOX_USER}'@'localhost' IDENTIFIED BY '{SANDBOX_PASSWORD}';"
        f"ALTER USER '{SANDBOX_USER}'@'localhost' IDENTIFIED BY '{SANDBOX_PASSWORD}';"
        f"GRANT ALL PRIVILEGES ON *.* TO '{SANDBOX_USER}'@'127.0.0.1' WITH GRANT OPTION;"
        f"GRANT ALL PRIVILEGES ON *.* TO '{SANDBOX_USER}'@'localhost' WITH GRANT OPTION;"
        "CREATE DATABASE IF NOT EXISTS udflab;"
        "FLUSH PRIVILEGES;"
        "SELECT 'provisioned' AS r;"
    )

    # 依次尝试：命名管道 → localhost → 127.0.0.1
    # 注意：root@localhost 可能**已被设过密码**（provision 非首次运行），
    # 故每轮先试无密码，再试已知密码 —— 保证 provision 幂等。
    attempts = [
        ("--pipe",),
        ("-h", "localhost"),
        ("-h", "127.0.0.1"),
    ]
    last = ""
    provisioned = False
    for extra in attempts:
        for pw_args in ([], [f"-p{SANDBOX_PASSWORD}"]):
            cmd = [str(MYSQL), "-P", str(SANDBOX_PORT), "-u", "root",
                   *extra, *pw_args, "-e", setup_sql]
            r = _run(cmd)
            out = (r.stdout or "") + (r.stderr or "")
            if r.returncode == 0 and "provisioned" in out:
                tag = " ".join(extra) + (" (带密码)" if pw_args else " (无密码)")
                print(f"[mysql-sandbox] 沙箱账号已就绪（连接方式：{tag}）")
                provisioned = True
                break
            last = out
        if provisioned:
            break

    if not provisioned:
        # 已是 provisioned 状态下 root 无密码会失败，这不算错误
        if _provisioned():
            print("[mysql-sandbox] 沙箱已就绪（跳过重复 provision）")
            return
        print("[mysql-sandbox] 建账号失败，最后错误：", last[-600:])
        return

    _init_lab_schema()


def _init_lab_schema() -> None:
    """在沙箱实例里初始化靶场 schema（复用项目既有的 init-db.mjs）。

    为什么需要：UDF 验证脚本要经**真实注入通道**跑扫描，靶场库
    (`sqli_lab`) 的表必须存在，否则 CREATE FUNCTION 与直连查询都会失败
    （实测：缺库时表现为 `mysql.func 注册数=0` + `No database selected`）。

    复用 `e2e/real-mysql-lab/init-db.mjs` 而不是另写 DDL —— 保证沙箱内的
    靶场结构与主实例**完全一致**，避免「沙箱里能过、真实环境不过」。
    """
    init_script = HERE.parent / "real-mysql-lab" / "init-db.mjs"
    if not init_script.exists():
        print("[mysql-sandbox] 未找到 init-db.mjs，跳过靶场初始化")
        return

    node = shutil.which("node") or shutil.which("node.exe")
    if not node:
        print("[mysql-sandbox] 未找到 node，跳过靶场初始化")
        return

    env = dict(os.environ)
    env.update({
        "MYSQL_HOST": "127.0.0.1",
        "MYSQL_PORT": str(SANDBOX_PORT),
        "MYSQL_USER": SANDBOX_USER,
        "MYSQL_PASSWORD": SANDBOX_PASSWORD,
        "MYSQL_DATABASE": "sqli_lab",
    })
    r = _run([node, str(init_script)], env=env)
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 0:
        for ln in out.splitlines():
            if "[init-db]" in ln:
                print("[mysql-sandbox] " + ln.strip())
    else:
        print("[mysql-sandbox] 靶场初始化失败：", out[-500:])


def do_start(wait_sec: int = 45) -> int:
    if _port_open(SANDBOX_PORT):
        print(f"[mysql-sandbox] 已在运行（端口 {SANDBOX_PORT} 已监听）")
        return 0
    if not is_initialized():
        print("[mysql-sandbox] datadir 未初始化，请先 --init")
        return 2

    _ensure_dirs()
    print(f"[mysql-sandbox] 启动 mysqld（端口 {SANDBOX_PORT}）…")
    logf = open(LOGS / "console.log", "a", encoding="utf-8")
    subprocess.Popen(
        [str(MYSQLD), f"--defaults-file={INI}", "--console"],
        stdout=logf, stderr=logf,
        creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
    )

    t0 = time.time()
    while time.time() - t0 < wait_sec:
        if _port_open(SANDBOX_PORT):
            print(f"[mysql-sandbox] 已就绪（{round(time.time()-t0,1)}s）")
            return 0
        time.sleep(0.5)

    print(f"[mysql-sandbox] 启动超时（{wait_sec}s）。错误日志尾部：")
    if ERRORLOG.exists():
        print(ERRORLOG.read_text(encoding="utf-8", errors="replace")[-1500:])
    return 1


def do_stop() -> int:
    if not _port_open(SANDBOX_PORT):
        return 0
    # 优先优雅关闭
    _mysql_exec("SHUTDOWN;", user=SANDBOX_USER, password=SANDBOX_PASSWORD)
    for _ in range(20):
        if not _port_open(SANDBOX_PORT):
            print("[mysql-sandbox] 已停止")
            return 0
        time.sleep(0.3)

    # 兜底：按 datadir 定位并杀进程（只杀本沙箱的 mysqld）
    killed = _kill_by_datadir()
    if killed:
        print(f"[mysql-sandbox] 已强制终止 {killed} 个沙箱 mysqld 进程")
    for _ in range(10):
        if not _port_open(SANDBOX_PORT):
            print("[mysql-sandbox] 已停止")
            return 0
        time.sleep(0.3)
    print("[mysql-sandbox] 停止失败：端口仍被占用")
    return 1


def _kill_by_datadir() -> int:
    """只杀 datadir 指向本沙箱的 mysqld，绝不误杀主实例。

    注意：本机 `wmic` 不可用（Win10 新版已移除，实测 WinError 2），
    故改用 `tasklist /v` 拿命令行 + PID。
    """
    try:
        r = _run(["tasklist", "/FI", "IMAGENAME eq mysqld.exe", "/V", "/FO", "CSV"])
    except FileNotFoundError:
        return 0

    n = 0
    for line in (r.stdout or "").splitlines():
        if "mysqld" not in line.lower() or ".mysql-sandbox" not in line:
            continue
        # CSV: "映像名称","PID","会话名","会话#","内存使用","状态","用户名","CPU时间","窗口标题"
        fields = [f.strip('"') for f in line.split('","')]
        for f in fields:
            if f.isdigit() and f != "0":
                _run(["taskkill", "/F", "/PID", f])
                n += 1
                break
    return n


# ---------------------------------------------------------------------------
# 生命周期上下文管理器 —— 让「起→用→停」在**同一进程内**闭合
# ---------------------------------------------------------------------------
# 为什么必须这样：实测确认（2026-09-18）Agent 会话里用 Popen 起的进程，
# 在命令（回合）结束后会被宿主回收。因此不能指望「先 --start，再另起
# 一条命令去用」。正确做法是：把沙箱实例的生命周期收在一个进程里 ——
# 进入时启动、退出时无论成败一律停止（finally 保证）。
#
# 这正是本沙箱「用完即毁」设计能够成立的前提。

class SandboxInstance:
    """隔离 MySQL 沙箱实例的生命周期句柄。

    典型用法::

        with mysql_sandbox.launch() as inst:
            # inst["port"] / inst["user"] / inst["password"] / inst["pluginDir"]
            ...跑验证脚本...

    退出 with 块即销毁实例进程；`keep_dir=False` 时连 datadir 一起清掉。
    """

    def __init__(self, *, keep_dir: bool = True, provision: bool = True):
        self.keep_dir = keep_dir
        self.provision = provision
        self.info: dict = {}
        self._started = False

    def __enter__(self) -> dict:
        _ensure_dirs()
        if not is_initialized():
            raise RuntimeError(
                "沙箱 datadir 未初始化。请先运行：\n"
                f"  python {Path(__file__).name} --init"
            )
        rc = do_start()
        if rc != 0:
            raise RuntimeError("沙箱实例启动失败，见上方日志")
        self._started = True
        if self.provision and not _provisioned():
            _provision()
        self.info = {
            "port": SANDBOX_PORT,
            "host": "127.0.0.1",
            "user": SANDBOX_USER,
            "password": SANDBOX_PASSWORD,
            "pluginDir": str(PLUGIN_DIR),
            "datadir": str(DATADIR),
            "sandboxRoot": str(SB),
        }
        return self.info

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._started:
            do_stop()
        if not self.keep_dir:
            shutil.rmtree(SB, ignore_errors=True)
        return False  # 不吞异常


def _provisioned() -> bool:
    """判断沙箱是否已完成 provision（账号 + 靶场库都在）。"""
    rc, out = _mysql_exec(
        "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='sqli_lab';",
        user=SANDBOX_USER, password=SANDBOX_PASSWORD, extra=["-N", "-B"])
    return rc == 0 and "sqli_lab" in out


def launch(*, keep_dir: bool = True, provision: bool = True) -> SandboxInstance:
    return SandboxInstance(keep_dir=keep_dir, provision=provision)


def do_status() -> int:
    running = _port_open(SANDBOX_PORT)
    info = {
        "running": running,
        "port": SANDBOX_PORT,
        "initialized": is_initialized(),
        "datadir": str(DATADIR),
        "pluginDir": str(PLUGIN_DIR),
        "hostDatadir": str(HOST_DATADIR),
        "hostDatadirUntouched": _host_untouched(),
    }
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


def _host_untouched() -> bool:
    """主实例 datadir 的 mtime 是否早于沙箱创建时间（粗略判断未被动过）。"""
    try:
        host_m = HOST_DATADIR.stat().st_mtime
        sb_m = SB.stat().st_mtime
        return host_m <= sb_m
    except Exception:
        return False


def do_destroy() -> int:
    do_stop()
    print(f"[mysql-sandbox] 删除沙箱数据：{SB}")
    shutil.rmtree(SB, ignore_errors=True)
    print("[mysql-sandbox] 已销毁（主实例 datadir 未触碰）")
    return 0


def do_verify_isolation() -> int:
    """实测隔离边界：沙箱实例必须**写不出** secure_file_priv 之外的路径。

    这是真负向验证 —— 不是断言，而是真跑一次越权写入看它是否失败。
    """
    if not _port_open(SANDBOX_PORT):
        print("[mysql-sandbox] 实例未启动，无法验证")
        return 2
    ok, checks = _isolation_checks()
    print(json.dumps({"ok": ok, "checks": checks}, ensure_ascii=False, indent=2))
    print("隔离验证：" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def do_verify_ephemeral() -> int:
    """自起自用自停的隔离验证 —— 一条命令内闭合整个生命周期。

    这是本机唯一可靠的验证方式：宿主要在命令结束后回收进程，
    所以「先 --start 再另起命令 --verify-isolation」必然落空。
    """
    print("[mysql-sandbox] 临时实例验证模式（起→验→停，单进程闭合）")
    try:
        with launch(keep_dir=True) as info:
            print(f"[mysql-sandbox] 实例就绪：127.0.0.1:{info['port']}")
            ok, checks = _isolation_checks()
            print(json.dumps({"ok": ok, "checks": checks}, ensure_ascii=False, indent=2))
            print("隔离验证：" + ("PASS" if ok else "FAIL"))
            return 0 if ok else 1
    except Exception as e:
        print(f"[mysql-sandbox] 验证失败：{e}")
        return 1


def _isolation_checks() -> tuple[bool, list]:
    """真跑一组越权动作，返回 (全通过?, 明细)。"""
    checks = []

    def q(sql: str) -> tuple[int, str]:
        return _mysql_exec(sql, user=SANDBOX_USER, password=SANDBOX_PASSWORD,
                           extra=["-N", "-B"])

    # ① secure_file_priv 必须指向沙箱 plugin 目录
    rc, out = q("SELECT @@secure_file_priv;")
    checks.append({
        "check": "secure_file_priv 指向沙箱内",
        "pass": rc == 0 and ".mysql-sandbox" in out,
        "detail": out[:160],
    })

    # ② 向 secure_file_priv 之外写文件 → 必须失败
    escape_target = r"C:\Windows\Temp\udf_sandbox_escape.txt"
    rc, out = q(f"SELECT 'pwned' INTO OUTFILE '{escape_target}';")
    leaked = Path(escape_target).exists()
    checks.append({
        "check": "越权写入沙箱外路径被拒",
        "pass": rc != 0 and not leaked,
        "detail": (out or "无输出")[:160],
    })
    if leaked:
        try:
            Path(escape_target).unlink()
        except Exception:
            pass

    # ③ plugin_dir 必须指向沙箱内
    rc, out = q("SELECT @@plugin_dir;")
    checks.append({
        "check": "plugin_dir 指向沙箱内",
        "pass": rc == 0 and ".mysql-sandbox" in out,
        "detail": out[:160],
    })

    # ④ 只监听 127.0.0.1（不对局域网暴露）
    rc, out = q("SELECT @@bind_address, @@port;")
    checks.append({
        "check": "仅监听回环且端口为 3308",
        "pass": rc == 0 and "127.0.0.1" in out and "3308" in out,
        "detail": out[:160],
    })

    # ⑤ 与主实例 datadir 不同
    rc, out = q("SELECT @@datadir;")
    checks.append({
        "check": "datadir 与主实例隔离",
        "pass": rc == 0 and ".mysql-sandbox" in out,
        "detail": out[:160],
    })

    return all(c["pass"] for c in checks), checks


def main() -> int:
    ap = argparse.ArgumentParser(description="隔离 MySQL 沙箱实例管理")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--init", action="store_true")
    g.add_argument("--start", action="store_true")
    g.add_argument("--stop", action="store_true")
    g.add_argument("--status", action="store_true")
    g.add_argument("--destroy", action="store_true")
    g.add_argument("--verify-isolation", action="store_true")
    g.add_argument("--verify-isolation-ephemeral", action="store_true",
                   help="自起自用自停的隔离验证（本机推荐方式）")
    ap.add_argument("--force", action="store_true", help="配合 --init：清空旧 datadir 重来")
    a = ap.parse_args()

    if a.init:
        return do_init(force=a.force)
    if a.start:
        return do_start()
    if a.stop:
        return do_stop()
    if a.status:
        return do_status()
    if a.destroy:
        return do_destroy()
    if a.verify_isolation:
        return do_verify_isolation()
    if a.verify_isolation_ephemeral:
        return do_verify_ephemeral()
    return 2


if __name__ == "__main__":
    sys.exit(main())
