#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
e2e/udf-lab/sandbox.py —— 在受控沙箱里执行 UDF 验证脚本（纯标准库，零第三方依赖）

============================================================================
为什么需要它
============================================================================
UDF 接管验证（udf-takeover.e2e.mjs / udf-register.e2e.mjs）要做的动作本身是
高敏感的：CREATE FUNCTION ... SONAME 加载原生库、sys_eval 执行系统命令。
历史上这两个脚本**连续两轮被环境安全审批拦在运行时**，导致 os-shell 至今
无法标记为「已验证」。

本沙箱不试图绕开任何审批（那是错的），而是把「脚本能做什么」收窄到
**可枚举、可审计、可复现**的最小集合，使验证从「高危不可自动化」变成
「受控可自动化」：

  · 进程创建：白名单制。只允许 node / cmd（且 cmd 仅限 echo/whoami/ver 等
    无副作用命令），其余一律拒绝并记账。
  · 文件写入：白名单制。只允许写入指定沙箱目录（temp + results）。
  · 网络出站：白名单制。默认只允许 127.0.0.1（靶场就在本机），
    外部地址一律拒绝。
  · 资源上限：超时（挂钟）、输出体积上限、子进程数上限。
  · 全程记账：每次触达管控点都写入审计日志，事后可核对「脚本到底做了什么」。

============================================================================
已知边界（如实声明，2026-09-18 实测，勿夸大）
============================================================================
★ 最重要的一条：**本沙箱不是强隔离容器。**
  它管不住被测脚本内部再起的子进程 —— Python 审计钩子只在**本进程**生效，
  被测的 node 进程是独立进程，其内部 `child_process.execSync(...)` 对钩子
  完全不可见（实测：node 内起 `cmd /c echo` 成功，钩子只记录到 `spawn node.exe`）。

★ 写文件被拦 ≠ 沙箱的功劳。
  实测中「写 C: 根目录被拒」来自 Windows 自身权限（EPERM），不是审计钩子。
  凡引用此类证据，必须标注来源，不得说成沙箱能力。

★ 因此本沙箱的**真实边界靠 MySQL 隔离实例提供**（见 mysql_sandbox.py）：
  脚本能破坏的最大范围 = 那个用完即毁的 datadir，而不是宿主数据库/文件系统。
  Python 审计钩子在此扮演的是**取证与防误操作**角色（记录脚本 spawn 了什么、
  写了哪些白名单外路径并尽力阻止），**不是**安全隔离边界。

其它限制：
1. `ctypes` 无审计事件，钩子拦不住 ctypes 直调 Win32 API（仅记录）。
2. Windows 无 `resource` 模块，CPU/地址空间上限不可用，降级为挂钟超时 +
   子进程数上限；Linux 下自动启用 resource 限制。
3. 白名单基于**命令名 + 参数形状**匹配，不解析 shell 语义。

============================================================================
用法
============================================================================
  # 跑 register 验证（不执行系统命令）
  python e2e/udf-lab/sandbox.py --script udf-register.e2e.mjs

  # 跑 takeover 验证（含 sys_eval 执行命令；需显式声明已授权）
  python e2e/udf-lab/sandbox.py --script udf-takeover.e2e.mjs --allow-command-exec

  # 只看策略、不真跑（检查白名单是否符合预期）
  python e2e/udf-lab/sandbox.py --script udf-takeover.e2e.mjs --dry-run

  # 跑**负向验证**：证明沙箱实际能拦住/拦不住什么（诚实量边界）
  python e2e/udf-lab/sandbox.py --script _sandbox_negative_probe.mjs --probe
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

# ---------------------------------------------------------------------------
# 策略定义
# ---------------------------------------------------------------------------

# 允许创建的可执行文件（按 basename 匹配，大小写不敏感）
ALLOWED_EXECUTABLES = {
    "node", "node.exe",
    "cmd", "cmd.exe",
    "mysql", "mysql.exe",
    "mysqld", "mysqld.exe",
    # python 自身：bootstrap 与验证脚本可能再起 python 子进程
    "python", "python.exe", "python3", "python3.exe", "pythonw.exe",
    # npm/npx：e2e 脚本可能经 npm script 转发
    "npm", "npm.cmd", "npx", "npx.cmd",
}

# cmd.exe 只允许跑这些「无副作用」命令（首 token 匹配）
ALLOWED_CMD_VERBS = {
    "echo", "whoami", "ver", "hostname", "set",
}

# 允许出站的地址（CIDR 简化为前缀 + 精确匹配）
ALLOWED_HOSTS = {
    "127.0.0.1", "localhost", "::1",
}

# 只允许写这些目录（运行时填入）
write_allowlist: list[Path] = []

# 资源上限
DEFAULT_TIMEOUT_SEC = 300
DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_CHILD_PROCS = 24

# 审计记录
audit_log: list[dict] = []
_child_proc_count = 0
_violations: list[str] = []


def _record(kind: str, detail: str, allowed: bool) -> None:
    entry = {
        "t": round(time.time(), 3),
        "kind": kind,
        "detail": detail[:300],
        "allowed": allowed,
    }
    audit_log.append(entry)
    if not allowed:
        _violations.append(f"[{kind}] {detail}")


# ---------------------------------------------------------------------------
# 审计钩子（在子进程内安装）
# ---------------------------------------------------------------------------

def _check_exe(exe: str) -> tuple[bool, str]:
    base = os.path.basename(str(exe)).lower()
    return (base in ALLOWED_EXECUTABLES, base)


def _check_cmd_args(cmdline: str) -> tuple[bool, str]:
    """cmd.exe 的命令行二次校验：只放行无副作用命令。

    cmd /c echo xxx   → 允许
    cmd /c del /f *   → 拒绝

    注意别被绕过：`cmd /c "del /f *"`、`cmd /c del/f *`、`cmd /c DEL` 都要
    归一到同一判定。故先剥引号、统一取 `/c` 之后的首个词干。
    """
    if not isinstance(cmdline, str):
        return False, f"cmd 命令行非法：{cmdline!r}"

    # 归一化：去掉引号，压缩空白
    norm = cmdline.replace('"', " ").replace("'", " ")
    m = re.search(r"/c\s+(.+)$", norm, re.IGNORECASE)
    if not m:
        return False, f"cmd 未使用 /c 形式：{cmdline[:80]}"

    tail = m.group(1).strip()
    # 首个词（可能是 "del" 或 "del/f"）
    first = tail.split()[0] if tail.split() else ""
    verb = os.path.basename(first).lower()
    verb = verb.split(".")[0].split("/")[0]
    # 处理 del/f 这类粘连写法
    if verb and verb not in ALLOWED_CMD_VERBS:
        for allowed in ALLOWED_CMD_VERBS:
            if verb.startswith(allowed):
                verb = allowed
                break
    ok = verb in ALLOWED_CMD_VERBS
    return ok, f"cmd /c {verb}"


def _split_command_line(cmdline: str) -> list[str]:
    """把一个命令行字符串拆成 token（去掉首尾空白 + 配对的引号）。

    不追求完整 Windows 命令行语义，够用于白名单判定即可。
    """
    toks = re.findall(r'"([^"]*)"|(\S+)', cmdline)
    return [a or b for a, b in toks]


def _resolve_exec_base(args: tuple) -> tuple[str, str]:
    """从 `subprocess.Popen` 审计事件里解析出真正的可执行文件名。

    关键事实（实测，勿改）：Python 的 `subprocess.Popen` 审计事件签名是
        (executable, args, cwd, env)
    其中 `executable` 在 Windows 上**恒为 None**（即便显式传了路径），
    真正的目标位于 `args` 字段——字符串形态时是命令行原文，
    列表形态时是 argv 列表。历史上把 `args[0]` 当可执行文件用，
    导致 `str(None)` → `"none"` 误判，把**所有**子进程创建都拦掉了。

    返回 (basename, 用于展示/二次校验的命令行原文)。
    """
    raw_args = args[1] if len(args) > 1 else None

    if isinstance(raw_args, (list, tuple)) and raw_args:
        exe = str(raw_args[0])
        cmdline = " ".join(str(x) for x in raw_args)
    elif isinstance(raw_args, (str, bytes)):
        cmdline = raw_args.decode("utf-8", "replace") if isinstance(raw_args, bytes) else raw_args
        toks = _split_command_line(cmdline)
        exe = toks[0] if toks else ""
    else:
        # 连命令行都拿不到：宁可记一条可疑事件也不误拦（打不开就没得跑）
        return "", ""

    return os.path.basename(exe).lower(), cmdline


def _install_audit_hook(policy: dict) -> None:
    """安装审计钩子。运行在**子进程**里，对被测脚本生效。"""
    allow_exec = set(policy["allowed_executables"])
    allowed_hosts = set(policy["allowed_hosts"])
    write_roots = [Path(p).resolve() for p in policy["write_allowlist"]]
    max_children = policy["max_child_procs"]

    state = {"children": 0, "violations": [], "events": []}

    def _is_under_write_root(p: str) -> bool:
        try:
            rp = Path(p).resolve()
        except Exception:
            return False
        for root in write_roots:
            try:
                rp.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    def _hook(event: str, args: tuple) -> None:
        # —— 进程创建 ——
        if event == "subprocess.Popen":
            base, cmdline = _resolve_exec_base(args)
            state["events"].append(f"spawn {base or '<unknown>'}")
            if not base:
                # 解析不出可执行名：不拦（否则会像历史 bug 那样拦错对象），
                # 但留下证据供事后核对。
                state["violations"].append(f"进程无法解析（已放行待核）：{cmdline[:120]}")
                return
            if base not in allow_exec:
                state["violations"].append(f"进程被拒：{base}（不在白名单）")
                raise PermissionError(f"[sandbox] 拒绝执行 {base}：不在可执行白名单内")
            if base in ("cmd", "cmd.exe"):
                verb_ok, desc = _check_cmd_args(cmdline)
                if not verb_ok:
                    state["violations"].append(f"cmd 参数被拒：{desc}")
                    raise PermissionError(f"[sandbox] 拒绝 cmd 调用：{desc}")
            state["children"] += 1
            if state["children"] > max_children:
                raise PermissionError(f"[sandbox] 子进程数超上限（{max_children}）")

        # —— 文件写入 ——
        elif event == "open":
            if len(args) >= 2:
                path, mode = args[0], args[1]
                if isinstance(mode, str) and any(c in mode for c in "wax+"):
                    if not _is_under_write_root(str(path)):
                        state["violations"].append(f"写入被拒：{path}")
                        raise PermissionError(f"[sandbox] 拒绝写入白名单外路径：{path}")

        # —— 网络出站 ——
        elif event == "socket.connect":
            if args:
                addr = args[0]
                host = ""
                if isinstance(addr, tuple) and addr:
                    host = str(addr[0])
                elif isinstance(addr, str):
                    host = addr
                bare = host.strip("[]")
                if bare not in allowed_hosts:
                    state["violations"].append(f"出站被拒：{host}")
                    raise PermissionError(f"[sandbox] 拒绝连接非白名单地址：{host}")
        # —— 动态代码加载（记录但放行，node 需要）——
        elif event in ("ctypes.dlopen", "ctypes.dlsym"):
            state["violations"].append(f"ctypes 调用（审计盲区，仅记录）：{event}")

    sys.addaudithook(_hook)

    # 供主流程读取
    globals()["_child_state"] = state


# ---------------------------------------------------------------------------
# 沙箱运行器
# ---------------------------------------------------------------------------

def _resource_limits(enabled: bool) -> None:
    """Unix 下启用 CPU/地址空间限制；Windows 无 resource 模块则跳过。"""
    if not enabled:
        return
    try:
        import resource  # noqa: PLC0415  (Unix only)

        resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    except Exception:
        pass


def run_in_sandbox(
    script: str,
    *,
    allow_command_exec: bool = False,
    timeout: int = DEFAULT_TIMEOUT_SEC,
    dry_run: bool = False,
    extra_env: dict | None = None,
    with_mysql: bool = True,
    probe: bool = False,
) -> dict:
    """在沙箱里执行 e2e 验证脚本，返回结构化结果。

    `with_mysql=True` 时会在**同一进程内**起一个隔离 MySQL 实例
    （见 mysql_sandbox.py），跑完无论如何都停掉 —— 这是本机唯一可靠的
    做法：宿主要在命令结束后回收进程，「先启动再另起命令使用」必然落空。
    """
    script_path = (HERE / script).resolve()
    if not script_path.exists():
        return {"ok": False, "error": f"脚本不存在：{script_path}"}

    # —— 建立本次运行的写入沙箱 ——
    sandbox_dir = Path(tempfile.mkdtemp(prefix="udf-sandbox-"))
    results_dir = HERE / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    # 项目自身基础设施必需的写路径。
    # 依据（实测 2026-09-18）：被测脚本 import server/src/core/logger.js 时，
    # winston 会创建以下日志目录，若不在白名单，沙箱会连正常启动都拦死：
    #   · <项目>/logs                    —— 项目日志目录
    #   · <系统 Temp>/sqli-scanner       —— logger.js 里的临时日志目录
    # 这些是**已知必需**的路径，显式放行；不在白名单内的其它路径照拦。
    infra_write_dirs = [ROOT / "logs", Path(tempfile.gettempdir()) / "sqli-scanner"]

    # 允许通过环境变量追加（供不同靶场脚本按需扩展）
    for extra in (os.environ.get("SANDBOX_EXTRA_WRITE_ROOTS") or "").split(os.pathsep):
        if extra.strip():
            infra_write_dirs.append(Path(extra.strip()))

    # takeover 脚本含 sys_eval 执行命令，未显式授权则拒绝启动
    if "takeover" in script and not allow_command_exec:
        _cleanup(sandbox_dir)
        return {
            "ok": False,
            "error": (
                "udf-takeover 含系统命令执行（sys_eval），需显式加 --allow-command-exec 声明已授权。\n"
                "  若只想验证「加载+注册+调用」链路，请跑 udf-register.e2e.mjs"
            ),
        }

    # —— MySQL 隔离实例：必须在 policy 定稿**之前**起 ——
    # 因为 UDF 验证要把 .dll 复制进 MySQL 的 plugin 目录，该路径需进写白名单。
    # 生命周期收在本进程内（见 mysql_sandbox.launch 的说明）。
    mysql_ctx = None
    mysql_info = None
    mysql_roots: list[Path] = []
    if with_mysql and not dry_run:
        import mysql_sandbox  # noqa: PLC0415  同目录模块

        if not mysql_sandbox.is_initialized():
            mysql_sandbox.do_init()
        mysql_ctx = mysql_sandbox.launch(keep_dir=True)
        mysql_info = mysql_ctx.__enter__()
        mysql_roots = [Path(mysql_info["pluginDir"]), Path(mysql_info["datadir"]),
                       Path(mysql_info["sandboxRoot"])]

    global write_allowlist
    write_allowlist = [sandbox_dir, results_dir, *infra_write_dirs, *mysql_roots]

    # 规范化（含 Windows 长短路径变体），转成字符串列表
    write_root_strs = _normalize_write_roots(write_allowlist)

    policy = {
        "allowed_executables": sorted(ALLOWED_EXECUTABLES),
        "allowed_hosts": sorted(ALLOWED_HOSTS),
        "write_allowlist": write_root_strs,
        "max_child_procs": DEFAULT_MAX_CHILD_PROCS,
        "allow_command_exec": allow_command_exec,
    }

    if mysql_info:
        mdir = mysql_info["datadir"].replace(str(ROOT), "<项目>")
        print(f"[sandbox] MySQL 沙箱实例：127.0.0.1:{mysql_info['port']}（datadir={mdir}）")

    print("[sandbox] 策略：")
    print(f"  可执行白名单：{', '.join(policy['allowed_executables'])}")
    print(f"  出站白名单  ：{', '.join(policy['allowed_hosts'])}")
    print("  写入白名单  ：")
    for w in policy["write_allowlist"]:
        print(f"    - {w}")
    print(f"  命令执行    ：{'已授权' if allow_command_exec else '未授权（拒绝 sys_eval 类动作）'}")
    print(f"  超时        ：{timeout}s")
    print(f"  MySQL 沙箱  ：{'启用（隔离实例）' if with_mysql else '不启用'}")

    if dry_run:
        _cleanup(sandbox_dir)
        return {"ok": True, "dryRun": True, "policy": policy}

    env = dict(os.environ)
    env.update({
        "SANDBOX_MODE": "1",
        "SANDBOX_WRITE_ROOTS": os.pathsep.join(write_root_strs),
        "SANDBOX_ALLOWED_EXECUTABLES": ",".join(sorted(ALLOWED_EXECUTABLES)),
        "SANDBOX_ALLOWED_CMD_VERBS": ",".join(sorted(ALLOWED_CMD_VERBS)),
        "SANDBOX_ALLOWED_HOSTS": ",".join(sorted(ALLOWED_HOSTS)),
        "SANDBOX_ALLOW_COMMAND_EXEC": "1" if allow_command_exec else "0",
        # node 侧守卫：Node 的审计机制与 Python 不同，必须用 --require 预加载
        "NODE_OPTIONS": f"--require {HERE / '_sandbox_node_guard.cjs'}",
    })
    if mysql_info:
        env.update({
            "MYSQL_PORT": str(mysql_info["port"]),
            "MYSQL_HOST": mysql_info["host"],
            "MYSQL_USER": mysql_info["user"],
            "MYSQL_PASSWORD": mysql_info["password"],
            # UDF 脚本常用这些变量定位 plugin 目录
            "MYSQL_PLUGIN_DIR": mysql_info["pluginDir"],
            "UDF_LAB_DLL": str(HERE / "udf_sys.dll"),
        })
    if extra_env:
        env.update(extra_env)

    try:
        return _run_script(script, script_path, sandbox_dir, policy, env, timeout, probe)
    finally:
        if mysql_ctx is not None:
            try:
                mysql_ctx.__exit__(None, None, None)
            except Exception as e:
                print(f"[sandbox] 停止 MySQL 沙箱实例异常：{e}")


def _run_script(script, script_path, sandbox_dir, policy, env, timeout, probe=False) -> dict:
    """真正执行脚本：生成 bootstrap → 跑 → 收审计日志 → 判结果。"""
    # —— 用 python 起一个「装好审计钩子」的子进程，由它再跑 node ——
    boot = _BOOTSTRAP.format(
        policy_json=json.dumps(policy, ensure_ascii=False),
        script_path=str(script_path),
        cwd=str(ROOT),
    )
    boot_file = sandbox_dir / "_sandbox_boot.py"
    boot_file.write_text(boot, encoding="utf-8")

    t0 = time.time()
    timed_out = False
    try:
        proc = subprocess.run(
            [sys.executable, str(boot_file)],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            timeout=timeout,
        )
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as e:
        stdout = (e.stdout or b"").decode("utf-8", "replace")
        stderr = (e.stderr or b"").decode("utf-8", "replace")
        exit_code = -1
        timed_out = True

    elapsed = round(time.time() - t0, 2)

    # 解析子进程回传的审计日志
    log_file = sandbox_dir / "_audit.json"
    child_audit, child_violations = [], []
    if log_file.exists():
        try:
            data = json.loads(log_file.read_text(encoding="utf-8"))
            child_audit = data.get("events", [])
            child_violations = data.get("violations", [])
        except Exception:
            pass

    overflow = len(stdout) + len(stderr) > DEFAULT_MAX_OUTPUT_BYTES

    # —— probe 模式：解析探针结构，按「预期 vs 实际」判定 ——
    probe_result = None
    if probe:
        probe_result = _eval_probe(stdout)

    result = {
        "ok": exit_code == 0 and not child_violations and not timed_out,
        "script": script,
        "exitCode": exit_code,
        "elapsedSec": elapsed,
        "timedOut": timed_out,
        "outputOverflow": overflow,
        "sandboxDir": str(sandbox_dir),
        "policy": policy,
        "audit": child_audit,
        "violations": child_violations,
        "stdout": stdout[-20000:],
        "stderr": stderr[-8000:],
    }
    if probe_result is not None:
        result["probe"] = probe_result
        result["ok"] = probe_result["ok"]

    _cleanup(sandbox_dir)
    return result


def _eval_probe(stdout: str) -> dict:
    """解析 `__PROBE_RESULT__<json>` 行，按 expectBlocked 与 blocked 比对。

    这是「诚实量边界」的核心：探针声明自己预期被拦还是被放行，
    沙箱按实际结果打分 —— 而不是沙箱自己声称拦得住什么。
    """
    line = ""
    for ln in stdout.splitlines():
        if ln.startswith("__PROBE_RESULT__"):
            line = ln[len("__PROBE_RESULT__"):]
    if not line:
        return {"ok": False, "error": "探针未输出结果（脚本可能未跑到最后）", "items": []}

    try:
        items = json.loads(line)
    except Exception as e:
        return {"ok": False, "error": f"探针输出解析失败：{e}", "items": []}

    passed, failed = [], []
    for it in items:
        expect = bool(it.get("expectBlocked"))
        actual = bool(it.get("blocked"))
        row = {
            "name": it.get("name"),
            "expectBlocked": expect,
            "actualBlocked": actual,
            "pass": expect == actual,
            "note": it.get("note", ""),
        }
        (passed if row["pass"] else failed).append(row)

    return {
        "ok": not failed,
        "passed": len(passed),
        "failed": len(failed),
        "items": passed + failed,
        "mismatches": failed,
    }


def _cleanup(sandbox_dir: Path) -> None:
    try:
        shutil.rmtree(sandbox_dir, ignore_errors=True)
    except Exception:
        pass


def _normalize_write_roots(paths: list) -> list[str]:
    """把写白名单路径规范化，并补上 Windows 短路径(8.3)变体。

    坑（实测 2026-09-18）：Windows 上 `tempfile.gettempdir()` 返回短名
    `C:\\Users\\ADMIN~1\\AppData\\Local\\Temp`，而 node 侧 `path.resolve()`
    可能得到包含中文的长名 `C:\\Users\\Admin（无密码）\\...`。两边字符串不等
    → 白名单匹配失败 → 正常写入被误拦。
    故同时输出长名与短名两种形式，node 侧任一命中即放行。
    """
    out: list[str] = []

    def _add(s: str) -> None:
        if s and s not in out:
            out.append(s)

    for p in paths:
        try:
            rp = Path(p).resolve()
        except Exception:
            continue
        _add(str(rp))
        # 补短路径变体（仅 Windows 有效）
        try:
            import ctypes

            buf = ctypes.create_unicode_buffer(512)
            n = ctypes.windll.kernel32.GetShortPathNameW(str(rp), buf, 512)
            if n:
                _add(buf.value)
        except Exception:
            pass
        # 反向：若本身就是短名，尝试展开成长名
        try:
            if "~" in str(rp):
                import ctypes

                buf = ctypes.create_unicode_buffer(512)
                n = ctypes.windll.kernel32.GetLongPathNameW(str(rp), buf, 512)
                if n:
                    _add(buf.value)
        except Exception:
            pass
    return out


# 子进程引导脚本：装钩子 → 跑 node 验证脚本 → 回传审计日志
_BOOTSTRAP = '''
# -*- coding: utf-8 -*-
import json, os, subprocess, sys, time
sys.path.insert(0, r"{cwd}")
from pathlib import Path

_policy = json.loads(r"""{policy_json}""")

# 复用 sandbox.py 的钩子实现
sys.path.insert(0, str(Path(r"{cwd}") / "e2e" / "udf-lab"))
import sandbox as _sb
_sb._install_audit_hook(_policy)

_script = r"{script_path}"
_node = None
for cand in ("node", "node.exe"):
    from shutil import which
    _node = which(cand)
    if _node:
        break
if not _node:
    print("[sandbox] 找不到 node", file=sys.stderr)
    sys.exit(127)

_t0 = time.time()
try:
    _proc = subprocess.run(
        [_node, _script],
        cwd=r"{cwd}",
        env=os.environ.copy(),
    )
    _code = _proc.returncode
except Exception as _e:
    print(f"[sandbox] 子进程异常：{{_e}}", file=sys.stderr)
    _code = 1

_state = getattr(_sb, "_child_state", {{"violations": [], "events": []}})
_roots = os.environ.get("SANDBOX_WRITE_ROOTS", "")
_log = Path((_roots.split(os.pathsep)[0] if _roots else ".")) / "_audit.json"
try:
    _log.write_text(json.dumps({{
        "violations": _state.get("violations", []),
        "events": _state.get("events", []),
        "elapsedSec": round(time.time() - _t0, 2),
    }}, ensure_ascii=False), encoding="utf-8")
except Exception:
    pass

sys.exit(_code)
'''


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="UDF 验证脚本沙箱执行器")
    ap.add_argument("--script", required=True, help="要执行的 e2e 脚本（udf-lab 目录内）")
    ap.add_argument("--allow-command-exec", action="store_true",
                    help="显式声明已授权系统命令执行（takeover 脚本必需）")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SEC)
    ap.add_argument("--dry-run", action="store_true", help="只打印策略，不真跑")
    ap.add_argument("--probe", action="store_true",
                    help="负向验证模式：解析探针输出，按「预期 vs 实际」判定")
    ap.add_argument("--no-mysql", action="store_true",
                    help="不起隔离 MySQL 实例（脚本不依赖数据库时用）")
    ap.add_argument("--json-out", help="把结果写入指定 json 文件")
    a = ap.parse_args()

    res = run_in_sandbox(
        a.script,
        allow_command_exec=a.allow_command_exec,
        timeout=a.timeout,
        dry_run=a.dry_run,
        with_mysql=not a.no_mysql,
        probe=a.probe,
    )

    if a.json_out:
        Path(a.json_out).write_text(
            json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[sandbox] 结果已写入 {a.json_out}")

    if a.dry_run:
        return 0

    print("\n" + "=" * 70)
    if res.get("stdout"):
        print(res["stdout"])
    if res.get("stderr"):
        print("--- stderr ---")
        print(res["stderr"])
    print("=" * 70)

    probe = res.get("probe")
    if probe:
        print(f"负向验证：通过 {probe.get('passed', 0)} / "
              f"失败 {probe.get('failed', 0)}")
        for it in probe.get("items", []):
            mark = "OK  " if it["pass"] else "MISS"
            print(f"  [{mark}] {it['name']}")
            if not it["pass"]:
                print(f"         预期拦={it['expectBlocked']} "
                      f"实际拦={it['actualBlocked']}｜{it['note'][:100]}")
        if probe.get("error"):
            print("  " + probe["error"])

    print(f"退出码={res.get('exitCode')} 耗时={res.get('elapsedSec')}s "
          f"超时={res.get('timedOut')} 违规={len(res.get('violations', []))}")
    for v in res.get("violations", [])[:20]:
        print(f"  [违规] {v}")
    for ev in res.get("audit", [])[:20]:
        print(f"  [轨迹] {ev}")
    print("沙箱判定：" + ("PASS" if res.get("ok") else "FAIL"))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
