#!/usr/bin/env python3
# ============================================================================
# e2e/run-with-pg.py —— PG 靶场运行器（隔离/复用本机 pg-smoke 实例）
# ============================================================================
# 背景：oob-real-lab / pg-osshell / concurrent-isolation 依赖 PostgreSQL:5432，
#       本机无 PG 常驻 → run-all 长期跳过这 3 项。而 D:/pg-smoke 装有真实 PG 16，
#       datadir 已初始化（pg2.log 里有历史成功记录）。
#
# 与 MySQL 沙箱同样的约束：宿主会回收后台进程 → 必须把「起→用→停」收在同一进程。
#
# 用法：
#   python e2e/run-with-pg.py e2e/oob-real-lab/pg-osshell.e2e.mjs
#   python e2e/run-with-pg.py --probe          # 只探测能否拉起，不跑靶场
#   python e2e/run-with-pg.py --keep           # 退出后保留 PG（调试用）
# ============================================================================
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent

PG_BIN = Path(os.environ.get("PG_BIN", "D:/pg-smoke/bin/bin"))
PG_EXE = PG_BIN / "postgres.exe"
PG_DATA = Path(os.environ.get("PG_DATA", "D:/pg-smoke/data"))
PG_PORT = int(os.environ.get("PG_PORT") or 5432)
PG_USER = os.environ.get("PG_USER") or "postgres"
PG_DB = os.environ.get("PG_DB") or "sqli_lab"


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _find_node() -> str:
    managed = Path.home() / ".workbuddy" / "binaries" / "node"
    cands = sorted(managed.glob("versions/*/node.exe"), reverse=True)
    return str(cands[0]) if cands else "node"


# 真就绪判定：端口监听 ≠ PG 可用。
# 实测踩坑（2026-09-18）：端口先开、服务端还在 recovery，靶场拿到
# "the database system is starting up" 就 SKIP 了。故必须**真连一次**再算就绪。
_PG_READY_PROBE = r"""
// 基准必须指向**已存在**的 package.json，否则 createRequire 会退化到当前目录
// 而解析不到 pg（实测：Cannot find module 'pg'）。
const { createRequire } = require('module');
const req = createRequire(process.env.PG_BASE_JSON);
const pg = req('pg');
const c = new pg.Client({
  host: process.env.PGHOST, port: Number(process.env.PGPORT),
  user: process.env.PGUSER, password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE, connectionTimeoutMillis: 3000,
});
c.connect().then(() => c.query('SELECT 1'))
 .then(() => { console.log('PG_READY'); return c.end(); })
 .catch((e) => { console.log('PG_NOT_READY ' + (e.message || e)); process.exit(3); });
"""


def _pg_env(port: int, db: str | None = None) -> dict:
    env = dict(os.environ)
    env.update({
        "PGHOST": "127.0.0.1", "PGPORT": str(port),
        "PGUSER": PG_USER, "PGDATABASE": db or PG_DB,
        "PGPASSWORD": env.get("PGPASSWORD", ""),
        # pg 只在 server/package.json 的解析域内（hoisted 到根 node_modules）
        "PG_BASE_JSON": str(PROJECT / "server" / "package.json"),
    })
    return env


def _materialize_probe() -> Path:
    """把内联探针脚本写到磁盘（pg 的 resolve 需要真实文件路径作 createRequire 基准）。"""
    probe = PROJECT / "e2e" / ".pg-ready-probe.cjs"
    if not probe.exists() or probe.read_text(encoding="utf-8") != _PG_READY_PROBE:
        probe.write_text(_PG_READY_PROBE, encoding="utf-8")
    return probe


def pg_ready(probe_js: Path, timeout: float = 8.0, verbose: bool = False) -> bool:
    """用真实 pg 客户端探一次；连上并跑通 SELECT 1 才算就绪。

    为什么不能只看端口：实测端口先开、服务端仍在 recovery，
    靶场拿到 "the database system is starting up" 直接 SKIP。
    """
    # [FIX 2026-10-09 D30] 探针必须连 **PG 自带的 postgres 库**，不能连业务库 PG_DB：
    # 实测 datadir 里只有 postgres/template*，sqli_lab 从未被建过 ⇒ 端口通、能认证、
    # 但连不上 sqli_lab ⇒ 探针永远 PG_NOT_READY ⇒ 60s 超时 ⇒ 靶场在"PG 半起"状态下跑，
    # 拿到 "the database system is in recovery mode" 而 SKIP。
    # 判据该问的是「PG 能不能用」，不是「某个业务库在不在」——后者是 ensure_database 的事。
    try:
        r = subprocess.run([_find_node(), str(probe_js)],
                           env=_pg_env(PG_PORT, db="postgres"), capture_output=True,
                           text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        if verbose and "PG_READY" not in out:
            # 探针失败必须可见：此前静默返回 False，导致「端口通却判不就绪」无法归因
            print(f"[pg-run] 探针未就绪（exit={r.returncode}）：{out.strip()[:300]}")
        return "PG_READY" in out
    except subprocess.TimeoutExpired:
        # 探针自身超时（连接挂起）——与「PG 未就绪」是两回事，必须区分
        if verbose:
            print(f"[pg-run] 探针超时（>{timeout}s）：连接挂起，非『未就绪』")
        return False
    except Exception as e:
        if verbose:
            print(f"[pg-run] 探针异常：{e}")
        return False


_DB_ENSURE_JS = r"""
// 确保 PGDATABASE 指向的业务库存在（PG 初始化只给 postgres/template*）。
// 与就绪探针分开：先判「PG 能用」，再备「靶场要用的库」——
// 混在一起会把「库不存在」误读成「PG 没起来」。
const { createRequire } = require('module');
const req = createRequire(process.env.PG_BASE_JSON);
const pg = req('pg');
const db = process.env.PG_ENSURE_DB;
(async () => {
  const c = new pg.Client({
    host: process.env.PGHOST, port: Number(process.env.PGPORT),
    user: process.env.PGUSER, password: process.env.PGPASSWORD,
    database: 'postgres', connectionTimeoutMillis: 3000,
  });
  await c.connect();
  const r = await c.query('SELECT 1 FROM pg_database WHERE datname = $1', [db]);
  if (r.rowCount === 0) {
    await c.query('CREATE DATABASE "' + db.replace(/"/g, '""') + '"');
    console.log('PG_DB_CREATED ' + db);
  } else {
    console.log('PG_DB_EXISTS ' + db);
  }
  await c.end();
})().catch((e) => { console.log('PG_DB_FAIL ' + (e.message || e)); process.exit(3); });
"""


def ensure_database(port: int, db: str, verbose: bool = True) -> bool:
    """就绪之后备库：没有就建，有了就复用。失败要出声（否则又是静默半起）。"""
    script = PROJECT / "e2e" / ".pg-ensure-db.cjs"
    if not script.exists() or script.read_text(encoding="utf-8") != _DB_ENSURE_JS:
        script.write_text(_DB_ENSURE_JS, encoding="utf-8")
    env = _pg_env(port, db="postgres")
    env["PG_ENSURE_DB"] = db
    try:
        r = subprocess.run([_find_node(), str(script)], env=env,
                           capture_output=True, text=True, timeout=20)
        out = (r.stdout or "") + (r.stderr or "")
        ok = "PG_DB_CREATED" in out or "PG_DB_EXISTS" in out
        if verbose:
            print(f"[pg-run] 备库 {db}：" + ("就绪" if ok else f"失败（{out.strip()[:200]}）"))
        return ok
    except Exception as e:
        if verbose:
            print(f"[pg-run] 备库异常：{e}")
        return False


def start_pg(log_path: Path, probe_js: Path) -> subprocess.Popen | None:
    """前台方式拉起 postgres.exe（不用 pg_ctl start —— 它会 fork 后退出而被回收）。"""
    if not PG_EXE.exists():
        print(f"[pg-run] 找不到 {PG_EXE}", file=sys.stderr)
        return None
    if not (PG_DATA / "PG_VERSION").exists():
        print(f"[pg-run] datadir 未初始化：{PG_DATA}", file=sys.stderr)
        return None

    logf = open(log_path, "a", encoding="utf-8", errors="replace")
    print(f"[pg-run] 启动 PostgreSQL：{PG_EXE} -D {PG_DATA}")
    proc = subprocess.Popen(
        [str(PG_EXE), "-D", str(PG_DATA)],
        cwd=str(PG_DATA), stdout=logf, stderr=logf,
        creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
    )
    t0 = time.time()
    last_msg = ""
    while time.time() - t0 < 60:
        # 就绪判据：端口通 **且** 真能 SELECT 1（端口先开、服务端仍在 recovery 是常见中间态）
        if port_open(PG_PORT) and pg_ready(probe_js, verbose=True):
            print(f"[pg-run] PostgreSQL 就绪（{round(time.time()-t0,1)}s）@ 127.0.0.1:{PG_PORT}")
            return proc
        last_msg = f"（{round(time.time()-t0,1)}s：端口={'通' if port_open(PG_PORT) else '不通'}）"
        if proc.poll() is not None:
            print(f"[pg-run] postgres 进程已退出（code={proc.returncode}），日志尾部：")
            try:
                print(log_path.read_text(encoding="utf-8", errors="replace")[-1800:])
            except Exception:
                pass
            return None
        time.sleep(0.5)
    # [FIX 2026-10-09 D30] 超时 = 起不来。原先照样 return proc ⇒ 调用方拿到一个「起来了」的
    # 假信号，靶场在半死状态下开跑，把环境问题读成产品缺陷（实测：recovery mode ⇒ SKIP）。
    # 起不来就返回 None，并当场收摊（不带病继续，也不留后台进程）。
    print(f"[pg-run] 启动超时（60s）{last_msg} —— 判为起不来，本轮不跑")
    stop_pg(proc)
    return None


def stop_pg(proc: subprocess.Popen | None) -> None:
    """优雅停：优先 pg_ctl stop（等足 20s），失败则按 datadir 杀进程。"""
    if proc is None and not port_open(PG_PORT):
        return
    ctl = PG_BIN / "pg_ctl.exe"
    if ctl.exists():
        subprocess.run([str(ctl), "stop", "-D", str(PG_DATA), "-m", "fast", "-w", "-t", "20"],
                       capture_output=True, text=True)
    for _ in range(60):  # 最多等 18s（pg_ctl 已 -w -t 20，此处兜底）
        if not port_open(PG_PORT):
            print("[pg-run] PostgreSQL 已停止")
            return
        time.sleep(0.3)
    # 兜底：按命令行定位只杀本 datadir 的 postgres 进程
    try:
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq postgres.exe", "/V", "/FO", "CSV"],
                           capture_output=True, text=True)
        n = 0
        for line in (r.stdout or "").splitlines():
            if "postgres" not in line.lower() or "pg-smoke" not in line:
                continue
            fields = [f.strip('"') for f in line.split('","')]
            for f in fields:
                if f.isdigit() and f != "0":
                    subprocess.run(["taskkill", "/F", "/PID", f], capture_output=True, text=True)
                    n += 1
                    break
        if n:
            print(f"[pg-run] 已强制终止 {n} 个 postgres 进程")
    except FileNotFoundError:
        pass
    time.sleep(1)
    print("[pg-run] PostgreSQL 已停止" if not port_open(PG_PORT) else "[pg-run] 停止失败：端口仍占用")


def main() -> int:
    ap = argparse.ArgumentParser(description="PG 靶场运行器")
    ap.add_argument("entry", nargs="?", help="靶场入口脚本（相对项目根）")
    ap.add_argument("--probe", action="store_true", help="只探测能否拉起 PG")
    ap.add_argument("--keep", action="store_true", help="退出后保留 PG 进程")
    ap.add_argument("--extra-arg", action="append", default=[], help="透传给靶场的参数")
    args = ap.parse_args()

    log_path = PROJECT / "e2e" / "pg-run.log"
    probe_js = _materialize_probe()
    proc = None
    rc = 0

    if port_open(PG_PORT) and pg_ready(probe_js):
        print(f"[pg-run] PostgreSQL 已在运行且可用（{PG_PORT}），复用")
    else:
        proc = start_pg(log_path, probe_js)
        if proc is None and not pg_ready(probe_js):
            return 3

    # 备库放在「PG 已就绪」之后：自建的库与复用的宿主实例都要有 PGDATABASE 指向的那个库。
    if not ensure_database(PG_PORT, PG_DB):
        return 3

    try:
        if args.probe:
            # 连一下确认可用（用 psql 若在，否则只报端口）
            psql = PG_BIN / "psql.exe"
            if psql.exists():
                r = subprocess.run([str(psql), "-h", "127.0.0.1", "-p", str(PG_PORT),
                                    "-U", PG_USER, "-d", PG_DB, "-c", "SELECT version();"],
                                   capture_output=True, text=True,
                                   env={**os.environ, "PGPASSWORD": os.environ.get("PGPASSWORD", "")})
                print(f"[pg-run] psql 探测 exit={r.returncode}")
                print((r.stdout or r.stderr or "").strip()[:400])
                rc = 0 if r.returncode == 0 else 4
            else:
                print("[pg-run] 无 psql，仅确认端口可达")
            return rc

        if not args.entry:
            ap.error("需要靶场入口路径，或用 --probe")

        entry_path = PROJECT / args.entry
        if not entry_path.exists():
            print(f"[pg-run] 入口不存在：{entry_path}", file=sys.stderr)
            return 2

        env = dict(os.environ)
        env.update({
            "PGHOST": "127.0.0.1", "PGPORT": str(PG_PORT),
            "PGUSER": PG_USER, "PGDATABASE": PG_DB,
            "PGPASSWORD": env.get("PGPASSWORD", ""),
            "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
        })
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env.pop(k, None)

        node = _find_node()
        print(f"[pg-run] node = {node}\n[pg-run] entry = {args.entry}")
        r = subprocess.run([node, str(entry_path), *args.extra_arg],
                           env=env, cwd=str(PROJECT), text=True)
        print(f"[pg-run] 退出码 = {r.returncode}")
        rc = r.returncode
    finally:
        if proc is not None and not args.keep:
            stop_pg(proc)
        elif args.keep:
            print("[pg-run] --keep：保留 PG 进程（宿主回收后自动消失）")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
