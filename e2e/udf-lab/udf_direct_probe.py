# -*- coding: utf-8 -*-
"""沙箱内 UDF 完整链路验证（直接 SQL 路径）。

目的：证明「DLL 落地 → CREATE FUNCTION 注册 → SELECT 调用 → 返回值回传」
在隔离实例里真的能跑通，且全程不涉及任何系统命令执行。

这是 udf-register.e2e.mjs（走注入通道）的**前置基线**：
若直连都跑不通，注入通道失败就无从归因。
"""
import sys
from pathlib import Path
from shutil import copyfile

sys.path.insert(0, r"D:\projects\sqli-scanner\e2e\udf-lab")
import mysql_sandbox as ms

results = []


def sql(text):
    rc, out = ms._mysql_exec(text, user=ms.SANDBOX_USER, password=ms.SANDBOX_PASSWORD,
                             extra=["-N", "-B"], database="sqli_lab")
    # 去掉密码警告行
    lines = [ln for ln in out.splitlines() if "Using a password" not in ln]
    return rc, "\n".join(lines).strip()


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"  [{'OK  ' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


with ms.launch() as info:
    print(f"[udf-diag] 沙箱实例 {info['host']}:{info['port']}")

    # ① DLL 落地
    src = Path(ms.HERE) / "udf_sys.dll"
    dst = Path(info["pluginDir"]) / "udf_sys.dll"
    copyfile(src, dst)
    check("DLL 落地 plugin_dir", dst.exists() and dst.stat().st_size == src.stat().st_size,
          f"{dst.stat().st_size} bytes")

    # ② 注册函数（符号名必须是 DLL 真实导出的 udf_echo）
    rc, out = sql("CREATE FUNCTION udf_echo RETURNS STRING SONAME 'udf_sys.dll';")
    check("CREATE FUNCTION 注册成功", rc == 0, out[:200] if rc else "")

    # ③ 独立事实源复核：mysql.func 表
    rc, out = sql("SELECT COUNT(*) FROM mysql.func WHERE name='udf_echo';")
    check("mysql.func 表确认已注册", rc == 0 and out.strip().endswith("1"), f"count={out.strip()}")

    # ④ 调用并断言返回值（外部事实：回传值 == 传入标记）
    marker = "sandbox_udf_probe_42"
    rc, out = sql(f"SELECT udf_echo('{marker}');")
    check("SELECT 调用返回值正确", rc == 0 and marker in out, f"回传={out.strip()[:80]}")

    # ⑤ 清理
    rc, out = sql("DROP FUNCTION IF EXISTS udf_echo;")
    rc2, out2 = sql("SELECT COUNT(*) FROM mysql.func WHERE name='udf_echo';")
    check("DROP FUNCTION 已清理", rc == 0 and out2.strip().endswith("0"))

    # ⑥ 确认没碰主实例：主实例 plugin 目录不应有我们的 DLL
    host_plugin = Path(r"D:\mysql\lib\plugin")
    if host_plugin.is_dir():
        leaked = (host_plugin / "udf_sys.dll").exists()
        check("主实例 plugin 目录未被污染", not leaked)

    dst.unlink(missing_ok=True)

print()
ok_all = all(r[1] for r in results)
print(f"结论：{sum(1 for r in results if r[1])}/{len(results)} 通过 → "
      + ("PASS" if ok_all else "FAIL"))
sys.exit(0 if ok_all else 1)
