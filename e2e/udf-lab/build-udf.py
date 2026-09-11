#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
e2e/udf-lab/build-udf.py —— 编译 MySQL UDF（Windows x64 / MSVC）

为什么单独一个脚本：UDF 验证需要「编译出真 DLL」这一步，而 MSVC 只能在
vcvars64 环境里调用（cl.exe 不在 PATH），且中文 Windows 输出为 GBK 编码，
直接塞进 shell 一行命令会踩引号与编码两个坑。这里固定下来，便于复现。

用法：python e2e/udf-lab/build-udf.py
依赖：VS 2022 BuildTools（MSVC + Windows SDK）+ D:\\mysql\\include\\mysql.h
输出：e2e/udf-lab/udf_sys.dll
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VCVARS = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
MYSQL_INCLUDE = os.environ.get("MYSQL_INCLUDE", r"D:\mysql\include")

def main():
    if not os.path.isfile(VCVARS):
        print(f"[SKIP] 未找到 vcvars64.bat：{VCVARS}")
        print("       UDF 真验证需要 MSVC 工具链（VS BuildTools）")
        return 2
    if not os.path.isfile(os.path.join(MYSQL_INCLUDE, "mysql.h")):
        print(f"[SKIP] 未找到 mysql.h：{MYSQL_INCLUDE}")
        return 2

    # 不使用 vcvars64.bat：它内部依赖 reg.exe 查询 SDK 位置，而本机安全策略禁止 reg.exe
    # （实测报“PROGRAM BLOCKED BY SECURITY POLICY”），导致环境初始化不全 → windows.h 找不到。
    # 改为**显式构造 INCLUDE/LIB/PATH** 直接调用 cl.exe —— 不绕过任何策略，只是不调用被禁程序。
    import glob

    vs_root = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
    msvc_ver = sorted(glob.glob(os.path.join(vs_root, r"VC\Tools\MSVC\*")))
    sdk_root = r"C:\Program Files (x86)\Windows Kits\10"
    sdk_ver = sorted(glob.glob(os.path.join(sdk_root, r"Include\10.*")))
    if not msvc_ver or not sdk_ver:
        print("[SKIP] 未找到 MSVC 或 Windows SDK 目录")
        return 2
    msvc = msvc_ver[-1]
    sdk_inc = sdk_ver[-1]
    sdk_lib_ver = os.path.basename(sdk_inc)

    env = dict(os.environ)
    env["PATH"] = os.pathsep.join([
        os.path.join(msvc, r"bin\Hostx64\x64"),
        os.path.join(sdk_root, "bin", sdk_lib_ver, "x64"),
        env.get("PATH", ""),
    ])
    env["INCLUDE"] = os.pathsep.join([
        MYSQL_INCLUDE,
        os.path.join(msvc, "include"),
        os.path.join(sdk_inc, "ucrt"),
        os.path.join(sdk_inc, "um"),
        os.path.join(sdk_inc, "shared"),
    ])
    env["LIB"] = os.pathsep.join([
        os.path.join(msvc, "lib", "x64"),
        os.path.join(sdk_root, "Lib", sdk_lib_ver, "ucrt", "x64"),
        os.path.join(sdk_root, "Lib", sdk_lib_ver, "um", "x64"),
    ])

    cl = os.path.join(msvc, r"bin\Hostx64\x64\cl.exe")
    r = subprocess.run(
        [cl, "/nologo", "/LD", "udf_sys.c", "/link", "/OUT:udf_sys.dll"],
        capture_output=True, cwd=HERE, env=env,
    )
    out = (r.stdout + r.stderr).decode("gbk", errors="replace")
    dll = os.path.join(HERE, "udf_sys.dll")

    ok = r.returncode == 0 and os.path.isfile(dll)
    print(out.strip()[-1500:])
    if ok:
        print(f"\n[OK] 编译成功：{dll}（{os.path.getsize(dll)} bytes）")
        # 确认导出符号（UDF 靠函数名约定导出，缺符号会导致 CREATE FUNCTION 报错）
        try:
            dumpbin = subprocess.run(
                ["cmd", "/c", f'call "{VCVARS}" >nul 2>&1 && dumpbin /exports udf_sys.dll'],
                capture_output=True, cwd=HERE,
            ).stdout.decode("gbk", errors="replace")
            syms = [ln.split()[-1] for ln in dumpbin.splitlines() if "udf_" in ln]
            print(f"[OK] 导出符号：{sorted(set(syms))}")
        except Exception as e:  # noqa: BLE001
            print(f"[warn] 导出符号检查跳过：{e}")
        return 0
    print(f"\n[FAIL] 编译失败（exit={r.returncode}）")
    return 1


if __name__ == "__main__":
    sys.exit(main())
