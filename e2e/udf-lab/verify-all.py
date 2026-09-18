#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
e2e/udf-lab/verify-all.py —— UDF 验证沙箱一键回归（纯标准库）

把散落的验证步骤串成一条命令，每个步骤都产出**可观测的通过/失败**：

  1. 沙箱隔离边界       —— 越权写入沙箱外路径必须被 MySQL 拒绝（真跑）
  2. 沙箱负向拦截       —— powershell/危险cmd/越权写/外网连接必须被拦
  3. UDF 直连基线       —— DLL 落地 → 注册 → 调用 → 回传（不经注入通道）
  4. udf-register       —— 经真实注入通道注册 + 调用
  5. udf-takeover       —— 经注入通道 + sys_eval 执行命令（需 --with-command-exec）

用法：
  python e2e/udf-lab/verify-all.py                    # 跑 1-4（不执行系统命令）
  python e2e/udf-lab/verify-all.py --with-command-exec # 额外跑 5（需你已授权）
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable


def run(label: str, cmd: list[str], *, expect_zero: bool = True) -> dict:
    print("\n" + "=" * 72)
    print(f"▶ {label}")
    print("=" * 72)
    r = subprocess.run(cmd, cwd=str(HERE.parent.parent), capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    # 只打印有信息量的尾部
    for ln in out.splitlines()[-22:]:
        print("  " + ln)
    ok = (r.returncode == 0) if expect_zero else True
    print(f"  → {'PASS' if ok else 'FAIL'}（退出码 {r.returncode}）")
    return {"label": label, "ok": ok, "exitCode": r.returncode}


def main() -> int:
    ap = argparse.ArgumentParser(description="UDF 验证沙箱一键回归")
    ap.add_argument("--with-command-exec", action="store_true",
                    help="包含 udf-takeover（会执行只读系统命令，需你已授权）")
    a = ap.parse_args()

    steps = [
        ("① 沙箱隔离边界",
         [PY, str(HERE / "mysql_sandbox.py"), "--verify-isolation-ephemeral"]),
        ("② 沙箱负向拦截",
         [PY, str(HERE / "sandbox.py"), "--script", "_sandbox_negative_probe.mjs",
          "--probe", "--no-mysql"]),
        ("③ UDF 直连基线",
         [PY, str(HERE / "udf_direct_probe.py")]),
        ("④ udf-register（经注入通道）",
         [PY, str(HERE / "sandbox.py"), "--script", "udf-register.e2e.mjs"]),
    ]
    if a.with_command_exec:
        steps.append((
            "⑤ udf-takeover（含 sys_eval）",
            [PY, str(HERE / "sandbox.py"), "--script", "udf-takeover.e2e.mjs",
             "--allow-command-exec"]))

    results = [run(label, cmd) for label, cmd in steps]

    print("\n" + "=" * 72)
    print("汇总")
    print("=" * 72)
    for r in results:
        print(f"  [{'PASS' if r['ok'] else 'FAIL'}] {r['label']}")
    ok_all = all(r["ok"] for r in results)
    print(f"\n结论：{sum(1 for r in results if r['ok'])}/{len(results)} 通过 → "
          + ("PASS" if ok_all else "FAIL"))

    # —— 复核：主实例未被污染 ——
    host_dll = Path(r"D:\mysql\lib\plugin\udf_sys.dll")
    print(f"\n主实例 plugin 目录未被污染：{'是' if not host_dll.exists() else '否（异常！）'}")

    if not a.with_command_exec:
        print("\n提示：未包含 udf-takeover（sys_eval 命令执行）。"
              "如已授权可加 --with-command-exec。")

    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
