# 外部裁判 5 号 · VulnLab（[D156] 2026-10-25）

[真值来源：hediwen831-star/vulnlab](https://github.com/hediwen831-star/vulnlab) ——
自研 Web 漏洞靶场 + PoC 基准集（W43 竞品对标排队项，见 `docs/竞品对标-2026W43.md`）。

## 为什么是它

- **同一应用里的三档实现**：`html/sqli/{low,medium,high}.php` —— low 数字型直拼 /
  medium 黑名单（非递归替换，官方标注双写可绕）/ high `:id` 参数化修复。
  修复档即**天然误报诱饵**：对方 `benchmark/manifest.yaml` 明示「high 档上的任何一条
  漏洞报告都是误报，无需人工复核」，且对方 CI 用 52 条绕过尝试断言守护修复档
  （真值失效对方 CI 先红）—— 不是本仓出题本仓判卷。
- **零依赖形态**：php -S + pdo_sqlite（SQLite 首次访问自动建库），runner 自拉自收
  （未 clone 自动 `git clone --depth 1`；已在跑则复用），CI ubuntu 自带 php 即可真实执行。

## 跑法

```bash
node e2e/vulnlab-lab/run.mjs          # 三档扫描 + 裁决（通过 exit 0 / 未通过 exit 1 / php 缺失 [SKIP]）
```

可覆盖环境变量：`VULNLAB_PORT`（默认 8135）· `VULNLAB_DIR`（默认
`%LOCALAPPDATA%\Temp\verify-labs\vulnlab`）· `PHP_EXE`（php 路径，默认探测
`D:/tools/php83/php.exe` → PATH）。

## 本机形态备注（Windows）

共享 `php.ini` 常被 DVWA 场景锁死为 MySQL 形态（未启用 pdo_sqlite）—— runner 用
`php -n -d extension_dir=… -d extension=pdo_sqlite` **独立加载、不改共享 ini**。
Linux/macOS 的 php 通常内置 pdo_sqlite，无需额外参数。

## 判据口径（防自欺）

- 真值档（low/medium）漏检从严：没检出就是漏检（没测成也计入，`verdict` 不可信另行披露）；
- 每档请求计数 < 25 或结论不可信 ⇒ 「证据不足」，**不许**当零误报通过（[D113] 教训：
  「没测过」是本仓栽过三次的形状）;
- 三档必须各自真跑（acceptance assert 校验三行请求计数都在），删档防缩水。

结果落盘：`results/external-judge-<日期>-d155.md`。
