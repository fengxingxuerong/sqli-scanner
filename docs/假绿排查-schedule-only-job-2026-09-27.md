# 假绿模式排查：schedule / workflow_dispatch-only job（2026-09-27）

> **起因**：`tamper-waf-matrix` 的 WAF A/B 门禁在 ubuntu runner 上**从未成功过**，
> 却长期以「绿」或「跳过」两种形态存在。根因是那一步调的
> `e2e/udf-lab/mysql_sandbox.py` 是 **Windows 专用**（`mysqld.exe` 硬编码、`MYSQL_HOME`
> 默认 `D:\mysql`、`tasklist`/`taskkill`，全文零平台分支）⇒ ubuntu 上连 `--init` 都跑不起来。
> 详见 `docs/优化空间评估-2026-09-26.md` 与 commit `98bd55c`。
>
> **本文做两件事**：① 用同一判据扫一遍其余 schedule/dispatch-only job；
> ② 把这个「假绿」模式固化成可复跑的守卫，避免同类第三次复发。
>
> 核实方式：读 `ci.yml` + GitHub API 查历史 run/job/step 结论 + 逐脚本读码。**未跑任何扫描**。

---

## 一、排查范围：谁是 schedule / workflow_dispatch-only

`ci.yml` 共 12 个 job，只有 **2 个**是 schedule/dispatch-only（其余都是 `!= 'schedule'`，即 push/PR 就跑）：

| job | 条件 | 首次进入 CI |
|---|---|---|
| `tamper-waf-matrix` | `schedule \|\| workflow_dispatch` | 早已存在 |
| `modsec-live` | 同上（与前者同款） | 2026-09-27 新增 |

> 口径说明：`if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`
> 的含义是「push 时不跑」。这类 job **天然具备潜伏条件** —— 平时 `git status` 全绿，
> 只有周度定时或手动触发才暴露。这是本次假绿的**第一层掩盖**。

## 二、历史真跑记录（GitHub API 实测）

全仓 86 次 run 中，非 push 的只有 **4 次**：

| run | 事件 | `tamper-waf-matrix` | `modsec-live` |
|---|---|---|---|
| #10 | schedule（2026-09-21） | ✅ success —— **假绿** | 不存在 |
| #82 | workflow_dispatch | ❌ failure | ✅ success |
| #84 | workflow_dispatch | ❌ failure | ✅ success |
| #86 | workflow_dispatch（修复后） | ✅ **success（首次真跑）** | ✅ success |

**#10 为什么是假绿**：查该 run 对应 commit（`5e5aa2b0`）的 `ci.yml`，该步骤当时带
`continue-on-error: true` —— 它**当时同样在失败**，只是被吞成绿。
（`continue-on-error` 于 2026-09-22 才去掉，此后 #82/#84 才如实报红。）

⇒ 这是本次假绿的**第二层掩盖**：`continue-on-error` 让「从未验证过任何东西」伪装成绿。

## 三、结论：其余 job 是否有同类问题

| job | 结论 | 依据 |
|---|---|---|
| `modsec-live` | ✅ **无问题** | #82/#84/#86 三次真跑全 success，16 个步骤全执行、0 skipped；新增时即按「真门禁」设计（自检不过直接 exit 1，**不加 continue-on-error**） |
| `tamper-waf-matrix` | ✅ **已修复** | commit `98bd55c`：改用 docker MySQL（与 acceptance 同款）。#86 实测 `MySQL 已连通：8.0.46`、`users 行数=6`、A/B 三判据全过（拦截率 79.4%→45.7%） |

**其余 10 个 job 不在排查范围内**（push/PR 即跑，不存在「平时看不见」的窗口）。
但为稳妥，另查了它们的最近一次真跑（run #86）：**13/13 job success，0 个 skipped 步骤**。

## 四、顺带扫出并已核实的 Windows-only 命中（全部安全）

用「.exe 硬编码 / 盘符路径 / tasklist·taskkill·wmic」三种模式扫 `ci.yml` 直接调用链：

| 文件 | 命中 | 定性 |
|---|---|---|
| `e2e/redteam-lab/env.mjs` | 8 处（17/18/24/25/50 行） | ✅ **安全**：有 `existsSync(MYSQLD)` 前置 + `[SKIP]` + exit 0（2026-09-21 CI-FIX）。CI 实测输出 `[SKIP] 未找到 mysqld 二进制`，按设计跳过 |
| `e2e/run-all.mjs` | 2 处（177/216 行） | ✅ **安全**：`:177` 的 `py` 只在 `useSandbox=true` 时用（而 `sandboxAvailable()` 在 CI 上为 false）；`:216` 的 `taskkill` 在 `if (process.platform === 'win32')` 内（**跨行守卫**） |
| `e2e/waf-lab/compare-real.e2e.mjs` | 1 处（154 行） | ✅ **安全**：纯错误提示文案，紧邻下一行已给 POSIX 方案（`lsof -ti :PORT \| xargs kill -9`） |
| `e2e/udf-lab/mysql_sandbox.py` | 8 处（57/58/318/401/402/405 行） | ⚠️ **真 Windows-only**，但**已不挂在 ubuntu CI 上**（修复后改走 docker）；本机 Windows 跑 UDF/fileops 时仍用它，属正确用法 |

## 五、已固化的守卫（防止第三次复发）

新增 `server/tests/ciWindowsOnly.guard.test.js`（5 用例，随 `npm test` 自动进 CI 的 test-server job，无需额外接线）。

**判据**：
1. **检出**：`ci.yml` 的 `run:` 里指向**本仓脚本**的，该脚本不得含**未登记**的 Windows-only 模式；
2. **不空转**：扫描器必须真能抽到脚本调用（否则「零违规」可能是解析写错）；
3. **反例自证**：用合成片段证明判据会红（断言不敏感 = 假绿，正是本守卫要防的东西）；
4. **import 链追踪**：必须能到达 `mysql_sandbox.py` —— 这是那次 bug 的**间接路径**
   （`ci.yml → compare-real.run.py → import mysql_sandbox`，Windows-only 代码在**被 import 的文件里**）；
5. **登记表防腐烂**：每个已登记例外必须仍真实命中（代码变了就该删条目）。

**设计取舍（重要）**：采用**显式登记已核实例外**（同 `KNOWN_MISSING_UI_KEYS` / `EXCLUDED_JOBS` / `.arch-baseline.json` 的本仓既有模式），
而非纯静态判定。原因：多处命中是**合法的**（默认值 + 跨行守卫 / 纯文案），
纯行级判据会把它们全报成违规 —— 噪声淹没信号。登记项**每条都写明「为什么安全」**，不写等于没写。

**只查 `ci.yml` 的 `run:` 而不查全仓**：`e2e/udf-lab/*.py` 等**本来就是 Windows 工具链**，
在 Windows 本机跑是正确用法；真正的风险面只有一处 —— **CI 会在 ubuntu 上执行的那些命令**。

### 缺陷注入复验（关键证据）

把当初的 bug 形态放回去（`run: node compare-real.e2e.mjs` → `run: python3 compare-real.run.py`），
守卫**恰好 1 条红**（检出测试），4 条自证仍绿；报出内容精确命中根因行：

```
e2e/udf-lab/mysql_sandbox.py:56  [硬编码 Windows 盘符路径]  MYSQL_HOME = Path(os.environ.get("MYSQL_HOME", r"D:\mysql"))
e2e/udf-lab/mysql_sandbox.py:57  [硬编码 .exe 可执行文件路径]  MYSQLD = MYSQL_HOME / "bin" / "mysqld.exe"
e2e/udf-lab/mysql_sandbox.py:58  [硬编码 .exe 可执行文件路径]  MYSQL      = MYSQL_HOME / "bin" / "mysql.exe"
e2e/waf-lab/compare-real.run.py:34  [硬编码 .exe]  candidates = sorted(managed.glob("versions/*/node.exe"), ...)
```

恢复后 5/5 全绿。⇒ 判据对真实 bug 敏感，且**报的是根因行而非症状**。

## 六、这次假绿模式的三个可复用判据（教训固化）

| # | 掩盖形态 | 判据 / 处置 |
|---|---|---|
| 1 | **job 级跳过**（schedule-only，push 时 skipped） | 对这类 job，**不能只看「最近一次 push 的 CI 绿」** —— 它根本没跑。必须查 `workflow_dispatch`/`schedule` 的历史 run |
| 2 | **`continue-on-error`** 把失败吞成绿 | 真门禁**一律不加**；若某步确需容错，必须同时给它一个「跳过也要有理由」的显式出口（如 `[SKIP]` + exit 0 + 原因打印） |
| 3 | **路径没走到**（条件分支在 CI 上恒不成立） | 「本地能跑」不等于「CI 走到」：`acceptance` 里那条同类沙箱路径只在宿主不放行 `secure_file_priv` 时才走，而它起的 docker MySQL 已放行 ⇒ 从不触发。「没走到」会被读成「能跑」 |

> 另记一条**判据层面的教训**：判断「能否恢复/是否安全」前，先确认自己看的是**正确的层**。
> 本次两次踩到同一形状：① 早先误判 U+FFFD 不可恢复（实际原始 GB18030 字节仍在 blob 里）；
> ② 守卫首版只扫**直接调用点**，而 Windows-only 代码在 **import 链下游**。
> **「某处没有 X」≠「项目里没有 X」** —— 这是本仓第四次同源病例。

---

## 附 · 复跑命令

```bash
# 守卫（含 4 条自证 + 1 条检出）
cd server && node --test tests/ciWindowsOnly.guard.test.js

# 枚举 schedule/dispatch-only job
python -c "import yaml,io; d=yaml.safe_load(io.open('.github/workflows/ci.yml',encoding='utf-8')); [print(n, j.get('if')) for n,j in d['jobs'].items() if 'schedule' in j.get('if','') and '!=' not in j.get('if','')]"

# 查历史非 push run（需 GH_TOKEN）
curl -s -H "Authorization: Bearer $GH_TOKEN" \
  "https://api.github.com/repos/fengxingxuerong/sqli-scanner/actions/runs?per_page=100" \
  | python -c "import json,sys; [print(r['run_number'], r['event'], r['conclusion']) for r in json.load(sys.stdin)['workflow_runs'] if r['event']!='push']"
```
