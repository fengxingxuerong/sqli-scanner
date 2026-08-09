# SQL 注入检测工具「sqli-scanner」— WAF-v2 增量 PRD（仅变更部分 · 指纹库 7→~30 + 真机/e2e 验证）

> 作者：产品经理 许清楚（Xu）
> 版本：WAF-v2 增量（基于 F-20 已交付：后端 277 / 前端 48 测试 PASS）
> 语言：简体中文
> 配套文档：`docs/prd_f20_waf.md`、`docs/system_design_f20.md`；既有规则：`server/src/core/waf/wafRules.js`、`wafRecommend.js`

---

## 1. 增量概述

WAF-v2 是 F-20 之上的一轮"最高规则"严格增量，合并用户两件诉求：

- **#2 指纹库扩库（7 → ~30）**：把现有 `WAF_RULES` 的 7 类扩到约 30 类，对齐 sqlmap `--identify-waf`（thirdparty/identywaf，实测支持 70+ 产品）与 wafw00f 权威清单；每个新 vendor 基于响应头/状态码/body 特征（大小写不敏感，沿用 `wafRules.js` 写法）给 matcher 与置信度，多 matcher 命中升级置信度；同步扩展 `WAF_RECOMMEND_MAP`，每个 vendor 映射到**仅由 `tamperRegistry` 已注册插件名**组成的组合（可复用 F-20 的 `TAMPER_INTENSITY_PRESETS` 低/中/高三档，必要时为特定 WAF 定制）。**严禁写未注册插件名。**
- **#1 真机 / e2e 验证（沙箱只能等价复现，用户已选「本地模拟 WAF 实验室」）**：新增本地 mock-WAF 实验室（Express 中间件复刻 ModSecurity CRS 类签名拦截，命中 SQLi 关键字/正则即 403，一键启动；背后挂 sqli-labs 风格注入点，让扫描器能真正跑出检测结果）；提供 e2e 夹具对比「tamper 全关」vs「tamper 开（推荐组合）」的注入检出成功率与被拦截比例；并产出一份真实云 WAF（用户自有 Cloudflare / AWS WAF + 靶机）runbook，供用户本机执行（沙箱不跑该数据）。

> 范围边界：本期**不改写** F-20 的 WAF 识别引擎（`WafIdentifier`）、推荐契约（`recommend()`）与前端面板（`WafTamperPanel` 建议流已能消费任意 vendor 的推荐）。WAF-v2 仅是"规则/映射扩库 + 验证体系"，属数据面与测试面增量。

---

## 1.1 现状核查（基于 F-20 已交付代码，如实记录）

编写前已阅读 F-20 PRD / 设计、`server/src/core/waf/wafRules.js`、`wafRecommend.js`、`server/src/core/tamper/applyTampers.js`（确认 62 插件注册名）。事实如下：

1. **F-20 已交付且测试 PASS**：后端 277 / 前端 48 用例通过；`WafIdentifier` + `WAF_RULES` + `WAF_RECOMMEND_MAP` + `recommend()` + `GET /api/tampers` + `WafTamperPanel` 建议流均已落地。本期是**在其上扩库与加验证**，非重做。
2. **现有 `WAF_RULES` 仅 7 类**：Cloudflare / ModSecurity / AWS_WAF / Aliyun_WAF / Baidu_Yunjiasu / SafeDog / Tencent_WAF；matcher 写法统一为 `{type:'header'|'status'|'body', key?, test?}`，大小写不敏感（设计文档 §3.4 定义，`WafIdentifier` 负责聚合与置信度）。
3. **现有 `WAF_RECOMMEND_MAP` 7 项**，值均为已注册插件名（如 `modsecurityversioned`、`securesphere` 均在 62 之内），`recommend(vendors)` 仅返回命中映射且 plugins 非空项——该契约可原样复用，扩库只需增键。
4. **`TAMPER_INTENSITY_PRESETS` 已定义（F-20 设计 §7.3）**：`low=[space2comment,randomcase]`、`medium=[space2comment,randomcase,charencode]`、`high=[space2comment,randomcase,charencode,modsecurityversioned,percentage,versionedkeywords]`；所有名均为 `tamperRegistry` 已注册名。新 vendor 推荐可直引预设或定制。
5. **62 个已注册插件名已确认**（来自 `applyTampers.js` 导入）：含 `space2comment/space2plus/randomcase/randomcomments/charencode/charunicodeencode/chardoubleencode/appendnullbyte/equaltolike/between/modsecurityversioned/modsecurityzeroversioned/percentage/versionedkeywords/versionedmorekeywords/securesphere/sp_password/bluecoat/…` 等——足以覆盖约 30 个 vendor 的"针对性推荐组合"需求，**无需新增插件**（呼应 F-20 待确认 ① 结论：基本齐全）。
6. **sqlmap identywaf 实际清单已调研**：交叉核对 sqlmap 调试日志（`checking for WAF/IPS/IDS product '...'`）与 wafw00f 权威厂商表，确认 sqlmap 可识别 **70+** 真实 WAF 产品（如 Barracuda、F5 BIG-IP、FortiWeb、Imperva/Incapsula、Akamai Kona、DenyAll、Wordfence、Sucuri、Citrix NetScaler、Cisco ACE、Radware AppWall、Sophos、360/Qihoo、NAXSI、DotDefender、BinarySec、BlockDoS、Bluedon、Chuangyu、Eisoo、Janusec、KnownSec KS-WAF、Safe3、WebKnight、HyperGuard、Armor、GoDaddy、Yundun、Yunsuo、Zenedge、Reblaze、SignalSciences、WallArm 等）。本期取其中**真实存在、可经响应头/状态码/body 特征化**的约 30 个（含保留的 7 个原厂）。
7. **验证缺口（F-20 遗留）**：F-20 仅有单元级 `waf.f20.test.js`（样本识别/零误报），**没有可复现的端到端"开/关 tamper 检出率差异"证据**，也没有本地 WAF 实验室与真实云 WAF runbook——这正是 #1 要补的。

> **结论**：WAF-v2 工程重心 = ① 把 `WAF_RULES` / `WAF_RECOMMEND_MAP` 扩到约 30 vendor（数据面，带单测护栏）；② 建本地 mock-WAF 实验室 + e2e 对比夹具 + 真实云 WAF runbook（验证面）。前端无需新组件（建议流自动消费更多 vendor）。

---

## 2. 产品目标

| # | 目标 | 说明（可衡量） |
|---|------|----------------|
| G1 | 指纹覆盖对齐 sqlmap：规则数 7 → ~30 | 扩库后 `WAF_RULES` 含约 30 vendor；`identify` 对已知样本**零误报、命中准确**（单测覆盖）。 |
| G2 | 推荐精准且合法：每个新 vendor 都有"仅已注册插件"的推荐组合 | `recommend()` 对扩库后所有 vendor 返回的 plugins 名**全部存在于 `tamperRegistry`**；不允许出现未注册名。 |
| G3 | 可验证的绕过效果：本地实验室 + e2e 产出"开 tamper 检出率 > 关 tamper"的可复现数据 | mock-WAF 实验室可一键启；e2e 跑出关 vs 开两种配置的检出率对照；真实云 WAF runbook 可执行（沙箱不出数据）。 |

三目标正交：G1 是覆盖广度、G2 是推荐质量、G3 是效果可证。

---

## 3. 用户故事

| # | 角色 | 期望 | 价值 |
|---|------|------|------|
| US1 | 安全测试人员 | 作为测试人员，当目标前置的是小众/国产 WAF（如安全狗、KnownSec、360、Chuangyu）时，我希望工具也能识别并给出推荐 tamper。 | 不再只认 7 个主流 WAF，覆盖面接近 sqlmap。 |
| US2 | 安全测试人员 | 作为测试人员，我希望推荐的每个 tamper 都真实可用（不出现"推荐了不存在的插件"）。 | 一键应用后真的能触发变换，而非静默失效。 |
| US3 | 安全测试人员 | 作为测试人员，我希望有一套本地 WAF 实验室，能在不开通真实云 WAF 的情况下，复现"被拦截→开 tamper 绕过→检出"的全过程。 | 在 CI/本机即可验证绕过能力，不依赖外部资源。 |
| US4 | 审计/合规人员 | 作为审计人员，我希望看到"开/关 tamper 的注入检出率对比"数据，证明绕过确实提升了检测覆盖。 | 量化 WAF 绕过的实际收益，支撑整改沟通。 |
| US5 | 安全测试人员 | 作为测试人员，我希望有一份真实云 WAF（我的 Cloudflare / AWS WAF）的 runbook，按步骤就能在本机复现验证。 | 把实验室结论延伸到真实环境，闭环验证。 |

---

## 4. 需求池（P0 / P1 / P2 分级）

> 优先级：P0 = 必须（本期交付）；P1 = 应当（高价值，力争本期）；P2 = 可选（后续）。
> 本期**不改写识别引擎/契约/前端面板**，仅扩规则/映射 + 加验证。

### P0（必须）

| ID | 需求 | 受影响模块 | 验收标准 |
|----|------|-----------|----------|
| P0-1 (#2) | 扩展 `WAF_RULES` 至约 30 vendor：保留原有 7 个，新增约 23 个（见附录 A）；每个含 `matchers`（`header`/`status`/`body`，大小写不敏感，沿用 `wafRules.js` 写法），并由 `WafIdentifier` 按命中数/权重估算置信度（强特征头 0.9、body/status 0.7，多命中升级至 0.95+）。 | `server/src/core/waf/wafRules.js` | 规则数约 30（允许 28–32）；每个新 vendor 至少 1 个可特征化 matcher；`WafIdentifier` 识别准确、不崩。 |
| P0-2 (#2) | 同步扩展 `WAF_RECOMMEND_MAP` 至约 30 vendor：每个 vendor 映射到**仅由 `tamperRegistry` 已注册插件名**组成的数组；可复用 `TAMPER_INTENSITY_PRESETS` 低/中/高三档，或为特定 WAF 定制（如 ModSecurity→`modsecurityversioned` 系列、Imperva→`securesphere`、Citrix/NetScaler→含 `space2plus`）。**严禁未注册名。** | `server/src/core/waf/wafRecommend.js` | 扩库后 `recommend(vendors)` 对所有 vendor 返回的 plugins 名**全部在 62 注册名内**；新增静态校验（启动期断言）防止误写未注册名。 |
| P0-3 (#2) | 扩库护栏测试：①`identify` 对带特征的样本响应准确识别对应 vendor；②对**无特征**响应返回 `[]`（零误报）；③`recommend` 仅返回命中映射且 plugins 非空项；④新增"推荐名合法性"测试——遍历 `WAF_RECOMMEND_MAP` 所有值，断言每个名都在 `tamperRegistry.list()` 中。 | `server/tests/waf*.test.js` | 全量 vendor 单测通过；零误报用例存在；推荐名合法性断言通过。 |
| P0-4 (#1) | 本地 mock-WAF 实验室：新增 Express 中间件复刻 ModSecurity CRS 类**签名拦截**——对请求参数/body 命中 SQLi 关键字或典型正则（`UNION`/`SELECT`/`OR 1=1`/`--`/`#`/`0x..`/`SLEEP` 等）即返回 403；否则放行至后端 sqli-labs 风格注入点（已知 `id` 注入参数，能跑出真实检测结果）。提供一键启动脚本（如 `npm run waf-lab`）。 | `e2e/waf-lab/*`（新增，独立于生产 server） | 实验室可一键启；对含 SQLi 特征的请求稳定 403；对良性请求放行且注入点可被扫描器检出。 |
| P0-5 (#1) | e2e 对比夹具：驱动扫描器（或 `Detector`）以「tamper 全关」vs「tamper 开（对识别到的 WAF 用推荐组合）」两种配置打**同一 mock-WAF 目标**，对比**注入检出成功率**与「被 WAF 拦截导致 0 检出」的比例，产出可复现数据（JSON/Markdown 对照表）。 | `e2e/waf-lab/*.e2e.js`（新增） | 跑出"开 tamper 检出率 > 关 tamper"的差异数据；拦截率可量化；结果可复现（固定靶机样本）。 |
| P0-6 (#1) | 真实云 WAF runbook：产出 `docs/waf_runbook.md`，给出用户本机执行流程（自有 Cloudflare 域名 / AWS WAF + 靶机 + 本工具启动与命令 + 如何读取 `waf_detected` 建议并一键应用）。沙箱不在本期跑该数据，仅保证文档步骤可执行、命令准确。 | `docs/waf_runbook.md`（新增） | 文档步骤自洽、可复现；含"开启→识别→应用推荐→复扫"闭环命令。 |

### P1（应当）

| ID | 需求 | 受影响模块 | 验收标准 |
|----|------|-----------|----------|
| P1-1 (#2) | 置信度分层细化：为不同 vendor 设基础权重（强特征头 0.9 / body 0.7 / 弱疑似 0.5），多命中升到 0.95+；区分"强识别"与"弱疑似"，影响前端建议展示门槛（强识别才给"一键应用"，弱疑似仅提示）。 | `WafIdentifier` / `WafTamperPanel` 建议展示 | 强/弱分级在建议流有可见差异；不影响 F-20 既有 7 vendor 行为。 |
| P1-2 (#2) | 多 WAF 串联识别：单目标前置多层 WAF 时，`identify` 已返回数组，本期明确"多命中"测试与推荐合并策略（取各 vendor 推荐并集去重，或用户手动选其一）。 | `wafRules.js` / `wafRecommend.js` / 测试 | 多 WAF 样本能返回多个候选；推荐合并策略有单测。 |
| P1-3 (#1) | e2e 结果产物化：把"关 vs 开"对照数据输出为可复现报告片段（纳入 CI artifact / 工具报告可附加），而不只是控制台打印。 | `e2e/waf-lab/*` | CI 可产出对照报告文件；结构稳定可 diff。 |
| P1-4 (#2) | 针对性推荐标注：为重点 WAF（Imperva=`securesphere`、ModSecurity=`modsecurityversioned`、Citrix/NetScaler=`space2plus` 等）给专属组合，并在前端建议区分"针对性组合"与"通用预设"，帮助用户理解推荐依据。 | `wafRecommend.js` / `WafTamperPanel` | 专属组合生效；建议区标注针对性程度。 |

### P2（可选 / 后续增强）

| ID | 需求 | 说明 |
|----|------|------|
| P2-1 | 自动套用推荐（用户二次确认总开关） | F-20 已定为留待后续；本期仅推荐不套用。 |
| P2-2 | 绕过成功率统计 / 关 vs 开 命中率对比报表 | 高级分析；e2e 已产出原始对照数据，报表可视化留此。 |
| P2-3 | 用户自定义 WAF 规则条目 | UI/配置扩展 `WAF_RULES`（运行时注入自定义 matcher）。 |
| P2-4 | 真实云 WAF 数据集沉淀 | 用户回传匿名化命中样本，反哺扩库（社区化）。 |
| P2-5 | 继续扩库至 50+/对齐 sqlmap 全量 70+ | 持续扩库，本期先到 ~30 建立可维护流程。 |

---

## 5. 附录 A：建议 ~30 vendor 清单（含 matcher 示意与推荐组合）

> 下表为 PRD 建议基线（7 保留 + 23 新增 = 30）。matcher 仅列**代表性特征**，具体正则由工程师按 sqlmap identywaf / wafw00f 签名实现，须"可特征化"。推荐组合**仅含已注册插件名**（已与 62 注册名核对）。
> 置信度基准：强特征响应头=0.9，body/状态码特征=0.7，多 matcher 命中升级至 0.95+。

| # | vendor（key） | 建议 matcher（示意，大小写不敏感） | 推荐组合（仅已注册插件名） | 类型 |
|---|---------------|-----------------------------------|----------------------------|------|
| 1 | Cloudflare | header `cf-ray`；server `cloudflare` | space2comment, randomcase, charencode | 保留 |
| 2 | ModSecurity | body `/modsecurity/i`；server `mod_security`；status 406/501 | modsecurityversioned, versionedkeywords, space2comment | 保留 |
| 3 | AWS_WAF | header `x-amzn-requestid`；body `request blocked by aws waf` | charencode, randomcase, space2comment | 保留 |
| 4 | Aliyun_WAF | server `aliyun`；body `阿里云` | space2comment, randomcase, charencode | 保留 |
| 5 | Baidu_Yunjiasu | server `bws|baidu`；via `yunjiasu` | space2comment, randomcomments, randomcase | 保留 |
| 6 | SafeDog | server `safedog`；header `x-powered-by-safedog` | charencode, space2comment, equaltolike | 保留 |
| 7 | Tencent_WAF | server `tencent|stgw`；header `x-ws-request-id` | space2comment, randomcase, charencode | 保留 |
| 8 | Barracuda | header `x-barracuda-*`；server `barracuda` | space2comment, randomcase, charencode | 新增 |
| 9 | F5_BIG_IP | cookie `BIGipServer*`；server `BigIP` | space2comment, randomcase, space2plus | 新增 |
| 10 | FortiWeb | server `FortiWeb`；header `x-wa-*` | space2comment, randomcase, percentage | 新增 |
| 11 | Imperva_Incapsula | header `x-iinfo`/`incap`；body `Incapsula` | securesphere, space2comment, randomcase | 新增 |
| 12 | Akamai_Kona | header `akamai`/`x-akamai`；server `Akamai` | space2comment, randomcase, charencode | 新增 |
| 13 | DenyAll | cookie `denyall_*`；body `DenyAll` | space2comment, randomcase, charencode | 新增 |
| 14 | Wordfence | body `Wordfence`；server `wordfence` | space2comment, randomcase, charencode | 新增 |
| 15 | Sucuri | header `x-sucuri-id`；server `Sucuri` | space2comment, randomcase, charencode | 新增 |
| 16 | Citrix_NetScaler | cookie `NSC_*`；via `NS-CACHE` | space2comment, randomcase, space2plus | 新增 |
| 17 | Cisco_ACE | server `ACE` | space2comment, randomcase, charencode | 新增 |
| 18 | Radware_AppWall | header `x-rdw-*`；server `Radware` | space2comment, randomcase, percentage | 新增 |
| 19 | Sophos_UTM | server `sophos`；body `Sophos` | space2comment, randomcase, charencode | 新增 |
| 20 | Qihoo_360 | body `360webscan|qihoo`；header `x-*` | space2comment, randomcase, charencode | 新增 |
| 21 | NAXSI | body `blocked by NAXSI`；server `nginx`+`naxsi` | space2comment, randomcase, charencode | 新增 |
| 22 | DotDefender | header `x-dotdefender`；server `DotDefender` | space2comment, randomcase, charencode | 新增 |
| 23 | BinarySec | server `BinarySec` | space2comment, randomcase, charencode | 新增 |
| 24 | BlockDoS | header/body `BlockDoS` | space2comment, randomcase, charencode | 新增 |
| 25 | Bluedon | server `Bluedon`；body `Bluedon` | space2comment, randomcase, charencode | 新增 |
| 26 | Chuangyu | body `chuangyu|Yunaq`；header `*` | space2comment, randomcase, charencode | 新增 |
| 27 | Eisoo | server `Eisoo|esafe`；body `Eisoo` | space2comment, randomcase, charencode | 新增 |
| 28 | Janusec | header `x-janusec`；body `Janusec` | space2comment, randomcase, charencode | 新增 |
| 29 | KnownSec_KSWAF | server `ks-waf`；body `Knownsec` | space2comment, randomcase, charencode | 新增 |
| 30 | Safe3 | body `Safe3 Web Application Firewall` | space2comment, randomcase, charencode | 新增 |

> 说明：新增 vendor 的推荐组合默认取 `TAMPER_INTENSITY_PRESETS.medium`（= `[space2comment,randomcase,charencode]`），并对少数"针对性"WAF 做了定制（FortiWeb/Radware 加 `percentage`、F5/Citrix 加 `space2plus`、Imperva 用 `securesphere`、SafeDog 保留 `equaltolike`、ModSecurity 用 `modsecurityversioned` 系列）。所有名均经 62 注册名核对，无未注册名。

---

## 6. 验证方案 / UI 设计

### 6.1 本地 mock-WAF 实验室（#1，P0-4）

- **结构（新增 `e2e/waf-lab/`，独立于生产 `server/`）**：
  - `lab-server.js`：Express 应用。① 中间件 `wafMiddleware`：解析 query/body，对 SQLi 特征（关键字/典型正则，如 `UNION\s+SELECT`、`OR\s+\d+=\d+`、`--`、`#`、`0x[0-9a-f]+`、`SLEEP\(`、`/\*.*\*/`、单引号配对异常等）命中即 `res.status(403).send('<h1>403 Forbidden</h1>')`；② 后端路由 `GET /vuln?id=1`：sqli-labs 风格，按 `id` 做不安全拼接查询并返回"查询结果行"，让扫描器能真正跑出 UNION/报错/布尔/时间等检测；③ 另提供 `GET /benign` 良性页用于基线。
  - `package.json` script：`"waf-lab": "node e2e/waf-lab/lab-server.js"`（默认端口如 8099，可配）。
- **"ModSecurity CRS 类"程度**：默认采用"简化但具代表性"的关键字/正则黑名单，足以验证 tamper 绕过差异；**不强制**对齐完整 CRS 规则集（避免规则库体积与维护成本，见待确认 ⑦）。
- **一键启动**：`npm run waf-lab` 即起；无外部依赖（Express 已在技术栈内）。

### 6.2 e2e 对比夹具（#1，P0-5）

- **夹具流程**：
  1. 启动 mock-WAF 实验室（对 `GET /vuln?id=` 拦截 SQLi 特征）。
  2. **配置 A（tamper 全关）**：启动扫描器对 `/vuln?id=` 扫描，收集报告 `reportA`（被 403 拦截的点 → 0 检出）。
  3. **配置 B（tamper 开，推荐组合）**：以识别到的 WAF 推荐组合（如 `space2comment,randomcase,charencode`）开启 tamper，复扫同目标，收集 `reportB`。
  4. **指标计算**：`检出率 = 被确认 vulnerable 的注入点数 / 总注入点数`；`拦截率 = 返回 403 且未检出的点占比`。
  5. **产物**：输出对照表（JSON + Markdown），示例：
     | 配置 | 总注入点 | 检出 | 检出率 | 被 WAF 拦截(0 检出) |
     |------|---------|------|--------|----------------------|
     | tamper 关 | 12 | 3 | 25% | 9 |
     | tamper 开(推荐) | 12 | 10 | 83% | 2 |
- **可复现**：固定靶机样本（同一 `/vuln` 路由与上同的注入点集），CI 可重复跑出稳定差异。

### 6.3 真实云 WAF runbook（#1，P0-6）

- **`docs/waf_runbook.md` 内容大纲**：① 前置条件（自有域名 + Cloudflare/AWS WAF 已开启、一台有注入点的靶机、本工具已 `npm run dev`）；② 在 WAF 后挂靶机并确认"裸请求即被 403"；③ 用本工具对靶机发起扫描（tamper 关）→ 观察 `waf_detected` 事件与建议；④ 一键应用推荐组合并显式开启 `enabled` → 复扫；⑤ 对比两次报告检出率；⑥ 收尾与合规提示（仅授权目标）。沙箱不在本期跑该数据。

### 6.4 UI 设计（前端无需新组件）

- F-20 的 `WafTamperPanel` 建议流已能消费**任意 vendor** 的 `waf_detected` 建议（`vendor` + `plugins`），扩库后自动对约 30 vendor 生效，**无需新增 UI 组件**。
- 若 P1-4 落地，建议在 `WafTamperPanel` 建议区对"针对性组合"做轻微标注（如徽标"针对 ModSecurity"），复用现有 `Alert`/`Chip`，不引入新依赖。
- 实验室/runbook 属测试与文档产物，不进产品 UI。

---

## 7. 对旧架构的影响与风险

### 7.1 接入点

| 变更 | 接入旧模块 | 说明 |
|------|------------|------|
| P0-1 扩库 | `server/src/core/waf/wafRules.js` | 仅增 `WAF_RULES` 键；`WafIdentifier` 遍历逻辑不变（已支持多 vendor 数组返回）。 |
| P0-2 扩映射 | `server/src/core/waf/wafRecommend.js` | 仅增 `WAF_RECOMMEND_MAP` 键；`recommend()` 契约不变。 |
| P0-3 测试 | `server/tests/waf*.test.js` | 纯增量测试，不改动 F-20 引擎。 |
| P0-4/5/6 验证 | 新增 `e2e/waf-lab/*`、`docs/waf_runbook.md` | 独立于生产 server，不影响线上契约与前端。 |

### 7.2 兼容 / 回归风险

- **低（识别引擎不变）**：`WafIdentifier` / `recommend()` 逻辑不改，扩库只是数据增量；原 7 vendor 行为完全保持。
- **低（推荐合法性）**：若误写未注册插件名，扫描器 `TamperRegistry.resolve` 会**跳过并 warn**（F-20 已具备），不会崩溃；P0-2 新增"启动期静态断言"进一步防呆。
- **低（前端零改动）**：建议流按 `vendor` 字符串消费，扩库无需前端改动即可生效。
- **中（误报风险）**：约 30 vendor 的 matcher 若过宽（如仅靠 `server` 含某子串）可能误命中。护栏：① 弱特征给低置信度（0.5）；② 单测必须含"无特征→`[]`"零误报用例；③ 多 matcher 才升强识别。
- **中（实验室真实性）**：mock-WAF 是"简化 CRS"，与真实 WAF 规则有差距；e2e 差异数据仅证明"tamper 能提升检出"，不等于真实环境效果——runbook 负责真实闭环（见 P0-6）。
- **低（依赖）**：实验室用既有 Express，无新 npm 依赖；e2e 复用既有测试框架。

---

## 8. 范围与明确排除

- **不重写 WAF 识别引擎 / 推荐契约 / 前端面板**：仅扩规则与映射 + 加验证（沿用 F-20 架构）。
- **不新增 tamper 插件**：约 30 vendor 的推荐组合均可在现有 62 插件内满足（呼应 F-20 待确认 ①）。
- **不实现自动套用**：命中后仍仅推荐，需用户二次确认开启（自动套用留 P2-1）。
- **不做绕过成功率可视化报表**：e2e 产出原始对照数据即可，报表可视化留 P2-2。
- **mock-WAF 不强制对齐完整 ModSecurity CRS**：采用简化但具代表性规则（见待确认 ⑦）。

---

## 9. 待确认问题（需工程/架构拍板，已给默认决策）

| # | 问题 | 默认决策（建议） | 拍板方 |
|---|------|------------------|--------|
| ① | 最终 vendor 清单与数量：取哪约 30 个？是否严格 30 或允许浮动？ | **以附录 A 为基线（7 保留 + 23 新增 = 30）**；工程可在"可特征化"原则下微调 ±2（即 28–32）。优先覆盖 sqlmap/wafw00f 中**有响应头/状态码/body 特征**的真实产品。 | 架构 |
| ② | 各 vendor matcher 特征来源：仅复用指纹 baseline（零额外发包），还是允许"主动探测"？ | **沿用 F-20「零额外发包」**：只用响应头/状态码/body；不引入主动探测（保性能与合规）。主动探测留 P2。 | 架构 |
| ③ | 推荐组合生成策略：复用 `TAMPER_INTENSITY_PRESETS` 三档，还是每 vendor 定制？ | **通用预设为基线 + 重点 WAF 定制**（ModSecurity=`modsecurityversioned`、Imperva=`securesphere`、Citrix/NetScaler=`space2plus`、FortiWeb/Radware=`percentage`、SafeDog=`equaltolike`）；所有名须已注册。前端建议区可标注"针对性/通用"。 | 产品/架构 |
| ④ | mock-WAF 实验室形态：独立 npm script 还是并入生产 server？ | **独立轻量服务**（`e2e/waf-lab/`，`npm run waf-lab` 启动），不复用生产 server，避免污染与权限问题；背后挂 sqli-labs 风格 `/vuln?id=`。 | 工程 |
| ⑤ | e2e 对比指标口径：检出率如何定义？"被拦截导致 0 检出"如何统计？ | **检出率 = 被确认 vulnerable 的注入点数 / 总注入点数**；拦截率 = 返回 403 且未检出的点占比；固定靶机样本保证可复现。 | 工程/QA |
| ⑥ | 真实云 WAF runbook 是否随 PRD 一并产出文档？ | **本期产出 `docs/waf_runbook.md`**（用户本机执行流程），沙箱不跑该数据，仅保证文档可执行、命令准确。 | 产品 |
| ⑦ | mock-WAF 的"签名"强度：对齐真实 ModSecurity CRS 规则集，还是简化关键字黑名单？ | **默认"简化但具代表性"**：覆盖核心 SQLi 关键字/典型正则触发 403，足以验证 tamper 绕过差异；不强制对齐完整 CRS（控规则库体积与维护成本）。如需更高仿真可后续加 CRS 子集（P2）。 | 工程 |
| ⑧ | 扩库后是否需要新端点把约 30 vendor 名单暴露给前端（如"WAF 知识库"展示）？ | **默认不新增端点**：前端按 `waf_detected` 事件消费识别结果即可；若要做"WAF 知识库"展示页，留 P2（只读端点）。 | 前端/架构 |

---

> 本增量 PRD 为 WAF-v2（F-20 之上），只描述相对 F-20 的变更 + e2e 方案：#2 把 `WAF_RULES`/`WAF_RECOMMEND_MAP` 从 7 扩到约 30（对齐 sqlmap identywaf/wafw00f，推荐组合仅用 62 已注册插件名，附单测护栏）；#1 新增本地 mock-WAF 实验室（Express 复刻 CRS 类拦截 + sqli-labs 注入点）、e2e 关 vs 开对比夹具、真实云 WAF runbook。前端无需新组件（F-20 建议流自动消费更多 vendor）。现状核查已确认 F-20 已交付、62 插件齐备、识别引擎与契约可原样复用，本期纯属数据面与验证面增量。
