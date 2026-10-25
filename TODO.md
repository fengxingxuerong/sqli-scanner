# sqli-scanner 待办清单

> 生成于 2026-09-13 全面审计后。P0 四项已全部完成（见文末「已完成」），本清单按优先级维护后续优化空间。
> 原则：每项标注依赖前提与验证口径，避免「文件存在=能力存在」的误读。

---

## 2026-10-25 批次 D160 · `-r` 声明 JSON 但 body 非法时显式告警

**动机**：D159 修完 multipart 后顺手查了同一条入口的另外两路。JSON 这一路是：抓包声明
`Content-Type: application/json` 但 body 解析失败（截断/ jsonp / 多段拼接）时，
`applyBodyToArgs` **静默返回** ⇒ 0 个 body 注入点 ⇒ 扫描照常跑完、报告写「未检出」，
与「这个站没有注入」同形。属「静默假阴性」族。

**本批**：解析失败且 CT 含 json ⇒ 显式告警（前 60 字预览 + 「未检出不代表没有注入」）。
非 JSON CT 行为不变（urlencoded 启发式仍兜底）。测试 +1。

### 待推进（仍未关闭）

- 只告警、不阻止扫描。要不要升级成 exit 1（像「筛光点位即报错」那样）需要先评估：
  抓包里 CT 写错是常见误标，硬拒会让整批 `-l` 扫描中断。倾向保持告警。
- `body` 是 JSONP（`callback({...})`）时可以直接剥壳再解析 —— 目前只告警。属低优先级。

---

## 2026-10-25 批次 D159 · `-r` multipart 保真 + 文件字段 filename 注入面

**动机**：`-r` 是实战最常用的入口（Burp 抓到什么测什么）。这条路上有两层静默失效：
① `applyRequestFile` 把 multipart 目标降级成 urlencoded（理由写的是「引擎不支持发
multipart」，但 2026-09-22 起 `buildMultipartBody` 已能发）⇒ 只认 multipart 的上传接口
415/400 ⇒ 注入值从未进业务逻辑；② 文件字段的 filename 被当文本字段内容发，`filename=`
属性消失 ⇒ 「上传接口把文件名落库后再拼 SQL」这个形态从未被注入过。

**本批**：
- 解析器：文件字段单列 `fileParts`（name/filename/contentType），不混进 bodyFields。
- `-r` 接线：保留 multipart CT 与 fileParts；文本字段仍走 bodyParams。
- 发现：每个 filePart 建一个 `fileField` 注入点（注入 filename）。
- 发送：`declaredHeaderValue` 同时看 headerParams 与 auth.headers（否则 `-r` 的 CT 找不到，
  报文会变成「urlencoded 实体 + multipart 声明」）；multipart 按真实结构重建，filename
  内的 `"` 转义。
- 靶场：`e2e/detect-surface-lab` 新增 `/api/upload`（只认 multipart、filename 拼 SQL）+
  `/safe/upload`；`-r` 真值 0/1 → 1/1、安全对照 0 误报；14 用例全绿。
- 推翻链：`requestFile.importWiring.test.js` 两条旧断言（三字段全进 body / 必须丢 CT）
  按新事实改写，旧结论与原理由保留在测试注释里。

### 待推进（仍未关闭）

- **文件二进制内容不重放**：重建时报文里文件部分为空（filename 保留）。若某目标把
  「文件内容」也拼进 SQL（极罕见），本批不覆盖——真要覆盖得先定「用哪个内容注入」，
  属产品决策。
- **多文件字段 + 字段顺序**：重建顺序是「文本字段在前、文件字段在后」，与原始抓包顺序
  可能不同。FastAPI/Express 一类按名字取值的目标无影响，**按下标取值**的目标会错位——
  需要抓包保留原始 part 顺序才能修，单独一批。
- `paramMine` 仍跳过 multipart 载体（help 已注明），本批没有改它。
- REST 入口（`POST /api/scan/start`）没有 fileParts 字段：面板用户不能上传抓包文件，
  与 CLI 能力仍不对称（评估是否值得开口）。

---

## 2026-10-25 批次 D157 · 报错定库补三 Java 引擎（Derby 从「定不出」到 `定库=Derby`）

**动机**：`docs/优化底账-2026-10-18.md` P1-13（HSQLDB/Derby 定库通道失效）。真机靶场
`e2e/multi-engine-lab`（真 JDBC 内存库，NO_WAF=1）实测：Derby 三场景检出正常但
`定库=null（未识别）`——报错原文 `Syntax error: Encountered "\'" at line 1, column 31.`
里没有 "Derby"，而 `ERROR_SIG_BY_DBMS` 只认品牌词/驱动类名。H2/HSQLDB 同形态，只是靠
UNION 版本回显才定出来（盲注档同样 null）。

**本批**：
- 补三库解析器句式签名：Derby `Encountered … at line N, column M` + `ERROR 42Xxx`；
  HSQLDB `unexpected token: … in statement [...]`；H2 `Syntax error in SQL statement`。
  **裸 `unexpected token` 刻意不收**（JS `Uncaught SyntaxError: Unexpected token '<'` 会误判 HSQLDB）。
- 修 `FINGERPRINT.Derby` 误报源：去掉 `\bjava\b`（`Server: Java/1.x` 会被判成 Derby ⇒ 错方言 payload）。
- 测试 +3（三库真报错定库 / JS 报错不判 HSQLDB / 裸 Java 不判 Derby）。
- `e2e/multi-engine-lab/verify.mjs` `expectDbms`：Derby `null → 'Derby'`（正向漂移按该文件
  注释要求的流程改，README 覆盖面一栏同步）。
- 实测：`NO_WAF=1 node e2e/multi-engine-lab/verify.mjs` → `derby … 定库=Derby`、断言行全绿。

### 待推进（仍未关闭）

- 盲注档（无回显、无报错）三库仍 `定库=null` —— 报错签名救不了没有报错的场景，要另做
  时间向量/函数存在性探针（Derby 无原生 sleep，需 LIKE 重运算类方案，成本高，单独评估）。
- 同批发现的 `FINGERPRINT.H2` 裸 `H2`（`/(org\.h2|Syntax error in SQL statement|H2)/i`）
  仍靠 ±160 字符报错上下文兜底，是否收紧到句式级需一次误报语料回归（DVWA docs 页那种 `<h2>` 已剥标签，但纯文本 "H2" 仍可能命中）。
- CRS PL1 档定库仍不达（UNION 哨兵被吞，与本次无关）；把「回显被打掉时报错签名能否兜底」做成
  modsec-live 的一个新断言，可验证 WAF 下这条新通道是否还有效。

---

## 2026-10-25 批次 D156 · 外部裁判 5 号：VulnLab（W43 对标排队项落地）

**动机**：D152 对标矩阵排队项。VulnLab（[hediwen831-star/vulnlab](https://github.com/hediwen831-star/vulnlab)，
更正：初版对标文档误记仓库名 Cryshana/Micro-Bench，clone 404 实证后修正）带来前四位裁判
都没有的形态：**同一应用里的三档实现**（low 直拼 / medium 可绕黑名单 / high 参数化修复），
修复档即误报诱饵，真值来自对方 benchmark/manifest.yaml（非本仓断言，对方 CI 52 条绕过
断言守护）。

**本批**：
- `e2e/vulnlab-lab/`：runner 自拉自收（未 clone 自动 `git clone --depth 1`；Windows 共享
  php.ini 被 DVWA 锁 MySQL 形态 ⇒ `php -n -d extension=pdo_sqlite` 独立加载不改共享 ini；
  已在跑则复用）⇒ **CI ubuntu 自带 php 即可真实执行**，非环境性 SKIP。
- 验收 25 → **26 套件**（acceptance + run-all + README/AGENTS 口径同步）；防缩水判据：
  三档必须各自真跑并打印请求计数，请求 <25 或结论不可信 = 证据不足不通过。
- 实测（2026-10-25 本机）：low 3 条（union/error/boolean）· medium 1 条（error 打穿黑名单）
  · high 修复档零误报（127 请求，verdict=no_vulnerability_detected）—— 真值档 2/2 漏检 0。

### 待推进

- VulnLab 其余 12 个场景（XSS/LFI/SSRF/反序列化等）超出本仓 SQLi 定位，不做；
  若做 NoSQL/SSTI 补充趟的对照可另评估 ssti/unserialize 场景（排队，低优先）。

---

## 2026-10-25 批次 D155 · body 通道按声明的 Content-Type 判定（扁平 JSON API 不再静默 0 检出）

**动机**：`--body` 的通道判定（D… [JSON-BODY-FIX 2026-09-20]）刻意「只有真含嵌套才走
`jsonBody`，扁平一律 bodyParams(urlencoded)」—— 那条保守规则是对的（表单目标不能被
顺手改语义），但它只对「**没声明** Content-Type」成立。声明了 `application/json` 却仍按
urlencoded 发，是另一件事：只吃 JSON 的目标直接 415/400，注入值从未进业务逻辑 ⇒
扫描正常跑完、报告写「未检出」。`e2e/detect-surface-lab` 的 `/api/json`（只认 JSON）实测：
`--method POST --body '{"id":1}' --header 'Content-Type: application/json'` → **0 检出**。

**本批**：
- `resolveBodyChannel(parsed, declaredContentType?)`：声明 JSON（`application/json` /
  `text/json` / `*+json`，大小写与 charset 不敏感）且 body 是对象/数组 ⇒ 走 `jsonBody`。
- 新增 `declaredContentType(args)`：`--header` 与 `-r` 抓包 headerObj 合流读 CT，只读不改筛选。
- CLI 播报改成分因（「声明的 Content-Type 是 application/json」/「检测到嵌套 JSON」）。
- 测试 +3（声明 JSON 扁平 → jsonBody 且叶子点=id / `+json` 与 charset 变体 / 未声明与
  非 JSON 声明逐位零回归）。**既有 4 条扁平 body 用例继续守着「没声明就按 urlencoded」**。
- 靶场扩到 12 用例（新增 `json-body` 真值 + `json-body-safe` 参数化对照）。

### 待推进（仍未关闭）

- REST 入口（`POST /api/scan/start`）没有这层判定：调用方传 `bodyParams` 时仍按 urlencoded 发。
  是否要加 `contentType` 字段属于接口面变更，单独评估（REST 用户本来可以直接传 `jsonBody`）。
- `-r` 抓包里 CT 为 `application/json` 但 body 是**非法 JSON** 的场景：目前 `bodyToJsonString`
  返回 null（不回填 body），扫描会跑「无 body 点」—— 应该显式告警而不是静默，下一批处理。
- multipart 里的 file 字段（filename 注入）仍只按空值占位，未作为注入面。

---

## 2026-10-25 批次 D154 · 路径注入面扩展（多段路径中间段 + 数据后缀段）

**动机**：`--test-path` 自 2026-09-16 起只取「最后一个非空段，且含点即判静态资源」。
用真 MariaDB 建的检测面探针靶场 `e2e/detect-surface-lab/` 实测，该口径对两类真实载体
**0 检出且不报错**（与「这个站没洞」同形）：
- `/api/users/5/orders` —— REST 最常见的形态，中间的 id 永远不是点位（只测末段 `orders`）；
- `/api/item/5.json` —— `\.[a-z]+$` 把整段当静态文件跳过 ⇒ 0 个注入点。
同形态安全对照（真参数化 `?`）0 误报 ⇒ 这是漏检，不是「本来就测不到」。

**本批**：
- `TargetParser._discoverPathPoints()` + 纯函数 `classifyPathSegment()`（新口径：
  末段必测零回归 / 中间段只测含数字的数据段（精确指定仍用既有 URL `*` 标记，P3 短路优先）/
  `v\d+` 版本前缀排除 / `.json/.xml/.do/.action/.csv/.yaml/.yml` 只换前缀保留后缀 /
  静态资源与未知后缀跳过 / 每目标上限 6 点）。
- `injection.js` 路径分支按 `pathSuffix` 保留后缀（去掉后缀即 404，注入值不会进业务逻辑）。
- 测试：`headerPathPoints.test.js` 新增 7 例（多段中间段 / 纯路由段跳过 / `.json` 后缀保留 /
  静态与未知后缀 / `*` 标记 / 上限 / pathSegment 下标）。原 4 条路径用例逐条保持通过。
- 靶场：`e2e/detect-surface-lab/`（真 MariaDB，10 条用例 = 4 类载体 × 真值/安全对照 + 2 条基准），
  实测 **修复前 5/5 漏检 → 修复后 10/10 通过、0 误报**；接进 `e2e/run-all.mjs` 与
  `npm run lab:surface`。
- 钉住的既有能力（本批实测，不改代码）：矩阵参数 `;cat=` 与重复 query 键（后端取末值）
  当前**已能检出**，不是缺口 —— 一并写进靶场，防止以后回归时无人发现。

### 待推进（仍未关闭）

- 中间段的「非数字 slug」（`/product/widgets-xyz/orders`）仍不测：纯启发式会把
  `/api/v1/users` 这类路由段一起烧掉（每点约 100-300 请求）。要覆盖得先有「路由 vs 数据」
  的更强判据（如按同名段在多个 URL 里是否恒定）—— 单独一批，别混进来。
- `--crawl`/`--crawl-browser` 发现的 URL 目前只进 query/body 面，不自动扩 path 面
  （`testPath` 是全局开关，爬到的 URL 会跟着测，但没做按 URL 的预算分配）。
- 路径点的请求量随段数线性增长（最多 6 倍），`--test-path` 大扫描时建议配
  `--smart`/`--skip-static` 收敛；是否要在 `--advise` 里给出提示待评估。

---

## 2026-10-25 批次 D153 · MCP get_findings 附 nextSteps 代理建议（agentic 方向试水）

**动机**：D152 对标排队项「agentic 化」的第一步——代理最常见的错是**把报告读扁**
（inconclusive 当没洞/未验证面当测了没洞/误报未裁决就外报），把 AGENTS §2 的读错模式
翻成 `get_findings` 的机器可消费建议字段。

**本批**：
- `services/nextStepHints.js` 纯函数（7 类建议，只引用既有披露不造新结论）；MCP
  `get_findings` 附 `nextSteps`；单测 8 例 + MCP 测试扩展；README/AGENTS 同步。
- 门禁驱动重构：nextStepHints 一类一函数；tools.js 抽 `findingsPayload`
  （buildTools 265→249）；complexity 基线**重锚**两箭头键（行号漂移，值原样，diff 可审）。

### 待推进

- agentic 深水区（自主侦察→决策→复测循环）仍不做：属宿主侧策略，本仓先保持「建议字段」
  形态积累代理调用数据，等真实用法反馈再决定要不要内置循环。
- 其余照旧：nuclei 模板生态调研、外部裁判 5 号（见 D152 待推进）。

---

## 2026-10-25 批次 D152 · 竞品对标落盘 + 判红口径可配（`--fail-severities`）

**动机**：对标 2026-W43 GitHub 同类热点后，本仓已覆盖绝大多数头牌能力（逐项核实见
`docs/竞品对标-2026W43.md`）；唯一小而真实的缺口 = nuclei `-severity` 式**分级判红口径**
（退出码判红等级此前写死）。

**本批**：
- `--fail-severities <子集>`（一键扫描）：显式判红口径，普通/diff 两模式统一生效；
  不传 = 既有语义原样。单一真源 `services/diffGate.js`（`parseFailSeverities` +
  `decideDiffExit` 扩展），低于口径的新增披露不判红，`manifest.gate.failSeverities` 落盘。
- 测试 `diffGate.test.js` 9 → 16；README / CI-集成.md 第五节 / AGENTS §1.1 / help 同步。

### 待推进（对标排队项，见吸收矩阵）

- **nuclei 式模板化检测规则生态**（YAML DSL + 社区规则订阅）：✅ 调研收口（2026-10-25，
  `docs/nuclei模板生态可行性调研-2026-10-25.md`）——「payload 池外置化」最小形态已存在
  （`--payload-file`，追加式+高危门管辖+硬校验）；格式兼容与开放订阅**不做**
  （matcher 旁路会稀释差分判定的误报证据链）；分发生态以「受控配方包」形态留档，
  出现真实用户诉求再立项。
- **Vigolium 式 agentic 编排**（自主侦察→决策→复测循环）：MCP 9 工具已是代理可驱动的
  形态，自主循环属宿主侧策略；可先在 MCP 加「建议下一步」提示字段试水。
- **第三方评测基准靶场做外部裁判 5 号**（[评测基准仓库](https://github.com/hediwen831-star/vulnlab)
  ，机读 PoC + 修复对照）：✅ 已落地（D156，见顶部批次条目）。

---

## 2026-10-24 批次 D151 · workflow 门禁再补一条：顶层 permissions 必填（最小权限进代码）

**本批**：
- 判据：每个 workflow 必须显式写顶层 `permissions:`（对象 / `read-all` / `write-all`），形态非法也报。
  理由：不声明时 token 权限取决于仓库设置 ⇒ 权限不由代码决定、无法评审。
- **当场抓到**：`ci.yml` 15 个 job 都没有顶层 permissions ⇒ 补 `permissions: contents: read`
  （checkout / upload-artifact / audit 够用；`docker-publish`(packages: write) 与
  `release`(contents: write) 的 job 级声明保持不变）。`codeql.yml` 本就声明了。
- 测试 5 条（新增缺 permissions / 形态非法 2 例）；facts 因测试文件内容变化重采（数字不变）。

### 待推进（仍未关闭）

- permissions 只判「有声明 + 形态合法」，**不判最小化程度**（哪个 job 其实不需要那项权限）——
  真要判需要按 job 逐个核对用到的 API，属人工评审范畴；目前的护栏是「默认最小 + 提权必须写在 job 上」。
- 三个新 job（`desktop-package` / `docker-publish` / `codeql`）仍无首跑记录；结构已静态守住。

---

## 2026-10-24 批次 D150 · workflow 门禁补两条（timeout 必填 / 硬编码凭据）

**动机**：D149 立了 workflow 结构判据；本批补「成本」与「凭据」两类同样只能出事后才知道的判据。

**本批**：
- `timeout-minutes` 必填：不写默认上限 **360 分钟**。判据上线**当场抓到 9 个 job 缺超时**
  （lint / test-frontend / test-server / test-matrix / tamper-waf-matrix / docker /
  docker-publish / release / audit）⇒ 已补齐 45/25/30/45/20/20/20/20/15（2–3× 余量，不卡紧）。
  另判非法值（0 / >360）。
- 硬编码凭据扫描（ghp_ / github_pat_ / AKIA / sk- / 私钥块），`${{ secrets.X }}` 表达式不算（反向护栏）。
- 测试 4 → 5 条；facts 重采（前端 575/67、服务端 3749、徽章 4320）。

### 待推进（仍未关闭）

- timeout 取值是**估算**（参照既有 job 的超时与实测运行时），不是从 CI 历史分布算出来的；
  首次 push 后可按真实耗时收紧（判据本身会守「必须写」这条）。
- 仍只判结构：job 的业务语义（该跑什么、跑多久算合格）由各自门禁守；CI 的**运行**结果
  仍需一次 push/tag 才能验证（`desktop-package` / `docker-publish` / `codeql` 无首跑记录）。

---

## 2026-10-24 批次 D149 · workflow 结构门禁（新增守卫 + 条件性版本豁免）

**动机**：4 个 workflow 的结构错误只有 GitHub 才知道（push 才红，本地无从验证）；结构却是静态可判的。

**本批**：
- `scripts/lib/workflowLint.mjs`：`runs-on` 缺失 / `needs` 断链 / 空 `steps` / 空步骤 /
  `uses`+`run` 同写 / 未钉版本 action / 可复用 job 误写 `runs-on` / 没有 `jobs`。
- `server/tests/ciWorkflows.guard.test.js`：8 条规则各有反例自证 + 仓库全部 workflow 0 问题 +
  收集非空 + 「YAML 重复 job 名必须解析失败」。守卫自动进 wiring 收集（67 → **68**）。
- **判据抓到真事**：`dtolnay/rust-toolchain@master` 未钉版本（CI 注释里论证过的有意选择）
  ⇒ 做成**条件性豁免**：允许不钉，但必须同时给 `with.toolchain`，缺了就报。

### 待推进（仍未关闭）

- 只判**结构**，不判业务语义（哪个 job 该跑什么由各自门禁守）；workflow 的**运行**仍只能在
  push/tag 后由 GitHub 验证（`desktop-package` / `docker-publish` / codeql 三个 job 尚无首跑记录）。
- 若将来加多文件 workflow，`workflowLint` 的规则可直接复用（已按「吃已解析对象」设计，可合成样本单测）。

---

## 2026-10-24 批次 D148 · 验收前置靶场体检（`--labs-only` / `--require-labs=`，判据与 labs.mjs 同源）

**动机**：`labs.mjs` 解决了「靶场没起没人告诉你」，但**验收自己**仍只会把没起的靶场摊成 SKIP/BLOCKED。

**本批**：
- `scripts/lib/labs.mjs` 新增 `judgeLabs(rows, required)` 纯函数（只认「正在监听」，
  「可拉起但没起」也算没达标）；`labs.mjs --require=` 改为复用同一份判据（删掉内联的同口径过滤）；
  `labs --selftest` 8 → **11 条**。
- `e2e/acceptance.mjs`：`--labs-only`（只体检后退出）、`--require-labs=ids`（硬要求，开跑前 exit 2
  并给出 `--up` 处置）、默认只在有靶场没起时多打一行提示。
- README 验收段补两个入口的用法。

### 待推进（仍未关闭）

- CI 侧仍跑不到这些外部靶场（无 MySQL/PHP/Java 靶场 provision），因此 `--require-labs` 目前只在
  本机/自建 CI 有意义；若要进 GitHub Actions，需要先给 job 起靶场（或把外部裁判整套跑在容器里）。
- `--up` 的从零拉起已在 D147 实测（4 个靶场）；MariaDB 首次冷启路径仍未在空机验证。
- 其余照旧：`desktop-package` / `docker-publish` job 首跑、云 WAF 样本、远端推送。

---

## 2026-10-24 批次 D146 · 发布链与社区工程（tag → Release / ghcr / SBOM / 自动化）

**动机**：D145 之后代码可交付，但“外部能不能拿到”仍是最大缺口：远端 release 零资产、
Docker 只构建不推送、无依赖机器人/CodeQL、无 issue/PR 模板、英文资料只有摘要。

**本批**：
- `ci.yml` 新增三个 tag 触发 job：
  - `docker-publish`：推 `ghcr.io/<repo>:vX.Y.Z` / `X.Y.Z` / `latest`，带 provenance + SBOM
    （**仅 linux/amd64**：arm64 未验证，不做多架构假声明）。
  - `release`：下载 `desktop-package` 产物，生成 CycloneDX SBOM（前端/引擎）与
    `SHA256SUMS.txt`，创建/更新 GitHub Release 并上传全部资产。
  - 复用既有 `desktop-package` 构建，不重复跑 Tauri。
- `.github/dependabot.yml`：npm（根 + server）、cargo、github-actions 每周。
- `.github/workflows/codeql.yml`：JS/TS 静态分析（push / PR / 每周）。
- 社区模板：issue（bug/feature）、PR 模板、`CODE_OF_CONDUCT.md`。
- 文档：`docs/en/quickstart.md`（英文安装 / CLI / CI / REST / MCP / Docker / 边界）、
  `docs/release-process.md`（升版本、验收、tag、CI 产物、回滚）。

**验证**：工作流 YAML 可解析；`ref-integrity` 全绿（新增引用均指向已入库路径）；
`gate:close` 27/27。

**未做**：实际打 tag / 推送 / 创建 Release（需显式授权）；Docker arm64；Windows 代码签名 /
macOS notarization；Action Marketplace 上架。

---

## 2026-10-24 批次 D145 · 交付阻断修复（D144 收口 + 门禁/沙箱/i18n/审计）

**动机**：2026-10-24 全方面交付评估实测出的红项（不是新增能力）：D144 工作树 lint/deadcode 红；
已提交的 HEAD 被 CI lint 的 greenguard 判红而 `gate:close` 看不见；MySQL 沙箱在「已初始化未 provision」
的 datadir 上必然超时并泄漏 3308（run-all 12/12 级联失败）；首页缺 `home.recentScansDesc`；
server 运行时依赖 4 high / 1 moderate（README 的 0 漏洞徽章已失真）。

**本批**：
- **D144 收口**：移除 `scripts/labs.mjs` 未使用导入；`planLab` 收为模块内函数；Windows 下 `.cmd`
  经 shell 启动（Node 24 直接 spawn 会 EINVAL）；benchmark-app 启动等待 45s → 180s（实测 ~80s）。
- **greenguard**：识别委托给 `failWith()` 的非零退出路径（D143 的 build-portable 因此被误判 only-exit-0）；
  自证从 1 条扩到 3 条（纯 exit(0) 仍检出 / 正常与委托不误报）；接入 `gate:close`（25 → **27 项**）
  与 AGENTS §3（并记为「已漏七次」的第七次）。
- **MySQL 沙箱**：新增「初始 datadir（root 无密码 + datadir 属本沙箱）」身份判据 —— 原判据只认
  sandbox 账号，而账号在启动成功后才 provision，导致 `--init` 在自己的 `do_start` 处必然超时；
  启动等待 45s → 120s（`SANDBOX_START_TIMEOUT` 可覆盖）；超时必收尸；
  `--stop` 改用 PowerShell 命令行定位（`tasklist /V` 不含命令行，原来永远 0 命中）。
  自证 4 → 7 条（新增 E 初始 datadir / F 复用初始 / G 超时收尸）。
- **UI**：补 `home.recentScansDesc`（zh/en）+ `src/tests/i18n.keys.test.ts` 守卫（全量 638 个 `t()` 键）。
- **依赖**：`npm audit fix` + `overrides: @azure/msal-node@^7.1.1`。上游 `@azure/identity@4.14.0`
  仍锁 `msal ^6` 且无兼容修复版；override 后 server audit 0，`require('mssql')` 正常。
  **边界**：mssql 的 AAD 交互式授权路径无 Azure 环境可测（服务端凭据流不受该公告影响）。

**验证**：`gate:close` 27/27；server 3744（3740 pass / 0 fail / 4 skip）；frontend 575/575；
`npm audit --audit-level=high` = 0；sandbox `real-mysql-lab` 11/11（启动 3.7s，退出后 3308 释放）；
`labs --up=benchmark-app` + `benchmark-db` → `https://127.0.0.1:8443/benchmark/` = 200。

**未做**：远端推送（本轮只做本地提交；origin 与本地历史分叉，推送需单独确认）。

---

## 2026-10-23 批次 D144 · 靶场体检/拉起脚本化（`labs.mjs`）+ 判据进收口清单（24 → 25 项）

**动机**：25/25 依赖 6 个外部服务，起法此前只在 TODO 散文里、路径本机硬编码；而没起的靶场在验收里
**只表现为 SKIP/BLOCKED**（假绿温床）。

**本批**：
- `scripts/labs.mjs` + `scripts/lib/labs.mjs`：`--check`（体检，`--require=ids` 变硬要求）、
  `--up[=ids]`（拉起，pid 记 `.box-agent-scratch/labs-pids.json`）、`--stop`（只停自己起的）、
  `--list`（配方 + 可覆盖的环境变量）、`--selftest`（纯判据 8 条）。
- npm scripts：`labs:check` / `labs:up` / `labs:stop` / `labs:list`；README 验收段补用法。
- 修 `readOpt` 只认 `--flag value` 导致 `--require=nope` 被**静默跳过**的问题（实测反例暴露）；
  补 `hasFlag`（含「`--u` 不等于 `--up`」前缀护栏），自证 +3 条。
- `labs:selftest` 接入 `gate:close`（24 → 25 项）、`must` 名单与 AGENTS §3。

### 待推进（仍未关闭）

- `--up` 只实测过「已在跑 ⇒ 不重复拉起」这条路径；**从零拉起整链**（尤其 Benchmark 的
  `cargo:run` 与 MariaDB 首次启动）本轮未在空机上验证 —— 换机器时按 `--list` 配方核对。
- 靶场是长驻手工态（本机当前 8 项全 ✅）；CI 跑不到这些外部靶场，靠 acceptance 的 SKIP 如实披露。
- 其余照旧：`desktop-package` job 首跑、Docker 镜像、云 WAF 样本、远端推送。

---

## 2026-10-23 批次 D143 · 交付件判据收敛到单源 + 自证进收口清单（22 → 24 项）

**触发**：D142 之后 `duplication` 由 3272 涨到 3274（超基线）、`deadcode` 抓到 1 个新导出 —— 两个红都是真问题，
不是噪声（判据两份实现、跨模块不可见的导出）。

**本批**：
- 新增 `scripts/lib/portable.mjs`：Tauri 命名约定 / manifest / 探活 / 选项解析 / 失败与跳过 /
  自证 harness + 两组自证用例，**收敛为单一来源**；`build-sidecar` 的 D128 版本冒烟改用同一个探活
  （此前探活有三份实现）。
- 两个便携包脚本补 `--selftest`（11 + 7 条判据），并接进 `gate:close`（22 → **24 项**）、
  `must` 名单与 AGENTS §3 手写清单。
- `targetTriple` 去掉 export（只有本模块用）；`deadcode` 回到基线 166/166。

### 待推进（仍未关闭）

- `desktop-package` CI job 首跑仍需一次 tag/手动 dispatch（有网环境）。
- 便携包链路在收口清单里只跑 **selftest**；真冒烟（要壳 + sidecar 产物）由 `package:portable`
  与 CI job 承担 —— 若将来想让本机清单也覆盖真冒烟，需要把「壳 release 构建 2m15s」的耗时纳入权衡。
- 其余照旧：Docker 镜像、云 WAF 样本、远端推送。

---

## 2026-10-23 批次 D142 · 便携包组装/冒烟固化为脚本 + CI 桌面交付件 job

**本批**：
- `scripts/build-portable.mjs`（离线）：校验壳/sidecar 产物 → 按 Tauri 约定落成 `sqli-engine[.exe]`
  → 带 README/LICENSE + `manifest.json`（逐文件 sha256）→ 打 zip；任一步失败**非零退出**。
- `scripts/portable-smoke.mjs`：**干净解压**后启动，断言壳拉起 sidecar + 版本一致 +
  `authEnabled=true`，再清理进程与临时目录；非 Windows 输出 `[SKIP]`（不计通过）。
- npm scripts：`dist:portable` / `dist:portable:smoke` / `package:portable`。
- CI 新 job **`desktop-package`**（windows-latest，**仅 tag/手动**）：构建前端 + sidecar →
  `npx tauri build --bundles nsis`（有网 ⇒ 产出官方安装包）→ 组装便携包 → 冒烟 → 上传产物。
- 判据有牙（本地实测）：sidecar 故意不改名 → 冒烟 exit 1 且报出命名约定；正常包 → exit 0、0 残留。

### 待推进（仍未关闭）

- **CI 的 `desktop-package` job 尚未真跑过**（首次会在下一次打 tag 或手动 dispatch 时验证；
  本地无网跑不了 NSIS）。若它红了，先看两处：`build:sidecar` 在 windows runner 上的 SEA 冒烟、
  以及 `tauri build` 的 NSIS 工具链下载。
- `dist-portable/` 已进 .gitignore（内含 92 MB sidecar）；交付件由 CI artifact 或仓库外目录承载。
- Docker 镜像（本机无 docker；CI 的 docker job 覆盖）、真实商业云 WAF 授权样本、远端推送。

---

## 2026-10-23 批次 D141 · 免安装便携包（portable zip）+ 干净解压冒烟

**背景**：官方安装包需联网下载 NSIS，本机不通 ⇒ 产一个**离线可交付**的绿色包，且**干净解压后冒烟**。

**做法与产物**（仓库外，不入库）：
```powershell
$dst='D:\projects\sqli-v1.2.0-portable-win-x64'
Copy-Item <repo>\src-tauri\target\release\sqli-scanner.exe            "$dst\sqli-scanner.exe"
Copy-Item <repo>\src-tauri\binaries\sqli-engine-<triple>.exe          "$dst\sqli-engine.exe"   # 改名，壳按此名找
Compress-Archive "$dst\*" "$dst.zip"        # 38.7 MB（解压后 105.7 MB）
```
**冒烟**：解压到临时目录 → 启动 → 壳拉起 sidecar → `/api/health` = `1.2.0`
（`versionSource=env:ENGINE_VERSION`、`authEnabled=true`）→ 退出无残留。

### 待推进（仍未关闭）

- **NSIS/WiX 官方安装包**：需能联网的环境跑 `npm run package:win`（本机 `%LOCALAPPDATA%\tauri`
  为空、github.com 不可达）。
- Docker 镜像（本机无 docker/podman）、真实商业云 WAF 授权样本、`v1.2.0` 推送。
- 便携包目前是「手工组装」；若要进 CI，需把组装与干净解压冒烟固化成脚本 + job
  （本批因产物放仓库外、且无安装包链路，先手工留证）。

---

## 2026-10-23 批次 D140 · Cargo.lock 纳入版本互校（8 处 → 9 处）

**背景**：D139 跑完 `tauri build` 后 `Cargo.lock` 冒出一处改动——本仓包版本从 `1.1.1` 被
cargo 改写成 `1.2.0`。即 D127 的 8 处互校**漏了这份副本**，不真跑 cargo 就永远发现不了
（同一形状第三次复现：同一事实多份副本、缺一道互校）。

**本批**：`version-sync` 增加 `src-tauri/Cargo.lock（本仓包）` 判据（只认 `name = "sqli-scanner"`
之后的 version）+ 一例 selftest；目标数 8 → 9。判据：`version:check` 9/9 一致、selftest 6/6、
`gate:close` 22/22。

### 待推进（仍未关闭）

- 版本号互校仍**不覆盖文档里手写的版本号**（CHANGELOG/README 的历史段落刻意保留旧数字，
  不算漂移）；若将来要给「文档当前版本」立判据，需先定义哪些段落属于「当前」。
- D139 的其余待推进照旧：NSIS 安装包、Docker 镜像、云 WAF 样本、远端推送、靶场重拉配方。

---

## 2026-10-23 批次 D139 · 桌面壳 release 构建 + 真机冒烟 + MCP 手测

**背景**：评估里「桌面端零验证」「MCP 真机未验」两块一直挂着。本批补上（**代码未改动**）。

**本批实测**：
```powershell
# 壳 release 构建（不打包 installer）
npx tauri build --no-bundle        # Finished release profile in 2m15s → src-tauri\target\release\sqli-scanner.exe（12.9 MB）
# 真机冒烟：壳 → sidecar → 引擎
Start-Process src-tauri\target\release\sqli-scanner.exe
#   壳自动拉起 sqli-engine 子进程，引擎监听 127.0.0.1:4567
curl http://127.0.0.1:4567/api/health
#   → {"version":"1.2.0","versionSource":"env:ENGINE_VERSION","authEnabled":true,"exploitEnabled":false,...}
# MCP stdio 手测
'{"jsonrpc":"2.0","id":1,"method":"initialize",...}' | node server/bin/cli.js mcp
#   → protocolVersion 2024-11-05 · serverInfo.version 1.2.0 · 9 个工具
```

**真机确认的三件事**：① 壳能拉起/管理 sidecar；② D128 的第二道保险（Rust 注入
`ENGINE_VERSION`）在真实链路上生效（`versionSource=env:ENGINE_VERSION`）；③ 壳注入的一次性
token 生效（`authEnabled:true`，public 的 `/api/health` 仍可读）。冒烟后进程已清理。

### 待推进（仍未关闭）

- **NSIS 安装包未产出**：本机无 tauri 打包缓存（`%LOCALAPPDATA%\tauri` 不存在），NSIS 工具链要联网
  下载而 github.com 不可达 ⇒ 只到 `sqli-scanner.exe`（12.9 MB）。有网环境跑
  `npm run package:win` 即可产出安装包。
- **Docker 镜像**未构建（本机无 Docker）。
- **真实商业云 WAF 授权样本**（台账唯一 unverified 条目）。
- **`v1.2.0` 推送**（本机到 github.com:443 不通；bundle 已备）。
- 本机靶场是临时进程，重启后需按 D134–D138 的配方重新拉起（MariaDB 3306、DVWA 8099、
  VAmPI 5000/5001、Juice 3199 用 Node 22、Benchmark 9001+8443；3308 遗留沙箱 mysqld 待清）。

---

## 2026-10-23 批次 D138 · 本机起 OWASP Benchmark → 全量验收 25/25 全绿（0 FAIL / 0 SKIP）

**背景**：D137 后只剩 Benchmark 一个 SKIP。本轮发现本机已有它的源码与构建产物
（`.box-agent-scratch/BenchmarkJava-master`、`benchmark-db`；JDK17 在 `D:\tools\jdk`，
Maven 3.9.11 在 `D:\tools\maven`，`~/.m2` 里 hsqldb 2.7.4 与 cargo 的 Tomcat 都已缓存），
**不需要连 GitHub**。

**复现（照抄）**：
```powershell
$java='D:\tools\jdk\jdk-17.0.2\bin\java.exe'
$hsql="$env:USERPROFILE\.m2\repository\org\hsqldb\hsqldb\2.7.4\hsqldb-2.7.4.jar"
$bj='<repo>\.box-agent-scratch\BenchmarkJava-master'
& $java -cp $hsql org.hsqldb.Server --database.0 "file:$bj/target/db/benchmark.db" `
  --dbname.0 benchmarkDataBase --port 9001            # 必须常驻（antrun 的 fork 会被回收）
$env:JAVA_HOME='D:\tools\jdk\jdk-17.0.2'
cd $bj; mvn cargo:run -Pdeploy -Dspotless.apply.skip=true      # https/8443 自签
$env:BENCHMARK_BASE='https://127.0.0.1:8443/benchmark'
node e2e/acceptance.mjs --only=benchmark              # 或三清单全跑：BENCHMARK_CASES=.../cases-query.json
```

**结果**：基线 43/43 + 0/24、query 111/111 + 0/99、header 33/33 + 0/34 ⇒ **187/187、0/157**；
全量 acceptance **25 PASS / 0 BLOCKED / 0 FAIL / 0 SKIP（exit 0）**。

### 待推进（仍未关闭）

- **仓库外才能验的三件事**：真实商业云 WAF 授权样本、Docker 镜像与桌面打包、`v1.2.0` 推送
  （本机到 github.com:443 不通）。
- 本机依赖一旦重启需重新起靶场：MariaDB 3306、DVWA 8099、VAmPI 5000/5001、
  Juice Shop 3199（**Node 22**）、Benchmark 9001 + 8443；3308 有一份遗留沙箱 mysqld 待清。

---

## 2026-10-23 批次 D137 · 推翻「Juice Shop 本机不可复现」（24 PASS / 0 FAIL / 1 SKIP）

**背景**：README/TODO/`docs/verification-2026-10-22-full-sweep.md` 都写着 Juice Shop
「本机不可复现（需完整 Angular 构建，无法只部署 API 层），4 轮尝试失败」。本轮把它跑起来了，
**旧结论按 §3.5 作废**（台账 `juice-shop-runnable-local-d137`）。

**三个真实根因**：
1. 解压出的源码树**缺整个 `data/`**（partial 解压）——重解压 `juice.tar.gz` 恢复 228 条；
2. 前端依赖必须**扁平**装：`npm install` 崩 `null.matches`；`pnpm`（strict）报
   `Cannot find module '@codemirror/state'`；`npx pnpm@9 install --shamefully-hoist` + `ng build` 通过；
3. 必须跑 **Node 22**：Node 24 在 Windows 下扫搜索路由触发 libuv `fs-event.c:72` 断言，
   **进程当场崩**（裁判侧只见 ECONNREFUSED）；引擎的 validity-guard 正确判为「结论不可信」。

**复现（照抄）**：
```powershell
cd $env:TEMP\verify-labs; tar -xzf juice.tar.gz              # 恢复 data/
cd juice-shop-20.3.0\frontend
npx --yes pnpm@9 install --shamefully-hoist --no-frozen-lockfile
npx ng build --configuration production                     # 约 42s
cd ..; node_modules\.bin\tsc.cmd --ignoreDeprecations 6.0    # 根目录编译 build/
$env:PORT='3199'; <node22>\node.exe build/app                # Node 22，不要用 24
JUICE_BASE=http://127.0.0.1:3199 node e2e/acceptance.mjs --only=juice-shop
```

**结果**：Juice **2/2 真值、0/4 误报**；全量 **24 PASS / 0 BLOCKED / 0 FAIL / 1 SKIP（exit 0）**。

### 待推进（仍未关闭）

- 唯一 SKIP：**OWASP Benchmark** 未在本机起靶场（需 JDK+Maven+cargo，且源码要从 github.com 拉，
  本机到 github.com:443 不通）；单独复跑证据仍是 178/178、0/149。
- 真实商业云 WAF 样本；Docker 镜像与桌面打包；`v1.2.0` 推送。

---

## 2026-10-23 批次 D136 · 本机再补 VAmPI 裁判（23 PASS / 0 FAIL / 2 SKIP）

**本批**：外部裁判 2 号 VAmPI 在本机起真靶场（上游源码 + 现成 venv）。
两处踩坑写进配方，避免下次重复：

```powershell
$venv = "$env:TEMP\verify-labs\vampi-venv\Scripts\python.exe"; $src = "$env:TEMP\verify-labs\VAmPI-master"
$env:tokentimetolive='7200'      # 官方默认 60s ⇒ 整轮扫描中途全 401 ⇒ 真假恒等（假阴性）
Start-Process $venv -ArgumentList 'app.py' -WorkingDirectory $src -PassThru -NoNewWindow   # 5000 漏洞实例
Invoke-WebRequest 'http://127.0.0.1:5000/createdb'                                          # 建库灌种子
$env:PYTHONPATH=$src; $env:PORT='5001'; $env:vulnerable='0'
Start-Process $venv -ArgumentList 'D:\projects\sqli-scanner\e2e\vampi-lab\run_port.py' `
  -WorkingDirectory $src -PassThru -NoNewWindow   # 5001 参数化对照（cwd 与 PYTHONPATH 都要给源码目录）
```

**结果**：VAmPI **2/2 真值、0/5 误报、证据不足 0、Bearer 5 端点未测 0**；
全量 **23 PASS / 0 BLOCKED / 0 FAIL / 2 SKIP（exit 0）**。

### 待推进（仍未关闭）

- ~~2 个 SKIP：**Juice Shop**（需完整 Angular 构建产物，本机 4 轮未起）、
  **OWASP Benchmark**（需 JDK17 + Maven + cargo + HSQLDB）~~：**D137 已推翻 Juice Shop 那条**
  （本机真跑通、2/2 检出，真因是源码树缺 `data/` + 前端依赖需扁平装 + 必须跑 Node 22）；
  仍剩 Benchmark 一个 SKIP（其单独复跑证据已有 178/178、0/149）。
- 真实商业云 WAF 样本；Docker 镜像与桌面打包；`v1.2.0` 推送（需能出网的环境）。

---

## 2026-10-23 批次 D135 · 本机补齐 DVWA 裁判与数据泄露实证（22 PASS / 0 FAIL / 3 SKIP）

**背景**：D134 后只剩「外部裁判未起 + 数据泄露实证环境不满足」这类 SKIP。本批把本机**能起的起起来**：
真 DVWA（PHP 8.3 + 宿主 MariaDB 10.11）→ 外部裁判 3 号 + 数据泄露实证两条同时转绿。

**本机复现配方（下次直接照抄）**：
```powershell
# 1) 宿主 MariaDB（该 datadir 里已有 dvwa / sqli_lab / redteam_lab / param*-lab 等靶场库）
D:\tools\mariadb\mariadb-10.11.19-winx64\bin\mariadbd.exe --defaults-file=D:\tools\mariadb\data\my.ini `
  --port=3306 --secure-file-priv=D:/tools/mariadb/files --console
# 2) DVWA（config.inc.php 从 .dist 拷贝；env 驱动，关鉴权、默认 low）
$env:DISABLE_AUTHENTICATION='true'; $env:DEFAULT_SECURITY_LEVEL='low'
$env:DB_SERVER='127.0.0.1'; $env:DB_PORT='3306'; $env:DB_DATABASE='dvwa'; $env:DB_USER='root'; $env:DB_PASSWORD='root'
D:\tools\php83\php.exe -S 127.0.0.1:8099 -t <DVWA-master>
# 3) 验收
$env:MYSQL_HOST='127.0.0.1'; $env:MYSQL_PORT='3306'; $env:MYSQL_USER='root'; $env:MYSQL_PASSWORD='root'
$env:MYSQL_DATABASE='sqli_lab'; $env:WAF_GATE_PL='1'; $env:DVWA_BASE='http://127.0.0.1:8099'
node e2e/acceptance.mjs
```

**结果**：外部裁判 3 号 DVWA **5/5、0 误报、0 证据不足**（四形态）；数据泄露实证**成立**
（真库名 9 个、139 请求、3 条漏洞）；全量 **22 PASS / 0 BLOCKED / 0 FAIL / 3 SKIP（exit 0）**。

### 待推进（仍未关闭）

- 3 个 SKIP：Juice Shop / VAmPI / OWASP Benchmark 未在本机起靶场（VAmPI 有现成 venv 与源码，
  Juice 有已构建产物，Benchmark 需 JDK+Maven+cargo —— 属「起靶场」工作量，非能力缺口）。
- 真实商业云 WAF 样本；Docker 镜像与桌面打包；`v1.2.0` 推送（需能出网的环境）。

---

## 2026-10-23 批次 D134 · 环境路径/依赖不再伪装成能力退化（fileops 目录判定 + 红队 BLOCKED）

**背景**：本轮把全量 acceptance 在本机真跑起来（宿主 MariaDB 10.11 + 真 MySQL 8.0.28 沙箱），
最好结果 **20 PASS / 0 BLOCKED / 0 FAIL / 5 SKIP**。过程中抓到两个把环境记成能力的真缺陷——
与 D126「缺表被写成漏检」同形，按同一纪律修。

**本批**：
- `e2e/lib/fileopsPaths.mjs`（+5 例自证）：按 MySQL 语义解析可用目录（NULL 禁用 / '' 不限制 /
  '/dir/' 限定必须用它），优先级 显式 env > 实例自报 `@@secure_file_priv` > tmpdir 兜底。
- `e2e/fileops/exploit-{file-read,file-write}.e2e.mjs`：接入上述判定并**把目标路径打在 pre 行**。
  实测宿主限定目录下：fileWrite `{wrote:true,verified:true,via:"union"}`、fileRead 回读一致，
  `方式=宿主实例`（不再依赖沙箱重试）。
- `e2e/udf-lab/mysql_sandbox.py`：stdout/stderr 切 UTF-8 + replace，修掉 GBK 控制台下 `⚠`
  触发的 UnicodeEncodeError（它会把「沙箱重试」整条自愈链路崩成 BLOCKED）。
- `e2e/lib/redteamVerdict.mjs`（+8 例自证）+ `e2e/redteam-lab/env.mjs` + `acceptance.withRedteamLab`：
  靶场库不可用 ⇒ `[BLOCKED]` 显形（不再记成 0/19 检出率 0%）；env 输出改为捕获（原 `stdio:'ignore'`）。

### 待推进（仍未关闭）

- 数据泄露实证（extract-proof）仍需 DVWA @8099 起靶场；本轮未跑。
- 真实商业云 WAF 样本、OOB 真机（缺 PG）、Docker 镜像与桌面打包：同上。
- 沙箱实例 3308 有一份**上一会话遗留的 mysqld**（身份探测不认，`--start` 会拒绝复用并提示
  `--stop/--destroy`）；换机器或复跑沙箱套件前先清掉。
- `v1.2.0` 仍只在本机；推送需能出网的环境。

---

## 2026-10-23 批次 D133 · v1.2.0 发布复验（四项旧未决销账 + 全量验收 + 外部裁判）

**背景**：v1.2.0 tag 已在本地，但发布证据还停在 1.1.x/D121–D124；README 的
16 PASS / 6 FAIL / 3 SKIP 快照里还有 4 项能力级未决。本批在真 MySQL 8.0.28/10.11 上复跑，
把「未验证」从「发布阻断」降为「已补证/仍属环境边界」。

**本批实测**：
- 报告契约：`python e2e/run-with-sandbox.py e2e/contract/report-contract.e2e.mjs --drop-dir`
  → **8/8**，显式 UNION 点 union 通道检出（旧 FAIL 作废）。
- CRS PL1：`acceptance --only=waf-real,waf-auto` → **off=8/on=8、auto=8、误报 0**（旧 4/8 作废）。
- fileRead/fileWrite：MySQL 8.0.28 沙箱（`secure_file_priv` 限定目录）→ **均 PASS**；
  fileWrite `{wrote:true,verified:true,via:"union"}`，文件系统侧含标记。
- 全量 acceptance：**17 PASS / 0 FAIL / 8 SKIP**（8 SKIP 中外部 4 + fileRead/fileWrite 已单独补跑；
  OOB 真机缺 PG、数据泄露实证环境不满足仍未验证）。
- 外部裁判 v1.2.0：Juice 2/2、VAmPI 2/2+0/5、DVGA 1/1、DVWA 5/5、Benchmark 178/178+0/149
  ⇒ **187/187、0 误报**；证据 `e2e/results/external-sweep-2026-10-23-v1.2.0.md`。

### 待推进（仍未关闭）

- OOB 真机（PG COPY TO PROGRAM）与数据泄露实证：环境不满足，未验证。
- 真实商业云 WAF 样本仍缺；CRS 8/8 是仓库内执行器口径，不是云 WAF 绕过率。
- Benchmark 占 187 里的 178；`{call <过程名>}` 4 条真值未检出（已知边界）。
- Docker 镜像未构建/冒烟（本机无 Docker）；桌面打包未在本轮验证。
- `v1.2.0` 目前只在本机；推送/远端 tag 需单独授权（GitHub 443 曾不可达）。
- vitest 3→5 升级仍按独立批次处理（覆盖率口径需重定，不混进发布批）。

---

## 2026-10-23 批次 D127–D132 · 发布收尾

**背景**：`docs/release-readiness-2026-10-23.md` 逐项实测出 6 项 P0 + 5 项 P1；
本批把能从代码侧修的全部修掉，剩下的（依赖外部 MySQL/CRS 环境的）如实留在下面「待推进」。

**本批**：
- D127 提交 D125/D126 未提交工作（含未跟踪实现）→ version-sync 判据 3 处 → **8 处**
  （server/package.json + 两个 lock 的顶层与 `packages[""]`）→ 1.1.1 → **1.2.0**；
  台账两条失效 `refute_cmd` 修正。
- D128 sidecar 版本戳（SEA asset 内嵌 package.json + 解耦解析器 + 冒烟断言；
  Rust 侧 `ENGINE_VERSION` 第二道保险）；顺带修 build-sidecar 的 CJS bundle 新鲜度判据
  （只看目录 mtime ⇒ 会复用旧 bundle）。
- D129 `release-check` 在 CI 真跑（原来只跑 selftest）；greenguard / gate-recorder /
  coverage-calibration / readme-flag-coverage selftest 接线进 CI；`npx eslint` → `npm run lint`。
- D130 README 竞品表按 D102 重判（14/19、0/7）、Benchmark 按 D115/D117（178/178、0/149）、
  删 09-20 历史快照改 25 套件实测表、en README 17→25、AGENTS 口径同步。
- D131 fileWrite `wrote` 只由回读验证置位（新增 attempted/unverified）。
- D132 `sideEffectLedger` scanId 校验 + 浏览器出站闸门 + `npm audit fix`（server 0 漏洞）
  + CLI `-V/--version` + SECURITY.md 依赖状态与浏览器例外如实登记。

### 待推进

- ~~**CRS PL1 4/8 vs 基线 8/8**~~：2026-10-23 复跑 **off=8/on=8、auto=8、误报 0**
  （`acceptance --only=waf-real,waf-auto`，真 MySQL 10.11）。旧 4/8 数字作废。
- ~~**显式 UNION 注入点的 union 通道漏报**~~：2026-10-23 report-contract **8/8**，
  `union 技术应被检出` 通过（沙箱 MySQL 8.0.28 + schema 自愈）。旧 FAIL 作废。
- ~~**fileWrite 真闭环**~~：2026-10-23 MySQL 8.0.28 沙箱复跑 PASS
  （`{wrote:true,verified:true,via:"union"}`，文件系统侧含标记）；fileRead 同步 PASS。
  宿主 `secure_file_priv=NULL` 时验收仍 SKIP，属环境边界而非能力缺口。
- **vitest 3 → 5 升级**：已实测尝试并**回退**（2026-10-23，证据见下），不是"没时间做"。
  - 依赖可解：`vitest@5.0.5 + @vitest/coverage-v8@5.0.5 + @types/node@^24` 安装成功，
    功能面 **574/574 全过**、根包 `npm audit` → **0 vulnerabilities**（清掉 2 critical + 2 moderate）。
  - 两个卡点：① **覆盖率口径整体下移约 8pt**（statements 93.16 → 84.73、lines 91.5 → 87.3，
    低于既有的 88/88 阈值）——这是 v5 覆盖率语义变化，不是代码退化；按本仓纪律
    「不为变绿放宽校准阈值」，需要先按新口径重测再一次性重定基线（属独立批次）。
    ② 本地单跑耗时 90s → **242s**（v5 的模块隔离/导入统计变化；CI 并行档未测）。
  - 复现：`npm i -D vitest@5.0.5 @vitest/coverage-v8@5.0.5 "@types/node@^24"` →
    `npx vitest run`（过）→ `npx vitest run --coverage`（阈值红）。
  - 下次做这件事的顺序：先升 v5 → 用新口径重测覆盖率 → **同一批**重定 `vitest.config.ts`
    阈值与 `docs/_facts.json` → 再评估 CI 耗时；不要只改阈值。
- **Docker 镜像未实测**：`.dockerignore` 已排掉 `src-tauri/`、`e2e/`、`logs/`、`reports/`
  等 GB 级目录（D132），但本机无 Docker ⇒ 镜像构建与容器内冒烟仍未跑过；CI 的 `docker`
  job 会兜这一层，首次推送后看它。
- **远端历史**：本地比 origin/master 多 50+ 提交且 `origin/master` 在本地已 gone；
  推送前需确认 force-push 策略与 tag 归属（v1.2.0 只在本地打过）。

---

## 2026-10-22 批次 D126 · 验收前置 schema 自愈

**背景**：全方面验证里 `pentest-lab` 8/11、`real-mysql-lab` 3/11，报告写成「真值漏检」。
同代码同机器 A/B 证明是**测试库缺表**（空库 1/11 与 3/11；有表 11/11 与 11/11）——
环境缺失被伪装成引擎退化，门禁红得指错方向。

**本批**：
- `e2e/lib/sqliSchema.mjs`：`probeSqliSchema` / `ensureSqliSchema` / `schemaVerdict` /
  `assertSafeDbName`（库名白名单）。
- 四处共用：`init-db.mjs`、`pentest-lab/verify.mjs`、`real-mysql-lab/verify.mjs`、
  `acceptance.mjs` MySQL 前置（自愈/失败都写进报告前置行）。
- 单测 11 例 + 缺陷注入复验；空库跑两套件 → 2 PASS / exit 0。

### 待推进

- **MySQL 8.x 方言复验**：本轮只在 MariaDB 10.11 跑通 11/11；CI 的 MySQL 8.x 未同口径复跑。
- **其他套件的隐性数据依赖**：`blackbox-lab` / `fullchain-lab` 等同样假设库里有表，
  是否要一并接 `ensureSqliSchema` 需逐个确认（它们登记为参考靶场，暂不动）。
- **fileWrite 的 `wrote` 置位条件**：本轮未改（环境侧是 `secure_file_priv` 目录不匹配；
  但「未验证落盘却置 wrote」仍应单独修，见验证报告 P0-4）。

---

## 2026-10-22 批次 D125 · 人工裁决（finding triage）

**背景**：真实渗透交付需要「人确认/误报/接受风险」的标注，而报告只有引擎命中；
顾问在外表另记一份，复扫后必然漂移。

**本批**：
- `services/findingTriage.js`：稳定指纹 + `<ledger>/triage.json` 原子存储 + `attachTriage`。
- `PATCH /api/scan/:id/findings/:findingId/triage`；报告查看/导出/MCP 统一合并。
- CSV/MD/HTML 增裁决列与汇总；SARIF `properties.triage` + 误报 external suppression。
- Web UI 裁决控件（状态下拉 + 备注 + 保存）与卡片芯片；zh/en 文案。
- 测试 6 + 3；浏览器实操确认/误报两态；typecheck/build/i18n/gate 全绿。

### 待推进

- **批量裁决**：按技术/风险/参数批量设置（当前逐条）。
- **裁决审计**：记录操作者与变更历史（当前只存最后状态 + updatedAt；多用户部署前必须补）。
- **MCP 写入**：MCP 目前只读裁决（`get_findings` 透传）；是否暴露 `set_finding_triage`
  需先定授权边界（代理不应替人做交付结论）。
- **跨实例存储**：当前单进程原子写；多副本部署需外部 KV/DB + 并发控制。

---

## 2026-10-21 批次 D124 · 覆盖范围披露（未覆盖面 + 浏览器降级进报告）

**背景**：报告写 `no_vulnerability_detected` 时，用户分不清「测了没洞」与「压根没测」。
两处事实只活在日志/配置里：① 默认 `level=1` 只测 URL query + POST body
（cookie/header/path/表单四类面从未进入检测）；② `--crawl-browser` 在 playwright/浏览器
不可用时静默降级为 HTTP 爬虫，SPA 的 XHR 接口面整体丢失——而 playwright 在
`devDependencies`，生产 `--omit=dev` 必然触发。

**本批**：
- `scan/discover.js`：`uncoveredSurfaces(config)` + `annotateSurfaceCoverage` ⇒
  `summary.uncoveredSurfaces` / `uncoveredSurfacesHint`（带开启方式，随开关收缩）。
- `TargetParser.js`：降级时记录 `target.crawlBrowserFallback` ⇒
  `summary.crawlBrowserFallback` / `crawlBrowserHint`（点明 SPA 接口面可能未发现）。
- 两字段都只在事实成立时出现；未开启/浏览器可用时不写，避免假警示。
- 测试 7/7（降级替身 2 + 未覆盖面 5，含真实 `ScanManager` 端到端）。

**外部核验**（2026-10-22）：5 裁判 187/187 无回归，新字段 8/8 场景无假阳性
（Juice/VAmPI/DVWA/DVGA + Benchmark header），acceptance 4 PASS。证据
`e2e/results/external-sweep-2026-10-22-post-d124.md`。

### 待推进

- **playwright 依赖位置**：本批只做披露；生产部署 `--omit=dev` 仍会降级。候选：
  移到 `dependencies`/`optionalDependencies`，或在启动横幅显式告警（两者可并存）。
- **真实 SPA 复现**：降级阳性路径目前由本地替身制造，未在真实 SPA 目标上复现。
- 未覆盖面清单目前是配置级静态判定；`--crawl-browser` 实际发现到的接口面未参与
  「覆盖/未覆盖」的动态核算（若后续要精确到「本次发现了多少面、测了多少面」需另立批次）。

---

## 2026-10-21 批次 D123 · 「未验证注入面」显形（P0 第一件事：WAF 场景给正式结论）

**背景（用户视角的缺口）**：问「能当真实渗透工具用吗」时，最该补的不是检出率，而是
**目标挂了 WAF 时能不能给严肃结论**。现状是：整体健康、局部注入面被吃掉 ⇒ 报告写
`no_vulnerability_detected`，不说「有 N 个面根本没送达 payload」。

**根因（实测）**：`detect.js` 的 `fullyTestedPoints.add(point.id)` **无条件执行**——403 拦截
不抛错 ⇒ 被拦的点也算「跑完」。`validity` 是整轮级、`verdict` 只在整轮不可信时翻转，
看不见中间态。

**本批**：
- 新增 `scan/unverifiedSurfaces.js`：按注入面摊开 + 生成结论句。
- `detect.js`：`blockHitsSnapshot` / `attributePointBlocks` ⇒ `point.blockedRequests`（点级归因）。
- `scanRunner.js`：`annotateUnverifiedSurfaces` / `buildVerdictNote` ⇒ 未验证面**进 verdictNote**。
- `AGENTS.md` §2 判读表补一行（代理最容易读错的第四件事）。

### 待推进（本批之后，按原顺序）

- **P0 剩余**：真实云 WAF 授权样本采集（`docs/WAF-真机样本采集-runbook.md` 已就绪，缺真实流量）。
  没有它，WAF 侧仍只能给「可解释结论」，给不出绕过率。
- **P1**：真实形态样本（SPA / 签名接口 / 网关重写 / GraphQL variables）替换 Benchmark 权重。
- **P2**：18 库分层里 DM8 / TiDB 提到真引擎验证。
- ~~**顺带**：`playwright` 在 `devDependencies`，生产部署（`--omit=dev`）时 `--crawl-browser`
  静默回落 HTTP 爬虫 —— 应在启动横幅显式告警。~~ **D124 已把降级事实写进报告**
  （`summary.crawlBrowserFallback`）；依赖位置仍未改，生产部署仍会降级 → 见 D124 待推进。
- **环境债（D123 发现）**：Node v24.18.0 / Windows 下含 HTTP 服务端的测试文件在**进程退出**
  触发 libuv 断言（`win/async.c:94`），整个文件被判 fail 而用例全过；`git archive HEAD` 隔离
  复跑同样崩溃 ⇒ 运行时缺陷，待评估 Node 版本或改用 `--test-isolation` 规避。

---

## 2026-10-21 批次 D122 · 外部靶场全量复跑（5 裁判同轮）

**背景**：D121 之后五个外部靶场的结论分散在各自旧报告里，且汇总口径**已过期**：
`external-judge-sweep-2026-10-21.md` 写「DVWA 4/4、VAmPI 安全 0/2、合计 185」，而
D113 当天给 DVWA 加了第 5 个真值点（medium 盲注 POST）、给 VAmPI 加了 3 个 Bearer
安全端点 —— 当日 d113 运行的实测结果就是 5/5（该 `.log` 按 `.gitignore` 不入库；
数字内联在 `e2e/dvwa-lab/results/external-judge-2026-10-20-dvwa.md`）。汇总没跟上，属**口径腐烂**。

**本批**（不改引擎代码，只重搭靶场 + 复跑 + 修口径）：
- 五个靶场全部在本机**从零重搭**：Juice Shop v20.3.0（含前端构建）、VAmPI 双实例、
  DVGA、DVWA（PHP 8.3 + MariaDB 10.11）、OWASP Benchmark（JDK17 + Maven + HSQLDB + cargo）。
  补齐 `e2e/vampi-lab/run_port.py`（README 引用但目录内缺文件）。
- 同轮全量复跑：**真值 187/187 可打穿、安全端点误报 0、证据不足 0**。
  其中 Benchmark 按三份清单全量跑（query 210 → 111/111 + 0/99；header 67 → 33/33 + 0/34；
  基线 74 → 43/43 + 0/24），与 D117 的 178/149 逐条吻合。
- `acceptance --only=juice-shop,vampi,dvwa,benchmark` → **4 PASS / 0 FAIL / 0 SKIP**。
- 口径修正（§3.5：保留旧数字并标注作废）：DVWA 真值 4→5、VAmPI 安全分母 2→5、
  合计真值端点 185→**187**；D121 前「只补跑 DVGA、其余沿用旧证据」的说明作废。
- 证据：`e2e/results/external-sweep-2026-10-21-full.md`（数字内联，不依赖日志）、
  `e2e/dvwa-lab/results/external-judge-2026-10-21-dvwa-rerun.md`；台账新增
  `external-judge-sweep-2026-10-21-5judges`（verified），并给 `external-judge-dvwa-d112`
  补 5/5 与复跑证据。

### 待推进

- `{call <过程名>}` 4 条真值仍未检出（已知边界，单列不计入 178）——P0 ② 仍在。
- Benchmark 仍占 187 里的 178：外部样本**严重不均衡**，别拿 187/187 说「通用检出率」。
- DVGA 要转稳定门禁，前置仍是「靶场需手动起 + 只有 1 个 GraphQL 真值端点」。

---


## 2026-10-21 批次 D121 · GraphQL 查询串内联值位注入（P0 ① 收口）

**背景**：D114 外部裁判 DVGA 真值点 `pastes(filter)` 0/1 —— 旧 JSON 叶子通道把**整个
`query` 字符串**替换成 payload，GraphQL 解析层直接 400，注入值从未进 SQL；D120 修完
表单路径后，它仍是唯一未打穿的外部真值点。

**本批**：
- 新增 `server/src/engine/graphqlInline.js`：GraphQL 查询串词法扫描（双引号字面量/
  转义/注释；block string 跳过）+ 编码与按区间替换。边界：只处理内联字面量，
  variables 走既有 JSON 叶子通道，裸 `application/graphql` 不支持。
- `TargetParser._collectGraphqlQueryLeaf`：`query` 字段像 GraphQL 时只生成
  `carrier='graphql'` 的内联字面量点（如 `query.filter`），不再回退整串点；同名字面量
  以 `param[2]` 区分；数组路径 `0.query.filter` 可用。
- `injection.buildGraphQLBodyRequest`：clone `jsonBody`，只替换目标字面量，保留查询
  骨架/其他字段；基线逐字不变。`_resolveJsonParent` 复用于 JSON 叶子路径（抽出
  `applyJsonBodyInjection`，`buildInjectionRequest` 圈复杂度 91→78）。
- `prefilter.skipStaticPoints`：GraphQL 点不参与同值去重（`field(a:"x", b:"x")` 只测
  一个会静默漏另一个），仍参与静态哨兵。
- 回归：`server/tests/graphqlInline.injection.test.js` 12 例（发现/构造/转义/多字面量/
  batch/variables/非 GraphQL `query` 零回归/区间失效）+ `graphqlInline.scan.test.js`
  2 例（本地同构靶场 + 真 `ScanManager`：检出且安全点零误报）。

**外部实测**：`DVGA_BASE=http://127.0.0.1:5013 node e2e/dvga-lab/run.mjs` 连续 3 轮：
真值 **1/1**（union/error/boolean，98 请求）、安全 `search(keyword)` **0 误报**
（124 请求）、无 filter resolver 0 点/0 请求结构对照、证据不足 0；证据
`e2e/dvga-lab/results/external-judge-2026-10-21-d121.md`。台账：
`external-judge-dvga-d121` verified；`graphql-inline-injection-gap` /
`external-judge-dvga-d114` refuted（旧 0/1 保留作历史）。

**边界**：单端点样本，不外推 GraphQL 通用覆盖率；block string / 裸
`application/graphql` 未覆盖；DVGA 仍为参考靶场，不接 acceptance/run-all。

### 待推进

- **DVGA 转稳定门禁的前置**：靶场需手动起（Python 依赖）+ 只有 1 个真值端点；
  要接 CI 需容器化或补多端点样本，否则只是「参考证据」。
- **P0 ② `{call <过程名>}`**：Benchmark 4 条真值未检出（327 条有效覆盖之外单列）。
- **P0 ③ 发现阶段签名爬虫 + 外部裁判进 CI**：`--request-script` 尚未用于 crawler；
  外部裁判多数 optional，CI 不稳定。

---

## 2026-10-21 批次 D120 · 表单伴随字段 + GET 表单 url 点（接手并发会话未提交工作）

**背景**：DVWA low `/vulnerabilities/sqli/` 真机自测暴露 D112 的**第二条路径**（那次修
`--body` 生成点，这次是表单爬取）：① 按钮/提交控件没采集 ⇒ `isset($_REQUEST['Submit'])`
不成立 ⇒ 查询不执行；② GET 表单生成 body 点 ⇒ axios 发 GET 不带 body ⇒ 参数没发出去。
两者都表现为「响应恒等于基线」的静默 0 检出。

**本批**：接手并发会话工作区里未提交且语法不合法的 `TargetParser.js`（最小语法救援：
`_parseForms` 多一个 `}`，把 textarea 采集踢出循环、`return forms;` 掉到类层级），
不改其设计意图；`_parseForms` 拆 `_collectInputs`/`_collectTextareas`（44→23 行），
两处「表单→注入点」收敛为 `_pushFormPoints`；复杂度基线三条同步下调；
crawl/forms 测试同步新语义并新增「按钮进 formValues 但不生成注入点」用例。

**真机 A/B（DVWA low，本机复现）**：修复前 `actionUrl=…/sqli/#`（无 Submit、无 query）、
verdict `no_vulnerability_detected`（0 条，退出码 0）；修复后
`actionUrl=…/sqli/?id=&Submit=Submit#` + `formValues={Submit:"Submit"}`、verdict
`vulnerability_detected`（**3 条**，退出码 2）。

**验证**：服务端全量 3691 例 0 fail；表单/爬取 46/46；复杂度守卫通过；三个外部裁判
复跑零回归（Juice 2/2+0/4、VAmPI 2/2+0/5+Bearer、DVGA 0/1 按设计红）。

### 待推进

- ~~**P0 ① GraphQL 内嵌注入点**（`graphql-inline-injection-gap`）~~：**D121 已完成**
  （DVGA 1/1，连续 3 轮；`carrier='graphql'` 内联字面量点）。
- **`<select>` 采集**：取值需解析 selected option，场景较少，按需补。
- DVWA 靶场起法已固化在 `e2e/dvwa-lab/README.md`；本机资产 `/d/tools/{php83,mariadb,jdk,maven}`。

---

## 2026-10-21 批次 D119 · 回显剔除变体矩阵化（P0 ②）

**背景**：外部靶场自测中 DVGA 抓到的假阳性（JSON 转义回显未被剔除）是回显剔除这条线的
**第 5 次同族复发**（09-16 URL/HTML 实体 → 09-17 SQL/反斜杠 → 10-20 JSON 转义）。
每次都是「抓一个补一个、只测那一个」，其余形态继续漏。

**本批**：`echoStrip.js` 抽出 `echoVariants()`（变体清单 + 逐形态实测出处写进 JSDoc），
补 Unicode `\uXXXX` / 双重 URL / base64 / 截断型回显最长前缀剔除（阈值 16）；
新增 `server/tests/echoStrip.variantsMatrix.test.js` 16 例矩阵契约，
§A2 钉住「变体生成器必须覆盖矩阵全部形态」。
修了首版两条假绿用例（base64 probe 用编码串、截断长度覆盖关键字全字）。

**实测**：矩阵 16/16；缺陷注入（摘 4 个新形态）→ 4 条红、还原 → 16/16；
回显/报错通道相关测试 59/59 绿（`errorParse` 因并发会话半写 TargetParser 而红，非本批）。

**台账**：`echo-strip-variants-coverage-d119`（verified）。

### 待推进（P0 ① 未动）

- ~~**结构化文本内嵌注入点**（GraphQL / batch / 嵌套 JSON）~~：D121 已完成 GraphQL
  查询串内联字面量（DVGA 1/1）；batch 数组路径与 variables 通道有测试，但其他结构化文本
  （如 GraphQL block string）仍未覆盖。
- 矩阵后续形态候选（未实测到，不进矩阵）：XML 属性回显、十六进制转义、各语言特有转义。

---

## 2026-10-19 批次 D108 · Collaborator-Everywhere 式背景 OOB 哨兵（P1-5 收口）

**背景**：P1-5 —— interactsh（D87）已就绪，但 OOB 仍是 opt-in 通道：risk=1 技术门控剔除 OOB、
被预筛选/静态判定跳过的点、以及根本没生成注入点的请求头，全程零 OOB 标记 ⇒ 无回显目标静默假阴性。

**本批**：新增 `scan/oobSentinel.js` 背景哨兵——向「选定技术没覆盖的面」（跳过点 / `headerParams`
未生成头点 / 配置常见头 / 未测完点）播撒 OOB token，任一回连即确认无回显注入；`oobWaiters.js`
共享 `waitForAnyTokenIn`（三方同接口）；命中清掉 `noInjectionPoints` 误导标记；CLI `--oob-background`
+ REST `guardOobBackground` 净化；默认关（零行为变化）。

**实测**：真 oast.pro 链 `e2e/oob-interactsh-lab` 场景 A+B 全过（场景 B：无 query + 头传参 +
技术不含 oob → header 面回连检出 1 条）；单测 15 例；gate 全绿。

### 待推进（从 P1-5 拆出）

- **P1-6 自建协作端一键部署**：公共协作端回连记录归运营方；自建 docker-compose（公网域名 +
  DNS 委派）仍待做（底账 P1-6 原文）。
- **哨兵面穷尽化**：当前只保证「每个面一次机会」（预算封顶轮转），预算内未轮到即不播撒；
  若未来要「穷尽每个面 × 每库」，需按请求预算调 `maxRequests`（上限 200）。

---

## 2026-10-18 批次 D107 · tamper 手写字面量扫描收口（P1-4 收口）

**背景**：台账「25 个复杂插件未迁 walkLiterals」系 D57 时点快照。逐文件重审实况：手写引号
状态机共 7 个 —— 白名单 4 个 + 3 个因变量名（inQuote/inStr）逃过守卫 grep。

**本批**：`literalWalk.js` 新增 `maskLiterals`（长度保持打码）；if2case / ifnull2casewhenisnull
（字面量内 `IF(`/`IFNULL(` 不再被误改写）与 plus2concat / plus2fnconcat（转义引号、双引号、
注释三类误改修正）共 4 个迁移；守卫扩到四变量全集 + 剥注释比对，白名单 4→3。
A/B 42 例差 8 处（全为修正向）；上游 doctest 7/7；tamper 三门禁全绿。

### 待推进（从 P1-4 拆出，均已白名单点名）

- **literalWalk 反引号/块注释扩展**：space2comment 五态机（反引号 + `/* */`）与
  space2morehash 两遍扫描要迁 walkLiterals 需先把抽象扩到反引号/块注释语义（独立批次）。
- **scalarselectinline 逃逸启发式**：hasClosingQuote/isEscapeQuote 与 8 轮收敛是定制语义，
  维持现状；若未来引号判据再出事，应以 quoteScan 扩展真源而非就地打补丁。

---

## 2026-10-18 批次 D106 · paramName「ORDER BY 固定后缀」形态（P1-2 收口：序数差分探针）

**背景**：P1-2 —— `WHERE ${k} = ?` 属可注释形态（D93 覆盖）；键名拼进 ORDER BY 位置且后跟
固定尾部语法（`ORDER BY ${k} DESC`）时既有通道全盲（真 MySQL 靶场实测：三通道 64 请求零
检出）。布尔载荷退化为常量排序（§M 老坑）、UNION 在 ORDER BY 之后语法不可表达。

**能力**：`detectorSupport/orderByKey.js` 序数差分验证器（P1=`{k}, 1-- -` 合法序号 vs
P2=`{k}, 9999-- -` 序数越界报错；分化 + 复核轮；反射剥离零误报；只对标准赛道零命中的
非 XML 参数名点补测，已命中点零开销）。

**实测**：param-name-lab 扩 `/colsort`（`ORDER BY ${k} DESC`）三判据：
`sortVuln=1 sortParamNameHit=1 sortOff=0 sortSafe=0`（修复前零检出）；acceptance 1 PASS；
单测 21 例（+D106 三）。

### 待推进

- **XML 元素名在 ORDER BY 位置**：`{tag}, 9999` 非法 NameChar ⇒ 序数探针不可承载；
  候选=错误差分通道（合法名触发/不触发错误页），与 P1-1 错误差分余项同族，需错误可控靶点。

---

## 2026-10-18 批次 D105 · XML body 元素名注入面（P1-1 收口：算术位移探针）

**背景**：P1-1 余项（D103 留的 XML 元素名面）。NameChar 不允许空格/引号 ⇒ 布尔/UNION 载荷
发出即畸形报文（不以畸形报文换检出）；底账建议的算术位移方案本批落地：B=`tag`、
P0=`tag-0`（恒等）、P1=`tag-1`（位移），判据 P0==B ∧ P1≠B + 复核轮，归类布尔差分族
（technique='boolean'），专用验证器不进通用检测器赛道、WAF tamper 重跑亦排除。

**实测**：param-name-lab 扩 XML 三判据（`xmlVuln=1 xmlParamNameHit=1 xmlOff=0 xmlSafe=0`，
安全端点零误报、开关语义真实），acceptance 1 PASS / 0 FAIL；单测 18 例（D93 三 + D103 七 + D105 八）。

### 待推进

- **错误差分通道**（P1-1 余项转挂）：字符串列上 `tag-0` 恒等因隐式数值转换不成立 ⇒ 当前诚实
  假阴性；可评估错误差分（合法名触发/不触发 SQL 错误页/状态码差异）作第二判据族，
  需先造错误可控靶点（不靠错文回显）。
- **ORDER BY 位置形态**：`ORDER BY ${tag}` 拼接无固定值参照，位移探针不适用；另立形态探针。
  （[D106] query/JSON 键名侧已落地序数差分探针；XML 元素名侧仍待错误差分通道。）

---

## 2026-10-18 批次 D104 · CI macos 提取器判据抖动响应（墙钟 → 请求预算双护栏）

**背景**：D103 推送（run 276 = `39130198438`，`13a9f873`）macos 腿红：`extractor.timeBaseline.test.js`
「慢目标上从不延迟」用例 15s 墙钟截止时已发 239 个请求——慢 runner 定时器抖动把「零额外延迟」
探针系统性读成恒真 ⇒ 判定链失控；墙钟红得不可解释（像 load 慢，实为失控）。windows 腿 fail-fast 连带取消。

**改动（仅测试护栏）**：`extractWithDeadline` 在墙钟之外加**请求预算护栏**（200ms 轮询，>100 判红，
消息含实测口径）。请求计数与 runner 快慢无关，是失控的直接证据：修复后单表达式提取实测
tb-ok=34 / tb-null=11，取 100 = 3 倍余量。反例自证：预算降 5 → total=7 即触发（先于墙钟）。
与 D96「故障②墙钟改请求预算」同一教训：不拿墙钟当唯一判据。

### 待推进

- 观察后续 3-5 次 CI macos 腿：若再出现「判定链失控」实况（预算护栏红或墙钟红），
  考虑把不变量下移产品侧（提取器自持请求预算），而非只在测试护栏兜底。

---

## 2026-10-18 批次 D102 · P0-5 台账收口（versioned 覆盖口径 + paramminer 同题对照）

**A · tamper versioned 族（覆盖口径关闭）**：上游 5 个示例的**默认件**形态差异保留 drift 点名
（默认链是否切换待真机 A/B）；上游形态由复刻件（*nospace / *open / *block）承载，对拍脚本 ALIAS
段机械比对 **5/5**（复刻件缺失/漂移直接判红，无豁免位）。台账 `tamper-versioned-parity` 改写为
覆盖口径 → verified；AGENTS.md §四行同步。

**B · paramminer（改写措辞 + 实测量化）**：新真靶场 `e2e/param-mine-lab`（隐藏参数 kw 只在字典里，
不在任何链接表单；开挖掘 3/3 检出、关挖掘 0、安全点 0，已接 acceptance 与 run-all）；同题对照
（redteam 口径：同参 `--level 2 --dbms=mysql`、各 3 轮多数决）：我方零告知 3/3；sqlmap 零告知
0/3、全告知 3/3 ⇒ 差异在**发现环节**。台账改写为「提供 sqlmap 所没有的主动发现能力」→ verified。

**顺带实锤（判定脚本自伤）**：redteam `sqlmap-bench.mjs` 裸词正则 + neg-AND 两处自伤 ⇒ 旧
`results-sqlmap-runs3.json` 的「sqlmap 16/19、6/7 误报」实际 **14/19、0/7**（重算文件
`results-sqlmap-runs3.rescored.json`；旧文件与 archive 纪要留痕不重写；bench 正则已修正）。

### 待推进

- 重跑 redteam-lab sqlmap-bench（需 PG 常驻 + env.mjs）刷新修正后 runner 的新基线（当前用重算文件佐证）。
- 同族审计：blackbox-lab `sqlmap-bench.mjs` 的「pos && !neg」在多参数混合日志上同样会反向误杀
  （本批只修了 redteam 侧）；`sqlmap-benchmark/run.mjs` 的 `hit` 口径一并复核。

---

## 2026-10-17 批次 D93 · 参数名注入点（`--test-param-names`，吸收队列 #7）

**缺口**：后端把 query **键名**拼进 SQL（`WHERE ${Object.keys(req.query)[0]} = ?`、键名当列名
的 `ORDER BY`），值参数化 ⇒ 值注入扫不到。

**三处接缝**：TargetParser 生成 paramName 点（`originalValue` = 键名本身）·
injection.js 改键名保值（基线保持原键名）· boundary 跳过闭合探测 · prefilter 不剪枝。

**实测（真 MySQL 靶场 `e2e/param-name-lab`）**：vuln=2（命中点全为 paramName）、
开关关闭=0、安全白名单点=0。单测 4 例。

### 待推进

- JSON/XML **键名**注入面（本批只做 URL query 键名）；
- [D103 2026-10-18] **JSON body 键名面已补**（`Object.keys(req.body)[0]` 当列名拼 SQL 同型；
  carrier='json' 键名点 + 改键保值构造 + lab 新增 `/colfilter-json` 三判据实测全过）；
  本项原「e2e/param-name-lab 接入 acceptance/run-all（当前需手动跑）」的描述自 D95 起已过时，随批更正。
- 余 **XML 元素名**面（P1-1 剩项）：载荷字符集受 XML NameChar 约束（布尔载荷含空格/引号
  ⇒ 发出即畸形报文）⇒ 需专门探针（算术位移/错误差分），另批。
- paramName 点的 union 通道在「键名后还有固定后缀」的拼接形态下可能被截断（本批靶点
  `WHERE ${k} = ?` 属可注释形态；`ORDER BY ${k} DESC` 这类尾部固定语法未覆盖，需另造靶点）。

---

## 2026-10-17 批次 D92 · D91 的两个遗留口子

**① REST 入口 auth.headers 夹击面**：CLI 侧 `--test-headers` 的注入点头会从 `auth.headers`
删除（251-261），REST（`sanitizeStart`）没有等价逻辑 ⇒ `auth.headers` 同名副本经
`mergeAuthHeaders` 覆盖语义把注入值顶回原值 ⇒ header 类注入点静默假阴性。
修复：`sanitizeStart` 补去重（非 cookie 头，大小写不敏感；cookie 不删，与 CLI 同口径）。
判据 4 例 + 变异验证（路径不可达 ⇒ 2 红）。

**② 红队判据 90%→100%**：18/19（95%）曾判 PASS，而那正是 D91 的真回归
⇒ 阈值容错把「漏整类注入点」吞成通过。`gate-check.mjs` 与 acceptance assert 同步收紧为
**全中 + 零误报**；注入 18/19 验证 ⇒ FAIL exit=1（旧判据 PASS）。

### 待推进

- Cookie 之外的**其他注入点形态**（url/body/header/二阶）与 auth 配置的交互是否还有同类
  夹击（本轮已覆盖 header 的 REST 路径；CLI 与 REST 的去重口径应长期保持一致，可考虑抽共享函数）；
- 商业云 WAF 真机样本（D89 遗留）、62 家其余 44 家外部对拍源；
- versioned 注释形态 —— **已关闭（D102 2026-10-18）**：上游形态由复刻件承载并纳入 ALIAS 比对 5/5，台账转 verified（覆盖口径）；默认链切换仍待真机 A/B。

---

## 2026-10-17 批次 D91 · Cookie 注入点静默假阴性回归修复（推翻协议落地）

**反证**：10-17 acceptance 红队 **18/19**（D11-cookie 漏），台账/README 却写 19/19
（证据 10-05 三轮，D11 当时全命中）⇒ 真回归。

**根因（抓包实证）**：`--header "cookie: uid=1"` 被存进 **headerParams + config.auth.headers 两处**；
cookie 注入点构造后请求头同时含 `cookie=uid=1`（原值小写）与 `Cookie=uid=<注入>`（大写）。
axios 1.20.0 的 `AxiosHeaders.set` 同名头**后写赢** ⇒ 原值在后 ⇒ 服务端永远收到原值 ⇒
124 个探针全打在未注入值上 ⇒ 门控真假恒等 ⇒ 「未检出」（与「这个站没注入」同形）。
引入点：`5db14b8` 升 axios 1.18.1→1.20.0；Node 22/24 与 D88 boundary 候选表均已对照排除。

**修复**：A 构造层 `injection.js` cookie 分支删所有大小写同名键后单键写入；
B 发送层 `requestContext.js` `mergeAuthHeaders` 的 auth.headers Cookie 同名且已有 Cookie 时跳过。
判据 `server/tests/injection.cookieHeaderCollision.test.js` 6 例，双向变异验证（删 A/B 各 1 红，还原即绿）。

**修复后实测**：D11 命中（union+error+boolean，61 请求）；红队 **19/19、0/7 误报**；
F18 上次 acceptance 的引擎崩溃码（0xC0000409）**未复现**，留观不立结论。

**台账**：`detect-benchmark-redteam-26` → **refuted**（旧 19/19 证据作废、数字保留）；
新证据另立 `-d91` 条目；README 四处口径（R2 表/sqlmap 对照表/验收表/D6 注释）按推翻协议更新。

### 待推进

- ~~全量 acceptance 复跑~~ **已完成（10-17 晚，分三批 `--only` 跑，避开全量 20 分钟单测预算）**：
  单测 PASS（3606 例 / 3604 pass / 0 fail / 2 skip）；MySQL 依赖 12 套件 **12/12 PASS**
  （含上午 BLOCKED 的刁钻靶场 11/11、检测回归 19/19、真 MySQL 11/11、报告契约 8/8、
  CRS 三件套、WAF A2/A3、批量隔离、登录编排）；红队 PASS（**19/19、0/7 误报**）。
  当次仍 SKIP 的 5 个为环境缺失（PG 5432 未监听、secure_file_priv=NULL、Juice Shop /
  interactsh 环境不满足）——**未覆盖即不计过，也不假装全量**。Juice Shop 已于
  2026-10-19 D109 补跑通过（2/2 检出、0/4 误报，见
  `e2e/juice-shop-lab/results/external-judge-2026-10-19.md`）。
- D91 类问题的**通用化排查**：还有哪些注入点形态会被 auth.headers 副本夹击（当前只修了 Cookie 同名）；
- 商业云 WAF 真机样本（D89 遗留）、62 家其余 44 家外部对拍源。

---

## 2026-10-20 批次 D118 · 「可提交报告」核验：修数据实证 + SQLite3 误报

**起因**：评估「一个目标 → 可提交报告」。真靶场跑一遍四件套后逐条打分，发现两个「做错了」：
① `--dbs` 拿到 payload 残片（回显 payload 使标记自匹配）⇒ 修为提取前 stripEchoedPayload；
② 静态文档页 `<h2>SQLite3 SQL Injection</h2>` 命中裸签名 ⇒ 报 3 条 High 假漏洞
⇒ 收紧 SQLite3 签名 + 补 SQLite 强特征。

**新增**：acceptance 第 25 套件 `extract-proof`（真库名，非残片）；errorSig 语料守卫。

**当前结论**：单目标（URL + 参数 + 认证）已能一条命令出可提交报告。

### 待推进（按优先级）

1. **表单点被预筛选误杀**（接「给域名自动爬」的最后一公里）：
   `node server/bin/cli.js -u "http://127.0.0.1:8099/vulnerabilities/sqli/" --forms --level 5
   --cookie "security=low; PHPSESSID=x"` ⇒ 发现 3 点、预筛选跳过 3/3、0 检出；
   同目标 `--method POST --body '{"id":"1","Submit":"Submit"}'` 检出 3 条。
   ⇒ 查 prefilter 对 body/form 点的判据（怀疑伴随字段或 method 处理）。
2. 表单 `method="GET"` 应生成 url 点而非 body 点（现按 body 发，靠 `$_REQUEST` 碰运气）。
3. 报告补「修复后复扫验证」字段（工单闭环用）。

## 2026-10-20 批次 D117 · Benchmark 注入面全量（query 210 + header 67）

**本批**：`cases-query.json`（210）+ `cases-header.json`（67）两套全量清单，独立于门禁基线
（基线 74 条已要 25 分钟）。

**实测**：query **111/111 + 0/99**（54s）；header **33/33 + 0/34**（20s，92~124 请求全打满）。
累计有效覆盖 **327 条：178/178 真值、0/149 误报**；call 7 条单列。四裁判合计真值 **187 个**。

**待推进**：
- 113 条 prepared/其它形态未纳入；若要跑，先确认「安全侧对照」的意义（它们本就是安全实现）。
- Benchmark 的 `{call}` 4 条真值仍是缺口（需新能力）。
- 门禁套件耗时：baseline 74 条 25 分钟（paramName 用例单条 194 请求）——若继续扩基线，
  需要先给 paramName 用例降预算或拆到夜间任务。

## 2026-10-20 批次 D116 · Benchmark 扩面 20 → 74 用例（参数名全量 + `{call}` 边界单列）

**本批**：清单落盘 `e2e/benchmark-lab/cases.json`（不再硬编码）+ 并入全部 57 条参数名形态
⇒ 74 条（真值 43 + 安全 24 + `{call}` 7）。

**实测**：真值 43/43、安全 0/24、证据不足 0、header 2/2、参数名形态 50/50 全检出；
`acceptance --only=benchmark` 1 PASS。

**口径修正**：`{call <过程名>}` 7 条单列（4 真值全未检出 = 已知能力边界，不计入分母；
3 条安全对照 0 误报 —— 边界不豁免误报）。

### 待推进

- **`{call <过程名>}` 注入面**（4 条真值未检出）：注入点是存储过程名，需要
  `CALL <payload>` 形态的探测（含 HSQLDB/MySQL 的 `CREATE PROCEDURE` 回显差异），
  属于新能力而非判据调整；接之前先评估误报风险。
- **query / header 形态继续扩**：池子里还有 query 真值 111 / 安全 99、header 真值 33 / 安全 34
  未纳入（当前优先做参数名形态的全量，因为它最容易被误判成漏检）。
- **官方 scorecard 对齐**：Benchmark 官方按类别加权出 CWE 覆盖率，本仓只做 sqli（CWE-89）
  子集，不追求 scorecard 分数 —— 若要对比必须写清口径差异。

## 2026-10-20 批次 D115 · 外部裁判 4 号：OWASP Benchmark ＋ 推翻 D114 的 4/12 结论

**背景**：前三号裁判都没有 **HTTP header 位置的注入点**。OWASP Benchmark（504 个 CWE-89
用例，官方 CSV 逐条标注真值）补这块，并带来「同族 A/B」能力。

**本批**：新增 `e2e/benchmark-lab/`（run.mjs + README + results 报告）；acceptance 增
`benchmark` 套件（第 24 个）；run-all / e2e/README 登记；README 套件数 23→24。

**环境打通**（全是坑）：JDK17（华为云）+ Maven 3.9（archive.apache.org）+ `-Dspotless.apply.skip=true`
+ **`-Pdeploy` 打包**（HSQLDB server / init 是 deploy profile 的 antrun execution；
缺了 = `Connection refused` 或 `object not found: USERS`）+ cargo 到 **https/8443 自签**。

**推翻链（D114 → D115）**：D114（并发会话）记「query 3/10、header 1/2，已知漏检缺口 ⇒
仅作参考靶场、不接门禁」。本批复跑 9/12，逐条查官方源码后定位：00037/00038/00039 是
**参数名注入**变体（`param = name`，要求值 === 类名）⇒ 按普通 query 参数发时 param 恒为空，
注入没进查询（基线/真/假响应字节全同）。改用 `?<payload>=<类名>` + `testParamNames` 后
**12/12 全检出**；台账 d114 置 refuted、新立 d115。

**实测**：真值 12/12、安全对照 0/8 误报、证据不足 0、header 面 2/2、`acceptance
--only=benchmark` 1 PASS / 0 FAIL / 0 SKIP。

**待推进**：
- 子集扩到全集（504 个 sqli）：每端点 60~150 请求，全跑约数小时；可分批（先 57 个参数名形态）。
- `{call` 存储过程用例（57 个）未纳入子集：需先确认引擎对 HSQLDB CALL 的支持面。
- Benchmark 的 XSS/命令注入等其它类别不在判据范围（本仓只测 SQLi）。

## 2026-10-20 批次 D113 · 外部裁判认证场景扩面（VAmPI Bearer + DVWA 盲注 POST）

**背景**：D112 之后外部裁判仍有缺口 —— ① 三个裁判全部匿名、无认证头，而 D91 的假阴性
正是认证链路形状；② DVWA POST 真值都带错误回显，缺「仅布尔可分」的盲注形态。

**本批**：
- `e2e/vampi-lab/run.mjs` 加「自注册→登录拿 `auth_token`」链路 + 5 个端点
  （官方 books `token_validator + filter_by` 带 Bearer 的安全端点 ×3；同一 Bearer 下
  users 拼接真值 ×2）。判据加 `Bearer 认证端点：N 个（未测 M）`（未测≠零误报）。
- `e2e/dvwa-lab/run.mjs` 加 `sqli_blind` medium 真值（盲注 POST），真值 4→5。
- 两个 acceptance 定向均 1 PASS / 0 FAIL / 0 SKIP。

**实测**：VAmPI 真值 2/2、同源 2/2、安全端点误报 0/5、Bearer 5 个全实跑；
DVWA 真值 5/5、误报 0、证据不足 0。三裁判合计真值端点 **7 个**。

**踩坑**：① VAmPI token 官方默认 60 秒过期（`tokentimetolive`）⇒ 扫描中途全 401 ⇒
真假恒等（假零误报）⇒ 起靶场必须设 7200；② Bearer books 端点被输入校验剪枝只发
5 请求（同款陷阱第三次）⇒ 显式 `validationSkip:false`。

---

## 2026-10-20 批次 D112 · 外部裁判 3 号：DVWA（PHP+MySQL 栈）＋ POST 伴随字段假阴性修复

**背景**：前两个外部裁判都是 SQLite + 非 PHP 栈 ⇒ 「检出率」只证明「在 SQLite 上能打」。
本机 2026-10-18 装好 PHP 8.3 + MariaDB 10.11 后 DVWA 首次可起（旧限制解除）。

**本批**：新增 `e2e/dvwa-lab/`（run.mjs + README + results 报告）；acceptance 增 `dvwa` 套件
（optional，未就绪 SKIP）；run-all / e2e/README 登记；README 套件数 22 → 23。

**实测**：真值 **4/4 检出**（sqli low GET / blind low GET / **blind high cookie 注入点** /
sqli medium POST 表单）；同源复检 1/1；安全端点 **0/2 误报**（官方 impossible 档，同路径 PDO
参数化，均打满 150 请求）；证据不足 0。sqlmap 1.10.7 同题：medium POST 4 类全中（55 请求），
cookie 注入亦检出。

**修复（真 bug，外部靶场抓出）**：POST 表单伴随字段被丢弃 ⇒ 静默假阴性。
`buildInjectionRequest` 用 `point.formValues` 重建 body，而它只有页面抓表单路径才赋值 ⇒
`--body` 生成的点请求体只剩注入点自身 ⇒ DVWA medium（以 `isset($_POST['Submit'])` 为开关）
124 条响应字节数全同 ⇒ 0 检出且不报错。修法：bodyParams 点自带完整表单快照
（`TargetParser._appendBodyParamsPoints`），只覆盖单键；守卫
`server/tests/bodyParamsCompanion.guard.test.js`（4 例含变异自证）。

### 待推进（外部裁判面继续扩）

- **OWASP Benchmark**：需 JDK17 + Maven，本机只有 TRAE 内置 JRE ⇒ 仍未接入。
- **VAmPI 其余面**：官方只此一处字符串拼接（`books`/`login` 走 ORM），扩不出更多 SQLi 真值；
  若要扩「带认证头的安全端点」（`/books/v1/{title}` 需 Bearer），需先解决 runner 传静态头。
- **DVWA 其余面**：本轮只覆盖 sqli / sqli_blind 两模块；`--forms` 自动抓表单路径
  （`crawl-lab` 已覆盖部分）尚未与 DVWA 交叉验证。
- **同源复检的通用化**：VAmPI / Juice Shop / DVWA 各 1 条；可考虑抽成 runner 公共能力。
- **外部裁判的「漏检即判红」口径**：三套件已统一（真值必须检出 + 安全端点打满 + 零误报），
  但 acceptance 全量跑时它们都是 optional（未就绪 SKIP）——CI 上从未跑过，需确认 CI 环境能否起。

---

## 2026-10-19 批次 D111 · 外部裁判 2 号：VAmPI（路径段注入 + 同形态 A/B 零误报）

**背景**：D88/D109 之后外部裁判仍只有 **1 个项目、2 个真值端点** ⇒「外部检出率」类结论
只是单数据点。TODO 点名的同族靶场（DVWA / OWASP Benchmark）本机无 PHP / MySQL / Docker，
起不来；改选 **VAmPI**（`erev0s/VAmPI`，官方定位即「评估第三方工具对 API 的发现能力」），
它补的是 Juice Shop 没有的注入点形态 —— **URL 路径段**。

**本批**：新增 `e2e/vampi-lab/`（run.mjs + README + results 报告）；acceptance 增 `vampi`
套件（optional，未就绪 SKIP）；run-all / e2e/README 登记；台账增 `external-judge-vampi-d111`。

**实测**：真值 **1/1 检出**（95 请求，boolean+union+error，`dbms=SQLite`）；同源复检 1/1；
安全端点 **0/2 误报**（123 / 144 请求，均打满）；证据不足 0；`acceptance --only=vampi`
1 PASS / 0 FAIL / 0 SKIP。sqlmap 1.10.7 同题检出（boolean + UNION 5 列 + SQLite，51 请求）。

**判据修正两处（真值归类错误，非代码 bug）**：
1. 良性输入 ≠ 安全端点（漏洞实例上 `/users/v1/name1` 仍是注入点）⇒ 改为「同源复检」，
   单列统计不并入真值分母；
2. 参数化实例的该点被输入校验剪枝只发 5 请求 ⇒ 显式 `validationSkip:false`，并新增
   「安全端点证据不足（请求<30）」计数要求为 0。

### 待推进（D111 时代的旧清单，DVWA 一项已由 D112 完成；其余并入上方 D112 待推进）

- ~~**DVWA**~~ **已完成（D112 2026-10-20）**：本机 PHP 8.3 + MariaDB 10.11 就位后接入，
  见 `e2e/dvwa-lab/`。剩余：**OWASP Benchmark** 需 JDK17 + Maven，本机只有 TRAE 内置 JRE；
  sqli-labs 目前仍是本仓自写 Python 复刻（真值自证）。
- **VAmPI 其余面**：官方只此一处字符串拼接（`books`/`login` 走 ORM），扩不出更多 SQLi 真值；
  若要扩「带认证头的安全端点」（`/books/v1/{title}` 需 Bearer），需先解决 runner 传静态头。
- **同源复检的通用化**：当前只 VAmPI 有；Juice Shop 也可加（搜索点换良性词），
  用来钉住「检出不依赖畸形输入」。

---

## 2026-10-18 批次 D90 · 写副作用登记与自动清理（P2-5）

**动机**：TODO 2026-10-10 盘点的 P2-5「写副作用无自动清理/回滚（只有
`docs/pentest-handover/05` 的人工条款 R5/R6）」。人工条款要求「记录全部副作用并清理」，
但**代码里没有对应物** —— 正是本仓反复治理的形状：承诺写在文档里，实现里没有。

真实后果：fileWrite 往客户服务器落的文件、os-shell 起的进程、udf 装的 DLL，
测试结束全留在目标上，报告里只有正文描述、**没有可复核清单也没有收尾动作**。

| 面 | 落地 |
|---|---|
| 登记 | `server/src/services/sideEffectLedger.js`：**写前**登记（写失败也留痕——「试过但没记」比「记了失败」危险），落 `ledger/<scanId>/side-effects.json` |
| 可逆性分档 | `file_write` 可删／`udf_install` 可尝试卸载／`stacked_dml` 仅在给了反向语句时可逆／**`os_shell` 标 `irreversible`**（起的进程无法保证收回，如实标注不假装能清） |
| 自动清理 | `buildCleanupPlan`（不执行）+ `cleanupSideEffects`（逐条回报 cleaned/failed/skipped/irreversible）。**失败不静默**，客户须知道哪个残留没清掉 |
| 接入 | fileWrite 写前登记（`recordFileWriteEffect`）；CLI `ledger side-effects <scanId> [--cleanup]`；REST `GET /api/exploit/side-effects`（只读）+ `POST /api/exploit/side-effects/cleanup` |
| 报告 | `sideEffectSummaryForReport`：让报告写出「写了什么/清没清」的可核对面 |

### 安全口径（不得绕过）

- 本模块**不新增任何写能力**，只登记与撤销既有能力已产生的副作用；
- **GET 只读**不需 EXPLOIT 门（与 `ledger show` 同口径）—— 关掉利用能力后运维仍须能查残留；
- **POST 清理与写类端点同门控**（EXPLOIT_ENABLED + 授权声明 + scope 声明）：
  清理会对目标再发一次命令/写请求，**必须不是绕过门控的第二条写链路**（已断言钉住）；
- **默认不自动执行清理**：扫描器「自作主张再动一次目标」比不清理更危险。

### 诚实边界

- 只登记**被显式调用**的写操作；不调用即无记录（不是全自动兜底）；
- 不做「回滚整个业务事务」（需目标侧配合），只清理**本工具自己留下的痕迹**；
- os-shell 类不可逆项在报告与 CLI 输出里显式列出，需人工确认。

### 过程中修正

- 测试首版用了错误的环境变量名（`SCAN_LEDGER_ROOT`，实为 `SQLI_LEDGER_DIR`）⇒ 登记表写进
  真实 `data/ledger` 造成用例互相污染（实测「2 !== 1」）。命名为准后已核验真实目录零残留；
- 复杂度棘轮拦下 5 处（我在存量函数里加逻辑）：按仓库纪律**拆函数**（抽出
  `readBackAndVerify` / `runOneCleanup` / `irreversibleRows` / `summarizeResults` /
  `runSideEffectsSubcommand`），最终 main 312→311 行、fileWrite 43→39 行，**未抬任何基线**。

---

## 2026-10-18 批次 D89 · WAF 指纹 × 第三方权威工具对拍（补台账 unverified 的外部证据）

**动机**：台账 `waf-fingerprint-coverage`（「62 个 WAF 指纹识别」）长期 unverified ——
真机只有 ModSecurity **1/62** 有样本，其余是「规则存在 + 判据单测」。本批补上**第三方权威对拍**。

**外部裁判**：wafw00f（EnableSecurity，6.5k stars，173 厂商插件）的 `matchHeader`/`matchCookie`
规则 = 各家**真实拦截页特征**，由第三方维护、非本项目编写。

### 口径（首版错过一次，已纠正——记下来防复发）

首版把 wafw00f 全 173 家都算进分母，得 25.8% —— **毫无意义**：未识别的大多数
（Baffin Bay / Anubis / CacheFly / Envoy…）本就不在本仓 62 家清单内，不识别是**设计子集边界**。
**口径错会把「范围小」误读成「能力差」**。纠正后只比「双方共有厂商」：18 家。

### 结果（同一批样本，修复前后）

| 时点 | 样本级 | 厂商级 |
|---|---|---|
| 修复前 | 45.7%（16/35） | 56%（10/18） |
| **修复后** | **100%（36/36）** | **100%（18/18）** |

### 修复内容（真缺口，非凑数）

- **cookie 通道形态**：Cloudflare `__cfduid`、FortiWeb `FORTIWAFSID`、Imperva `incap_ses`/`visid_incap`、
  Barracuda `BNI*`/`BN[IE]S_`、F5 BIG-IP APM 会话 cookie（`LastMRH_Session`/`MRHSession`/`F5_fullWT`/`F5_HT_shrinked`）、
  F5 ASM `TS<hex>=`
- **header 形态**：BinarySec `x-binarysec-*`、Bluedon `BDWAF`、Radware `x-sl-compstate`、
  Wordfence `wfWAF` 变体、网宿 `Powered-By-ChinaCache`、百度云加速 server 本体、360 `panyun`、BlockDoS server

### 判据固化

`server/tests/wafExternalParity.guard.test.js`（4 例）：离线快照（36 样本入库，CI 零外网依赖）
+ 正向对拍 + 零误报反向 + 反例自证。**双向变异验证**：删 Cloudflare `__cfduid` → 红；
删 Bluedon `BDWAF` → 红；还原即绿（逐字节一致）。

### ★ 过程中修掉两个「我自己的 bug」（不改就会得出错误结论）

1. **具体化器转义顺序错**：`\.`（字面点）在 `.`→`x`（通配点）替换**之后**才处理，
   把 `blockdos\.net` 变成 `blockdosxnet` ⇒ 永不可能命中 ⇒ 对拍显示「未识别」。
   实为**脚本 bug 被误读成产品缺陷**。
2. **口径含不可测项**：`denyall.py` 只用 `matchStatus`+`matchReason` 判定（无 header/cookie），
   本脚本不采集其样本却把它算进分母 ⇒ 低估命中率。已改为只统计「有 header/cookie 规则」的厂商。

### 诚实边界（不得越界引用）

- 「100%」只覆盖这 **18 家 × 36 样本**，**不是「62 家全能识别」**；
- 样本由 wafw00f 正则具体化构造，证明「同一份厂商特征我们认得」，**不等于真机必然命中**；
- 仍缺**商业云 WAF 真机样本** ⇒ 台账**据实维持 unverified**（内涵已从「只有规则+单测」
  升级为「第三方权威对拍 18 家 100% + 有牙守卫」，缺口缩小到具体一项）。

### 待推进

- 商业云 WAF（阿里云/腾讯云/Cloudflare 等）真机样本采集 → 才能谈转 verified；
- 62 家其余 44 家的外部对拍源（wafw00f 侧无对应插件）。

---

## 2026-10-18 批次 D88 · 第三方真框架靶场（外部裁判）+ 修复其抓到的真漏检

**动机**：本仓最硬的一类缺口——37 个 e2e 靶场除 `sqli-labs`（还是本项目自写的 Python 复刻，
真值自证）外**全部自建** ⇒ 检出率/误报率只有「自己出题自己判卷」的证据。
本批接入 **OWASP Juice Shop**（第三方活跃项目：Angular + Sequelize ORM + SQLite）作为外部裁判。

### ★ 首跑即抓到一条真漏检（本批最有价值的产出，不是设计意图）

| 项 | 内容 |
|---|---|
| 现象 | Juice Shop `/rest/products/search?q=` 存在可打穿 10 列的 UNION 注入，**本引擎 0 检出** |
| 外部裁判 | 同目标 **sqlmap 1.10.7 检出成功**（boolean-based blind + 确认 SQLite）⇒ 判我方漏检 |
| 根因 | 闭合候选表缺 `%'))` 档（**LIKE 上下文 × 双层括号**）。逐候选实测基线 1617 字节：13 个候选**全部落空**，唯 `%'))` 命中 |
| 失明链 | 候选全落空 ⇒ `point.boundary=''` ⇒ 门控探针退化为 `apple AND 1=1-- -`（谓词整条落在字符串字面量内）⇒ 真假响应恒等（都 30 字节）⇒ 门控判「不是注入」⇒ UNION/布尔通道**从未启动** ⇒ 报告写「未检出」（与「这个站没注入」同形） |
| 为何 OR 降级复判也没救回 | OR 复判同样依赖 boundary；boundary 为空时 `apple OR 1=1-- -` 也是恒空 |

**修法**：候选表 13 → 15（补 `%'))` 与 `%")`），并把候选表从**函数内字面量**提为导出常量
`BOUNDARY_CANDIDATES`（此前无任何测试能引用它 ⇒ 漏项可长期无人发现）。

**修复后**：boundary=`%'))` → 门控 `pass=true`（1617 vs 30）→ **检出 1 条**（布尔盲注 / CVSS 7.5 / param=q），
列数正确探到 10。与 sqlmap 同题结论一致。

### 新增判据

| 面 | 内容 |
|---|---|
| 靶场 | `e2e/juice-shop-lab/run.mjs`：真漏洞端点须检出 + 安全端点须零误报；已接入 `run-all` 与 `acceptance`（判据读文本，避开「退出码恒 0 = 永远绿」） |
| 守卫 | `server/tests/boundaryCandidates.guard.test.js` 6 例：钉**结构不变量**（LIKE 族括号层级成阶梯 / 两族对称 / 无重复 / 高频在前），而非单个字符串——补一个字符串只治一处，不变量才防同族复发 |
| 变异验证 | 删 `%'))` → 不变量①③红；删 `%")` → ②③红；还原即绿（逐字节一致） |

### 零误报证据（有意区别于「没测过」）

安全端点必须**带可测参数**——首版误用无参数路径（`/api/Products/1`），那时「0 检出」只是
「没测过」，不构成零误报证据。改后 4 个安全端点**各产生 124–174 请求**（真测过）且全部零误报。

### 环境说明（本机可复现路径）

Juice Shop 本机跑通链：codeload tarball（npm 上 `juice-shop` 已弃用）→ `npm install --omit=dev --ignore-scripts`
→ `npm rebuild sqlite3`（原生模块必须编译，否则启动报找不到 `node_sqlite3.node`）→
`frontend/` 单独 install + 关 production 字体内联（否则构建时联网拉 Google Fonts 失败）→
`tsc --moduleResolution node`（上游 TS 配置与其 devDep 版本不匹配）。
⚠️ 靶场是**外部项目**，不进本仓依赖；未就绪时套件 SKIP 并写明原因。

### 待推进

- ~~Juice Shop 登录绕过~~ **已完成（D109 2026-10-19：`POST /rest/user/login` 纳入真值清单，
  套件 2/2 + 0/4）**；密码重置等其余 SQLi 挑战点仍待纳入；
- 同族第三方靶场（DVWA / OWASP Benchmark）可后续补充，扩大外部裁判面。
  → **D111（2026-10-19）已补 VAmPI**（外部裁判 2 号，路径段注入形态）。
  → **D112（2026-10-20）已补 DVWA**（外部裁判 3 号，PHP+MySQL 栈 / cookie 注入点 /
    POST 表单；本机 PHP 8.3 + MariaDB 10.11 就位后接入）。外部裁判合计 **7 个真值端点**
    （Juice Shop 2 + VAmPI 1 + DVWA 4）。剩余：**OWASP Benchmark** 需 JDK17 + Maven。

---

## 2026-10-18 批次 D87 · OOB 外部隧道（interactsh 协议）—— 补实战缺口 P1-3

**动机**：TODO 2026-10-10 实战盘点的 P1-3。内置 `oobReceiver` 只监听本机，要求「目标能回连
扫描器」；真实授权测试里目标多在云上/NAT 后/跨网段 ⇒ 这条回连路径通常不通 ⇒ **无回显盲注
（OOB 是唯一可达通道）恒判「未检出」**，是与「这个站没注入」长得一样的静默假阴性。
interactsh 模式改为「扫描器主动轮询协作端」，**只要求扫描器能出网**。

| 面 | 落地 |
|---|---|
| 协议客户端 | `server/src/core/interactshClient.js`：**零依赖**手写（引擎不加运行时 npm 依赖）——注册（RSA-2048 SPKI PEM 明文 base64）/ 轮询 / AES-256-CTR（IV 前置）+ RSA-OAEP-SHA256 解 key / 注销 |
| 拓扑抽象 | `server/src/core/oobTunnel.js`：`local` 与 `interactsh` 两拓扑统一为「要地址 + 等 token」一个接口 ⇒ **检测器零分支**；默认仍走本地（零行为漂移） |
| 接线 | `OobDetector` / `scan/detect.js` / `scan/supplementalRuns.js` 改经 `oobTunnel`；`defaults.oob.interactsh` + REST `guardInteractsh`（主机名白名单，不放任意 URL）+ CLI `--oob-interactsh` + help |
| 文档 | README 能力速查补旗标（readme:check 逼出来的）、help、`--config` 档案键登记 |

**判据（离线 + 真机双层）**：
- 离线 `server/tests/interactshClient.test.js` 9 例（mock 协作端，进 CI 常驻）：解密往返 / 域名长度阈值 / 大小写归因 / 外会话记录必须丢弃（防误报）/ 逐服务器回退 / 超时。
- 真机 `e2e/oob-interactsh-lab/run.mjs`：自带**无回显**靶站（响应体无注入证据）→ 真实回连协作端 → 扫描器轮询取回 → **检出 1 条 OOB**、exit 0。已接入 `e2e/run-all.mjs` 与 `acceptance`（判据读文本，避开「退出码恒 0 = 永远绿」）。

**实测踩到的两条协议硬约束**（都写进了源码注释与测试，别当推理）：
1. **首标签长度 ≥ 33**（corrID 20 + nonce 13）：受控实验逐档递增，20/26/31/32 全失败、33/34/36 成功。
   服务端 DNS 侧 `SlideWithLength(chunk, GetIdLength())` 在标签上滑窗找 corrID，长度不足窗口落不下。
   ⚠️ **不过这道坎会表现为「偶发命中」**（本文件最初版本即如此），极易被误判成「公共服务器限流」。
2. **DNS 标签大小写不敏感** ⇒ 服务端 `storeMatch` 存下来恒为小写，而引擎 token 是 nanoid（含大写）
   ⇒ 不归一化则**隧道通了却恒不检出**（实测靶站回连 14 次、本地 received 恒 0）。两侧统一小写比较。

**诚实边界**：① 默认关闭（开启即对外发带外请求）；② 公共协作端（`oast.*`）的回连记录交给其运营方，**真实项目建议自建**，且 OOB 只回带 token、不回带数据本身；③ UNC/SMB 向量的 445 握手仍不在覆盖内（走 DNS 通道归因）；④ 自建协作端的一键部署脚本未做。

### 待推进

- collaborator-everywhere 式普遍外带（TODO 理论清单第 10 条）依赖本条已就绪，可另行排期；
- 自建协作端部署（docker-compose 一键）未做——公共端在生产环境不合适。

---

## 2026-10-16 批次 D86 · 引导三件套收尾 + 白屏可诊断性收尾（主体已提交 `5adac0c`；白屏修复部分见下）

用户对 D85 收尾时列的三个可选项回复「都要加上」，全部落地（对应 CHANGELOG D86 条目）：

| 项 | 落地 |
|---|---|
| 术语表扩充 | `help.glossary` 16→24 条（sidecar/token、--request-script、--postprocess、扫描预设、断点续跑、WAF 指纹、SSE 事件直播）；中英同步 |
| 浅色赛博 | `themeMode.tsx` `useThemeDataset` hook（`<html data-theme>` 同步）+ `index.css` 浅色变体（HUD 描边深青化、辉光/闪烁去除）；挂载点零 JSX 改动 |
| 引导回看 | `onboardingReplay.ts`（CustomEvent 通道）+ HelpCenter「重新查看新手引导」按钮 + OnboardingTour 监听——修掉 D85「文案承诺回看却无入口」的真缺口 |

- 引导延迟保持 1.5s（测试安全边际：engineGate waitFor 窗口 ~500ms，2 倍余量；不为看起来更快牺牲门禁）
- 自查修掉：条件调用 useEffect（Rules of Hooks）→ effect 内判空；事件常量误导出 → 去 export（deadcode）
- 验证：vitest 574/574 · typecheck 0 · lint 0 · 八守卫 + wiring 230 + readme/facts/refs/modules 全 0

### 同批次第二部分 · 白屏可诊断性收尾（2026-10-16 晚，即本仓 D86 收尾现场）

D85/D86 主体提交后，桌面 dev 白屏现场复盘发现**三个「白屏但无可见反馈」缺口**——本次修的是
「可诊断性」，不是新功能：

| 缺口 | 现象 | 修法 |
|---|---|---|
| vite dev 只听 `::1` | 本机 localhost 优先解析 IPv6，Tauri 桌面端 WebView2 按 IPv4 连 `localhost:5173` ⇒ 连不上，纯白板 | `vite.config.ts` 绑 `127.0.0.1` + `strictPort`；不开 0.0.0.0 |
| ErrorBoundary 只包页面出口 | App/主题/DisclaimerDialog/OnboardingTour 抛错 ⇒ 整树卸载 ⇒ 白屏无反馈 | ErrorBoundary 上移到 App 根，错误至少渲染出文案 |
| 引擎门禁只有转圈 | 引擎慢起与死掉同形 | 载入态补「正在连接检测引擎…」（`common.engineConnecting`，zh/en） |

诚实边界：前端改动无自动化判据，白屏消失的验证依赖真机 `tauri dev`（D75 已修起不来根因）。

### 待推进

- 桌面端真机安装验收（1.1.1 包仍是 D85 版；D86 改动需重新 `npm run package:win` 才进安装包——**当前包看不到回看按钮与浅色变体**）；
- 浅色赛博只覆盖了 D85/D86 资产（hud-frame/grid-floor/neon-text/caret/flicker）；TopBar 顶栏恒深色不受影响；
- 后续新功能落地时同步补术语表条目（防再次漂移）。

---

## 2026-10-16 批次 D85 · 桌面端赛博视觉增强 + 小白引导体系（已完成，已提交 71f6976+3bb5f3a，已推送）

**动机**：用户实测桌面端反馈——UI「太简陋」要赛博科技感；功能对小白不友好缺引导说明。
D80 已有赛博基底，缺的是**可读性引导体系**与资产纵深覆盖。

### 已落地

| 面 | 内容 |
|---|---|
| 帮助中心 | `src/components/HelpCenter.tsx`：右侧抽屉 3 Tab（快速上手 / 术语表 16 条带过滤 / 结果判读三表）；TopBar「?」入口 |
| 首启引导 | `src/components/OnboardingTour.tsx`：仅 Tauri + 首次启动，1.5s 延迟 4 步 Modal，`sqli_onboarded` 记忆 |
| 配置引导 | `InfoHint.tsx`（Tooltip/Popover 两形态）+ `scanConfig/SectionTitle.tsx`；16 分区全接入；`configHints.*` 中英同步 |
| 赛博资产 | `index.css` 7 项新资产（HUD 四角/切角/辉光/闪烁/光标/网格地面/状态点）；TopBar 版本角标 + HomeHero 终端风 + 首页三步卡霓虹化 + 报告判读速览 |
| 保基线拆分 | `EnginePicker` / `ReportResumeButton` / `ReportVerdictHint` / `HeroDecor`；ReportPage 325→284 行、圈复杂度 69→58 |

### 关键踩坑（代码注释 + CHANGELOG 均有记录）

1. 前端 `import package.json` → TS2307（include 挡根目录）⇒ vite `define: __APP_VERSION__` 注入；
2. vitest 不继承 define ⇒ `typeof` 守卫 + dev 兜底；
3. InfoHint aria-label 全文 ⇒ 与测试 `getByLabelText` 多重匹配 ⇒ 文案避让（测试不可改，facts 指纹）；
4. OnboardingTour Modal aria-hidden 挡桌面测试 ⇒ isTauri 门 + 1.5s 延迟。

### 待推进

- 桌面端真机视觉核查（打包后截图验收赛博资产在暗色下的实际表现）——需用户在本机跑 `npm run package:win` 后确认；
- 术语表后续可扩：随新功能（如 D52 postprocess）补充条目；
- 浅色模式未挂赛博资产类（按设计只服务暗色语义）——若用户要浅色赛博需另做对比度方案。

---

## 2026-10-12 批次 D52 · 响应解密扩展点 --postprocess（与 --request-script 对偶）

**动机**：`--request-script` 治「发不出合法请求」，D52 治对偶面「读不懂合法响应」——目标把响应体
加密/编码后返回时（AES 信封、自定义 Base64 变体、自研 RPC 序列化），检测层拿到的全是密文，
真/假条件的响应差异被加密抹平 ⇒ 报告写「未检出」。是与「这个站没有注入」长得一模一样的静默假阴性。

### 已落地

| 面 | 内容 |
|---|---|
| 引擎 | `core/responseTransform.js`：`assertResponseScriptPath`（白名单根 `RESPONSE_SCRIPT_DIR`，复用 assertScriptPath——后者加 envVar/label/invalidCode 三可选参数，缺省即原行为）；`applyResponseTransform` 只替换 data、fail-closed |
| 接线 | scanClient 最内层（与请求变换同层：safeUrl/csrf/login 都要看明文）；lifecycle 回收；ScanManager.start 硬失败 + constraints 写明判读基于解密后响应 |
| 入口 | CLI `--postprocess` + 档案键 + REST 白名单 + scalarsEgress 形状校验 + defaults；TUNING_NO_UI_KEYS 登记 |
| 判据 | `tests/responsePostprocess.test.js` 15 条，killer = AES-CBC 随机 IV 模拟 oracle：不配脚本 extractBoolean 诚实 null，配脚本正确提取；接线 GET/HEAD 两条；4 发缺陷注入全杀 |

### 设计口径（防后人改错）

1. **只换 data**：status/headers 是可信度判账（拦截/会话失效/5xx）的输入，脚本改不了——
   放行 status 覆写等于让脚本把一次 403 洗成 200。
2. **fail-closed**：脚本炸 ⇒ 该响应按失败处理（_send 记 null、重试/放弃，与网络失败同义）。
   绝不「解不动就用密文继续比」——那正是本扩展点要消灭的静默假阴性。
3. **挂最内层**：与请求变换同层。挂外层会让 safeUrl/csrf/login 各层读到密文
   （csrf 取页读 body 提 token 会直接失败）。
4. **边界**：只覆盖经 getScanClient 的扫描/检测请求（含保活/CSRF/登录），**不含**注入点
   发现阶段的爬虫请求（与 requestTransform 逐字一致的边界，文档不许含混）。

### 未验证（如实标注）

- **真机**：全部判据为离线 mock oracle（随机 IV 模拟 + 接线层 stub），未经真实加密目标验证；
  真机验证需自建加密响应靶场（归 e2e 下一轮）。
- **盲区**：脚本同步/异步、流式响应体、超大响应体的解密成本未测（mock 均为小体量字符串）。

---

## 2026-10-13 批次 D57 · tamper 字面量遍历收口（P1）

**动机**：73 个 tamper 插件各自手写 `inSingle`/`inDouble`/`inLine` 主循环，逐字重复。判据漂移（如 `isQuoteEscaped` 的奇偶性 vs 前一字符）已在 23 个文件中出过事（quoteScan.js 已修但循环仍在各插件重复）。

### 已落地

| 面 | 内容 |
|---|---|
| 共享遍历抽象 | `server/src/core/tamper/literalWalk.js`（新建）：`walkLiterals(src, {onText, onLiteral, onAbort})` —— 引号外/引号内两类语义统一回调；未闭合字面量 → onAbort 原样输出（继承 quoteScan.js:63-67 契约） |
| space2* 迁移 | 33 个简单 space2 插件改为 `walkLiterals` + `onText`（消除内联 inSingle/inDouble 循环） |
| 编码族迁移 | 15 个引号内编码插件（rot13/caesar/vigenere/atbash/xor 等）改为 `walkLiterals` + `onLiteral` |
| 迁移守卫 | `server/tests/tamperLiteralWalk.guard.test.js`（2/2）：已迁移插件不得回退 + 白名单防腐烂（25 个复杂插件待后续迁移） |
| 三闸等价 | `tamper:parity` ✅ / `tamper:examples` ✅ / `tamper-matrix` ✅ —— 迁移前后行为逐字不变 |
| 重复门禁复校 | 重复块 42660→41368（-1292，迁移消除重复扫描循环）；基线已更新 |
| 变异目标 | `scripts/mutation-check.mjs` TARGETS +1（literalWalk.js）；selftest 25 目标全绿 |

### 待推进

- 25 个复杂插件（if2case/randomcaseall/str2hex 等）尚未迁移——语义更复杂（多遍/条件分支），留作后续批次

---

## 2026-10-13 批次 D61 · 技术债闭环 + 可读性（P2）

**动机**：`server/src` 内约 25 处 TODO/FIXME/HACK/XXX 标记格式不一：有的裸 `// TODO 修一下`，有的带日期但无批次归属。没有门禁 → 新标记随意加、旧标记无人闭环。

### 已落地

| 面 | 内容 |
|---|---|
| 门禁 | `scripts/debt-guard.mjs`（新建）：统一格式 `// [TODO YYYY-MM-DD D##] 简述`；新增裸标记不在基线 → 失败；基线只减不增 |
| selftest | 4/4 全绿（裸标记→报出、合规→通过、基线删除→提示、基线内裸→豁免） |
| 基线 | `docs/_debt-baseline.json`（25 个标记，全部基线豁免） |
| 接入 | `ci-local.mjs` GATES + `package.json`（debt:guard/:selftest/:baseline）+ CI ci.yml + pre-commit hook |
| 守卫 | `server/tests/debtGuard.wiring.test.js`（6/6） |

### 待推进

- 9.4/9.5 25 处标记逐项闭环 + 注释校正（P2，需逐项人工审阅）

---

## 2026-10-13 批次 D60 · 覆盖率盲区 + 跳过可观测 + 阈值收紧（P1）

**动机**：`useServerHistory` 无直接用例（分支覆盖盲区）；跳过的测试被读成「通过」；前端阈值未按实测收紧。

### 已落地

| 面 | 内容 |
|---|---|
| 直接用例 | `src/tests/useServerHistory.test.ts`（新建）：成功/失败(Error)/失败(非 Error)/卸载后不 setState 四分支 |
| skipped 可观测 | `scripts/run-coverage.mjs`：解析 vitest 输出，skipped > 0 时打印醒目摘要（跳过 ≠ 通过） |
| 变异目标 | `scripts/mutation-check.mjs` TARGETS +1（useServerHistory.ts，frontend runner） |
| 文件修复 | `server/src/core/bearerKeeper.js`：修复内容重复追加导致的语法错误（585→293 行恢复原状） |
| 回归 | `cd server && npm test` 3548/3552 全绿（0 fail, 4 skip）；`test:coverage` 通过（91.18%/80.83%/84.13%） |

### 待推进

- 8.4 前端覆盖率阈值按实测收紧（esbuild 二进制缺失，无法跑 vitest，暂留）

---

## 2026-10-13 批次 D59 · 错误形态一致性 + 显式 any 收敛（P1）

**动机**：`server/src/api/**` 与 `server/src/services/**` 是对外契约层：裸 `Error` 不携带 `ErrorCode`，路由层无法映射响应码、消费方无法区分「参数错」与「目标不可达」。

### 已落地

| 面 | 内容 |
|---|---|
| 门禁 | `scripts/error-contract-guard.mjs`（新建）：受限目录裸 `Error` 必须为 0；非受限目录按文件计数与基线比对、只减不增 |
| selftest | 5/5 全绿（受限裸 Error→报出、AppError→通过、非受限超基线→失败、基线内→通过、下降→提示可下调） |
| 基线 | `docs/_errorstyle-baseline.json`（19 文件 39 处非受限裸 Error，只减不增） |
| 归零 | `scanLedger.js`（2 处→AppError: INVALID_PARAM/SCAN_ID_INVALID）；`ReportAI.js`（7 处→AppError: AI_REPORT_DISABLED/RATE_LIMITED/UNKNOWN/HTTP_TIMEOUT） |
| 接入 | `ci-local.mjs` GATES + `package.json`（errorstyle:guard/:selftest/:baseline）+ CI ci.yml + pre-commit hook |
| 守卫 | `server/tests/errorContractGuard.wiring.test.js`（6/6） |

### 待推进

- 7.5 生产显式 any 逐处评估与收敛（117 处 JSDoc `{any}`，medium 优先级）
- 7.6 eslint `no-explicit-any` 分阶段收紧（限生产 files，medium 优先级）

---

## 2026-10-13 批次 D58 · 死代码门禁 + 清理（P1）

**动机**：`getResponseTransform` 已导出但无引用；测试专用导出散落无标注。没有门禁管「导出是否有人用」——死代码静默积累，重构时漏删或误删仍被引用者。

### 已落地

| 面 | 内容 |
|---|---|
| 门禁 | `scripts/deadcode-guard.mjs`（新建）：符号收集（export function/const/class/default）→ 引用收集（import/require/namespace import）→ 差集 → 扣减用途标记（@public/@used-by/@test-only/@dynamic）与基线豁免 |
| selftest | 5/5 全绿（导出无人引用→报出、@public→豁免、namespace→豁免、基线裁定正/反两档） |
| 基线 | `docs/_deadcode-baseline.json`（162 个未使用导出，只减不增） |
| 清理 | `server/src/core/responseTransform.js::getResponseTransform` 加 `@public` 标注（registry getter，公共 API） |
| 接入 | `ci-local.mjs` GATES + `package.json`（deadcode:guard/:selftest/:baseline）+ CI ci.yml + pre-commit hook |
| 守卫 | `server/tests/deadcodeGuard.wiring.test.js`（6/6） |

---

## 2026-10-13 批次 D56 · 重复代码门禁 + 提取合并单核（P1）

**动机**：234 个 tamper 插件中 68 个含逐字重复的字符串扫描状态机；`scanHelpers.js` 有两份近似白名单合并（`mergeExtracted`/`mergeExtractedForResume`），注释自述 P0-FIX 两次栽在漏 `search`/`meta`。修一处漏另一处 → 静默缺陷。

### 已落地

| 面 | 内容 |
|---|---|
| 重复代码门禁 | `scripts/duplication-guard.mjs`（新建）：令牌级克隆检测（jsLexer token 化 + 标识符归一化 + FNV-1a 滚动哈希 + 精确比对 + delta 分组合并）；MIN_TOKENS=80（design 定 40，实测 500+ 文件仓 40 token 匹配过泛 10 万+，提至 80 聚焦显著重复）；跨文件检测 |
| selftest | 5/5 全绿（正/负/中性三档：等价复制检出、标识符归一化检出、单段不报、基线增长判失败、减少提示可下调） |
| 基线 | `docs/_dup-baseline.json`（新建）：42660 个跨文件重复块（只减不增） |
| 提取合并单核 | `server/src/engine/extractMerge.js`（新建）：`FIELD_TABLE` 字段清单单点化 + `mergeFields(target, src, {onConflict})` 冲突策略参数化；`mergeExtracted`/`mergeExtractedForResume` 变薄包装 |
| 等价性单测 | `server/tests/extractMerge.test.js`（12/12）：两策略与原函数行为等价 + 字段集一致性 + P0-FIX 回归 |
| 接线 | CI ci.yml / pre-commit / ci-local.mjs / package.json / 接线守护 `server/tests/duplicationGuard.wiring.test.js`（6/6） |

---

## 2026-10-13 批次 D55 · JSDoc 类型覆盖门禁 + 隐性 any 分批启动（P0）

**动机**：`server/tsconfig.json` 自述 `noImplicitAny` 3045 处未启用；`eslint.config.js` 显式关闭 `no-explicit-any`。编译器开关一时半会打不开，但「JSDoc 标注覆盖率」可以**独立于编译器开关**度量推进度。

### 已落地

| 面 | 内容 |
|---|---|
| 类型覆盖门禁 | `scripts/typecoverage-guard.mjs`（新建）：`measureCoverage`/`judge` + CLI；按目录批次度量 `@param`/`@returns` 标注率；基线只升不降、热点范围不得扩大、批次集合不得缩小 |
| 基线 | `docs/_typecoverage-baseline.json`（新建）：4 个批次（core 49.1% / engine 29.3% / api 21.9% / services 21.9%） |
| coverage-calibration 扩展 | `scripts/coverage-calibration.mjs` 新增 server 侧 `test:coverage`/`test:coverage:core` 阈值只读校验（存在 + `0<v<100`） |
| 接线 | CI ci.yml / pre-commit / ci-local.mjs / package.json / 接线守护 `server/tests/typecoverageGuard.wiring.test.js`（6/6） |
| 恒绿 | `greenguard-check` 通过 |

### 待推进

- **3.4 首批目录归零**：`server/src/services`（13 文件，当前 21.9%）补 JSDoc 标注——门禁基础设施已就位，标注工作留作下一轮推进，进度由门禁度量。

---

## 2026-10-13 批次 D54 · 复杂度热点拆分（P0）

**动机**：D53 门禁量化出的两个复杂度热点——`blindExtractor.js::extractBoolean`（271 行/复杂度 97）和 `BooleanBlindDetector.js::_robustDetect`（197 行/复杂度 41）——按**职责**拆分，保持对外行为与检测判据逐字不变。

### 已落地

| 面 | 内容 |
|---|---|
| extractBoolean 拆分 | 5 个子过程：`_resolveExtractPlan`（plan 解析+缓存检查）/`_extractLength`（长度二分+延伸）/`_extractBytesBitwise`（位平面提取，opt-in）/`_extractBytesBisect`（字节二分+字符集收窄）/`_finalizeExtract`（UTF-8 解码+整值复验+缓存写入）。`extractBoolean` 从 271 行降到 11 行（复杂度 5） |
| _robustDetect 拆分 | 3 个子过程：`_collectRobustBaselines`（基线采样）/`_buildRobustJudges`（动态块判定协作）/`_probeBooleanPairs`（真假对遍历+表决）。`_robustDetect` 从 197 行降到 20 行（复杂度 3） |
| scanHelpers | 2.3 确认：`mergeExtracted`/`mergeExtractedForResume` 分支下降由 D56 驱动；`publicTarget`/`hasData` 已在基线内且无劣化 |
| 定点单测 | `server/tests/blindExtractSubprocess.test.js`（5/5）：端到端提取/缓存命中/结构性不支持/位平面 opt-in/空值不缓存 |
| 变异目标 | `scripts/mutation-check.mjs` TARGETS 新增 `blindExtractor.js`（4 个测试文件）；`--runner=server --limit=1` PASS 无存活变异 |
| 基线 | `docs/_complexity-baseline.json`：260 个函数（+3 子过程 -1 extractBoolean +1 _probeBooleanPairs -1 _robustDetect = 净 +2） |
| 回归 | `cd server && npm test` 3494/3498 全绿（4 skip 环境缺依赖） |

### 设计口径（防后人改错）

1. **等价搬移**：仅移动代码位置到子函数，不改变任何逻辑、请求序列、判据或置信度写入时机。
2. **仅传数据不共享可变状态**：子过程通过 `plan`/`judges` 对象传参，无共享可变闭包。
3. **基线只减不增**：拆分后 `extractBoolean`/`_robustDetect` 退出基线（已降至限内），新子过程入基线（存量代码搬移）。

---

## 2026-10-13 批次 D53 · 函数级复杂度门禁 + 共享词法内核（P0）

**动机**：arch-guard 管**文件**体积、nesting-guard 管**嵌套深度**，但没有门禁管**函数**。
真实事故形态：文件不到 1200 行、嵌套不到 7 层，但某个函数体几百行、圈复杂度几十 ——
改它时"这个分支属于哪段逻辑"要靠滚动条确认，漏改一支的概率极高。本仓实测
`blindExtractor.js::extractBoolean` 单函数约 271 行；`scanHelpers.js` 仅 181 行却含
上百个分支点。文件级门禁对这类"单函数巨兽"完全无感。

### 已落地

| 面 | 内容 |
|---|---|
| 词法内核 | `scripts/lib/jsLexer.mjs`（新建）：导出 `lex`/`findFunctions`/`countBranches`/`effectiveBodyLines`；`nesting-guard.mjs` 的 `analyzeNesting` 改为复用 `lex`，输出逐字节不变（全仓 778 文件对比 IDENTICAL） |
| 复杂度门禁 | `scripts/complexity-guard.mjs`（新建）：`measureFunctions`/`judge` + CLI（检查/`--selftest`/`--fix-baseline`/`--json`/`--force`）；软上限 100 行/复杂度 15，硬上限 200 行/复杂度 25；基线内函数豁免硬上限、只许持平或下降 |
| 基线 | `docs/_complexity-baseline.json`（新建）：258 个存量超软上限函数入基线（含约 100 个超硬上限者，由 `--force` 收录） |
| 接线 | CI ci.yml（selftest + 检查各一步）/ pre-commit（0.9s）/ ci-local.mjs GATES lint 组 / package.json（`complexity:guard`/`:selftest`/`:baseline` + `check:all`）/ 接线守护 `server/tests/complexityGuard.wiring.test.js`（7/7） |
| 单测 | `server/tests/jsLexer.guard.test.js`（10/10）：模板串/注释里的 `{` 与 `if` 不计入、对象字面量不计深度、countBranches 各分支点、findFunctions 识别 function/类方法/箭头、effectiveBodyLines 剔除空行/注释行 |
| 恒绿 | `greenguard-check` 通过（无恒绿嫌疑） |

### 设计口径（防后人改错）

1. **保守识别**：`findFunctions` 不确定者计入 `unparsed` 不判定，避免把嵌套内函数误当外层长度。
2. **有效行数**为主判据（剔除纯空白/纯注释行）——纯注释行不代表职责复杂度。
3. **基线只减不增**：`--fix-baseline` 用 `Math.min(现测, 旧基线)`；超硬上限需 `--force` 才收录。
4. **新函数强制软/硬上限**：不在基线的新函数不得从超限起步（必须先拆分）。

---

## 2026-10-12 批次 D50 · --fetch-using=between（提取比较算子）

**上游归属更正（先读这个）**：本项原登记于「下一批候选口径」表，写作「`--fetch-using=between/in`（ghauri）」。
2026-10-12 对 ghauri **v1.0.5 与 `v1.0.1#dev` 两个 tag 整包取证**（codeload 下载 + grep）：
`--fetch-using` / `fetch_using` **0 命中**（仅 `fetch_using_error_based_vector` 方法名无关）⇒
**ghauri 没有这个参数**，原调研归属错误。能力本身有独立价值，按技术价值落地，**不称对标 ghauri**。

### 已落地

| 面 | 内容 |
|---|---|
| 引擎 | `resolveFetchUsing`（gt\|between，非法值抛错）；字节二分 BETWEEN 窄化；长度二分/延伸预检/时间通道同构 |
| 入口 | CLI `--fetch-using` + 档案键 + REST 白名单（scanConfigTuning 枚举校验）+ defaults |
| 收口 | TUNING_NO_UI_KEYS 登记；README/CHANGELOG 同步 |
| 判据 | `tests/fetchUsing.test.js` 11 条（含 WAF 过滤 `>` 模拟：gt 诚实 null、between 照常提取）；5 发缺陷注入全杀 |

### 关键设计口径（防后人改错）

1. **BETWEEN 上界必须取提取长度上限（lenCap），不能用当前段上界**：`x BETWEEN n+1 AND 255`
   在 x>255 时恒假 ⇒ 260 字符长值被判长度 0（开发中实测踩到）。用 lenCap 后
   `x ∈ (n, lenCap]` ⇔ `x > n` 恒成立，顶界语义交回 capped/延伸段。
2. **两模式收敛判定不同，别合并**：between 不变式 x∈[lo,hi] ⇒ `lo>=hi` 收敛（candidate=lo）；
   gt 不变式 x∈[lo,hi+1] ⇒ `lo>hi` 才收敛（candidate=hi+1）。gt 下 lo===hi 是未收敛中间态，
   误判会丢候选值。且收敛判定必须在窄化**之后**算。
3. **`in` 不实现（有证据地不做）**：`x IN (v1..vk)` 为假时只说明 x 不在名单内，无法定位到
   k+1 个缺口中的哪一个，驱动不了窄化；单值 IN 退化为相等判断（最坏 256 次线性扫描）。

### 未验证（如实标注）

- **真机**：between 全部判据为离线 mock oracle（确定性 + WAF 模拟），**未经真库靶场验证**；
  真机验证归 real-mysql-lab 下一轮（本机不起常驻进程是硬约束）。
- **边界**：等值验证（extractVerify）与 false 基准（1=2）仍用 `=`——`=` 被过滤时整条通道
  本就不要命，非本开关可救；blindBitwise 位平面路径无比较算子，天然兼容两模式。

---

## 2026-10-12 新增 · 推送前置链（只读盘点）与下一批候选口径

> 本轮**未落地任何代码**，只做仓库状态与 CI 取证（网络可用、本机无法 spawn 子进程期间的静态排查）。
> 结论：当前**唯一的前置动作是推送**，其余事项几乎全被它阻塞。登记在此防重复调研。

### 状态事实（判据与坑）

| 项 | 事实 |
|---|---|
| 远端真 HEAD | `1da1017` = **D39** ⇒ 本地 **D40–D46 共 7 个提交未推送** |
| 判同步**三不靠** | ① `refs/remotes/origin/*` 陈旧（fetch 不落 ref）；② `git ls-remote`（本机 PATH 上的 Git 缺 `remote-https`）；③ `git rev-list <远端sha>..HEAD`（API 建的 commit **sha 与本地不同** ⇒ 报 bad object）。**正解**：`curl api.github.com/repos/OWNER/REPO/commits?per_page=5` 取远端 HEAD 的 **message**，按提交标题对齐本地 `git log` |
| facts 状态 | `docs/_facts.json` 采集于 `2026-10-10T18:33:48Z`，其后 **13 个 `server/tests/*` 被改**（D40–D46）⇒ 指纹过期、README 徽章 3855 是旧数（README 与 facts 一致**只说明文档没漂移**，不代表数字是新的） |

### CI 两条红（run #206，push 触发）—— 已定位，非本机环境问题

| job | 红因 |
|---|---|
| `lint` | `facts:check` 报采集源已改动（`server/tests/lintScope.guard.test.js`）⇒ 指纹过期即 exit 1 |
| `test-server` | `lintScope.guard.test.js` 三条 `ERR_MODULE_NOT_FOUND: '@eslint/js'` —— CI 只装 `server/node_modules`，而 `@eslint/js` 在**根** node_modules ⇒ 守卫真加载 `eslint.config.js` 必崩。**D40 的修法（判据采集改静态文本解析）正对此，但从未被 CI 复验**（未推送） |

⚠️ **读 CI 徽章要分两种 skipped**（别混为一谈）：

- **run #206（push）**：lint + test-server FAIL ⇒ 依赖 `test-server` 的下游 job（`acceptance` /
  `release-smoke` / `sidecar-build` / `docker` / `audit`）**连锁 skipped** —— 这是上游失败的连带。
- **run #207（schedule）**：ci.yml 每个 job 都有 `if: github.event_name != 'schedule'` ⇒ 10 个 job 跳过，
  只剩 `tamper-waf-matrix` 与 `modsec-live`（两者 success）⇒ **run 结论 success（夜跑语义，不是全量绿）**。

⇒ **推论**：D39 接进 `acceptance` 的 `pentest-lab` / `api-range-lab` **在 CI 上一次都没真跑过**
（每次 push 都被上游 test-server 那条红连带跳过）。**只有推送且 lint/test-server 转绿后才有 CI 首跑**，
那才是 D39 真正的验收点。

### ⚠️ `test-server` 是整条 CI 的单点瓶颈（2026-10-12 静态排查得出）

`acceptance` / `e2e-self-contained` / `release-smoke` / `sidecar-build` / `docker` / `audit`
**六个 job 全部 `needs: [test-server]`**（其中前两个还叠加 `if != schedule`）。⇒ 后果：

1. `test-server` 一红 ⇒ **6 个下游 job 全部静默 skipped**，run 只报失败、看不出"半个门禁没跑"；
2. 实测从 run #200（D30 前后）到 #206，`test-server` 持续红 ⇒ 这 6 个 job **连续多轮从未真跑**
   （`acceptance` 里就含 D39 新接入的两套真靶场）；
3. 夜跑（schedule）里它们又因 `if` 跳过，只剩两个外部裁判 ⇒ **run 报 success**
   ⇒ **CI 徽章绿 ≠ 核心门禁绿**。读徽章必须看 job 明细。

**解锁顺序**：修 `test-server` → 下游 6 job 才会真跑 → 才有 acceptance / e2e 的真证据。

### D40 的修复已静态可证（无需跑 CI）

`server/tests/lintScope.guard.test.js` 已改为**从 `eslint.config.js` 的源码文本静态解析 `ignores`**
（该文件注释里写明根因：CI 的 `test-server` job 只装 `server/node_modules`，root 专属的
`@eslint/js` / `typescript-eslint` / `eslint-plugin-react-hooks` / `globals` 一个都没装 ⇒
从 server 侧 `import()` 根配置必然 `ERR_MODULE_NOT_FOUND`）。文件内已无对根 `eslint.config.js`
的动态导入 ⇒ **`@eslint/js` 那条红的根因已消除**，推送后应转绿（仍待 CI 复验）。

### 推送前的动作序列（顺序不可跳）

1. `node scripts/facts-sync.mjs --refresh --coverage`（一批只 refresh 一次）
2. `node scripts/facts-sync.mjs --fix`
3. `npm run lint && npm run typecheck && npm run test`
4. 提交走 **plumbing**（`git add` → `write-tree` → `commit-tree -p <base> -F -` → `update-ref`），
   **不要用 `git commit`**（本机 husky 曾让对象库损坏加剧、也曾删掉 `.git`）
5. `node scripts/push-via-api.mjs`（需 `GH_TOKEN`，幂等，约 2.5 分钟）

### CI 解锁战报（run #208–#210，2026-10-12）—— 近两周第一次拿到完整 CI 证据

解锁链：**推送（`0ff772c`→`8a8430d1`，11 个提交，全部 1703/1703 零失真）→ `test-server` 转绿
→ 6 个下游 job 首次真跑**。

| job | run #208 / #210 | 说明 |
|---|---|---|
| `test-server` | ✅ / ✅ | **D40 的修复（lintScope 守卫改静态文本解析）被 CI 复验成立** —— `@eslint/js` 那条红消失 |
| `test-frontend` | ❌ / ✅ | ❌ 是**真缺陷**：D41/D42 新增 5 个后端可达键没走收口二选一（`testParameter`/`paramExclude`/`paramFilter`/`ignoreCodes`/`randomize`），判据 ④ 报未登记、⑥ 报 43 ≠ 38。已登记进 `TUNING_NO_UI_KEYS`（覆盖型旋钮 ⇒ 调优类，非能力缺失）⇒ run #209 转绿 |
| `acceptance` | ❌ / ⏳ | 唯一红 = `[gates] 未知 API 路径返回 404 JSON`，实际收到 `text/html`。**根因是位置写错**：那段 `/api` 404 JSON 被包在 `if (existsSync(dist/index.html))` 里 ⇒ 有 dist 走 JSON（本机绿）、无 dist 落到 Express 默认 HTML（CI 红）。已在 dist 块之外无条件兜一层（提交 `a7793bb`） |
| `e2e-self-contained` | ✅ / ✅ | 挂了 22 天的老待查**销账**（见 §Y） |
| `release-smoke` / `sidecar-build` / `docker` / `audit` | ✅ | 都是首次真跑（此前被连带 skipped） |
| `lint` | ❌ / ✅ | ~~facts 过期（唯一剩账）：指纹 441 → 448 文件。需换会话跑 `facts-sync --refresh --coverage` + `--fix`~~ ✅ **已销账（2026-10-12 D47）**：本机 `node` 的 `child_process` 全程 EBUSY 是**有解法的** —— `NODE_OPTIONS="--require=D:/projects/_sqli-gitfix-2026-10-03/cp-pipe-shim.cjs"` ⇒ spawn 恢复，正规跑完 refresh+fix（6m41s）：前端 561、服务端 3373（3369 pass/0 fail/4 skip）、徽章 3930、指纹 448 文件。本机 `lint` exit 0。**⚠️ 记牢：下次再遇到"本机 spawn 不了"，先上 shim，别直接把活推给 CI** |

⚠️ 本机 `node` 的 `child_process` 全程 EBUSY（`execFileSync` 一律失败），三笔修复**均未经本地测试验证**，
判据全部交给 CI。**教训：不能本地验证时，就把"未经本地验证"写进提交信息，别假装验过。**

### 下一批候选口径（登记用，**不占批次号**；落地时按本地 `git log` 最新编号顺延）

| 方向 | 代价 | 验证口径 / 前提 |
|---|---|---|
| ~~`--fetch-using=between/in`（ghauri）~~ | S | ⚠️ **候选前提不实（2026-10-12 上游取证）**：ghauri v1.0.5 与 `v1.0.1#dev` 全仓 `--fetch-using`/`fetch_using` **0 命中**（codeload 整包 grep，仅 `fetch_using_error_based_vector` 方法名含 fetch_using，与 CLI 参数无关）⇒ **ghauri 没有这个参数**，原调研归属错误。能力本身（BETWEEN 窄化二分）仍有独立价值（比较算子 `>`/`<` 被 WAF 过滤时本仓 cls 类探测早已单方面依赖 BETWEEN 可用），**按技术本身价值落地为 D50**，不称"对标 ghauri"；`in` 不做（见 D50 节证据） |
| 参数名注入（SQLiDetector） | S | TargetParser 新增 location + buildInjectionRequest 换位（列名 / 排序名拼接场景） |
| 时间通道动态基线（BlindSQL） | S | 每靶点先测 N 条基线 RTT，阈值 = 基线 + k·σ；与 `autoDynamicBlock` 对偶（后者只管内容噪声） |
| `--postprocess` 响应侧解密 | S–M | 与 `--request-script` 对偶；加密响应目标现状是**静默比对失败**，价值 High |
| backslash-powered 变换探针 | M | prefilter 阶段前置探针族（`\`、`\\`、`%00`、引号族差分） |
| interactsh OOB | M | ⚠️ **需公网**：本机离线只能做协议 mock 单测 ⇒ 真机验证另起批次，**建议后置**（否则再留一条未验证账） |

---

## 2026-10-11 新增 · 同源项目优点盘点（吸收路线图）与批次 D41

> 应「吸取同类 GitHub 项目全部优点」的盘点：三路调研（sqlmap 全量参数面逐条比对
> `lib/parse/cmdline.py`；ghauri/jsSQL/DSSS/SQLiDetector/wafw00f/backslash-powered 等
> 同类工具的独有优点；nuclei/dalfox/ffuf/ZAP/semgrep/trivy 的工程化实践），每条都已
> 与本仓现状核对（README 已有项不重复推荐）。**本批 D41 先落地高价值低风险项**，
> 其余按批次排队如下。

### D41 已落地（2026-10-11）

| 项 | 内容 | 验证 |
|---|---|---|
| 参数筛选三件套 | `-p/--test-param`、`--param-exclude <re>`、`--param-filter <place>`（对标 sqlmap 同名）：TargetParser 收口（`engine/paramSelection.js` 单一归一化，CLI/REST/档案三路同源），筛光点位即硬拒并列出可用点位——0 点扫描不许伪装成「未检出」 | `tests/paramSelection.test.js` 19/19 |
| CLI 补接既有键 | `--retries`（0-5）/ `--http-timeout`（1s-60s）：引擎 `config.retry/timeoutMs` 与 REST 白名单早已有、CLI 一直缺入口 | 同上 |
| `--skip` 错位修复 | `buildConfig` 里 skipParams 映射嵌在 `csrfUrl` 块内——不配 `--csrf-url` 时 `--skip` **静默失效**（「传了没生效」红线；顺带踩实：缩进撒谎，`} ` 才是事实） | 同上（回归钉） |
| 配置档案 | `--config <file>` 预载（argv > 档案 > 默认，未知键硬拒）+ `--save-config <file>` 增量落盘可复扫（对标 sqlmap -c/--save + ffuf -config）。键注册表在 `bin/cli/configFile.js`（默认键 ∪ 动态键显式登记） | `tests/cli.configFile.test.js` 8/8 |
| AGENTS.md | AI 代理/CI 驱动契约：授权红线、CLI/REST 最小闭环、结果判读三陷阱、工程纪律（对标 dalfox/semgrep 的 agent-facing 文档实践） | 静态文档 |

### D42 已落地（2026-10-11，同日第二波）

| 项 | 内容 | 验证 |
|---|---|---|
| `--second-req <file>` | 二阶触发页整请求（对标 sqlmap 同名）：`-r` 同源解析器 → `secondOrder.triggerRequest {url,method,headers,body}`；`_trigger` 优先消费（幂等门 `resolveSecondOrderMethod` 照走、会话 cookie 合并照做），编排门与 URL 触发源并列；REST 闸 clamp + SSRF/scope 校验与 `secondUrl` 同级 | `tests/d42.sqlmapParity.test.js` 15/15 |
| `--ignore-code <codes>` | 忽略码不参与「拦截/会话失效/5xx」三本账（内容照常比对），按业务响应计账 + `counts.ignoredHits` 透出；`ScanValidityGuard.observe` 单缝 + scanRunner 透传 + CLI/REST | 同上 |
| `--randomize <params>` | 注入请求随机化指定参数（URL query/Cookie/请求头/表单伴随字段），注入点自身与传输关键头（Host/CL/CT/Authz/Cookie）永不随机化；JSON/XML body 不覆盖（诚实边界写在 help 与代码注释） | 同上 |
| `--dump-format` 接线 | `engine/dumpFormat.js` 四格式化函数与 27 条既有单测早已在、链路从未接通（Extractor 头部注释自证）——一键扫描产物层接通：有拖库数据时产出 `dump.<ext>`（csv 带 BOM 与 report.csv 同口径）；报告内嵌拖库区不变 | 同上 + one-click |
| `--verify`/`--no-verify` CLI 开关 | **勘缝发现第 1 条路线图项已被本仓超前实现**：`blindRobust.extractVerify`（每字节等值确认 + 完整值复验 + 失败重测，布尔/时间双通道，默认开）——本批只补 CLI 显式开关与文档口径 | 同上 |

**勘缝时的口径修正（防后人重复调研）**：ghauri `--verify` ≈ 本仓 `blindRobust.extractVerify`（更全）；
jSQL 多比特 ≈ 本仓 `blindBitwise` 位平面提取（8 位并行，MySQL/TiDB 族）；sqlmap `--charset`
思路 ≈ 本仓字符类收窄（cls-digits/cls-lower 探测）。这三条从队列销掉。

### D42+ 吸收队列（按 价值×可行性 排序；每批落地前先在 TODO 本节登记口径）

**检测可靠性族（ghauri 派）**

1. ~~**布尔/时间盲注字符复核 `--verify`**（ghauri）~~ —— ✅ **勘缝发现已被本仓超前实现**（`blindRobust.extractVerify`：每字节等值确认 + 完整值复验 + 失败重测，默认开），D42 只补了 CLI 开关（`--verify`/`--no-verify`）。
2. ~~**`--fetch-using=between/in`**（ghauri）~~ —— ✅ **已落地为 D50（2026-10-12）**：布尔+时间双通道 between 窄化，11 条判据 + 5 发缺陷注入全杀。上游归属已更正（ghauri 无此参数，见本节 D50 节）；`in` 不实现（IN 为假时无法定位区间）。
3. **多比特提取（jSQL Strategy 6）**：多值渲染目标 3 bit/请求。需先造「7 值 7 页」靶点，接缝同上。代价 M，价值 Med。
4. **时间通道动态基线**（BlindSQL）：每靶点先测 N 条基线 RTT，阈值=基线+k·σ，扫描中重标定。本仓 `autoDynamicBlock` 只管内容噪声，时延噪声还没有对偶物。接缝：time 探测标定段（`timeBlindCalibrate` 旁）。代价 S，价值 Med。

**发现/判定族**

5. ~~**wafw00f 式通用差分判定**~~ —— ⚠️ **勘缝发现大半已被本仓实现**：`WafIdentifier.activeProbe`
   本就是「良性 vs 恶意探针 → 状态码差分 → 拦截响应复用指纹 → 行为兜底」的 wafw00f 骨架，
   且 identify() 已带通用拦截页签名层（generic_block）。**D44 补齐了与 wafw00f 的剩余差距**：
   +xss/lfi 两向量（区分「SQLi 专项规则」与「全站拦截」）、Server 头差分（genericdetect 判据②）、
   **连接级阻断识别**（旧实现 `.catch(()=>null)` 把断连型 WAF 整个吞掉——真缺口，现重试一次后
   分类，防偶发抖动误报）、429 补进拦截码集、evidence 结构化透传；顺带补 `--active-waf-probe`
   CLI 旗标（扫描期主动探测此前只有 REST 入口）。未采纳：wafw00f 的 UA 差分（第④判据，需要
   再 +2 请求且国内设备命中率低，记为 non-goal）。
6. **backslash-powered 变换探针**（PortSwigger）：良性 vs 异常变换对（`\`、`\\`、`%00`、引号族）差分，先摸清服务端解码/归一化行为再选 tamper；顺带覆盖后端参数名爆破（差分响应）。接缝：prefilter 阶段前置探针族。代价 M，价值 High。
7. **参数名注入**（SQLiDetector）：注入点类型加「参数名本身」（列名/排序名拼接场景）。接缝：TargetParser `createInjectionPoint` 新 location + buildInjectionRequest 换位。代价 S，价值 Med。
8. **静态错误正则普查先行**（SQLiDetector 152-regex 形态）：error 通道前置一轮「1 payload × 正则库」的廉价相 0。本仓报错定库已强（`dbmsFromError` 带护栏），这条只做**排序**不做判定。代价 S，价值 Low-Med。

**OOB 族（对应本表 2026-10-10 盘点的 P1-3）**

9. ~~**interactsh 公网协作端客户端**~~ —— ✅ **D87 已落地并真机验证**（本机公网可达，未留未验证账）：`server/src/core/interactshClient.js`（零依赖手写协议，Node 内置 crypto + fetch；注册→轮询→AES-256-CTR+RSA-OAEP 解密→token 归因）；配置走 `config.oob.interactsh`，与 `oob.dnsOob` 并列；CLI `--oob-interactsh`。**整链真机**：`e2e/oob-interactsh-lab`（自带无回显靶站 → 真回连协作端 → 扫描器轮询取回 → 检出 1 条 OOB）+ 已接入 acceptance/run-all 与接线门禁；离线单测 `server/tests/interactshClient.test.js` 9 例（进 CI 常驻）。⚠️ 本批实测踩到两条**协议硬约束**，已写进源码注释与测试：① 首标签 = corrID(20)+nonce 必须 ≥33 字符（否则服务端滑窗匹配不到，表现为「偶发命中」）；② DNS 大小写不敏感 ⇒ 服务端记录恒小写，token（nanoid 含大写）必须归一化比较（否则「隧道通了却检不出」）。代价 M，价值 High。
10. **Collaborator-Everywhere 式普遍外带**：对所有未显式测的头/参数播撒 OOB 标记（非侵入），把 OOB 从 opt-in 通道变背景哨兵。依赖第 9 条先落地。代价 M，价值 Med。

**SQL 面补齐族（sqlmap 派，全部已核对本仓 args.js 确认缺位）**

11. ~~`--ignore-code <codes>`~~ —— ✅ **D42**（observe() 单缝 + ignoredHits 透出）。
12. ~~`--randomize <params>`~~ —— ✅ **D42**（buildInjectionRequest 出站随机化；JSON/XML body 不覆盖已如实标注）。
13. ~~`--second-req <file>`~~ —— ✅ **D42**（secondOrder.triggerRequest 全链路 + SSRF 同级校验）。
14. ~~`--dump-format` 接线~~ —— ✅ **D42**（一键扫描产物层接通 `dump.<ext>`；报告内嵌区不变）。
15. ~~`-b/--banner`、`--statements`、`--procs`、`-U <user>`、`--exclude <db>`：枚举面补齐~~ —— ✅ **D46**：
    三模式方言目录在 `extraction/sysQueries.js`（STATEMENTS_QUERY/PROCS_QUERY，全部硬上界
    20/100，SQLite 等结构性不支持方**诚实 null** 不回落 MySQL 语法）；`-U` 对 users/passwords
    做客户端聚合串过滤（双口径：用户段或完整 user@host 均命中；--privileges/--roles 只覆盖
    当前用户，-U 显式报错）；`--exclude` 与 excludeSysdbs 正交（点名排除优先）。钉在
    `tests/enumSurface.test.js`（9 条）。**诚实边界**：--statements/--procs 未在真机逐库验证
    （查询形态沿用 SYS_QUERIES 同族聚合惯用法，真机验证归 real-mysql-lab 下一轮）。
16. `--chunked`（Transfer-Encoding 分块发 body，WAF 不缓冲不检的真向量）、`--safe-post/--safe-req`（POST 保活）、`--load-cookies/--live-cookies`（会话接力）、`--crawl-exclude <re>`：各自代价 S，价值 Med。~~`--postprocess <file.js>`（响应侧解密，与 `--request-script` 对偶）~~ —— ✅ **已落地为 D52（2026-10-12）**：15 条判据（含 AES-CBC 随机 IV 模拟 oracle 的 killer 用例）+ 4 发缺陷注入全杀；真机验证待自建加密响应靶场。

**工程化族（nuclei/dalfox/ZAP/semgrep/trivy 派）**

17. ~~**原生 MCP server**~~ —— ✅ **D43**：`node cli.js mcp`（stdio NDJSON，零依赖），9 工具（run_scan/get_scan_status/get_findings/get_report/list_scans/stop/pause/resume/**preflight**），与 REST 同一条 sanitizeStart 白名单与 SSRF/scope 护栏；真靶场端到端 + stdio spawn 冒烟见 `tests/mcp.server.test.js`。AGENTS.md §4 已给宿主配置。
18. ~~**diff-aware CI 报告**（semgrep `ci` 语义）~~ —— ✅ **D45**：one-click `--diff-base <scanId|auto>`，
    diff 计算与 REST `/api/scan/:id/diff` 同源（scanDiff，键 location:param:technique）；
    新增发现 exit 2 / 存量仍在 exit 0 / 结论不可信或无基线 exit 1（不判红也不假绿）；
    产出 diff.json + manifest.diff。裁决语义钉在 `tests/diffGate.test.js`（9 条）。
    顺带修正 `docs/CI-集成.md` 一条陈旧断言（「官方 GitHub Action ❌ 尚无」——action.yml 早已在仓库根）。
19. **扫描计划文件**（ZAP Automation Framework 语义）：`--plan plan.json`（目标/认证/批次/阈值声明式可评审），配 autogen 模板与 schema。与 --config 的区别：config 是参数档案，plan 是**战役编排**。代价 M，价值 Med。
20. **发布信任链**：`release.yml` 上 SBOM + `actions/attest-build-provenance`（SLSA L2）+ cosign，README 写 `gh attestation verify` 验法。SEA 单二进制目前无第三方可验证来源。代价 M，价值 Med-High。
21. payload 包生态（nuclei-templates 形态：独立 packs 仓 + 安装器 + 校验门）、文档站（CLI 参考自动生成）、winget/scoop/brew 渠道、canary 通道、`--ai-triage`（AI 流水线扩展）：更后置，见工程化调研原文（本节只留索引）。

**明确不吸收**（与既有架构冲突，调研代理逐条点名过的）：MSF 运行时集成（--os-pwn/--priv-esc/--os-bof）、Windows 注册表族（--reg-*）、原生 `--eval`（红线：requestScript 的沙箱白名单架构）、GUI/TUI 向导（Web 面板已占位）、`--union-char/--no-escape`（P0-D3 高危区，args.js 已留拒绝提示）、Google dork 拉目标（ToS/脆弱）。

---

## 2026-10-10 新增 · 实战视角缺口盘点（渗透工程师口径）与批次 D32

盘点结论：工程纪律（门禁/真值链/口径）已足够厚，剩下的缺口集中在**入口层**——
「发不出合法请求」与「拿不到回调」，而不是检测算法。按「失效时是否让整场测试零产出」排序：

| # | 缺口 | 状态 |
|---|---|---|
| P0-1 | 加密/签名参数接口无扩展点（`sign=`、整参加密、timestamp+nonce） | ✅ **D32 扩展点 + 判据**，✅ **D34 真机闭环**（`e2e/signed-api-lab` 五场景三轮一致）；⚠️ 只覆盖**签名**形态，整包 AES / 防重放没有靶点（见本节第 7 条） |
| P0-2 | 认证只覆盖标准 HTML 表单登录（`loginFlow.js` 自承不做 OAuth/JWT 刷新/验证码/前端加密提交） | ✅ **D36 Bearer/Token 自动续期**（`bearerKeeper` + `--refresh-url` + 面板 + 真机 `e2e/bearer-lab` 六场景三轮一致）。仍不做：OAuth2 授权码流程 / SSO / 验证码 / 解析 JWT `exp` 做前瞻性续期（见下面 D36 节的账） |
| P1-3 | OOB 通道在真实目标上拿不到（`oobReceiver` 默认绑 127.0.0.1、DNS 需自建域+占 53；无 interactsh/Collaborator 对接） | ✅ **D87 已做**：`server/src/core/interactshClient.js`（零依赖手写协议：注册/轮询/AES-256-CTR+RSA-OAEP 解密）+ `core/oobTunnel.js`（本地/外部两拓扑统一抽象，检测器零分支）+ CLI `--oob-interactsh` + REST 白名单；整链真机 `e2e/oob-interactsh-lab` 实测通过。⚠️ 仍不做：自建协作端一键部署脚本、SMB 通道归因（UNC 走 DNS 通道，非 445 监听） |
| P1-4 | WAF 结论只有 CRS 一家（62 厂商指纹只做「识别」，推荐链无实测背书） | ⏳ 未做 |
| P2-5 | 写副作用无自动清理/回滚（只有 `docs/pentest-handover/05` 的人工条款 R5/R6） | ✅ **D90 已做**：`server/src/services/sideEffectLedger.js`（写前登记 + 撤销计划 + 自动清理）+ fileWrite 接入 + CLI `ledger side-effects` + REST `GET/POST /api/exploit/side-effects[/cleanup]`。⚠️ os-shell 类**不可逆**如实标注（不假装能清）；清理默认不自动执行 |
| P2-6 | 真实弱网下的召回衰减没有数（e2e 全跑本地回环） | ⏳ 未做 |

已在、**别再当待办推**的：批量 `-m`（含 Burp/HAR/Postman/OpenAPI 集合展开 + 共享限速桶）、HPP、
宽字节 `unmagicquotes`、multipart 收/发两侧、链接爬虫与 headless 爬取、csrfKeeper、SARIF/`action.yml`、
scope/SSRF 逐跳校验。

### D32 · 请求变换扩展点（P0-1）做完之后剩下的账

1. **⚠️ 没有真靶场证据。** —— ✅ **已补（2026-10-10 D34）：`e2e/signed-api-lab`**
   （真 SQLite + 真 md5 验签中间件 + 真 CLI 子进程，`deps: []` ⇒ CI 的 `e2e-self-contained` 自动收）。
   五场景 D/A/B/C/E 三轮逐字一致，实测表与结论见 `docs/请求变换脚本.md` §8。
   **阈值这两笔账的结果和预期不同，值得记**：
   · 原本想回答"8 / 2 该不该调"，实测回答的是"**这两个数不承载安全性**"——
     E 场景（正确签名 + 目标按关键字回 400）一次健康扫描里天然就有 **19 次**注入请求被拒，
     只数被拒条数的判据会当场误报；守住不误报的是 `injectOk===0` / `baselineOk===0` 那半边。
     ⇒ 8 / 2 保留，但角色改成"多快停手"（早停实测：C 用 11 条收摊，同目标健康扫描 83 条）。
   · 新增靶点时的前置检查（本批踩过）：**先确认 `prefilter` 不会把你的靶点判成"输入校验"**——
     第一版靶站用 `500 + {"error":"unrecognized token: X"}` 回显，两个靶点都被安全跳过，
     看着像"引擎 0 检出"，实际该修的是靶站（改成 sqli-labs 式 200 页内回显后即正常）。
   **仍未覆盖**：整包 AES 加密、timestamp+nonce 两种形态没有对应靶点（症状同、脚本写法不同）；
   `--request-script` 与 `--dbs`/`--dump` 等利用阶段的组合未测。
2. **`e2e/api-range-lab` 未加 `requestScript` 用例。** 接口靶场是这条链路唯一的「从 HTTP 入口进」
   的验证面；本批只在 `sm.start()` 一层测了失败闸门。
   验证口径：加两条 —— REST 传非法路径得 `code=6007` 且**不产生 scanId**；
   传合法路径且目标拒绝时报告 `summary.verdict='inconclusive'`（而不是 `no_vulnerability_detected`）。
3. **sqlmap 桥接侧没有等价能力**（同 §3 那批欠账的形状：内置引擎有、sqlmap 模式没有交付面）。
   需要定口径：`--eval` 是既有桥接参数、语义接近但不等价（`--eval` 只改 payload 字符串，不改整条报文）。
4. **面板字段无 UI 测试。** `ScopeSecuritySection` 新增的输入框没有组件级用例（前端契约测试只钉
   「面板键 ⊆ SCAN_CONFIG_KEYS ⊆ 后端白名单」，不钉渲染）。要么补一条渲染断言，要么按 §13 的
   口径明确记「UI 侧未覆盖」。
5. **`REQUEST_SCRIPT_DIR` 只做了目录包含判定，没做「脚本内容变更」留痕。** 台账里存了 sha256，
   但没有「同一个 scanId 的报告与脚本当前版本是否一致」的判据 ⇒ 事后改签名脚本，旧报告的 PoC
   可复现性无法证明。方向：把 sha256 与脚本副本一起进台账目录（体积要限）。
6. **注入点发现阶段的爬虫不经变换层**（D32 复核时发现，已写进 `docs/请求变换脚本.md` §7）。
   根因不是漏接线，是既有的客户端归属问题：`ScanManager` 构造时
   `this.parser = new TargetParser(this.httpClient)` 拿的是**模块级单例**，`LinkCrawler` 再继承它，
   调用时不带 `scanId` ⇒ 同一一路请求此前也**不受暂停闸与 per-scan 限速桶约束**
   （F1 那批修的是「经 `getScanClient` 的 ad-hoc 客户端」，这一路连 `getScanClient` 都不走）。
   后果：签名型 API 上 `--crawl` / `crawlForms` 爬不到东西（目标按非法请求拒），
   注入点发现只能靠 URL / `--body` / `-r` 抓包显式给出。
   改法（二选一，都要真机验证，别只让单测变绿）：
   ① 把 `TargetParser`/`LinkCrawler` 换成按 scanId 取视图（顺带把暂停闸与限速桶一起收进来，
      那是同一个断口的另一半）；② 不改，但在报告里把「发现阶段未签名 ⇒ 爬取结果为空
      **不代表**目标没有可爬的表单」写成显式标注。
   验证口径：带签名的靶点上，爬虫发出的请求必须**真的**带上签名（①），
   或报告必须能看见那句标注（②）；两者都没有就是第三个静默假阴性来源。
7. **只有签名形态的靶点，另两种症状没有**（D34 复核时明确）。—— ✅ **已补（2026-10-10 D35）**：
   `e2e/signed-api-lab` 现有三族（签名 / 整包 AES 字段级加密 / timestamp+nonce 防重放），
   加密族是「整个报文只有一个叶子是密文」的形状，防重放族带**靶站侧可证的防重放**
   （同一条合法报文连发两次，第二次必须因 nonce 被拒 —— 否则 A3 的"0 次复用拒"是白送的）。
   **本条挖出的真问题（比补靶点更值钱）**：加密族上 `transform_rejected` **永不成立** ——
   `validationGuardedSkipPoints` 的"输入校验甄别"会在 4 次同构 400 后把唯一的注入点剪掉，
   整轮只发 5 条请求 ⇒ `injectRejects` 永远到不了 8 ⇒ 结论照常落成「未检出」。
   即 D34 认定的"安全边际在 `injectOk===0` 那半边"这条结论，**前提是有足够样本**；
   单点 + 早剪的目标上判据不可达。
   修法（已做）：**启用请求变换时停用该剪枝** —— 在签名/加密目标上，
   "改一个字段连良性值一起被拒"恰恰是签名没覆盖/密文没重算的定义，不是输入校验拦截。
   差分单测钉住两侧（`prefilter.validation.test.js`：未启用仍 5 请求削减、启用则 2 探即保留）。
   ⚠ 没有降阈值来"修绿"—— 那会把 D34 的实测结论抹掉。
   **仍未覆盖**：`--request-script` 与 `--dump`（真拖数据）未测（本批只测了 `--dbs`/`--current-db`，
   SQLite 上 `--dbs` 语义本身不是重点，要回答的是"利用阶段的请求有没有被签名"，答案是拒 0 次）；
   防重放族的"nonce 复用 ⇒ 判被拒"只做了靶站自证，未做成扫描器侧场景。
8. **早停粒度是"点边界"，单点目标省不下预算**（D35 实测：`/api/tick?id=1` 单点时
   `transform_rejected` 成立后仍跑满 75 条）。`validity.shouldAbort` 只在
   `scan/detect.js` 的 scheduler 回调顶部判（每个点开始前），所以一个点内部无从打断。
   与 F1 那批"暂停只在点边界"是同一个形状。要不要给"签名被拒"加一层**通道边界**的早停
   （一个点内也有几十上百条请求，签名不匹配时全然是白烧）需要先定口径：
   验证口径 = 造一个单点加密目标，断言总请求数显著低于同形态健康扫描（现在这两个数是 5/86 与 75/83）。
9. **给 config 加键时，缺省值本身必须过一次入口校验**（D35 由 api-range-lab 抓到：
   `requestScript` 的"必须非空"撞上了它自己的默认值 `''`，而只有「单点重测/续跑」这类
   **配置回放**入口会撞上 —— 单目标扫描永远看不见）。
   现状：`configWhitelist.passthrough.test.js` 的探针值是**手写的合法值**，不测默认值。
   建议（未做）：给它加一条"逐键用 `defaults[key]` 再走一次 `sanitizeStart`"，
   这样任何"默认值与入口校验互相不认"在键写入当天就红，而不是等 e2e。
   已做的只是点状补测：`server/tests/requestScript.guard.test.js` 对这一个键钉了该性质。
10. **包装链上的三个会话层会把 `headRequest` 整个丢掉**（D36 做 bearer 续期时撞见，未修）。
    `withSafeUrl` / `withCsrf` / `withLoginFlow` 都 `return { request }`，**不带 `headRequest`**。
    而 `engine/scan/scanClient.js` 里两处都按"有没有这个方法"决定行为：
    `const baseHead = typeof view.headRequest === 'function' ? … : null`（协议层包装）与
    F1 那批加的暂停闸（`if (typeof view.headRequest === 'function')`）。
    ⇒ 只要配了 `--safe-url` / `--csrf-url` / `--login-url` 任意一个：
    · `--null-connection` 的 HEAD 通道**静默退化成 GET**（`detectorSupport/egress.js` 的
      `sendHead()` 有 `typeof httpClient.headRequest !== 'function' → 回退 send` 的兜底，所以不报错）；
    · F1 的"暂停期间零发包"承诺对 HEAD 路径失效（因为 HEAD 路径没了）。
    危害不高（方向是"多发 GET"不是漏测），但形状是本仓最典型的一类：**能力没了而没有任何东西变红**。
    修法：四个会话层包装（含 D36 新增的 bearer 续期）统一返回 `{ ...client, request, headRequest }`，
    且 `headRequest` 必须走**同一套**加工（csrf token 要挂上、bearer 头要挂上、401/403 同样续期
    一次并重试）—— 只把方法名透传过去等于 HEAD 绕过加工，比现状更糟（现状是 HEAD 不存在、
    退回带 token 的 GET）。
    验证口径：① 三个开关各配一个，断言 `getScanClient(...).headRequest` 是函数；
    ② 断言 HEAD 实收参数里带着 csrf token / bearer 头（从内层视图捕获比对）；
    ③ `--null-connection` + `--csrf-url` 在真靶站上仍能检出（这条组合现在是静默降级）。

    ⚠ 状态更新（2026-10-10 D36）：**第四个包装（bearer 续期）没有复制这条缺陷** —— 它保留并加工
    `headRequest`（`bearerKeeper.test.js` / `bearerKeeper.wiring.test.js` 各钉一条，
    把 `typeof client.headRequest === 'function'` 改成常量会当场红）。
    所以本条现在只剩**三个旧包装**，修法不变（一起改，别留一条不一致的路）。

### D36 · Bearer/Token 自动续期（P0-2）做完之后剩下的账

1. **`--login-url` / `--csrf-url` / `--safe-url` 三个包装仍丢 `headRequest`**（就是上面第 10 条，
   本批只保证新增的那个不丢）。危害方向是"HEAD 静默退化成 GET"，不是漏测。
2. **面板只暴露三个子键**（`url` / `tokenField` / `refreshToken`）。`bodyFormat=form`、
   `body={client_id…}`、`headerName` / `headerTemplate`、`eager` 这五项目前只能走 REST/CLI。
   判据要不要接：`eager` 与 `bodyFormat` 是"目标形状"而不是"调优旋钮"，缺了它们那类目标配不上；
   接线成本是 NetworkAuthSection 再长一截 + `scanConfigSections.bindings` 各补一条。
3. **`expiredMidScan` / `neverAuthenticated` 都不中止扫描**（只降级结论）。
   与 `transform_rejected(kind=baseline)` 的区别是刻意的：后者"我们自己发出的东西不合法"，
   继续跑注定零产出；前者可能只是某个点位需要认证，其它点位仍可能是公开的。
   要不要加一条"整轮零业务响应即中止剩余点位"的预算闸门，需要先拿到真实分布
   （目前只有靶场里 71 条请求这一个样本，不足以定阈值）。
4. **`neverAuthenticated` 与 `blocked` 的分界靠"403 算业务响应"这一条约定**。
   用 403 表达令牌过期的目标（不少网关就是这么干的）落点是 `blocked` 而不是 `session_expired`，
   本批只在 `blocked` 的 advice 里加了一句指向续期的话。**更彻底的做法**是给 `blocked` 也做
   成因分支（WAF 特征 vs 令牌过期），但那要先有能区分的证据位（比如响应体里的
   `error="invalid_token"` / `WWW-Authenticate` 头），目前没实现。
5. **JWT `exp` 的前瞻性续期没做**（只在收到挑战后续）。文档里给的出路是 `eager: true`
   或自己写 `--request-script` 现算 —— 后者其实能覆盖，但需要脚本自己判 `r.url` 并给
   `/oauth/token` 也签名，这条组合没有靶点（signed-api-lab 与 bearer-lab 是两个靶场，
   没有"签名 + Bearer 续期"同时开的场景）。**这是本批留的最实在的一条空档**。
6. **`e2e/bearer-lab` 没有 `--request-script` 组合场景**（同上）。接线级证据有
   （`bearerKeeper.wiring.test.js` 钉了"续期请求也过变换层"），真机级没有。
7. **凭据有效期与扫描规模的关系没有量化输出**。报告会说"续期尝试 N 次失败 M 次"，
   但不会说"这轮扫描跑了多久、令牌在第几条请求失效"。交付时甲方问"你们的扫描会不会
   扫到一半掉登录"，现在只能靠 reason 文本反推。方向：`summary.validity.counts.refresh`
   已经在了，缺的是首次挑战发生在第几条请求（一个 int 就够）。
8. **`bearerRefresh` 没进 `docs/api.md` 的 `/scan/start` 示例**。核对过：api.md 里连 `login`
   都没有（`grep -n "login\b" docs/api.md` = 0 命中），所以这不是"本批漏了一条"而是
   **整张 config 键表在 api.md 里不存在** —— 现在的口径是"键的用法在各专题文档里"
   （`docs/Bearer令牌续期.md` §3 有完整 REST 形状与子键表）。要补的话应该补一张
   「config 键 → 所在专题文档」的索引表，而不是往示例里塞一个键。
   `refs:check` 只钉链接有效性，钉不住"新键有没有文档"。


## 2026-09-28 新增 · 接口靶场（`e2e/api-range-lab`）暴露出的待办

背景：新建的「HTTP 接口 × 真实靶场」套件（44 条用例 / 26 个端点）一轮就抱出 9 条接口层缺陷，
已随本批修复（详见 CHANGELOG 同日批次）。以下是**故意留在后面**的项，每项写清验证口径。

1. **History 页仍读浏览器 localStorage** —— ✅ **已修（2026-09-29）**：改为
   `useServerHistory()`（`src/hooks/useServerHistory.ts`）拉 `GET /api/scans`，经
   `shared/historyMerge.ts` 做「服务端 ∪ 本地」合并（同名条目服务端胜出做展示，**但保留本地
   快照引用** —— 续跑要读 `report.target.config`，服务端清单里没有报告全文）。
   来源以 Chip 明示：`服务端` / `进行中` / `仅本机`，改造后不再出现"换台机器历史就空了"。
   服务端取不到时**退回本地列表 + 如实提示**，不允许比改造前更差的白屏。
   顺带把服务端清单缺的 `riskLevel` 补上（台账 meta 新增 `highestRisk` 字段；老台账没这个字段
   ⇒ UI 显示"风险未知"，不猜不兜底 `Low`）。
   纯服务端条目不给删除按钮 —— 服务端没有 DELETE 端点，给了按钮点了没反应等于骗人。
   测试：`src/tests/historyMerge.test.ts`（7 条）+ `historyServerSource.test.tsx`（4 条）。
   **缺陷注入 3/3 杀**：组件不接服务端数据 ⇒ 3 条红；`riskLevel` 兜底成 `'Low'` ⇒ 2 条红；
   丢掉本地快照引用 ⇒ 1 条红。
2. **`/exploit/capabilities` 是手写清单** —— ✅ **已修（2026-09-29）**：新增 `capabilityIndex()`
   （`Exploiter.js`，由 `TAKEOVER_CAPS` 反向索引），路由改为 `...capabilityIndex()` + `matrix`，
   手抄数组删除；前端类型补 `matrix` / `enabled`。
   验证口径达成：`server/tests/exploitCapabilities.test.js`（5 条）—— 接口返回值必须逐条等于
   推导结果、推导与方言表双向自洽、关键能力钉真值、源码不得再手抄清单。
   **缺陷注入 2/2 杀**：关掉 `MySQL.fileWrite` ⇒ ③ 红；改回手写数组 ⇒ ①④⑤ 红。
3. **sqlmap 侧缺 `--file-write`，且 `/sqlmap/:id` 没有 diff/export** —— `capabilities.fileWrite`
   声明的是内置引擎的能力，走 sqlmap 模式拿不到同一交付面。
   验证口径：接口靶场在 `sqlmap.available=true` 的机器上补两条正向用例（真写文件、真导出）。
4. **暂停对两支 ad-hoc 客户端仍不生效**（`server/src/engine/scan/detect.js:478` tamper 链验证、
   `:505` 拦截驱动重跑）—— 它们绕过 `scanRunner` 的 ctxBase 包装直接 `getScanClient`。
   本轮把它们包进 `_wrapWithSignal` 会打断 `detect.orchestration.test.js` 的 fake-sm 契约
   （该测试断言客户端身份），故**保留原状**。
   验证口径：把暂停闸收到 `getScanClient` 返回视图上，同时让接口靶场的暂停用例对
   "开启 wafEvasion 自动选链"的目标也断言零流量；并复跑 orchestration 契约。
   —— ✅ **已修（2026-10-03，批次 F1）**：暂停闸下沉到 `getScanClient` 返回视图本身
   （request 与 headRequest 都过闸，`scanClient.js`）—— 不动 detect.js，orchestration 契约
   零改动，branches 测试的 fake 补 `_waitWhilePaused` no-op（契约显式建模）。
   验证三件套：① 单测 `scanClient.pause.test.js` 4 条（paused 挂闸 / HEAD 过闸 /
   cancelled 放行 / 源码钉住 ad-hoc 必经 getScanClient），缺陷注入杀；② 接口靶场新增
   `/wafnum`（只拦原始签名、放行 tamper 变换形态 —— 全拦光会让引擎「跳过自动重跑」、
   重跑根本不发生）+ 事件锚定用例（SSE 第一发 `point_testing(tamperRetry:true)` 后暂停，
   断言重跑路径零发包），16/16 PASS；③ 靶场级缺陷注入复验：撤闸重跑 ⇒ 该用例红（15/16）。
5. **台账无保留策略** —— ✅ **已修（2026-09-29）**：新增 `pruneLedger()` / `retentionPolicy()`
   （`server/src/services/scanLedger.js`），`SCAN_LEDGER_MAX`（条目数）与
   `SCAN_LEDGER_MAX_DAYS`（天数）可叠加，两维都未设 ⇒ **零淘汰**（默认值必须是不删东西）。
   `recordScan()` 写完后自动收敛一次；CLI 新增 `ledger prune --max=<N> / --days=<N>` 手动入口
   （无策略时 exit 2 拒绝执行）。
   **顺序刻意是「先原子重写索引、再删目录」**：看失败模式定的 —— 反过来的话，目录删成功而
   索引重写失败 ⇒ 列表里有、点开 404（半份数据，最坏）；现在的顺序下，索引已收敛而目录删除
   失败 ⇒ 磁盘泄漏 + 一条孤儿目录，列表干净且可重试。
   顺带治掉 `appendFileSync` 造成的**重复登记**（同 scanId 多行 ⇒ 列表出现两条同名条目）——
   重写索引时按 scanId 收敛成最新一行。
   测试 10 条，判据不采信 `pruneLedger` 自报的 removed，全部外加外部事实断言（目录存不存在、
   索引行在不在、`readReport` 是否真的返回 null ⇒ `/scan/:id/report` 走 404）。
   **缺陷注入 6/6 杀**：只删索引不删目录 / 不重写索引 / 缺时间戳伪装成最新 / 天淘汰方向反 /
   切断 recordScan→prune 接线 / 早退跳过去重 —— 各杀 1~5 条。
6. **`docs/api.md` 不在自动门禁里** —— ✅ **已修（2026-09-29）**：`readme-consistency.mjs`
   新增判据 **⑭b**，把 api.md 的 `#### \`METHOD /path\`` 标题集并入同一把尺子（判据会自动补
   `/api` 前缀、剥掉查询串）。**首跑即抓到 4 个真缺口**：`POST /scan/:id/pause`、
   `POST /scan/:id/resume`、`GET /scan/:id/diff`、`POST /exploit/sql` 都已上线但文档没写，已补齐。
   **缺陷注入 2/2 杀**：删掉 pause 标题 ⇒ 报漏写；加一个幽灵端点 ⇒ 报"不存在"。
7. **采集脚本与并发改动互相踩** —— ✅ **已修（2026-09-29）**：`--refresh` 现在在跑测试**前后各取一次**
   采集源指纹，不一致即报「**采集期间文件被改动，本次结果不可用**」+ 点名被改/新增/删除的文件，
   并**拒绝写盘**（不留下一次没人能复现的采集），退出码 1。
   实现：`scripts/facts-sync.mjs` 新增 `diffDigests()`（纯函数）+ `--selftest`（5 类形态自证），
   CI lint job 已加这一步。
   **真实验证**：采集到第 40 秒改 `server/tests/exploitCapabilities.test.js` ⇒ 报「被改（1）」+ EXIT=1 + 未写盘。
   ⚠️ 实验时先拿 `docs/api.md` 试了一次，**它不在指纹源里**（指纹源只有测试文件）⇒ 判据当然不报 ——
   验证前先确认改动对象真在指纹源里。
8. **`ciWindowsOnly` 登记表用行号做锚点，一天内漂了两次**（177→182→186、216→221→254），
   每次都要靠"自证③"红一遍才知道。改法：登记键换成**内容锚点**（如 `file:片段前 40 字符:kind`），
   或让守卫在报"登记项失效"时直接给出该 kind 当前的真实行号，省一次人工 grep。
   验证口径：在 `e2e/run-all.mjs` 顶部插 10 行注释 ⇒ 守卫应仍然通过（内容锚点不随行号移动），
   而删掉那两条 Windows-only 行 ⇒ 守卫必须红。
   —— ✅ **两种改法都已落地（2026-10-10 D34，内容锚点为正解）**。触发点是第四次漂移：
   本批只是**往 run-all 的 LABS 里加一个靶场**（+7 行）就把三个键全顶歪
   （152→159、225→232、318→325）—— 而这恰是最常见的正常操作，说明"每次上游插入都靠人记得核对"
   本身就是判据失效的形状。
   新键 `path:kind:内容锚点`（整行去空白后前 60 字符）；键由 `regKey()` 生成，
   登记表头写明「别手抄、别用行号」。同时把 §8 的两条验证口径变成**长期断言**（不只是文档里的期望）：
   · `自证⑤`：合成文件顶部插 10 行注释 ⇒ 同一处仍被豁免且登记项不陈旧；删掉命中行 ⇒ 登记项必须报「已不存在」。
   · `自证⑥`：同一锚点命中 2 行 ⇒ 必须报错（一张免检牌不许盖多处，否则新加的违规被静默放过）。
   · 真机复验（用一次性变异器跑完即还原，逐次断言替换命中数=1 且字节还原一致）：
     往 `run-all.mjs` 真加一行未登记的 `.exe` ⇒ ① 红；顶部真插 10 行注释 ⇒ 7/7 仍绿。
   —— ✅ **第二条改法已做（打印真实行号）；本条仍未结**：2026-10-10 复核又漂了**第三次**
   （195→225、263→318，外加 D30 新增的 152 一处未登记），已按真实行号重新登记并逐条核过代码
   （existsSync 前置 / 候选列表含 PATH 上的 python / `process.platform==='win32'` 守卫在上一行）。
   ⚠️ 值得记的是**它为什么没在 D30 当轮红**：`run-all` 不在 acceptance 的收敛集里，
   要等下一次全量服务端套件才撞上 —— 那时看着就像"新改动引入的"。
   ⇒ 内容锚点（第一种改法）仍是正解：行号锚点每次上游插入都要人记得去核对，这本身就是判据失效的形状。

---

## 2026-09-28 新增 · 真机 WAF 对拍（真库化后）的三个待办

背景：`e2e/waf-real/modsec-live.mjs` 已从「放行率」升级为**「打穿率」**（靶站接真 MySQL，
同一条样本要同时满足过 WAF **且** SQL 真执行并吐出证据）。CI run #97 首次出数，
数字与边界见 `docs/WAF-真机对拍-2026-09-28.md`。

1. **扩样本集** —— ✅ **已完成并取证（2026-09-28 第三轮，CI run #101/#102）**。
   根因定位：不是 WAF 强，是**样本与靶站形态不匹配** —— 靶站只有 `WHERE id = ${raw}`
   （数值无引号），而样本多为字符串上下文写法，拼进去是语法错误 ⇒ 只能算「抵达 SQL 层」。
   改法：样本自带 `ctx`，`CONTEXTS` 作为拼接模板单一来源，注入点扩到 3 种
   （`id = ${raw}` / `name = '${raw}'` / `id IN (${raw})`），样本 8 → 15 条，
   判据收紧为「报错也必须有注入标记」，CI 加 `MODSEC_MIN_UPPER=4` 闸门。
   **CI 实测：直连上界 1/8 → 7/15（闸门通过）；真机打穿 1 个（`unionvaluesrow` 2/15，
   其直连上界 7/15 ⇒ 2/7）；放行 PL1 24 / PL3 23；0 误拦。** ⚠️ 分母仍只有 7 ⇒ 依旧禁止
   对外声明绕过率。详见 `docs/WAF-真机对拍-2026-09-28.md` 第六、七节。
2. **查明「74 → 8」** —— ✅ **已结案（结论是「不许引用」，不是「查明了成因」）**。
   复查只拿到后两轮的报告产物（均为旧 8 条样本、上界 1/8、放行 8），**首轮（74/72）的产物已不在**；
   三轮之间样本集、镜像 digest、PARANOIA/阈值、放行判据（`status >= 400`）全部一致，
   剩下的唯一差别（靶站 echo vs db）又被第三轮数据证伪 —— `encode2hex` 在 db 靶站上必然产生
   MySQL 语法错误响应却仍 15/15 放行 ⇒ 出站数据泄漏规则（CRS `RESPONSE-951`）在本镜像下未生效。
   ⇒ **74 既不能复现也无产物佐证，两轮的放行数都不许引用**（README 已就地标注）。
   若日后要定性：在**同一次 CI 里并排跑首轮脚本版本与当前版本**，不要拿历史数字互相减。
3. **真机 × 真库 × 真实框架** —— ✅ **已做掉一半（2026-09-29 第四轮，CI 已取证）**：
   注入点从 3 种（WHERE 等值/枚举）扩到 **5 种**，补上搜索页 `LIKE '%q%'` 与列表页排序
   `ORDER BY ${sort}`（两者逃逸前提与前三种完全不同；PHP/Python 的差别只在字符串怎么拼，
   落到 SQL 是同一句 ⇒ 按 **SQL 拼接位置**划分而不是按语言）。
   **CI 实测：上界 7/15 → 10/19；新形态 4 条打穿 3 条（含 `ORDER BY` 的报错取数）；
   真机打穿插件仍只有 1 个 ⇒ 形态变多 ≠ 绕过链变多。** 详见
   `docs/WAF-真机对拍-2026-09-28.md` 第八节。
   ⏳ **剩余（下一步该做的方向）**：① 提「打穿链数」而不是再加形态 —— 现在分母已有 10，
   但过 WAF 的链只有 1 条，这是链侧能力问题，加形态解决不了；② 若要继续扩形态，
   剩下的候选是 `LIMIT ${raw}`（分页，`PROCEDURE ANALYSE` 在 MySQL 8 上是否可用需先验证）
   与 `HAVING`/`GROUP BY` 位置，价值与请求量要一起权衡。

---

## 2026-09-18 批次 · 定库与检出链路的回显污染（已修，留此防回归）

已修内容见 CHANGELOG「[Unreleased]」与 README「P1-F / P1-G」。这一批**没有新增任何能力**，
全部是把「已经在报『未检出』的地方其实根本没发对请求」挖掉：
r2 档黑盒 9/13 → 13/13，A3-like 从 time 变 union+boolean。

本批实测顺手暴露、**尚未处理**的四项（按性价比排序）：

### A. P1-D 的真实危害面比「20 处冲突」这句话更具体（H2 已修，余下待办见文末）
`node e2e/blackbox-lab/check-dbms-sig.mjs` 报 20 处 sig 冲突，其中**可执行**的那几条才是真风险
（冲突要成立，前提是「A 库的版本函数在 B 库上也能跑」）：
- `MySQL.sig = /^\d+\.\d+\.\d+(?!.*MariaDB).*$/` 会吞掉任何「裸三段版本号」回显 → 若别家库的版本串
  能从 MySQL 那条探针回显出来，就会被定成 MySQL（payload 族整体错配）。
  **但 2026-09-19 的真引擎实测把这条降级了**：MySQL/MariaDB/PG/TiDB/ClickHouse 五条探针各自带的 WRAP
  （`CAST(x AS CHAR)` 等）在 H2 / HSQLDB / Derby 三台上**全部报错、无标记回显**（18/18 echo=N），
  所以「MySQL 抢走别家裸版本号」在这三台上不可达。其余库（真 PG/CH/MSSQL）未测，不作断言。
  （H2 原本也被列进这条，实测**不成立**：H2 根本没有 `version()` 标量函数，见下方撤回。）
- `Sybase.sig = /(Adaptive Server|Sybase|ASE)/i` 的 `ASE` **没有词边界**，
  Oracle 的 banner「Rel**ease** 19.0.0.0.0」直接命中 —— 与 L46 那次 `Server: BaseHTTP` 含
  "ase" 误判 Sybase 是同一个坑（那次只修了 `FINGERPRINT` 头签名，DB_VERSION 与报错签名两处没同步）。

**2026-09-19 补（含一次撤回）：这条已从"理论冲突"进到实测，但我当时的归因是错的。**
先更正：我写过「H2 的 `version()` 返回 `2.2.224 (2023-09-17)` 命中 MySQL 的裸版本号 sig → 真 H2 被定成
MySQL」—— **这句是错的，实际测到的是定库失败（dbms=null），不是定成 MySQL。** A/B 数据（真 JDBC 内存库
H2 2.2.224，`{waf:false}` 才跑得通，见下）：
- 修复前（H2 在遍历末尾 + `func:'version()'`）：18 条探针**全部** `echo=N` → `dbms=null`。
  原因：H2 没有 `version()` 标量函数，而 MySQL 系 WRAP 用的是 `CAST(x AS CHAR)`，H2 直接报错 → 无标记回显。
  也就是说「MySQL 抢走 H2 版本串」这条路径在这台真 H2 上**根本不可达**，我把它当成了观测结果。
- 修复后（H2 前置 + `func:'H2VERSION()'`）：`verFp H2 echo=Y 取到值="2.2.224" sig命中=true` → `dbms=H2`。
- 反向确认（真 MySQL 8.0.28，blackbox-lab r2 三点）：`A1-numeric / A3-like / C2-blindtime` 全部
  `dbms=MySQL`、3/3 HIT、0 误报 —— 前置的 H2 条目不会抢 MySQL。

**已实施**（本批）：`server/src/engine/payloads/index.js` 的 `DB_VERSION.H2` 换成 exclusive 的
`H2VERSION()` 并排到 MySQL 之前（与 `extractionMaps.js:408` 早已用 `H2VERSION()` 对齐）；单测侧把
「假引擎能执行哪些探针表达式」显式建模（`boundary.echoTarget.test.js` 新增正/反两条 exclusive 守卫，
`fingerprint.mariadb.test.js` 的 mock 加 `supportedFuncs`）—— 不给这层，mock 等于「谁探测都回同一个
版本」，会把真实判据（跑不动 → 无回显）抹平，这正是刚才那次错误归因的来源。

- **验收口径（部分已达）**：真引擎 A/B ✅、真 MySQL 回归 ✅、相关单测 58/58 ✅。仍欠两条：
  1. `check-dbms-sig.mjs` 的 20 处冲突是 **sig 层**口径、不等于运行时误判数（脚本头已写明口径边界）；
     要报「可执行冲突」得补跨库可执行性矩阵，尚未做。
  2. 本批新暴露：`e2e/multi-engine-lab` **默认开着 CRS**，UNION 哨兵探针整条被 403 →
     版本回显定库通道在该靶场上从未执行（这就是为什么它"没现形"）。要么给 `verify.mjs` 加一档
     `waf:false`，要么在报告里写清"本靶场只覆盖 boolean 通道"。
  3. 同批实测：HSQLDB / Derby 两台在**关掉 WAF** 后仍 `18/18 echo=N → dbms=null`，即这两台的版本回显
     定库整条失效（各自的 WRAP/伪表问题，与 H2 无关）。README 的分层措辞（「3 种部分通道验证」）不用改，
     但"这三家的**定库**都可用"不成立：三台里只有 H2 现在能被版本回显定库。

### B. `binaryProbe` 的 `capped` 在长度链路上被忽略（**已修，2026-09-20**）
`docs/统一探测判据-设计.md` 3.3 明确要求「拿到 capped=true 不得当正常结果用」；
`engine/blindExtractor.js` `_binarySearch` 原先只 `return r.n + 1`，把 `r.capped` 丢了。

**修法（比原计划的「直接判失败」多一层，因为一刀切会打死正常长值 —— 实测挂了 2 个用例）**：
「顶到上界」有两种成因，探测层面无法区分，必须分层裁决：

| 位置 | 顶到上界的含义 | 处置 |
|---|---|---|
| 主段（hi=255） | 可能只是真实长度 ≥256（合法信号） | 只打 `ctx.blindLenCapped` 标记，交 `_extendLength` 预检 `>255` 裁决 |
| 延伸段（hi=maxLen，用户**显式**配了 `blindMaxLen`） | 用户已授权「最多提这么长」 | 按 maxLen **截断**提取（旧行为不变） |
| 延伸段（hi=maxLen=默认护栏 4096） | 用户没授权过这么长 → 判据失效 | **判失败**（-1 → 该字段提取返回 null） |

失败原因经 `ctx.blindLenCapped` 上浮，由 `scan/extract.js` 写进 `report.summary.constraints`
（「盲注长度探测失败：二分顶到上界 N 且响应差异不可区分」）—— 让「没提取到」不再被读成「目标没数据」。

**验证**：新增 `server/tests/blindLenCapped.test.js`（3 条）。缺陷注入（撤销延伸段终审）→
**只有第 1 条红**，且实际值是一整串 4096 个垃圾字符（直观展示伤害），另两条（显式
blindMaxLen 截断 / 真长值 300 字节延伸）仍绿 —— 三条各测一面，不是一红红一片。

### C. `--test-path` 的闭合候选在 404 段上是噪声（✅ 已修 2026-09-20）
实测 `/api/sleep` 开 `--test-path` 时，path 点拿到 boundary `%"` —— 13 个候选的响应全是同一张
404 页（Express 回显 URL），剔除回显后仍偶有同形判定。path 点本身没洞无所谓，但它会**触发**
整轮指纹/列数探测（每次 ~40 请求）。修法方向：path 点基线为 4xx 时不投放闭合探测（或指纹
提前 bail），既省请求也少一份误判来源。

**✅ 已按此方向修（`Detector.probeBoundary` 基线请求后早退）**：
- **语义论证**：闭合前缀回答的是「怎么跳出 SQL 字符串字面量」，前提是该路径**真的执行了 SQL**。
  路径不存在时后端没路由到查询代码，候选拿到的只是同一张错误页 → 噪声 boundary
  → 触发整轮指纹/列数探测打在一条不存在的路径上。**真存在注入的路径不会是 4xx**
  （要么 200 要么 5xx 报错），故早退不影响任何真实检出。
- **口径**：`kind==='path'` 且 `400 ≤ status < 500`，但**排除 401/403/429** ——
  鉴权/封禁是「路径存在但本次不带凭据」，限流是「稍后可能通」，都不等于路径不存在。
- **留痕**：写入 `point.boundarySkipReason`，报告/排障可解释「这里为什么没探测」。
- **验证**（`tests/boundary.echoTarget.test.js` 新增 4 条，全绿 9/9）：
  · 正向：path+404 → **只发 1 次基线请求**（旧行为 1+13），boundary 回退空串 + 留原因；
  · 反向：path+200 → 照常投放（不误伤真实路径点）；
  · 边界：401/403/429 不跳过；非 path 点（url/body/cookie/header）404 也不走此早退。
- **缺陷注入验证**：临时把早退条件改成恒 false → **只有正向那条变红**（8 pass / 1 fail），
  其余 8 条仍绿 → 证明测试真的钉住了该行为，而非陪跑。

### D. 靶场侧缺陷（✅ 已扫完并修复 2026-09-20）
`e2e/blackbox-lab/lab-app.mjs` 的 `/api/profile` 对 Cookie 值做 `decodeURIComponent`，收到
`%'` 这类非法转义就在 **async handler** 里抛 URIError → Express 4 不捕获 async 异常 →
该请求**永不应答**，把 D3 的整个测段拖成分钟级停顿（真值标定用 `uid=1` 碰不到，所以一直没暴露）。
已加 try/catch 并注明「改的是靶场不应无端挂连接，SQL 拼接形态一字未改」。

**✅ 2026-09-20 全仓扫完 —— 原「待办」的 4 个靶场经实测全部无需修改，但扫出另一处真中招**：

- 原点名 4 靶场实测**都已有防护**：`redteam-lab:190`、`pentest-lab:72` 都是
  `try { decodeURIComponent } catch { 保持原样 }`；`real-mysql-lab` 零 decode；
  `multi-engine-lab` 仅 `JSON.parse` 且已包 try。**「同一形态」这个预判不成立。**
- **真中招的是 `e2e/redteam-lab/lab-app.mjs` 的 `/shop/semi`（D15 靶点）**：
  4 处 `decodeURIComponent` **裸调**（同文件 187 行已备好 `decodeSafe` 却没接上——写了工具没接线）。
- **实测表现比原描述更微妙**：不是"永不应答"，而是被外层 `run()` 的 try 兜成
  **500 + `SQL_ERROR: URIError` 回显**。危害在于——D15 真值是 `tech=union`（测 `--param-del`
  切分），返回的却是「数据库报错」，**靶场亲手给扫描器的 error 通道喂了假信号**。
- **修法**：改用 `decodeSafe`（与 187-191 行既有容错语义一致；真实站点只认分号时也不会
  对已切好的片段二次 decode，失败即用原值）。
- **验证（实测报错文本变化）**：
  | payload | 修复前 | 修复后 |
  |---|---|---|
  | `id=1%` | `URIError` | `MySQL syntax ... near ''`（真 SQL 信号） |
  | `id=1%zz` | `URIError` | `Unknown column 'zz' in 'where clause'` |
  `URIError` 彻底消失，全部转为真实 MySQL 报错。
- **顺带实测的有效能力**：扫描器对不可达目标（155 次请求全无响应）正确给出
  `validity.status="unreachable"` + `reliable:false` + 具体 advice，**拒绝输出阴性结论** ——
  这是 `scanValidityGuard` 的真靶场级正面验证。

### E. 本轮**未跑**的门禁（诚实记录）
`npm run acceptance`（11 套件）没有整跑：`e2e/acceptance.mjs` 与多份 `results/*` 是另一批次
未提交的在制品，跑一次就会覆盖它们的产物、把两批改动混进同一份报告。
本轮实跑到的门禁：服务端全量单测（1885 用例 0 fail）+ 前端 315/315 + `tsc` 0 错 + eslint
0 error + blackbox-lab 两轮 + redteam-lab R1/R2。合入前请补跑 acceptance 一次。

**（2026-09-19 更新）这条已经不再成立**：那批在制品提交后（`381afdb`）acceptance 在本机连跑 3 次
—— 2 次 `11 PASS / 0 FAIL`，1 次 `10 PASS / 1 FAIL`（失败的是「服务端单测」里的 1 条用例，
单独连跑 4 次不复现，属偶发；失败现场当时没留下 → 已改为失败即落盘 `e2e/results/last-failure-<id>.log`）。
同一天还按 ci.yml 的 job 顺序做了本机等价全量跑（`npm run ci:local`，17 段：15 PASS / 1 FAIL / 0 SKIP，
唯一稳定红的是 G 条那个 concurrent-isolation）。

### F. README 的 WAF 绕过口径已经过期（**已重定为 8/8 并定位到规则号**，2026-09-19）
README 原写 2026-09-10 复测的 **tamper off 2/5 → on 10/5 技术位**、自动路径 **11 技术位**。
本批整跑 acceptance 一次 + 单独复跑两套件一次，两次都是 **on=8、auto=8**。量纲也修了：
`N/M` 那个分数把「技术位合计」和「场景数」混在一起（README 于是抄成「10/5」），现打印
「技术位合计 8（5 个注入场景，每场景可有多个技术位）」，`acceptance.mjs` 的解析同步跟上；
`waf-auto-check.mjs` 里写死的「人工 dash2hash 基线 = 10」改成从 `waf-real-report.json` 现读
（写死的对照数不会随被测代码变化，等于长期说谎）。丢的两格都在 `num` 与 `blind` 的 union。

**归因（逐条手工发探针：真 MySQL 8.0.28 × CRS，规则号可复核）**：

| 探针 | 结果 | 规则 |
|---|---|---|
| `1 ORDER BY n-- -` | 403 | 942460（4 连非词字符） |
| `1 UNION SELECT NULL,…`（尾 `-- -` / `-- ` / `#` 三形态都试） | **全部 403** | **942190**（PL1，`union\s*select` 短语）|
| `1 UNION SELECT 'SQLISCANNER…'` | 403 | 942200（单引号字面量） |
| `alice' UNION SELECT NULL,…#`（字符串上下文） | **200** | 未命中 |

> **[修正 2026-09-20]** 第 2 行原记「942361」，**归因有误**。四版探针（见 I 条）逐格复核后确认：
> 拦住数值点 union 的是 **942190（PL1）**，不是 942361（PL2）。942361 是 CRS 里更**松**的兄弟规则，
> 判据是「起始形状」，而 942190 判的是「union↔select 相邻」，后者更早生效、覆盖面更大。
> 这个修正影响到当时的猜测链（见下），但**不影响本条结论**（两格确实丢在 WAF 层）。

即：**同一条 UNION 探针，数值上下文被 942190 拦、字符串上下文放行**；而 `dash2hash` 只规整尾部注释符，
对 942190 无效。所以这两格不是"判据判错"，是**请求在 WAF 层就到不了数据库**。
本批改动已排除（把动过的 4 个引擎文件回退到 `ebc660a^` 重跑，结果逐字相同）。
至于 09-10 那次为什么算进过 10：`e2e/waf-real/results/` 不入库、旧报告没留档，**已无从核对**；
原有一条猜测（链含 `space2comment`，`/**/` 拆开相邻性）**已被 I 条实测推翻** ——
942190 带 `t:removeCommentsChar`，注释在匹配前就被删掉，`/**/` 拆相邻性对它**无效**。
所以"当时算进过 10"至今**仍无可靠解释**，如实留白，不再编因果。本条按「合理代价 + 口径下修」结案，
不做"退化了 2 位"的断言。正面把这两格拿回来另立 I 条 —— **I 条也已结案为「PL1 下拿不回，且原假设错误」**。

顺带记录一个门禁自身的假红（已修）：`acceptance.mjs` 的「服务端单测」套件按 TAP 汇总行取数，
但 node:test 的 reporter 选型随 TTY 探测漂移 → 本机子进程走管道时输出 spec 格式 →
四个数全 null → 报成「FAIL　null 条失败」。现钉 `--test-reporter=tap`，并在取不到汇总行时
明确报「门禁取数口径不符，非单测失败」。同一坑此前已在 `scripts/facts-sync.mjs` 咬过一次
（还咬过 3d63b7 那轮回流解析器），**第三处应该去 `run()` 里统一收口**，别再一处一处打补丁。

### G. concurrent-isolation 是**确定性红**（**已修，2026-09-20**）
`e2e/run-all.mjs` 曾稳定挂在这一套：现象是 PG 那条扫描正常（`dbms=PostgreSQL`、union 命中），
两条 MySQL 扫描**什么都测不到**（`dbms=null techs=[]`）—— 不是判据判错，是请求层面就没拿到可用信号。

1. **`e2e/concurrent-isolation/e2e.mjs` 建 MySQL 池写死 `port: 3306`**（还有 user/password），
   只读了 `MYSQL_PASSWORD` 一个变量；而 `run-all` 按 `deps:['sandbox']` 把它交给
   `run-with-sandbox.py`（沙箱在 3308，并注入 `MYSQL_HOST/PORT/USER/PASSWORD/DATABASE`）。
   「声明走沙箱」与「实际连宿主」自相矛盾。
   实测复现沙箱路径：写死 3306 时沙箱注入的**空口令**连不上宿主 → 退出码 2；改成读 `MYSQL_*`
   契约后沙箱下 PASS（3308，3/3 union 命中）。另加了环境自检（连不上 / 库内 0 张表 → 显式
   BLOCKED 退出码 2），避免再把环境问题判成「并发串扰」归给被测代码。
2. **CI 里永远抓不到**（`deps` 含 `pg`，CI 无 PostgreSQL）：原先缺依赖的靶场被 `run-all`
   直接过滤掉，**连 SKIP 都不显示** → 「通过 6 / 失败 0」看起来是全绿。现汇总新增
   「未跑（缺依赖，本轮零断言）」单列，计数行加 `未跑 N`。
   注：给 CI 补 PG service container 仍未做（那是另一条路，二选一即可，现已不靠它保证诚实）。

**顺带修**：`run-all.mjs --only` 只认空格形式 `--only 名字`，写 `--only=名字` 时
`indexOf('--only')` 返回 -1 → **静默退化成跑全部依赖齐全的靶场**（实测：想跑 1 个 0.5s 套件，
结果跑了 21 个含 77s 红队）。现两种写法都认，并打印「定向模式：只跑 X」。

### H. udf-lab step6 的归因文案会把人带偏（✅ 已修 2026-09-20）
`sys_eval('cmd /c echo <ASCII marker>')` 偶发捕获为空时，step6 的 note 固定写
「典型：Windows 本地化 whoami 的 GBK 输出」。marker 是纯 ASCII，这句话把人往编码方向带，
而实际形态是**输出捕获为空**。改成按实测分支给原因（空捕获与"不可字符化"是两回事）。

**✅ 已按此修（`Exploiter.myOsShell` 路径 2.5）**：
- echo 探针（纯 ASCII 数字 marker）从**单次**改为**最多两次**，用重试结果把三种成因分开：
  | 观测 | 归因 | 关键点 |
  |---|---|---|
  | echo 命中 + 原命令 null | 真·输出不可字符化 | note 明确写「该命令**自身**的输出编码，非探测通道问题」 |
  | echo 首空、重试命中 | 判据抖动（偶发空捕获） | **不写任何编码归因**（ASCII marker 不存在字符化失败） |
  | echo 两次都空 | 探测通道不可靠 | 新增 `probeInconclusive: true`；note 点明 marker 是 ASCII、不是编码问题；**不写 udfInstall**（两次空 ≠ 未注册，不把人引向重投 DLL） |
- **验证**（`tests/exploiter.udfChain.test.js` 新增 3 条，9/9 绿）：
  · 正向（保留原语义）：echo 命中 + 原命令 null → `suggestHexEcho: true`，无 `probeInconclusive`；
  · 抖动：断言 echo 探针**确实发了 2 次**，且 note 不含 `GBK|本地化`；
  · 通道不通：`probeInconclusive: true`，note 含 `ASCII`、不含 `GBK|本地化`、不含 `udfInstall`。
- **缺陷注入验证**：撤掉重试段 → **第 8、9 条变红，第 7 条（保留原语义）仍绿**（7 pass / 2 fail）
  → 证明新测试钉的是新增行为，且没有破坏原归因路径。
- **实测背景**：`e2e/udf-lab/results/udf-takeover.json` 最近一次 `osShell.ok=true`（值 `osshell_ok`）
  未触发该分支，但同次 `whoami` 实测返回 `Admin（无密码）` —— **非 ASCII 用户名**，
  说明这条归因分支在真机上确实可达。

### I. 严格档 CRS 下数值点的 union 怎么拿回来（**已实测结案，两处归因被推翻**）
F 条的探针表给出：**换分隔符这条路对 942361 完全无效**（`/**/`、`%0a`、`%09`、双空格、`UNION ALL`
八种形态全部 403，且这些形态不套 WAF 时 MySQL 全部正常执行）。原因是该规则的判据是
`^[\W\d]+\s*?(?:alter|union)\b` —— 打的是**参数值起始形状**，不是 UNION/SELECT 相邻性。
数值点 `id=1…` 必然以数字开头 → 命中；`alice'…` 以字母开头 → 不命中。

**✅ 第 2 条「换档测量」已完成（实测发现早于本条记录）**：
`CRS_PL` 环境变量机制已落在 `crs-engine.js:287-293`（`DEFAULT_PL` 读环境变量，默认 3），
`e2e/waf-real/waf-bits-baseline.json` 已按 PL 分档锁基线，并写明 `_why_per_pl`：
「不带档位的绕过率没有可比性 —— CRS 官方默认部署是 PL1」。README 已同时给出两档：

| 档位 | tamper off | tamper on | 自动选链 |
|---|---|---|---|
| **PL1（CRS 默认部署档）** | 8 | 8 | 8 |
| **PL3（全规则最严档）** | 0 | 0 | 0 |

门禁默认跑 **PL1**（`WAF_GATE_PL=3 npm run acceptance` 可切档）。
→ 原担忧「README 只有最严档会低估自己在真实默认部署下的表现」**已消除**。

**✅ 第 1 条已实测结案（2026-09-20）—— 结论：原假设方向错误，这两格在 PL1 下拿不回来。**

写了 4 版单点探针（`probe-union-shape.mjs` / `probe-union-shape2.mjs` / `probe-union-ws.mjs` /
`probe-nounion.mjs`，纯发请求 + 直连真库，各几秒出结果），共扫 100+ 形态，逐格记录
「CRS 拦不拦 / MySQL 认不认 / 标记值能不能取回」三个独立事实。**归零，且推翻了本条的两处归因：**

| # | 原假设 | 实测结论 |
|---|---|---|
| 1 | 是 **942361**（`^[\W\d]+\s*?(?:alter\|union)\b`，PL2）拦住数值点的 union | ❌ **错**。拦住的是 **942190（PL1）** —— 它含 `union\b[\s\x0b]*(?:all\|(?:distin\|sele)ct)\b`。942361 是 CRS 里**更松**的兄弟规则，压根不是那道闸。原「起始形状」归因是把两兄弟混成一谈 |
| 2 | 改起始形状（`space2plus`/`1/*x*/UNION`…）能绕过 | ❌ **不成立**。942190 不看起始，只看 union↔select 相邻性。且它带 **`t:removeCommentsChar`** —— 所有注释在匹配前就被删掉，`/**/` 类填充全线失效（30 种填充形态实测 0 通过，唯一没被 942190 拦的 `UNION/*!*/SELECT` 落到 942500） |

**另外三条已排空的路径**（都不是"没想到"，是真测过）：
- **非 ASCII 空白**（NBSP / U+2000–200A / 表意空格 / BOM 等 18 种）：MySQL **全部不认作空白**（语法错），
  物理上不通。→ 这条路是死的，不是我们没用对。
- **改关键字大小写 / 换 `ALL`/`DISTINCT`**：942190 带 `(?i:)`，且 `all` 恰在它第二支里，全拦。
- **绕开 union 字面量**（boolean / subquery / error / time / stacked 五类 17 种）：
  被 **942130 / 942440 / 942120 / 942131 / 942151 / 942160 / 942140 / 942350** 逐一精准拦住，同样 0 通过。

**修正后的定性**：不是"我们的 tamper 链不够好"，而是 **CRS 在 PL1 档对 SQLi 是全覆盖的** ——
每一格都有对口规则守着。这条按「**原假设错误 + 口径下修**」结案，不再作为待办挂账。
`num`/`blind` 两格在 PL1 下丢掉 union 是**正确行为**（真实反映 WAF 强度），不是缺陷。

**如果将来还想再试**（诚实留档，非承诺）：唯一没被穷尽的方向是**真 ModSecurity(PCRE) 与 JS 正则的
语义差异** —— 本次全部用 JS 模拟执行器，JS 的 `\s` 比 PCRE 宽（含 `\v`/NBSP 等），所以「JS 侧拦」
不能直接判死 PCRE 侧。要定论得上真引擎（见 P1 第 1 条，本机无 docker）。

四个探针脚本留在 `e2e/waf-real/`，可复跑复核：`node e2e/waf-real/probe-union-shape.mjs`（余三同）。

---

## P0′ · 门禁可信度（2026-09-20 新增）

### J. 「CI 引用的文件是否存在」应固化成门禁（✅ 已完成 2026-09-20）

**已修的真 bug**（`8144fc7`）：`ci.yml` 里两个 job 引用**不存在**的文件 ——
`e2e/tamper-matrix/run.js`（真入口 `tamper-test.mjs`）与 `e2e/waf-lab/run.js`
（真入口 `compare-real.e2e.mjs`）。两者都带 `continue-on-error: true`，
于是 `node <不存在的文件>` 每次 Cannot find module 却**从不拦人** ——
**这两个 job 从未验证过任何东西**，是彻底的「空转门禁」。

**防护已落地**：新增 `scripts/ref-integrity.mjs`，校验三处引用源：
`.github/workflows/*.yml` 的 `run:` 步骤（含多行块 + `cd X &&` 基准目录偏移）、
两个 `package.json` 的 `scripts`（含 `npm run <name>` 交叉引用）、
`e2e/run-all.mjs` 的 `entry` 字段。当前校验 **82 处，全部存在**。
接入 `npm run refs:check` / `check:all` / `ci-local` 的 lint 组 / `ci.yml` 的 lint job。

**缺陷注入复验（4 例）**：① ci.yml 路径改回不存在的 → 报第 313 行；
② run-all entry 改坏 → 报出条目；③ package.json 引用不存在的 script → 报「脚本引用」；
④ **自指注入**（把 ref-integrity 自己在 ci.yml 里的路径写错）→ 被抓到，证明覆盖了自己。

**修门禁自身时的两个教训**（值得记住）：
- 初版不认 `cd server && node index.js` → 把 3 个**相对子目录**的正确路径误报成缺失。
  **门禁报假红比没有门禁更糟**（会训练人忽略红灯），故校验器自身也要测。
- 缺陷注入② 首次"成功"实为**替换未命中而静默通过** —— 注入脚本必须断言替换真的生效。
  这与 J 条本身的病根同源：**静默失败最危险**。

### K. `tamper-waf-matrix` job 红了没人知道（**✅ 观察面已解，2026-10-09**）

该 job 是 `schedule`/`workflow_dispatch` 专属的实验矩阵。**2026-10-09 复核后订正本条的前提**：
2026-09-22 那轮已把**真断言门禁**（`compare-real.e2e.mjs`）的 `continue-on-error` **去掉**
（那个开关本来就不阻塞 PR —— 本 job 压根不在 PR/push 上跑 ⇒ 它只买到"失败报成绿"）；
只剩纯测量脚本（`tamper-test.mjs`，无断言、不设退出码）保留该开关，属合理。
⇒ 所以本条的真问题从"失败被吞"降级为"**失败没人主动看**"（schedule 跑的 job 没人盯）。

**已解（D22 2026-10-09）**：job 末尾新增「门禁结果汇总（失败可见化）」step（`if: always()`），
把两个门禁的 `outcome` 写进 `$GITHUB_STEP_SUMMARY` ⇒ 红了在 workflow 列表页一眼可见；
并用守卫钉住「summary 读的 `steps.<id>.outcome` 必须与真实 `id:` 配对」
（少一个 id ⇒ summary 恒显示"未跑"，比没有更误导）。

**仍待决（唯一剩下的取舍）**：失败时是否**自动开 issue**（真正的"推送式告警"）。
会产生通知噪音 ⇒ 需要先定「要推送还是只看板」。目前**不做**。

### L. 「白名单有、引擎收不到」的第三段断口：CLI↔REST 键集不等（✅ 已修 2026-09-20）

J/K 都在讲 CI 的静默失败，这条是同一病根换了个器官：**扫描配置**。

`sanitizeStart` 的返回 `config` 只由白名单键构成，未知键原来只留一行 `logger.debug`
（默认 info 级等于没有）。于是调用方传 `testPath:true` 会拿到 **200 + 正常 scanId +
一句「未检出」**——请求成功了、开关根本没进引擎。这不是崩溃型 bug，是**静默假阴性**，
而假阴性对扫描器是最贵的一类错。

为什么既有两支守卫都没抱住：`configWhitelist.guard.test` 的正向真值来源是
**defaults.js 顶层键**，而这批键**根本不在 defaults.js 里**（只由 CLI 写入）。
`configWhitelist.passthrough.test` 只遍历 KNOWN_CFG_KEYS，也就永远看不到它们。
注释里已经留着 6 处「此前不在白名单被静默丢弃」——每次都是人肉发现一个补一个。

**判据改成两端交叉**（`configReachability.guard.test.js`，可跑，不靠人眼看 grep）：
CLI 侧 `config.X =` ∧ 引擎侧 `config.X` / `ctx.config?.X` − KNOWN_CFG_KEYS。
第一轮抱出 **9 个**：`testPath` `testHeaders` `noCast` `flushSession` `hex`
`unionFrom` `dumpWhere` `unionCols` `paramDel`。

> 其中 `hex` 是我自己 triage 时丢的：`hex` 这个词在 `server/src` 有上百处无关命中，
> 我按噪声跳过了。**守卫测试第一次跑就把它指出来**。教训写进文件头：判据要能跑。
> 反向 also 有价值——我最初给 `unionFrom` 写了句"大概由别处覆盖"的豁免，
> 实测它被 blindExtractor/DBFingerprinter/Extractor/injection **四处**读取，豁免已撤。

透传时顺手补的两处真校验（不是顺手重构，是这两类值会坏事）：
- `unionCols` 引擎按 `Number()` 当固定列数用 → 收敛成 1..200 整数（否则 `abc`→NaN 进二分）；
- `paramDel` 直接参与请求 URL 的 split/join → 只收 `; , | ^ ~` 单字符。
  这里取**窄集合**：宽集合写错是静默改请求形状，窄集合写错只是误拒且带 warn。
- `hex`/`flushSession` 必须真布尔——引擎按 `config.hex === true` 判定，
  通用标量透传会放过 `1`/`"true"`，那又变回「收了不生效」，同一个 bug 形状换个触发条件。
- `dumpWhere` 拒分号：它是拼进提取 SQL 的原始片段，分号是把「一个条件」变成
  「第二条语句」的那一步，而这个键没有任何合法场景需要分号。

顺手查实的一个**新形状**（已被新守卫的"BACKFILL ⊆ KNOWN"那条钉住）：
`BACKFILL_SCALAR_KEYS` 的透传循环**不看 KNOWN_CFG_KEYS**，所以白名单对这批键其实只管
告警不管放行——把 `testPath` 从 KNOWN 里删掉，它照样能透传到引擎。缺陷注入实测确认了这点。

**剩余待办（✅ 两条均已清，2026-10-09 复核）**
1. ~~这 9 个键在 Web 面板 / Tauri 桌面版仍然无处可设~~ —— **✅ 已做**：9 键全部有 UI 入口
   （`AdvancedInjectionSection.tsx` 渲染 noCast/hex/flushSession/unionFrom/unionCols/paramDel/dumpWhere；
   `InjectionScopeSection.tsx` 渲染 testPath/testHeaders），且都登记在 `SCAN_CONFIG_KEYS`（契约测试守着）。
   ⚠️ **本条原描述已过期，2026-10-09 复核时它把我误导过一次**（据它准备重做 UI，勘探后才发现早已完成）。
2. ~~`--random-agent` 在 CLI 侧同时写 `wafEvasion.randomUA`（活）和顶层 `randomUA`（空转冗余）~~
   —— **✅ 已清（D21 2026-10-09）**：根因比"冗余"更深 —— `args.js` 里 `--random-agent` 在
   **同一条 else-if 链里被解析两次** ⇒ 第二个分支永不执行 ⇒ `args.randomUA` 恒 undefined
   ⇒ `config.js` 那次写入是**死代码**（顶层 `randomUA` 在 server/src 内 0 读取点）。
   两处已删，并加了「同一 flag 不得出现两条分支」守卫。
3. ~~CLI `--body` 的 JSON 会摊平成顶层 `bodyParams`，嵌套叶子（`user.id`、`items.0.name`）
   只有 REST 的 `jsonBody` 路径能发现 → **CLI 用户在嵌套 JSON 目标上恒漏注入点**。~~
   **已修 2026-09-20**，见 §N。REST 侧同坑（`bodyParams` 里塞对象）也已补提示。

### M. 随机化电池的 ORDER BY 形态：探针选错让一整类恒被剔出分母（✅ 已修 2026-09-20）

`results/battery.json` 里 `c00/c20/c34-orderby` 三条长期是 `status:"unobservable"`。
看起来是"自证机制正常工作，剔掉了按构造不可观测的案例"，实际是**我自己把分母做空的**：
orderby 形态 `need:''`，于是复用了一对布尔探针 ` AND 1=1-- -` / ` AND 1=2-- -`，
而 `ORDER BY id AND 1=1` 与 `ORDER BY id AND 1=2` 在这张表上分别退化成
`ORDER BY id` 和 `ORDER BY 0`（常量，且与 id 物理序同序）；取 name/price 时字符串转数值恒 0，
两探针更是完全同序。**没有哪个检测器能看见这种案例**，而"看不见就剔掉"让它变成了沉默的
覆盖率漏洞：电池宣称 6 种形态，实际恒测 5 种，n 只有 17 时少一整类会明显抬高召回。

换成列索引有效性对 `, 1` / `, 9999`（后者报 `Unknown column '9999' in 'order clause'`，
正是 sqlmap `--order-by` 的信号）。**同 seed=20260919、同 cases=40 严格对照**：

| | 修复前 | 修复后 |
|---|---|---|
| 召回 | 17/17（3 条剔除） | **20/20（0 条剔除）** |
| orderby | 3/3 不可观测 | 3/3 以 `[error,boolean]` 真检出 |
| Wilson 95%CI 下界 | 81.57% | 83.9% |

分母补全、下界反而更高——是**更强的数字而不是更大的数字**。
可复用的判断：**"不可观测"的剔除清单必须按形态看分布**。三条全落在同一个 shape
就不是随机退化，而是那一类的探针选错了；只看"剔除了 3 条（共 20）"是看不出信号的。

### N. CLI 的嵌套 JSON body 摊平成不可注入的畸形值（✅ 已修 2026-09-20）

§L 第 3 条，也是这批里唯一**直接少测注入点**的一条。

`--body` 在 `help.js:25` 写的是「POST body（JSON 对象字符串）」，但 `runSingleScan`
一律把它摊进 `bodyParams`，而 `TargetParser` 对每个 body 值做 `String(v)`。实测两端：

```
--body '{"user":{"id":1,"name":"alice"},"tags":["a","b"],"plain":"x"}'
  CLI（bodyParams）   →  user="[object Object]"   tags="a,b"   plain="x"
  REST（jsonBody）    →  user.id="1"  user.name="alice"  tags.0="a"  tags.1="b"  plain="x"
```

前两个值**结构上不可能注入**——没有任何 payload 能让 `[object Object]` 变成合法 SQL。
所以同一份抓包，CLI 用户看到的是"这个 body 只有 3 个参数、都没洞"，REST 用户看到的是
5 个真叶子点。断的不是引擎（`_discoverJsonLeaves` 早写了），是 CLI 的接线。

修法保守：**只有 body 真含嵌套时才切 jsonBody**，扁平 body 继续走 bodyParams(urlencoded)。
否则会把"目标是表单接口、但顺手用 JSON 语法写了个扁平 body"的既有扫描全改成
application/json —— 那是回归不是修复。判定抽成 `cli/config.js` 的 `resolveBodyChannel`
（一处定义，`-r` 导入抓包那条路也共用）。

REST 侧同一个坑（`clampParams:696` 的 `String(v)`）选择**只加 warn 不改行为**：
自动把 bodyParams 里的对象路由到 jsonBody 会让两个字段的语义纠缠不清，
而"我传的东西其实没被测"这件事必须可见——这和本批把未知键从 debug 提到 warn 同源。

**验证**：`server/tests/cli.jsonBody.test.js` 6 条。主用例不测纯函数，而是走
`parseArgs(argv)` → `runSingleScan` → 捕获真正递给 `ScanManager.start()` 的对象 → 再接
TargetParser 看点位（只测 `resolveBodyChannel` 挡不住"忘了把 jsonBody 放进 input"）。
缺陷注入复验：从 input 里摘掉 `jsonBody` → 第 1、2 条同时红。
另用一次性靶场（gitignore 的 `e2e/diag/` 下，跑完已删）拿**真 CLI 二进制**打嵌套 JSON
目标，端到端跑出 `dbms=MySQL` + `param=user.id` 的 union/error 两条检出、共 206 请求
无拦截——这条链路是真通了，不是只有测试绿。

### O. `-r` 导入 multipart 抓包：整份 body 塌成一个垃圾键（✅ 已止血 2026-09-20，剩两条）

`-r`（Burp/curl 导入）是实战里喂目标最主要的方式，而这条路上**解析器是对的、接线是坏的**：
`parseRequestFile` 正确抽出 `{username, caption, avatar}`（`requestFileParser.multipart.test.js`
一直是绿的），但 `applyRequestFile` 丢开这些字段、把**原始 body** 交给
`bodyToJsonString` 的 urlencoded 启发式。multipart 里没有 `&`、只有 `name="…"` 里的 `=`，
于是整份 body 塌成**一个**键，键名是

```
--<boundary>\r\nContent-Disposition: form-data; name
```

值为余下全部内容；同时 `Content-Type: multipart/form-data; boundary=…` 被原样保留。
发出去的是"声明 multipart 却带一坨 urlencoded 垃圾"，目标必然解析不到参数 →
**扫描正常跑完、0 检出、零告警**。

修法：给解析器加 `bodyFields`（只装来自 body 的字段，与混了 query 的 `params` 分开），
multipart 时用它构造 body，并**删掉那个已经对不上的 Content-Type**，让引擎按 urlencoded
重发同一批字段名与值。这是"降级但说实话"：很多框架两种编码都吃；不吃的那批由 warn 明确
告知"未检出 ≠ 没有洞"，而不是让人以为目标干净。

**为什么既有测试全绿却没拦住**（这条最值得留）：
`requestFileParser.multipart.test.js` 测的是被调函数，而断点在调用链的下一环。
**只测被调函数、不测调用链**，就会出现"测试全绿而入口是坏的"。新加的
`requestFile.importWiring.test.js` 一律从 `applyRequestFile` 进、从引擎收到的注入点出；
缺陷注入复验（把 multipart 判定短路）→ 第 1、2 条同时红。

**还剩两条（本批未做，按需排）**
1. ~~**引擎不支持发送 multipart**~~ —— **✅ 已修 2026-09-22（`dd45522`）**：body 分支已加
   multipart 序列化（按目标声明的 boundary 重建报文，未声明则自动生成）；动手前先补了
   `e2e/pentest-lab` 的 `/mp` 靶点 + `mp` 场景，CI 实测 `漏洞场景=11/11`（原 10/10）。
   原描述留档：真要覆盖"只吃 multipart 的目标"，得在 body 构造处加一条 multipart 序列化分支
   （含 boundary 生成与文件字段回发）。**风险点要认清**：`buildInjectionRequest` 是全项目
   最吃重的函数，五种技术位每条请求都过它，而当前 multipart 的 e2e 覆盖为 0 ——
   动手前应先补一个 multipart 靶场进 `e2e/`，否则改完没有任何东西能证明没改坏别的。
2. ~~**前端 `src/shared/requestParser.ts` 完全没有 multipart 分支**~~ —— **✅ 已修 2026-09-22**：新增 `extractBodyFields()`，与 `server/src/core/requestFileParser.js` 同口径地分派 urlencoded / multipart / JSON 三种 body 编码；multipart 文本字段进 `params`、文件字段取 `filename`，另出 `bodyFields`（只装 body 来源，供调用方区分通道）。
   之前 multipart 报文会被 `toJsonText` 的 `=` 启发式塌成一个以 boundary 行命名的垃圾键 —— `bodyText` 现改为按编码分派（multipart 用字段重建 JSON，其它维持原行为）。
   缺陷注入复验：短路 multipart 分支 → 仅 2 条 multipart 用例红（JSON 用例不受影响，证明分支隔离正确）→ 恢复全绿。
   原描述留档：

### P. 版本回显定库在严格类型库上恒失效（✅ HSQLDB **与 Derby 均已修**，2026-09-22 实测确认）

先修的是**测量手段**：`e2e/multi-engine-lab/verify.mjs` 原来只记技术位、**不记定库结果**，
而且靶场默认挂 CRS（UNION 哨兵整条 403）→ 版本回显通道在这里从来没被执行过。
所以"HSQLDB/Derby 定不了库"这句 TODO 里的话，长期**没有任何可跑的验证手段**
（那次 H2 结论是靠临时手写探针跑的，跑完就没了）。补了两件事：
- 报告加 `定库=` 列与"与真实引擎不符则报误判"的告警；
- `NO_WAF=1` 一档，把"探针跑不动（真缺陷）"和"探针没被送达（靶场挡的）"分开——
  这两件事在报告里长得一模一样，都是 `dbms=null`。报告标题强制带口径，两档数字不可互换。

打开 NO_WAF 后，两个**互相独立**的缺陷显形：

**① 探针是死探针（func 与 sig 互不满足）**
`func` 是裸常量串 `'HSQLDB'`，而 09-16 为堵 DB2 误判把 `sig` 收紧成 `/HSQLDB\s+\d/`——
常量里没有数字，于是**回显了自己也永远匹配不上自己的 sig**。不是"探针跑不动"，
是判据写死了不可满足。换成 exclusive 探针（区分力来自只在自家库存在的 FROM 子句，
不是来自字面量，所以正面回应了 DB2 那次教训）：
- HSQLDB：`'HSQLDB ' || COUNT(*)` + `FROM INFORMATION_SCHEMA.SYSTEM_TABLES` → 真机回显 `"HSQLDB 103"`
  （同一条放 H2 报 `Table "system_tables" not found`、放 Derby 报 Schema 不存在）
- 为此给 `DB_VERSION` 加了可选字段 `from`（该条目的 FROM 优先于方言伪表与用户 `--union-from`，
  因为覆盖掉就没区分力了），其余 16 个库的探针构造一字不变。

**② 标记必须落在字符型回显列上**
`idx = echoCols[0]` 无条件取第一个回显列。真机实测同一条 UNION 探针：
放第 1 列（`name` VARCHAR）→ 正常回显；放第 0 列（`id` INTEGER）→
`incompatible data types in combination`，**整条 UNION 直接报错**、echo=N。
也就是严格类型库上这条通道恒失效，而失败症状与"探针跑不动"完全相同。
H2 之所以一直能过，是因为它以 `MODE=MySQL` 运行会隐式转类型——不是判据对了。
修法按代价收敛：只对**声明了 `from` 的候选**换列重试（其余 16 库请求数与形状零变化；
全候选换列会把本靶场 206 请求推到 ~240）。

**⚠️ 口径更正（2026-09-22 实测）**：本条长期写「Derby 未修」，**已被证伪**。
跑 `NO_WAF=1 node e2e/multi-engine-lab/verify.mjs` 实测（本机有 Java 21 + JDBC）：

`
h2      定库=H2     期望=H2     ✅
hsqldb  定库=HSQLDB 期望=HSQLDB ✅
derby   定库=Derby  期望=Derby  ✅
`

三个引擎**全部正确**。Derby 是被 `8a606f2`（「版本回显通道在严格类型库上恒失效」）
的同一个「换列重试」修法**顺带修好的** —— 该提交标题只提了 HSQLDB，加上没人跑 NO_WAF 档复验，
于是「Derby 未修」这条口径一直挂着。
**教训：修复的影响面比提交标题宽时，要么标题写全，要么补一条复验 —— 否则口径会长期失真。**

**结果**：`定库=HSQLDB` ✅（H2 依旧 ✅）。安全对照仍零误报，检出场景仍 3/3。

**必须记下的两点不完美**
1. **一条技术位归因变窄了**：hsqldb 的 `str` 从 `[union,error,boolean]` 变成 `[union,boolean]`
   （3→2）。漏洞照样检出、场景计数不变，但报错通道不再被单独记账——原因是定库成功后
   引擎跳过了那条冗余的报错重探。这是"知道 dbms 之后是否还该报 error 通道"的**策略问题**，
   不是我这次改出来的崩溃，值得单独定口径。
2. ~~**Derby 仍未识别**~~ —— **✅ 已证伪 2026-09-22**：`NO_WAF=1` 档实测 `定库=Derby` 与期望一致
   （见本条开头「口径更正」）。原描述留档：探针本身经真机验证可执行（`'DERBY ' || CAST(COUNT(*) AS CHAR(10))`
   over `SYS.SYSTABLES` → `"DERBY 24"`，且 Derby 不做 INTEGER→VARCHAR 隐式转换、
   `CAST(.. AS VARCHAR)` 反而报错、只有 `CHAR(n)` 通——都实测踩过），但组合成引擎实发的
   查询后仍 echo=N。下一个待查方向：手测时发现 Derby 对 select 列表里的**裸 `NULL`**
   报 `Syntax error: Encountered "NULL"`，若成立则影响的不只定库、而是 Derby 上**所有**
   UNION 探针（列数二分/回显列定位/提取都拿 NULL 占位）。该现象与我手工构造的列数
   有关，尚未在引擎实发形状上复现，**不当结论用**。

**守卫升级**：`dbmsExtend6.test.js` 原来只查"func 里有没有标识串"+"sig 能否命中一个
手写的漂亮串"，所以①这类缺陷可以长期全绿。新增一条静态不变量：
**sig 要求 `\d` 时 func 必须有数字来源**（必要条件检查，不替代真机验证）。
缺陷注入复验：把 func 改回 `"'HSQLDB'"` → 该测试立刻红并点名到条目。

### Q. `facts:check` 在采集源过期时给假绿（✅ 已修 2026-09-20）

与 J/K 同源（**静默地没在做事**），但换了个器官：这次是**校验的基准自己脏了**。
`facts:check` 只比对 README ↔ `docs/_facts.json`，**从不校验 _facts.json 是不是当前代码采出来的**。

现场（本会话实测）：后继两批提交带来 +19 条用例（1985 → 2004），没人回填，
`_facts.json` 停在 1985、README 也写 1985 → 门禁报「一致」，而真实用例数早已是 **2004**
（`cd server && npm test` 实跑：2004 / pass 2003 / fail 0 / skip 1）。

**判据选型（三条都权衡过）**：

| 方案 | 结论 |
|---|---|
| 比 mtime 是否新于 `_facts.json` | ❌ CI 上 checkout 后所有文件同一时刻，必然全量误报；git 操作也改 mtime |
| 每次 check 真跑一遍测试对比 | ❌ 每次多花 4 分钟，门禁会被人绕开 |
| **测试文件内容指纹** | ✅ 采用。把「决定跑哪些测试、多少条」的文件集合做 sha256 |

实现：`docs/_facts.sources.json` 存 per-file 短哈希 + 总指纹（当前 276 个文件），
由 `--refresh` 与数字**同批**落盘 —— 分开写会制造「数字已新、指纹还旧」的中间态，
那比「两个都旧」更坏（判据会说 stale，而数字其实是对的）。`--check` 时重算比对。

**两个设计决策（都有缺陷注入复验）**：
1. **指纹缺失不静默通过** —— 文件不存在时报「没有依据」并 exit 1。（实测：删掉 sources.json
   → `[facts] 缺少 …：无法确认 _facts.json 是当前测试代码采出来的` + exit 1。）
   J 条那两个空转 job 正是被「静默跳过」养出来的，这里不重犯。
2. **基准过期时拒绝 `--fix`** —— `_facts.json` 自己过期时按它改 README，等于把旧数字再抄一遍。
   实测：注入「改测试文件 + 把 README 改回 1999」→ `--fix` 打印
   「已**拒绝**本次 --fix：基准自己过期时，按它改 README 等于把旧数字再抄一遍」，
   且 README **仍是 1999**（确认未写盘）+ exit 1。

**缺陷注入复验（原始形态）**：给 `server/tests/blindLenCapped.test.js` 加一行注释 →
`facts:check` 的 **stdout 说「README 与 _facts.json 一致」、stderr 说「采集源已改动 ——
_facts.json 可能过期」并精确指名该文件**、exit 1；撤销后 → 绿。
这一组输出正是本条要抓的假绿现场（"一致"与"过期"同时为真）。

**边界（已写进脚本注释，勿当万能）**：只覆盖测试文件 + 驱动采集的配置
（`vitest.config.ts` / `server/package.json` / `server/tests/_setup.mjs`）。
依赖版本、`.env.test`、被测源码改动**不在内** —— 改源码不改用例数，那是覆盖率门禁的职责。
判据宁可窄而准，不宽而吵。

**后续**：`e2e/acceptance.mjs` 的 12 个套件同样缺「采集于哪一版代码」的凭证 —— 已做，见 §R。


### R. 验收报告的两段可信度断口：无版本凭证 + 定向跑覆盖全量报告（✅ 已修 2026-09-20）

与 §Q 同源（**结论看着正常，语义完全不同**），这次断在**验收报告**上。

**断口 1 —— 实测撞到，不是推测**：`e2e/acceptance.mjs` 支持 `--only=<id>` 做定向门禁，
但它把结果写进**同一个** `e2e/results/acceptance-report.md`，也就是入库的全量报告位置。
本会话实测现场：那份文件的内容变成了

```
| ✅ PASS | fileWrite 真闭环（文件系统侧断言） | PASS=true SKIP=false 文件落盘=true 方式=隔离沙箱重试 |
**汇总：1 PASS / 0 FAIL(含 BLOCKED) / 0 SKIP**
```

一行 + 一句「1 PASS / 0 FAIL」—— 看着全绿，实际 12 个套件只跑了 1 个。
而被覆盖掉的是**已入库**的全量结论（前一份是 12 PASS），信息直接丢失。

**断口 2**：报告头部只有时间戳，回答不了「这份 N PASS 是哪一版代码跑出来的」。
工作区 dirty 时跑出的报告照样入库 → 读的人会以为它对应某个提交。

**修法（三件）**：
1. 报告头加**版本凭证**：HEAD 短 sha + 未提交清单（dirty 时显式写「本报告不对应任何提交」
   + 前 3 个文件名 + 总数）。**必须在开跑前采集** —— 跑验收本身会写 `e2e/*/results/*`，
   结束时采集会把运行产物误读成「跑前的未提交改动」。
2. 报告头加**套件范围判据**：`N/M 跑出断言`（N = PASS+FAIL，即真跑了断言的套件数）
   + 非全量时追加「⚠️ 判定：不完整 —— 不得当作该代码版本的整体验收结论」。
   判据是数字，**不依赖文件名**（文件名可以被改）。
3. 只有**真全量**运行（无 `--only`、无 `--skip-heavy`）才写 `acceptance-report.md`；
   其余写 `acceptance-report.partial.md`，并加进 `.gitignore`（本地产物不入库）。

**验证（哈希对照，可复现）**：跑前 `acceptance-report.md` md5 = `6a38c043042a3b07f7259eed64767f16`
（被污染版本）→ 跑 `--only=report-contract` → 跑后 md5 **逐字相同**（未被覆盖），
终端打印「套件范围：1/12 跑出断言（**非全量**，未覆盖全量报告）」。
新报告头部实测（dirty 与范围两行都在）：

```
> 代码版本：`0ef2bc9`　⚠️ **工作区 dirty**（跑验收前有 9 个未提交改动：…）—— 本报告不对应任何提交
> 套件范围：**1/12 跑出断言**（定向 --only=report-contract）　｜　⚠️ **判定：不完整**
```

**顺带确认（避免误伤 CI）**：`.github/workflows/*.yml` 与 `scripts/ci-local.mjs`
都不用 `--skip-heavy`，CI 走的始终是「真全量」路径 → 报告仍写 `acceptance-report.md`，分流对 CI 无影响。


### S. 沙箱起不来被记成产品 FAIL；失败现场会过期（✅ 两条都修 2026-09-20）

全量 `ci:local` 里 `fileWrite` 报 `FAIL 文件落盘=false`，看着像文件写入被改坏了。
真因来自那份**保留下来的失败现场**：隔离 mysqld 沙箱启动超时 45s 后 python 抛
`RuntimeError`，**一条断言都没执行**。单独 `--only=file-write` 连跑 3 次全绿。

- **定性修正**：`FAIL` = 断言没过（代码有问题）；沙箱没起来 = `BLOCKED`。
  两者**一样进 failed、一样让门禁非零退出**，改的只是语义标签——
  让人一眼知道该去查环境还是查代码。这正是 §G 那次"把环境问题归给被测代码"的重演，
  差别是这次有现场可查。
  匹配只用 ASCII 稳定标记（`mysql_sandbox.py", line N, in` + `Traceback`），因为
  `[mysql-sandbox]` 那些行在本机 cp936 控制台下是乱码，按中文匹配必失效。
  三向验证过：真实现场判 BLOCKED ✅；合成的"真实断言失败"不判（否则就是放水）✅；
  只有中文超时行、没有 traceback 也不判（保守留在 FAIL）✅。
- **现场卫生**：dump 现在带 `失败于 <ISO>`，且**套件这次过了就删掉它的旧现场**。
  此前没有任何清理逻辑（我一度以为有，实测 `grep last-failure` 只有写入处一处）——
  于是一份三天前的失败日志会一直躺在那儿，长得像"刚刚又红了一次"的证据。
  **留着比没有更坏**，因为它会把人往已经作废的方向上带。

### T. udf-lab / 沙箱启动超时是同一个环境抖动源（✅ 抖动源已定位并修掉一半，2026-10-12）

§S 那次 traceback 与记忆里"udf-lab 约一半概率跑挂"是同一家族：多个套件各自
`起 mysqld 沙箱 → 用 → 停`，在全量跑批里挤同一个 3308 端口与同一份 datadir。

✅ **真根因（比原先两个候选更靠前）**：`do_start()` 用 **`_port_open(3308)` 代替"本沙箱是否就绪"** ——
端口被**任何**进程占用（上一套件残留的 mysqld、正在关闭中的实例、甚至别的程序）都立刻返回
「已在运行」⇒ `SandboxInstance` 拿到一个**身份不明**的实例跑完全程。判「已经在跑」必须问
「你是谁」，只看门牌号亮没亮就会周期性跑挂 —— 这不是超时不够，是**假绿**。
（顺带防住一个隐患：`_mysql_exec` 的连接候选里 `--pipe` 排最前，命名管道可能绕开 `-P` 打到主库；
datadir 校验后这种"连错库"会被判身份不符拒绝，而不是把沙箱的 provision/DROP 打到主库。）

修法（`mysql_sandbox.py`）：新增 `_sandbox_alive()` —— 用 `SELECT @@datadir` 验身份，
路径须含 `.mysql-sandbox`；`do_start` 的**复用分支**与**就绪判定**两处都调它，
身份不符/连不上 ⇒ 返回 **3**（非零 ⇒ `SandboxInstance.__enter__` 直接抛错），不再放行。
`wait_sec` **保持 45s 未动** —— 没有实测分布就不该拍一个 P99 数字。

验证（**本机全程未起 mysqld**，遵守"不起常驻进程"的硬约束）：
- `--selftest`（新入口，不起任何进程，外部依赖全用桩）：4/4 —— A 正常就绪 / B 占用者是主库⇒拒绝 /
  C 半死实例⇒拒绝 / D 反向钉子（确是本沙箱时仍要能复用）。**缺陷注入 2 条杀**（把身份校验退化成恒真 ⇒ B/C 红）。
- `server/tests/sandboxIdentity.guard.test.js`（5 条源码级守卫，随 `test-server` job 每次都跑）：
  **缺陷注入 3 条杀**。存在理由：那份 .py 不在 node 能直接调用的范围里，只靠 selftest 极易变成
  "写了没人跑"的脚本（D24 治理过的老病）⇒ 用源码断言钉住。

⏳ **仍未做（需真机，交 CI / 下次有沙箱环境时）**：
① **共享沙箱**（acceptance 内一个实例跑完所有需要的套件）—— 消除"各起各的"这个抖动源本身；
② 量化启动耗时分布再决定 `wait_sec` 要不要调（**没量过就不调**）。
⇒ 本次修掉的是"复用错了还不知道"，不是"别各起各的"；后者要动 acceptance 的套件编排。


### U. ci-local 声称「对齐 ci.yml」，却少跑 3 个 job 且只声明了 1 个（✅ 已修 2026-09-20）

与 J 条同源，换了个层级：J 那道闸门查「引用的**文件**存不存在」，
这条查「ci.yml 里的 **job** 有没有人执行」—— 都是「配置里写了、实际没人跑」。

**现场**：`scripts/ci-local.mjs` 头部原写

```
· 不覆盖：需要 docker 的 job（`docker`、`acceptance` 的 MySQL+secure_file_priv 前置、…）
```

只提了 **1 个** job，而实测未覆盖的是 **3 个**：

| job | 真实排除理由 |
|---|---|
| `docker` | 本机无 docker（exit 127 已实证）—— 原声明里唯一被提到的 |
| `test-matrix` | 跨平台矩阵（windows/macos）。命令集已被 lint/test-frontend/test-server 覆盖，但「另一个操作系统」本机替代不了 |
| `tamper-waf-matrix` | schedule-only 实验矩阵 + `continue-on-error` 有意设计（见 K 条） |

文件末尾还有一句散文式声明「CI 还有两个本机跑不了的 job」——「两个」里只有 `docker`
一个是 job（另一个是 acceptance 的前置条件，不是 job），而实际是 3 个。**两处声明都错。**

**为什么值得修而不是改几个字**：真正贵的不是这次的数字错，是**将来**——
ci.yml 新增一个 job，本地门禁会静默少跑一段，而没有任何东西会因此变红。
这正是本仓反复出现的那类错（J/K/Q/R 同族）。

**判据（不留默认跳过的口子）**：每个 ci.yml job 必须二选一 ——
① 被 GATES 覆盖；② 在 `EXCLUDED_JOBS` 里登记，并写清「为什么本机替代不了」。
没登记 → 启动即报错 exit 2，逼人当场做选择。反向也查：清单里登记了 ci.yml 已不存在的
job（清单腐烂）同样报错。解析侧另加一道自保：jobs 段之后若冒出新的顶级键，
直接报「结构变了，自检需要跟着改」，而不是静默漏检。

启动时打印一行（**数字即判据**，散文声明全部删掉，避免两处漂移）：
```
job 覆盖自检：ci.yml 12 个 job → 本地覆盖 9 / 显式排除 3 / 未声明 0
```

**缺陷注入复验（两例，均按预期 exit 2）**：
- ci.yml 末尾追加一个未声明 job → 「❌ ci.yml 里有 1 个 job 没有登记的归宿：`zzz-injected-job`」，
  且自检行变成「⚠️ 未声明 1」；
- `EXCLUDED_JOBS` 登记一个不存在的 job → 「❌ EXCLUDED_JOBS 里登记了 ci.yml 已不存在的
  job：`ghost-injected-job` …… 排除清单腐烂了」。
两处注入撤销后 → 自检行回到「未声明 0」、exit 0。

**边界**：这条只管「job 有没有人跑」，**不管 CI job 里的步骤是否被逐条等价覆盖**
（例如 acceptance 在 CI 里是「新克隆 + 空 datadir + docker 起 MySQL」的干净环境，
本机跑的是同一份脚本但环境不同 —— 这种差异本判据看不见，仍需真远端）。


### V. 红队真值链没有一致性判据：靶点清单少一个，分母静默变小（✅ 已修 2026-09-20）

沿着「结论看着正常、语义完全不同」再往上游走一格，这次到了**靶场真值**本身。

**结构**：redteam-lab 的检出率/误报结论依赖一条真值链 ——

```
selftest.mjs ──生成──▶ ground-truth.json ──被读──▶ gate-check.mjs ◀── results-r2.json
                                                    （分母只含 truth=true 的 vuln）
```

而「扫哪些靶点」（`run-scan.mjs` 的 TARGETS）与「标定哪些」（`selftest.mjs` 的 TARGETS）
是**两份各自手写的清单**，加上 `ground-truth.json`、`sqlmap-bench.mjs`、`verify-fix.mjs`，
共 **5 份**，彼此之间**没有任何判据**。

**为什么不同步危险（后果不对称）**：

| 方向 | 后果 | 会被发现吗 |
|---|---|---|
| run-scan 多一个、selftest 少一个 | 该点不进真值表 → gate-check 取不到 → **完全不计入分母** | ❌ 静默，且结论更好看 |
| selftest 多一个、run-scan 少一个 | 不可观测的 id 恒判未命中 → 检出率被拉低 | ✅ 会红，有人会查 |

**实测现状：三份核心清单当前是一致的**（权威 26 = 真值表 26；子集 18/10 均 ⊆ 权威）
—— 原本担心的断裂**不存在**，只是维护得好，**不是机制保证的**。故把它变成机制。

**新增 `scripts/lab-targets-check.mjs`**（`npm run targets:check`，接入 ci-local 的 lint 组 +
ci.yml 的 lint job），判据四条：
1. 权威集合 = run-scan ∪ selftest，且两者**逐 id 相等**（"扫哪些"与"标定哪些"是同一件事的两面）；
2. `ground-truth.json` == 权威集合，且不留 `truth≠true` 的 vuln；
3. 子集 ⊆ 权威 + 显式登记「为什么是子集」+ 规模走**只减不增**基线（18 / 10）；
4. 任一文件解析不到 id 即报错退出（判据失效必须显形，不静默返回空集合）。

**缺陷注入复验（4/4 按预期 exit 1）**：selftest 少一个 → 「权威清单不一致」并点名；
子集引用假 id → 「权威集合之外的靶点 id」；子集缩到 17 → 「低于基线 18（只减不增）」；
真值表换成幽灵 id → 「幽灵靶点」。注入脚本自身断言替换真的生效（未命中即报用例无效）。

**顺带核对（不是 bug，README 已标注）**：`sqlmap-bench` 缺的 5 个 vuln
（D11/D14/D15/D16/E15）与 3 个 safe（F19/F23/F24），与 README「sqlmap 同题对照」里写的
"分母不同"**逐条吻合**；`verify-fix` 的 10 条也与其文件头「只复核布尔/时间通道 + 全部安全点」自洽。

**本轮踩到的环境插曲（改文件前务必要懂，已踩过一次）**：本机 `core.autocrlf=true`，
于是「改一个入库文件的字节 → 用 `git checkout --` 恢复」**会把工作区文件从 LF 变成 CRLF**，
md5 因此与改前不同；而 `git status` 说 clean、`git diff --numstat` 也空（git 比较时做了 EOL 归一化）。
→ **在这种仓库里 md5 不能当"文件没被改"的判据**；权威判据是
`git cat-file -p HEAD:<path>` 取原始 blob 再 `cmp`。做字节级注入验证的正确做法是
**先用 `cp` 备份原文件、验完 `cp` 回来**，绕开 git 的 EOL 转换。
已按此法收尾：`git status` 无靶场文件残留、门禁仍绿。


### W. blackbox-lab 有 2 个靶点从未被扫描（✅ 已补齐：两点均检出，顺带纠正一处二阶标定错误）

**发现方式**：把 §V 的判据**推广到第二个靶场**时露出 —— `blackbox-lab` 的真值标定是
**22 点**，而 `run-scan.mjs` 的 POINTS 只有 **20 点**。

**查证（三条独立证据，不是推断）**：
1. `run-scan.mjs:49` 的注释写「（D1-postform / E1b-secondorder）由 `run-scenario.mjs` 单独处理」；
2. `find . -name "run-scenario*"` **零命中** —— 全仓唯一提及处就是那行注释；
3. `e2e/blackbox-lab/out/` 里 20 个靶点各有 r1/r2/sqlmap 三类产物，
   **那两个点一个产物都没有**。

且 `run-scan.mjs` 的汇总以 `vulnRows.length` 为分母 → 它实际报的是「漏洞检出 N/13」，
而 README 写「22 靶点（15 漏洞 + 7 安全对照）」「真值标定 15/15」——
**「真值标定 15 个漏洞点」与「实际扫描 13 个漏洞点」长期被混为一谈**。

**已做（消灭静默）**：
- `scripts/lab-targets-check.mjs` 扩展为**多靶场**（redteam-lab + blackbox-lab），
  新增第三类判据：**扫描清单 ⊆ 权威，差集必须显式登记在 `scanGaps`**，
  反向也查「登记腐烂」（登记了实际已覆盖的点）。启动输出：
  「扫描目标 **20/22（差集 2 个，已登记）**」。
- `run-scan.mjs:49` 的错注释已改为事实陈述（原文指向一个不存在的文件）。
- README 补「扫描覆盖 20/22」并指向本条。

**补齐结果（2026-09-20 实测，r1 + r2 两轮）**：

| 靶点 | 接入参数 | 结果 |
|---|---|---|
| `D1-postform` | `--method POST --body '{"username":"alice","password":"x"}'` | ✅ **HIT**（两轮均检出 `[boolean,time]`，333 / 546 请求） |
| `E1b-secondorder` | `--method POST --body '{…}'` + `--cookie <admin 会话>` + `--second-order <触发页 URL>` + `--allow-second-order-writes` + `--no-production-mode` | ❌ **MISS**（244 / 455 请求，有实质扫描） |

**D1 踩到的坑（很值得记）**：`--body` 只吃 **JSON 串**。第一版我按 urlencoded 写
`--body 'username=alice&password=x'` → CLI 直接报
`Unexpected token 'u', "username=a"... is not valid JSON` → **报告根本不产出**
→ run-scan 把它静默算成 MISS（0.7s、`req=undefined`）。
正确写法是**扁平 JSON** `{"username":"alice","password":"x"}` —— 扁平形态会经
`resolveBodyChannel`（§N 那次的产物）判为"不含嵌套" → 以 urlencoded 发出，正是靶场要的编码。
**若只看到"MISS"就去查引擎，会完全查错方向**（0.7s 这个耗时本身就该是线索）。

**E1b 的 MISS 原因：标定错误，不是引擎能力边界 —— 上轮结论已作废**

第一版我把它归因为「引擎二阶只覆盖 error 型回显」（那个**事实**本身没错，见
`SecondOrderDetector.js:55-70`），但**拿它当本次 MISS 的原因**是错的。查证后：

| # | 证据 |
|---|---|
| ① | 靶场代码：`/api/admin/orders` 的 SQL 是 `WHERE status='${req.query.status}'` —— 注入源是 **HTTP query** |
| ② | 靶场代码：`/api/comment` 是 `INSERT INTO orders (username,item,address,status) VALUES (?,?,?, 'pending')` —— status 硬编码，且写入的字段只出现在 **SELECT 列表（输出）**，不进 WHERE |
| ③ | 实测：**不带任何前置写入**、直接扫触发页 URL → 命中 `union+error`，风险 High |

→ 写入**丝毫不影响**查询结构；那个「先 POST comment 再注入」的标定里，comment 是**无关动作**。
本点实为「**需 admin 会话的普通 query 注入**」。

**修正（本轮）**：
- `selftest.mjs`：`E1b-secondorder` → `E1b-admin-query`，technique 由 `second_order` 改为
  `union/boolean`，标定去掉无关写入（直接注入触发页 query）；
- `run-scan.mjs`：接入由「POST /api/comment + `--second-order`」改为**直接扫触发页** + admin 会话 cookie；
- `lab-app.mjs`：订正那句与实现不符的注释（"把存储内容拼进 SQL"）；
- 重跑 `selftest` 重建真值表 → **漏洞点 15/15 + 安全点 7/7 仍全部成立**
  （改的只是分类与标定方式，**靶点的 SQL 拼接形态一字未动**）。

**验证（r1 + r2 两轮，均 2/2 检出）**：

| 靶点 | r1 | r2 |
|---|---|---|
| `D1-postform` | ✅ HIT `[boolean,time]`　333 请求 | ✅ HIT　546 请求 |
| `E1b-admin-query` | ✅ HIT `[union,error]` dbms=MySQL　81 请求 | ✅ HIT　287 请求 |

**教训（这条比修复本身更值钱）**：靶场/标定里的**注释与实现不符**，会把**分类错误**
伪装成**工具能力缺口**。若不是多问了一句"这个写入到底影响了什么"，
就会去给引擎加一个根本没被需要的能力（二阶 boolean 通道），而且**永远修不好这个靶点**。


### X. pentest-lab 自检的两处门禁断口：`must` 从不参与判定 + 无条件 exit 0（✅ 已修 2026-09-20）

与 §J/§Q/§R/§U/§V/W 同族（**声明了却没人拦**），这次落在**靶场自检脚本**里。

**断口 1：`must` 技术期望是装饰性的**。`e2e/pentest-lab/verify.mjs` 的每个场景都声明了
`must: ['union','error','boolean']` 这类期望（如 `ua` / `ck`），但判定式是：

```js
const miss = sc.must.filter((t) => !union.includes(t));
const ok = sc.expectSafe ? union.length === 0 : union.length > 0;   // ← ok 完全不用 miss
```

→ **must 未命中只在输出里附一句 `miss=[...]`，不会让任何东西变红**：
"声明了技术期望，但达不到也没关系"。

**断口 2：`process.exit(0)` 是无条件的**，就写在同一段里：

```js
const tag = sc.expectSafe ? … : union.length ? 'PASS' : 'FAIL(漏检)';
console.log(`[pentest-lab] 漏洞场景检出 ${detected}/${vulnerable}；…`);
process.exit(0);          // ← 漏检 / 误报 / must 未命中，一律退 0
```

→ 直接跑 `node e2e/pentest-lab/verify.mjs` **永远是绿退出码**，脚本自己打的 FAIL 标签形同装饰。
（同 skill 陷阱 11「打印 + 无条件退出 = 假绿」。）

**为什么更早没被发现**：acceptance 那条路**是有效的** —— 它解析 stdout 的
`漏洞场景检出 N/M` 数字并断言 `vuln === total && fp === 0`。于是"聚合门禁绿"与
"脚本自己绿"两件事长期并存；**两个入口口径不一致本身就是缺陷**。

**修法**：
1. `ok` 纳入 must（`union.length > 0 && miss.length === 0`；安全场景仍是"必须 0 检出"）；
2. `tag` 增加 `FAIL(miss=…)` 形态；
3. 末尾改为 `process.exit(failedRows.length ? 1 : 0)` 并按场景点名；
4. 顺带只给**描述里明确写了技术**的场景补 must —— 本次只补 `noisy`（描述写"布尔盲注"）。
   其余 9 个场景描述未声明技术，**故意不补**：把"当前实测出什么"固化成"期望出什么"
   等于把实现当规范，会制造假红。

**验证（实测 11 场景）**：

| 步骤 | 结果 |
|---|---|
| 加严后基准 | `漏洞场景检出 10/10；安全场景误报 0`，11 场景全 PASS，**exit 0**；`noisy` 的新 must 命中 |
| 注入 ①：`noisy` 的 must 改成 `['nosql']` | `❌ 1 个场景未通过：noisy` + **exit 1**（注意 `10/10` 仍显示"有检出" —— 这正是"有没有检出"与"期望是否满足"的区别） |
| 注入 ②：`empty` 指向不存在的路由 | `FAIL(漏检)` + `9/10` + **exit 1** |
| 撤销两处注入 | 恢复 10/10 + exit 0 |


### Y. CI 首跑战报（2026-09-20）：9 绿 3 红，三个红全部定位

远端接入后的**第一次真跑**（run `35513609939`，`ee14dd5`）。

**结果**：✅ test-server（2004 用例 Linux 全过）· test-frontend（315）· audit · **docker**
（本机没 docker 测不了的，在 CI 直接过了）· recall-lab · sidecar-build · release-smoke ·
红队 19/19；⏭ tamper-waf-matrix（按设计）、test-matrix（被 needs 连带跳过）；
❌ **lint** · **acceptance**（9 PASS/1 BLOCKED/2 FAIL）· **e2e-self-contained**。

**含金量**：服务端 2004 用例 + 前端 315 用例 + 红队 19/19 在 **Linux 干净环境全部复现**
—— 核心引擎没有平台性问题。

**三个红的定位与状态**：

| job | 根因 | 状态 |
|---|---|---|
| `lint` | ① 指纹门禁没做 **EOL 规范化**：本机 CRLF / CI LF → 69 文件假报"改动"（同 `git archive` 假阳性那一课，踩了两次）；② 修完指纹后仍红 → **Tauri 在 Linux 编译缺 GTK 系统库**（glib-sys 找不到 glib-2.0.pc → clippy exit 101），本地 Windows 是另一套依赖链 | ✅ 已修（hashFile 规范化 `b64e772` + apt 装 Tauri 依赖），待下轮验证 |
| `acceptance` | **三个套件各自独立**（靠 `last-failure-*.log` 现场定位）：<br>① **CRS 保真度** = `ERR_MODULE_NOT_FOUND: Cannot find package 'yaml'` —— acceptance job 只跑 `cd server && npm ci`，而 `yaml` 在 **root 的 devDependencies**；本机 node_modules 里早就有它（隐式依赖）→ **已修** `0fbbfaf`<br>② **fileWrite** = 落盘路径写死 Windows（`remotePath=D:/tmp/...`、`wrote:true` 但 `verified:false`）—— **✅ 已修 2026-09-21（`5e5aa2b`）**：兜底改 `tmpdir()` 派生 + CI docker 挂载卷 + `FILE_WRITE_DIR`<br>③ **fileRead** = 隔离沙箱 `datadir 未初始化` → BLOCKED（判据语义正确）→ **✅ 已决策 2026-09-22**：判 **BLOCKED（进 failed）**，既非 SKIP 也非 FAIL。理由：① 不该 SKIP —— SKIP 不进 failed，等于让这项能力的覆盖**静默归零**（本仓最贵的一类错）；② 不该 FAIL —— 一条断言都没执行，记 FAIL 会把下一个人引去查产品代码（§G 重演）；③ BLOCKED 与 FAIL 一样非零退出，区别只在标签。同时把判据抽成可单测的 `e2e/lib/suiteVerdict.mjs`，并**扩了两种漏检形态**（详见 §Y-b） |
| `e2e-self-contained` | redteam-lab 跑 90.6s 失败、multi-engine-lab 0.4s 秒败（疑似 CI 容器缺依赖） | ✅ **已销账（2026-10-12：run #208 与 #210 均 success）**。**过程比结论值钱**：① 来源是 **CI 首跑**（run `35513609939` / `ee14dd5`，2026-09-20），不是本机记录；② 此后因 `needs:[test-server]` 被上游红**连带 skipped，一次都没再真跑过** ⇒ **被 skipped 的 job 既不能证明"修好了"也不能证明"没修好"** —— 它挂 22 天不是因为一直红，而是根本没有判据；③ test-server 转绿后首次复跑即 success |

**过程教训（两条）**：
1. 我的监视脚本把「jobs 列表为空」（run 还在 queued 的正常中间态）当成了「全部完成」
   —— **判据失效必须显形**，自己写进 skill 的原则自己也要遵守。已改为以 run 自身 status 为准。
2. GCM 凭据通道**间歇性**返回 Bad credentials（旧监视器 12 轮后连续 30 分钟取到坏 token）——
   该通道可用但**不可靠**，重要取证别依赖它。

**另**：`ref-integrity` 在 CI 上校验了 **104 处**引用（本地 91 处 —— 因为本机跑的是旧提交；
差值即本轮新增的引用），CI 侧全绿 ✅ 这道门禁在两端都工作了。

**为什么长期没被发现**：blackbox-lab **不在任何门禁里** —— 它是"独立第三方评测靶场"
（刻意不复用项目自带靶场，属阶段性工具）。它的一致性原本没有任何东西在守护；
本轮起由 `npm run targets:check` 覆盖（已接入 ci-local 的 lint 组与 ci.yml 的 lint job）。

**顺带（未做）**：`ref-integrity` 只查 yml / package.json / run-all entry 的引用，
**注释里引用的本地文件不在其内** —— 本条的 `run-scenario.mjs` 就是这么藏住的。
是否把注释引用也纳入判据要先解决误报（注释里提及已删除的旧脚本是常见且合理的写法），
故本轮只手工修正了这一处，未加判据。


---

### Y-b. 两项挂起的决策（✅ 均已决 2026-09-22）

#### 决策 ①：`tamper-waf-matrix` 的 `continue-on-error` —— 分两步、两种待遇

先订正一个**过期前提**：旧注释写「带 continue-on-error 是为了不阻塞正常流水线」。
但该 job 的 `if:` 只允许 `schedule` / `workflow_dispatch` 触发，**根本不在 PR/push 上跑**
→ 它无论如何都不会阻塞 PR，`continue-on-error` 在这里**买不到任何"不阻塞"的好处**，
唯一效果是让失败（含依赖缺失、真回归）也报成绿。

进一步读代码发现**两步性质不同，不能一刀切**：

| 步骤 | 性质 | 处置 |
|---|---|---|
| `e2e/tamper-matrix/tamper-test.mjs` | **纯测量脚本**：输出绕过矩阵，无任何断言、不设退出码 | 保留 `continue-on-error`（它恒为 0，去掉无意义），但**改掉"门禁"的暗示** + **上传产物** |
| `e2e/waf-lab/compare-real.run.py` → `compare-real.e2e.mjs` | **真断言门禁**：`process.exit(pass ? 0 : 1)`，含 200/表空/靶场异常等硬断言；run.py 忠实透传 rc | **去掉 `continue-on-error`** —— 它吞掉的正是真实的红 |

实测证据（为什么第二步必须去掉）：该 job 在 CI 上从来是绿的，而「Tamper effect matrix」
这一步跑的脚本**没有任何退出码逻辑**，配合 `continue-on-error` → 这一步**不可能失败**。
这与 §Y 首跑时发现「`node <不存在的文件>` + continue-on-error = 空转门禁」**同源**：
上次修了**路径**，没修**静音**。

顺带补了一个缺口：两步产出的 `results/` **都在 .gitignore 里**（`e2e/tamper-matrix/results/`、
`e2e/waf-lab/results/*.json`）→ 加了 `actions/upload-artifact`，否则数据从 CI 取不回，
这一步等于白跑。

#### 决策 ②：fileRead 在 CI 起不来沙箱时 —— 判 **BLOCKED（进 failed）**，不是 SKIP 也不是 FAIL

理由见 §Y 表格第 ③ 行。这里补**实施细节**与一个**实测纠正**：

判据从 `acceptance.mjs` 内联抽到 `e2e/lib/suiteVerdict.mjs`（可单测），并扩了漏检形态：

| 形态 | 输出特征 | 旧判据 | 现判据 |
|---|---|---|---|
| ① 沙箱内部抛错（超时） | traceback 栈顶在 `mysql_sandbox.py` | ✅ 认得 | ✅ |
| ② 启动器 import 失败（缺模块） | traceback 栈顶在 `run-with-sandbox.py` | ❌ **漏检** | ✅ |
| ③ 无 traceback（容器缺 python/mysqld） | 只剩 `[sandbox-run]` 前缀 | ❌ **漏检** | ✅（**且要求"从未就绪"**） |

⚠️ **形态③ 的第一版写错了，被真实数据打回**（值得记下）：第一版判据是
「有 `[sandbox-run]` 前缀 + 无 `[PASS]`/`[SKIP]`」，随后用仓库里真实的历史现场
（`e2e/results/last-failure-oob-real-lab.log`）与一个合成的**真回归样本**去验，发现它会
把「沙箱正常就绪、靶场正常、但断言真失败」也判成 BLOCKED → **真回归被掩盖**（放水方向，
比漏检更坏）。正解是**要求「就绪」这行不存在**：就绪过 = 沙箱没问题，失败在下游。

**测试**：`e2e/lib/suiteVerdict.test.mjs` 12 例，含 4 条**反例**（真回归不许被贴环境标签、
真实历史现场不许被认领、SKIP 优先于沙箱判据）。缺陷注入复验：把 `isSandboxDead` 短路成恒
`false` → 恰好 4 条变红（3 形态 + BLOCKED 归类），4 条反例**保持绿**（证明注入只打中了该打的方向）。

**接线**（避免"写了但永远不会跑第二次"）：`e2e/` 下的 `*.test.mjs` **不在**
`server/tests` / `src/tests` 的发现范围里 → 已在 ci.yml 的 lint job 与 `scripts/ci-local.mjs`
各加一步 `node --test "e2e/lib/*.test.mjs"`。
注意**必须用 glob**：Node 的 `--test <目录>/` 会把目录当成待 require 的模块
（实测报 `Cannot find module .../e2e/lib`、1 fail），不是"扫描该目录"。

### Z. 注入请求**发送侧**补齐 multipart（✅ 已修 2026-09-22）

**缺口性质**：引擎只能以 urlencoded / JSON 发出注入请求（`buildInjectionRequest` 的 body
分支就这两条路）。碰到**只吃 multipart** 的目标 → 目标解析不到字段 → 注入值从未进 SQL
→ **静默 0 检出**，症状与「没洞」无法区分。

⚠️ **易混淆点**：`-r` 的**导入侧**（`requestCollectionParser`）早就支持 multipart ——
Postman `formdata` 会构造真实报文、设 `Content-Type: multipart/form-data; boundary=...`，
再交给 `requestFileParser` 提取真实字段名。所以「引擎支持 multipart」的印象来自那里；
**真正缺的一直是发送侧**。

**修法**：body 分支新增一条 —— 目标请求头声明 `multipart/form-data` 时，按其 boundary
重建报文（文本字段 + 闭合段），未声明 boundary 时自动生成。
已知限制：只重建**文本字段**，file 类型字段以空值占位（字段名仍在；注入面在字段名/文本值上，
对 SQL 注入检测无影响）。

**验证**：

| 层 | 结果 |
|---|---|
| 单测 | **5/5**（`server/tests/injection.multipart.test.js`，含 2 条回归：普通表单仍是 urlencoded、JSON 目标仍走 JSON 且点路径叶子被替换） |
| 缺陷注入 | 让 multipart 分支不可达 → **恰好 3 个 multipart 用例变红**，回归用例不受影响；恢复后 5/5 |
| 端到端 | pentest-lab 新增 `/mp` 靶点（只接受 multipart，其它 Content-Type 一律 415）+ `verify.mjs` 新增 `mp` 场景 → 由 CI（有 MySQL）真验 |

**过程注**：本机 MySQL 当时没在跑（本地不随便起常驻进程），故端到端交给 CI；
靶场的 415 分流逻辑已用手工 curl 在本地验证（urlencoded / JSON 均 415，multipart 通）。


## P1 · 实战视角高价值

### 1. 真实 ModSecurity/Coraza WAF 验证（可执行步骤）
- **依赖**：需有 Docker 的机器（本机无 docker，exit 127 已实证；Dockerfile/docker-compose.yml 已在仓库根目录，可复用）
- **现状**：全部 WAF 绕过结论均为「自实现 CRS 执行器 ≈PL3」口径（`e2e/waf-real`，CRS v4.1.0 官方规则原文 942/930），README 已诚实标注但这是对外可信度最大短板
- **验收**：真实 ModSecurity + libinjection 引擎下复测 tamper 链绕过率，README「WAF 绕过能力实测口径」表新增一行真实引擎数据

> **✅ 2026-09-27 已自动化（步骤 0–4 全部落进 CI）**：新增 job `modsec-live`
> （`.github/workflows/ci.yml`），手动 dispatch 或周度触发即在 GitHub Linux runner 上
> 起真实 `owasp/modsecurity-crs:nginx`，PL1 / PL3 两档各跑一遍 228 插件 × 8 样本，
> 报告以 artifact 下载（`e2e/waf-real/results/modsec-docker-<档位>-<日期>.md`）。
> 探针 `e2e/waf-real/modsec-live.mjs` + 靶站 `modsec-target.mjs` + 样本单一来源
> `samples.mjs`（与静态扫描共用，守卫见 `server/tests/wafSamples.guard.test.js`）。
> 本机无 docker → 已在 `scripts/ci-local.mjs` 的 `EXCLUDED_JOBS` 登记并写明理由。
> **只剩步骤 5（报告口径写回 README）待真跑出数字后做。**
> 下面 0–4 保留原文，作为「换一台有 docker 的机器手跑」时的可复现手册。

#### 步骤 0 · 前置确认（Docker 机器上）
```bash
docker --version && docker compose version   # 均需可用
git clone <repo> && cd sqli-scanner          # 或同步工作区到 Docker 机器
```

#### 步骤 1 · 搭真实 ModSecurity 反代容器（`e2e/waf-real/modsec/`）
新建 `docker-compose.modsec.yml`（ owasp/modsecurity-crs:nginx 官方镜像，一次性起完整栈）：
```yaml
services:
  modsec:
    image: owasp/modsecurity-crs:nginx
    ports: ["8088:8080"]
    environment:
      - PARANOIA=3                          # 对齐现有 crs-engine 的 ≈PL3 口径
      - ANOMALY_INBOUND=5                   # 默认阻断阈值
      - BACKEND=http://host.docker.internal:8151
      - ENGINE_MODE=DETECTION_ONLY_NO_BLOCK # 先观察模式校准，再切阻断
    extra_hosts: ["host.docker.internal:host-gateway"]
    volumes:
      - ./modsec/crs-custom.conf:/etc/modsecurity.d/instance.conf:ro
```
- `crs-custom.conf`：`Include` 官方 CRS，显式开启 `SecRuleEngine On` + libinjection（`SecRule ARGS "@detectSQLi"`）
- 关键点：**用 CRS v4.1.0**（与 `e2e/waf-real/crs/REQUEST-942-SQLI.conf` 同版本），镜像 tag 固定为 `owasp/modsecurity-crs:nginx@sha256:<digest>` 保证可复现

#### 步骤 2 · 确定靶场后端拓扑
- 后端 = 现有 `real-mysql-lab`（3306 MySQL + lab-app，端口 8151），**引擎扫描目标指向 8088（ModSec）而非直连后端**
- Windows 主机跑 lab-app：容器内 BACKEND 用 `host.docker.internal:8151`；Linux 机器用宿主 IP
- 自检：`curl "http://<docker-host>:8088/num?id=1"` 正常回显 + `curl "http://<docker-host>:8088/num?id=1' AND 1=1-- -"` 被 403 → WAF 生效

#### 步骤 3 · 观察模式校准（防阻断阈值差异污染对拍）
- `DETECTION_ONLY_NO_BLOCK` 下跑一遍 `tamper-sweep.mjs`（改 BASE 指向 8088）
- 从容器日志（`docker logs`，`ModSecurity: Warning.` 行）提取真实命中规则号与 anomaly 分值
- 若 PL3 + libinjection 的命中集与自实现 crs-engine 的命中集有系统性差异（预期会有：libinjection 是额外探测器），逐条记录差异样本（payload / 命中规则 / 是否拦截）

#### 步骤 4 · 阻断模式正式复测
- 切 `SecRuleEngine On`（去 DETECTION_ONLY），复跑与现有口径**完全相同**的场景矩阵：
  - `tamper-sweep.mjs`（tamper off/on 对比）
  - `waf-verify.mjs`（num/str/like/blind/orderby 5 端点 + safe/echo 安全对照）
- 记录两组数：tamper off X/5 → tamper on Y/5 技术位；安全对照误拦数（应为 0，非 0 说明 CRS 误报，需样本分析）

#### 步骤 5 · 对拍报告与口径更新
- 结果落 `e2e/waf-real/results/modsec-docker-<date>.md`：与自实现引擎逐场景对照表（检出/绕过/差异规则号）
- README「WAF 绕过能力实测口径」表新增一行：`真实 ModSecurity（owasp/modsecurity-crs:nginx，PL3+libinjection）`，数字照实填；若与自实现差异大，在表下加一句差异归因（如「libinjection 额外拦截了 X 类 payload」）
- 若 Docker 不可得，可降级跑 **Coraza**（Go 实现，`docker pull corazawaf/coraza-spoa` 或本地 `go run`），口径注明「Coraza（ModSecurity 兼容引擎）」——同样是真实引擎，可信度高于自实现

#### 常见坑（提前备好）
- 镜像默认 `ENGINE_MODE` 与 `PARANOIA` 环境变量名随版本变——起容器后 `docker exec` 进去 `cat /etc/modsecurity.d/*.conf` 核对生效值，别信文档
- Windows Docker Desktop 的 `host.docker.internal` 在 Linux 机器不存在——用 `host-gateway` extra_hosts 或直接 `--network host`
- CRS 版本漂移——务必固定镜像 digest 并在报告中记录镜像版本 + CRS 版本 + PARANOIA + 阻断阈值四要素，否则结果不可比

#### 2026-09-27 真跑暴露的一个**既有的红**（与本轮改动无关，别赖到新 job 头上）

手动 dispatch run #84 时 `tamper-waf-matrix` 报 **failure**：
`python3 e2e/waf-lab/compare-real.run.py` → `RuntimeError: 沙箱 datadir 未初始化`。
- 为什么以前没看见：该 job 仅在 `schedule || workflow_dispatch` 时跑 → **push 时恒 skipped**，
  所以 CI 一直绿。它不是新引入的红，是**一直存在、只是没人触发**。
- 与 `modsec-live` 无关（后者两轮均 success）。
- ~~待办：修 `compare-real.run.py` 在 GitHub runner 上的 datadir 初始化（或明确标注该路径在 CI 上不支持）~~
  —— **✅ 已按第二选项处理（2026-09-27）**：CI 侧改用与 acceptance 同款的 docker MySQL
  （走 `compare-real.e2e.mjs`），`compare-real.run.py` 本体保留给本机 Windows 用、不再挂 ubuntu CI
  （见 `ci.yml` tamper-waf-matrix 段注释）。**2026-10-09 复核：该 job 每轮 dispatch 均 success。**

### 2. NTLM 接线 HttpClient（✅ 已完成）
- **✅ 已接线（commit f5c40ae）**：独立模块 `core/ntlmHandshake.js`（NtlmHandshake 状态机：cred/preAuthHeader/replay/clear），HttpClient 请求前预附加 Type3（已握手主机免重复挑战）+ 401+NTLM 挑战时三步握手重放（上限 2 跳）；NTLM 模式不发 Basic 头
- **✅ DES 部署前提已消除**：desEcb 换自实现 `core/desEcb.js`（与 OpenSSL 交叉验证一致），不再依赖 `--openssl-legacy-provider`
- **✅ 测试覆盖（14 项）**：模块级 12 项（RFC 1320 向量 + Type1/2/3 闭环）+ HTTP 层集成 2 项（`ntlmHandshake.http.test.js`：mock server 401+Type2 → 自动 Type3 → 200 闭环、同主机状态复用 challenge 只发一次）
- **诚实边界**：mock server 不校验 NT/LM response 密码学正确性（模块级已钉 RFC 向量）；真实 IIS/NTLMv2 环境未实测
- **验收**：新增 NTLM mock 服务端 e2e（401→Type2→Type3→200），README 口径表更新为 ✅

### 3. 二阶跨角色双身份靶场 e2e
- **现状**：`secondOrder.storeCookies`（低权写入）/`triggerCookies`（高权读出）已实现并通过 20/20 单测 + real-world-lab 9/9 回归，但缺端到端双角色场景
- **实现点**：real-world-lab 增加 `/panel-admin`（仅 admin 会话可见的触发页），验证跨角色配置能检出单身份场景漏掉的二阶注入
- **验收**：verify.mjs 新增场景 PASS，README 二阶口径补一句实测结论
- **✅ 已完成（2026-09-14）**：real-world-lab 新增 admin-only 触发页 `/admin/panel`（users.admin 角色门禁 403）+ admin 会话禁写评论（403）；verify.mjs 新增 `second_order_crossrole` 场景——alice（user 会话）写评论、/admin/panel（triggerCookies: admin 会话）触发，检出 `[second_order]`（25 请求 4.1s），自检三连（写入 200 / admin 触发 500 真实引爆 / user+匿名 403 跨角色门禁）全过；现有 second_order 场景切 user 身份后零回归（real-world-lab 10 场景全 PASS）。README 二阶口径已补实测结论

### 3b. redteam-lab env.mjs 间歇性死亡根因排查（✅ 已结案 2026-09-14：连接风暴）
- **现象**：spawn 版 env.mjs 在 run-scan 中段无栈死亡（1/26、4/26、6/26），死亡点随机
- **根因（已坐实）**：**lab-app 的 `q()` 每条查询新建 TCP 连接再销毁**——26 靶点全量扫描 ≈ 2600 次高频短连，连接风暴下 node（靶场）与 mysqld 双双 native fast-fail（CrashDumps 同时存在 node 崩溃观测 `0xC0000409` 与 `mysqld.exe.5948.dmp`）
- **排查过程**（redteam-death-diag.mjs，5 轮对照实验）：
  - 抓到退出证据：`code=3221226505(0xC0000409) signal=null killed=false` → **native fast-fail 自崩，排除外部杀/进程树关联假设**（外部杀必有 signal）
  - stderr 全空 → 排除 JS 异常路径；内存曲线 154→270MB 正常 → 排除 OOM；pipe/inherit 均死 → 排除 stdio 管道断裂；`--report-on-fatalerror` 无报告（fast-fail 绕过诊断钩子）；WER/Defender 无记录 → 排除 EDR
  - 池化改造后连续 2 轮全存活（18/26、19/26），gate-check 19/19 rate=100% [PASS] → 根因坐实
- **修复**：`q()` 与两处 safe 端点改用常驻连接池（poolVuln/poolSafe 分池，严格保留 multipleStatements 语义边界防堆叠能力泄漏到安全端点）
- **教训**：靶场自身的「每请求建连」反模式 + 高频扫描 = 双进程 native 崩溃；门禁此前形同虚设掩盖了它。`--report-on-fatalerror` 对 fast-fail 无效，Windows 下抓这类死亡要靠 exit code（0xC0000409）+ CrashDumps 目录

### 4. 大文件二期拆分（照 scanRunner 模式）（⚠️ 2026-09-23 实测：本项数字已全部过期）
- **实测行数（2026-09-23，`wc -l`）**：`core/httpClient.js` **1115**（原记 1913 —— 已拆出 `core/http/requestContext.js`）、
  `engine/Extractor.js` **884**（原记 1388）、`engine/ScanManager.js` **756**（原记 1003）。
  **三者均已低于 1200 行软上限，`arch-guard` 对它们零告警。**
- **真正还在体积债上的只有 `engine/payloadRegistry.js`：167.2 KB / 983 行**（行数不超、**字节超**，
  已在 `scripts/.arch-baseline.json` 显式登记；字节判据见 D1）→ 出路是 E5 的声明式加载源切换，不是"拆分"。
- **结论**：本项**不再由架构门禁驱动**，降级为「机会性重构」。若要做，按下面的模式与验收口径执行；
  若不做，把额度投给 A3（WAF 通道降级编排）这类产品能力缺口更划算。
- **模式**：参考 scanRunner 第一轮「阶段外移」——纯搬移封边、输入输出注释明确、行为零变化
- **验收**：全量单测 + e2e 关键 lab（real-mysql/waf-real）回归通过

## P2 · 工程化补强

### 5. coverage 门禁数据刷新（✅ 已完成 2026-09-17）
- **✅ 已完成（2026-09-17）**：
  - 前端实测 `stmts 90.01 / branch 79.01 / func 70.64 / lines 90.01`（补测后由 89.47 提升），
    门禁由 **FAIL 转 PASS**；阈值按「实测 −3pt」刷新为 **87 / 76 / 67 / 87**。
    旧阈值 90 压在实测 90.01 上（差 0.01pt）——门禁架在刀尖：既容不下正常波动，也防不住真回退。
  - 服务端实测 `lines 88.42 / branch 72.67 / func 75.75`，阈值刷新为 **85 / 69 / 72**
    （原 84/71/73；branch 余量仅 1.67pt，太脆）。
  - 本轮补测：`src/shared/htmlSanitize.ts` —— **此前 0% 覆盖的安全模块**（现 100%，
    另修复其 CSS 清洗产出畸形 HTML 的瑕疵：`url()` 残留右括号 + 双引号提前闭合 style 属性）；
    `src/shared/scanConfig.ts` 的授权范围解析（76.31% → 92.1%，scope 解析错 = 扫越界）。

### 6. 弱引用模块补直接单测（✅ 已完成 2026-09-18，含清单纠错）
- **⚠️ 本项原描述已证伪**：原文写「tamperRoutes / digestAuth / egressOpts / reportDelivery 仅 1 个测试文件弱引用」，
  但实测覆盖率完全相反 —— `egressOpts.js` 行覆盖 **100%**、`reportDelivery.js` **99.55%**、
  `digestAuth` 也有专属测试文件。**照原文补测等于白做工**。
- **真实缺口在清单未提之处**：`scanLedger.js` 行 **26.39%** / 函数 **0%**
  （只被 `bin/cli.js` 调用，CLI 走 e2e 不入单测；但 `cli.js ledger list|show` 是真实交付路径，
  且已有 163 个真实台账目录）。
- **✅ 已完成（2026-09-18，commit efabace）**：新增 `server/tests/scanLedger.test.js`（12 条，
  真实文件系统、不 mock 落盘）；覆盖率 **行 26.39→96.02% / 函数 0→91.67%**。
  补测过程实测并修复三个真实缺陷：
  1. **PoC 落盘恒为空（交付级）**：`_attachPoc` 惰性且不可变（返回新对象不回写入参），
     CLI 传原始 report → `if (!v.poc) continue` 全命中 → **163 个真实台账 0 个 poc 文件**。
     修：CLI 两处改传 `rg.attachPoc(report)`。真靶场验证：修复版 poc=5 / 回退版 poc=0。
  2. **`getScan` files 分隔符随平台**：`poc\a.txt` vs `recordScan` 存的 `poc/a.txt`，
     消费方 `startsWith('poc/')` 过滤恒为空。修：统一归一为 `/`。
  3. **scanId 路径穿越**：`../x` 可建目录到 ledger 根之外（`getScan` 的 scanId 直接来自 CLI 参数）。
     修：新增 `safeScanId` 拒绝分隔符/`..`/绝对路径/`\0`。
- **教训**：清单里的模块名与数字都可能过时。**补测前必须先跑覆盖率报告**
  （`cd server && npm run test:coverage:report`）再决定打哪。
- **副产品发现（✅ 已修 2026-09-20）**：`scanManager.scheduling.test.js` 与 `tamper.f20.test.js`
  存在**既有 flaky**（连跑 3 次 2/1/2 个失败，从不全绿）。根因是 `runScan` 轮询预算
  `200×5ms=1s` 太紧（测试注释自承"飘到 1.6s"），机器负载高时扫描未完成即断言。
  与本次改动零引用关系（已核实导入链）。
- **修法与实测（2026-09-20）**：两处都是「拿固定墙钟给异步流水线设上限」，等价于在测机器负载。
  - `scanManager.scheduling.test.js:49`：轮询预算 `200×5ms=1s` → `6000×5ms=30s`（语义不变，仍轮询到终态即返回）。
  - `tamper.f20.test.js:15` `runScanUntilDone`：固定 `8000ms` 超时 → `30000ms`（`TAMPER_SCAN_TIMEOUT_MS` 可覆盖）。
  - **验证**：两文件各自连跑 3 次全绿（scheduling 4/4 ×3；tamper.f20 10/10 ×3）；全量 `npm test` → 1896 用例 / 1895 pass / 0 fail / 1 skip。
  - **踩坑记录（勿重蹈）**：曾把 `runScanUntilDone` 改成「事件 + setInterval 轮询」双通道，
    结果三条全红且报 `cancelledByParent`（`Promise resolution is still pending but the event loop has already resolved`）。
    原因是原实现靠**未 unref 的 setTimeout** 在等待期维持事件循环活跃；一旦把 poll/timer 全 clear 干净，
    事件循环见底，父级判定本轮结束并取消剩余子测试。**此类等待定时器不得 unref，收尾时也不得把活跃锚清光。**

### 7. docs/ 数字口径单一来源（✅ 已完成 2026-09-18）
- 32 个 md 中的测试数/引擎等级表易失真（本次审计修正 2 处）。可复制 `dbmsEvidence.js` 模式：数字由代码统一导出，文档生成时引用
- **✅ 已完成（2026-09-18）**：建立 `docs/_facts.json`（实时口径唯一来源，由 `scripts/facts-sync.mjs --refresh` 实跑采集）
  + 三档命令 `facts:refresh` / `facts:check` / `facts:fix`，并把 `facts:check` 接入 `check:all` 与 CI 的 lint job。
- **本轮实测的漂移（5 处，修正前）**：

  | 位置 | README 原写 | 实测 |
  |---|---|---|
  | 徽章 | tests-2144 | **2172**（294 + 1878） |
  | 「测试」块·服务端 | 1850 个用例 | **1881** |
  | 项目状态·服务端 | 1850 用例（1847 pass） | **1881（1878 pass）** |
  | 项目状态·复测日期 | 2026-09-17 | **2026-09-18** |
  | 项目状态·服务端覆盖率 | 88.42 / 72.67 / 75.75 | **88.82 / 72.95 / 76.26**（偏差 0.51pt） |

- **关键设计决策**：
  1. **只严格校验 README**（对外门面）。`docs/` 下带日期的评估报告与 `release-notes-*` 是历史存档，
     改了就毁证据 —— 已实测它们确实含旧数字（263 / 1815 / 1850），**均按记录保留，不动**。
  2. **阈值不重复定义**：前端读 `vitest.config.ts` 的 `coverage.thresholds`，服务端读 `server/package.json`
     的 `--test-coverage-*` 参数。
  3. **覆盖率给 0.2pt 容差，其余精确比对**：实测同一台机器连跑 3 次，前端 branch 得 79.03 / 79.01 / 79.01
     （抖动 0.02pt，其余字段稳定）。逐位精确比对会把门禁变成 flake 源 —— 正是本项目最反感的「假红」。
  4. **规则未命中即报错**（不静默跳过）：README 结构一变、规则失效，必须显形，否则校验会变假绿。

- **踩到的两个真坑（已修，留档）**：
  - **vitest 即使 stdout 被管道捕获仍输出 ANSI 颜色码**：`Tests \u001b[22m \u001b[1m\u001b[32m294 passed` ——
    数字前带转义序列，任何 `Tests\s+(\d+)` 都匹配不上；覆盖率表格同理。必须先剥离再解析。
  - **README 是纯 CRLF（575/575）且仓库无 `.gitattributes`**：按 `'\n'` 切分会让每行残留 `\r`，
    而 JS 正则的 `$` **不匹配**尾部 `\r` 之前的位置 → 带 `$` 锚点的规则**全部静默失效**（实测踩到）。
    现按检测到的 EOL 切分并原样写回，`--fix` 后 `git diff` 恰好 3 行、CRLF 保持 575/575。

- **顺带清掉一个同类缺陷**：`.eslintignore` 被 ESLint 10 的 flat config **静默忽略**（文件已废弃），
  内容又已被 `eslint.config.js` 的 `ignores` 完全覆盖 —— 一个「看起来在管、实际不工作」的配置，
  与文档数字漂移同源。已删除，删除前后 `npx eslint .` 均为 0 error / 6 warning（无行为变化）。

### 7b. 建议新增 `.gitattributes`（✅ 已完成，本条已过时）
- **实测修正（2026-09-20）**：`.gitattributes` **已存在**，且已按实际需求落地（原文"仓库无 .gitattributes"过时）：
  ```
  e2e/waf-real/crs/** -text
  server/src/core/tamper/upstream-sqlmap-tamper.json -text
  ```
- 取向与原文建议**相反**：不是 `* text=auto` 全仓规整，而是给 **sha256 校验的上游快照**打 `-text`，
  保证字节级保真（CRS 官方回归集、sqlmap upstream tamper）。这比"eol=lf 全仓"更贴合本仓的核心风险
  —— 快照被 EOL 转换后 hash 对不上，保真度门禁会假红。
- 仍可补的（低优先）：`*.md text eol=lf` 治 Windows↔Linux checkout 的整文件 diff 噪声。

### 7c. 前端 func 覆盖率低 = 指标假象（✅ 已查清 2026-09-18）
- **原判断被实测证伪**：此前评估写「func 70.64% 说明存在整块未执行的函数，属函数级盲区」。
  实测把未覆盖函数逐条拉出来后，**这个说法不成立**。
- **实测结构**（`coverage/coverage-final.json`，293 个函数）：

  | 类别 | 数量 | 说明 |
  |---|---|---|
  | 未覆盖合计 | 86 | 占 29.35% |
  | 其中 JSX 内联事件处理器 | **69** | onChange/onClick/onClose 之类，靠用户交互驱动 |
  | 其中「真逻辑」函数 | 17 | 且多数是 1–2 行透传（如 `goScan = () => navigate('/scan')`） |
  | 其中**带分支逻辑值得测** | **4** | 见下 |

- **本轮实际补测的 4 个（21 条用例）**：
  | 函数 | 文件 | 为什么值得测 |
  |---|---|---|
  | `renderValidity` | `components/progress/` | 可信度守卫的 UI 出口（被封/目标挂/会话失效时用户唯一看到的提示），此前 0 覆盖 |
  | `setApiToken` | `shared/apiClient.ts` | **鉴权**：trim/空值归一/localStorage 持久化/隐私模式降级 |
  | `setApiBase` | `shared/apiClient.ts` | **桌面版命门**：sidecar 随机端口经此注入，错了就「连不上」 |
  | `handleImportRequestFile` | `components/TargetForm.tsx` | 唯一带 IO 的多分支处理（取消/解析失败/成功/抛异常），结果直接决定扫描目标 |

- **量化结论**：21 条用例 → 4 个函数 → func 70.64% → **72.01%（+1.37pt）**，
  与 4/293 = 1.37pt 精确吻合，说明每一处都打在真逻辑上。
  但要到 85% 需再覆盖约 46 个函数，而真逻辑只剩 13 个 —— **数学上做不到，除非去测 JSX 样板**。
- **处置**：func 阈值**刻意不跟涨**（保持 67），理由已写进 `vitest.config.ts` 的注释；
  stmts/branch/lines 按「实测 −3pt」上调为 88/77/88。
- **教训**：覆盖率是**聚合指标**，会掩盖结构。看到某一维偏低时，先把它拆成「逐条清单」再下结论 ——
  否则容易把「组件里内联箭头函数多」误读成「有逻辑没测」。

### 7d. 沙箱配置不可复现（✅ 已修 2026-09-18，属真实缺陷）
- **现象**：`mysql_sandbox.py` 用 `mysqld --defaults-file=<INI>` 启动沙箱，但**全仓库
  搜不到任何生成该 INI 的代码**（只有第 48 行的引用）；而 INI 位于 `.mysql-sandbox/`（已 gitignore）
  且内含写死的绝对路径。
- **后果**：新克隆 / CI / 换机器跑 `--init` 会在「找不到 defaults-file」直接失败 →
  **README 报告的 UDF/os-shell 真机验证不可复现**。本机之所以一直能跑，只因为磁盘上
  遗留了一份来路不明的 INI（2175 字节，含 `secure_file_priv` / `plugin_dir` /
  「不要开 skip-name-resolve」等关键项与实测教训，全都只存在于那份未入库的文件里）。
- **修法**：新增 `render_ini()` + `write_ini()`，从脚本常量派生全部路径；在 `do_init` 与
  `do_start` 里**先落配置再起 mysqld**；`write_ini()` 幂等（内容不变不写）。
  另加 `--print-ini` 只读预览，无需启动任何进程即可校验配置。
- **验证（20 项断言全过，均为纯文本/文件操作，不启动 mysqld）**：
  删除 INI 后 `write_ini()` 能自建且**配置项与在用基线逐条一致**（不会把在用沙箱搞挂）、
  幂等、6 个路径项全部锁在沙箱内、`render_ini()` 与磁盘内容一致。
- **教训**：`gitignore` 一份「运行必需的配置」= 本地能跑、别人跑不了。
  凡 `--defaults-file` / 外部配置文件，**必须由代码生成**或入库，不能两头不占。

### 7e. 沙箱磁盘瘦身（⑤ 部分完成 2026-09-18）
- 已清理崩溃残留 `ibtmp1.DDA9.d`（孤儿临时表空间，MySQL 文档明确的 `ibtmp1.<随机>.d` 形态）：
  **202M → 190M**。只删孤儿，未动活动 `ibtmp1`。
- redo 日志仍占 ~100MB（`ib_logfile0/1` 各 50MB）。**不建议贸然改**：本机 MySQL 为 **8.0.28**，
  8.0.30 之前**不支持运行期改 redo 日志大小** —— 对已初始化 datadir 写 `innodb_log_file_size`
  会让 mysqld 拒绝启动。要瘦身必须重建：`SANDBOX_SMALL_REDO=1 python mysql_sandbox.py --init --force`
  （开关已实现并验证：追加而非替换，`skip-log-bin` 不丢）。默认关闭，避免把在用的沙箱搞挂。

### 9. 本地裸仓备份远端（✅ 2026-09-18 建立，属缓解非根治）
- **背景**：仓库长期无 remote（`gh` 未安装、无全局 git 身份、无 SSH 密钥 → 真远端与 CI 均阻塞），
  而本机 `.git` 有反复损坏史（`refs` 被整个删除、被标 Hidden）。
- **已做**：建裸仓 `D:/projects/sqli-scanner-backup.git`，加为名为 **`backup`** 的 remote
  （**刻意不占用 `origin`**，将来接真远端无冲突），push 全部分支 + tag。
  **验证方式不是「push 说 OK」**：实际 clone 出来核对 —— 131 提交与源一致、master 分支、
  两个 tag 在位、文件可读。
- **仍需你提供**：真远端地址 + 凭据。届时 `git remote set-url origin <url> && git push -u origin master --tags`
  即可，backup 可保留或删除。
- 提醒：本地裸仓能防 `.git` 损坏，**防不了磁盘故障**，不等于异地备份。

### 8. 前端测试环境差异固化
- ~~已修 `vitest.config.ts` 强制 `NODE_ENV=test`（jsdom 下 React production build 导致 246 个假失败）+ 契约测试 `@vitest-environment node`~~（已完成）；**CI 已搭建**（`.github/workflows/ci.yml`，2026-09-13）：lint/typecheck + 前端 vitest + 服务端 1767 用例 + `run-all` 自足 6 套靶场，ubuntu/Node 24。~~**剩余动作：push 后观察首次 CI 实跑**~~（Linux 与 Windows 的路径/换行差异只有真跑才能暴露）
—— **✅ 已完成**：CI 已实跑数十轮（含 ubuntu 双平台 matrix 与 e2e 套件），Linux 侧无平台性失败。
**2026-10-09 复核：本条不再有待办。**

---

### 10. 「脚本写了但没人能发现」的固化（✅ 已完成 2026-10-09，批次 D24）
- **普查结论**：`e2e/**` + `scripts/**` 的 197 个可执行脚本里 **47 个零引用**（口径：token 边界匹配；
  `CHANGELOG.md`/`TODO.md`/`AUDIT-SEC-2026.md` 属追加式历史**不算接线**；代码注释行不算；
  **自引用不算** —— 实测抓到 `scripts/probe-blob-400.mjs` 靠自己的 `'User-Agent'` tag 把自己接上线）。
- **处置**：删 39（30 个一次性根因诊断 + 5 个 payload-registry 迁移前的改码补丁 + 4 个已被单测接管的验证脚本），
  登记 8 个真还在用的本地工具进 `e2e/README.md`「本地手动探针」表（含依赖列）。
  ⚠️ 删 `verify-tamper-breakage.mjs` 前真跑过一次：`通过 4 / 失败 2`（des-ecb 在 OpenSSL 3 下 unsupported）
  ⇒ 它的 `exit(1)` 早就必红，只因没接线，这个红从没被看见。
- **守卫**：`server/tests/orphanScripts.guard.test.js` 四向（覆盖 / 分母不空转 / 取词自证 / 正反对照），
  `git ls-files` 不可用时**显式 skip**。缺陷注入 4/4 杀，其中第 2 条正是本项目反复出现的那类：
  把候选分类改坏后**主判据仍绿**，只有分母守卫会红 —— 分母不是形式主义。
  第 4 条是**真红不是注入**：`git add` 之后在全量套件里红一条，根因是**守卫文件自己贡献的 token
  把自己要抓的样本名接上了线** ⇒ 口径加了一条「守卫自己不当接线源」。
  ⚠️ 症状长得像"加了 git add 就红＝环境问题"，先单独复现再定位才敢定论。
- **留口**：门禁只管 `e2e/**` 与 `scripts/**`，`docs/**` 下的脚本未纳入；
  生产代码侧（`src/` + `server/src/`）同一口径 **0 命中**，所以本批没动生产代码。
- **验证口径**：改完任何 e2e/scripts 脚本后 `cd server && npm test` 里那条守卫必须绿；
  新增本地工具只有两条路 —— 进执行入口（ci.yml + ci-local.mjs 两处，见 `ciWiring.guard.test.js`），
  或写进 `e2e/README.md` 的表。名字埋在战报里不算登记。

### 11. lint 的上限与作用域（✅ 已完成 2026-10-09，批次 D25）
- **上限**：从「手挑 12 条」改为 **eslint:recommended 全集**，7 条例外逐条带实测数字与理由
  （98 处 `no-useless-assignment` / 86 处 U+3000 / 11 处控制字节 / 4 处"就是要匹配两个空格" /
  1 处"case 里只有取证注释" / 13 处字符类冗余转义 / 9 处空 catch）。
  换来约 45 条规则，其中 `no-dupe-else-if` 正是 D21 `--random-agent` 那类缺陷的形状。
- **作用域**：实测 `eslint .` 处理 1128 个文件而仓库只有 1094 个 —— 多管 35 个本机排障现场、
  静默吞掉 1 个入库 `.d.ts`。现由 `server/tests/lintScope.guard.test.js` 三向钉住
  （入库文件不许被吞 / 豁免理由不许变僵尸 / 本机现场必须继续排除）。
- **抓到的真缺陷**：3 个 tamper 插件把 Python 的 `\Z`（串尾）当 JS 断言 ⇒ 句尾关键词永不变形，
  且既有 doctest 一条都抓不到（样本全都不以关键词收尾）。
- **How to apply（今后动 lint 配置时）**：加例外必须给「实测 N 处 + 为什么在这里只产噪音」，
  不许只写"太严"；开任何一条新规则前先跑 `npx eslint -c <临时配置> .` 量一遍再决定；
  改配置后手动跑一次 `npx eslint . --format json` 与 `git ls-files` 对账（守卫只做静态比对）。
- **仍未清**：98 处 `no-useless-assignment`、86 处全角空格 —— 目前没有「改了能修什么缺陷」的例子，
  不为清零而清零。

### 12. 前端测试纳入类型检查（✅ 已完成 2026-10-09，批次 D26）+ **下一项：摘掉测试里的主动关闭**
- **本批**：`tsconfig.json` 的 `exclude: ["src/tests"]` 让 64 个前端测试文件**从没被任何静态检查看过**
  （vitest 用 esbuild 转译，类型错了照样绿）。新增 `tsconfig.tests.json` + `npm run typecheck:tests`
  并收进 `typecheck` 组合脚本（CI / ci-local / check:all 一处改完全链生效），
  打开即暴 **45 处**漂移：12 处 `expect(x).toBe(v,'说明')` 的说明被 vitest 静默丢弃、
  ScanWizard 夹具缺 `onPause/onResume` 又多传两个已不存在的 prop、
  ProgressView 用引擎不会发的事件类型 `'detect'` 与 `points:[{},{},{}]` 喂组件 … 已全修（45→0）。
- **下一项（D27 头一项）**：测试里现存 **37 处 `as never` / 42 处 `as any` / 37 处 `as unknown as` /
  5 处 `@ts-expect-error`** —— 每一处都是主动把刚建起来的检查关掉。逐处问"这层 cast 掩盖了什么"再摘，
  **不要为清零而清零**。已拿到的线索：`buildStartConfig(config?: Partial<ScanConfig> | null)`
  能接受 `ScanConfig`，调用点却写 `DEFAULT_CONFIG as never` ⇒ 多余 cast。
- **How to apply**：改任何 tsconfig 的 include/exclude 后跑
  `node scripts/../server/tests/typecheckScope.guard.test.js` 那条守卫（`cd server && npm test` 会带上），
  它钉的是「每个入库前端文件至少被一份根级 tsconfig 覆盖」+「typecheck 组合脚本与 CI/ci-local 两侧都串上」。

### 13. 「进了检查范围」≠「真在被检查」：cast 棘轮（✅ 已完成 2026-10-09，批次 D27）
- **本批**：D26 打开 `src/tests` 类型检查后，测试里仍有 **117 行** `as never` / `as any` /
  `as unknown as` 在原地关掉检查。摘掉打在**被测函数入参**上的那一批（3 个文件、−26 行 → 91 行），
  故意喂非法值的那几处换成**自反的 `@ts-expect-error`**（那行若没错了，指令自己报错）。
- **棘轮**：`server/tests/castBudget.guard.test.js` 按行计，`src/tests` ≤ 91、`src` 生产码 ≤ 11，
  只减不增；含自证与分母（判据扫不到 cast 必须红）。注入复验 2/2。
- **基线必须由判据自己产出**：先用 grep 量到 102 当基线，注入一条 cast 却不红 ——
  grep 把"注释里讨论 as never"的行也算进去了，判据剥注释后是 91。
  ⇒ 把基线临时设 0、从失败消息里读数，别用旁路探针。
- **下一项（若继续）**：剩余 91 行里 **`as any` 占 64 行**；但按 `mock`/`vi.fn`/`spyOn`/`stub`
  的启发式筛，只有 **20 行**真是 mock 管线（`(apiClient.get as any).mockResolvedValue(…)` 那种），
  另外 44 行是什么必须先分类再决定摘不摘——不要笼统说成"mock 写法，动不得"。
  （⚠️ 本条数字为剥注释后现测：早前用 `grep -cF "as any"` 量到的 69 含注释行，已作废。）
  生产码那 11 行本批未动，只钉住不许增长。
- **How to apply**：新增测试里要写 `as never`/`as any` 之前，先问"这层关闭掩盖了什么"；
  入参本来就合法就直接摘；非法值用 `@ts-expect-error`（注意它只管**紧挨的下一行**，
  且多余属性检查只作用于字面量直接进形参那种写法）。

### 14. 桌面导出/导入的授权范围 —— ✅ **已决策并修完（D49，决策 = (a) `$DOWNLOAD/**`）**
- **已修（D28）**：`@tauri-apps/plugin-dialog` / `plugin-fs` 从没进过 `package.json`，
  而"变量形式动态导入 + `as any`"把 Vite、TS、依赖表三层防护同时废掉 ⇒ 桌面「导出报告」
  「导入请求文件」两条功能**发货即坏**（旧产物里能原样 grep 到裸 `import("@tauri-apps/plugin-dialog")`）。
  现已入依赖、改回字面量导入、摘掉 3 处 `as any`，重新构建后 IPC 名被真正打进 chunk。
- ✅ **已决策 + 已修（D49）**：选 **(a)** —— `src-tauri/capabilities/default.json` 给
  `fs:allow-write-text-file` / `fs:allow-read-text-file` 各登记 `allow: [{ "path": "$DOWNLOAD/**" }]`。
  四个不确定点都是读本机 `~/.cargo/registry` 里的**真源码**定的，不是靠文档记忆：
  - `tauri-2.11.5/src/scope/fs.rs:419` `is_allowed()` = `allowed_patterns.any(matches)` ⇒
    **空 allow 列表恒 false** ⇒ 只加裸标识 `"fs:allow-…"` 等于**什么都没放开**，必须写**对象形态**；
  - `tauri-utils-2.9.3/src/acl/resolved.rs:313` `commands.allow.extend(...)` 无条件执行 ⇒
    对象形态**既授命令又加 scope**，不必再重复一遍裸标识；
  - `fs.rs:471` 对**不存在**的路径不 canonicalize（原样返回）⇒ 导出**新文件**照样过匹配；
  - `tauri-plugin-fs-2.5.2/src/commands.rs:1122-1136` 无 options 时默认 `create: true` ⇒ **不用**额外授 `fs:allow-create`。
- ✅ **守卫升级（同批）**：`server/tests/tauriPluginWiring.guard.test.js` 第 ④ 条从"标识在不在"
  扩成"**标识 + 范围**"三查，并新增 `EXPECTED_FS_SCOPE = '$DOWNLOAD/**'` —— 范围本身就是决策，
  谁把它换成 `$HOME/**` 会红着要求回来改常量并同步 TODO/CHANGELOG。`KNOWN_UNGRANTED` 已**清空**（豁免销账）。
  缺陷注入四发全中：退回 D28 / **只加裸标识不给 allow**（旧判据 `caps.has(perm)` 恰好看不出这个，会绿）/ 豁免不删 / 偷改范围 ⇒ 逐个红；还原后 5/5 绿。
- ⚠️ **残留限制（范围决策的代价，未修）**：`readTextFile` 同样只放开 `$DOWNLOAD/**` ⇒ 导入请求文件
  **只能从下载目录选**，用户在桌面/项目目录里选 `.req` 仍会被 scope 拒。要覆盖任意位置 ⇒ 升级到 (b) `$HOME/**`
  （属范围变更，按守卫要求得连 `EXPECTED_FS_SCOPE` 一起改）。另外越界时是裸抛 `forbidden path: …`，UI 无专门提示语（未做友好化）。
- ⚠️ **真壳验证仍欠**：`npm run tauri dev` 点一次导出、一次导入 —— 本机无 Tauri 桌面构建/运行环境
  （且"本机不起常驻/后台进程"是硬约束）⇒ 目前只有**源码级 + 守卫级**证据，**没有真机往返证据**，不许冒充已验。

### 15. 真机靶场跑出来的三笔欠账（⚠️ 2026-10-09 D29 开，均需决策或定位）
背景：本轮把 run-all 能跑的 27 套真靶场跑满（25 绿 / 2 确定性红），下列三笔是跑出来的账。

1. **pentest-lab `waf403` 的 `must:['boolean']` 确定性拿不到** —— ✅ **已修（2026-10-11 D38）**。
   已用单变量实验排除 D24–D28：把 D25 改过的 3 个 tamper 插件回退到改前 ⇒ 仍然红。
   机理已定位到"链选对了放行、没验语义"：`/waf` 服务端不做二次解码，而引擎给该点选的
   `chardoubleencode` 过 WAF 后落到 MySQL 是碎片 ⇒ error 有信号、boolean 物理不可达。
   **禁止**为了变绿把 `must` 改掉。复现：`node e2e/run-all.mjs --only pentest-lab`（走隔离沙箱）。

   —— ✅ **机理已定位到具体工位（2026-10-10 D31，用生产一致输入实测）**，两条此前被怀疑的
   路径**已排除**：
   · ❌ 保底逻辑（D20「替换末条」顶掉了有用的链）：实测兜底链 `chardoubleencode` 因 D19 补的
     `TAMPER_COVERS` 关键词全覆盖 ⇒ hit 最高 ⇒ **稳居排序后池子第 0** ⇒ 保底分支的
     前置判断（"兜底不在名单内"）**从不成立** ⇒ 替换/追加两种实现在该场景下返回逐字相同的名单。
   · ✅ 真根因：正因为它排第 0，它就是**第一条被验证、也第一条放行**的链 ⇒ 被选中重跑 ⇒
     双编码落库是碎片 ⇒ 只有 error、没有 boolean。判据应是「**过了还能不能用**」，不是「能不能过」。
   · ✅ 真正能用的是 `symboliclogical`（AND→&& / OR→||，语义等价；显式指定实测 842ms 拿到
     boolean），但它是静态链**第 3** 位，而 `slots = maxChains - generatedSlots = 2`
     ⇒ **根本进不了验证名单**（与保底逻辑无关）。

   **要定的事（三选一，都要真机验证）**：
   | 方案 | 做法 | 代价 / 风险 |
   |---|---|---|
   | A. 动 COVERS 口径 | `chardoubleencode` 去掉"关键词全覆盖"（整串编码是传输层伪装，不是消除）⇒ 它不再排第 0，靠 D20 显式保底保名额 | ⚠️ 这正是 D19 修 acceptance `pentest-lab` 11/11 的支点，可能回归 |
   | B. 增大 slots | `MAX_CHAINS` 3→4，让第 3 条静态链进得来 | 违反预算纪律（每目标多 1 次探针请求） |
   | C. 语义等价复核 | 验链放行后再验一次"真/假两侧同形且结果不同" | 新机制 + 额外请求，但收益覆盖所有 WAF 场景 |

   ⚠️ 方向性结论：**任何"让兜底链排得更前"的改动都在加剧这个缺口**，别再往那个方向使劲。

   ✅ **解法（D38，已落地并真机验证）**：判据从「能不能过 WAF」改成「**过了还能不能用**」，
   三处配合且**零额外请求**（不动 `MAX_CHAINS` 预算，故 B 的代价没有发生）：
   | 改动 | 位置 |
   |---|---|
   | 关键词模式识别：被拦 token 里关键字占多数 ⇒ `keyword-blacklist`（拿不准返回 null 不加权） | `blockProfile.blockedPatternOf` |
   | 该模式下 hit **只数关键字**（否则"顺带覆盖 comment 的链"靠杂项高分 ⇒ 对症链同不了分） | `rankChainsByProfile` |
   | 整串编码链（`eliminatesAll`）的关键字覆盖**不计分**（语义取决于服务端是否二次解码） | 同上 |
   | 同分时**对症优先**：`symboliclogical` 在语义索引里标 `applicablePattern: 'keyword-blacklist'` | `bypass/semantics.js` |
   ⇒ 排序后 `symboliclogical` 第 1、`chardoubleencode` 退第 2（**保底没丢**，仍在前 2 的验证名额内）；
   `pentest-lab` **12/12 PASS**，waf403 `检出=[boolean]` 577ms，CRS 保真 99.6% 未动，WAF 单测 52/52。
   **缺陷注入 4/4 杀**（三处判据 + 语义标记各打一次）。
   ⚠️ 一条既有断言按证据改了形态：`waf.dbmsAwareChains.test.js` 的 D19 用例原要求"编码兜底链
   必须**排链首**"—— 链首 = 第一条被验证并放行 = 被选中重跑（正是本缺陷），真正要保证的是
   "在验证名额内、前面全拦时轮得到它"（由 D20 显式保底保证）⇒ 断言改为"必须在前 2 条内"。

   🧪 **A 的变体已实测（2026-10-11 凌晨，改完即回滚，未提交）**：不动 `TAMPER_COVERS` 声明
   （避免触发 D20 的 COVERS 口径守卫），只在 `rankChainsByProfile` 里对**含 `eliminatesAll`
   插件的链**把 `and/or/union/select/sleep/comment/hash` 这几类 token **不计入 hit**。
   - 排序层**确实生效**：离线同输入复现 ⇒ `chardoubleencode` 从第 0 掉到末位，
     `symboliclogical` 升到……**第 3 位**（前两位是 `unionvaluesrow+dash2hash[+hexliterals]`，
     它们 covers 含 union/select ⇒ 同样 hit=2，靠稳定排序的原序占先）。
   - 但 `slots = 2` ⇒ symboliclogical **依然进不了验证名单**；端到端 `pentest-lab` 仍是
     `FAIL(miss=boolean)`，验证名单实测为
     `[unionvaluesrow+dash2hash → chardoubleencode（D20 替换末条）→ bypass:modsecurityversionedkeywords]`。
   ⇒ **结论：A 单独修不好 waf403。** 它只能消除"编码链靠伪装覆盖压过语义等价链"这一层，
     第二层（slots=2 与"真机打穿链占前两位"）必须靠 B 或 C 一起解。别再单独试 A。
   ⚠️ 另一条已验证**无效**的路（勿重复）：把兜底改成"追加在末尾" —— `verifyTamperChains`
     第 194 行还有一道 `ranked.slice(0, MAX_CHAINS)`，第 4 条会被**静默切掉** ⇒ 兜底比替换式更糟。
2. **api-range-lab 两条 `[ai]` 用例确定性 404 / code 2001「扫描任务不存在」** —— ✅ **已修（2026-10-09 D30）**。
   根因**不是**用例写法，是 TTL：`ctx.state.numScan` 背后是 ScanManager 的**内存上下文**，
   扫描终态后进入 `retiredAt`、**默认 30s 回收**，而 AI 路由查的正是这张表
   （`sm.scans.get(id)` 拿不到就 404 / code 2001）。全序跑到 ai 组时早已过 30s
   ⇒ 无条件复用 = 赌机器快慢（只跑 `--groups=ai` 6/6 通过，全序必红）。
   修法：给缓存加**年龄闸**（`NUM_SCAN_MAX_AGE_MS = 15000`，默认 TTL 的一半），过期就重新扫。
   全序 **49/49 PASS**。
   **缺陷注入 3/3 杀**：把闸改成无条件复用 ⇒ 2 条 `[ai]` 404 + 1 条 `[exploit] POST /exploit/sql`
   （吃同一个缓存）—— 也就是说这口闸同时保住了 exploit 组，D29 只记了 2 条红是记少了。
   ⚠️ 留下的尾巴：`ScanManager` 的回收 TTL 是**产品行为**（不是测试缺陷）；用例侧加了年龄闸
   只是让判据不再赌运气。若以后 AI 报告需要对**已完成较久**的扫描也能出，那是产品侧要改的
   （例如落盘台账可回读），别在用例里加长 TTL 去绕。
3. **这两套都不在 CI 里** —— ✅ **已接（2026-10-11 D39）**：`ci.yml` 的 `acceptance` job 新增两步
   （`node e2e/pentest-lab/verify.mjs` 与 `node e2e/api-range-lab/run.mjs`，各配 `MYSQL_*` env 直连
   该 job 已起的 docker MySQL 3306）。不需要 Python 沙箱（沙箱只解决"本机没 mysqld"）；
   `init-db` 建的 `users`/`products` 正好覆盖两套，api-range-lab 缺表时还会自己再跑一次 init-db。
   本机验证：两套的"env 直连"路径已跑通（沙箱注入的就是同一组变量）⇒ pentest-lab 12/12、
   api-range-lab 49/49；`refs:check` 174 处全入库、读 ci.yml 的 5 个守卫 27/27、YAML 解析通过。
   **待确认**：CI 侧**首跑**（Linux + 容器 mysqld 与本机组合不同，本机无 docker 无法先验）；
   判据是退出码，环境出问题会显式 FAIL 而不是静默 SKIP。
   `scripts/ci-local.mjs` 未同步（它只整步跑 `npm run acceptance`，本机这两套走
   `node e2e/run-all.mjs --only=...`，覆盖面不缺）。
   ⚠️ 若并发会话随后推送（基于不含本提交的树）⇒ 这两步会被覆盖，按 CHANGELOG D39 段重放。
   （原条目：）`ci.yml` 对 `pentest-lab` / `api-range-lab` 零引用，
   `e2e-self-contained` 只收敛 `deps: []` 的 6 套，而它们依赖 MySQL 沙箱（CI 无 mysqld）。
   ⇒ 上面两笔红从第一次跑到现在没人看见。**顺序必须是：先定位/修，再接进 CI**
   （直接接进去只会得到一个天天红、然后被人加 `continue-on-error` 关掉的 job —— 那是 K 条的老路）。
4. **PG 那 3 套的解锁** —— ✅ **已修（2026-10-09 D30）**：`run-with-sandbox.py --with-pg`
   （同进程内两套引擎"起→用→停"）+ `run-all` 的 `pg` 探测改成"能自起就不算缺依赖"。
   三套**首次真跑通**：`pg-osshell` 17.6s、`oob-real-lab` 36.3s、`concurrent-isolation` 25.7s。
   配套修掉三个静默缺陷（详见 CHANGELOG D30 段）：探针连不存在的业务库 `sqli_lab`、
   `start_pg` 超时仍返回半死进程、`run-all` 的 `spawnSync` 在本机撞 EBUSY 把沙箱类全误标 SKIP。
   ⚠️ 顺带把 `e2e/run-with-pg.py` **从 `.gitignore` 里放出来并入库**（它 09-18 被故意排除）：
   不入库则上面两条路径在任何 clone 上都是坏的；`refs:check` 天然守着这条。
   **剩下的账**：
   ① 这三套不在 CI 里 —— ✅ **已接（2026-10-12 D50）**：`.github/workflows/ci.yml` 的 acceptance job
      起 runner 自带 PostgreSQL 16.15（`sudo systemctl start postgresql.service`，**不用 docker** ——
      OOB 链路是 PG 服务进程执行 `COPY (SELECT '') TO PROGRAM 'curl …'`，curl 必须在 PG 那一侧，
      宿主 PG 天然满足、容器镜像不保证装了 curl），三套以 `run: node <entry>` + `PG_*` env 直连。
      ⚠️ **接之前先修了两个假绿源**（否则接进去只会买到恒绿）：
        · `oob-real-lab/verify.mjs` 结尾是**无条件 `process.exit(0)`** —— OOB 没命中、对照组误报
          都只打一行"需排查"，退出码照样 0 ⇒ 任何接它的门禁都是恒绿。现改为 `exit(pass ? 0 : 1)`；
        · `pg-osshell.e2e.mjs` 把 PG 连接**写死** 127.0.0.1:5432/postgres/postgres（不读 `PG_*`），
          且 PG 连不上/非超管时 `exit(0)` 静默 SKIP。现统一从 `lab-app.mjs` 的 `PG_CONF` 取，
          并加 `PG_REQUIRE=1` 开关（口径同 `RECALL_REQUIRE_MYSQL`：默认 SKIP 不是代码缺陷，
          但"已经专门起了 PG 的门禁里跳过"= 降级 = 必须红）。
      **本机实测（不起任何数据库）**：默认 ⇒ `[SKIP]` + 退出码 0；`PG_REQUIRE=1` ⇒ `[FAIL]` + 退出码 1；
      `PGPORT=59999` ⇒ 报错端口随之变成 59999（证明真读了 env，不再写死）。
      **守卫（新增 ③④ 于 `server/tests/ciWiring.guard.test.js`）**：③ 三套必须在 ci.yml 接线；
      ④ 三套最后一个 `process.exit` 不得是字面量 0、不得写死 PG 端口/口令、SKIP 必须受 `PG_REQUIRE`
      控制。缺陷注入 **5 发全中**（退回无条件 exit(0) / 退回硬编码 / 删接线 / 删开关 / 开关不分支）。
      ⚠️ 其中「删开关」一发**第一版判据没红**：用 `includes('PG_REQUIRE')` 查，删掉代码后注释里
      还写着 `PG_REQUIRE=1` ⇒ 绿着放行（本仓第三次栽在"判据文本源没排注释"）。已改成查
      `process.env.PG_REQUIRE` + `if (PG_REQUIRE) {` 两个**代码形态**。
      ⚠️ **待确认**：CI 首跑（本机无 PG/docker 无法先验）。若 runner 的 PG 起不来，三套会**红**
      （不是悄悄 SKIP）—— 这正是本批的目的：让"没跑过"这件事看得见。
   ② `ensure_database` / `pg_ready` 这一层**没有单测**（纯 Python + 真 PG，目前只有端到端证据） —— **未做**，
   若下次再出现"静默半起"，仍要靠人读日志归因。
5. **⛔ 已证伪的方向：扩注入点形态到 `LIMIT` 位**（2026-10-10 复核，别再当待办推）。
   曾有提议把注入点形态扩到 `LIMIT ${raw}` / `HAVING` / `GROUP BY`，前置条件是先验证
   `PROCEDURE ANALYSE` 在 MySQL 8 上可用 —— **答案已存在，且是否定的**：
   `e2e/pentest-lab/probe-limit-expr.mjs` 实测 14 种表达式（`2-0`、`1=1`、`CASE WHEN…END`、
   `(2)`、`(SELECT 2)`、`(SELECT SLEEP(1))`、`0x2`、`1e1`、`2 PROCEDURE ANALYSE(1)`、`'2'` …）
   **全部语法错** ⇒ MySQL 的 `LIMIT` 参数**只接受十进制整数字面量**（连括号包裹都不行）
   ⇒ 无法塞进"求真假的表达式"，boolean/time 判据无从成立，UNION 也被语法禁掉。
   结论写在 `e2e/pentest-lab/verify.mjs:37-46`：这是 **SQL 语法决定的客观边界，不是引擎缺陷**。
   ⇒ 想提打穿链数，方向只剩 `HAVING` / `GROUP BY` 位（未验证）或造新的语义保持变换（研究型）。

## 环境清理备忘（一次性）

- [x] NRPT 规则 `.ooblab.test` / `.oob-lab.local` 已提权移除（2026-09-11 完成，`Get-DnsClientNrptRule` 确认清零）
- [x] MySQL 3307 实验实例（secure-file-priv 放行模式）已回收
- [ ] MySQL 3306 常规实例现为后台进程（bash_id 3eb9c610，runtime 存活）；按 mysql-start.bat 语义属本机常驻，无需处理，但注意下次开机需手动拉起
- [x] `D:/mysql/data-backup-20260912`（187MB）**已删除**（2026-09-14，数据未损坏已实证，雪绒确认无回滚需求）
- [ ] 实验用 pg 驱动 --no-save 安装已核验未污染 package.json，无需处理

## 诚实边界（README 已标注，勿夸大）

- 真实 ModSecurity/Coraza/商业云 WAF 未实测
- SQL Server `xp_dirtree` / Oracle `UTL_HTTP` OOB 模板未真机验证
- ⛔ 等级数据库（TiDB/DM8/ClickHouse/DB2/Sybase/Firebird/Informix/Access/MonetDB 共 **9 种**）仅有模板适配，结论视为待复核线索
  —— **SQL Server 与 Oracle 已于 2026-09-14/15 升级 verified，2026-09-22 补齐产物与版本凭证**，
  不再属于本行（见 `e2e/mssql-lab/results/VERIFICATION-2026-09-22.md`：4/4 PASS）。
- fileWrite / UDF / os-shell **均已跑通真机闭环**（fileWrite 见 `npm run acceptance` 的
  「fileWrite 真闭环」套件；MSSQL os-shell 见 `e2e/mssql-lab/results/last-run-osshell.log`
  —— xp_cmdshell auto-enable 真实覆盖、回显 marker 命中；UDF 见 `e2e/udf-lab`）。
  仅**注册表**侧仍为 mock 单测。

---

## 已完成（2026-09-13 审计批次，留档防回归）

| 项 | 内容 | 验证 |
|---|---|---|
| NTLM 死文件修复 | 语法断裂 + 缺 import + DES key 截断三重缺陷；MD4 注释向量错误记忆值修正（权威对拍 6/6） | 12 项单测，legacy provider 下 12/12 |
| 前端测试假失败 | `vitest.config.ts` 强制 `NODE_ENV=test`（246 假失败恢复） | 40 文件 263/263 |
| qa_theme 错误断言 | `0f172a`（light 前景色）→ `getComputedStyle(body)` 断言 `rgb(10,14,22)` | 前端全量绿 |
| 契约测试挂起 | `@vitest-environment node`（jsdom 覆盖 node:url 导出） | 9/9 |
| eslint 清零 | scanRunner 20+ 死 import、detect.js `schedulerRef` 未定义真 bug | eslint exit 0 |
| 文档数字对齐 | README 徽章/正文 → 263/1767；docs 评估 1719 → 1753 复测口径 | 双端全量：前端 263/263、服务端 1764 pass/0 fail/3 skip |

> 更早批次成果（DNS OOB 真机验证、强动态页/定库加固、二阶跨角色、sqli-labs 23/23、L46 词边界修复等）见 README 各「实测口径」段与 `e2e/*/results/`。
