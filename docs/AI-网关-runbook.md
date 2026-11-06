# AI 报告网关 Runbook（本地 LLM 网关 × ReportAI 流水线）

> [D228 2026-11-01] 本文是「AI 报告」功能对接**本地/自建 LLM 网关**的操作手册。
> 功能设计见 `docs/api.md`「AI 报告」节与 `server/src/services/ReportAI.js` 头注释；
> 本文只写「怎么把本地网关跑通」与运维坑。

## 0. 两种本地网关形态

| 形态 | 例 | 特点 |
|---|---|---|
| **模型网关**（开箱即用） | Ollama `127.0.0.1:11434` | 自带 OpenAI 兼容 `/v1/chat/completions`，key 随意填 |
| **自建代理网关** | dsh `127.0.0.1:8326` 型 | OpenAI 兼容但带鉴权（401 = key 不对）；key 由网关方发放 |

两条链路不要混淆：AutoClaw 本地 token 服务（`127.0.0.1:18432/get_token`）签发的 JWT
**只用于 AutoGLM 自有接口**，对 open.bigmodel.cn / autoglm-api.zhipuai.cn 的 chat 路径
均返回 401/404（2026-11-01 实测）——不能当 ReportAI 的 key 用。

## 1. 环境变量矩阵（服务端读取，进 env 不进源码）

| 变量 | 必填 | 说明 |
|---|---|---|
| `AI_REPORT_API_BASE` | ✅ | **完整的 chat/completions 端点**（不是 host）。不设 = 功能关闭；只配 key 不设 base 会明确报错拒绝（opt-in 外发，防漏洞报告静默外发第三方） |
| `AI_REPORT_KEY_1/2/3` | ✅ 至少 1 个 | 按 role 分工（analyst/writer/reviewer 各用 1/2/3）；同角色 429 自动在其余 key 降级，再跨角色降级 |
| `AI_REPORT_MODEL_1/2/3` | 本地网关必填 | 覆盖默认模型名（`deepseek-v4-flash` / `glm-5.2` / `sensenova-6.8-flash-lite`）——**自建/本地网关常强制 provider/model 全名**（D192） |
| `AI_REPORT_API_BASE_2/_3` | 可选 [D254] | 按 key 索引配对的备用端点。三个角色/429 降级路径可分到**不同网关**；未配时逐项回落主 `AI_REPORT_API_BASE`，单网关行为零变化。验收套件用 `AI_GATEWAY_URL_2` / `AI_GATEWAY_KEY_2` 注入 |
| `AI_REPORT_429_COOLDOWN_MS` | 可选 [D254] | 429 冷却毫秒数，默认 60000（生产语义不变）。多网关分担时可设 3000，让降级立刻换端点而不是原地等 |
| `AI_REPORT_SHORT_RETRY` | 可选 [D255] | **默认开启**，设 `0` 关闭。writer/reviewer 首次「空内容 / 超时」失败时，用压缩后的短 prompt 再试 **1 次**；429 / HTTP 错误不重试（仍走原有 key 降级）。成功路径零变化 |
| `AI_REPORT_SHORT_RETRY_TIMEOUT_MS` | 可选 [D255] | 短重试单步超时上限，默认 20000；实际取 `min(每步超时, 该值)`。短 prompt 实测 4s 返回，20s 足够 |
| `AI_REPORT_STEPWISE` | 可选 [D259] | **默认关闭**，设 `1` 启用分步短 prompt：analyst 首轮即短请求，writer/reviewer 按 5 个章节逐章短请求后拼装。绕开「推理型网关长报告 prompt 挂起」；未开启时 D258 链路逐字不变 |
| `AI_REPORT_STEPWISE_MAX_CHARS` | 可选 [D259] | 单个短请求的用户消息字符上限，默认 1200（与 D255 短重试预算对齐） |
| `AI_REPORT_STEPWISE_TIMEOUT_MS` | 可选 [D259] | 分步单步超时上限，默认取 `AI_REPORT_SHORT_RETRY_TIMEOUT_MS`（20s）；实际 `min(每步超时, 该值)` |
| `AI_REPORT_MAX_TOKENS` | 可选 | 默认 8192。推理模型（带 `reasoning_content`）生成长输出会拖过 per-step 超时，本地网关建议 2048（验收套件默认注入） |
| `AI_REPORT_MASK` | 默认 on | 默认脱敏（host → `<目标Host>`，路径 → `/***`）。**指向本机网关时建议 `=0`**：不脱敏 LLM 才能写出可直接复现的 PoC（D205 实测） |
| `AI_REPORT_TOTAL_TIMEOUT_MS` | 可选 [D263] | **整场总闸**，默认 300000ms（5 分钟）。CLI 传入的 `timeoutMs` 被 /3 当「每步超时」，而流水线有三级降级 + 短重试 + 分步 11 章共十余步 ⇒ 慢网关可挂 10+ 分钟。所有 LLM 请求共享同一 deadline，单步超时裁到剩余预算，耗尽即抛「AI 报告总预算耗尽」并停止剩余降级/重试。实际取 `min(调用方 timeoutMs, 该值)` |
| `AI_REPORT_TIMEOUT_MS` | 可选 | 未接线；超时由路由硬编码 120s（REST）与 `generateAiReport(report, timeoutMs)` 三均分（[D263] 再受上面的整场总闸约束） |

## 2. 最小可用配置

### 2.1 Ollama（链路验证 / 低成本自托管）

```powershell
ollama pull qwen2.5:0.5b          # 链路验证模型（397MB）；生产建议 ≥7B
$env:AI_REPORT_API_BASE = 'http://127.0.0.1:11434/v1/chat/completions'
$env:AI_REPORT_KEY_1   = 'ollama'                      # Ollama 不校验 key
$env:AI_REPORT_KEY_2   = 'ollama'; $env:AI_REPORT_KEY_3 = 'ollama'
$env:AI_REPORT_MODEL_1 = 'qwen2.5:0.5b'                # 三个角色可同模型
$env:AI_REPORT_MODEL_2 = 'qwen2.5:0.5b'
$env:AI_REPORT_MODEL_3 = 'qwen2.5:0.5b'
$env:AI_REPORT_MASK    = '0'                           # 本机网关：不脱敏，PoC 可复现
node server/bin/cli.js -u "<目标URL>" --ai-report       # 扫描 + AI 报告一次完成
```

### 2.2 自建代理网关（dsh:8326 型）

同上，把 `API_BASE` 换成网关的完整端点、`KEY_1..3` 换成网关发放的 key；
模型名以网关 `/v1/models` 返回的 id 为准（网关 401 = key 不对，先 `curl -H "Authorization: Bearer <key>" <base>/v1/models` 排查）。

## 3. 模型分档（重要）

| 档位 | 模型 | 用途 | 实测表现 |
|---|---|---|---|
| 链路验证 | qwen2.5:0.5b（397MB） | 验证 HTTP 链路 / 脱敏 / 审阅 / 落盘全通 | CPU ≈75s/角色；输出极短（实测 93B 元回复），**内容不可用** |
| 生产建议 | ≥7B 自托管或云端（glm / deepseek / sensenova 系） | 产出可交付的漏洞报告 | 需按「漏洞盒子提交标准」prompt 实测校准 |

0.5B 级模型会输出「请提供漏洞报告内容」式元回复——**这是模型上限，不是链路故障**；
验收套件的判据只锁链路事实，不锁文风。

## 4. 用法与产物

- **CLI**：`--ai-report [dir]`（D205）。落点：带值用该目录；不带值用 `<--out 目录或当前目录>/ai-report/`。
  扫描结论不受 AI 失败影响（内部 `{ok:false, error}` 不抛异常）。
- **REST**：`POST /api/scan/:id/report/ai`（超时硬编码 120s）。
- **产物**：`ai-report.md`（正文）+ `ai-report.json`（元数据）。md 头部注释可复核来源：
  `source report`（scanId）/ `pipeline: analyst→writer→reviewer` / `elapsed` /
  审阅状态（`✅ 已经过安全审阅角色校验` 或 `⚠️ 未过审`）/ 数据脱敏标记。
  ⚠️ `ai-report/` 默认落仓库根目录时记得入 .gitignore（D228 已加）或显式传 dir。

## 5. 验收（套件 ai-gateway，D228）

```powershell
node e2e/acceptance.mjs --only=ai-gateway
```

[D254] 双网关分担（避免单网关 429 连环降级；`AI_GATEWAY_URL` 要 host，不带 `/v1`）：

```powershell
$env:AI_GATEWAY_URL = 'http://127.0.0.1:8080'
$env:AI_GATEWAY_KEY = '<主网关 key>'
$env:AI_GATEWAY_URL_2 = 'http://192.168.151.151:18080'
$env:AI_GATEWAY_KEY_2 = '<备用网关 key>'
$env:AI_GATEWAY_MODEL = 'glm-5.3-flash'
node e2e/ai-gateway-lab/run.mjs
```

⚠️ 2026-11-05 实测边界：这两个网关上 `glm-5.3-flash` 对**短 prompt** 4s 返回，
但 ReportAI 形态的长 system+user 报告 prompt 挂起不返回（30s abort，与是否含 SQL
payload 无关）。因此该套件在这两个网关上仍 FAIL；详见
`docs/llm-gateway-capability-2026-11-05.txt`。这是网关/上游侧限制，不是判据放宽的理由。

- **PASS**：真实 HTTP 网关跑完三角色流水线，断言「网关实调回声（model 链）+ 元数据头 4/4 +
  数据脱敏 on + 落盘字节数 >0 + 审阅角色 ✅」；
- **SKIP**：网关/模型未就绪 → `[SKIP] AI 网关不可用：…` + exit 0（未就绪不是失败，但写明原因）；
  自建网关注入：`AI_GATEWAY_URL` / `AI_GATEWAY_KEY` / `AI_GATEWAY_MODEL`；
- **FAIL**：流水线抛错（三角色全空）或断言事实不全。
- 判据边界：**不判报告文风质量**——那是模型分档问题（§3），不是链路问题。

### 5.1 [D255/D258 2026-11-06] 短 prompt 重试（失败路径的降级补救，不是「长 prompt 修好了」）

**触发**：analyst / writer / reviewer 首次调用返回空 content 或超时。11-05 决定性实验证明
长报告 prompt 挂起、短 prompt 4.1s 返回；11-06 双网关套件实测 analyst 出稿但
writer/reviewer 空（落盘「角色暂不可用」）。**D258 修正**：D255 的短重试只挂在
writer/reviewer，而三级降级实际全在 analyst 阶段就失败 —— 流水线走不到后两步。
现 analyst 主角色与 writer/reviewer 两级降级**都带短重试**，且短 analyst prompt
仍要求同一份 JSON 结构（`vulns` / `overall_risk`），否则重试成功也会被判非 JSON 降级。

**行为**：丢掉大段 SRC 模板，只留「一句任务 + 截断到 1200 字的事实 JSON / 报告节选」
再发一次；复用同一 cfg 与端点（不借重试偷偷换网关）；重试成功清掉首轮留下的 key
冷却，避免后续角色被「无可用 key」误挡。**只接受真实非空内容**，重试也空则保留原降级
文案，绝不把没产出记成 ✅ 已审阅。429 / 5xx 属于配额或故障，短 prompt 救不了，不重试 ——
端点切换由 D254 在**下一次** `getRoleConfig` 完成（429 冷却该 key → keyOrder 选另一 idx
→ `API_ENDPOINTS[idx]` 换网关）；writer/reviewer 单步 429 会直接降级，
**不在同一步内换网关重发**。另：套件内三角色串行 ≠ 网关侧无并发，
`user concurrency limit` 可由其它进程共用同一 key 触发。

**诚实边界**：`result.shortPromptRetries` 与 `ai-report.json` 只记录**真正产出内容**的
短重试角色。reviewer 走短重试成功时 `reviewNote` 仍是 ✅，但审阅基于**截断节选**而非
全文——引用「已审阅」口径时必须同时看这个字段，别只信 ✅。失败的重试不改变产出，
不落盘。默认关闭方式：`AI_REPORT_SHORT_RETRY=0`。

**效果以真网关套件退出码为准**（`node e2e/ai-gateway-lab/run.mjs`）。链路单测只证明
「请求确实变短、没有伪造成功」，不能证明模型会返回内容；未 PASS 就如实登记，
不放宽 `ai-gateway` 任何断言。

[D258] 没有可用真网关时，用 **mock-hang 网关**确定性复现「长 prompt 挂起、短 prompt 秒回」，
验证真 HTTP + 真 abort + 真重试这条链（无需外部 key）：

```powershell
# 终端 A：长 prompt 挂 5s、短 prompt 30ms 返回
node e2e/ai-gateway-lab/mock-hang-gateway.mjs
# 终端 B：per-step 超时 2s ⇒ 三阶段首轮必 abort，短重试必成功
$env:AI_GATEWAY_URL='http://127.0.0.1:18326'; $env:AI_GATEWAY_MODEL='mock-hang'
$env:AI_GATEWAY_TIMEOUT_MS='6000'
node e2e/ai-gateway-lab/run.mjs
```

判读：耗时 ≈ 3 ×（2s abort + 30ms 短重试）≈ **6.2s** 且审阅 ✅ ⇒ 三个阶段都真的
走了短重试；若 analyst 没接短重试，三级降级会先挂 6s 再失败，套件不可能 PASS。
2026-11-06 实测 6172ms，证据见 `docs/ai-短重试-真HTTP验证-2026-11-06.txt`。

### 5.2 [D259 2026-11-06] 分步短 prompt（主动拆章，opt-in）

**与 §5.1 的区别**：短重试是**失败之后**补一发短 prompt，仍要先挂 100s；
分步模式让**每个请求本来就短** —— 1 次短分析 + 5 次逐章短撰写 + 5 次逐章短审阅，
再按固定章节顺序拼装。开关 `AI_REPORT_STEPWISE=1`，默认关闭（D258 链路零变化）。

**事实保真**：writer 事实包与整篇 `buildWriterPrompt` 同源（脱敏、参数名、提取数据、
引擎实测判据 `formatBasis` 都随短请求发出）；PoC 章额外带原始 payload 与判据，
不因拆章丢「参数名逐字一致 / poc_verify 引用实测数字」这两条 D205 约束。

**失败语义**：单章空内容/超时 ⇒ 该章写「（本节生成失败，需人工补全；未由模型产出）」，
`stepwise.partial=true` + `failedSteps` 记录，**不编造、不冒充全文审阅**；
审阅按章进行，全部成功才写 ✅（标注 `n/n`）。5 章全失败 ⇒ 回退原整篇流水线并
登记 `fallback='legacy'`。`result.stepwise` 与 `ai-report.json` 如实落盘 ——
引用「报告完整 / 已审阅」口径时**必须同时看** `partial` / `failedSteps` / `reviewedSections`。

**套件判据（加严，不放宽）**：分步模式下额外要求 `partial=false`、`fallback=null`、
`failedSteps` 为空、章节数 >1；非分步模式该判据恒 true。

```powershell
# 无需外部 key：验证 11 个请求全短 + 真 HTTP 超时语义
node e2e/ai-gateway-lab/mock-hang-gateway.mjs        # 终端 A
$env:AI_REPORT_STEPWISE='1'; $env:AI_GATEWAY_URL='http://127.0.0.1:18326'
$env:AI_GATEWAY_MODEL='mock-hang'; $env:AI_GATEWAY_TIMEOUT_MS='6000'
node e2e/ai-gateway-lab/run.mjs                      # 终端 B
# 真实模型（Ollama 已就绪时）：AI_REPORT_STEPWISE=1 node e2e/ai-gateway-lab/run.mjs
```

**2026-11-06 真 HTTP 结果**（原样记录见 `docs/ai-分步短prompt-真HTTP验证-2026-11-06.txt`）：
mock-hang 分步 **462ms PASS**、同配置非分步基线 **6160ms PASS**（与 D258 的 6172ms 一致）；
真实 Ollama `qwen2.5:0.5b` 分步 **29966ms PASS**（5/5 章审阅、正文 12354B）、
非分步基线 **6246ms PASS**。462ms ≈ 11 × 30ms ⇒ 分步链路里没有长 prompt；
若混进一个长 prompt，2s per-step 超时必触发 abort，耗时不可能低于 2s。

**诚实边界**：分步**不省时间**（11 次推理串行和约 30s），它换的是「不再卡死在长 prompt」；
0.5B 是链路级模型，正文更长只说明章节齐全，**不判文风质量**。
glm-5.3-flash 生产网关本轮仍无可用 key，**未复跑** —— 不能宣称 `ai-gateway` 套件
在 D254/D255 那两个网关上已 PASS。
> **[D261 2026-11-06 补注]** 上句是 D259 当时的口径，保留不删。本机 dsh 网关
> （`127.0.0.1:8326`，250 模型）已用自带 key 复跑，结果见 §5.3：**仍 FAIL**。
> A/B zcode-proxy（8080 / 18080）本轮探活不可达，两个生产网关依旧未复跑。

### 5.3 [D261 2026-11-06] 本地网关复跑（真 HTTP，未改任何断言）

两个本地网关都在线时直接跑官方套件，判据 = 退出码；完整输出见
[`本地网关-真HTTP验证-2026-11-06.txt`](本地网关-真HTTP验证-2026-11-06.txt)。

| 网关 / 模型 | 模式 | exit | 事实 |
|---|---|---|---|
| Ollama `qwen2.5:0.5b` | 非分步 | **0 PASS** | 11990ms，审阅 ✅，元数据 4/4，落盘 710B |
| Ollama `qwen2.5:0.5b` | 分步 | **0 PASS** | 16838ms，writer 5 章 / 审阅 5 章 / `partial=false` |
| dsh `trae/glm-5.3-flash` | 分步 / 非分步 | 1 FAIL | 三轮降级全在 analyst 阶段 20s 超时 |
| dsh `deepseek-v4-flash` | 分步 2048 tok | 1 FAIL | `finish_reason=length` 空内容（推理占满预算） |
| dsh `deepseek-v4-flash` | 分步 4096 tok / 90s | 1 FAIL | 流水线跑完但 `partial=true`、审阅 0 章、未过审 ⇒ 加严判据正确判红 |

**真因（诊断探针实证）**：本地 dsh 网关 HTTP 链路与模型都可用——
`trae/glm-5.3-flash` 对真实分步 analyst prompt（468 字符）39.95s 返回合法 JSON、
`deepseek-v4-flash` 24.5s 返回合法 JSON；但默认单步 **20s** 对推理型档位不够，
放宽到 60/90s 后仍有空内容或逐章审阅失败。属**模型档位 / token 预算 / 上游波动**，
不是 ReportAI 链路缺陷，也不是判据该放宽的理由。

**可复现命令**（key 从 `~/.dsh/openai-gateway/api-key` 读，不写进文档）：
```bash
# 本地 Ollama（默认即它）
AI_REPORT_STEPWISE=1 AI_GATEWAY_TIMEOUT_MS=180000 node e2e/ai-gateway-lab/run.mjs
# 本地 dsh
DSH_KEY=$(node -p "require('fs').readFileSync(require('os').homedir()+'/.dsh/openai-gateway/api-key','utf8').trim()")
env AI_GATEWAY_URL=http://127.0.0.1:8326 AI_GATEWAY_KEY=$DSH_KEY \
  AI_GATEWAY_MODEL=trae/glm-5.3-flash AI_GATEWAY_TIMEOUT_MS=180000 \
  AI_REPORT_STEPWISE=1 node e2e/ai-gateway-lab/run.mjs
```

**边界**：**不得宣称 ai-gateway 套件在 dsh / glm-5.3-flash 上已 PASS**；
0.5B 只验链路不判文风；网关 `/v1/models` 列出 250 个 id 不等于 250 个可用档位。

**[D262 2026-11-06 补] CLI 真扫外部靶场时的本地网关表现**：用 `server/bin/cli.js --ai-report`
打第三方官方 DVWA（外部裁判，非自建靶场），Ollama 组 AI 报告完整（5/5 章审阅 ✅、
`partial=false`、18s / 4877B）；dsh `deepseek-v4-flash` 组虽落盘 1962B，但
`partial=true` / `fallback=legacy` / 审阅 0 章 / **未过审**，是半成品，不能当完整报告引用。
两次扫描结论（3 条命中、High、exit 2）逐字一致 —— AI 报告成败不改扫描结论（D205）。
证据见 [`CLI-本地网关-外部靶场实测-2026-11-06.txt`](CLI-本地网关-外部靶场实测-2026-11-06.txt)。

## 6. 运维坑（实测记录）

1. **ollama 0.40.12 拉取模型时 sha256 校验阶段可能挂死**（partial blob 已满 397MB 但
   `ollama list` 迟迟不出现）：杀掉 pull 客户端重试 `ollama pull` 即秒过（blob 已完整）。
2. **网关 401 三连**（/v1/models、/、/health 全 401）= key 不对或没带；先核对 key 再查 base。
3. ReportAI 在**模块加载时**读取 env —— 任何 wrapper 脚本必须先设 env 再 `import`
   （`e2e/ai-gateway-lab/run.mjs` 是标准写法）。
4. `generateAiReport` 有**结果缓存**（按报告指纹 + TTL）：同内容短时间二次调用会命中缓存，
   链路测试类场景要让 fixture 的 `startedAt`/`scanId` 每次变化（套件已处理）。
5. **超时 env 必须带 `AI_REPORT_` 前缀**（D263 实测）：写成 `STEPWISE_TIMEOUT_MS` /
   `SHORT_RETRY_TIMEOUT_MS` 源码完全不读，实际仍走 20s 默认；D262 证据文档里那两个名字
   已按推翻协议标注作废。正确名见 §1 矩阵。
6. **半成品报告不得标「✅ 已过审」**（D263）：`stepwise.partial=true`（分步 writer 全章失败、
   回退整篇）时头部与 `ai-report.json` 的 `reviewNote` 统一改为「报告不完整」；
   引用 AI 报告必须同时看 `partial` / `fallback` / `reviewedSections`。
