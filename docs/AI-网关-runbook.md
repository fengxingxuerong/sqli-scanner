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
| `AI_REPORT_MAX_TOKENS` | 可选 | 默认 8192。推理模型（带 `reasoning_content`）生成长输出会拖过 per-step 超时，本地网关建议 2048（验收套件默认注入） |
| `AI_REPORT_MASK` | 默认 on | 默认脱敏（host → `<目标Host>`，路径 → `/***`）。**指向本机网关时建议 `=0`**：不脱敏 LLM 才能写出可直接复现的 PoC（D205 实测） |
| `AI_REPORT_TIMEOUT_MS` | 可选 | 未接线；超时由路由硬编码 120s（REST）与 `generateAiReport(report, timeoutMs)` 三均分 |

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

## 6. 运维坑（实测记录）

1. **ollama 0.40.12 拉取模型时 sha256 校验阶段可能挂死**（partial blob 已满 397MB 但
   `ollama list` 迟迟不出现）：杀掉 pull 客户端重试 `ollama pull` 即秒过（blob 已完整）。
2. **网关 401 三连**（/v1/models、/、/health 全 401）= key 不对或没带；先核对 key 再查 base。
3. ReportAI 在**模块加载时**读取 env —— 任何 wrapper 脚本必须先设 env 再 `import`
   （`e2e/ai-gateway-lab/run.mjs` 是标准写法）。
4. `generateAiReport` 有**结果缓存**（按报告指纹 + TTL）：同内容短时间二次调用会命中缓存，
   链路测试类场景要让 fixture 的 `startedAt`/`scanId` 每次变化（套件已处理）。
