# WAF 真机样本采集 Runbook（P0-1）

> 目标：把台账 `waf-fingerprint-coverage` 从 `unverified` 推进到 `verified` 的唯一可接受路径——**真机样本**。
> 配套守卫：`server/tests/wafRealSamples.guard.test.js`（空快照显式 SKIP 不假绿；非空逐条正检 + 零误报反向 + 变异自证）。
> 配套收集器：`e2e/waf-real/cloud-sample-collector.mjs`。
> 判据与守卫同源：本文件与守卫的 schema 约定改任一侧必须同步另一侧。

## 0. 为什么是这道缺口

- 当前证据链：62 条 matcher + 判据单测 + D89 wafw00f 构造样本对拍 **18/18 厂商 100%**（36/36 样本）。
- 缺口：真机样本只有 **ModSecurity 1/62**——构造样本证明「同一份厂商特征我们认得」，**不证明真机必然命中**。
- 台账原文（`docs/_claims-ledger.json` 的 `waf-fingerprint-coverage`）：「未补证前对外只能说『62 条规则 + 判据单测』，不得说『识别准确率』」。

## 1. 合规红线（不可违反）

- **只采集你有权测试的目标**（你拥有的站点域名、或已获书面授权的测试目标）。内网/回环目标默认被 SSRF 防护拒绝，本 runbook 不绕过。
- 本仓库任何自动工具**不发攻击 payload**。收集器默认只发一次性良性 GET（与指纹阶段同行为）；「拦截页」形态的样本由**你在授权目标上自行触发**（如用 curl 发一条你确认安全的测试特征请求），再把响应 `--from-json` 导入，收集器不做攻击性探测。
- 采集到的样本禁止包含：真实会话 cookie 的完整值、登录态、敏感业务字段。`--from-json` 导入前先脱敏（value 只留前缀/特征片段即可，守卫只比对子串/存在性）。

## 2. 采集步骤

### 2.1 良性响应直接采（推荐起步）

```bash
# 对授权目标发一次良性 GET，自动识别厂商并写入快照
node e2e/waf-real/cloud-sample-collector.mjs --url https://your-authorized-site.example/page?id=1
```

- 适用：目标前置了 Cloudflare / 阿里云 / 腾讯云 / AWS WAF 等会在**正常响应**里带指纹头（如 `cf-ray`、`server: cloudflare`、`x-ws-request-id`）的 WAF。
- 识别成功会打印 `✓ <vendor>（evidence）` 并追加进 `server/tests/fixtures/waf-real-samples.json`。
- 识别不出时先看打印的候选；可以 `--expect <vendor>` 强制校验（识别结果不含该厂商则 exit 2，不落脏样本）。

### 2.2 拦截页形态（需自行触发）

很多国产 WAF（阿里云/腾讯云类）只在拦截时暴露指纹。做法：

```bash
# 在授权目标上自行触发一次拦截，抓取响应存成 JSON（示例：curl 保存头与正文）
curl -sS -D headers.txt -o body.html 'https://your-site.example/?id=1%27%20AND%201=1'
# 组装成收集器可读的 JSON
cat > capture.json <<'EOF'
{
  "status": 403,
  "headers": { "server": "aliyun", "x-request-id": "xxxx" },
  "body": "<html>...blocked by WAF...</html>",
  "note": "授权目标自触发拦截页"
}
EOF
node e2e/waf-real/cloud-sample-collector.mjs --from-json ./capture.json
```

> 注意：`?id=1' AND 1=1` 是你对手中**有完整权限**的目标做的一次性无害验证，不是对公网第三方批量探测。没有授权目标就不要做这一步，等有合法目标再补。

### 2.3 批量采集多家

逐家执行 2.1/2.2，覆盖目标（每家有 1 条即可支撑正向识别声明，建议每家 2–3 条不同形态）：

| 目标厂商 | 常见指纹形态（仅供核验，全部以抓包为准） |
| --- | --- |
| Cloudflare | `cf-ray` 头、`server: cloudflare`、`__cfduid` cookie |
| F5 BIG-IP | `set-cookie: BIGipServer*`、`server: BigIP` |
| 阿里云 WAF | `server: aliyun`、拦截页含「阿里云」 |
| 腾讯云 WAF | `server: tencent/stgw`、`x-ws-request-id` |
| AWS WAF | `x-amzn-requestid`、拦截页 "Request blocked by AWS WAF" |
| 百度云加速 | `server: bws/yunjiasu`、`via: yunjiasu` |
| 安全狗 | `x-powered-by-safedog`、`server: safedog` |
| 网宿 | `via: ChinaCache` 形态 |
| Imperva | `incap_ses` / `visid_incap` cookie |
| 360 企业安全 | `server: panyun` 形态 |

## 3. 验收口径（转 verified 的门槛）

快照满足以下全部条件即可把台账条目转 `verified`（在 `docs/_claims-ledger.json` 的 `recheck_batch` 注明本 runbook 与守卫 ID）：

1. `samples` 非空，且覆盖 **≥3 家不同厂商**（守卫强制）；建议 8–10 家对齐台账 caveat 原话。
2. 每条样本 `sourceRule === 'real-capture'`、带 `capturedAt` 时间戳与 `target`（脱敏域名）。
3. 守卫三项全绿：
   ```bash
   node --test server/tests/wafRealSamples.guard.test.js
   ```
   即：正向识别命中 + 零误报反向 + 变异自证（删规则必红）。
4. 全量回归不破：`cd server && npm test`（守卫属于 wiring 集合，`npm run gate:close` 会兜住）。

## 4. 常见失败与处理

| 现象 | 含义 | 处理 |
| --- | --- | --- |
| 收集器提示「未识别出厂商候选」 | 目标无 WAF 或 WAF 不在 62 家规则内 | 换目标；或核对规则（`server/src/core/waf/wafRules.js` 是否覆盖该厂商） |
| `--expect` 校验失败 exit 2 | 识别结果不含期望厂商 | 查看实际候选；样本可能串台（该厂商顺带命中别家规则），人员核对后决定是否采 |
| 守卫「干净响应被误识别」 | matcher 过宽（真缺陷） | **不是删样本**，是修 matcher/规则，修完重采 |
| 守卫「删规则仍能识别」 | 样本命中他家规则（特征太泛，如 `server: nginx` 类） | 换用更特异形态的样本（如厂商专属 `set-cookie` 前缀） |

## 5. 维护约定

- 快照被守卫与收集器共享：**新增/修改 schema 必须三处同步**（守卫 test、收集器 mjs、本文档 §schema）。
- 快照 `.json` 提交进仓库（属 fixtures，不 gitignore）；`e2e/waf-real/results/*` 的运行时产物才被忽略。
- 构造样本（wafw00f 快照、waf_rules_v2/v3 用例）与真机样本**物理隔离**在两个文件：前者不可混入 `waf-real-samples.json`（守卫的 `sourceRule` 检查会拦）。