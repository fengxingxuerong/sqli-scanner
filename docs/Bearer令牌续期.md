# Bearer/Token 自动续期（长扫描的会话维持）

> 批次 D36（2026-10-10）。对应 CLI `--refresh-url / --refresh-token / --refresh-field`、
> REST `config.bearerRefresh`、面板「网络与认证」分段。实现：`server/src/core/bearerKeeper.js`。

## 1. 解决什么问题

现代 API 的主流认证是 `Authorization: Bearer <access token>`，access token 有效期通常是
15 分钟到 1 小时。而一次黑盒扫描动辄几千条请求、跑几十分钟 —— 于是**前 10 分钟的结果是真的，
后面全 401**。那半程在检测层看到的是"响应没有差异"，报告落成「未检出」，使用者据此收工。

本工具此前对认证只有两件事：静态注入（cookie/header 一次带上，过期即废）+ 会话失效**检测**
（`scanValidityGuard` 判出 authLost 后建议人工重取）。本模块补的是**自动续期**：收到 401/403
时调刷新端点换新令牌，重试原请求一次。

## 2. 与表单登录（`config.login`）的分工

刻意分成两个模块，不合并：

| | `config.login`（loginFlow） | `config.bearerRefresh`（bearerKeeper） |
| --- | --- | --- |
| 换什么 | 用户名密码 → 会话 Cookie | refresh 凭据 → 新 access token |
| 语义 | 表单（取登录页、探测输入框名、hidden/CSRF 透传、POST） | API（一个 POST + 从 JSON 里取字段） |
| 「失效」长什么样 | 401/403 **或 302 跳登录页** | **只有 401/403**（跳登录页对 Bearer 目标毫无意义） |
| 共存 | 可以同时配：表单换 cookie、Bearer 换 token，两层串在包装链上 |

## 3. 配置面

```bash
# 只给 URL：刷新凭据从会话 Cookie 里取（多数实现的默认形态）
node server/bin/cli.js -u https://app.example.com/api/item?id=1 \
  --header "Authorization: Bearer <抓包带来的 access token>" \
  --refresh-url https://app.example.com/oauth/token

# 目标要求 body 携带 refresh token / 令牌在响应的非常见字段里
  --refresh-token rt-abcdef --refresh-field data.jwt
```

REST：

```json
{ "target": { "url": "https://app.example.com/api/item?id=1",
    "config": { "auth": { "headers": { "Authorization": "Bearer <access>" } },
      "bearerRefresh": {
        "url": "https://app.example.com/oauth/token",
        "method": "POST", "bodyFormat": "json", "bodyField": "refresh_token",
        "refreshToken": "rt-abcdef", "body": { "client_id": "web" },
        "tokenField": "data.access_token",
        "headerName": "Authorization", "headerTemplate": "Bearer {token}",
        "eager": false
      } } } }
```

子键（全部可选，除 `url`；非法形状由 `guardBearerRefresh` 逐项收紧，`url` 非 http(s) 时
**整组丢弃并 warn** —— 坏 url 与"没配"后果相同（都不续期），但只有前者该被看见）：

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `url` | 必填 | 刷新端点。SSRF / scope 仍逐请求校验（它就是一个普通出站请求） |
| `method` | `POST` | |
| `refreshToken` | 不带 | 缺省时**不发明文 body**，靠会话 jar 里的 cookie（真实实现最常见） |
| `bodyField` | `refreshToken` | refreshToken 放进 body 的哪个字段 |
| `bodyFormat` | `json` | `json` \| `form`（`application/x-www-form-urlencoded`） |
| `body` | `{}` | 额外固定字段（`client_id` / `scope` 之类） |
| `tokenField` | 自动探测 | 点路径（支持 `data.items.0.token`）。未给时按候选表顺序取第一个命中：`access_token`/`accessToken`/`token`/`id_token`/`data.access_token`/`data.token`/`result.accessToken`/`result.access_token` |
| `headerName` | `Authorization` | 换成 `X-Api-Key` 这类自定义头时，模板默认变成裸 token |
| `headerTemplate` | `Bearer {token}` | 必须含 `{token}` 占位，否则该键被忽略（不含占位=每条请求带同一串字面量，那是配置错误） |
| `headers` | `{}` | 刷新请求的额外固定头 |
| `eager` | `false` | true = 首条请求**前置**一次续期（有些目标对无 token 请求直接 403 且不给可用挑战） |

⚠️ `tokenField` 两种都有时按候选表顺序：响应同时含顶层 `token` 与嵌套 `data.access_token`
属于本身有歧义，**必须显式配 `tokenField`**（不配就取 `token`）。

## 4. 四条口径（为什么这么写）

1. **拿到新 token 之前绝不动用户带来的 `Authorization`。** 调用方常从抓包带来一枚还没过期的
   token；如果一上来就用"续期结果"覆盖它，而续期端点其实配错了，那就是把能用的会话换成不能用的。
   ⇒ 只在 ① 首次收到 401/403 之后，或 ② 显式配 `eager: true` 时才注入。
2. **一次挑战只重试一次。** 续期后仍 401 ⇒ 放行原响应，绝不循环打续期端点 —— 那会对客户的
   认证服务造成 DoS 式压力，也会把扫描拖死。
3. **并发去重。** 同一时刻几十条请求都 401 时只发一次续期请求（in-flight 共享）。
4. **失败必须显形。** 续期端点自己 4xx/5xx/网络异常时，把"为什么"回传可信度守卫
   （`observeRefresh`），让报告写「你配的续期端点没拿到 token」而不是笼统的"重新登录"。
   没有这条，配错续期 = 又一次静默假阴性。

新令牌挂头时还有一处必须知道的出口层语义：`mergeAuthHeaders` 是 **`auth.headers` 覆盖
per-request 头**（抓包重建走的就是这条路）。如果续期只把新令牌写进请求自己的 headers，
它会在出口被旧令牌就地盖回去 —— 日志说"已取到新 token"、目标收到的还是旧令牌。
⇒ `applyBearer` 在这条请求上摘掉 `auth.headers` 里的同名键（只改副本，不动共享的 `config.auth`）。
这条由 `e2e/bearer-lab` B 场景实测抓到（26 次续期全成功、94 条请求仍被拒）。

## 5. 三种失效形态与报告文案

`session_expired` 现在区分三种成因（都归同一状态，因为处置同为"把凭据带对再复扫"，
但**必须说清是哪一种**，否则建议会把人支到错误方向）：

| 形态 | 判据 | reason 关键句 | advice 指向 |
| --- | --- | --- | --- |
| 从来没进去过 `neverAuthenticated` | 整轮**零业务响应**且认证挑战 ≥ `unauthMinRequests`(8) | 「没有任何一次得到过业务响应……从头到尾都不在已认证状态下」 | 带上凭据：`--auth` / `--header` / `--cookie` / `-r` 原始包；Bearer+refresh 配 `--refresh-url` |
| 中途失效 `expiredMidScan` | 有过业务响应，此后**连续** ≥ `authStreakAll`(8) 次都是认证挑战（不分注入与否） | 「前 N 次请求得到过业务响应，此后连续 M 次被认证层挡回……扫描进行中失效」 | 配 `--refresh-url`（Bearer）或 `--login-url`（表单自动重登） |
| 注入请求被打回（既有口径） | 注入请求连续 ≥ `authStreak`(3) 次 401/跳登录，而基线没有 | 「……而基线请求未出现该特征，判定会话已失效」 | 重新登录并携带有效 Cookie/Authorization |

配了 `bearerRefresh` 时，前两种的 reason 还会追加「本次已配 Bearer 自动续期，但续期尝试 N 次里
失败 M 次（最后一次：<原因>）」，advice 换成"先修续期链路"并点出 `bearerRefresh.url` / `tokenField`。
取不到 token 的原因会写明**试过哪些字段**与**响应顶层有哪些键** —— 字段名配歪是这类配置
最常见的错，这一句通常就够定位了。

### 为什么补前两种（既有判据为什么漏）

`authLost` 要求「基线请求**没有** 401」，这条反证是为了不把"整站本来就要登录"误写成"扫到一半会话过期"，
它是对的。问题是**排除之后没有第二条判据接手**：

- 令牌真的过期时，基线请求同样吃 401 ⇒ 反证恒成立 ⇒ 那条判据在这类目标上**永不可达**
  （与 D35 的 `transform_rejected` 在"单点 + 早剪"目标上不可达是同一类失效：判据写得对，
  但在它要管的那类目标上收不到样本）。
- 实测现场（`e2e/bearer-lab` A/C1/C2）：靶站 71 条请求里 69 条 401、其中 61 条是白打的注入 payload，
  而修之前的报告写 `verdict=no_vulnerability_detected` + `reliable=true`。

阈值取 8 而不是沿用 3：这两条**不分注入与否**，而"自动续期正在工作"的正常纹理就是
`401 → 重试 200` 交替出现；下限 3 会把这类目标误判成失效。连续段任一业务响应即清零，
所以续期成功时永远攒不到 8。

## 6. 403 的归属（一条容易踩的边界）

本守卫里 **403 属 `blocked` 族**（WAF/封 IP），不算认证挑战；而 `bearerKeeper` 把 403 也当成
挑战去续期（很多 API 的确用 403 表达"令牌过期"）。两套判据不合并，因此在"目标用 403 表达过期 +
续期又失败"时，落点是 `blocked` 而不是 `session_expired`。为免把人支到错误方向，`blocked` 的
advice 在配过续期且失败时会先说："目标用 403 表达令牌过期时，上面的拦截特征其实是会话失效，
先修 `bearerRefresh.url/tokenField` 再谈 WAF 规避"，随后保留完整的 WAF 出路。

## 7. 诚实边界（刻意不做）

- 不实现 OAuth2 授权码流程 / SSO / 验证码 / JS 加密提交。
- 不解析 JWT 的 `exp` 做"提前续期"。要做前瞻性续期请配 `eager: true`（首条请求前置一次续期），
  或自己写 [`--request-script` 变换脚本](./%E8%AF%B7%E6%B1%82%E5%8F%98%E6%8D%A2%E8%84%9A%E6%9C%AC.md) 现算。
- 续期请求本身走 per-scan 客户端 ⇒ 享受同一套 SSRF/scope/限速/Cookie jar；但它**不经过**
  `--request-script` 之外的签名层假设：如果刷新端点也要求签名，请让变换脚本对 `/oauth/token`
  这类 URL 生效（脚本可判 `r.url`）。
- 注入点发现阶段（爬虫）的请求经过的是同一个视图链，但续期只在**出现 401/403 时**触发。

## 8. 实测数字（`node e2e/bearer-lab/run.mjs`，三轮连跑逐位一致）

靶站：真 HTTP + 真 SQLite（sql.js）+ 真 HS256 JWT 验签 + 真刷新端点；令牌"何时失效"由靶站的
**虚拟时钟**（每条业务请求拨快 20s）决定 —— 用真实 TTL 会让 CI 变成抛硬币。

| 场景 | 靶站侧（认证通过 / 401 / 续期请求 / 过期后白打的注入） | 引擎 refresh 计数 | 报告 |
| --- | --- | --- | --- |
| A 不配续期 | 2 / 69 / 0 / **61** | attempts=0 | `session_expired` + inconclusive |
| B `--refresh-token` body 形态 | 70 / 1 / 1 / **0** | attempts=1 successes=1 | 检出 2 条 · vulnerability_detected |
| C1 续期端点 5xx | 2 / 69 / 24 / 61 | attempts=3 failures=3（最后一次：续期端点返回 500） | `session_expired` + inconclusive，reason 指名续期 |
| C2 端点 200 但响应里没有可用 token | 2 / 69 / 24 / 61 | attempts=3 failures=3（最后一次：试过 8 个候选字段；响应顶层键=code,msg） | 同 C1 |
| D 凭据只在 Cookie 里（不配 `--refresh-token`） | 70 / 1 / 1 / 0 | attempts=1 successes=1 | 检出 2 条 · vulnerability_detected |
| SAFE 参数化查询对照（配续期） | 89 / 1 / 1 / 0 | attempts=1 successes=1 | 0 条 · no_vulnerability_detected 且 **reliable=true** |

差分档：`node e2e/bearer-lab/run.mjs --break-chain` 把 B 的 `--refresh-url` 摘掉重跑
⇒ 检出从 2 掉回 0、过期后白打的注入从 0 涨回 61、续期请求 0 次 —— 证明 B 那套证据不是白送的。

SAFE 那一行是本套件存在的理由：**同一份代码、同一个靶站**，参数化查询接口在会话被维持住的前提下
0 检出且结论可信；一旦会话维持不住（A/C1/C2），就必须落成 inconclusive 而不是"未检出"。
