# sqli-scanner v1.1.0

> 一键式 SQL 注入检测工具 · Web / Docker / 桌面（Tauri）/ CLI 四态交付
> 发布日期：2026-09-18

## ⚠️ 升级注意（有破坏性变更）

1. **容器或任何非回环监听部署必须配置 token**：引擎在 `HOST` 非回环（容器必需的 `0.0.0.0` 即属此列）
   且未设置 `SCAN_API_TOKEN` 时会**拒绝启动**——这是有意设计，本服务能对被扫描目标发起扫描与拖库。
   设置方式：`SCAN_API_TOKEN=<随机串>` 或 `SCAN_API_TOKEN_FILE=/run/secrets/scan_token`；
   确知风险的隔离网络可用 `SCAN_API_ALLOW_NO_TOKEN=1` 显式接受无鉴权。
   `docker-compose.yml` 的 `SCAN_API_TOKEN` 已改为必填（未设置时 compose 直接报错）。
2. 启用鉴权后，Web 端首次访问会弹一次 token 输入（写入 `localStorage.scanApiToken`），
   或构建期注入 `VITE_SCAN_API_TOKEN`。
3. 桌面端：应用会自动注入端口与一次性 token，无需手工配置；从旧版升级建议重新打包 sidecar。

## 安全

- **默认鉴权（fail-closed）**：统一 `resolveApiToken()`——`SCAN_API_TOKEN_FILE` → `SCAN_API_TOKEN` →
  回环允许无鉴权 → 非回环拒绝启动。
- **CSP 按响应类型分流**：`/api`、`/sqlmap` 保持 `default-src 'none'`；前端静态资源放行 `'self'`
  （含 MUI 所需的 `style-src 'unsafe-inline'`）。修复 Docker/单端口部署**打开即白屏**。
- **静态外壳与 API 鉴权分离**：启用 token 后前端外壳（dist 静态资源 / SPA 路由）不再被 401 拦截；
  所有数据接口（含不带 `/api` 前缀的 `/scan/*`、`/exploit/*`、`/sqlmap/*`）仍需 token。
- **桌面 sidecar 加固**：端口 4567 被占则自动改用空闲端口；引擎生成一次性 token
  （`crypto.randomBytes(32)`）经 stdout 回传、由壳转交前端；sidecar 构造/启动失败不再 panic；
  引擎默认放行 Tauri WebView 的 origin。

## 桌面端可打包了

- `npm run build:sidecar`（Node SEA）：cjs bundle → SEA blob → postject 注入 → 起 exe 冒烟。
- 补齐 `tauri.conf.json` 的 `bundle.externalBin`（此前缺失，即使有 exe 也进不了安装包）。
- 实测产出 `SQL注入检测工具_1.1.0_x64-setup.exe`（26.4 MB），壳启动后 sidecar 监听 127.0.0.1:4567。
- ⚠️ MSI（WiX `light.exe`）在含全角括号的路径下会失败，Windows 打包默认改用 NSIS。
- ⚠️ 已知限制：SEA 单文件不含 sql.js（external）→ 桌面版「直连 SQLite」不可用，HTTP/HTTPS 扫描完整。

## 正确性

- **拖库（MySQL 系）**：`GROUP_CONCAT` 显式行分隔符（真库实测 `SEPARATOR` 只接受字面量，改用 `0x1E`/`0x0A`）；
  聚合结果的 `LIMIT/OFFSET` 无意义，分页下推到源表行；`CONCAT_WS` 增加 NULL 安全包装。
- **网络失败不再判负**：全部检测器因传输层失败时标记为未决（`reliable=false`），不再写成「已检测、无漏洞」。
- **本地/私网默认绕过环境变量代理**（`proxyBypassLocal`），修复系统代理导致的本地靶场假阴性。
- 报告导出确定性：`POC_CACHE` 改为稳定字符串键 + 容量上限，修复 flaky。

## 门禁与可复现验证

| 门禁 | 本次结果 |
|---|---|
| 服务端单测 | 1850 tests / 1847 pass / 0 fail / 3 skip |
| 前端单测 + 类型 + 构建 | 294/294；tsc 0 错误；build 成功 |
| ESLint 全量 | 0 error / 7 warning |
| 依赖漏洞 | 0（服务端与前端 prod） |
| 检测回归 19 场景 | 19 PASS / 0 FAIL |
| 红队真值对照 | **R2 检出 19/19（100%）、安全点 7、误报 0**；sqlmap 同题 13/14 |
| 全量验收门禁 | **11 PASS / 0 FAIL / 0 SKIP**（含真 MySQL 10/10、CRS v4.1.0、红队、fileRead/fileWrite 真闭环） |
| 发布冒烟（沙箱） | 30 项断言全过（生产配置：token + 托管 dist + 真靶场扫描） |
| sidecar 冒烟 | exe 起服务 + 一次性 token + 真扫 PGlite 靶场检出 3 条 |

复现：`npm run acceptance`（需 MySQL）、`node e2e/diag/release-smoke.mjs`、
`node e2e/diag/security-guardrails.e2e.mjs`、`npm run build:sidecar`。

## 文档

- 新增 `CHANGELOG.md`、`docs/安全与架构全面审计-2026-09-17.md`、`docs/发布就绪度评估-2026-09-18.md`。

---

**合规提示**：本工具仅限在**获得明确授权的目标**上使用。对未授权系统进行扫描、测试或数据提取可能违反法律法规。
