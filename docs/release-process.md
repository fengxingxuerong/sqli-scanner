# 发布流程（Release process）

> 适用：把当前 `master` 上的 D 批次交付成一个可被外部下载的版本。
> 发布链的自动化在 `.github/workflows/ci.yml` 的 `docker-publish` / `desktop-package` / `release` 三个 job。

## 0. 前置

- 工作树干净、本机 `gate:close` 全绿。
- 推送权限与远端历史处理方式已确认（本仓曾出现本地/远端分叉，推送前先对树）。
- 版本号遵循 semver：修复批次 → patch，能力批次 → minor。

## 1. 升版本

```bash
# 改根 package.json 的 version 后，同步其余 8 处（tauri.conf / Cargo.toml / 两个 lock 等）
npm run version:fix
npm run version:check
```

把 `CHANGELOG.md` 的 `[Unreleased]` 整理成 `## [x.y.z] - YYYY-MM-DD`，并补汇总段。
`release-check` 会核对版本号 9 处一致、Tauri npm↔crate 同线。

## 2. 本机验收

```bash
node scripts/labs.mjs --check          # 先确认靶场；缺项会表现为 SKIP
node scripts/labs.mjs --up             # 拉起（Windows 上 benchmark-app 需要 ~80s）
npm run gate:close                     # 35 项收口
npm run acceptance                     # 25 套件；SKIP 不算通过
node scripts/pack-install-check.mjs    # 发版包「registry 式安装」端到端（干净目录真装真跑；需网络）
npm run package:portable               # 壳构建 → 便携包 → 干净解压冒烟
npm run release:check                  # 干净工作区 / tag↔版本 / Tauri 线
```

`acceptance` 里 OOB/外部裁判依赖网络与本机 PG/靶场；网络不可用时应记录 SKIP 原因，
不要把 SKIP 写成通过。

## 3. 提交与打 tag

```bash
git add <本次批次文件>
git commit -m "release: vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin master            # 需显式授权
git push origin vX.Y.Z            # 触发发布链
```

> 本仓纪律：提交、推送是两次独立授权；tag 推送会真实对外发布，执行前确认。

## 4. CI 会做什么（tag 触发）

| job | 产物 / 动作 |
|---|---|
| `docker-publish` | 构建并推送 `ghcr.io/<owner>/repo:vX.Y.Z`、`X.Y.Z`、`latest`（**仅 linux/amd64**），带 provenance + SBOM |
| `desktop-package` | Windows 壳 release 构建、NSIS 安装包、便携包组装 + 干净解压冒烟；上传 workflow artifact |
| `release` | 下载桌面产物 + 生成 CycloneDX SBOM（前端/引擎）+ `SHA256SUMS.txt` + 创建 GitHub Release 并上传全部资产 |

前置失败时 `release` 不会创建 Release（`needs` 强依赖 `desktop-package` 与 `docker-publish`）。

## 5. 发布后核对

- GitHub Release 资产齐全：portable zip、NSIS exe、`manifest.json`、两个 SBOM、`SHA256SUMS.txt`。
- 下载 portable zip，在一台**没有仓库**的机器上解压运行一次（版本应与 tag 一致）。
- `docker pull ghcr.io/<owner>/<repo>:X.Y.Z` 后跑一次 health 冒烟（非回环部署必须带 token）。
- 把 Release 链接与安装方式补进 README / README.en 的下载段。

## 6. 回滚

- 若 Release 尚未被消费：删除 Release 与 tag，修好后重新发 patch 版本。
- 若镜像已发布：重新推一个修正 tag；不要用 `latest` 覆盖已发布的版本号。
- 任何“发布后发现结论有误”的情况，按 `AGENTS.md` §3.5 的推翻协议处理：先停用结论、
  列影响面、补证据，再发修正版。

## 7. 尚未自动化 / 需人工确认

- Windows 代码签名（SmartScreen）与 macOS notarization 未配置。
- Docker arm64 未验证（`oracledb` 等原生依赖在 QEMU 下未跑过）。
- `desktop-package` 的 NSIS 构建依赖 runner 联网下载工具链。
