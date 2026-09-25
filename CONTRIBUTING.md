# Contributing Guide

感谢你对 sqli-scanner 的兴趣！本指南说明如何参与开发、测试与提交。

## 项目结构

```
src/                 前端（React + TypeScript + MUI + Vite）
server/              后端引擎（Node + Express + 自研检测引擎）
  ├── src/engine/    检测引擎（9 种检测器 + Extractor + Exploiter + 指纹）
  ├── src/core/      核心模块（tamper 225 个 / WAF 62 指纹 / HttpClient / OOB 接收）
  ├── src/api/       REST 路由（scan / exploit / tamper / report-ai / sqlmap 桥）
  └── tests/         服务端测试（node:test，~2355 用例）
src-tauri/           Tauri 桌面壳（Rust，sidecar 启动本地引擎）
e2e/                 端到端靶场（recall-lab 16–18 场景，差 2 条真 MySQL / sqli-labs / tamper-matrix / waf-lab）
docs/                设计文档与对标分析
```

## 开发环境

1. **依赖**：Node ≥ 20（`node --version` 检查）；前端 `npm install`，服务端 `cd server && npm install`
2. **启动**：
   - 后端：`npm run server`（监听 127.0.0.1:4567）
   - 前端：`npm run dev`（http://localhost:5173）
3. **测试**：
   - 前端：`npm test`（vitest，349 用例）
   - 服务端：`cd server && npm test`（node:test，~2361 用例）
   - 召回靶场：`npm run recall-e2e` ⇒ **16 条 + 2 条 SKIP**（真实 MySQL 组）。要跑满 18 条走隔离沙箱：
     `python e2e/run-with-sandbox.py e2e/recall-lab/recall.e2e.js`（实测 18/18 通过；驱动端点由
     `MYSQL_HOST/PORT/USER/PASSWORD` 注入，SKIP 时会打印究竟是哪一类原因）。
     CI 的 `acceptance` job 里有 mysqld，故那一步带 `RECALL_REQUIRE_MYSQL=1` 跑满 18 条 ——
     **这个开关的语义是"跳过按失败处理"**：步骤名写着 18 就必须真跑到 18，否则静默降级成 16
     （首次 CI 实跑 2026-09-25：两条 MySQL 场景分别检出 `[union,error,boolean]` / `[boolean]`，该步 45s）
   - 以上用例数以 `docs/_facts.json` 为准（`node scripts/facts-sync.mjs --refresh` 重采）

## 日志输出

- **前台运行**（`npm run dev` / `npm run server` / `npm test`）直接看控制台输出，不落盘
- **需后台运行或保留日志时，统一重定向到 `logs/` 目录**，禁止写到项目根目录，避免散落 `*.log` / `*.err` 杂物：

  ```bash
  npm run server > logs/server.log 2>&1 &
  cd server && npm test > ../logs/test-server.log 2>&1
  ```

- `logs/` 与根级 `*.log` 均已 `.gitignore`，重定向到 `logs/` 的产物不会入库
- 引擎内置 `winston` 日志器已自动写入 `logs/engine.log`（10MB×5 轮转 + 敏感脱敏 + 只读目录降级），无需手动配置

## 代码规范

- **前端**：TypeScript 严格模式 + ESLint + React Hooks 规则；提交前跑 `npx tsc --noEmit` 与 `npx eslint .`
- **服务端**：ESM（`"type": "module"`）；提交前跑 `cd server && npm test` 保证零回归
- **Rust**：`cd src-tauri && cargo fmt --check && cargo clippy -- -D warnings`（CI 强制执行）

## 引擎架构要点（改引擎前必读）

- **检测器注册表**：`ScanManager.js` 的 `this.detectors` 数组是唯一调度入口；新增技术需：① 新建 `detectors/XxxDetector.js` 继承 `Detector` ② 在 ScanManager 注册 ③ 加入 `scanRunner.js` 的 FAST/SLOW 层 ④ 在 `payloads/` 补模板 ⑤ 补测试
- **payload 双轨**：扁平 `PAYLOADS`（向后兼容）+ 声明式 `PAYLOAD_REGISTRY`（含 level/risk/clause 元数据）；新 payload 两处都要维护，并有 `payloadRegistry.test.js` 断言同步
- **tamper 插件**：每个插件一个文件在 `server/src/core/tamper/plugins/`，命名与 sqlmap 官方脚本对齐；改插件必须跑 `npm run tamper-matrix`
- **HttpClient 铁律**：所有出站请求必须经 `core/httpClient.js`（SSRF 防护 + DNS 钉死 + 限速 + 日志脱敏），禁止绕过
- **提取/指纹标记**：`__S__/__E__` 与 `SQLISCANNER<i>` 必须走 tamper 免疫（占位暂存还原），否则开 tamper 后拖库静默失效

## 提交规范

- Husky + lint-staged 会在提交时自动运行 ESLint fix
- 提交信息建议：`feat(engine): ...` / `fix(api): ...` / `perf(extractor): ...` / `test(...)` / `docs: ...`
- 大型改动请先运行 `npm run test:all` 确认前后端全绿

## 新增/修改功能 Checklist

- [ ] `npx tsc --noEmit` 零错误
- [ ] `npx eslint .` 零错误
- [ ] `npm test`（前端）全绿
- [ ] `cd server && npm test`（服务端）全绿
- [ ] 涉及检测/提取：`python e2e/run-with-sandbox.py e2e/recall-lab/recall.e2e.js` 18 场景全 PASS（直跑只有 16，MySQL 组 SKIP 不算绿）
- [ ] 涉及 tamper/WAF：`npm run tamper-matrix` 与 `python e2e/waf-lab/compare-real.run.py`（真 MySQL 装置；`npm run waf-e2e` 指向的是 2026-09-18 已废弃的空壳靶场，别再用）。后者是**门禁**（0 通过 / 1 判据失败 / 2 连不上库），2026-09-25 起 CI 每次 push 也在 acceptance job 里直连该 job 自己的 mysqld 跑一遍，不必等周度矩阵
- [ ] 更新 `README.md` 功能表与测试数字（如受影响）