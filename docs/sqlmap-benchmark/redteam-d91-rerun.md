# 红队靶场 D91 修复后复跑（26 靶点，r2 档）

- 日期：2026-10-17｜批次：D91（Cookie 注入点静默假阴性回归修复）
- 复跑命令：`node e2e/redteam-lab/run-scan.mjs r2`（需 MySQL 3306 常驻：`node e2e/redteam-lab/env.mjs`）
- 环境：真 MySQL 8.0.28 @127.0.0.1:3306（redteam_lab 库）、靶场 `e2e/redteam-lab/lab-app.mjs`、Node v22.22.2
- 引擎档位：r2 = level 3 / risk 2 / 全技术 BEUSTQ（`--level 3 --risk 2 --technique BEUSTQ`）
- 分母：vuln 19 + safe 7 = **26**

## 汇总

| 指标 | 结果 |
|---|---|
| 漏洞检出 | **19/19** |
| 安全点误报 | **0/7** |
| D11-cookie（回归点） | **检出** union+error+boolean，MySQL 指纹，61 请求，exit=2（修复前：0 检出 / 124 请求 / exit=0） |
| F18-F24 进程退出码 | 全 0（10-17 上午 acceptance 中 F18 曾出现 0xC0000409 native 崩溃，本批未复现） |

## 逐靶点

| 靶点 | 类型 | 结果 | 技术位 | DBMS | 请求数 | 退出码 |
|---|---|---|---|---|---|---|
| A1-int-union | vuln | ✅ 检出 | union+error+boolean | MySQL | 61 | exit=2 |
| A2-str-union | vuln | ✅ 检出 | union+error+boolean | MySQL | 49 | exit=2 |
| A3-like | vuln | ✅ 检出 | union+error+boolean | MySQL | 50 | exit=2 |
| A4-orderby | vuln | ✅ 检出 | error+boolean | MySQL | 83 | exit=2 |
| A5-dual-param | vuln | ✅ 检出 | union+error+boolean | MySQL | 67 | exit=2 |
| B6-error | vuln | ✅ 检出 | union+error+boolean | MySQL | 61 | exit=2 |
| C7-boolean | vuln | ✅ 检出 | boolean | MySQL | 162 | exit=0 |
| C8-time | vuln | ✅ 检出 | time | MySQL | 116 | exit=0 |
| D9-post-form | vuln | ✅ 检出 | union+error+boolean | MySQL | 181 | exit=2 |
| D10-json | vuln | ✅ 检出 | union+error+boolean | MySQL | 61 | exit=2 |
| D11-cookie | vuln | ✅ 检出 | union+error+boolean | MySQL | 61 | exit=2 |
| D12-xff-header | vuln | ✅ 检出 | union+error+boolean | MySQL | 61 | exit=2 |
| D13-path | vuln | ✅ 检出 | union+error+boolean | MySQL | 61 | exit=2 |
| D14-base64 | vuln | ✅ 检出 | union+error+boolean | MySQL | 61 | exit=2 |
| D15-param-del | vuln | ✅ 检出 | union+error+boolean | MySQL | 67 | exit=2 |
| D16-collate-mix | vuln | ✅ 检出 | error | MySQL | 95 | exit=2 |
| E15-second-order | vuln | ✅ 检出 | second_order | - | 11 | exit=2 |
| E16-stacked | vuln | ✅ 检出 | union+error+boolean | MySQL | 62 | exit=2 |
| E17-waf-guarded | vuln | ✅ 检出 | boolean+error | MySQL | 104 | exit=2 |
| F18-safe-item | safe | ✅ 未误报 | - | - | 124 | exit=0 |
| F19-safe-search | safe | ✅ 未误报 | - | - | 146 | exit=0 |
| F20-safe-rand | safe | ✅ 未误报 | - | - | 148 | exit=0 |
| F21-safe-500 | safe | ✅ 未误报 | - | - | 149 | exit=0 |
| F22-safe-403 | safe | ✅ 未误报 | - | - | 123 | exit=0 |
| F23-safe-redirect | safe | ✅ 未误报 | - | - | 124 | exit=0 |
| F24-safe-static | safe | ✅ 未误报 | - | - | 124 | exit=0 |

## D11-cookie 明细（回归点修复后）

- verdict：`vulnerability_detected`；3 条漏洞：union（CVSS 8.2 High）、error（8.2 High）、boolean（7.5 Medium/High）
- 注入点：`location=cookie`、`param=uid`、`boundaryProbed=true`、`boundary=''`、`echoCols=[0,1,2]`、`columns=3`、dbmsVersion=8.0.28
- 请求头实证（修复前抓包：124 个请求的 `Cookie` 全是 `uid=1` 原值）：修复后探针 payload 进入
  `Cookie: uid=1' OR '1'='1` 等形态，目标真实执行
- 根因链的三处存储在报告 config 里可复核：`target.cookieParams.uid="1"`、
  `target.headerParams`、`target.config.auth.headers.cookie="uid=1"`（最后一项即发送层
  每请求重附原值的通道）

## 边界（不得越界引用）

- 本复跑为**单轮 r2**（非 3 轮多数决定版）；耗时中位未重测，**不引用旧 747ms**
- 靶场为自建真 MySQL，**不是互联网真实目标**；19/19 只代表本靶场本配置
- 「19/19 恢复」证明 D91 修复对 D11 有效，**不证明无其他 cookie 相关回归**（本轮只覆盖红队 26 靶点）
