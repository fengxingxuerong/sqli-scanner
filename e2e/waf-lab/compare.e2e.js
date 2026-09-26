// e2e/waf-lab/compare.e2e.js
//
// ============================================================================
// 已废弃入口（2026-09-18 判定失效，2026-09-25 收成提示）—— 跑它只会得到一句恒为 NO 的结论
// ============================================================================
// 本夹具原先同进程起 `lab-server-v2.js` 的 `/vuln` 端点做 tamper A/B。那个端点的实现是：
//     app.get('/vuln', (req, r) => r.send(`row:${req.query.id}`));
// —— 纯字符串拼接回显，**没有任何 SQL 执行**。2026-09-18 实测：
//     ?id=1'                → 200 `row:1'`                     （无报错）
//     ?id=1' order by 1-- - → 200 `row:1' order by 1-- -`      （无差异）
//     ?id=1' and 1=1-- -    → 403（只是 WAF 拦，不是注入信号）
// 所以 union / error / boolean 三条通道在服务端**不可能**产生信号 ⇒ 两侧检出恒为 0，
// 判据 `detectRateB > detectRateA` 从设计上不可能成立。
//
// 为什么把整段夹具删掉而不是留着加 if：留着就会被再跑一次，而它每次产出的都是
// "这个判据没通过" —— 读的人得到的是**反向结论**（真因是夹具结构上不可能通过）。
// 历史实现：`git log -- e2e/waf-lab/compare.e2e.js`。
// `compare-real.e2e.mjs` 与 `lab-server-v2.js` 的注释仍按名字引用本文件（讲的就是这段历史），
// 所以文件保留成一份提示，而不是删除。
//
// ── 顺带留下的三条 tamper 实测结论（当年的 configB 组合为什么长那样）──────────────
//   · space2comment：绕过 `union\s+select` 这类**空格锚定**规则的关键一步。但它的引号状态机
//     会把闭合引号（如 `1'`）之后的整段当字符串字面量跳过替换 ⇒ **不能单独依赖**；
//   · charencode：把 `-- -` 变成 `--%20-`，绕过 `--\s*$` 这种行尾注释规则；
//   · randomcase：**不要**放进这类 A/B 的 configB —— 它随机化每个字母的大小写，会把
//     UnionDetector 用于确认回显的标记 `SQLISCANNER0` 打乱，导致 body.includes() 失败、
//     union 检测失效（当年表现为"开了 tamper 反而 0 检出"，判据照样不成立）。
//
// ── 真验 tamper 的入口 ──────────────────────────────────────────────────────
//   python e2e/waf-lab/compare-real.run.py   # 自起隔离 MySQL 沙箱（本机推荐）
//   node e2e/waf-lab/compare-real.e2e.mjs    # 已有 mysqld：设 MYSQL_* 指过去
//   npm run waf-e2e-real                     # 等价于第一条
// CI 侧：2026-09-25 起 acceptance job 每次 push 直连它自己的 mysqld 跑这份门禁
// （退出码 0 通过 / 1 判据失败 / 2 连不上库；判据含"两侧都必须有检出"的有效性前置）。
// ============================================================================

const NL = String.fromCharCode(10);
console.error(
  '[waf-e2e] 该入口已于 2026-09-18 废弃：本夹具的 /vuln 端点不执行 SQL ⇒ 两侧检出恒为 0，' +
    `判据 detectRateB > detectRateA 结构上不可能成立（详见本文件头）。${NL}` +
    '  改用真 MySQL 装置：' +
    `${NL}    python e2e/waf-lab/compare-real.run.py        # 自起隔离沙箱${NL}` +
    `    node e2e/waf-lab/compare-real.e2e.mjs         # 已有 mysqld 时，设 MYSQL_* 指过去${NL}` +
    `    npm run waf-e2e-real                          # 等价于第一条${NL}` +
    '  历史实现：git log -- e2e/waf-lab/compare.e2e.js'
);
process.exit(2);
