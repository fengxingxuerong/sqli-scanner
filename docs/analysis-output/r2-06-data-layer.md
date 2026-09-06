# sqli-scanner 二轮审查 —— 数据/知识库资产（r2-06）

> 审查日期：2026-08-25 晚 · 审查人：data-layer 主代理直审（子代理额度耗尽后补位）· 基于上一轮（06-data-layer.md）修复后的复检

---

## 一、上一轮遗留项复核

| 上轮发现 | 本轮状态 |
|---|---|
| gzip tamper 产出 gzip 容器与 MySQL UNCOMPRESS 不匹配 | ✅ 已修（deflateSync，实测 0x78 前缀 + inflate 还原）|
| wafRules 头注释「覆盖 7 类」漂移 | ✅ 已修（实测 62 vendor / 126 matcher）+ 启动期结构断言（非法 matcher throw）|
| README 18 种 DBMS vs 3 种真实验证的表述 | ✅ README 已如实标注「3 种真实验证，15 种最小适配」|

## 二、tamper 插件库（203 个）现状

- 注册表启动校验 ✓（唯一 name + transform 可调用）；本轮新增 WAF 厂商专项测试（tamper.wafVendor.test.js）覆盖 safedog/_360waf 等面向国产 WAF 的插件变换正确性
- 遗留观察：同名语义插件仍存少量成对重复（如 space2plus 与 space2comment 在 + 注释场景互斥但可共存于链），属设计允许，不建议清理；真正的问题是**无任何插件级性能基准**——203 个全链串行时 CPU 成本未知，建议在 tamper-matrix 实验室加一档耗时统计输出

## 三、WAF 指纹库（62 vendor / 126 matcher）

- 结构断言上线后，header 缺 key / body-status 缺 test 正则的规则会在启动时直接失败——数据质量从「约定」升级为「强制」✓
- 遗留：wafRecommend 推荐表仍有约 50/62 条推荐组合雷同（一轮发现），对识别结果区分度贡献低；可按 vendor 分组去重收敛到 ~20 条高置信组合

## 四、payload 资产（1200+ 模板 / 71 条声明式注册表）

- payloads.others.test.js 本轮补齐边缘 DBMS（Access/HSQLDB/Derby/MonetDB 等）模板完整性测试 ✓
- PAYLOADS 扁平结构与 REGISTRY 双轨并存的维护成本依旧存在，但 payloadRegistry 的 71 条 sqlmap 对标条目已全部有消费路径（--level/--risk 门控），判定为「有意保留的双轨」而非死数据
- 边缘 DBMS 15 种仍是「模板存在、未真实验证」状态——与 README 表述一致，维持最小适配定位合理

## 五、汇总

高：0 ｜ 中：1（tamper 全链无性能基准）｜ 低：1（wafRecommend 收敛）。上轮三项 HIGH 已全部闭环，数据资产当前处于「结构有守卫、规模有测试、文档无漂移」的健康态。