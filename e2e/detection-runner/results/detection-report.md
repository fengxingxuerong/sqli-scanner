# 数据驱动检测测试报告（Detection Test Report）

> 生成时间：2026-09-20T10:13:29.027Z　｜　运行器：`npm run test:detection`
> 场景总数：19　｜　PASS：19　｜　FAIL：0　｜　SKIP：0　｜　WARN：1

## 召回场景（vulnerable=true，must 技术须全命中）

| 场景 | 描述 | 检出 | must 命中 | 请求数 | 检查项 | 耗时 | 结果 |
|---|---|---|---|---|---|---|---|
| num | 数值型上下文（id=1，无引号） | union, error, boolean | 全部命中 | 54 | ✓vulnerable=true ✓must=[union,error,boolean] ✓requests<=80 | 47ms | PASS |
| str | 单引号字符串上下文（name='foo'，需 ' 闭合） | union, error, boolean | 全部命中 | 47 | ✓vulnerable=true ✓must=[boolean,error] ✓nice=[union] ✓requests<=80 | 46ms | PASS |
| paren | 括号包裹上下文(('...')，需 ') 闭合) | union, error, boolean | 全部命中 | 51 | ✓vulnerable=true ✓must=[boolean] ✓nice=[error,union] ✓requests<=90 | 46ms | PASS |
| orderby | ORDER BY 位置注入（逗号型子句 payload，level=2） | boolean | 全部命中 | 88 | ✓vulnerable=true ✓must=[boolean] ✓nice=[time] ✓requests<=120 | 2.1s | PASS |
| bool_only | 仅布尔差异（无回显/无报错/无延迟） | boolean | 全部命中 | 74 | ✓vulnerable=true ✓must=[boolean] ✓requests<=120 | 2.1s | PASS |
| time_only | 仅时间通道（内容恒定，sleep 生效） | time | 全部命中 | 164 | ✓vulnerable=true ✓must=[time] ✓requests<=170 | 3.2s | PASS |
| stacked | 堆叠注入（; 第二条语句 sleep） | stacked | 全部命中 | 167 | ✓vulnerable=true ✓must=[stacked] ✓requests<=170 | 4.1s | PASS |
| inline | 内联查询（标量子查询随响应回显） | inline | 全部命中 | 24 | ✓vulnerable=true ✓must=[inline] ✓requests<=40 | 46ms | PASS |
| union_extract | UNION 提取链（版本值经 __S__..__E__ 回显可拖库） | union | 全部命中 | 36 | ✓vulnerable=true ✓must=[union] ✓requests<=150 ✓extracted.databases non-empty ✓extracted.tables non-empty | 62ms | PASS |
| search_like | 搜索型注入（LIKE %{v}% 上下文，需 % 与 ' 双闭合） | boolean | 全部命中 | 51 | ✓vulnerable=true ✓must=[boolean] ✓requests<=60 | 77ms | PASS |
| update_set | UPDATE SET 注入（name='...' 赋值上下文，引号闭合后逗号拼接赋值） | boolean | 全部命中 | 159 | ✓vulnerable=true ✓must=[boolean] ✓requests<=170 | 482ms | PASS |

## 假阳性场景（vulnerable=false，检出数须=0）

| 场景 | 描述 | 检出数 | 请求数 | 耗时 | 结果 |
|---|---|---|---|---|---|
| fp_strict | 数字白名单（非法即 400） | 0 | 5 | 32ms | PASS |
| fp_param | 参数化查询语义（无注入面） | 0 | 137 | 107ms | PASS |
| fp_escape | 单引号转义（'' 无法闭合） | 0 | 145 | 92ms | PASS |
| fp_noecho | 无回显（输入不进入响应） | 0 | 6 | 33ms | PASS |
| fp_json | JSON API（数值型回显） | 0 | 149 | 92ms | PASS |

## 提取验证场景（golden output 对比）

| 场景 | 描述 | 检出 | 提取检查 | 请求数 | 耗时 | 结果 |
|---|---|---|---|---|---|---|
| extract_mock_values | UNION 提取链验证：提取的数据库/表名与 mock lab 已知值匹配（golden output 对比） | union | ✓databases non-empty ✓tables non-empty ✓databases contains "labdb" ✓tables contains "users" | 41 | 105ms | PASS |
| extract_no_false_positive | 安全目标提取验证：无注入时不产生提取数据（golden output 对比） | - | ✓databases empty ✓tables empty | 126 | 108ms | WARN |

## 二阶注入场景

| 场景 | 描述 | 检出 | must 命中 | 请求数 | 耗时 | 结果 |
|---|---|---|---|---|---|---|
| second_order_store | 二阶注入：payload 经 POST 表单存储到 /store，在 GET /profile 拼入 SQL 执行产生报错 | second_order | 全部命中 | 5 | 47ms | PASS |

---

**场景文件**：`e2e/fixtures/**/*.json`　｜　**运行器**：`e2e/detection-runner/run.js`
**添加新场景**：在 `e2e/fixtures/<category>/` 下新建 .json 文件，无需修改运行器代码