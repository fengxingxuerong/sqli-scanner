// ============================================================================
// e2e/diag/deliverable-demo.mjs —— 交付物形态演示（一次扫描 → 四种报告格式）
// ============================================================================
// 用途：回答「给一个靶场，最终交付的成果长什么样」——跑一次真实扫描，把
// JSON / Markdown / HTML / CSV 四种报告连同证据链一起落到一个目录，供人直接查看。
// 与 CLI 的 `--format/--out` 同源（ReportGenerator），只是这里一次产出全部格式。
//
// 用法：MYSQL_PORT=3306 MYSQL_USER=root MYSQL_PASSWORD=root node e2e/diag/deliverable-demo.mjs [目标URL]
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);
const { ReportGenerator } = await import(pathToFileURL(resolve(ROOT, 'server/src/services/ReportGenerator.js')).href);

const URL_ARG = process.argv[2] || 'http://127.0.0.1:8178/num?id=1';
// 第 2 个参数：输出子目录名（便于一目录多场景并列交付）
const OUT_NAME = process.argv[3] || 'default';
const OUT = resolve(ROOT, 'deliverables-demo', OUT_NAME);
if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const sm = new ScanManager();
const t0 = Date.now();
const scanId = await sm.start({
  url: URL_ARG,
  config: {
    concurrency: 4,
    retry: 0,
    timeoutMs: 15000,
    // 演示「带证据链」的交付：开启提取并限制行数，便于快速出结果
    enableExtract: true,
    dumpRowLimit: 20,
    // level 3 更贴近真实使用；WAF 压制场景在 level 2 下 payload 池不足会漏检（实测）
    level: 3,
    risk: 2,
  },
});
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 300000) break;
  await new Promise((r) => setTimeout(r, 50));
}
const report = sm.getReport(scanId) || {};
const gen = new ReportGenerator();

const files = {
  'report.json': JSON.stringify(report, null, 2),
  'report.md': gen.toMarkdown(report),
  'report.html': gen.toHTML(report),
  'report.csv': gen.toCSV(report),
};
for (const [name, content] of Object.entries(files)) {
  writeFileSync(resolve(OUT, name), content, 'utf8');
  console.log(`[deliverable] ${name.padEnd(13)} ${Buffer.byteLength(content, 'utf8')} bytes`);
}

// 汇总「这份交付物里到底有什么」——只报事实，不做修饰
const vulns = report.vulns || [];
const techs = [...new Set(vulns.map((v) => v.technique))];
const points = report.points || [];
// 字段名以实际 report 结构为准（vulns[] = id/pointId/technique/dbms/riskLevel/payloads/
// description/evidence/trace）：PoC 是渲染期由 payloads 还原的，故用 payloads 判断可复现性
const extracted = vulns.filter((v) => v.evidence);
console.log('\n[deliverable] 内容摘要：');
console.log(`  目标        ${report.target?.baseUrl || URL_ARG}`);
console.log(`  状态/耗时   ${sm.scans.get(scanId)?.status} / ${Date.now() - t0}ms`);
console.log(`  风险等级    ${report.summary?.riskLevel || report.riskLevel || '(见报告)'}`);
console.log(`  注入点      ${points.length} 个；其中命中 ${new Set(vulns.map((v) => v.pointId)).size} 个`);
console.log(`  检出技术    ${techs.join(', ') || '(无)'}`);
console.log(`  证据条目    ${extracted.length} 条（含回显列/报错特征）`);
console.log(`  方言等级    ${report.summary?.dbmsEvidence?.levelText || '(未写入)'}（${report.summary?.dbmsEvidence?.dbms || '?'}）`);
console.log(`  拦截处置    ${report.summary?.blockPolicy?.action || 'none'}`);
console.log(`  可复现 PoC  ${vulns.filter((v) => Array.isArray(v.payloads) && v.payloads.length).length} 条（报告内附 curl + 原始 HTTP 报文）`);
console.log(`\n[deliverable] 输出目录：${OUT}`);
process.exit(0);
