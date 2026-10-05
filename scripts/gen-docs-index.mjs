// ============================================================================
// gen-docs-index.mjs —— 生成 docs/INDEX.md（按类目分组的文档导航）
//
// 为什么要有索引（评价 2026-10-03 §三.G：文档「内容极好，体量失控」）：
//   73 篇 md 没有目录，找一份实测口径要靠文件名猜。本脚本扫描 docs/*.md 的
//   一级标题（没有就取文件名），按类目规则分组，生成 INDEX.md。
//   可重复执行（幂等覆盖），文档增删后重跑即可。
// 用法：node scripts/gen-docs-index.mjs
// ============================================================================
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DOCS = resolve(ROOT, 'docs');

// 类目规则：首个命中的 pattern 决定分组（顺序即优先级）
const CATEGORIES = [
  { name: '体检与评价（项目当前水准的定期体检）', test: /项目评价|发布就绪|进步空间|验收门禁|状态收拢/ },
  { name: '批次纪要与推进记录（按时间序的战报）', test: /优化推进|实战审计|批次|纪要|待办盘点|待办全景|优化空间/ },
  { name: 'WAF 真机对拍与绕过能力（对外口径的唯一来源）', test: /WAF|waf|绕过/ },
  { name: '对标与竞品分析（sqlmap / Arjun / ZAP）', test: /sqlmap|竞品|对标|vs-sqlmap/ },
  { name: '实测口径与验证记录（数字怎么来的）', test: /口径|验证|实测|复盘|排查|假绿|假阴性|缺陷|沙箱/ },
  { name: '设计文档与 PRD（为什么这么设计）', test: /prd_|system_design|design|设计|拆分|方案|计划|建议|勘查|评估|清单/ },
  { name: '使用与交付（怎么部署、怎么用）', test: /deploy|user-guide|faq|使用手册|交付|release-notes|发布|API|api\.md/ },
];
const FALLBACK = '其它（专题笔记与过程记录）';

const files = readdirSync(DOCS)
  .filter((f) => f.endsWith('.md') && f !== 'INDEX.md')
  .sort();

const groups = new Map();
for (const f of files) {
  const raw = readFileSync(resolve(DOCS, f), 'utf8');
  // 一级标题；没有就用文件名（去扩展名）
  const h1 = (raw.match(/^# (.+)$/m) || [])[1] || f.replace(/\.md$/, '');
  // 标题过长截断（索引是导航，不是摘要）
  const title = h1.length > 60 ? `${h1.slice(0, 57)}…` : h1;
  const cat = CATEGORIES.find((c) => c.test.test(f) || c.test.test(h1))?.name || FALLBACK;
  if (!groups.has(cat)) groups.set(cat, []);
  groups.get(cat).push({ file: f, title });
}

const lines = [
  '# docs 导航索引',
  '',
  `> 由 \`node scripts/gen-docs-index.mjs\` 生成（${new Date().toISOString().slice(0, 10)}），`,
  `> 覆盖 docs/ 下 ${files.length} 篇 md。文档增删后重跑即可；标题取各文件的一级标题。`,
  '',
];
for (const [cat, items] of groups) {
  lines.push(`## ${cat}（${items.length}）`, '');
  for (const it of items) lines.push(`- [${it.file}](./${encodeURIComponent(it.file)}) — ${it.title}`);
  lines.push('');
}
writeFileSync(resolve(DOCS, 'INDEX.md'), lines.join('\n'), 'utf8');
console.log(`[docs-index] ${files.length} 篇 → ${groups.size} 类 → docs/INDEX.md`);
