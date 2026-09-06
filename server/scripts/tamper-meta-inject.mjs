// 一次性脚本：给关键 tamper 插件批量注入元数据（terminal / dbms）
// terminal：输出形态固定的全编码类——其后任何 tamper 均空转
// dbms：方言限定——对齐 sqlmap 官方 tamper 的 dbms 声明（运行时仅告警不截断）
import { readFileSync, writeFileSync } from 'node:fs';

const TERMINAL = ['base64encode', 'charencode', 'chardoubleencode', 'decimal2char', 'keyword2decimal', 'bin2ascii'];
const DBMS = {
  dollarquote: ['PostgreSQL'],
  oraclequote: ['Oracle'],
  sleep2getlock: ['MySQL'],
  sleep2pg: ['PostgreSQL'],
  space2mssqlblank: ['SQL Server'],
  space2mssqlhash: ['SQL Server'],
  space2mysqlblank: ['MySQL'],
  space2mysqldash: ['MySQL'],
  percentage: ['SQL Server'],
  '0eunion': ['MySQL'],
  versionedkeywords: ['MySQL'],
  versionedmorekeywords: ['MySQL'],
  halfversionedmorekeywords: ['MySQL'],
  modsecurityversioned: ['MySQL'],
  modsecurityzeroversioned: ['MySQL'],
  charunicodeencode: null, // 通用（ASP/宽字节场景多），不打标
};

const errors = [];
let n = 0;
const allNames = [...new Set([...Object.keys(DBMS), ...TERMINAL])];
for (const name of allNames) {
  const meta = DBMS[name] || null;
  const file = `src/core/tamper/plugins/${name}.js`;
  let src;
  try { src = readFileSync(file, 'utf-8'); } catch { errors.push(`缺文件: ${file}`); continue; }
  if (/^\s+(terminal|dbms):/m.test(src)) { console.log(`跳过（已有元数据）: ${name}`); continue; }
  const lines = [];
  if (meta) lines.push(`  dbms: [${meta.map((d) => `'${d}'`).join(', ')}], // [P1-FIX] 方言限定：异构库下无效，运行时告警`);
  if (TERMINAL.includes(name)) lines.push('  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断');
  if (!lines.length) { console.log(`跳过（无元数据）: ${name}`); continue; }
  const idx = src.search(/\n  (async )?transform\(/);
  if (idx < 0) { errors.push(`未找到 transform: ${name}`); continue; }
  const out = src.slice(0, idx) + '\n' + lines.join('\n') + src.slice(idx);
  writeFileSync(file, out, 'utf-8');
  n++;
}
console.log(`完成 ${n} 个；错误 ${errors.length} 个${errors.length ? '：' + errors.join('; ') : ''}`);
