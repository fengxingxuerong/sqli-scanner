// tamper 变体对 CRS v4.1.0 的绕过率矩阵（静态 payload 层，不发包）
import { evaluate } from '../waf-real/crs-engine.js';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const { applyTampers } = require(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/core/tamper/applyTampers.js'));

const SAMPLES = [
  "1' UNION SELECT NULL,CONCAT('__S__',CAST((version()) AS CHAR),'__E__'),NULL,NULL-- -",
  "1' AND 1=1-- -",
  "1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
  "1 AND SLEEP(5)-- -",
  "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
  "keyboard%' AND 1=1-- -",
];
const CHAINS = {
  off: null,
  '经典三件套': ['space2comment', 'commentbeforeparentheses', 'charencode'],
  mysqlversioncomment: ['mysqlversioncomment'],
  logicalops: ['logicalops'],
  'CRS组合(mvc+logicalops)': ['mysqlversioncomment', 'logicalops'],
};
const ctx = { dbms: 'MySQL', config: {} };
const total = SAMPLES.length;
for (const [label, chain] of Object.entries(CHAINS)) {
  let blocked = 0;
  const lines = [];
  for (const p of SAMPLES) {
    const t = chain ? applyTampers(p, ctx, chain) : p;
    const r = evaluate({ uri: '/num?id=1', queryString: 'id=1', args: { id: t, q: t }, cookies: {}, headers: {} });
    if (r.blocked) blocked++;
    lines.push(`  ${r.blocked ? '拦' : '过'} rule=${r.ruleId || '-'}  ${t.slice(0, 80)}`);
  }
  console.log(`[${label}] 绕过率 ${(total - blocked)}/${total}（拦截 ${blocked}）`);
  for (const l of lines) console.log(l);
  console.log('');
}
process.exit(0);
