import { evaluate } from '../waf-real/crs-engine.js';
// 引擎在真实 MySQL 靶场实际投放的 payload 形态（从 diag20/verify 采集）
const payloads = [
  ['布尔', '1 AND 1=1-- -'],
  ['布尔', "1' AND 1=1-- -"],
  ['布尔', "1' AND '1'='1"],
  ['布尔', "1') AND 1=1-- -"],
  ['UNION', "1 UNION SELECT NULL,NULL,NULL,NULL-- -"],
  ['UNION', "1 UNION SELECT NULL,CONCAT('__S__',CAST((version()) AS CHAR),'__E__'),NULL,NULL-- -"],
  ['UNION', "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1'-- -"],
  ['报错', "1' AND 1=CAST((SELECT current_schema) AS int)-- -"],
  ['报错', "1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -"],
  ['报错', "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -"],
  ['时间', '1 AND SLEEP(5)-- -'],
  ['时间', "1' AND SLEEP(5)-- -"],
  ['堆叠', "1; SELECT SLEEP(5)-- -"],
  ['LIKE', "keyboard%' AND 1=1-- -"],
];
let blocked = 0;
for (const [tech, p] of payloads) {
  const r = evaluate({ uri: '/num?id=1', queryString: 'id=1', args: { id: p, q: p }, cookies: {}, headers: {} });
  if (r.blocked) blocked++;
  console.log(`${r.blocked ? 'BLOCK' : 'PASS '} [${tech}] rule=${r.ruleId || '-'}  ${p.slice(0, 70)}`);
}
console.log(`\n拦截 ${blocked}/${payloads.length}`);
process.exit(0);
