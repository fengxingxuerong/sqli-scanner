// ============================================================================
// samples.mjs —— CRS 对拍的**唯一样本集**（静态 crs-engine 与真机 ModSecurity 共用）
//
// 为什么抽出来：静态扫描（tamper-sweep.mjs / crs-equivalence.mjs）与真机对拍
// （modsec-live.mjs）结论要能横向比，前提是**喂的是同一批 payload**。
// 此前两边各自内联一份数组 —— 改了一边忘另一边，出来的「自实现 vs 真引擎」差异
// 里就混着「样本不同」这个假差异，归因必然跑偏。单一来源后这类漂移不可能发生。
//
// 样本来源（不是随手编的）：引擎真实形态，取自 scanner 实际发出的注入请求。
//   · UNION 列探测带 SQLISCANNER<N> 标记（CRS 942511/942200 以引号为锚点）
//   · blind / error / time 各通道一条，覆盖 942 族主要规则
// ============================================================================

/** 攻击样本：期望被 WAF 拦（放行 = 绕过成功） */
export const SAMPLES = [
  "1' UNION SELECT NULL,CONCAT('__S__',CAST((version()) AS CHAR),'__E__'),NULL,NULL-- -",
  "1' AND 1=1-- -",
  "1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
  "1 AND SLEEP(5)-- -",
  "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
  "keyboard%' AND 1=1-- -",
  // UNION 列探测（引擎真实形态，带 SQLISCANNER<N> 标记）——CRS 942511/942200 以「引号」为锚点
  "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1'",
  "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1','SQLISCANNER2','SQLISCANNER3'",
];

/**
 * 安全样本：期望**不被拦**（被拦 = 误报）。
 * 前两条是纯业务输入；第三条含撇号（英文姓名/所有格的日常写法），
 * 是 CRS 942 族最典型的误报来源；第四条含中文（多字节，验证解码路径不误伤）。
 */
export const SAFE_SAMPLES = ['1', 'keyboard', "O'Brien", '笔记本电脑'];
