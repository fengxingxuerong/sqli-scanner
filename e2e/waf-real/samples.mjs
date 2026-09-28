// ============================================================================
// samples.mjs —— CRS 对拍的**唯一样本集**（静态 crs-engine 与真机 ModSecurity 共用）
//
// 为什么抽出来：静态扫描（tamper-sweep.mjs / crs-equivalence.mjs）与真机对拍
// （modsec-live.mjs）结论要能横向比，前提是**喂的是同一批 payload**。
// 此前两边各自内联一份数组 —— 改了一边忘另一边，出来的「自实现 vs 真引擎」差异
// 里就混着「样本不同」这个假差异，归因必然跑偏。单一来源后这类漂移不可能发生。
//
// ── 2026-09-28 扩样本集：样本自带**上下文** ──────────────────────────────────
// 起因：直连打穿上界只有 1/8。根因不是 WAF 强，而是**样本与靶站拼接形态不匹配** ——
// 旧样本多为「字符串上下文」写法（`1' UNION ...-- -`），而靶站只有一处
// `WHERE id = ${raw}`（数值、无引号）。拼进去后不是注入，是语法错误 → 只能算
// 「抵达 SQL 层」，取不到任何数据 ⇒ 打穿率的分母恒为 1，任何百分比都建立在单条样本上。
//
// 修法：样本从裸字符串升级为 `{ ctx, payload }`，`ctx` 指向 CONTEXTS 里的一个注入点形态，
// 靶站与对拍脚本都按 ctx 路由（同一份模板，见 CONTEXTS.sql）。这样：
//   · 样本在**自己所属的上下文里语法成立** → 上界才可能被真实测量；
//   · 三种形态（数值无引号 / 字符串带引号 / IN 括号）同时覆盖 → 顺带回答「换一种
//     业务拼接写法还能不能打穿」（对拍不再只代表一种靶点）。
//
// ⚠️ 判据纪律：`exfil: true` 的样本**必须携带注入标记**（`__S__..__E__` 或 `SQLISCANNER<n>`）。
//    没有标记，即使 MySQL 报了错也只能算「抵达 SQL 层」—— 详见 pwnVerdict.mjs。
//    这条由 `server/tests/modsecLive.wiring.test.js` ⑮ 钉住：按 **声明的** exfil 字段查，
//    不按 payload 形状筛（形状筛会把「标记被删掉」的样本直接筛出集合 → 断言空转）。
// ============================================================================

/**
 * 注入点形态（靶站拼接模板的**单一来源**：靶站与对拍脚本共用，防两端分叉）
 * sql(raw) 就是真实业务里那句拼接 —— 改这里等于改靶点形态，两端同时生效。
 */
export const CONTEXTS = {
  // 数值、无引号：`WHERE id = $_GET[id]`（PHP/Python 里最常见的裸拼）
  num: {
    path: '/num',
    param: 'id',
    sql: (raw) => `SELECT id, name, note, extra FROM waf_items WHERE id = ${raw}`,
  },
  // 字符串、单引号包裹：`WHERE name = '$name'`（需要闭合引号才能逃逸）
  str: {
    path: '/str',
    param: 'name',
    sql: (raw) => `SELECT id, name, note, extra FROM waf_items WHERE name = '${raw}'`,
  },
  // 括号内：`WHERE id IN ($ids)`（需要先闭合右括号）
  in: {
    path: '/in',
    param: 'id',
    sql: (raw) => `SELECT id, name, note, extra FROM waf_items WHERE id IN (${raw})`,
  },
};

/**
 * 攻击样本：期望被 WAF 拦（放行 = 绕过成功）。
 * payload 来源不是随手编的：引擎真实形态 + CRS 942 族主要规则的触发面。
 */
export const SAMPLES = [
  // ── num（数值、无引号）───────────────────────────────────────────────────
  { ctx: 'num', exfil: true, payload: "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1'", note: 'union 2 列（与 4 列表不匹配 → 真实负例，保留）' },
  { ctx: 'num', exfil: true, payload: "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1','SQLISCANNER2','SQLISCANNER3'", note: 'union 4 列（引擎列探测真实形态）' },
  { ctx: 'num', exfil: true, payload: "1 UNION SELECT 1,CONCAT('__S__',version(),'__E__'),3,4", note: 'union 取数（带标记）' },
  { ctx: 'num', exfil: true, payload: "1 AND extractvalue(1,concat(0x7e,(SELECT CONCAT('__S__',version(),'__E__'))))", note: '报错取数 extractvalue（带标记）' },
  {
    ctx: 'num',
    exfil: true,
    payload:
      "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT('__S__',(SELECT version()),'__E__',0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)",
    note: '报错取数 floor-rand 重复键（带标记）',
  },
  { ctx: 'num', payload: '1 AND 1=1', note: '布尔通道（单请求不取数，只测放行）' },
  { ctx: 'num', payload: '1 AND SLEEP(5)-- -', note: '时间通道（单请求不取数，只测放行）' },

  // ── str（字符串、单引号）─────────────────────────────────────────────────
  { ctx: 'str', exfil: true, payload: "1' UNION SELECT NULL,CONCAT('__S__',CAST((version()) AS CHAR),'__E__'),NULL,NULL-- -", note: 'union 4 列（需闭合引号）' },
  { ctx: 'str', payload: "1' AND 1=1-- -", note: '布尔通道（需闭合引号）' },
  { ctx: 'str', exfil: true, payload: "1' AND extractvalue(1,concat(0x7e,(SELECT CONCAT('__S__',version(),'__E__'))))-- -", note: '报错取数 extractvalue（需闭合引号）' },
  {
    ctx: 'str',
    exfil: true,
    payload:
      "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT('__S__',(SELECT version()),'__E__',0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
    note: '报错取数 floor-rand（需闭合引号）',
  },
  { ctx: 'str', payload: "keyboard%' AND 1=1-- -", note: '布尔通道（业务词 + 百分号前缀）' },

  // ── in（括号内）──────────────────────────────────────────────────────────
  { ctx: 'in', exfil: true, payload: "1) UNION SELECT 'SQLISCANNER0','SQLISCANNER1','SQLISCANNER2','SQLISCANNER3'-- -", note: 'union（需闭合右括号）' },
  { ctx: 'in', exfil: true, payload: "1) UNION SELECT 1,CONCAT('__S__',version(),'__E__'),3,4-- -", note: 'union 取数（需闭合右括号）' },
  { ctx: 'in', exfil: true, payload: "1) AND extractvalue(1,concat(0x7e,(SELECT CONCAT('__S__',version(),'__E__'))))-- -", note: '报错取数（需闭合右括号）' },
];

/**
 * 安全样本：期望**不被拦**（被拦 = 误报）。
 * 放在 str 上下文（业务字符串输入的最常见形态）：
 * `1` 纯数字 / `keyboard` 业务词 / `O'Brien` 含撇号（英文姓名与所有格的日常写法，
 * 是 CRS 942 族最典型的误报来源）/ `笔记本电脑` 含中文（多字节，验证解码路径不误伤）。
 */
export const SAFE_SAMPLES = [
  { ctx: 'str', payload: '1' },
  { ctx: 'str', payload: 'keyboard' },
  { ctx: 'str', payload: "O'Brien" },
  { ctx: 'str', payload: '笔记本电脑' },
];

/** 取 payload（老代码传裸字符串时原样返回，兼容两种形态） */
export const payloadOf = (s) => (typeof s === 'string' ? s : s.payload);

/** URL 构造：/path?param=<encoded>（对拍脚本与靶站共用，防两端拼法不一致） */
export const sampleUrl = (base, s) => {
  const c = CONTEXTS[s.ctx];
  if (!c) throw new Error(`样本 ctx「${s.ctx}」未在 CONTEXTS 登记`);
  return `${base}${c.path}?${c.param}=${encodeURIComponent(payloadOf(s))}`;
};
