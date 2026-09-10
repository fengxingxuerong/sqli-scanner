// =====================================================================
// unionDebug.js —— UNION 检出链路的可选诊断输出
// =====================================================================
// 为什么单独一个文件：
//   UNION 是唯一一条「门控（真假探针）→ 列数二分 → 回显列定位」三段式的检测链，
//   任何一段静默失败都会表现为「union 技术位恒 0」，而上层只看到一个 false。
//   2026-09-09 定位「CRS 下 union 恒 0」时，正是靠逐请求打印 status/echoed/len
//   才发现根因在门控尾注（`/*` 在 MySQL 下语法错误 → 真假探针双双 500）
//   而不是在 WAF。为避免下次再从零插桩，这里把开关固化下来。
//
// 用法（仅在排障时开，默认全静默）：
//   SQLI_UNION_DEBUG=1 node bin/cli.js --url ... --tech U
//
// 输出走 stderr，不污染 stdout 的报告/JSON 输出。
// =====================================================================

// 惰性读取：允许测试/调用方在 import 之后再设置环境变量。
function enabled() {
  const v = process.env.SQLI_UNION_DEBUG;
  return v === '1' || v === 'true';
}

/**
 * 打印一条 union 链路诊断。未开启开关时为零开销（直接 return）。
 * 写 stderr 失败（管道关闭 / 沙箱限制）时静默吞掉——诊断绝不能打断扫描主链路。
 */
export function unionDebug(msg) {
  if (!enabled()) return;
  try {
    console.error(`[union-debug] ${msg}`);
  } catch {
    /* 诊断输出失败不影响检测 */
  }
}

/** 判断诊断是否开启（调用方用于跳过昂贵的字符串拼接）。 */
export function unionDebugEnabled() {
  return enabled();
}

export default unionDebug;
