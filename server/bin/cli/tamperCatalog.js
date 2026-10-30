// ============================================================================
// cli/tamperCatalog.js —— `--list-tampers` 的渲染层（[D197 2026-10-30] 对标 sqlmap --list-tampers）
//
// 为什么要有：本仓 tamper 插件是**运行时注册**的（applyTampers.js 的 registerMany），
// 总数与名字在文档里会漂（tamperPluginCount.guard 的注释演进链 28→62→…→200 与实际 234 早就脱节），
// 而使用者挑链时唯一可靠的问题是「现在到底有哪些名字可用」。sqlmap 用 `--list-tampers`
// 回答它；本仓此前只能读源码或 REST（GET /api/tampers）——CLI 用户没有等价入口。
//
// 三条纪律：
//   ① 总数是**运行时真值**，不写死在文档里（那正是漂移的来源）；
//   ② 元信息直接来自 registry.list()（name/description/dbms/terminal/idempotent），
//      不在渲染层重新推导语义 —— 渲染层只做排版；
//   ③ 排序确定（按名升序），便于 diff 与快照测试。
// ============================================================================
import { tamperRegistry } from '../../src/core/tamper/TamperRegistry.js';
// 副作用导入：注册全部内置插件（与 REST 的 tamperRoutes 同一入口，两处必须一致）
import '../../src/core/tamper/applyTampers.js';

/** 元信息 → 行内标记串（dbms 限定 / terminal / 幂等）。 */
function markers(p) {
  const out = [];
  if (Array.isArray(p.dbms) && p.dbms.length) out.push(`dbms=${p.dbms.join('|')}`);
  if (p.terminal === true) out.push('terminal');
  if (p.idempotent === true) out.push('幂等');
  return out.length ? `[${out.join(' ')}]` : '';
}

/**
 * 生成 `--list-tampers` 的全部输出行（纯函数，便于单测与快照）。
 * @returns {string[]} 输出行
 */
export function tamperCatalogLines() {
  const list = tamperRegistry.list().slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
  const lines = [];
  lines.push(`tamper 插件（内置 + 本次进程内注册的自定义）：${list.length} 个`);
  lines.push('用法：--tamper "space2comment,charencode"（按书写顺序应用；dbms 不匹配只告警，terminal 之后被截断）');
  lines.push('列：[dbms=…] 仅适用该库；[terminal] 输出形态已固定（其后插件空转）；[幂等] 重复应用不损坏 payload');
  lines.push('');
  const width = list.reduce((n, p) => Math.max(n, String(p.name).length), 0);
  for (const p of list) {
    const mark = markers(p);
    lines.push(`  ${String(p.name).padEnd(width)}  ${mark ? `${mark} ` : ''}${p.description || '(无说明)'}`);
  }
  return lines;
}

/** 打印插件清单（`--list-tampers` 的副作用入口）。 */
export function printTamperCatalog() {
  for (const line of tamperCatalogLines()) console.log(line);
}
