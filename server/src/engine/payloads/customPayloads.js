// ==================== 用户自定义 payload 条目（扩展点，对标 nuclei 模板生态的最小入口） ====================
//
// 为什么需要这一层：
//   内置注册表（registry.json + registry.versioned.json）覆盖通用场景，但真实业务里总有
//   「某个中间件 / 某个 WAF 放行形态 / 某个国产库的特殊语法」是内置库覆盖不到的。此前唯一的
//   用户扩展点是 `--tamper <file>.js`（`args.js` 的 resolveTamperPlugins）——它只能加**变换**，
//   加不了**检测条目** ⇒ 用户想多测一条自己的 payload，只能改代码再发版。
//   本模块提供**追加式**扩展：`--payload-file <file.json>` 在本次扫描内把外部条目追加到
//   注册表尾部。**不传即零变化**（见 mergeCustomEntries 对空数组的短路）。
//
// 三条硬约束（都是"防自己变成新攻击面"）：
//   1. **只允许追加，不允许覆盖**：id 与内置条目冲突即抛错退出（CLI 侧 exit 2）。
//      理由：一个外部文件静默改掉内置条目 = 让"基线能力"取决于用户磁盘上有什么，
//      报告上的证据等级也就无从谈起（本仓最忌「声明与真值分处两地」）。
//   2. **自定义条目同样受高危池硬门管辖**：判定复用 `isDestructivePayload()`（按模板串比对，
//      不靠 id 命名）⇒ productionMode 未确认时它们一样不投放，不会因为"用户自己写的"就绕过去。
//   3. **校验失败即硬失败**：文件不可读 / JSON 坏 / 字段不合法 / technique 越界，一律报错退出，
//      不降级为"忽略继续扫" —— 静默忽略会让用户以为自定义生效了，比报错危险得多。
//
// 与 registry.json 的关系：同 schema（id/dbms/technique/level/risk/clause/boundary/
// template/falseTemplate/where），缺的标量字段按**最保守值**补全（level=1 / risk=1），
// 而不是按"缺字段=不过滤"放行（那等于让外部文件把 level 闸门顶开）。

import { TECHNIQUE_TYPES } from './index.js';

/** 必填字段（与声明式条目一一对应） */
export const CUSTOM_REQUIRED_FIELDS = ['id', 'dbms', 'technique', 'template'];

/** 合法注入位置（见 payloadRegistry.js 分级约定） */
export const CUSTOM_WHERE_VALUES = ['value', 'position'];

/**
 * 校验并规范化用户自定义条目。
 * 纯函数：不读文件、不碰全局、不改入参。
 * @param {unknown} list JSON.parse 后的顶层值
 * @returns {{entries: Array<Record<string, any>>, errors: string[]}} errors 非空 ⇒ 调用方必须硬失败
 */
export function validateCustomEntries(list) {
  const entries = [];
  const errors = [];
  if (!Array.isArray(list)) {
    return { entries, errors: ['顶层必须是数组（与 registry.json 同构）'] };
  }
  const seen = new Set();
  list.forEach((raw, i) => {
    const at = `第 ${i + 1} 条`;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      errors.push(`${at}: 必须是对象`);
      return;
    }
    for (const f of CUSTOM_REQUIRED_FIELDS) {
      if (raw[f] === undefined || raw[f] === null || raw[f] === '') {
        errors.push(`${at}: 缺必填字段 ${f}`);
        return;
      }
    }
    if (typeof raw.id !== 'string' || !raw.id.trim()) {
      errors.push(`${at}: id 必须是非空字符串`);
      return;
    }
    if (!Array.isArray(raw.dbms) || raw.dbms.length === 0) {
      errors.push(`${at}: dbms 必须是非空数组`);
      return;
    }
    if (!TECHNIQUE_TYPES.includes(raw.technique)) {
      errors.push(`${at}: technique 必须是 ${TECHNIQUE_TYPES.join('/')} 之一，收到 ${String(raw.technique)}`);
      return;
    }
    if (typeof raw.template !== 'string' || !raw.template) {
      errors.push(`${at}: template 必须是非空字符串`);
      return;
    }
    if (raw.where !== undefined && !CUSTOM_WHERE_VALUES.includes(raw.where)) {
      errors.push(`${at}: where 必须是 ${CUSTOM_WHERE_VALUES.join('/')} 之一，收到 ${String(raw.where)}`);
      return;
    }
    if (seen.has(raw.id)) {
      errors.push(`${at}: 文件内 id 重复 ${raw.id}`);
      return;
    }
    seen.add(raw.id);
    entries.push({
      ...raw,
      // 保守补全：缺 level/risk 按最低档（而不是"不过滤"），缺集合类字段按空数组
      level: Number.isFinite(raw.level) ? raw.level : 1,
      risk: Number.isFinite(raw.risk) ? raw.risk : 1,
      clause: Array.isArray(raw.clause) ? raw.clause : [],
      boundary: Array.isArray(raw.boundary) ? raw.boundary : [],
      where: raw.where || 'value',
      // 来源标记：报告/排查时能一眼看出这条不是内置基线
      custom: true,
    });
  });
  return { entries, errors };
}

/**
 * 把自定义条目追加到内置注册表。
 * @param {Array<Record<string, any>>} base 内置注册表（PAYLOAD_REGISTRY）
 * @param {Array<Record<string, any>>} custom 已校验的自定义条目
 * @returns {Array<Record<string, any>>} 合并后的新数组（不改 base）
 * @throws {Error} id 与内置冲突时抛错（拒绝覆盖，见文件头约束 1）
 */
export function mergeCustomEntries(base, custom) {
  // 默认路径短路：不传 --payload-file 时返回**同一个数组引用**，保证与旧行为逐位一致
  if (!custom || custom.length === 0) return base;
  const builtin = new Set(base.map((p) => p.id));
  const conflicts = custom.filter((c) => builtin.has(c.id)).map((c) => c.id);
  if (conflicts.length > 0) {
    throw new Error(
      `[customPayloads] 自定义条目 id 与内置注册表冲突（不允许覆盖内置）：${conflicts.join(', ')}`
    );
  }
  return [...base, ...custom];
}
