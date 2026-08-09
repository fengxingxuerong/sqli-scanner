import { ErrorCode, AppError } from '../errors.js';
import { logger } from '../logger.js';

// tamper 插件注册表（策略模式容器）
// 对标 sqlmap --tamper：把"单一内联混淆"升级为"链式可插拔"体系。
// 内置插件在 applyTampers.js 导入时注册；用户插件可按名注册后由 config.wafEvasion.tamper.plugins 引用。
export class TamperRegistry {
  constructor() {
    // name -> 插件对象 { name, description, transform(payload, ctx) }
    this._plugins = new Map();
  }

  /**
   * 注册单个插件
   * @param {{name:string, description?:string, transform:(payload:string, ctx:object)=>string}} plugin
   * @returns {TamperRegistry} 便于链式
   * @throws {AppError} 缺 name 抛 TAMPER_INVALID_NAME
   */
  register(plugin) {
    if (!plugin || typeof plugin.name !== 'string' || !plugin.name) {
      throw new AppError(ErrorCode.TAMPER_INVALID_NAME, 'tamper 插件必须包含唯一 name 字段');
    }
    if (typeof plugin.transform !== 'function') {
      throw new AppError(ErrorCode.TAMPER_INVALID_NAME, `tamper 插件 ${plugin.name} 必须实现 transform 函数`);
    }
    this._plugins.set(plugin.name, plugin);
    return this;
  }

  /**
   * 批量注册插件（启动期注册内置 + 用户插件）
   * @param {Array} plugins
   * @returns {TamperRegistry}
   */
  registerMany(plugins = []) {
    for (const p of plugins || []) this.register(p);
    return this;
  }

  /**
   * 按名取插件
   * @param {string} name
   * @returns {object|null}
   */
  get(name) {
    return this._plugins.get(name) || null;
  }

  /**
   * 列出全部插件元信息（不含 transform，便于序列化展示）
   * @returns {Array<{name:string, description:string}>}
   */
  list() {
    return [...this._plugins.values()].map((p) => ({
      name: p.name,
      description: p.description || '',
    }));
  }

  /**
   * 按名数组解析成有序插件数组（未知名跳过并告警，保证链式顺序由数组顺序决定）
   * 兼容性元数据（对标 sqlmap 各 tamper 的 dbms/dependencies 约束）：
   *   - plugin.compat.dbms：声明该插件适用的 DBMS 键（如 ['MySQL','MariaDB']）；
   *     当传入 ctx.dbms 且不在作用域内 → 跳过并告警（避免 MySQL-only tamper 误用到 SQLite/PG 静默失效）。
   *   - plugin.compat.conflicts：声明与之冲突的插件名（如 space 类互相改写）；存在冲突 → 告警（保留两者，由操作员裁决）。
   * 向后兼容：不传 ctx（或 ctx.dbms 未知）时退化为原行为（仅按名解析，不加 dbms 过滤）。
   * @param {string[]} names 有序插件名
   * @param {object|null} ctx 检测上下文（含 dbms）；可不传
   * @returns {Array} 有序插件对象数组
   */
  resolve(names = [], ctx = null) {
    const resolved = [];
    const dbms = ctx && ctx.dbms;
    for (const n of names || []) {
      const p = this._plugins.get(n);
      if (!p) {
        logger.warn(`tamper 插件未找到：${n}（已跳过）`);
        continue;
      }
      // dbms 作用域过滤：插件声明了 compat.dbms 且当前 ctx.dbms 已知且不在作用域内 → 跳过
      const compat = p.compat || {};
      if (dbms && Array.isArray(compat.dbms) && compat.dbms.length > 0) {
        if (!compat.dbms.includes(dbms)) {
          logger.warn(
            `tamper 插件 ${n} 声明仅适用于 [${compat.dbms.join(',')}]，当前 DBMS=${dbms}，已跳过`
          );
          continue;
        }
      }
      // 冲突检测：与已入选插件存在 conflicts 关系 → 告警（保留两者，由操作员裁决顺序）
      const cc = compat.conflicts || [];
      for (const prev of resolved) {
        const prevCc = (prev.compat || {}).conflicts || [];
        if (cc.includes(prev.name) || prevCc.includes(p.name)) {
          logger.warn(
            `tamper 插件冲突：${prev.name} 与 ${p.name} 可能互相干扰（space/comment 类重复改写），建议二选一`
          );
        }
      }
      resolved.push(p);
    }
    return resolved;
  }
}

// 单例：全应用共享同一注册表
export const tamperRegistry = new TamperRegistry();
export default tamperRegistry;
